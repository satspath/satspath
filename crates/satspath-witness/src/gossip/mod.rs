//! Gossip monitor, durable signed evidence and Nostr relay transport.

mod store;
mod transport;

#[cfg(test)]
mod tests;

pub use store::GossipStore;
pub use transport::{run_relay, validate_relay_url, NostrGossipEvent};

use std::{collections::HashMap, sync::Arc};

use satspath_core::transparency::{
    compare_verified_gossip_observations, verify_checkpoint_transition, GossipComparison,
    GossipObservation, PinnedCheckpoint, SplitViewEvidence, MAX_GOSSIP_BYTES,
};
use tokio::sync::Mutex;

use crate::WitnessError;
use store::{observation_key, ObservationKey, SaveResult};

/// Cached, authenticated historical views for one immutable trust policy.
#[derive(Default)]
struct VerifiedCache {
    loaded: bool,
    observations: HashMap<ObservationKey, GossipObservation>,
    split_view_size: Option<u64>,
}

/// Enforce each observer's pinned history before their new view is shared.
fn check_observer_transition(
    previous: &GossipObservation,
    proposed: &GossipObservation,
) -> Result<(), WitnessError> {
    let old = &previous.checkpoint;
    let new = &proposed.checkpoint;
    if new.log_size < old.log_size {
        return Err(WitnessError::Rollback {
            pinned: old.log_size,
            proposed: new.log_size,
        });
    }
    if new.log_size == old.log_size {
        if new.log_root != old.log_root || new.map_root != old.map_root {
            return Err(WitnessError::EquivocationDetected {
                log_id: new.log_id.clone(),
                tree_size: new.log_size,
            });
        }
        return Ok(());
    }
    let pin = PinnedCheckpoint {
        log_id: old.log_id.clone(),
        operator_pubkey: old.operator_pubkey.clone(),
        operator_sequence: old.operator_sequence,
        tree_size: old.log_size,
        root_hash: old.log_root.clone(),
        checkpoint_hash: old
            .checkpoint_hash()
            .map_err(|_| WitnessError::InvalidSignature)?,
        first_seen_at: previous.observed_at,
        last_seen_at: previous.observed_at,
    };
    verify_checkpoint_transition(&pin, new, proposed.consistency_proof.as_ref())
        .map_err(|_| WitnessError::InvalidConsistencyProof)
}

/// Accept only canonical compressed keys; string comparisons elsewhere are exact.
fn canonical_key(value: &str) -> Option<secp256k1::PublicKey> {
    let bytes = hex::decode(value).ok()?;
    if value.len() != 66 || hex::encode(&bytes) != value {
        return None;
    }
    secp256k1::PublicKey::from_slice(&bytes).ok()
}

/// The operator key is an out-of-band trust anchor; a relay never chooses it.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub log_id: String,
    pub operator_pubkey: String,
    pub trusted_observers: Vec<String>,
}

impl GossipConfig {
    /// Reject malformed, noncanonical or duplicate x-only trust identities.
    pub fn validate(&self) -> Result<(), WitnessError> {
        let mut distinct_identities = std::collections::HashSet::new();
        if self.log_id.is_empty()
            || self.log_id.len() > 256
            || self.trusted_observers.len() < 2
            || self.trusted_observers.len() > 32
            || canonical_key(&self.operator_pubkey).is_none()
            || self.trusted_observers.iter().any(|key| {
                let identity = canonical_key(key).map(|key| key.x_only_public_key().0.serialize());
                identity.is_none_or(|pubkey| !distinct_identities.insert(pubkey))
            })
        {
            return Err(WitnessError::InvalidSignature);
        }
        Ok(())
    }
}

/// One monitor per state directory; clones share a serialized verified cache.
#[derive(Clone)]
pub struct GossipMonitor {
    config: GossipConfig,
    store: GossipStore,
    cache: Arc<Mutex<VerifiedCache>>,
}

impl GossipMonitor {
    /// Construct a monitor only after validating its independent trust anchors.
    pub fn new(config: GossipConfig, store: GossipStore) -> Result<Self, WitnessError> {
        config.validate()?;
        Ok(Self {
            config,
            store,
            cache: Arc::new(Mutex::new(VerifiedCache::default())),
        })
    }

    /// Return the fixed trust policy used for this monitor's lifetime.
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    /// Access persisted observations when preparing local publication.
    pub fn store(&self) -> &GossipStore {
        &self.store
    }

    /// Lazily load and authenticate persisted observations once per trust policy.
    async fn load_cache(&self, cache: &mut VerifiedCache) -> Result<(), WitnessError> {
        if cache.loaded {
            return Ok(());
        }
        let store = self.store.clone();
        let config = self.config.clone();
        let mut stored = tokio::task::spawn_blocking(move || store.observations(&config.log_id))
            .await
            .map_err(|e| WitnessError::Storage(e.to_string()))??;
        stored.sort_by(|a, b| {
            (&a.observer_pubkey, a.checkpoint.log_size, a.observed_at).cmp(&(
                &b.observer_pubkey,
                b.checkpoint.log_size,
                b.observed_at,
            ))
        });
        for older in stored {
            if older
                .verify_evidence(
                    &self.config.log_id,
                    &self.config.operator_pubkey,
                    &self.config.trusted_observers,
                )
                .is_ok()
            {
                if let Some(latest) = cache
                    .observations
                    .values()
                    .filter(|previous| previous.observer_pubkey == older.observer_pubkey)
                    .max_by_key(|previous| (previous.checkpoint.log_size, previous.observed_at))
                {
                    if check_observer_transition(latest, &older).is_err() {
                        eprintln!("skipping stored checkpoint with unverified observer transition");
                        continue;
                    }
                }
                cache.observations.insert(observation_key(&older)?, older);
            } else {
                eprintln!("skipping stored checkpoint outside the current gossip trust policy");
            }
        }
        if let Some(existing) = self.alerts(chrono::Utc::now().timestamp()).await?.first() {
            return Err(WitnessError::SplitViewDetected {
                log_id: self.config.log_id.clone(),
                tree_size: existing.first.checkpoint.log_size,
            });
        }
        cache.loaded = true;
        Ok(())
    }

    /// Persist a valid observation; return an immediate failure on a split view.
    pub async fn ingest(
        &self,
        observation: GossipObservation,
        now: i64,
    ) -> Result<(), WitnessError> {
        let size = serde_json::to_vec(&observation)
            .map_err(|e| WitnessError::Storage(e.to_string()))?
            .len();
        if size > MAX_GOSSIP_BYTES {
            return Err(WitnessError::InvalidSignature);
        }
        observation
            .verify(
                &self.config.log_id,
                &self.config.operator_pubkey,
                &self.config.trusted_observers,
                now,
            )
            .map_err(|_| WitnessError::InvalidSignature)?;
        let tree_size = observation.checkpoint.log_size;
        let mut cache = self.cache.lock().await;
        self.load_cache(&mut cache).await?;
        if let Some(tree_size) = cache.split_view_size {
            return Err(WitnessError::SplitViewDetected {
                log_id: self.config.log_id.clone(),
                tree_size,
            });
        }
        let new_key = observation_key(&observation)?;
        if cache
            .observations
            .get(&new_key)
            .is_some_and(|old| old.observed_at >= observation.observed_at)
        {
            return Ok(());
        }
        if let Some(latest) = cache
            .observations
            .values()
            .filter(|old| old.observer_pubkey == observation.observer_pubkey)
            .max_by_key(|old| (old.checkpoint.log_size, old.observed_at))
        {
            check_observer_transition(latest, &observation)?;
        }
        let mut split_view = false;
        for older in cache.observations.values() {
            if older.observer_pubkey == observation.observer_pubkey {
                continue;
            }
            if let GossipComparison::SplitView(evidence) =
                compare_verified_gossip_observations(older, &observation, now)
                    .map_err(|_| WitnessError::InvalidSignature)?
            {
                let store = self.store.clone();
                let recorded = evidence.clone();
                tokio::task::spawn_blocking(move || store.save_alert(&recorded))
                    .await
                    .map_err(|e| WitnessError::Storage(e.to_string()))??;
                split_view = true;
            }
        }
        let store = self.store.clone();
        let saved = observation.clone();
        let result = tokio::task::spawn_blocking(move || store.save_observation(&saved))
            .await
            .map_err(|e| WitnessError::Storage(e.to_string()))??;
        if let SaveResult::Stored(evicted) = result {
            if let Some(old_key) = evicted {
                cache.observations.remove(&old_key);
            }
            cache.observations.insert(new_key, observation);
        }
        if split_view {
            cache.split_view_size = Some(tree_size);
            eprintln!(
                "GOSSIP_SPLIT_VIEW {}",
                serde_json::json!({
                    "log_id": &self.config.log_id,
                    "tree_size": tree_size,
                })
            );
            return Err(WitnessError::SplitViewDetected {
                log_id: self.config.log_id.clone(),
                tree_size,
            });
        }
        Ok(())
    }

    /// Return alerts valid under the current policy; retain former-policy files
    /// on disk so users can verify archived alerts with their former trust set.
    pub async fn alerts(&self, now: i64) -> Result<Vec<SplitViewEvidence>, WitnessError> {
        let store = self.store.clone();
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || {
            let alerts = store.alerts(&config.log_id)?;
            Ok::<Vec<SplitViewEvidence>, WitnessError>(
                alerts
                    .into_iter()
                    .filter(|alert| {
                        alert
                            .verify(
                                &config.log_id,
                                &config.operator_pubkey,
                                &config.trusted_observers,
                                now,
                            )
                            .is_ok()
                    })
                    .collect(),
            )
        })
        .await
        .map_err(|e| WitnessError::Storage(e.to_string()))?
    }
}
