//! Gossip monitor, durable signed evidence and Nostr relay transport.

mod store;
mod transport;

pub use store::GossipStore;
pub use transport::{run_relay, validate_relay_url, NostrGossipEvent};

use std::sync::Arc;

use satspath_core::transparency::{
    compare_gossip_observations, GossipComparison, GossipObservation, SplitViewEvidence,
    MAX_GOSSIP_BYTES,
};
use tokio::sync::Mutex;

use crate::WitnessError;

/// The operator key is an out-of-band trust anchor; a relay never chooses it.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub log_id: String,
    pub operator_pubkey: String,
    pub trusted_observers: Vec<String>,
}

impl GossipConfig {
    pub fn validate(&self) -> Result<(), WitnessError> {
        let mut distinct_identities = std::collections::HashSet::new();
        if self.log_id.is_empty()
            || self.log_id.len() > 256
            || self.operator_pubkey.len() != 66
            || self.trusted_observers.len() < 2
            || self.trusted_observers.len() > 32
            || secp256k1::PublicKey::from_slice(
                &hex::decode(&self.operator_pubkey).map_err(|_| WitnessError::InvalidSignature)?,
            )
            .is_err()
            || self.trusted_observers.iter().any(|key| {
                let identity = hex::decode(key)
                    .ok()
                    .filter(|_| key.len() == 66)
                    .and_then(|bytes| secp256k1::PublicKey::from_slice(&bytes).ok())
                    .map(|key| key.x_only_public_key().0.serialize());
                identity.is_none_or(|pubkey| !distinct_identities.insert(pubkey))
            })
        {
            return Err(WitnessError::InvalidSignature);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct GossipMonitor {
    config: GossipConfig,
    store: GossipStore,
    write_lock: Arc<Mutex<()>>,
}

impl GossipMonitor {
    pub fn new(config: GossipConfig, store: GossipStore) -> Result<Self, WitnessError> {
        config.validate()?;
        Ok(Self {
            config,
            store,
            write_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    pub fn store(&self) -> &GossipStore {
        &self.store
    }

    /// Saves only validated observations and returns newly recorded alerts.
    pub async fn ingest(
        &self,
        observation: GossipObservation,
        now: i64,
    ) -> Result<Vec<SplitViewEvidence>, WitnessError> {
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
        let _lock = self.write_lock.lock().await;
        let previous = self.store.observations(&self.config.log_id)?;
        let mut alerts = Vec::new();
        for older in &previous {
            older
                .verify_evidence(
                    &self.config.log_id,
                    &self.config.operator_pubkey,
                    &self.config.trusted_observers,
                )
                .map_err(|_| WitnessError::InvalidSignature)?;
            if older.observer_pubkey == observation.observer_pubkey {
                continue;
            }
            if let GossipComparison::SplitView(evidence) = compare_gossip_observations(
                older,
                &observation,
                &self.config.log_id,
                &self.config.operator_pubkey,
                &self.config.trusted_observers,
                now,
            )
            .map_err(|_| WitnessError::InvalidSignature)?
            {
                if self.store.save_alert(&evidence)? {
                    alerts.push(*evidence);
                }
            }
        }
        self.store.save_observation(&observation)?;
        Ok(alerts)
    }

    /// Verify persisted evidence on every read, rather than trusting JSON files.
    pub fn alerts(&self, now: i64) -> Result<Vec<SplitViewEvidence>, WitnessError> {
        let alerts = self.store.alerts(&self.config.log_id)?;
        for alert in &alerts {
            alert
                .verify(
                    &self.config.log_id,
                    &self.config.operator_pubkey,
                    &self.config.trusted_observers,
                    now,
                )
                .map_err(|_| WitnessError::InvalidSignature)?;
        }
        Ok(alerts)
    }
}
