//! Operator-signed checkpoint evidence exchanged by independent observers.

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{sign_message, verify_message_signature};
use crate::Result;

use super::{
    verify_checkpoint, verify_consistency_proof, MerkleConsistencyProof, TransparencyCheckpoint,
    TransparencyError,
};

/// Normalize Schnorr identities so negated compressed keys cannot count twice.
fn observer_identity(pubkey: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(pubkey).map_err(|_| TransparencyError::InvalidGossipObservation)?;
    let point =
        PublicKey::from_slice(&bytes).map_err(|_| TransparencyError::InvalidGossipObservation)?;
    Ok(point.x_only_public_key().0.serialize())
}

pub const GOSSIP_KIND: u64 = 3978;
pub const MAX_GOSSIP_BYTES: usize = 64 * 1024;
pub const GOSSIP_MAX_AGE_SECS: i64 = 7 * 24 * 3600;
pub const GOSSIP_FUTURE_SKEW_SECS: i64 = 300;
const GOSSIP_DOMAIN: &str = "SatsPathCheckpointGossipV1";

/// Full operator-signed checkpoint, witnessed by an independent observer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GossipObservation {
    pub version: u16,
    pub checkpoint: TransparencyCheckpoint,
    pub observer_pubkey: String,
    pub observed_at: i64,
    /// Required when this observer advances beyond its previously advertised pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_proof: Option<MerkleConsistencyProof>,
    pub signature: String,
}

impl GossipObservation {
    /// Canonical, domain-separated payload signed by the observer key.
    fn signing_message(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let canonical = canonical_json::to_string(&serde_json::to_value(unsigned)?)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        Ok(format!("{GOSSIP_DOMAIN}\n{canonical}"))
    }

    /// Sign an initially observed or unchanged checkpoint without an advance proof.
    pub fn sign(
        checkpoint: TransparencyCheckpoint,
        secret: &SecretKey,
        observed_at: i64,
    ) -> Result<Self> {
        Self::sign_with_proof(checkpoint, None, secret, observed_at)
    }

    /// Bind a checkpoint-bound RFC 6962 proof to a signed advancement.
    pub fn sign_with_proof(
        checkpoint: TransparencyCheckpoint,
        consistency_proof: Option<MerkleConsistencyProof>,
        secret: &SecretKey,
        observed_at: i64,
    ) -> Result<Self> {
        let observer_pubkey =
            hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), secret).serialize());
        let mut observation = Self {
            version: 1,
            checkpoint,
            observer_pubkey,
            observed_at,
            consistency_proof,
            signature: String::new(),
        };
        observation.signature = sign_message(&observation.signing_message()?, secret);
        Ok(observation)
    }

    /// Verify both signatures and the independently configured trust anchors.
    /// Historical observations remain valid evidence after their relay replay window.
    pub fn verify_evidence(
        &self,
        log_id: &str,
        operator_pubkey: &str,
        observers: &[String],
    ) -> Result<()> {
        if self.version != 1
            || log_id.is_empty()
            || self.checkpoint.log_id != log_id
            || self.checkpoint.operator_pubkey != operator_pubkey
            || !observers.iter().any(|key| key == &self.observer_pubkey)
            || !verify_checkpoint(&self.checkpoint).unwrap_or(false)
            || !verify_message_signature(
                &self.signing_message()?,
                &self.signature,
                &self.observer_pubkey,
            )
            .unwrap_or(false)
            || self.consistency_proof.as_ref().is_some_and(|proof| {
                proof.new_tree_size != self.checkpoint.log_size
                    || proof.new_root != self.checkpoint.log_root
                    || !verify_consistency_proof(proof).unwrap_or(false)
            })
        {
            return Err(TransparencyError::InvalidGossipObservation.into());
        }
        Ok(())
    }

    /// Network-ingest freshness is separate from permanent evidence validity.
    pub fn verify(
        &self,
        log_id: &str,
        operator_pubkey: &str,
        observers: &[String],
        now: i64,
    ) -> Result<()> {
        self.verify_evidence(log_id, operator_pubkey, observers)?;
        if self.observed_at < now.saturating_sub(GOSSIP_MAX_AGE_SECS)
            || self.observed_at > now.saturating_add(GOSSIP_FUTURE_SKEW_SECS)
        {
            return Err(TransparencyError::InvalidGossipObservation.into());
        }
        Ok(())
    }
}

/// Archivable pair of independent, operator-signed incompatible checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SplitViewEvidence {
    pub first: GossipObservation,
    pub conflicting: GossipObservation,
    pub detected_at: i64,
}

/// Only a conflicting root at the same size proves a split view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipComparison {
    SameView,
    DifferentSizes,
    SplitView(Box<SplitViewEvidence>),
}

/// Different sizes are inconclusive without a verified consistency proof.
pub fn compare_gossip_observations(
    first: &GossipObservation,
    second: &GossipObservation,
    log_id: &str,
    operator_pubkey: &str,
    observers: &[String],
    now: i64,
) -> Result<GossipComparison> {
    first.verify_evidence(log_id, operator_pubkey, observers)?;
    second.verify_evidence(log_id, operator_pubkey, observers)?;
    compare_verified_gossip_observations(first, second, now)
}

/// Compare already verified observations inside the core's authenticated API.
fn compare_verified_gossip_observations(
    first: &GossipObservation,
    second: &GossipObservation,
    now: i64,
) -> Result<GossipComparison> {
    if first.checkpoint.log_id != second.checkpoint.log_id
        || first.checkpoint.operator_pubkey != second.checkpoint.operator_pubkey
    {
        return Err(TransparencyError::InvalidGossipObservation.into());
    }
    if observer_identity(&first.observer_pubkey)? == observer_identity(&second.observer_pubkey)? {
        return Err(TransparencyError::InvalidGossipObservation.into());
    }
    if first.checkpoint.log_size != second.checkpoint.log_size {
        return Ok(GossipComparison::DifferentSizes);
    }
    if first.checkpoint.log_root == second.checkpoint.log_root
        && first.checkpoint.map_root == second.checkpoint.map_root
    {
        return Ok(GossipComparison::SameView);
    }
    Ok(GossipComparison::SplitView(Box::new(SplitViewEvidence {
        first: first.clone(),
        conflicting: second.clone(),
        detected_at: now,
    })))
}

impl SplitViewEvidence {
    /// Re-verify historical evidence under an explicit operator and observer policy.
    pub fn verify(
        &self,
        log_id: &str,
        operator_pubkey: &str,
        observers: &[String],
        now: i64,
    ) -> Result<()> {
        if self.detected_at > now.saturating_add(GOSSIP_FUTURE_SKEW_SECS) {
            return Err(TransparencyError::InvalidGossipObservation.into());
        }
        if !matches!(
            compare_gossip_observations(
                &self.first,
                &self.conflicting,
                log_id,
                operator_pubkey,
                observers,
                self.detected_at
            )?,
            GossipComparison::SplitView(_)
        ) {
            return Err(TransparencyError::InvalidGossipObservation.into());
        }
        Ok(())
    }
}

/// Deterministic relay filter tag (not anonymity for low-entropy log IDs).
pub fn gossip_topic(log_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"SatsPathCheckpointGossipTopicV1:");
    digest.update(log_id.as_bytes());
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_identity_keypair;

    /// Build a signed checkpoint with independently chosen test roots.
    fn checkpoint(key: &SecretKey, root: &str, size: u64) -> TransparencyCheckpoint {
        let mut cp = TransparencyCheckpoint {
            version: 1,
            log_id: "example-log".into(),
            log_size: size,
            log_root: root.into(),
            map_root: None,
            previous_checkpoint_hash: None,
            created_at: 1_800_000_000,
            operator_pubkey: hex::encode(
                PublicKey::from_secret_key(&Secp256k1::new(), key).serialize(),
            ),
            operator_sequence: 0,
            operator_rotation: None,
            operator_signature: String::new(),
            bitcoin_anchor: None,
        };
        cp.sign(key).unwrap();
        cp
    }

    /// Only two distinct trusted Schnorr observers can report a valid fork.
    #[test]
    fn only_signed_operator_evidence_from_independent_trusted_observers_alerts() {
        let operator = generate_identity_keypair();
        let alice = generate_identity_keypair();
        let bob = generate_identity_keypair();
        let now = 1_800_000_100;
        let a = GossipObservation::sign(
            checkpoint(&operator.secret_key, &"ab".repeat(32), 10),
            &alice.secret_key,
            now,
        )
        .unwrap();
        let b = GossipObservation::sign(
            checkpoint(&operator.secret_key, &"cd".repeat(32), 10),
            &bob.secret_key,
            now,
        )
        .unwrap();
        let trusted = vec![a.observer_pubkey.clone(), b.observer_pubkey.clone()];
        let operator_key = &a.checkpoint.operator_pubkey;
        let result =
            compare_gossip_observations(&a, &b, "example-log", operator_key, &trusted, now)
                .unwrap();
        let GossipComparison::SplitView(evidence) = result else {
            panic!("missing split view");
        };
        evidence
            .verify(
                "example-log",
                operator_key,
                &trusted,
                now + GOSSIP_MAX_AGE_SECS + 1,
            )
            .unwrap();
        assert!(
            compare_gossip_observations(&a, &a, "example-log", operator_key, &trusted, now)
                .is_err()
        );

        let mut unsigned = b.clone();
        unsigned.checkpoint.log_root = "ef".repeat(32);
        assert!(unsigned
            .verify("example-log", operator_key, &trusted, now)
            .is_err());
        let mut tampered = b.clone();
        tampered.observed_at += 1;
        assert!(tampered
            .verify("example-log", operator_key, &trusted, now)
            .is_err());
        assert!(b
            .verify(
                "example-log",
                operator_key,
                std::slice::from_ref(&a.observer_pubkey),
                now
            )
            .is_err());
        assert!(b.verify("other-log", operator_key, &trusted, now).is_err());
        assert!(b
            .verify("example-log", &"00".repeat(33), &trusted, now)
            .is_err());
        assert!(b
            .verify(
                "example-log",
                operator_key,
                &trusted,
                now + GOSSIP_MAX_AGE_SECS + 1
            )
            .is_err());
    }

    /// An ahead peer is not proof of operator equivocation.
    #[test]
    fn same_root_and_different_sizes_are_not_proof_of_a_fork() {
        let operator = generate_identity_keypair();
        let alice = generate_identity_keypair();
        let bob = generate_identity_keypair();
        let now = 1_800_000_100;
        let a = GossipObservation::sign(
            checkpoint(&operator.secret_key, &"ab".repeat(32), 10),
            &alice.secret_key,
            now,
        )
        .unwrap();
        let trusted = vec![
            a.observer_pubkey.clone(),
            hex::encode(bob.public_key.serialize()),
        ];
        let b = GossipObservation::sign(a.checkpoint.clone(), &bob.secret_key, now).unwrap();
        assert_eq!(
            compare_gossip_observations(
                &a,
                &b,
                "example-log",
                &a.checkpoint.operator_pubkey,
                &trusted,
                now
            )
            .unwrap(),
            GossipComparison::SameView
        );
        let ahead = GossipObservation::sign(
            checkpoint(&operator.secret_key, &"cd".repeat(32), 11),
            &bob.secret_key,
            now,
        )
        .unwrap();
        assert_eq!(
            compare_gossip_observations(
                &a,
                &ahead,
                "example-log",
                &a.checkpoint.operator_pubkey,
                &trusted,
                now
            )
            .unwrap(),
            GossipComparison::DifferentSizes
        );
        assert_ne!(gossip_topic("example-log"), gossip_topic("other-log"));
    }

    /// A state-map split is material even if log-root hashes match.
    #[test]
    fn same_merkle_root_with_conflicting_signed_state_map_is_a_split_view() {
        let operator = generate_identity_keypair();
        let alice = generate_identity_keypair();
        let bob = generate_identity_keypair();
        let now = 1_800_000_100;
        let first = checkpoint(&operator.secret_key, &"ab".repeat(32), 10);
        let mut second = first.clone();
        second.map_root = Some("cd".repeat(32));
        second.sign(&operator.secret_key).unwrap();
        let a = GossipObservation::sign(first, &alice.secret_key, now).unwrap();
        let b = GossipObservation::sign(second, &bob.secret_key, now).unwrap();
        let trusted = vec![a.observer_pubkey.clone(), b.observer_pubkey.clone()];
        assert!(matches!(
            compare_gossip_observations(
                &a,
                &b,
                "example-log",
                &a.checkpoint.operator_pubkey,
                &trusted,
                now
            )
            .unwrap(),
            GossipComparison::SplitView(_)
        ));
    }

    /// Opposite-parity compressed keys refer to the same Schnorr author.
    #[test]
    fn negating_an_observer_key_cannot_create_a_second_independent_observer() {
        let operator = generate_identity_keypair();
        let alice = generate_identity_keypair();
        let negated = alice.secret_key.negate();
        let now = 1_800_000_100;
        let a = GossipObservation::sign(
            checkpoint(&operator.secret_key, &"ab".repeat(32), 10),
            &alice.secret_key,
            now,
        )
        .unwrap();
        let b = GossipObservation::sign(
            checkpoint(&operator.secret_key, &"cd".repeat(32), 10),
            &negated,
            now,
        )
        .unwrap();
        assert_ne!(a.observer_pubkey, b.observer_pubkey);
        assert_eq!(
            observer_identity(&a.observer_pubkey).unwrap(),
            observer_identity(&b.observer_pubkey).unwrap()
        );
        let trusted = vec![a.observer_pubkey.clone(), b.observer_pubkey.clone()];
        assert!(compare_gossip_observations(
            &a,
            &b,
            "example-log",
            &a.checkpoint.operator_pubkey,
            &trusted,
            now
        )
        .is_err());
    }
}
