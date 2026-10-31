use serde::{Deserialize, Serialize};

use super::{
    MerkleConsistencyProof, MerkleInclusionProof, NameEvent, StateMapProof, TransparencyCheckpoint,
};
use crate::SignedPaymentProfile;

/// BIP340 verifies x-only keys: P, -P and alternate encodings are one signer.
pub fn witness_signing_identity(pubkey: &str) -> Option<String> {
    pubkey
        .parse::<secp256k1::PublicKey>()
        .ok()
        .map(|key| key.x_only_public_key().0.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceDescriptor {
    pub version: u16,
    pub domain: String,
    pub log_id: String,
    pub authority_pubkey: String,
    pub endpoint_urls: Vec<String>,
    pub witness_quorum: u8,
    pub witness_pubkeys: Vec<String>,
    pub valid_from: i64,
    pub expires_at: i64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessCosignature {
    pub version: u16,
    pub witness_id: String,
    pub witness_pubkey: String,
    pub checkpoint_hash: String,
    pub tree_size: u64,
    pub timestamp: i64,
    pub signature: String,
}

impl NamespaceDescriptor {
    pub fn signing_message(&self) -> crate::Result<String> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let canonical = canonical_json::to_string(&serde_json::to_value(unsigned)?)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        Ok(format!("SatsPathNamespaceDescriptorV1\n{canonical}"))
    }

    pub fn sign(&mut self, key: &secp256k1::SecretKey) -> crate::Result<()> {
        self.signature = crate::sign_message(&self.signing_message()?, key);
        Ok(())
    }

    pub fn verify(&self, now: i64) -> crate::Result<bool> {
        let witness_keys: std::collections::HashSet<_> = self
            .witness_pubkeys
            .iter()
            .filter_map(|key| witness_signing_identity(key))
            .collect();
        if self.version != 2
            || self.valid_from > now
            || self.expires_at <= now
            || self.expires_at <= self.valid_from
            || self.endpoint_urls.is_empty()
            || self.witness_quorum as usize > self.witness_pubkeys.len()
            || witness_keys.len() != self.witness_pubkeys.len()
        {
            return Ok(false);
        }
        crate::verify_message_signature(
            &self.signing_message()?,
            &self.signature,
            &self.authority_pubkey,
        )
    }
}

/// Compute the canonical domain-separated message string for a witness cosignature.
pub fn witness_cosignature_message(
    witness_id: &str,
    checkpoint_hash: &str,
    tree_size: u64,
    timestamp: i64,
) -> String {
    format!(
        "SatsPathWitnessV1\nwitness_id={witness_id}\ncheckpoint_hash={checkpoint_hash}\ntree_size={tree_size}\ntimestamp={timestamp}"
    )
}

impl WitnessCosignature {
    pub fn signing_message(&self) -> String {
        witness_cosignature_message(
            &self.witness_id,
            &self.checkpoint_hash,
            self.tree_size,
            self.timestamp,
        )
    }

    pub fn verify(&self, checkpoint: &TransparencyCheckpoint) -> crate::errors::Result<bool> {
        let cp_hash = checkpoint.checkpoint_hash()?;
        if self.checkpoint_hash != cp_hash || self.tree_size != checkpoint.log_size {
            return Ok(false);
        }
        let msg = self.signing_message();
        crate::crypto::verify_message_signature(&msg, &self.signature, &self.witness_pubkey)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionEnvelope {
    pub version: u16,
    pub identifier: String,
    pub namespace_descriptor: NamespaceDescriptor,
    pub signed_profile: SignedPaymentProfile,
    pub name_events: Vec<NameEvent>,
    pub inclusion_proof: MerkleInclusionProof,
    pub checkpoint: TransparencyCheckpoint,
    pub consistency_proof: Option<MerkleConsistencyProof>,
    pub current_state_proof: Option<StateMapProof>,
    pub witness_cosignatures: Vec<WitnessCosignature>,
    pub served_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolutionRequest {
    pub identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_tree_size: Option<u64>,
    #[serde(default)]
    pub include_history: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRole {
    Primary,
    Replica,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplicaEndpoint {
    pub url: String,
    pub role: EndpointRole,
    pub priority: u8,
}
