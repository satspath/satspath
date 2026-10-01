use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::sign_message;
use crate::crypto::verify_message_signature;
use crate::Result;

use super::BitcoinAnchor;

pub const CHECKPOINT_DOMAIN: &str = "SatsPathTransparencyCheckpointV1";
pub const OPERATOR_ROTATION_AUTH_DOMAIN: &str = "SatsPathOperatorKeyRotationAuthorizationV1";
pub const OPERATOR_ROTATION_ACCEPT_DOMAIN: &str = "SatsPathOperatorKeyRotationAcceptanceV1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparencyLogIdentity {
    pub log_id: String,
    pub operator_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorKeyRotation {
    pub version: u16,
    pub log_id: String,
    pub previous_operator_pubkey: String,
    pub new_operator_pubkey: String,
    pub previous_checkpoint_hash: String,
    pub sequence: u64,
    pub rotated_at: i64,
    pub old_key_authorization: String,
    pub new_key_acceptance: String,
}

impl OperatorKeyRotation {
    fn message(&self, domain: &str) -> String {
        format!(
            "{domain}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.log_id,
            self.previous_operator_pubkey,
            self.new_operator_pubkey,
            self.previous_checkpoint_hash,
            self.sequence,
            self.rotated_at
        )
    }

    pub fn create(
        log_id: String,
        old: &SecretKey,
        new: &SecretKey,
        previous_checkpoint_hash: String,
        sequence: u64,
        rotated_at: i64,
    ) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let previous_operator_pubkey =
            hex::encode(secp256k1::PublicKey::from_secret_key(&secp, old).serialize());
        let new_operator_pubkey =
            hex::encode(secp256k1::PublicKey::from_secret_key(&secp, new).serialize());
        let mut rotation = Self {
            version: 1,
            log_id,
            previous_operator_pubkey,
            new_operator_pubkey,
            previous_checkpoint_hash,
            sequence,
            rotated_at,
            old_key_authorization: String::new(),
            new_key_acceptance: String::new(),
        };
        rotation.old_key_authorization =
            sign_message(&rotation.message(OPERATOR_ROTATION_AUTH_DOMAIN), old);
        rotation.new_key_acceptance =
            sign_message(&rotation.message(OPERATOR_ROTATION_ACCEPT_DOMAIN), new);
        rotation
    }

    pub fn verify(&self) -> Result<bool> {
        if self.version != 1
            || self.log_id.is_empty()
            || self.previous_checkpoint_hash.len() != 64
            || self.sequence == 0
        {
            return Ok(false);
        }
        Ok(verify_message_signature(
            &self.message(OPERATOR_ROTATION_AUTH_DOMAIN),
            &self.old_key_authorization,
            &self.previous_operator_pubkey,
        )? && verify_message_signature(
            &self.message(OPERATOR_ROTATION_ACCEPT_DOMAIN),
            &self.new_key_acceptance,
            &self.new_operator_pubkey,
        )?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparencyCheckpoint {
    pub version: u16,
    pub log_id: String,
    pub log_size: u64,
    pub log_root: String,
    pub map_root: Option<String>,
    pub previous_checkpoint_hash: Option<String>,
    pub created_at: i64,
    pub operator_pubkey: String,
    pub operator_sequence: u64,
    pub operator_rotation: Option<OperatorKeyRotation>,
    pub operator_signature: String,
    pub bitcoin_anchor: Option<BitcoinAnchor>,
}

impl TransparencyCheckpoint {
    pub fn signing_message(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.operator_signature.clear();
        let value = serde_json::to_value(unsigned)?;
        let canonical = canonical_json::to_string(&value)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        Ok(format!("{CHECKPOINT_DOMAIN}\n{canonical}"))
    }

    pub fn sign(&mut self, secret_key: &SecretKey) -> Result<()> {
        self.operator_signature = sign_message(&self.signing_message()?, secret_key);
        Ok(())
    }

    pub fn checkpoint_hash(&self) -> Result<String> {
        // Stable anchor identity: the Bitcoin receipt is deliberately excluded
        // to avoid a circular txid -> checkpoint -> txid commitment. The
        // operator signature still commits to the receipt via signing_message.
        let mut core = self.clone();
        core.operator_signature.clear();
        core.bitcoin_anchor = None;
        let canonical = canonical_json::to_string(&serde_json::to_value(core)?)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        let mut h = Sha256::new();
        h.update(b"SatsPathTransparencyCheckpointHashV1");
        h.update(canonical.as_bytes());
        Ok(hex::encode(h.finalize()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedCheckpoint {
    pub log_id: String,
    pub operator_pubkey: String,
    pub operator_sequence: u64,
    pub tree_size: u64,
    pub root_hash: String,
    pub checkpoint_hash: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointComparison {
    FirstSeen,
    Unchanged,
    ConsistentExtension,
}
