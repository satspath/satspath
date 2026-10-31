//! Authenticated renewal of the existing checkpoint chain, without name events.
use super::{
    verify_checkpoint, verify_checkpoint_transition, MerkleConsistencyProof, PinnedCheckpoint,
    TransparencyCheckpoint, TransparencyError,
};
use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FreshnessPolicy {
    pub max_age_secs: i64,
    pub future_skew_secs: i64,
}

impl Default for FreshnessPolicy {
    fn default() -> Self {
        Self {
            max_age_secs: 900,
            future_skew_secs: 60,
        }
    }
}

impl FreshnessPolicy {
    pub fn validate(&self) -> Result<()> {
        if !(30..=86_400).contains(&self.max_age_secs)
            || !(0..=300).contains(&self.future_skew_secs)
        {
            return Err(TransparencyError::InvalidFreshnessPolicy.into());
        }
        Ok(())
    }

    pub fn check(&self, checkpoint: &TransparencyCheckpoint, now: i64) -> Result<()> {
        self.validate()?;
        if checkpoint.created_at > now.saturating_add(self.future_skew_secs) {
            return Err(TransparencyError::CheckpointClockSkew.into());
        }
        if checkpoint.created_at < now.saturating_sub(self.max_age_secs) {
            return Err(TransparencyError::ExpiredCheckpoint.into());
        }
        Ok(())
    }
}

/// Durable position in the checkpoint journal, separate from owner event sequence
/// and operator-key rotation sequence. Existing wire checkpoint fields are reused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCursor {
    pub index: u64,
    pub checkpoint: TransparencyCheckpoint,
}

/// Verify an adjacent journal transition. Freshness is checked separately on the
/// final head: historical backfill is allowed to contain expired predecessors.
pub fn verify_checkpoint_successor(
    previous: &TransparencyCheckpoint,
    next: &TransparencyCheckpoint,
    consistency: Option<&MerkleConsistencyProof>,
) -> Result<()> {
    if !verify_checkpoint(previous)? || !verify_checkpoint(next)? || previous.log_id != next.log_id
    {
        return Err(TransparencyError::InvalidCheckpointSignature.into());
    }
    if next.log_size < previous.log_size {
        return Err(TransparencyError::CheckpointRollback.into());
    }
    if next.log_size == previous.log_size
        && (next.log_root != previous.log_root || next.map_root != previous.map_root)
    {
        return Err(TransparencyError::ConflictingCheckpoint.into());
    }
    if next.previous_checkpoint_hash.as_deref() != Some(previous.checkpoint_hash()?.as_str()) {
        return Err(TransparencyError::CheckpointHistoryGap.into());
    }
    if next.created_at < previous.created_at
        || (next.log_size == previous.log_size
            && next.operator_sequence == previous.operator_sequence
            && next.created_at <= previous.created_at)
    {
        return Err(TransparencyError::CheckpointClockSkew.into());
    }
    let pin = PinnedCheckpoint {
        log_id: previous.log_id.clone(),
        operator_pubkey: previous.operator_pubkey.clone(),
        operator_sequence: previous.operator_sequence,
        tree_size: previous.log_size,
        root_hash: previous.log_root.clone(),
        checkpoint_hash: previous.checkpoint_hash()?,
        first_seen_at: previous.created_at,
        last_seen_at: previous.created_at,
    };
    verify_checkpoint_transition(&pin, next, consistency)
}
