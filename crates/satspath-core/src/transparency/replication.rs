use serde::{Deserialize, Serialize};

use crate::Result;

use super::protocol::{EndpointRole, ReplicaEndpoint};
use super::{TransparencyCheckpoint, TransparencyError};

/// Maximum allowed checkpoint age (in seconds) for a stale replica to still serve.
pub const MAX_STALENESS_WINDOW_SECS: i64 = 3600; // 1 hour

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplicaHealth {
    pub endpoint: ReplicaEndpoint,
    pub latest_checkpoint_age_secs: i64,
    pub latest_tree_size: u64,
    pub is_healthy: bool,
}

/// Select the best endpoint from a list of replicas, preferring:
/// 1. Primary endpoints first.
/// 2. Among replicas, the one with the largest tree_size (freshest).
/// 3. Reject any endpoint whose checkpoint age exceeds the staleness window.
pub fn select_endpoint(
    _endpoints: &[ReplicaEndpoint],
    health: &[ReplicaHealth],
) -> Option<ReplicaEndpoint> {
    // First try to find a healthy primary
    if let Some(primary) = health
        .iter()
        .find(|h| h.endpoint.role == EndpointRole::Primary && h.is_healthy)
    {
        return Some(primary.endpoint.clone());
    }

    // Fall back to the freshest healthy replica within staleness window
    health
        .iter()
        .filter(|h| {
            h.endpoint.role == EndpointRole::Replica
                && h.is_healthy
                && h.latest_checkpoint_age_secs <= MAX_STALENESS_WINDOW_SECS
        })
        .max_by_key(|h| h.latest_tree_size)
        .map(|h| h.endpoint.clone())
}

/// Detect equivocation: two checkpoints at the same tree size but different roots.
pub fn detect_equivocation(
    cp_a: &TransparencyCheckpoint,
    cp_b: &TransparencyCheckpoint,
) -> Result<()> {
    if cp_a.log_size == cp_b.log_size && cp_a.log_root != cp_b.log_root {
        return Err(TransparencyError::ConflictingCheckpoint.into());
    }
    Ok(())
}

/// Validate that a replica's checkpoint does not roll back the tree size
/// compared to a previously pinned checkpoint.
pub fn validate_no_rollback(
    pinned_tree_size: u64,
    replica_checkpoint: &TransparencyCheckpoint,
) -> Result<()> {
    if replica_checkpoint.log_size < pinned_tree_size {
        return Err(TransparencyError::CheckpointRollback.into());
    }
    Ok(())
}
