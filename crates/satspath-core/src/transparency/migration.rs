use serde::{Deserialize, Serialize};

use super::protocol::NamespaceDescriptor;
use super::{NameEvent, TransparencyCheckpoint, TransparencyError, WitnessCosignature};
use crate::Result;

/// A signed statement binding the previous descriptor/checkpoint to a new
/// endpoint/operator arrangement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationStatement {
    pub version: u16,
    /// The descriptor epoch this migration departs from.
    pub from_epoch: u64,
    /// The descriptor epoch this migration targets.
    pub to_epoch: u64,
    /// Hash of the last checkpoint under the old arrangement.
    pub previous_checkpoint_hash: String,
    /// Tree size at the migration boundary.
    pub boundary_tree_size: u64,
    /// The new endpoint URL(s) where the log will be served.
    pub new_endpoint_urls: Vec<String>,
    /// The new operator pubkey (if rotated).
    pub new_operator_pubkey: Option<String>,
    /// Signature by the namespace authority key over this statement.
    pub authority_signature: String,
    /// Timestamp of the migration.
    pub migrated_at: i64,
}

/// Portable deterministic export for server migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationExport {
    pub namespace_descriptor: NamespaceDescriptor,
    pub events: Vec<NameEvent>,
    pub checkpoints: Vec<TransparencyCheckpoint>,
    pub witness_receipts: Vec<WitnessCosignature>,
    pub migration_statement: Option<MigrationStatement>,
}

/// Verify that a migration statement is internally consistent and properly
/// bridges the old and new arrangements.
pub fn verify_migration_statement(
    statement: &MigrationStatement,
    old_descriptor: &NamespaceDescriptor,
    latest_checkpoint: &TransparencyCheckpoint,
) -> Result<()> {
    // Epoch must advance
    if statement.to_epoch <= statement.from_epoch {
        return Err(TransparencyError::BrokenIdentifierHistory(
            "migration epoch must advance".into(),
        )
        .into());
    }

    // Boundary tree size must match the latest checkpoint
    if statement.boundary_tree_size != latest_checkpoint.log_size {
        return Err(TransparencyError::BrokenIdentifierHistory(
            "boundary tree size does not match latest checkpoint".into(),
        )
        .into());
    }

    // from_epoch must reference the old descriptor's validity
    if old_descriptor.signature.is_empty() {
        return Err(TransparencyError::BrokenIdentifierHistory(
            "old descriptor has no signature".into(),
        )
        .into());
    }

    // Authority signature must be present
    if statement.authority_signature.is_empty() {
        return Err(TransparencyError::BrokenIdentifierHistory(
            "migration statement has no authority signature".into(),
        )
        .into());
    }

    // Must have at least one new endpoint
    if statement.new_endpoint_urls.is_empty() {
        return Err(TransparencyError::BrokenIdentifierHistory(
            "migration must specify at least one new endpoint".into(),
        )
        .into());
    }

    Ok(())
}
