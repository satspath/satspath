use std::path::{Path, PathBuf};

use super::{PinnedCheckpoint, TransparencyCheckpoint, TransparencyError};
use crate::Result;

pub struct CheckpointStore {
    path: PathBuf,
}

impl CheckpointStore {
    pub fn new(dir: &Path) -> Self {
        Self {
            path: dir.join("transparency-pins.json"),
        }
    }

    pub fn load(&self) -> Result<Vec<PinnedCheckpoint>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let bytes = std::fs::read(&self.path)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| TransparencyError::CorruptStore(e.to_string()).into())
    }

    pub fn pin_verified(&self, checkpoint: &TransparencyCheckpoint) -> Result<PinnedCheckpoint> {
        let now = chrono::Utc::now().timestamp();
        let mut pins = self.load()?;
        let hash = checkpoint.checkpoint_hash()?;
        let pin = if let Some(existing) = pins.iter_mut().find(|p| p.log_id == checkpoint.log_id) {
            if existing.operator_pubkey != checkpoint.operator_pubkey {
                let rotation = checkpoint
                    .operator_rotation
                    .as_ref()
                    .ok_or(TransparencyError::UnexpectedOperatorKey)?;
                if rotation.previous_operator_pubkey != existing.operator_pubkey
                    || rotation.new_operator_pubkey != checkpoint.operator_pubkey
                    || rotation.previous_checkpoint_hash != existing.checkpoint_hash
                    || rotation.sequence != existing.operator_sequence.saturating_add(1)
                    || !rotation.verify()?
                {
                    return Err(TransparencyError::InvalidOperatorRotation.into());
                }
            }
            existing
                .operator_pubkey
                .clone_from(&checkpoint.operator_pubkey);
            existing.operator_sequence = checkpoint.operator_sequence;
            existing.tree_size = checkpoint.log_size;
            existing.root_hash.clone_from(&checkpoint.log_root);
            existing.checkpoint_hash.clone_from(&hash);
            existing.last_seen_at = now;
            existing.clone()
        } else {
            let pin = PinnedCheckpoint {
                log_id: checkpoint.log_id.clone(),
                operator_pubkey: checkpoint.operator_pubkey.clone(),
                operator_sequence: checkpoint.operator_sequence,
                tree_size: checkpoint.log_size,
                root_hash: checkpoint.log_root.clone(),
                checkpoint_hash: hash,
                first_seen_at: now,
                last_seen_at: now,
            };
            pins.push(pin.clone());
            pin
        };
        let bytes = serde_json::to_vec_pretty(&pins)?;
        let tmp = self.path.with_extension("json.tmp");
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, &self.path)?;
        Ok(pin)
    }

    /// Persist a pin only after the caller has verified signature, inclusion,
    /// consistency and operator continuity.
    pub fn pin(&self, checkpoint: &TransparencyCheckpoint) -> Result<PinnedCheckpoint> {
        self.pin_verified(checkpoint)
    }
}
