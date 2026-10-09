use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use satspath_core::transparency::{GossipObservation, SplitViewEvidence, MAX_GOSSIP_BYTES};
use sha2::{Digest, Sha256};

use crate::WitnessError;

const MAX_RECORDS: usize = 512;

#[derive(Clone)]
pub struct GossipStore {
    root: PathBuf,
}

fn storage_error(error: impl std::fmt::Display) -> WitnessError {
    WitnessError::Storage(error.to_string())
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
) -> Result<T, WitnessError> {
    let metadata = fs::symlink_metadata(path).map_err(storage_error)?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(storage_error("invalid gossip evidence file"));
    }
    serde_json::from_slice(&fs::read(path).map_err(storage_error)?).map_err(storage_error)
}

fn records<T: serde::de::DeserializeOwned>(
    dir: &Path,
    max_bytes: u64,
) -> Result<Vec<T>, WitnessError> {
    if !dir.try_exists().map_err(storage_error)? {
        return Ok(Vec::new());
    }
    let mut results = Vec::new();
    for entry in fs::read_dir(dir).map_err(storage_error)? {
        let entry = entry.map_err(storage_error)?;
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            if results.len() >= MAX_RECORDS {
                return Err(storage_error("gossip evidence record limit exceeded"));
            }
            results.push(read_json(&entry.path(), max_bytes)?);
        }
    }
    Ok(results)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), WitnessError> {
    let parent = path
        .parent()
        .ok_or_else(|| storage_error("missing gossip directory"))?;
    fs::create_dir_all(parent).map_err(storage_error)?;
    // One writer per process is guarded by GossipMonitor. The temporary name
    // depends on the content, so concurrent processes cannot share an open tmp.
    let tmp = parent.join(format!("{}.{}.tmp", std::process::id(), digest(bytes)));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(storage_error)?;
    let result = (|| {
        file.write_all(bytes).map_err(storage_error)?;
        file.sync_all().map_err(storage_error)?;
        fs::rename(&tmp, path).map_err(storage_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

impl GossipStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, WitnessError> {
        let root = root.as_ref();
        fs::create_dir_all(root.join("observations")).map_err(storage_error)?;
        fs::create_dir_all(root.join("alerts")).map_err(storage_error)?;
        Ok(Self {
            root: root.to_owned(),
        })
    }

    fn log_dir(&self, kind: &str, log_id: &str) -> PathBuf {
        self.root.join(kind).join(digest(log_id.as_bytes()))
    }

    pub fn observations(&self, log_id: &str) -> Result<Vec<GossipObservation>, WitnessError> {
        records(
            &self.log_dir("observations", log_id),
            MAX_GOSSIP_BYTES as u64,
        )
    }

    pub fn save_observation(&self, observation: &GossipObservation) -> Result<(), WitnessError> {
        let log_id = &observation.checkpoint.log_id;
        let dir = self.log_dir("observations", log_id);
        let key = format!(
            "{}:{}",
            observation.observer_pubkey,
            observation
                .checkpoint
                .checkpoint_hash()
                .map_err(storage_error)?
        );
        let path = dir.join(format!("{}.json", digest(key.as_bytes())));
        if path.try_exists().map_err(storage_error)? {
            let previous: GossipObservation = read_json(&path, MAX_GOSSIP_BYTES as u64)?;
            if previous.observed_at >= observation.observed_at {
                return Ok(());
            }
        } else if self.observations(log_id)?.len() >= MAX_RECORDS {
            return Err(storage_error("gossip evidence record limit exceeded"));
        }
        let bytes = serde_json::to_vec(observation).map_err(storage_error)?;
        if bytes.len() > MAX_GOSSIP_BYTES {
            return Err(storage_error("gossip observation exceeds byte limit"));
        }
        atomic_write(&path, &bytes)
    }

    pub fn alerts(&self, log_id: &str) -> Result<Vec<SplitViewEvidence>, WitnessError> {
        records(
            &self.log_dir("alerts", log_id),
            (2 * MAX_GOSSIP_BYTES + 2048) as u64,
        )
    }

    /// The key is the unordered pair of operator commitments; relay replays and
    /// extra observers cannot create duplicate alerts for the same fork.
    pub fn save_alert(&self, evidence: &SplitViewEvidence) -> Result<bool, WitnessError> {
        let log_id = &evidence.first.checkpoint.log_id;
        let dir = self.log_dir("alerts", log_id);
        let mut hashes = [
            evidence
                .first
                .checkpoint
                .checkpoint_hash()
                .map_err(storage_error)?,
            evidence
                .conflicting
                .checkpoint
                .checkpoint_hash()
                .map_err(storage_error)?,
        ];
        hashes.sort();
        let key = format!(
            "{}:{}:{}",
            evidence.first.checkpoint.log_size, hashes[0], hashes[1]
        );
        let path = dir.join(format!("{}.json", digest(key.as_bytes())));
        if path.try_exists().map_err(storage_error)? {
            return Ok(false);
        }
        if self.alerts(log_id)?.len() >= MAX_RECORDS {
            return Err(storage_error("gossip alert limit exceeded"));
        }
        let bytes = serde_json::to_vec_pretty(evidence).map_err(storage_error)?;
        atomic_write(&path, &bytes)?;
        Ok(true)
    }
}
