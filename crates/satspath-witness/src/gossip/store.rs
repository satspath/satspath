use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use satspath_core::transparency::{GossipObservation, SplitViewEvidence, MAX_GOSSIP_BYTES};
use sha2::{Digest, Sha256};

use crate::WitnessError;

const MAX_RECORDS: usize = 512;
const MAX_RECORDS_PER_OBSERVER: usize = 16;

pub(super) type ObservationKey = (String, String);

/// Indicates whether an authenticated observation replaced or evicted state.
pub(super) enum SaveResult {
    Stored(Option<ObservationKey>),
    Ignored,
}

/// Stable cache key for one observer's particular operator commitment.
pub(super) fn observation_key(
    observation: &GossipObservation,
) -> Result<ObservationKey, WitnessError> {
    Ok((
        observation.observer_pubkey.clone(),
        observation
            .checkpoint
            .checkpoint_hash()
            .map_err(storage_error)?,
    ))
}

/// On-disk observations and immutable, deduplicated fork alerts.
#[derive(Clone)]
pub struct GossipStore {
    root: PathBuf,
}

/// Wrap filesystem failures without exposing peer-provided content in logs.
fn storage_error(error: impl std::fmt::Display) -> WitnessError {
    WitnessError::Storage(error.to_string())
}

/// Name persistent records by content hashes rather than unchecked log IDs.
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Map a concurrent removal to `None` while propagating other I/O failures.
fn ignore_not_found<T>(result: std::io::Result<T>) -> Result<Option<T>, WitnessError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(storage_error(error)),
    }
}

/// Read one bounded regular file; never follow a local symlink.
/// Returns `None` if the file was removed concurrently.
fn read_json_if_present<T: serde::de::DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
) -> Result<Option<T>, WitnessError> {
    let Some(metadata) = ignore_not_found(fs::symlink_metadata(path))? else {
        return Ok(None);
    };
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(storage_error("invalid gossip evidence file"));
    }
    let Some(bytes) = ignore_not_found(fs::read(path))? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(storage_error)
}

/// Read one bounded regular file that is expected to exist.
fn read_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
) -> Result<T, WitnessError> {
    read_json_if_present(path, max_bytes)?
        .ok_or_else(|| storage_error("missing gossip evidence file"))
}

/// Load a bounded directory, isolating bad observations but not corrupt alerts.
fn records<T: serde::de::DeserializeOwned>(
    dir: &Path,
    max_bytes: u64,
    tolerate_invalid: bool,
) -> Result<Vec<T>, WitnessError> {
    if !dir.try_exists().map_err(storage_error)? {
        return Ok(Vec::new());
    }
    let mut results = Vec::new();
    let mut file_count = 0;
    for entry in fs::read_dir(dir).map_err(storage_error)? {
        let entry = entry.map_err(storage_error)?;
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            file_count += 1;
            if file_count > MAX_RECORDS {
                return Err(storage_error("gossip evidence record limit exceeded"));
            }
            match read_json_if_present(&entry.path(), max_bytes) {
                Ok(Some(record)) => results.push(record),
                // Removed concurrently (e.g. evicted); treat as already gone for observations.
                Ok(None) if tolerate_invalid => {}
                Ok(None) => return Err(storage_error("missing gossip evidence file")),
                Err(error) if tolerate_invalid => {
                    eprintln!("skipping unreadable stored gossip observation: {error}");
                    ignore_not_found(fs::rename(
                        entry.path(),
                        entry.path().with_extension("invalid"),
                    ))?;
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(results)
}

/// Sync a fresh temporary file before replacing a public evidence record.
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
    /// Create bounded public-observation and persistent-alert directories.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, WitnessError> {
        let root = root.as_ref();
        fs::create_dir_all(root.join("observations")).map_err(storage_error)?;
        fs::create_dir_all(root.join("alerts")).map_err(storage_error)?;
        Ok(Self {
            root: root.to_owned(),
        })
    }

    /// Isolate each log in an opaque hash-named subdirectory.
    fn log_dir(&self, kind: &str, log_id: &str) -> PathBuf {
        self.root.join(kind).join(digest(log_id.as_bytes()))
    }

    /// Read retained observations, quarantining unreadable old records.
    pub fn observations(&self, log_id: &str) -> Result<Vec<GossipObservation>, WitnessError> {
        records(
            &self.log_dir("observations", log_id),
            MAX_GOSSIP_BYTES as u64,
            true,
        )
    }

    /// Keep at most 16 checkpoints per observer and 512 per log in total.
    pub(super) fn save_observation(
        &self,
        observation: &GossipObservation,
    ) -> Result<SaveResult, WitnessError> {
        let log_id = &observation.checkpoint.log_id;
        let dir = self.log_dir("observations", log_id);
        let new_key = observation_key(observation)?;
        let key = format!("{}:{}", new_key.0, new_key.1);
        let path = dir.join(format!("{}.json", digest(key.as_bytes())));
        let mut evict = None;
        if path.try_exists().map_err(storage_error)? {
            match read_json::<GossipObservation>(&path, MAX_GOSSIP_BYTES as u64) {
                Ok(previous) if previous.observed_at >= observation.observed_at => {
                    return Ok(SaveResult::Ignored);
                }
                Err(_) => eprintln!("replacing unreadable stored gossip observation"),
                Ok(_) => {}
            }
        } else {
            let existing = self.observations(log_id)?;
            let mine: Vec<_> = existing
                .iter()
                .filter(|old| old.observer_pubkey == observation.observer_pubkey)
                .collect();
            evict = if mine.len() >= MAX_RECORDS_PER_OBSERVER {
                mine.into_iter()
                    .min_by_key(|old| (old.checkpoint.log_size, old.observed_at))
            } else if existing.len() >= MAX_RECORDS {
                existing
                    .iter()
                    .min_by_key(|old| (old.checkpoint.log_size, old.observed_at))
            } else {
                None
            }
            .map(observation_key)
            .transpose()?;
        }
        let bytes = serde_json::to_vec(observation).map_err(storage_error)?;
        if bytes.len() > MAX_GOSSIP_BYTES {
            return Err(storage_error("gossip observation exceeds byte limit"));
        }
        if let Some(old_key) = &evict {
            let old_name = format!("{}:{}", old_key.0, old_key.1);
            ignore_not_found(fs::remove_file(
                dir.join(format!("{}.json", digest(old_name.as_bytes()))),
            ))?;
        }
        atomic_write(&path, &bytes)?;
        Ok(SaveResult::Stored(evict))
    }

    /// Load archival alerts without hiding damaged evidence files.
    pub fn alerts(&self, log_id: &str) -> Result<Vec<SplitViewEvidence>, WitnessError> {
        records(
            &self.log_dir("alerts", log_id),
            (2 * MAX_GOSSIP_BYTES + 2048) as u64,
            false,
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
