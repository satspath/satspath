//! Independent checkpoint observer. The configured operator key is never learned from a relay.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use satspath_core::{
    crypto::generate_identity_keypair,
    transparency::{
        GossipObservation, MerkleConsistencyProof, TransparencyCheckpoint, MAX_GOSSIP_BYTES,
    },
};
use satspath_witness::{
    gossip::{run_relay, validate_relay_url, GossipConfig, GossipMonitor, GossipStore},
    FilePinStore, WitnessService,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

#[derive(Parser)]
#[command(about = "Compare operator-signed checkpoints across independent Nostr observers")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Trust {
    /// Directory containing verified observations, pins, and split-view alerts.
    #[arg(long)]
    state_dir: PathBuf,
    /// Log ID supplied by the namespace trust configuration, never by a relay.
    #[arg(long)]
    log_id: String,
    /// Compressed operator public key supplied independently of the log endpoint.
    #[arg(long)]
    operator_pubkey: String,
    /// Authorized compressed observer keys (including this observer); repeat for each.
    #[arg(long = "observer-pubkey", required = true)]
    observer_pubkeys: Vec<String>,
}

impl Trust {
    /// Create a monitor with a fixed, out-of-band operator trust anchor.
    fn monitor(&self) -> Result<GossipMonitor> {
        let config = GossipConfig {
            log_id: self.log_id.clone(),
            operator_pubkey: self.operator_pubkey.clone(),
            trusted_observers: self.observer_pubkeys.clone(),
        };
        Ok(GossipMonitor::new(
            config,
            GossipStore::open(&self.state_dir)?,
        )?)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Generate a dedicated owner-only observer key (never a spending key).
    Keygen {
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Verify and pin an independently obtained checkpoint before announcing it.
    Observe {
        #[command(flatten)]
        trust: Trust,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        checkpoint_file: PathBuf,
        /// Required for an advancement beyond a previously pinned tree size.
        #[arg(long)]
        consistency_file: Option<PathBuf>,
    },
    /// Publish the latest verified local checkpoint and monitor independent peers.
    Run {
        #[command(flatten)]
        trust: Trust,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long = "relay", required = true)]
        relays: Vec<String>,
    },
    /// Re-verify and print persistent cryptographic split-view evidence as JSON.
    Alerts {
        #[command(flatten)]
        trust: Trust,
    },
}

/// Bound local checkpoint and proof files before allocating decoded JSON.
fn read_bounded<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    if fs::metadata(path)?.len() > MAX_GOSSIP_BYTES as u64 {
        bail!("checkpoint/proof exceeds the byte limit");
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// Decode the dedicated observer key without logging the secret or its bytes.
fn read_key(path: &Path) -> Result<SecretKey> {
    let raw = fs::read_to_string(path).context("reading observer key file")?;
    let bytes = hex::decode(raw.trim()).context("observer key must be hex")?;
    SecretKey::from_slice(&bytes).context("invalid observer key")
}

/// Derive the canonical compressed identity for the observer allowlist.
fn pubkey(key: &SecretKey) -> String {
    hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), key).serialize())
}

/// Generate a fresh signing key in a new owner-only file on Unix.
fn keygen(path: &Path) -> Result<()> {
    let pair = generate_identity_keypair();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(hex::encode(pair.secret_key.secret_bytes()).as_bytes())?;
    file.sync_all()?;
    println!("{}", hex::encode(pair.public_key.serialize()));
    Ok(())
}

/// Dispatch offline observation, Nostr monitoring, and alert inspection.
#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { key_file } => keygen(&key_file),
        Command::Observe {
            trust,
            key_file,
            checkpoint_file,
            consistency_file,
        } => {
            let monitor = trust.monitor()?;
            let key = read_key(&key_file)?;
            let me = pubkey(&key);
            if !monitor.config().trusted_observers.contains(&me) {
                bail!("observer key is not on the trusted observer list");
            }
            let checkpoint: TransparencyCheckpoint = read_bounded(&checkpoint_file)?;
            if checkpoint.log_id != trust.log_id
                || checkpoint.operator_pubkey != trust.operator_pubkey
            {
                bail!("checkpoint does not match configured log and operator");
            }
            let proof: Option<MerkleConsistencyProof> =
                consistency_file.as_deref().map(read_bounded).transpose()?;
            let pins = FilePinStore::open(trust.state_dir.join("witness-pins"))?;
            WitnessService::new(
                "checkpoint-gossip".into(),
                satspath_core::crypto::IdentityKeypair {
                    public_key: PublicKey::from_secret_key(&Secp256k1::new(), &key),
                    secret_key: key,
                },
                pins,
            )
            .process_checkpoint(&checkpoint, proof.as_ref())
            .await?;
            let now = chrono::Utc::now().timestamp();
            let observation = GossipObservation::sign_with_proof(checkpoint, proof, &key, now)?;
            let alerts = monitor.ingest(observation, now).await?;
            for alert in alerts {
                eprintln!("GOSSIP_SPLIT_VIEW {}", serde_json::to_string(&alert)?);
            }
            println!("checkpoint verified and ready for gossip");
            Ok(())
        }
        Command::Run {
            trust,
            key_file,
            relays,
        } => {
            if relays.len() > 8 {
                bail!("at most eight relays may be configured");
            }
            for relay in &relays {
                validate_relay_url(relay)?;
            }
            let key = read_key(&key_file)?;
            let monitor = trust.monitor()?;
            let mut tasks = tokio::task::JoinSet::new();
            for relay in relays {
                tasks.spawn(run_relay(monitor.clone(), relay, key));
            }
            tokio::select! {
                signal = tokio::signal::ctrl_c() => signal?,
                failed = tasks.join_next() => {
                    failed.context("no relay task")??.context("relay task exited")?;
                    bail!("gossip relay task stopped unexpectedly");
                },
            }
            tasks.abort_all();
            Ok(())
        }
        Command::Alerts { trust } => {
            let alerts = trust
                .monitor()?
                .alerts(chrono::Utc::now().timestamp())
                .await?;
            println!("{}", serde_json::to_string_pretty(&alerts)?);
            Ok(())
        }
    }
}
