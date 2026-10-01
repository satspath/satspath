//! Optional public-profile transport. A downloaded candidate is never a routing authority.
use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use satspath_core::{privacy::canonical_identifier, registry::Registry, SignedPaymentProfile};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::Mutex,
};

use crate::{
    config::AppState,
    handlers::{profile::profile_response, wallet::load_wallet},
    types::now,
};

const MAX_BYTES: usize = 50 * 1024;

#[derive(Clone, Serialize)]
pub(crate) struct TransportStatus {
    pub state: &'static str,
    pub announcements: usize,
    pub last_publish: Option<i64>,
    pub last_resolution: Option<i64>,
    pub active_peers: Option<usize>,
}

pub(crate) struct Bridge {
    pub status: Mutex<TransportStatus>,
    resolution: Mutex<()>,
}

impl Bridge {
    pub fn new(enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(TransportStatus {
                state: if enabled { "starting" } else { "disabled" },
                announcements: 0,
                last_publish: None,
                last_resolution: None,
                active_peers: None,
            }),
            resolution: Mutex::new(()),
        })
    }
}

fn command(mode: &str, alias: &str) -> Result<Command> {
    // Fixed trusted source-tree script. No peer-supplied path, shell, or module.
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/satspath-p2p/src/bridge.mjs")
        .canonicalize()?;
    let mut cmd = Command::new("node");
    cmd.arg(script)
        .arg(mode)
        .arg(alias)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .env_clear();
    // Node/native runtime needs these on Windows; do not inherit daemon secrets.
    for key in ["PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
    Ok(cmd)
}

pub(crate) fn validate_candidate(
    bytes: &[u8],
    alias: &str,
    prior: Option<&SignedPaymentProfile>,
) -> Result<SignedPaymentProfile> {
    if bytes.len() > MAX_BYTES {
        bail!("candidate size limit");
    }
    let text = std::str::from_utf8(bytes)?;
    satspath_core::validation::assert_no_private_material(text)?;
    let signed: SignedPaymentProfile = serde_json::from_str(text)?;
    if signed
        .profile
        .expires_at
        .is_some_and(|expiry| expiry.checked_add(60).is_none())
    {
        bail!("invalid expiry");
    }
    Registry::validate_profile_write(alias, &signed)?;
    if signed.profile.revoked {
        bail!("revoked candidate");
    }
    if let Some(old) = prior {
        if old.profile.revoked {
            bail!("existing identity is revoked");
        }
        // Bare profiles cannot prove full rotation history/checkpoint continuity.
        if old.profile.identity_pubkey != signed.profile.identity_pubkey {
            bail!("pinned identity differs; use existing transparent rotation flow");
        }
        if old.profile.updated_at > signed.profile.updated_at {
            bail!("stale candidate");
        }
        match (old.profile.sequence, signed.profile.sequence) {
            (Some(_), None) => bail!("sequence downgrade"),
            (Some(old_seq), Some(new_seq)) if new_seq < old_seq => bail!("stale sequence"),
            (Some(old_seq), Some(new_seq))
                if new_seq == old_seq
                    && serde_json::to_vec(old)? != serde_json::to_vec(&signed)? =>
            {
                bail!("conflicting sequence")
            }
            _ => {}
        }
    }
    Ok(signed)
}

fn publication(state: &AppState) -> Result<Option<(String, Vec<u8>)>> {
    let response = profile_response(state)?;
    let Some(signed) = response.signed_profile else {
        return Ok(None);
    };
    if response.wallet.identity_pubkey.as_deref() != Some(&signed.profile.identity_pubkey) {
        bail!("not local identity");
    }
    let alias = signed.profile.alias.clone();
    let bytes = serde_json::to_vec(&signed)?;
    validate_candidate(&bytes, &alias, None)?;
    // Withdraw strictly at expiry, without the core's receive clock-skew grace.
    if signed
        .profile
        .expires_at
        .is_some_and(|expiry| expiry <= now())
    {
        return Ok(None);
    }
    Ok(Some((alias, bytes)))
}

async fn stop_child(child: &mut Child) {
    child.stdin.take(); // EOF requests graceful swarm shutdown.
    if tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

pub(crate) async fn supervise(state: AppState, mut shutdown: tokio::sync::oneshot::Receiver<()>) {
    let mut child: Option<Child> = None;
    let mut previous = None;
    let mut ticks = tokio::time::interval(Duration::from_secs(2));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! { _ = &mut shutdown => break, _ = ticks.tick() => {} }
        if let Some(process) = child.as_mut() {
            if !matches!(process.try_wait(), Ok(None)) {
                child = None;
                previous = None;
                let mut status = state.p2p.status.lock().await;
                status.state = "degraded";
                status.announcements = 0;
            }
        }
        let snapshot = {
            let _guard = state.mutation_lock.lock().await;
            publication(&state)
        };
        let snapshot = match snapshot {
            Ok(value) => value,
            Err(_) => {
                state.p2p.status.lock().await.state = "degraded";
                None
            }
        };
        if snapshot == previous {
            if snapshot.is_none() && state.p2p.status.lock().await.state == "starting" {
                state.p2p.status.lock().await.state = "active";
            }
            continue;
        }
        if let Some(mut process) = child.take() {
            stop_child(&mut process).await;
        }
        {
            let mut status = state.p2p.status.lock().await;
            status.announcements = 0;
            status.state = "starting";
        }
        previous = snapshot.clone();
        if let Some((alias, bytes)) = snapshot {
            let started = async {
                let mut process = command("publish", &alias)?.spawn()?;
                process
                    .stdin
                    .as_mut()
                    .context("stdin")?
                    .write_all(&bytes)
                    .await?;
                process
                    .stdin
                    .as_mut()
                    .context("stdin")?
                    .write_all(b"\n")
                    .await?;
                let mut reply = Vec::new();
                process
                    .stdout
                    .take()
                    .context("stdout")?
                    .take(7)
                    .read_to_end(&mut reply)
                    .await?;
                if reply != b"active\n" {
                    bail!("bridge failed");
                }
                Ok::<_, anyhow::Error>(process)
            };
            // kill_on_drop protects cancellation during startup.
            let result = tokio::select! {
                _ = &mut shutdown => break,
                result = tokio::time::timeout(Duration::from_secs(20), started) => result,
            };
            let mut status = state.p2p.status.lock().await;
            match result {
                Ok(Ok(process)) => {
                    child = Some(process);
                    status.state = "active";
                    status.announcements = 1;
                    status.last_publish = Some(now());
                }
                _ => {
                    status.state = "degraded";
                    previous = None;
                }
            }
        } else {
            state.p2p.status.lock().await.state = "active";
        }
    }
    if let Some(mut process) = child {
        stop_child(&mut process).await;
    }
    let mut status = state.p2p.status.lock().await;
    status.state = "stopped";
    status.announcements = 0;
}

pub(crate) async fn resolve_candidate(state: &AppState, alias: &str) -> Result<serde_json::Value> {
    if state.p2p.status.lock().await.state == "disabled" {
        bail!("P2P disabled");
    }
    let _permit = state
        .p2p
        .resolution
        .try_lock()
        .context("P2P resolution busy")?;
    satspath_core::privacy::validate_ascii_identifier(alias)?;
    if alias.len() > 254 || canonical_identifier(alias).is_empty() {
        bail!("invalid alias");
    }
    let received = async {
        let mut child = command("resolve", alias)?.spawn()?;
        // Keep stdin open as a parent-liveness pipe until the operation finishes.
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .context("stdout")?
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > MAX_BYTES {
            child.kill().await?;
            bail!("candidate size limit");
        }
        if !child.wait().await?.success() {
            bail!("P2P unavailable");
        }
        Ok::<_, anyhow::Error>(bytes)
    };
    let bytes = tokio::time::timeout(Duration::from_secs(30), received).await??;
    let _guard = state.mutation_lock.lock().await;
    let store = satspath_core::TransactionalTransparencyStore::open(&state.home)?;
    let prior = store.profile(alias)?;
    let signed = validate_candidate(&bytes, alias, prior.as_ref())?;
    // Legacy/local registry pins also constrain this lower-trust source.
    let registry = Registry::open(&state.home)?;
    if registry.is_registered(alias) {
        let legacy_prior = registry.resolve_alias(alias)?;
        validate_candidate(&bytes, alias, Some(legacy_prior))?;
    }
    let methods = satspath_core::verify_payment_method_states(&signed.profile, now());
    state.p2p.status.lock().await.last_resolution = Some(now());
    Ok(
        serde_json::json!({ "source": "hyperswarm", "routing_eligible": false,
        "profile_signature_verified": true, "identifier_verified": false,
        "key_continuity_verified": false, "transparency_verified": false,
        "identifier_scope": identifier_scope(alias), "payment_method_states": methods,
        "signed_profile": signed,
        "warning": "Candidate only. Namespace authority and remote transparency are unverified. Not imported or usable for routing." }),
    )
}

pub(crate) fn identifier_scope(alias: &str) -> &'static str {
    let domain = canonical_identifier(alias)
        .split_once('@')
        .map(|(_, d)| d.to_owned())
        .unwrap_or_default();
    if domain.ends_with(".local") || domain.ends_with(".test") || domain == "localhost" {
        "local_dev"
    } else {
        "self_asserted"
    }
}

pub(crate) fn local_summary(state: &AppState) -> Result<serde_json::Value> {
    let wallet = load_wallet(&state.home)?;
    let trust = wallet
        .alias
        .as_deref()
        .and_then(|alias| crate::handlers::resolve::resolve_profile(state, alias).ok());
    let fingerprint = wallet
        .identity_pubkey
        .as_deref()
        .map(satspath_core::crypto::fingerprint_pubkey)
        .transpose()?;
    Ok(serde_json::json!({ "fingerprint": fingerprint,
        "active_aliases": usize::from(wallet.alias.is_some()),
        "identifier_scope": wallet.alias.as_deref().map(identifier_scope),
        "identifier_authority": if trust.as_ref().is_some_and(|resolved| resolved.verification.identifier_verified) { "attested" } else { "unverified" },
        "verification": trust.as_ref().map(|resolved| serde_json::json!({
            "profile_signature_verified": resolved.verification.profile_signature_verified,
            "identifier_verified": resolved.verification.identifier_verified,
            "key_continuity_verified": resolved.verification.key_continuity_verified,
            "transparency_inclusion_verified": resolved.verification.transparency_inclusion_verified,
            "payment_methods_verified": resolved.verification.payment_methods_verified
        })),
        "capabilities": trust.as_ref().map(|resolved| resolved.signed_profile.profile.methods.iter().map(|method| method.method_name()).collect::<Vec<_>>()),
        "privacy": { "plaintext_dht_aliases": false, "private_keys_transmitted": false, "spending_keys_transmitted": false, "peer_addresses_logged": false },
        "routing_policy": "Existing transparency-verified routing only; P2P candidates do not grant authority" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::crypto::{generate_identity_keypair, sign_profile};

    fn fixture(alias: &str) -> SignedPaymentProfile {
        let key = generate_identity_keypair();
        let profile = serde_json::from_value(serde_json::json!({
            "alias": alias, "identity_pubkey": hex::encode(key.public_key.serialize()),
            "methods": [], "updated_at": now(), "sequence": 2, "revoked": false
        }))
        .unwrap();
        sign_profile(profile, &key.secret_key).unwrap()
    }
    fn bytes(profile: &SignedPaymentProfile) -> Vec<u8> {
        serde_json::to_vec(profile).unwrap()
    }

    #[test]
    fn signature_is_not_namespace_authority() {
        let signed = fixture("truja@binance.com");
        assert!(validate_candidate(&bytes(&signed), "truja@binance.com", None).is_ok());
        assert_eq!(identifier_scope("truja@binance.com"), "self_asserted");
        assert_eq!(identifier_scope("rodrigo@test.local"), "local_dev");
        assert_eq!(identifier_scope("rodrigo@example.test"), "local_dev");
    }
    #[test]
    fn rejects_untrusted_input_and_alias_substitution() {
        let signed = fixture("alice@example.com");
        assert!(validate_candidate(&bytes(&signed), "bob@example.com", None).is_err());
        assert!(validate_candidate(b"{", "alice@example.com", None).is_err());
        assert!(validate_candidate(&[255], "alice@example.com", None).is_err());
        assert!(validate_candidate(&vec![0; MAX_BYTES + 1], "alice@example.com", None).is_err());
        let mut forged = signed.clone();
        forged.profile.updated_at += 1;
        assert!(validate_candidate(&bytes(&forged), "alice@example.com", None).is_err());
        let mut private = serde_json::to_value(&signed).unwrap();
        private["identity_secret_key"] = serde_json::json!("xprv123456");
        assert!(validate_candidate(
            &serde_json::to_vec(&private).unwrap(),
            "alice@example.com",
            None
        )
        .is_err());
    }
    #[test]
    fn rejects_revoked_expired_and_overflowing_expiry() {
        let key = generate_identity_keypair();
        let mut profile = fixture("alice@example.com").profile;
        profile.identity_pubkey = hex::encode(key.public_key.serialize());
        profile.revoked = true;
        let revoked = sign_profile(profile.clone(), &key.secret_key).unwrap();
        assert!(validate_candidate(&bytes(&revoked), &profile.alias, None).is_err());
        profile.revoked = false;
        profile.expires_at = Some(now() - 120);
        let expired = sign_profile(profile.clone(), &key.secret_key).unwrap();
        assert!(validate_candidate(&bytes(&expired), &profile.alias, None).is_err());
        profile.expires_at = Some(i64::MAX);
        let overflow = sign_profile(profile.clone(), &key.secret_key).unwrap();
        assert!(validate_candidate(&bytes(&overflow), &profile.alias, None).is_err());
    }
    #[test]
    fn pins_cannot_be_replaced_or_replayed() {
        let old = fixture("alice@example.com");
        assert!(validate_candidate(&bytes(&old), &old.profile.alias, Some(&old)).is_ok());
        let replacement = fixture("alice@example.com");
        assert!(validate_candidate(&bytes(&replacement), &old.profile.alias, Some(&old)).is_err());
        let mut prior = old.clone();
        prior.profile.sequence = Some(3);
        assert!(validate_candidate(&bytes(&old), &old.profile.alias, Some(&prior)).is_err());
        prior.profile.sequence = Some(2);
        prior.profile.updated_at -= 1;
        assert!(validate_candidate(&bytes(&old), &old.profile.alias, Some(&prior)).is_err());
        prior = old.clone();
        prior.profile.revoked = true;
        assert!(validate_candidate(&bytes(&old), &old.profile.alias, Some(&prior)).is_err());
    }
    #[test]
    fn process_arguments_are_fixed_and_environment_is_filtered() {
        let command = command("resolve", "alice@example.com; echo secret").unwrap();
        let std = command.as_std();
        assert_eq!(std.get_program(), "node");
        assert_eq!(std.get_args().count(), 3);
        assert!(!std.get_envs().any(|(key, _)| key == "SATSPATHD_AUTH_TOKEN"));
    }
}
