//! Transparency log handlers: checkpoints, events, proofs, anchors, namespace.

use std::fs;
use std::path::Path;

use anyhow::Result;
use satspath_core::{MerkleConsistencyProof, TransactionalTransparencyStore, TransparencyLog};
use serde::Serialize;

use crate::config::AppState;
use crate::http::write_owner_only_file;

pub(crate) fn transparency_log(state: &AppState) -> Result<TransparencyLog> {
    transparency_log_at(&state.home)
}

pub(crate) fn transparency_log_at(home: &Path) -> Result<TransparencyLog> {
    Ok(TransactionalTransparencyStore::open(home)?.load_log()?)
}

pub(crate) fn load_or_create_transparency_operator(home: &Path) -> Result<secp256k1::SecretKey> {
    let dir = home.join("transparency");
    fs::create_dir_all(&dir)?;
    let path = dir.join("operator.key");
    if path.exists() {
        let bytes = hex::decode(fs::read_to_string(path)?.trim())?;
        return secp256k1::SecretKey::from_slice(&bytes).map_err(Into::into);
    }
    let key = satspath_core::crypto::generate_identity_keypair().secret_key;
    write_owner_only_file(&path, hex::encode(key.secret_bytes()).as_bytes())?;
    Ok(key)
}

pub(crate) fn query_u64(url: &str, name: &str) -> Option<u64> {
    url.split_once('?')?.1.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

pub(crate) fn query_str(url: &str, name: &str) -> Option<String> {
    url.split_once('?')?.1.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        if key == name {
            url::form_urlencoded::parse(part.as_bytes())
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
                .or_else(|| Some(value.to_string()))
        } else {
            None
        }
    })
}

pub(crate) fn paginated<T: Clone + Serialize>(url: &str, items: &[T]) -> serde_json::Value {
    let offset = query_u64(url, "offset")
        .unwrap_or(0)
        .min(items.len() as u64) as usize;
    let limit = query_u64(url, "limit").unwrap_or(50).clamp(1, 200) as usize;
    let page: Vec<_> = items.iter().skip(offset).take(limit).cloned().collect();
    serde_json::json!({"items": page, "offset": offset, "limit": limit, "total": items.len()})
}

pub(crate) fn consistency_from_query(
    state: &AppState,
    url: &str,
) -> Result<MerkleConsistencyProof> {
    let from = query_u64(url, "from").ok_or_else(|| anyhow::anyhow!("missing from tree size"))?;
    let to = query_u64(url, "to").ok_or_else(|| anyhow::anyhow!("missing to tree size"))?;
    Ok(transparency_log(state)?.consistency(from, to)?)
}

pub(crate) async fn anchor_latest_checkpoint(
    state: &AppState,
) -> Result<satspath_core::TransparencyBitcoinAnchor> {
    let log = transparency_log(state)?;
    let checkpoint = log
        .checkpoints()
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no checkpoint to anchor"))?;
    let checkpoint_hash = checkpoint.checkpoint_hash()?;
    let client = satspath_core::transparency::RegtestAnchorClient::from_env()?;
    let anchor = client.anchor_checkpoint(&checkpoint_hash).await?;
    if !anchor.verified {
        anyhow::bail!("regtest anchor could not be verified after confirmation");
    }
    let operator = load_or_create_transparency_operator(&state.home)?;
    let mut anchored = checkpoint;
    anchored.bitcoin_anchor = Some(anchor.clone());
    anchored.sign(&operator)?;
    TransactionalTransparencyStore::open(&state.home)?
        .replace_latest_checkpoint(&checkpoint_hash, &anchored)?;
    Ok(anchor)
}

pub(crate) fn namespace_descriptor(
    state: &AppState,
) -> Result<satspath_core::transparency::NamespaceDescriptor> {
    satspath_core::lab::require_lab(
        &state.network,
        super::lab::enabled(),
        "authority@lab.satspath.test",
    )?;
    let operator = load_or_create_transparency_operator(&state.home)?;
    let authority_pubkey =
        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &operator).to_string();
    let log = transparency_log(state)?;
    let endpoint = std::env::var("SATSPATH_AUTHORITY_URL")
        .unwrap_or_else(|_| format!("http://{}", state.bind));
    let parsed = url::Url::parse(&endpoint)?;
    let loopback = parsed.host_str().is_some_and(|h| {
        h == "localhost"
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        anyhow::bail!("lab endpoint requires HTTPS or explicit loopback HTTP");
    }
    let now = chrono::Utc::now().timestamp();
    let mut endpoints = vec![endpoint];
    if let Ok(json) = std::env::var("SATSPATH_REPLICA_URLS") {
        let replicas: Vec<String> = serde_json::from_str(&json)?;
        anyhow::ensure!(replicas.len() <= 7, "at most seven replica origins allowed");
        for origin in replicas {
            satspath_core::transparency::validate_lab_origin(&origin)?;
            anyhow::ensure!(!endpoints.contains(&origin), "duplicate endpoint");
            endpoints.push(origin);
        }
    }
    let mut descriptor = satspath_core::transparency::NamespaceDescriptor {
        version: 2,
        domain: satspath_core::lab::LAB_NAMESPACE.into(),
        log_id: log.log_id().into(),
        authority_pubkey,
        endpoint_urls: endpoints,
        witness_quorum: 0,
        witness_pubkeys: vec![],
        valid_from: now,
        expires_at: now + 3600,
        signature: String::new(),
    };
    descriptor.sign(&operator)?;
    Ok(descriptor)
}
