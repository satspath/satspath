//! Transparency log handlers: checkpoints, events, proofs, anchors, namespace.

use std::fs;
use std::path::Path;

use anyhow::Result;
use satspath_core::{MerkleConsistencyProof, TransactionalTransparencyStore, TransparencyLog};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingCatenaAnchor {
    checkpoint_hash: String,
    anchor: satspath_core::TransparencyBitcoinAnchor,
}

pub(crate) async fn anchor_latest_checkpoint(
    state: &AppState,
) -> Result<satspath_core::TransparencyBitcoinAnchor> {
    let _anchor_guard = state.anchor_lock.lock().await;
    let log = transparency_log(state)?;
    let checkpoint = log
        .checkpoints()
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no checkpoint to anchor"))?;
    if checkpoint.bitcoin_anchor.is_some() {
        anyhow::bail!("latest checkpoint is already anchored");
    }
    let checkpoint_hash = checkpoint.checkpoint_hash()?;
    let client = satspath_core::transparency::RegtestAnchorClient::from_env()?;

    // Crash resilience: check if a pending anchor was broadcast before an uncommitted shutdown
    let pending_file = state.home.join("catena_pending_anchor.json");
    if pending_file.exists() {
        if let Ok(bytes) = fs::read(&pending_file) {
            if let Ok(pending) = serde_json::from_slice::<PendingCatenaAnchor>(&bytes) {
                if pending.checkpoint_hash == checkpoint_hash {
                    if let Ok(verified) = client
                        .verify_anchor(&pending.anchor.txid, &pending.anchor.commitment)
                        .await
                    {
                        if verified.verified {
                            let operator = load_or_create_transparency_operator(&state.home)?;
                            let mut anchored = checkpoint.clone();
                            anchored.bitcoin_anchor = Some(pending.anchor.clone());
                            anchored.sign(&operator)?;
                            let _mutation_guard = state.mutation_lock.lock().await;
                            TransactionalTransparencyStore::open(&state.home)?
                                .replace_latest_checkpoint(&checkpoint_hash, &anchored)?;
                            let _ = fs::remove_file(&pending_file);
                            return Ok(pending.anchor);
                        }
                    }
                }
            }
        }
    }

    // Find the latest Catena anchor by selecting the anchor with the maximum chain_index
    let prev_anchor = log
        .checkpoints()
        .iter()
        .filter_map(|c| c.bitcoin_anchor.as_ref())
        .filter(|a| a.chain_index.is_some() && a.continuation_vout.is_some())
        .max_by_key(|a| a.chain_index.unwrap_or(0))
        .cloned();

    let anchor = match prev_anchor {
        Some(prev) => client.anchor_catena_next(&checkpoint_hash, &prev).await?,
        None => {
            let allow_genesis = log.checkpoints().iter().all(|c| c.bitcoin_anchor.is_none())
                || std::env::var("SATSPATH_ALLOW_CATENA_GENESIS")
                    .map(|v| v == "1" || v == "true")
                    .unwrap_or(false);
            if !allow_genesis {
                anyhow::bail!(
                    "no previous Catena anchor found in log; set SATSPATH_ALLOW_CATENA_GENESIS=1 to initialize a new Catena genesis chain"
                );
            }
            client.anchor_catena_genesis(&checkpoint_hash).await?
        }
    };

    if !anchor.verified {
        anyhow::bail!("regtest anchor could not be verified after confirmation");
    }

    // Persist pending record before store commit so crashes can reconcile confirmed anchor
    let pending = PendingCatenaAnchor {
        checkpoint_hash: checkpoint_hash.clone(),
        anchor: anchor.clone(),
    };
    let data = serde_json::to_vec(&pending)?;
    write_owner_only_file(&pending_file, &data)?;

    let operator = load_or_create_transparency_operator(&state.home)?;
    let mut anchored = checkpoint;
    anchored.bitcoin_anchor = Some(anchor.clone());
    anchored.sign(&operator)?;

    let _mutation_guard = state.mutation_lock.lock().await;
    TransactionalTransparencyStore::open(&state.home)?
        .replace_latest_checkpoint(&checkpoint_hash, &anchored)?;
    let _ = fs::remove_file(&pending_file);
    Ok(anchor)
}

pub(crate) fn catena_chain(
    state: &AppState,
) -> Result<Vec<satspath_core::TransparencyBitcoinAnchor>> {
    let log = transparency_log(state)?;
    let anchors: Vec<_> = log
        .checkpoints()
        .iter()
        .filter_map(|c| c.bitcoin_anchor.clone())
        .filter(|a| a.chain_index.is_some())
        .collect();
    Ok(anchors)
}

pub(crate) fn namespace_descriptor(
    state: &AppState,
) -> Result<satspath_core::transparency::NamespaceDescriptor> {
    let domain =
        std::env::var("SATSPATH_AUTHORITY_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let wallet = crate::handlers::wallet::load_wallet(&state.home)?;
    let authority_pubkey = wallet.identity_pubkey.clone().unwrap_or_else(|| {
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    });
    let log = transparency_log(state).ok();
    let log_id = log
        .as_ref()
        .map(|l| l.log_id().to_string())
        .unwrap_or_else(|| format!("satspath:{domain}"));
    let endpoint_urls = if let Ok(custom_url) = std::env::var("SATSPATH_AUTHORITY_URL") {
        vec![custom_url]
    } else if domain != "localhost" {
        vec![format!("https://{domain}/v2")]
    } else {
        vec![format!("http://{}/v2", state.bind)]
    };
    let quorum = std::env::var("SATSPATH_WITNESS_QUORUM")
        .ok()
        .and_then(|q| q.parse::<u8>().ok())
        .unwrap_or(1);
    let now = chrono::Utc::now().timestamp();

    Ok(satspath_core::transparency::NamespaceDescriptor {
        version: 2,
        domain,
        log_id,
        authority_pubkey,
        endpoint_urls,
        witness_quorum: quorum,
        witness_pubkeys: vec![],
        valid_from: now,
        expires_at: now + 30 * 86400,
        signature: String::new(),
    })
}
