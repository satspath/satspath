//! Verified, bounded S2S envelope mirror. No authority or owner keys.
use crate::{
    config::AppState,
    http::{json_error, json_response},
};
use anyhow::{ensure, Result};
use satspath_core::{lab, transparency::*, TransactionalTransparencyStore};
use std::path::Path;
use tiny_http::{Method, Request, StatusCode};

pub(crate) struct ReplicaConfig {
    pub trusted: NamespaceDescriptor,
    pub aliases: Vec<String>,
    pub interval: u64,
}

impl ReplicaConfig {
    pub fn load(
        path: &Path,
        aliases: &[String],
        interval: u64,
        network: &str,
        p2p: bool,
    ) -> Result<Self> {
        ensure!(!p2p, "replica mode cannot run a publisher");
        ensure!(
            (1..=60).contains(&interval),
            "replica sync interval requires 1..60 seconds"
        );
        ensure!(
            !aliases.is_empty() && aliases.len() <= 32,
            "replica requires 1..32 identifiers"
        );
        let mut seen = std::collections::HashSet::new();
        for alias in aliases {
            lab::require_lab(network, crate::handlers::lab::enabled(), alias)?;
            ensure!(seen.insert(alias), "duplicate replica alias");
        }
        let bytes = std::fs::read(path)?;
        ensure!(bytes.len() <= 16_384, "descriptor exceeds size bound");
        let trusted: NamespaceDescriptor = serde_json::from_slice(&bytes)?;
        ensure!(
            trusted.domain == lab::LAB_NAMESPACE
                && trusted.verify(chrono::Utc::now().timestamp())?,
            "invalid lab trust descriptor"
        );
        ensure!(
            (1..=8).contains(&trusted.endpoint_urls.len()),
            "expected 1..8 authorized endpoints"
        );
        for origin in &trusted.endpoint_urls {
            validate_lab_origin(origin)?;
        }
        Ok(Self {
            trusted,
            aliases: aliases.to_vec(),
            interval,
        })
    }
}

async fn sync_once(state: &AppState, config: &ReplicaConfig) -> Result<()> {
    let store = TransactionalTransparencyStore::open(&state.home)?;
    let previous = store.replica_pin(&config.trusted.log_id)?;
    let mut envelopes = Vec::new();
    // Pull only from the primary. A mirror never refreshes freshness from itself.
    for alias in &config.aliases {
        let fetched = fetch_lab_resolution(
            &config.trusted,
            &config.trusted.endpoint_urls[0],
            alias,
            previous.as_ref(),
        )
        .await;
        let envelope = match fetched {
            Ok(envelope) => envelope,
            Err(ReplicaFetchError::Invalid(error)) => {
                store.quarantine_replica(
                    &config.trusted.log_id,
                    "invalid authoritative S2S evidence",
                )?;
                return Err(error.into());
            }
            Err(ReplicaFetchError::Unavailable(error)) => {
                anyhow::bail!("replica source unavailable: {error}")
            }
        };
        envelopes.push(envelope);
    }
    store.commit_replica_batch(&config.trusted, &envelopes, chrono::Utc::now().timestamp())?;
    Ok(())
}

pub(crate) async fn synchronize(state: AppState) {
    let config = state.replica.as_ref().expect("replica configuration");
    loop {
        if let Err(error) = sync_once(&state, config).await {
            // Availability failure does not erase already verified evidence or
            // extend its signed freshness. Each read revalidates the cache.
            eprintln!("replica synchronization unavailable: {error}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(config.interval)).await;
    }
}

pub(crate) fn handle(mut request: Request, state: &AppState) -> Result<()> {
    let config = state.replica.as_ref().expect("replica configuration");
    let raw = request.url().to_string();
    let path = raw.split('?').next().unwrap_or("/");
    let method = request.method().clone();
    if !matches!(method, Method::Get | Method::Head | Method::Options)
        && !(method == Method::Post && path == "/v2/resolve")
    {
        request.respond(json_error(
            StatusCode(403),
            anyhow::anyhow!(
                "read-only replica; identity mutations require the namespace authority"
            ),
        ))?;
        return Ok(());
    }
    let result: Result<serde_json::Value> = (|| {
        if path == "/health" {
            return Ok(serde_json::json!({"live":true,"role":"replica","production_ready":false}));
        }
        if path == "/.well-known/satspath-authority" || path == "/v2/namespace" {
            ensure!(
                config.trusted.verify(chrono::Utc::now().timestamp())?,
                "descriptor expired"
            );
            return Ok(serde_json::to_value(&config.trusted)?);
        }
        let store = TransactionalTransparencyStore::open_read_only(&state.home)?;
        if path == "/v2/resolve" {
            let alias = if method == Method::Post {
                crate::http::read_json::<ResolutionRequest>(&mut request)?.identifier
            } else {
                crate::handlers::transparency::query_str(&raw, "identifier")
                    .ok_or_else(|| anyhow::anyhow!("missing identifier"))?
            };
            return Ok(serde_json::to_value(store.replica_resolution(
                &config.trusted,
                &alias,
                chrono::Utc::now().timestamp(),
            )?)?);
        }
        if path == "/v1/transparency/consistency" {
            let from = crate::handlers::transparency::query_u64(&raw, "from")
                .ok_or_else(|| anyhow::anyhow!("missing from"))?;
            let to = crate::handlers::transparency::query_u64(&raw, "to")
                .ok_or_else(|| anyhow::anyhow!("missing to"))?;
            return Ok(serde_json::to_value(store.replica_consistency(
                &config.trusted.log_id,
                from,
                to,
            )?)?);
        }
        if path == "/v2/health" {
            for alias in &config.aliases {
                store.replica_resolution(&config.trusted, alias, chrono::Utc::now().timestamp())?;
            }
            return Ok(
                serde_json::json!({"role":"replica","replication_ready":true,"namespace_trust":"explicit_lab_pin","production_ready":false,"witness_quorum":config.trusted.witness_quorum}),
            );
        }
        anyhow::bail!("unsupported replica endpoint");
    })();
    match result {
        Ok(body) => request.respond(json_response(StatusCode(200), &body))?,
        Err(error) => request.respond(json_error(StatusCode(503), error))?,
    }
    Ok(())
}
