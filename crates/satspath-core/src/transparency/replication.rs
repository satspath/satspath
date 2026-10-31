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
    endpoints: &[ReplicaEndpoint],
    health: &[ReplicaHealth],
) -> Option<ReplicaEndpoint> {
    // First try to find a healthy primary
    if let Some(primary) = health.iter().find(|h| {
        h.endpoint.role == EndpointRole::Primary
            && h.is_healthy
            && endpoints.contains(&h.endpoint)
            && (0..=MAX_STALENESS_WINDOW_SECS).contains(&h.latest_checkpoint_age_secs)
    }) {
        return Some(primary.endpoint.clone());
    }

    // Fall back to the freshest healthy replica within staleness window
    health
        .iter()
        .filter(|h| {
            h.endpoint.role == EndpointRole::Replica
                && h.is_healthy
                && endpoints.contains(&h.endpoint)
                && (0..=MAX_STALENESS_WINDOW_SECS).contains(&h.latest_checkpoint_age_secs)
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

/// Data carriers do not become authorities. Only origins explicitly listed in
/// the trusted descriptor are contacted; redirects and ambient proxies are off.
#[cfg(feature = "std")]
pub fn validate_lab_origin(origin: &str) -> crate::Result<()> {
    let url =
        url::Url::parse(origin).map_err(|e| crate::SatsPathError::RegistryError(e.to_string()))?;
    let loopback = url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(crate::SatsPathError::RegistryError(
            "lab endpoint requires an HTTPS origin or loopback HTTP".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub enum ReplicaFetchError {
    Unavailable(String),
    Invalid(crate::SatsPathError),
}

#[cfg(feature = "std")]
async fn bounded_json<T: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
) -> std::result::Result<T, ReplicaFetchError> {
    use ReplicaFetchError::*;
    let invalid = |message: String| Invalid(crate::SatsPathError::RegistryError(message));
    let mut response = request
        .send()
        .await
        .map_err(|e| Unavailable(e.to_string()))?;
    if response.status().is_server_error() {
        return Err(Unavailable(format!("HTTP {}", response.status())));
    }
    if response.status() != reqwest::StatusCode::OK {
        return Err(invalid(format!(
            "unverified HTTP status {}",
            response.status()
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Unavailable(e.to_string()))?
    {
        if bytes.len() + chunk.len() > 65_536 {
            return Err(invalid("S2S response exceeds 64 KiB".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))
}

#[cfg(feature = "std")]
pub async fn fetch_lab_resolution(
    trusted: &super::NamespaceDescriptor,
    origin: &str,
    alias: &str,
    previous: Option<&super::PinnedCheckpoint>,
) -> std::result::Result<super::ResolutionEnvelope, ReplicaFetchError> {
    use ReplicaFetchError::*;
    let bad = |s: &str| Invalid(crate::SatsPathError::RegistryError(s.into()));
    if !trusted.endpoint_urls.iter().any(|s| s == origin) {
        return Err(bad("endpoint not authorized by pinned descriptor"));
    }
    validate_lab_origin(origin).map_err(Invalid)?;
    crate::lab::require_lab("regtest", true, alias).map_err(Invalid)?;
    if !trusted
        .verify(chrono::Utc::now().timestamp())
        .map_err(Invalid)?
    {
        return Err(bad("trusted descriptor expired or invalid"));
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|e| Unavailable(e.to_string()))?;
    let base = origin.trim_end_matches('/');
    let mut envelope: super::ResolutionEnvelope = bounded_json(
        client
            .get(format!("{base}/v2/resolve"))
            .query(&[("identifier", alias)]),
    )
    .await?;
    if let Some(pin) = previous {
        if pin.tree_size < envelope.checkpoint.log_size
            && !envelope.consistency_proof.as_ref().is_some_and(|p| {
                p.old_tree_size == pin.tree_size && p.new_tree_size == envelope.checkpoint.log_size
            })
        {
            envelope.consistency_proof = Some(
                bounded_json(
                    client
                        .get(format!("{base}/v1/transparency/consistency"))
                        .query(&[
                            ("from", pin.tree_size),
                            ("to", envelope.checkpoint.log_size),
                        ]),
                )
                .await?,
            );
        }
    }
    crate::lab::verify_resolution(
        alias,
        trusted,
        &envelope,
        previous,
        chrono::Utc::now().timestamp(),
    )
    .map_err(Invalid)?;
    Ok(envelope)
}

/// Availability failure permits failover. Invalid cryptographic evidence is
/// terminal: do not silently downgrade or vote across other peers.
#[cfg(feature = "std")]
pub async fn resolve_lab_network(
    trusted: &super::NamespaceDescriptor,
    alias: &str,
    previous: Option<&super::PinnedCheckpoint>,
) -> crate::Result<(String, super::ResolutionEnvelope)> {
    if trusted.endpoint_urls.is_empty() || trusted.endpoint_urls.len() > 8 {
        return Err(crate::SatsPathError::RegistryError(
            "expected 1..8 pinned endpoints".into(),
        ));
    }
    for origin in &trusted.endpoint_urls {
        match fetch_lab_resolution(trusted, origin, alias, previous).await {
            Ok(envelope) => return Ok((origin.clone(), envelope)),
            Err(ReplicaFetchError::Invalid(error)) => return Err(error),
            Err(ReplicaFetchError::Unavailable(_)) => continue,
        }
    }
    Err(crate::SatsPathError::RegistryError(
        "all authorized resolution endpoints unavailable".into(),
    ))
}
