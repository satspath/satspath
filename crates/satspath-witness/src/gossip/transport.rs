use std::{net::SocketAddr, time::Duration};

use futures_util::{SinkExt, StreamExt};
use satspath_core::transparency::{
    gossip_topic, GossipObservation, GOSSIP_FUTURE_SKEW_SECS, GOSSIP_KIND, GOSSIP_MAX_AGE_SECS,
    MAX_GOSSIP_BYTES,
};
use secp256k1::{Keypair, Message as SecpMessage, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{handshake::client::Response, protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};

use super::{GossipConfig, GossipMonitor};
use crate::WitnessError;

const MAX_FRAME_BYTES: usize = 2 * MAX_GOSSIP_BYTES + 2048;
const SUBSCRIPTION: &str = "satspath-checkpoint-gossip-v1";
/// How often to look for a changed local checkpoint (no event is sent unless it changed).
const LOCAL_POLL: Duration = Duration::from_secs(15);
/// Re-announce an unchanged checkpoint this often so peers still see a fresh event.
const LIVENESS_REPUBLISH_SECS: u64 = 3600;
const _: () = assert!((LIVENESS_REPUBLISH_SECS as i64) < GOSSIP_MAX_AGE_SECS);

/// Checkpoint hash and time of the last event this relay task sent.
type LastPublished = Option<(String, tokio::time::Instant)>;

/// Production cannot select the test-only plaintext loopback connector.
#[derive(Clone, Copy)]
pub(super) enum RelayPolicy {
    Public,
    #[cfg(test)]
    LocalTest,
}

/// Normalize malformed relay input to one non-leaking validation error.
fn invalid() -> WitnessError {
    WitnessError::InvalidSignature
}

/// Convert a compressed observer key to its NIP-01 x-only author identity.
fn xonly(pubkey: &str) -> Result<String, WitnessError> {
    let bytes = hex::decode(pubkey).map_err(|_| invalid())?;
    let key = PublicKey::from_slice(&bytes).map_err(|_| invalid())?;
    Ok(hex::encode(key.x_only_public_key().0.serialize()))
}

/// NIP-01 event signed by the same observer as its independently signed content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NostrGossipEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl NostrGossipEvent {
    /// Compute the canonical NIP-01 event ID from its public fields.
    fn id_digest(&self) -> Result<[u8; 32], WitnessError> {
        let payload = json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ]);
        let encoded = serde_json::to_vec(&payload).map_err(|_| invalid())?;
        Ok(Sha256::digest(encoded).into())
    }

    /// Sign a bounded NIP-01 envelope using its inner observation's author key.
    pub fn sign(
        observation: &GossipObservation,
        secret: &SecretKey,
        now: i64,
    ) -> Result<Self, WitnessError> {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, secret);
        let pubkey = hex::encode(keypair.x_only_public_key().0.serialize());
        if xonly(&observation.observer_pubkey)? != pubkey {
            return Err(invalid());
        }
        let content = serde_json::to_string(observation).map_err(|_| invalid())?;
        if content.len() > MAX_GOSSIP_BYTES {
            return Err(invalid());
        }
        let mut event = Self {
            id: String::new(),
            pubkey,
            created_at: now,
            kind: GOSSIP_KIND,
            tags: vec![vec![
                "d".into(),
                gossip_topic(&observation.checkpoint.log_id),
            ]],
            content,
            sig: String::new(),
        };
        let digest = event.id_digest()?;
        event.id = hex::encode(digest);
        event.sig = hex::encode(
            secp.sign_schnorr(&SecpMessage::from_digest(digest), &keypair)
                .serialize(),
        );
        Ok(event)
    }

    /// Verify event ID, Nostr signature, topic, freshness and inner evidence.
    pub fn verify(
        &self,
        config: &GossipConfig,
        now: i64,
    ) -> Result<GossipObservation, WitnessError> {
        if self.kind != GOSSIP_KIND
            || self.tags != vec![vec!["d".to_string(), gossip_topic(&config.log_id)]]
            || self.content.len() > MAX_GOSSIP_BYTES
            || self.created_at < now.saturating_sub(GOSSIP_MAX_AGE_SECS)
            || self.created_at > now.saturating_add(GOSSIP_FUTURE_SKEW_SECS)
        {
            return Err(invalid());
        }
        let observation: GossipObservation =
            serde_json::from_str(&self.content).map_err(|_| invalid())?;
        observation
            .verify(
                &config.log_id,
                &config.operator_pubkey,
                &config.trusted_observers,
                now,
            )
            .map_err(|_| invalid())?;
        if self.pubkey != xonly(&observation.observer_pubkey)? {
            return Err(invalid());
        }
        let digest = self.id_digest()?;
        if self.id != hex::encode(digest) {
            return Err(invalid());
        }
        let key_bytes = hex::decode(&self.pubkey).map_err(|_| invalid())?;
        let sig_bytes = hex::decode(&self.sig).map_err(|_| invalid())?;
        let pubkey = XOnlyPublicKey::from_slice(&key_bytes).map_err(|_| invalid())?;
        let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes).map_err(|_| invalid())?;
        Secp256k1::new()
            .verify_schnorr(&sig, &SecpMessage::from_digest(digest), &pubkey)
            .map_err(|_| invalid())?;
        Ok(observation)
    }
}

/// Parse only events for the expected subscription and trust configuration.
pub fn parse_relay_event(
    raw: &str,
    config: &GossipConfig,
    now: i64,
) -> Result<Option<GossipObservation>, WitnessError> {
    if raw.len() > MAX_FRAME_BYTES {
        return Err(invalid());
    }
    let message: Value = serde_json::from_str(raw).map_err(|_| invalid())?;
    let Some(items) = message.as_array() else {
        return Err(invalid());
    };
    if items.first().and_then(Value::as_str) != Some("EVENT")
        || items.get(1).and_then(Value::as_str) != Some(SUBSCRIPTION)
    {
        return Ok(None);
    }
    let event: NostrGossipEvent =
        serde_json::from_value(items.get(2).cloned().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    event.verify(config, now).map(Some)
}

/// Production relays require WSS and a host permitted by the core SSRF policy.
pub fn validate_relay_url(relay: &str) -> Result<(), WitnessError> {
    validated_relay_url(relay, RelayPolicy::Public).map(|_| ())
}

/// Reject the entire DNS answer set if even one address is unsafe.
pub(super) fn allowed_resolved_addresses(addresses: &[SocketAddr], policy: RelayPolicy) -> bool {
    !addresses.is_empty()
        && addresses.iter().all(|address| match policy {
            RelayPolicy::Public => !satspath_core::ssrf::is_private_or_reserved_ip(address.ip()),
            #[cfg(test)]
            RelayPolicy::LocalTest => address.ip().is_loopback(),
        })
}

/// Reject local relay endpoints in production; unit tests alone can use WS loopback.
fn validated_relay_url(relay: &str, policy: RelayPolicy) -> Result<url::Url, WitnessError> {
    let url = url::Url::parse(relay).map_err(|_| invalid())?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(invalid());
    }
    #[cfg(test)]
    if matches!(policy, RelayPolicy::LocalTest)
        && url.scheme() == "ws"
        && url.host().is_some_and(|host| match host {
            url::Host::Domain(name) => name == "localhost",
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
        })
    {
        return Ok(url);
    }
    if url.scheme() != "wss" {
        return Err(invalid());
    }
    let https = url.as_str().replacen("wss://", "https://", 1);
    satspath_core::ssrf::validate_url(&https, false).map_err(|_| invalid())?;
    let _ = policy;
    Ok(url)
}

/// Resolve once, reject every non-public address, then connect to that same IP.
/// The original hostname is retained for TLS SNI and certificate verification.
async fn connect_pinned(
    relay: &str,
    socket_config: WebSocketConfig,
    policy: RelayPolicy,
) -> Result<
    (
        WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
        Response,
    ),
    WitnessError,
> {
    let url = validated_relay_url(relay, policy)?;
    let host = url.host_str().ok_or_else(invalid)?;
    let port = url.port_or_known_default().ok_or_else(invalid)?;
    let resolved: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| WitnessError::Relay("DNS resolution failed".into()))?
        .collect();
    if !allowed_resolved_addresses(&resolved, policy) {
        return Err(WitnessError::Relay(
            "relay resolved to an unsafe IP address".into(),
        ));
    }
    for address in resolved {
        if let Ok(socket) = tokio::net::TcpStream::connect(address).await {
            return client_async_tls_with_config(relay, socket, Some(socket_config), None)
                .await
                .map_err(|_| WitnessError::Relay("TLS or WebSocket handshake failed".into()));
        }
    }
    Err(WitnessError::Relay("relay connection failed".into()))
}

/// Publish the latest locally authenticated checkpoint without blocking Tokio,
/// but only when it changed or the liveness interval has elapsed.
async fn publish_local(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    monitor: &GossipMonitor,
    key: &SecretKey,
    last_published: &mut LastPublished,
) -> Result<Option<String>, WitnessError> {
    let local_pubkey = hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), key).serialize());
    let store = monitor.store().clone();
    let log_id = monitor.config().log_id.clone();
    let observations = tokio::task::spawn_blocking(move || store.observations(&log_id))
        .await
        .map_err(|e| WitnessError::Storage(e.to_string()))??;
    let cached = monitor.local_observation(&local_pubkey).await?;
    let mut updates: Vec<_> = observations
        .into_iter()
        .filter(|item| item.observer_pubkey == local_pubkey)
        .filter(|item| {
            item.verify_evidence(
                &monitor.config().log_id,
                &monitor.config().operator_pubkey,
                &monitor.config().trusted_observers,
            )
            .is_ok()
        })
        .filter(|item| {
            cached.as_ref().is_none_or(|prior| {
                item.checkpoint.log_size > prior.checkpoint.log_size
                    || (item.checkpoint.log_size == prior.checkpoint.log_size
                        && item.observed_at > prior.observed_at)
            })
        })
        .collect();
    updates.sort_by_key(|item| (item.checkpoint.log_size, item.observed_at));
    let now = chrono::Utc::now().timestamp();
    for item in updates {
        let refreshed =
            GossipObservation::sign_with_proof(item.checkpoint, item.consistency_proof, key, now)
                .map_err(|_| invalid())?;
        match monitor.ingest(refreshed, now).await {
            Ok(()) => {}
            Err(
                WitnessError::Rollback { .. }
                | WitnessError::EquivocationDetected { .. }
                | WitnessError::InvalidConsistencyProof,
            ) => {
                eprintln!("skipping invalid local gossip checkpoint transition");
            }
            Err(error) => return Err(error),
        }
    }
    let observation = monitor.local_observation(&local_pubkey).await?;
    let Some(observation) = observation else {
        return Ok(None);
    };
    let checkpoint_hash = observation
        .checkpoint
        .checkpoint_hash()
        .map_err(|_| invalid())?;
    if last_published.as_ref().is_some_and(|(hash, sent_at)| {
        *hash == checkpoint_hash && sent_at.elapsed() < Duration::from_secs(LIVENESS_REPUBLISH_SECS)
    }) {
        return Ok(None);
    }
    let renewed = GossipObservation::sign_with_proof(
        observation.checkpoint,
        observation.consistency_proof,
        key,
        now,
    )
    .map_err(|_| invalid())?;
    match monitor.ingest(renewed.clone(), now).await {
        Ok(()) => {}
        Err(
            WitnessError::Rollback { .. }
            | WitnessError::EquivocationDetected { .. }
            | WitnessError::InvalidConsistencyProof,
        ) => {
            eprintln!("skipping invalid local gossip checkpoint transition");
            return Ok(None);
        }
        Err(error) => return Err(error),
    }
    let event = NostrGossipEvent::sign(&renewed, key, now)?;
    let id = event.id.clone();
    let payload = json!(["EVENT", event]).to_string();
    tokio::time::timeout(
        Duration::from_secs(5),
        ws.send(Message::Text(payload.into())),
    )
    .await
    .map_err(|_| WitnessError::Relay("send timed out".into()))?
    .map_err(|_| WitnessError::Relay("send failed".into()))?;
    *last_published = Some((checkpoint_hash, tokio::time::Instant::now()));
    Ok(Some(id))
}

/// Continuously subscribe and republish the latest locally verified checkpoint.
/// Each relay connection is independent; a caller can run several concurrently.
pub async fn run_relay(
    monitor: GossipMonitor,
    relay: String,
    key: SecretKey,
) -> Result<(), WitnessError> {
    run_relay_with_policy(monitor, relay, key, RelayPolicy::Public).await
}

/// Local plaintext transport exists only in the unit-test build, not the CLI.
#[cfg(test)]
pub(super) async fn run_local_test_relay(
    monitor: GossipMonitor,
    relay: String,
    key: SecretKey,
) -> Result<(), WitnessError> {
    run_relay_with_policy(monitor, relay, key, RelayPolicy::LocalTest).await
}

/// Reconnect and gossip with one URL under an explicit network policy.
async fn run_relay_with_policy(
    monitor: GossipMonitor,
    relay: String,
    key: SecretKey,
    policy: RelayPolicy,
) -> Result<(), WitnessError> {
    validated_relay_url(&relay, policy)?;
    let local_pubkey = hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), &key).serialize());
    if !monitor.config().trusted_observers.contains(&local_pubkey) {
        return Err(invalid());
    }
    let authors = monitor
        .config()
        .trusted_observers
        .iter()
        .map(|k| xonly(k))
        .collect::<Result<Vec<_>, _>>()?;
    let filter = json!(["REQ", SUBSCRIPTION, {
        "kinds": [GOSSIP_KIND],
        "#d": [gossip_topic(&monitor.config().log_id)],
        "authors": authors,
        "limit": 256,
    }])
    .to_string();
    let socket_config = WebSocketConfig::default()
        .read_buffer_size(8192)
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES));
    // Kept across reconnects so a flapping relay does not trigger duplicate events.
    let mut last_published: LastPublished = None;
    loop {
        let connected = tokio::time::timeout(
            Duration::from_secs(8),
            connect_pinned(relay.as_str(), socket_config, policy),
        )
        .await;
        if let Ok(Ok((mut ws, _))) = connected {
            let sent = tokio::time::timeout(
                Duration::from_secs(5),
                ws.send(Message::Text(filter.clone().into())),
            )
            .await;
            if matches!(sent, Ok(Ok(()))) {
                let mut tick = tokio::time::interval(LOCAL_POLL);
                let mut last_sent = None;
                loop {
                    tokio::select! {
                        _ = tick.tick() => {
                            match publish_local(&mut ws, &monitor, &key, &mut last_published).await {
                                Ok(Some(id)) => last_sent = Some(id),
                                Ok(None) => {}
                                Err(WitnessError::Relay(_)) => break,
                                Err(e) => return Err(e),
                            }
                        }
                        message = ws.next() => {
                            match message {
                                Some(Ok(Message::Text(text))) => {
                                    let now = chrono::Utc::now().timestamp();
                                    if let Ok(Some(observation)) = parse_relay_event(&text, monitor.config(), now) {
                                        match monitor.ingest(observation, now).await {
                                            Ok(()) => {}
                                            Err(WitnessError::Rollback { .. } | WitnessError::EquivocationDetected { .. } | WitnessError::InvalidConsistencyProof) => {
                                                eprintln!("gossip observer checkpoint transition rejected");
                                            }
                                            Err(error) => return Err(error),
                                        }
                                    } else if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&text) {
                                        if items.first().and_then(Value::as_str) == Some("OK")
                                            && items.get(1).and_then(Value::as_str) == last_sent.as_deref()
                                            && items.get(2).and_then(Value::as_bool) == Some(false)
                                        {
                                            eprintln!("gossip relay rejected checkpoint event");
                                        }
                                    }
                                }
                                Some(Ok(Message::Ping(data))) => {
                                    if ws.send(Message::Pong(data)).await.is_err() { break; }
                                }
                                Some(Ok(_)) => {}
                                Some(Err(_)) | None => break,
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
