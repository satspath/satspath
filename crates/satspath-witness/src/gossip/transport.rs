use std::time::Duration;

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
    connect_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message},
};

use super::{GossipConfig, GossipMonitor};
use crate::WitnessError;

const MAX_FRAME_BYTES: usize = 2 * MAX_GOSSIP_BYTES + 2048;
const SUBSCRIPTION: &str = "satspath-checkpoint-gossip-v1";

fn invalid() -> WitnessError {
    WitnessError::InvalidSignature
}

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

/// Only operator-configured WSS relays, or explicitly enabled loopback WS for development.
pub fn validate_relay_url(relay: &str, allow_local_ws: bool) -> Result<(), WitnessError> {
    let url = url::Url::parse(relay).map_err(|_| invalid())?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(invalid());
    }
    if url.scheme() == "ws"
        && allow_local_ws
        && url.host().is_some_and(|host| match host {
            url::Host::Domain(name) => name == "localhost",
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
        })
    {
        return Ok(());
    }
    if url.scheme() != "wss" {
        return Err(invalid());
    }
    let https = relay.replacen("wss://", "https://", 1);
    satspath_core::ssrf::validate_url(&https, false).map_err(|_| invalid())
}

fn report_alerts(alerts: Vec<satspath_core::transparency::SplitViewEvidence>) {
    for alert in alerts {
        if let Ok(json) = serde_json::to_string(&alert) {
            eprintln!("GOSSIP_SPLIT_VIEW {json}");
        }
    }
}

async fn publish_local(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    monitor: &GossipMonitor,
    key: &SecretKey,
) -> Result<Option<String>, WitnessError> {
    let local_pubkey = hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), key).serialize());
    let observation = monitor
        .store()
        .observations(&monitor.config().log_id)?
        .into_iter()
        .filter(|item| item.observer_pubkey == local_pubkey)
        .max_by_key(|item| (item.checkpoint.log_size, item.observed_at));
    let Some(observation) = observation else {
        return Ok(None);
    };
    observation
        .verify_evidence(
            &monitor.config().log_id,
            &monitor.config().operator_pubkey,
            &monitor.config().trusted_observers,
        )
        .map_err(|_| invalid())?;
    let now = chrono::Utc::now().timestamp();
    let renewed =
        GossipObservation::sign(observation.checkpoint, key, now).map_err(|_| invalid())?;
    report_alerts(monitor.ingest(renewed.clone(), now).await?);
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
    Ok(Some(id))
}

/// Continuously subscribe and republish the latest locally verified checkpoint.
/// Each relay connection is independent; a caller can run several concurrently.
pub async fn run_relay(
    monitor: GossipMonitor,
    relay: String,
    key: SecretKey,
    allow_local_ws: bool,
) -> Result<(), WitnessError> {
    validate_relay_url(&relay, allow_local_ws)?;
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
    loop {
        let connected = tokio::time::timeout(
            Duration::from_secs(8),
            connect_async_with_config(relay.as_str(), Some(socket_config), false),
        )
        .await;
        if let Ok(Ok((mut ws, _))) = connected {
            let sent = tokio::time::timeout(
                Duration::from_secs(5),
                ws.send(Message::Text(filter.clone().into())),
            )
            .await;
            if matches!(sent, Ok(Ok(()))) {
                let mut tick = tokio::time::interval(Duration::from_secs(15));
                let mut last_sent = None;
                loop {
                    tokio::select! {
                        _ = tick.tick() => {
                            match publish_local(&mut ws, &monitor, &key).await {
                                Ok(id) => last_sent = id,
                                Err(WitnessError::Relay(_)) => break,
                                Err(e) => return Err(e),
                            }
                        }
                        message = ws.next() => {
                            match message {
                                Some(Ok(Message::Text(text))) => {
                                    let now = chrono::Utc::now().timestamp();
                                    if let Ok(Some(observation)) = parse_relay_event(&text, monitor.config(), now) {
                                        report_alerts(monitor.ingest(observation, now).await?);
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
