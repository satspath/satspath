use std::{sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use satspath_core::{
    crypto::{generate_identity_keypair, IdentityKeypair},
    transparency::{GossipObservation, TransparencyCheckpoint},
};
use satspath_witness::gossip::{
    run_relay, GossipConfig, GossipMonitor, GossipStore, NostrGossipEvent,
};
use serde_json::{json, Value};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{broadcast, Mutex},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

const LOG_ID: &str = "split-view-test";
const SUB: &str = "satspath-checkpoint-gossip-v1";

fn checkpoint(operator: &IdentityKeypair, root: &str) -> TransparencyCheckpoint {
    let mut cp = TransparencyCheckpoint {
        version: 1,
        log_id: LOG_ID.into(),
        log_size: 10,
        log_root: root.into(),
        map_root: None,
        previous_checkpoint_hash: None,
        created_at: chrono::Utc::now().timestamp(),
        operator_pubkey: hex::encode(operator.public_key.serialize()),
        operator_sequence: 0,
        operator_rotation: None,
        operator_signature: String::new(),
        bitcoin_anchor: None,
    };
    cp.sign(&operator.secret_key).unwrap();
    cp
}

async fn relay_connection(
    stream: TcpStream,
    history: Arc<Mutex<Vec<Value>>>,
    sender: broadcast::Sender<Value>,
) {
    let mut socket = accept_async(stream).await.unwrap();
    let mut feed = sender.subscribe();
    let mut subscribed = false;
    loop {
        tokio::select! {
            received = socket.next() => {
                let Some(Ok(Message::Text(text))) = received else { break; };
                let Ok(Value::Array(message)) = serde_json::from_str::<Value>(&text) else { break; };
                match message.first().and_then(Value::as_str) {
                    Some("REQ") => {
                        subscribed = true;
                        for event in history.lock().await.iter() {
                            if socket.send(Message::Text(json!(["EVENT", SUB, event]).to_string().into())).await.is_err() { return; }
                        }
                    }
                    Some("EVENT") => {
                        let Some(event) = message.get(1) else { break; };
                        history.lock().await.push(event.clone());
                        let _ = sender.send(event.clone());
                        let response = json!(["OK", event["id"], true, ""]);
                        if socket.send(Message::Text(response.to_string().into())).await.is_err() { return; }
                    }
                    _ => {}
                }
            }
            incoming = feed.recv(), if subscribed => {
                let Ok(event) = incoming else { break; };
                if socket.send(Message::Text(json!(["EVENT", SUB, event]).to_string().into())).await.is_err() { break; }
            }
        }
    }
}

#[tokio::test]
async fn two_independent_observers_detect_and_persist_signed_split_view_over_nostr() {
    let operator = generate_identity_keypair();
    let alice = generate_identity_keypair();
    let bob = generate_identity_keypair();
    let trusted = vec![
        hex::encode(alice.public_key.serialize()),
        hex::encode(bob.public_key.serialize()),
    ];
    let config = GossipConfig {
        log_id: LOG_ID.into(),
        operator_pubkey: hex::encode(operator.public_key.serialize()),
        trusted_observers: trusted,
    };
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let a =
        GossipMonitor::new(config.clone(), GossipStore::open(alice_dir.path()).unwrap()).unwrap();
    let b = GossipMonitor::new(config.clone(), GossipStore::open(bob_dir.path()).unwrap()).unwrap();
    let now = chrono::Utc::now().timestamp();
    a.ingest(
        GossipObservation::sign(
            checkpoint(&operator, &"ab".repeat(32)),
            &alice.secret_key,
            now,
        )
        .unwrap(),
        now,
    )
    .await
    .unwrap();
    b.ingest(
        GossipObservation::sign(
            checkpoint(&operator, &"cd".repeat(32)),
            &bob.secret_key,
            now,
        )
        .unwrap(),
        now,
    )
    .await
    .unwrap();
    assert!(a.alerts(now).unwrap().is_empty());
    assert!(b.alerts(now).unwrap().is_empty());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = format!("ws://{}", listener.local_addr().unwrap());
    let history = Arc::new(Mutex::new(Vec::new()));
    let (sender, _) = broadcast::channel(32);
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(relay_connection(stream, history.clone(), sender.clone()));
        }
    });
    let alice_task = tokio::spawn(run_relay(a.clone(), relay.clone(), alice.secret_key, true));
    let bob_task = tokio::spawn(run_relay(b.clone(), relay, bob.secret_key, true));
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if !a.alerts(chrono::Utc::now().timestamp()).unwrap().is_empty()
                && !b.alerts(chrono::Utc::now().timestamp()).unwrap().is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    alice_task.abort();
    bob_task.abort();
    server.abort();

    let restarted =
        GossipMonitor::new(config, GossipStore::open(alice_dir.path()).unwrap()).unwrap();
    let alerts = restarted.alerts(chrono::Utc::now().timestamp()).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_ne!(
        alerts[0].first.checkpoint.log_root,
        alerts[0].conflicting.checkpoint.log_root
    );
    assert_eq!(alerts[0].first.checkpoint.log_size, 10);
    // A corrupted on-disk alert cannot be silently presented as verified evidence.
    let log_dir = std::fs::read_dir(alice_dir.path().join("alerts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let alert_path = std::fs::read_dir(log_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut tampered: Value = serde_json::from_slice(&std::fs::read(&alert_path).unwrap()).unwrap();
    tampered["first"]["checkpoint"]["log_root"] = json!("ef".repeat(32));
    std::fs::write(alert_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(restarted.alerts(chrono::Utc::now().timestamp()).is_err());
}

#[tokio::test]
async fn reject_forged_nostr_messages_rogue_observers_and_replays() {
    let operator = generate_identity_keypair();
    let alice = generate_identity_keypair();
    let bob = generate_identity_keypair();
    let rogue = generate_identity_keypair();
    let config = GossipConfig {
        log_id: LOG_ID.into(),
        operator_pubkey: hex::encode(operator.public_key.serialize()),
        trusted_observers: vec![
            hex::encode(alice.public_key.serialize()),
            hex::encode(bob.public_key.serialize()),
        ],
    };
    let now = chrono::Utc::now().timestamp();
    let observation = GossipObservation::sign(
        checkpoint(&operator, &"ab".repeat(32)),
        &alice.secret_key,
        now,
    )
    .unwrap();
    let valid = NostrGossipEvent::sign(&observation, &alice.secret_key, now).unwrap();
    assert!(valid.verify(&config, now).is_ok());
    let mut poisoned = valid.clone();
    poisoned.content.push(' ');
    assert!(poisoned.verify(&config, now).is_err());
    let mut forged = valid.clone();
    forged.tags = vec![vec!["d".into(), "other-log".into()]];
    assert!(forged.verify(&config, now).is_err());
    let rogue_obs =
        GossipObservation::sign(observation.checkpoint, &rogue.secret_key, now).unwrap();
    assert!(NostrGossipEvent::sign(&rogue_obs, &rogue.secret_key, now)
        .unwrap()
        .verify(&config, now)
        .is_err());
    assert!(valid.verify(&config, now + 7 * 24 * 3600 + 1).is_err());
    assert!(GossipConfig {
        trusted_observers: vec![config.trusted_observers[0].clone(); 2],
        ..config
    }
    .validate()
    .is_err());
    let opposite_pubkey = hex::encode(
        secp256k1::PublicKey::from_secret_key(
            &secp256k1::Secp256k1::new(),
            &alice.secret_key.negate(),
        )
        .serialize(),
    );
    assert!(GossipConfig {
        log_id: LOG_ID.into(),
        operator_pubkey: hex::encode(operator.public_key.serialize()),
        trusted_observers: vec![hex::encode(alice.public_key.serialize()), opposite_pubkey],
    }
    .validate()
    .is_err());
}
