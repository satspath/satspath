use std::{sync::Arc, time::Duration};

use super::transport::run_local_test_relay;
use super::transport::{allowed_resolved_addresses, validate_relay_url, RelayPolicy};
use super::{GossipConfig, GossipMonitor, GossipStore, NostrGossipEvent};
use crate::WitnessError;
use futures_util::{SinkExt, StreamExt};
use satspath_core::{
    crypto::{generate_identity_keypair, IdentityKeypair},
    transparency::{
        consistency_proof, leaf_hash, merkle_root, GossipObservation, MerkleConsistencyProof,
        TransparencyCheckpoint,
    },
};
use serde_json::{json, Value};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{broadcast, Mutex},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

const LOG_ID: &str = "split-view-test";
const SUB: &str = "satspath-checkpoint-gossip-v1";

/// Production URL validation and the pinned DNS answer set reject SSRF targets.
#[test]
fn production_relays_cannot_use_local_ws_or_mixed_private_dns_answers() {
    assert!(validate_relay_url("ws://127.0.0.1:19090").is_err());
    assert!(validate_relay_url("wss://127.0.0.1:443").is_err());
    assert!(validate_relay_url("wss://relay.example.com").is_ok());
    let public: std::net::SocketAddr = "1.1.1.1:443".parse().unwrap();
    let loopback: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
    let private: std::net::SocketAddr = "10.0.0.2:443".parse().unwrap();
    assert!(allowed_resolved_addresses(&[public], RelayPolicy::Public));
    assert!(!allowed_resolved_addresses(
        &[public, loopback],
        RelayPolicy::Public
    ));
    assert!(!allowed_resolved_addresses(&[private], RelayPolicy::Public));
    assert!(!allowed_resolved_addresses(&[], RelayPolicy::Public));
    let nat64_private = "[64:ff9b::a00:1]:443".parse().unwrap();
    let nat64_public = "[64:ff9b::808:808]:443".parse().unwrap();
    assert!(!allowed_resolved_addresses(
        &[nat64_private],
        RelayPolicy::Public
    ));
    assert!(allowed_resolved_addresses(
        &[nat64_public],
        RelayPolicy::Public
    ));
    for reserved in ["[100::1]:443", "[2001:2::1]:443", "[fec0::1]:443"] {
        assert!(!allowed_resolved_addresses(
            &[reserved.parse().unwrap()],
            RelayPolicy::Public
        ));
    }
}

/// Generate an operator-signed, deterministic-size checkpoint for test peers.
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

/// Echo subscription history and fan out events through the local mock relay.
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

/// Two independent observers persist replay-resistant split-view proof.
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
    assert!(a.alerts(now).await.unwrap().is_empty());
    assert!(b.alerts(now).await.unwrap().is_empty());

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
    let alice_task = tokio::spawn(run_local_test_relay(
        a.clone(),
        relay.clone(),
        alice.secret_key,
    ));
    let bob_task = tokio::spawn(run_local_test_relay(b.clone(), relay, bob.secret_key));
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if !a
                .alerts(chrono::Utc::now().timestamp())
                .await
                .unwrap()
                .is_empty()
                && !b
                    .alerts(chrono::Utc::now().timestamp())
                    .await
                    .unwrap()
                    .is_empty()
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
    let alerts = restarted
        .alerts(chrono::Utc::now().timestamp())
        .await
        .unwrap();
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
    assert!(restarted
        .alerts(chrono::Utc::now().timestamp())
        .await
        .unwrap()
        .is_empty());
}

/// A verified fork fails immediately, but its signed evidence survives a restart.
#[tokio::test]
async fn split_view_returns_error_after_persisting_reverifiable_evidence() {
    let operator = generate_identity_keypair();
    let alice = generate_identity_keypair();
    let bob = generate_identity_keypair();
    let config = GossipConfig {
        log_id: LOG_ID.into(),
        operator_pubkey: hex::encode(operator.public_key.serialize()),
        trusted_observers: vec![
            hex::encode(alice.public_key.serialize()),
            hex::encode(bob.public_key.serialize()),
        ],
    };
    let dir = tempfile::tempdir().unwrap();
    let monitor =
        GossipMonitor::new(config.clone(), GossipStore::open(dir.path()).unwrap()).unwrap();
    let now = chrono::Utc::now().timestamp();
    let a = GossipObservation::sign(
        checkpoint(&operator, &"ab".repeat(32)),
        &alice.secret_key,
        now,
    )
    .unwrap();
    let b = GossipObservation::sign(
        checkpoint(&operator, &"cd".repeat(32)),
        &bob.secret_key,
        now,
    )
    .unwrap();
    monitor.ingest(a.clone(), now).await.unwrap();
    assert!(matches!(
        monitor.ingest(b, now).await,
        Err(WitnessError::SplitViewDetected { tree_size: 10, .. })
    ));
    let alerts = monitor.alerts(now).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert!(matches!(
        monitor.ingest(a.clone(), now).await,
        Err(WitnessError::SplitViewDetected { .. })
    ));
    alerts[0]
        .verify(
            LOG_ID,
            &config.operator_pubkey,
            &config.trusted_observers,
            now,
        )
        .unwrap();
    let restarted = GossipMonitor::new(config, GossipStore::open(dir.path()).unwrap()).unwrap();
    assert_eq!(restarted.alerts(now).await.unwrap().len(), 1);
    assert!(matches!(
        restarted.ingest(a, now + 1).await,
        Err(WitnessError::SplitViewDetected { .. })
    ));
}

/// Untrusted Nostr authors, payload mutations, and stale events are rejected.
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
    let uppercase = hex::encode(alice.public_key.serialize()).to_uppercase();
    assert!(GossipConfig {
        log_id: LOG_ID.into(),
        operator_pubkey: hex::encode(operator.public_key.serialize()),
        trusted_observers: vec![uppercase, hex::encode(bob.public_key.serialize())],
    }
    .validate()
    .is_err());
    assert!(GossipConfig {
        log_id: LOG_ID.into(),
        operator_pubkey: hex::encode(operator.public_key.serialize()).to_uppercase(),
        trusted_observers: vec![
            hex::encode(alice.public_key.serialize()),
            hex::encode(bob.public_key.serialize())
        ],
    }
    .validate()
    .is_err());
}

/// Each observer enforces monotonicity and checkpoint-bound advances.
#[tokio::test]
async fn per_observer_rollbacks_forks_and_unproven_advances_are_rejected() {
    let operator = generate_identity_keypair();
    let alice = generate_identity_keypair();
    let bob = generate_identity_keypair();
    let config = GossipConfig {
        log_id: LOG_ID.into(),
        operator_pubkey: hex::encode(operator.public_key.serialize()),
        trusted_observers: vec![
            hex::encode(alice.public_key.serialize()),
            hex::encode(bob.public_key.serialize()),
        ],
    };
    let dir = tempfile::tempdir().unwrap();
    let monitor = GossipMonitor::new(config, GossipStore::open(dir.path()).unwrap()).unwrap();
    let now = chrono::Utc::now().timestamp();
    let leaves = [leaf_hash(b"one"), leaf_hash(b"two"), leaf_hash(b"three")];
    let mut first = checkpoint(&operator, &hex::encode(merkle_root(&leaves[..2])));
    first.log_size = 2;
    first.sign(&operator.secret_key).unwrap();
    monitor
        .ingest(
            GossipObservation::sign(first.clone(), &alice.secret_key, now).unwrap(),
            now,
        )
        .await
        .unwrap();

    let mut conflicting = checkpoint(&operator, &"cd".repeat(32));
    conflicting.log_size = 2;
    conflicting.sign(&operator.secret_key).unwrap();
    let fork = GossipObservation::sign(conflicting, &alice.secret_key, now + 1).unwrap();
    assert!(matches!(
        monitor.ingest(fork, now + 1).await,
        Err(WitnessError::EquivocationDetected { .. })
    ));
    let mut invalid_sequence = first.clone();
    invalid_sequence.operator_sequence += 1;
    invalid_sequence.sign(&operator.secret_key).unwrap();
    assert!(matches!(
        monitor
            .ingest(
                GossipObservation::sign(invalid_sequence, &alice.secret_key, now + 1).unwrap(),
                now + 1
            )
            .await,
        Err(WitnessError::InvalidConsistencyProof)
    ));
    let mut older = checkpoint(&operator, &hex::encode(merkle_root(&leaves[..1])));
    older.log_size = 1;
    older.sign(&operator.secret_key).unwrap();
    assert!(matches!(
        monitor
            .ingest(
                GossipObservation::sign(older, &alice.secret_key, now + 2).unwrap(),
                now + 2
            )
            .await,
        Err(WitnessError::Rollback {
            pinned: 2,
            proposed: 1
        })
    ));

    let forked_leaves = [
        leaf_hash(b"fork-one"),
        leaf_hash(b"fork-two"),
        leaf_hash(b"fork-three"),
    ];
    let mut forked_tip = checkpoint(&operator, &hex::encode(merkle_root(&forked_leaves)));
    forked_tip.log_size = 3;
    forked_tip.sign(&operator.secret_key).unwrap();
    let forked_proof = MerkleConsistencyProof {
        version: 2,
        old_tree_size: 2,
        new_tree_size: 3,
        old_root: hex::encode(merkle_root(&forked_leaves[..2])),
        new_root: forked_tip.log_root.clone(),
        audit_path: consistency_proof(&forked_leaves, 2)
            .unwrap()
            .into_iter()
            .map(hex::encode)
            .collect(),
    };
    let forked_advance = GossipObservation::sign_with_proof(
        forked_tip,
        Some(forked_proof),
        &alice.secret_key,
        now + 2,
    )
    .unwrap();
    assert!(matches!(
        monitor.ingest(forked_advance, now + 2).await,
        Err(WitnessError::EquivocationDetected { tree_size: 2, .. })
    ));

    let mut next = checkpoint(&operator, &hex::encode(merkle_root(&leaves)));
    next.log_size = 3;
    next.sign(&operator.secret_key).unwrap();
    assert!(matches!(
        monitor
            .ingest(
                GossipObservation::sign(next.clone(), &alice.secret_key, now + 3).unwrap(),
                now + 3
            )
            .await,
        Err(WitnessError::InvalidConsistencyProof)
    ));
    let proof = MerkleConsistencyProof {
        version: 2,
        old_tree_size: 2,
        new_tree_size: 3,
        old_root: first.log_root,
        new_root: next.log_root.clone(),
        audit_path: consistency_proof(&leaves, 2)
            .unwrap()
            .into_iter()
            .map(hex::encode)
            .collect(),
    };
    let advanced =
        GossipObservation::sign_with_proof(next, Some(proof), &alice.secret_key, now + 4).unwrap();
    monitor.ingest(advanced, now + 4).await.unwrap();
    assert_eq!(monitor.store().observations(LOG_ID).unwrap().len(), 2);
}

/// Missing an intermediate relay event must not disable later signed fork detection.
#[tokio::test]
async fn missed_intermediate_observation_remains_unlinked_but_detects_a_later_fork() {
    let operator = generate_identity_keypair();
    let alice = generate_identity_keypair();
    let bob = generate_identity_keypair();
    let config = GossipConfig {
        log_id: LOG_ID.into(),
        operator_pubkey: hex::encode(operator.public_key.serialize()),
        trusted_observers: vec![
            hex::encode(alice.public_key.serialize()),
            hex::encode(bob.public_key.serialize()),
        ],
    };
    let dir = tempfile::tempdir().unwrap();
    let monitor = GossipMonitor::new(config, GossipStore::open(dir.path()).unwrap()).unwrap();
    let leaves = [leaf_hash(b"one"), leaf_hash(b"two"), leaf_hash(b"three")];
    let now = chrono::Utc::now().timestamp();
    let mut first = checkpoint(&operator, &hex::encode(merkle_root(&leaves[..1])));
    first.log_size = 1;
    first.sign(&operator.secret_key).unwrap();
    monitor
        .ingest(
            GossipObservation::sign(first, &bob.secret_key, now).unwrap(),
            now,
        )
        .await
        .unwrap();

    let mut fork = checkpoint(&operator, &"ef".repeat(32));
    fork.log_size = 3;
    fork.sign(&operator.secret_key).unwrap();
    monitor
        .ingest(
            GossipObservation::sign(fork, &alice.secret_key, now).unwrap(),
            now,
        )
        .await
        .unwrap();

    let mut third = checkpoint(&operator, &hex::encode(merkle_root(&leaves)));
    third.log_size = 3;
    third.sign(&operator.secret_key).unwrap();
    let proof = MerkleConsistencyProof {
        version: 2,
        old_tree_size: 2,
        new_tree_size: 3,
        old_root: hex::encode(merkle_root(&leaves[..2])),
        new_root: third.log_root.clone(),
        audit_path: consistency_proof(&leaves, 2)
            .unwrap()
            .into_iter()
            .map(hex::encode)
            .collect(),
    };
    let observation =
        GossipObservation::sign_with_proof(third, Some(proof), &bob.secret_key, now + 1).unwrap();
    assert!(matches!(
        monitor.ingest(observation, now + 1).await,
        Err(WitnessError::SplitViewDetected { tree_size: 3, .. })
    ));
    assert_eq!(monitor.alerts(now + 1).await.unwrap().len(), 1);
}

/// Ordinary checkpoint churn prunes old observations without losing alerts.
#[tokio::test]
async fn retaining_recent_observations_does_not_stop_after_normal_log_updates() {
    let operator = generate_identity_keypair();
    let alice = generate_identity_keypair();
    let bob = generate_identity_keypair();
    let dir = tempfile::tempdir().unwrap();
    let monitor = GossipMonitor::new(
        GossipConfig {
            log_id: LOG_ID.into(),
            operator_pubkey: hex::encode(operator.public_key.serialize()),
            trusted_observers: vec![
                hex::encode(alice.public_key.serialize()),
                hex::encode(bob.public_key.serialize()),
            ],
        },
        GossipStore::open(dir.path()).unwrap(),
    )
    .unwrap();
    let leaves: Vec<_> = (0..20).map(|n| leaf_hash(&[n])).collect();
    let now = chrono::Utc::now().timestamp();
    for size in 1..=20usize {
        let mut cp = checkpoint(&operator, &hex::encode(merkle_root(&leaves[..size])));
        cp.log_size = size as u64;
        cp.sign(&operator.secret_key).unwrap();
        let proof = if size > 1 {
            Some(MerkleConsistencyProof {
                version: 2,
                old_tree_size: (size - 1) as u64,
                new_tree_size: size as u64,
                old_root: hex::encode(merkle_root(&leaves[..size - 1])),
                new_root: cp.log_root.clone(),
                audit_path: consistency_proof(&leaves[..size], size - 1)
                    .unwrap()
                    .into_iter()
                    .map(hex::encode)
                    .collect(),
            })
        } else {
            None
        };
        let observation =
            GossipObservation::sign_with_proof(cp, proof, &alice.secret_key, now + size as i64)
                .unwrap();
        monitor
            .ingest(observation, now + size as i64)
            .await
            .unwrap();
    }
    let saved = monitor.store().observations(LOG_ID).unwrap();
    assert_eq!(saved.len(), 16);
    assert_eq!(
        saved.iter().map(|obs| obs.checkpoint.log_size).min(),
        Some(5)
    );
    assert_eq!(
        saved.iter().map(|obs| obs.checkpoint.log_size).max(),
        Some(20)
    );
}

/// Old trust-state files cannot prevent new signed observations from being accepted.
#[tokio::test]
async fn former_trust_records_do_not_block_a_new_trusted_operator() {
    let first_operator = generate_identity_keypair();
    let next_operator = generate_identity_keypair();
    let alice = generate_identity_keypair();
    let bob = generate_identity_keypair();
    let former_observer = generate_identity_keypair();
    let dir = tempfile::tempdir().unwrap();
    let now = chrono::Utc::now().timestamp();
    let prior = GossipMonitor::new(
        GossipConfig {
            log_id: LOG_ID.into(),
            operator_pubkey: hex::encode(first_operator.public_key.serialize()),
            trusted_observers: vec![
                hex::encode(alice.public_key.serialize()),
                hex::encode(former_observer.public_key.serialize()),
            ],
        },
        GossipStore::open(dir.path()).unwrap(),
    )
    .unwrap();
    prior
        .ingest(
            GossipObservation::sign(
                checkpoint(&first_operator, &"ab".repeat(32)),
                &former_observer.secret_key,
                now,
            )
            .unwrap(),
            now,
        )
        .await
        .unwrap();
    let current = GossipMonitor::new(
        GossipConfig {
            log_id: LOG_ID.into(),
            operator_pubkey: hex::encode(next_operator.public_key.serialize()),
            trusted_observers: vec![
                hex::encode(alice.public_key.serialize()),
                hex::encode(bob.public_key.serialize()),
            ],
        },
        GossipStore::open(dir.path()).unwrap(),
    )
    .unwrap();
    current
        .ingest(
            GossipObservation::sign(
                checkpoint(&next_operator, &"cd".repeat(32)),
                &alice.secret_key,
                now,
            )
            .unwrap(),
            now,
        )
        .await
        .unwrap();
    assert_eq!(current.store().observations(LOG_ID).unwrap().len(), 2);
}

/// Publishing skips a stored checkpoint signed for a former operator policy.
#[tokio::test]
async fn former_operator_record_does_not_kill_the_relay_subscription() {
    let former_operator = generate_identity_keypair();
    let current_operator = generate_identity_keypair();
    let alice = generate_identity_keypair();
    let bob = generate_identity_keypair();
    let trusted = vec![
        hex::encode(alice.public_key.serialize()),
        hex::encode(bob.public_key.serialize()),
    ];
    let dir = tempfile::tempdir().unwrap();
    let store = GossipStore::open(dir.path()).unwrap();
    let former = GossipMonitor::new(
        GossipConfig {
            log_id: LOG_ID.into(),
            operator_pubkey: hex::encode(former_operator.public_key.serialize()),
            trusted_observers: trusted.clone(),
        },
        store.clone(),
    )
    .unwrap();
    let now = chrono::Utc::now().timestamp();
    former
        .ingest(
            GossipObservation::sign(
                checkpoint(&former_operator, &"ab".repeat(32)),
                &alice.secret_key,
                now,
            )
            .unwrap(),
            now,
        )
        .await
        .unwrap();
    let current = GossipMonitor::new(
        GossipConfig {
            log_id: LOG_ID.into(),
            operator_pubkey: hex::encode(current_operator.public_key.serialize()),
            trusted_observers: trusted,
        },
        store,
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = format!("ws://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let request = socket.next().await.unwrap().unwrap();
        assert!(matches!(request, Message::Text(_)));
        assert!(
            tokio::time::timeout(Duration::from_millis(300), socket.next())
                .await
                .is_err()
        );
    });
    let task = tokio::spawn(run_local_test_relay(current, relay, alice.secret_key));
    server.await.unwrap();
    assert!(
        !task.is_finished(),
        "a former-policy checkpoint must not stop relay monitoring"
    );
    task.abort();
}

/// Checkpoint publication is retried after disconnect or rejection until positively acknowledged.
#[tokio::test]
async fn unconfirmed_or_rejected_checkpoint_is_retried_on_reconnect() {
    let operator = generate_identity_keypair();
    let alice = generate_identity_keypair();
    let bob = generate_identity_keypair();
    let trusted = vec![
        hex::encode(alice.public_key.serialize()),
        hex::encode(bob.public_key.serialize()),
    ];
    let dir = tempfile::tempdir().unwrap();
    let store = GossipStore::open(dir.path()).unwrap();
    let monitor = GossipMonitor::new(
        GossipConfig {
            log_id: LOG_ID.into(),
            operator_pubkey: hex::encode(operator.public_key.serialize()),
            trusted_observers: trusted,
        },
        store,
    )
    .unwrap();
    let now = chrono::Utc::now().timestamp();
    monitor
        .ingest(
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

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = format!("ws://{}", listener.local_addr().unwrap());
    let (published_tx, mut published_rx) = tokio::sync::mpsc::channel(8);
    let server = tokio::spawn(async move {
        // First connection: drop socket before confirmation
        if let Ok((stream, _)) = listener.accept().await {
            let mut socket = accept_async(stream).await.unwrap();
            let _ = socket.next().await;
            if let Some(Ok(Message::Text(text))) = socket.next().await {
                let val: Value = serde_json::from_str(&text).unwrap();
                let _ = published_tx
                    .send(val[1]["id"].as_str().unwrap().to_string())
                    .await;
            }
        }
        // Second connection: send OK false (rejection)
        if let Ok((stream, _)) = listener.accept().await {
            let mut socket = accept_async(stream).await.unwrap();
            let _ = socket.next().await;
            if let Some(Ok(Message::Text(text))) = socket.next().await {
                let val: Value = serde_json::from_str(&text).unwrap();
                let id = val[1]["id"].as_str().unwrap().to_string();
                let _ = published_tx.send(id.clone()).await;
                let _ = socket
                    .send(Message::Text(
                        json!(["OK", id, false, "blocked"]).to_string().into(),
                    ))
                    .await;
            }
        }
        // Third connection: send OK true (acceptance)
        if let Ok((stream, _)) = listener.accept().await {
            let mut socket = accept_async(stream).await.unwrap();
            let _ = socket.next().await;
            if let Some(Ok(Message::Text(text))) = socket.next().await {
                let val: Value = serde_json::from_str(&text).unwrap();
                let id = val[1]["id"].as_str().unwrap().to_string();
                let _ = published_tx.send(id.clone()).await;
                let _ = socket
                    .send(Message::Text(
                        json!(["OK", id, true, ""]).to_string().into(),
                    ))
                    .await;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    let task = tokio::spawn(run_local_test_relay(monitor, relay, alice.secret_key));
    let first = tokio::time::timeout(Duration::from_secs(5), published_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(8), published_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let third = tokio::time::timeout(Duration::from_secs(8), published_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(!first.is_empty());
    assert!(!second.is_empty());
    assert!(!third.is_empty());

    task.abort();
    server.abort();
}
