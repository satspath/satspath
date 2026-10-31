use satspath_core::{lab::*, transparency::*, *};
#[allow(dead_code)]
#[path = "support/lab_fixture.rs"]
mod fixture;
use fixture::*;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn advance(lab: &mut Lab) -> ResolutionEnvelope {
    let previous = lab.event.event_hash().unwrap();
    let mut profile = lab.signed.profile.clone();
    profile.sequence = Some(1);
    profile.updated_at = now();
    if let PaymentMethod::Lightning {
        lightning_address, ..
    } = &mut profile.methods[0]
    {
        *lightning_address = Some("new-destination@example.com".into());
    }
    lab.signed = sign_profile(profile, &lab.owner.secret_key).unwrap();
    lab.event.sequence = 1;
    lab.event.action = NameAction::UpdateProfile;
    lab.event.previous_event_hash = Some(previous);
    lab.event.profile_hash = profile_hash(&lab.signed).unwrap();
    lab.event.sign(&lab.owner.secret_key).unwrap();
    let log = lab.store.load_log().unwrap();
    lab.checkpoint = log
        .prepare_append(lab.event.clone(), &lab.signed)
        .unwrap()
        .prepare_checkpoint(&lab.operator.secret_key)
        .unwrap();
    lab.store
        .commit_profile_event_checkpoint(ALICE, &lab.signed, &lab.event, &lab.checkpoint)
        .unwrap();
    let mut envelope = lab.envelope();
    envelope.consistency_proof = Some(lab.store.load_log().unwrap().consistency(1, 2).unwrap());
    envelope
}

#[test]
fn verified_mirror_restart_freshness_and_client_continuity() {
    let mut a = Lab::new();
    a.finish().unwrap();
    let bdir = tempfile::tempdir().unwrap();
    let b = TransactionalTransparencyStore::open(bdir.path()).unwrap();
    let first = a.envelope();
    let trusted = first.namespace_descriptor.clone();
    b.commit_replica_batch(&trusted, &[first.clone()], now())
        .unwrap();
    let client_pin = CheckpointStore::new(bdir.path())
        .pin(&first.checkpoint)
        .unwrap();
    let second = advance(&mut a);
    b.commit_replica_batch(&trusted, &[second.clone()], now())
        .unwrap();
    drop(b);
    drop(a);
    let b = TransactionalTransparencyStore::open_read_only(bdir.path()).unwrap();
    let mirrored = b.replica_resolution(&trusted, ALICE, now()).unwrap();
    verify_resolution(ALICE, &trusted, &mirrored, Some(&client_pin), now()).unwrap();
    assert_eq!(mirrored.signed_profile.profile.sequence, Some(1));
    assert!(b.replica_resolution(&trusted, ALICE, now() + 301).is_err());
    assert!(
        bdir.path()
            .join("transparency/operator.key")
            .try_exists()
            .unwrap()
            == false
    );
    assert!(
        b.load_log().unwrap().events().is_empty(),
        "mirror never authors events"
    );
}

#[test]
fn replay_fork_and_tampering_do_not_change_committed_replica() {
    let mut a = Lab::new();
    a.finish().unwrap();
    let first = a.envelope();
    let trusted = first.namespace_descriptor.clone();
    let dir = tempfile::tempdir().unwrap();
    let b = TransactionalTransparencyStore::open(dir.path()).unwrap();
    b.commit_replica_batch(&trusted, &[first.clone()], now())
        .unwrap();
    let second = advance(&mut a);
    b.commit_replica_batch(&trusted, &[second.clone()], now())
        .unwrap();
    assert!(b.commit_replica_batch(&trusted, &[first], now()).is_err());
    let mut forged = second.clone();
    forged.checkpoint.map_root = Some("ff".repeat(32));
    forged.checkpoint.sign(&a.operator.secret_key).unwrap();
    assert!(b.commit_replica_batch(&trusted, &[forged], now()).is_err());
    let rogue = Lab::new();
    rogue.finish().unwrap();
    assert!(b
        .commit_replica_batch(&trusted, &[rogue.envelope()], now())
        .is_err());
    let mut forged = second.clone();
    forged.signed_profile.profile.identity_pubkey = rogue.owner.public_key.to_string();
    assert!(b.commit_replica_batch(&trusted, &[forged], now()).is_err());
    let mut forged = second.clone();
    forged.signed_profile.profile.methods.clear();
    assert!(b.commit_replica_batch(&trusted, &[forged], now()).is_err());
    assert_eq!(
        b.replica_pin(&trusted.log_id).unwrap().unwrap().tree_size,
        2
    );
    assert!(b.replica_resolution(&trusted, ALICE, now()).is_ok());
    let conn =
        rusqlite::Connection::open(dir.path().join("satspath-transparency-v1.sqlite3")).unwrap();
    let mut corrupted = second;
    corrupted.signed_profile.signature = "00".repeat(64);
    conn.execute(
        "UPDATE replica_envelopes SET envelope_json=?1",
        [serde_json::to_string(&corrupted).unwrap()],
    )
    .unwrap();
    assert!(b.replica_resolution(&trusted, ALICE, now()).is_err());
}

#[test]
fn replica_commit_is_atomic_and_quarantine_survives_restart() {
    let a = Lab::new();
    a.finish().unwrap();
    let env = a.envelope();
    let trusted = env.namespace_descriptor.clone();
    let dir = tempfile::tempdir().unwrap();
    let b = TransactionalTransparencyStore::open(dir.path()).unwrap();
    let conn =
        rusqlite::Connection::open(dir.path().join("satspath-transparency-v1.sqlite3")).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_replica_head BEFORE INSERT ON replica_heads BEGIN SELECT RAISE(ABORT, 'injected commit failure'); END;").unwrap();
    assert!(b
        .commit_replica_batch(&trusted, &[env.clone()], now())
        .is_err());
    assert!(b.replica_pin(&trusted.log_id).unwrap().is_none());
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM replica_envelopes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    conn.execute_batch("DROP TRIGGER fail_replica_head")
        .unwrap();
    b.commit_replica_batch(&trusted, &[env.clone()], now())
        .unwrap();
    b.quarantine_replica(&trusted.log_id, "observed fork")
        .unwrap();
    drop(b);
    let b = TransactionalTransparencyStore::open(dir.path()).unwrap();
    assert!(b.replica_resolution(&trusted, ALICE, now()).is_err());
    assert!(
        b.commit_replica_batch(&trusted, &[env], now()).is_err(),
        "valid replay must not clear quarantine"
    );
}

#[test]
fn owner_cannot_cross_bind_a_profile_to_another_alias_event() {
    let mut a = Lab::new();
    a.event.identifier_hash = identifier_hash("other@lab.satspath.test");
    a.event.sign(&a.owner.secret_key).unwrap();
    assert!(a
        .store
        .load_log()
        .unwrap()
        .prepare_append(a.event.clone(), &a.signed)
        .is_err());
    assert!(verify_event_profile(&a.event, &a.signed).is_err());
    assert!(a.finish().is_err());
    a.empty();
}

#[test]
fn untrusted_sybil_endpoints_never_win_authority_selection() {
    let authorized = ReplicaEndpoint {
        url: "https://authorized.example".into(),
        role: EndpointRole::Replica,
        priority: 1,
    };
    let mut health: Vec<_> = (0..1000)
        .map(|n| ReplicaHealth {
            endpoint: ReplicaEndpoint {
                url: format!("https://sybil-{n}.example"),
                role: EndpointRole::Primary,
                priority: 0,
            },
            latest_checkpoint_age_secs: 0,
            latest_tree_size: u64::MAX,
            is_healthy: true,
        })
        .collect();
    assert!(select_endpoint(std::slice::from_ref(&authorized), &health).is_none());
    health.push(ReplicaHealth {
        endpoint: authorized.clone(),
        latest_checkpoint_age_secs: 0,
        latest_tree_size: 1,
        is_healthy: true,
    });
    assert_eq!(
        select_endpoint(std::slice::from_ref(&authorized), &health),
        Some(authorized.clone())
    );
    health.last_mut().unwrap().latest_checkpoint_age_secs = -1;
    assert!(select_endpoint(std::slice::from_ref(&authorized), &health).is_none());
    health.last_mut().unwrap().latest_checkpoint_age_secs = MAX_STALENESS_WINDOW_SECS + 1;
    assert!(select_endpoint(&[authorized], &health).is_none());
}

fn cosign(key: &IdentityKeypair, cp: &TransparencyCheckpoint, id: &str) -> WitnessCosignature {
    let mut receipt = WitnessCosignature {
        version: 1,
        witness_id: id.into(),
        witness_pubkey: key.public_key.to_string(),
        checkpoint_hash: cp.checkpoint_hash().unwrap(),
        tree_size: cp.log_size,
        timestamp: now(),
        signature: String::new(),
    };
    receipt.signature = sign_message(&receipt.signing_message(), &key.secret_key);
    receipt
}

#[test]
fn authorized_witness_failure_and_thousand_sybils_do_not_downgrade_quorum() {
    let a = Lab::new();
    a.finish().unwrap();
    let mut env = a.envelope();
    let witnesses: Vec<_> = (0..3).map(|_| generate_identity_keypair()).collect();
    env.namespace_descriptor.witness_quorum = 2;
    env.namespace_descriptor.witness_pubkeys =
        witnesses.iter().map(|w| w.public_key.to_string()).collect();
    env.namespace_descriptor
        .sign(&a.operator.secret_key)
        .unwrap();
    let trusted = env.namespace_descriptor.clone();
    env.witness_cosignatures = witnesses
        .iter()
        .enumerate()
        .map(|(i, w)| cosign(w, &env.checkpoint, &format!("w{i}")))
        .collect();
    verify_resolution(ALICE, &trusted, &env, None, now()).unwrap();
    env.witness_cosignatures.pop(); // One failed witness, 2-of-3 still satisfied.
    verify_resolution(ALICE, &trusted, &env, None, now()).unwrap();
    env.witness_cosignatures.pop(); // Only one authorized witness remains.
    for n in 0..1000 {
        let sybil = generate_identity_keypair();
        env.witness_cosignatures
            .push(cosign(&sybil, &env.checkpoint, &format!("sybil-{n}")));
    }
    assert!(verify_resolution(ALICE, &trusted, &env, None, now()).is_err());
    env.witness_cosignatures = vec![env.witness_cosignatures[0].clone(); 1000];
    assert!(
        verify_resolution(ALICE, &trusted, &env, None, now()).is_err(),
        "same authorized key cannot vote twice"
    );
    // Alternative text encodings of the same public key are still one witness.
    let mut upper = env.witness_cosignatures[0].clone();
    upper.witness_pubkey = upper.witness_pubkey.to_ascii_uppercase();
    env.witness_cosignatures = vec![env.witness_cosignatures[0].clone(), upper];
    assert!(verify_resolution(ALICE, &trusted, &env, None, now()).is_err());
    // P and -P are the SAME BIP340 x-only verification identity.
    let first = env.witness_cosignatures[0].clone();
    let mut opposite = first.clone();
    let prefix = if opposite.witness_pubkey.starts_with("02") {
        "03"
    } else {
        "02"
    };
    opposite.witness_pubkey.replace_range(..2, prefix);
    assert!(matches!(
        verify_witness_quorum_against_checkpoint(
            Some(&env.checkpoint),
            &[first.clone(), opposite.clone()],
            2,
            &[first.witness_pubkey, opposite.witness_pubkey]
        ),
        DimensionStatus::Failed(_)
    ));
    env.witness_cosignatures.clear();
    assert!(verify_resolution(ALICE, &trusted, &env, None, now()).is_err());
}

#[tokio::test]
async fn authorized_failover_on_unavailability_but_never_on_invalid_evidence() {
    let a = Lab::new();
    a.finish().unwrap();
    let mut primary = mockito::Server::new_async().await;
    let mut replica = mockito::Server::new_async().await;
    let mut envelope = a.envelope();
    envelope.namespace_descriptor.endpoint_urls = vec![primary.url(), replica.url()];
    envelope
        .namespace_descriptor
        .sign(&a.operator.secret_key)
        .unwrap();
    let trusted = envelope.namespace_descriptor.clone();
    let primary_down = primary
        .mock("GET", "/v2/resolve")
        .match_query(mockito::Matcher::Any)
        .with_status(503)
        .create_async()
        .await;
    let secondary = replica
        .mock("GET", "/v2/resolve")
        .match_query(mockito::Matcher::Any)
        .with_body(serde_json::to_string(&envelope).unwrap())
        .create_async()
        .await;
    let (origin, _) = resolve_lab_network(&trusted, ALICE, None).await.unwrap();
    assert_eq!(origin, replica.url());
    primary_down.assert_async().await;
    secondary.assert_async().await;
    primary_down.remove_async().await;
    secondary.remove_async().await;
    let mut tampered = envelope;
    tampered.signed_profile.signature = "00".repeat(64);
    let bad = primary
        .mock("GET", "/v2/resolve")
        .match_query(mockito::Matcher::Any)
        .with_body(serde_json::to_string(&tampered).unwrap())
        .create_async()
        .await;
    let forbidden = replica
        .mock("GET", "/v2/resolve")
        .match_query(mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    assert!(resolve_lab_network(&trusted, ALICE, None).await.is_err());
    bad.assert_async().await;
    forbidden.assert_async().await;
    assert!(
        fetch_lab_resolution(&trusted, "http://127.0.0.1:1", ALICE, None)
            .await
            .is_err()
    );
}
