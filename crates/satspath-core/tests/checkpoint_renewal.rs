use satspath_core::{transparency::*, *};

fn fixture() -> (
    tempfile::TempDir,
    TransactionalTransparencyStore,
    IdentityKeypair,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
    let owner = generate_identity_keypair();
    let operator = generate_identity_keypair();
    let now = chrono::Utc::now().timestamp();
    let signed = sign_profile(
        PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: owner.public_key.to_string(),
            methods: vec![],
            updated_at: now,
            expires_at: Some(now + 172800),
            sequence: Some(0),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: None,
            recovery: None,
        },
        &owner.secret_key,
    )
    .unwrap();
    let mut event = NameEvent {
        version: 1,
        identifier_hash: identifier_hash(&signed.profile.alias),
        action: NameAction::Register,
        identity_pubkey: signed.profile.identity_pubkey.clone(),
        profile_hash: profile_hash(&signed).unwrap(),
        sequence: 0,
        previous_event_hash: None,
        created_at: now,
        identifier_attestation_hash: None,
        removed_method_hashes: vec![],
        rotation: None,
        recovery_policy: None,
        recovery: None,
        owner_signature: String::new(),
    };
    event.sign(&owner.secret_key).unwrap();
    let checkpoint = store
        .load_log()
        .unwrap()
        .prepare_append(event.clone(), &signed)
        .unwrap()
        .prepare_checkpoint(&operator.secret_key)
        .unwrap();
    store
        .commit_profile_event_checkpoint(&signed.profile.alias, &signed, &event, &checkpoint)
        .unwrap();
    (dir, store, operator)
}

#[test]
fn idle_24_hours_has_signed_durable_renewal_without_profile_or_event_changes() {
    let (dir, store, operator) = fixture();
    let first = store.checkpoint_page(0, 1).unwrap().remove(0);
    let original = profile_hash(&store.profile("alice@example.com").unwrap().unwrap()).unwrap();
    let policy = FreshnessPolicy {
        max_age_secs: 7200,
        future_skew_secs: 60,
    };
    let mut prior = first.clone();
    for hour in 1..=24 {
        let now = first.checkpoint.created_at + hour * 3600;
        let renewed = store
            .renew_checkpoint(&operator.secret_key, now, 3600)
            .unwrap();
        assert_eq!(renewed.index, hour as u64);
        assert_eq!(renewed.checkpoint.log_size, 1);
        verify_checkpoint_successor(&prior.checkpoint, &renewed.checkpoint, None).unwrap();
        policy.check(&renewed.checkpoint, now + 1800).unwrap();
        prior = renewed;
    }
    drop(store);
    let reopened = TransactionalTransparencyStore::open(dir.path()).unwrap();
    assert_eq!(reopened.load_log().unwrap().events().len(), 1);
    assert_eq!(
        profile_hash(&reopened.profile("alice@example.com").unwrap().unwrap()).unwrap(),
        original
    );
    assert_eq!(reopened.checkpoint_page(24, 1).unwrap()[0], prior);
    assert!(matches!(
        policy.check(&first.checkpoint, prior.checkpoint.created_at),
        Err(SatsPathError::Transparency(
            TransparencyError::ExpiredCheckpoint
        ))
    ));
}

#[test]
fn renewal_replay_fork_clock_skew_and_wrong_operator_have_typed_failures() {
    let (_dir, store, operator) = fixture();
    let previous = store.checkpoint_page(0, 1).unwrap().remove(0);
    let now = previous.checkpoint.created_at + 60;
    let next = store
        .renew_checkpoint(&operator.secret_key, now, 60)
        .unwrap();
    assert_eq!(
        store
            .renew_checkpoint(&operator.secret_key, now, 60)
            .unwrap(),
        next
    );
    let mut fork = next.checkpoint.clone();
    fork.map_root = Some("ab".repeat(32));
    fork.sign(&operator.secret_key).unwrap();
    assert!(matches!(
        verify_checkpoint_successor(&previous.checkpoint, &fork, None),
        Err(SatsPathError::Transparency(
            TransparencyError::ConflictingCheckpoint
        ))
    ));
    assert!(matches!(
        verify_checkpoint_successor(&next.checkpoint, &previous.checkpoint, None),
        Err(SatsPathError::Transparency(
            TransparencyError::CheckpointHistoryGap
        ))
    ));
    assert!(matches!(
        store.renew_checkpoint(&operator.secret_key, now - 1, 60),
        Err(SatsPathError::Transparency(
            TransparencyError::CheckpointClockSkew
        ))
    ));
    assert!(matches!(
        store.renew_checkpoint(&generate_identity_keypair().secret_key, now + 60, 60),
        Err(SatsPathError::Transparency(
            TransparencyError::UnexpectedOperatorKey
        ))
    ));
    assert!(matches!(
        FreshnessPolicy::default().check(&next.checkpoint, now - 301),
        Err(SatsPathError::Transparency(
            TransparencyError::CheckpointClockSkew
        ))
    ));
}

#[test]
fn failed_renewal_transaction_preserves_head_and_retry_recovers() {
    let (dir, store, operator) = fixture();
    let first = store.checkpoint_page(0, 1).unwrap().remove(0);
    let conn =
        rusqlite::Connection::open(dir.path().join("satspath-transparency-v1.sqlite3")).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_renewal BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;").unwrap();
    assert!(store
        .renew_checkpoint(&operator.secret_key, first.checkpoint.created_at + 60, 60)
        .is_err());
    assert_eq!(store.checkpoint_page(0, 10).unwrap(), vec![first.clone()]);
    conn.execute_batch("DROP TRIGGER fail_renewal").unwrap();
    assert_eq!(
        store
            .renew_checkpoint(&operator.secret_key, first.checkpoint.created_at + 60, 60)
            .unwrap()
            .index,
        1
    );
}
