use satspath_core::{lab::*, transparency::*, *};
#[path = "support/lab_fixture.rs"]
mod fixture;
use fixture::*;
#[test]
fn legitimate_registration_restart_and_independent_verification() {
    let lab = Lab::new();
    lab.finish().unwrap();
    let reopened = TransactionalTransparencyStore::open(lab.dir.path()).unwrap();
    assert_eq!(
        profile_hash(&reopened.profile(ALICE).unwrap().unwrap()).unwrap(),
        profile_hash(&lab.signed).unwrap()
    );
    let env = lab.envelope();
    verify_resolution(
        ALICE,
        &env.namespace_descriptor,
        &env,
        None,
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    assert!(lab.finish().is_err(), "challenge replay");
    assert_eq!(reopened.load_log().unwrap().events().len(), 1);
}

#[test]
fn namespace_and_network_fail_closed() {
    for network in ["mainnet", "bitcoin", "testnet", "signet", "Regtest", ""] {
        assert!(require_lab(network, true, ALICE).is_err());
    }
    for alias in [
        "alice@gmail.com",
        "support@blink.sv",
        "alice@satspath.com",
        "Alice@lab.satspath.test",
        "a@x@lab.satspath.test",
        "a\n@lab.satspath.test",
        "@lab.satspath.test",
    ] {
        assert!(require_lab("regtest", true, alias).is_err());
    }
    assert!(require_lab("regtest", false, ALICE).is_err());
    assert!(require_lab("devnet", true, ALICE).is_ok());
}

#[test]
fn substituted_key_altered_signature_and_challenge_rejected_without_writes() {
    let mut lab = Lab::new();
    let original = lab.challenge.clone();
    lab.challenge.identity_pubkey = generate_identity_keypair().public_key.to_string();
    assert!(lab.finish().is_err());
    lab.empty();
    lab.challenge = original;
    lab.challenge.operation = "rotate".into();
    assert!(lab.finish().is_err());
    lab.empty();
    lab.challenge.operation = "register".into();
    lab.challenge.nonce = generate_nonce();
    assert!(lab.finish().is_err());
    lab.empty();
    lab.challenge.nonce = original_nonce(&lab.store, lab.dir.path());
    lab.signed.signature = "00".repeat(64);
    assert!(lab.finish().is_err());
    lab.empty();
}

fn original_nonce(_store: &TransactionalTransparencyStore, home: &std::path::Path) -> String {
    rusqlite::Connection::open(home.join("satspath-transparency-v1.sqlite3"))
        .unwrap()
        .query_row("SELECT nonce FROM lab_reservations", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn expired_challenge_and_expired_profile_rejected() {
    let mut lab = Lab::new();
    lab.challenge.expires_at = chrono::Utc::now().timestamp() - 1;
    assert!(lab.finish().is_err());
    lab.empty();
    let mut lab = Lab::new();
    lab.signed.profile.expires_at = Some(chrono::Utc::now().timestamp() - 1);
    lab.signed = sign_profile(lab.signed.profile.clone(), &lab.owner.secret_key).unwrap();
    assert!(lab.finish().is_err());
    lab.empty();
}

#[test]
fn operator_authorization_required_and_legacy_bypass_rejected() {
    let lab = Lab::new();
    let expiry = chrono::Utc::now().timestamp() + 100;
    let approval = sign_message(
        &admission_message(
            lab.store.log_id(),
            "bob@lab.satspath.test",
            &lab.owner.public_key.to_string(),
            expiry,
        ),
        &lab.owner.secret_key,
    );
    assert!(lab
        .store
        .reserve_lab_name(
            "regtest",
            true,
            "bob@lab.satspath.test",
            &lab.owner.public_key.to_string(),
            &lab.operator.public_key.to_string(),
            &approval,
            expiry
        )
        .is_err());
    assert!(lab
        .store
        .commit_profile_event_checkpoint(ALICE, &lab.signed, &lab.event, &lab.checkpoint)
        .is_err());
    lab.empty();
}

#[test]
fn concurrent_reservations_have_exactly_one_winner() {
    let lab = Lab::new();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let expiry = chrono::Utc::now().timestamp() + 200;
    let mut threads = vec![];
    for _ in 0..2 {
        let home = lab.dir.path().to_owned();
        let barrier = barrier.clone();
        let owner = lab.owner.public_key.to_string();
        let operator = lab.operator.public_key.to_string();
        let approval = sign_message(
            &admission_message(lab.store.log_id(), "bob@lab.satspath.test", &owner, expiry),
            &lab.operator.secret_key,
        );
        threads.push(std::thread::spawn(move || {
            let store = TransactionalTransparencyStore::open(&home).unwrap();
            barrier.wait();
            store
                .reserve_lab_name(
                    "regtest",
                    true,
                    "bob@lab.satspath.test",
                    &owner,
                    &operator,
                    &approval,
                    expiry,
                )
                .is_ok()
        }));
    }
    assert_eq!(
        threads
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|ok| *ok)
            .count(),
        1
    );
}

#[test]
fn partial_storage_failure_rolls_back_challenge_and_all_artifacts() {
    let lab = Lab::new();
    let conn = rusqlite::Connection::open(lab.dir.path().join("satspath-transparency-v1.sqlite3"))
        .unwrap();
    conn.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected disk failure'); END;").unwrap();
    assert!(lab.finish().is_err());
    lab.empty();
    let consumed: i64 = conn
        .query_row("SELECT consumed FROM lab_reservations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(consumed, 0);
    conn.execute_batch("DROP TRIGGER fail_checkpoint").unwrap();
    lab.finish().unwrap();
}

#[test]
fn remote_evidence_tampering_rejected() {
    let lab = Lab::new();
    lab.finish().unwrap();
    let envelope = lab.envelope();
    let trusted = envelope.namespace_descriptor.clone();
    assert_eq!(
        verify_namespace_binding(&trusted, LAB_NAMESPACE),
        DimensionStatus::Skipped
    );
    let now = chrono::Utc::now().timestamp();
    let reject =
        |e: &ResolutionEnvelope| assert!(verify_resolution(ALICE, &trusted, e, None, now).is_err());
    let rogue = Lab::new();
    rogue.finish().unwrap();
    reject(&rogue.envelope());
    let pin = CheckpointStore::new(lab.dir.path())
        .pin(&envelope.checkpoint)
        .unwrap();
    let rollback_pin = PinnedCheckpoint {
        tree_size: pin.tree_size + 1,
        ..pin
    };
    assert!(verify_resolution(ALICE, &trusted, &envelope, Some(&rollback_pin), now).is_err());
    let mut e = envelope.clone();
    e.signed_profile.profile.methods.clear();
    reject(&e);
    let mut e = envelope.clone();
    e.checkpoint.log_root = "00".repeat(32);
    reject(&e);
    let mut e = envelope.clone();
    e.namespace_descriptor.authority_pubkey = generate_identity_keypair().public_key.to_string();
    reject(&e);
    let mut e = envelope.clone();
    e.current_state_proof = None;
    reject(&e);
    let mut e = envelope.clone();
    e.current_state_proof.as_mut().unwrap().key_hash = "00".repeat(32);
    reject(&e);
    let mut e = envelope.clone();
    e.namespace_descriptor.signature.clear();
    reject(&e);
    assert!(verify_resolution(ALICE, &trusted, &envelope, None, now + 4000).is_err());
    assert!(verify_resolution("bob@lab.satspath.test", &trusted, &envelope, None, now).is_err());
    let mut changed = lab.signed.clone();
    if let PaymentMethod::Lightning {
        lightning_address, ..
    } = &mut changed.profile.methods[0]
    {
        *lightning_address = Some("attacker@blink.sv".into());
    }
    assert!(!verify_signed_profile(&changed).unwrap());
}
