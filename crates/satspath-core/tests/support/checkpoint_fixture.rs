use satspath_core::{transparency::*, *};

pub fn fixture() -> (
    tempfile::TempDir,
    TransactionalTransparencyStore,
    IdentityKeypair,
) {
    let (dir, store, operator, _) = fixture_with_owner();
    (dir, store, operator)
}

pub fn fixture_with_owner() -> (
    tempfile::TempDir,
    TransactionalTransparencyStore,
    IdentityKeypair,
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
    (dir, store, operator, owner)
}
