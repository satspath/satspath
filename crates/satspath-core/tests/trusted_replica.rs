use satspath_core::{transparency::*, *};
#[path = "support/checkpoint_fixture.rs"]
mod checkpoint_fixture;

fn envelope(
    store: &TransactionalTransparencyStore,
    operator: &IdentityKeypair,
) -> (ResolutionTrustPolicy, ResolutionEnvelope) {
    let log = store.load_log().unwrap();
    let now = chrono::Utc::now().timestamp();
    let mut descriptor = NamespaceDescriptor {
        version: 2,
        domain: "example.com".into(),
        log_id: store.log_id().into(),
        authority_pubkey: operator.public_key.to_string(),
        endpoint_urls: vec!["https://example.com/".into()],
        witness_quorum: 0,
        witness_pubkeys: vec![],
        valid_from: now - 60,
        expires_at: now + 172800,
        signature: String::new(),
    };
    descriptor.sign(&operator.secret_key).unwrap();
    let event = log.events().last().unwrap();
    let envelope = ResolutionEnvelope {
        version: 2,
        identifier: "alice@example.com".into(),
        namespace_descriptor: descriptor.clone(),
        signed_profile: store.profile("alice@example.com").unwrap().unwrap(),
        name_events: log.events().to_vec(),
        inclusion_proof: log.inclusion(&event.event_hash().unwrap(), None).unwrap(),
        checkpoint: log.checkpoints().last().unwrap().clone(),
        consistency_proof: None,
        current_state_proof: Some(
            log.prove_state(&identifier_hash("alice@example.com"))
                .unwrap(),
        ),
        witness_cosignatures: vec![],
        served_at: now,
    };
    (
        ResolutionTrustPolicy {
            descriptor,
            freshness: FreshnessPolicy::default(),
            mode: TrustMode::Laboratory,
        },
        envelope,
    )
}

fn link(index: u64, envelope: &ResolutionEnvelope) -> CheckpointLink {
    CheckpointLink {
        cursor: CheckpointCursor {
            index,
            checkpoint: envelope.checkpoint.clone(),
        },
        consistency: None,
    }
}

#[test]
fn independent_replica_renewal_restart_expiry_and_policy_downgrade() {
    let (_authority_dir, authority, operator) = checkpoint_fixture::fixture();
    let (policy, mut response) = envelope(&authority, &operator);
    let dir = tempfile::tempdir().unwrap();
    let replica = TransactionalTransparencyStore::open(dir.path()).unwrap();
    let now = response.checkpoint.created_at;
    replica.pin_resolution_policy(&policy, now).unwrap();
    replica
        .import_verified_resolution(&policy, &[link(0, &response)], &response, now)
        .unwrap();
    let renewed = authority
        .renew_checkpoint(&operator.secret_key, now + 60, 60)
        .unwrap();
    response.checkpoint = renewed.checkpoint;
    replica
        .import_verified_resolution(&policy, &[link(1, &response)], &response, now + 60)
        .unwrap();
    drop(authority);
    drop(replica);
    let replica = TransactionalTransparencyStore::open(dir.path()).unwrap();
    assert_eq!(
        replica
            .replica_cursor(&policy.descriptor.log_id)
            .unwrap()
            .unwrap()
            .index,
        1
    );
    assert!(replica
        .verified_replica_resolution(&policy, "alice@example.com", now + 120)
        .unwrap()
        .is_some());
    assert!(matches!(
        replica.verified_replica_resolution(&policy, "alice@example.com", now + 961),
        Err(SatsPathError::Transparency(
            TransparencyError::ExpiredCheckpoint
        ))
    ));
    let mut weaker = policy.clone();
    weaker.freshness.max_age_secs = 86400;
    assert!(matches!(
        replica.pin_resolution_policy(&weaker, now),
        Err(SatsPathError::Transparency(
            TransparencyError::TrustPolicyMismatch
        ))
    ));
    let mut public = policy.clone();
    public.mode = TrustMode::Public;
    assert!(matches!(
        public.validate(now),
        Err(SatsPathError::Transparency(
            TransparencyError::TrustPolicyMismatch
        ))
    ));
}

#[test]
fn signed_fork_is_durable_quarantine_but_unsigned_modification_is_not() {
    let (_a, authority, operator) = checkpoint_fixture::fixture();
    let (policy, response) = envelope(&authority, &operator);
    let dir = tempfile::tempdir().unwrap();
    let replica = TransactionalTransparencyStore::open(dir.path()).unwrap();
    let now = response.checkpoint.created_at;
    replica.pin_resolution_policy(&policy, now).unwrap();
    replica
        .import_verified_resolution(&policy, &[link(0, &response)], &response, now)
        .unwrap();
    let mut fork = response.clone();
    fork.checkpoint.map_root = Some("aa".repeat(32));
    assert!(matches!(
        replica.import_verified_resolution(&policy, &[link(1, &fork)], &fork, now),
        Err(SatsPathError::Transparency(
            TransparencyError::InvalidCheckpointSignature
        ))
    ));
    assert!(replica
        .verified_replica_resolution(&policy, "alice@example.com", now)
        .unwrap()
        .is_some());
    fork.checkpoint.sign(&operator.secret_key).unwrap();
    assert!(matches!(
        replica.import_verified_resolution(&policy, &[link(1, &fork)], &fork, now),
        Err(SatsPathError::Transparency(
            TransparencyError::ConflictingCheckpoint
        ))
    ));
    drop(replica);
    let replica = TransactionalTransparencyStore::open(dir.path()).unwrap();
    assert!(matches!(
        replica.verified_replica_resolution(&policy, "alice@example.com", now),
        Err(SatsPathError::Transparency(
            TransparencyError::QuarantinedHistory
        ))
    ));
    assert!(matches!(
        replica.import_verified_resolution(&policy, &[], &response, now),
        Err(SatsPathError::Transparency(
            TransparencyError::QuarantinedHistory
        ))
    ));
}

#[test]
fn thousand_duplicate_schnorr_signers_cannot_manufacture_quorum() {
    let (_a, authority, operator) = checkpoint_fixture::fixture();
    let (_policy, response) = envelope(&authority, &operator);
    let witness = generate_identity_keypair();
    assert_eq!(
        witness_signing_identity(&witness.public_key.to_string()),
        witness_signing_identity(&witness.public_key.x_only_public_key().0.to_string())
    );
    let negated = witness.public_key.negate(&secp256k1::Secp256k1::new());
    assert_eq!(
        witness_signing_identity(&witness.public_key.to_string()),
        witness_signing_identity(&negated.to_string())
    );
    let mut receipt = WitnessCosignature {
        version: 1,
        witness_id: "observer".into(),
        witness_pubkey: witness.public_key.to_string(),
        checkpoint_hash: response.checkpoint.checkpoint_hash().unwrap(),
        tree_size: 1,
        timestamp: response.checkpoint.created_at,
        signature: String::new(),
    };
    receipt.signature = sign_message(&receipt.signing_message(), &witness.secret_key);
    let receipts: Vec<_> = (0..1000)
        .map(|n| {
            let mut r = receipt.clone();
            if n % 2 == 0 {
                r.witness_pubkey = negated.to_string();
            }
            r
        })
        .collect();
    assert_eq!(
        verify_witness_quorum_against_checkpoint(
            Some(&response.checkpoint),
            &receipts,
            2,
            &[witness.public_key.to_string(), negated.to_string()]
        ),
        DimensionStatus::Failed(
            "witness quorum not met: 1/2 required valid unique cosignatures".into()
        )
    );
}

#[test]
fn invalid_proofs_and_backfill_are_rejected_without_advancing_pin() {
    let (_a, authority, operator) = checkpoint_fixture::fixture();
    let (policy, response) = envelope(&authority, &operator);
    let dir = tempfile::tempdir().unwrap();
    let replica = TransactionalTransparencyStore::open(dir.path()).unwrap();
    let now = response.checkpoint.created_at;
    replica.pin_resolution_policy(&policy, now).unwrap();
    replica
        .import_verified_resolution(&policy, &[link(0, &response)], &response, now)
        .unwrap();
    let mut bad = response.clone();
    bad.inclusion_proof.root_hash = "ff".repeat(32);
    assert!(matches!(
        replica.import_verified_resolution(&policy, &[], &bad, now),
        Err(SatsPathError::Transparency(
            TransparencyError::CheckpointInclusionMismatch
        ))
    ));
    bad = response.clone();
    bad.current_state_proof.as_mut().unwrap().audit_path[0] = "ff".repeat(32);
    assert!(matches!(
        replica.import_verified_resolution(&policy, &[], &bad, now),
        Err(SatsPathError::Transparency(
            TransparencyError::CheckpointInclusionMismatch
        ))
    ));
    let next = authority
        .renew_checkpoint(&operator.secret_key, now + 60, 60)
        .unwrap();
    bad = response.clone();
    bad.checkpoint = next.checkpoint;
    assert!(matches!(
        replica.import_verified_resolution(&policy, &[link(2, &bad)], &bad, now + 60),
        Err(SatsPathError::Transparency(
            TransparencyError::CheckpointHistoryGap
        ))
    ));
    assert_eq!(
        replica
            .replica_cursor(&policy.descriptor.log_id)
            .unwrap()
            .unwrap()
            .index,
        0
    );
    assert!(replica
        .verified_replica_resolution(&policy, "alice@example.com", now)
        .unwrap()
        .is_some());
    assert!(replica
        .verified_replica_resolution(&policy, "missing@example.com", now)
        .unwrap()
        .is_none());
}

#[test]
fn authenticated_revocation_survives_restart_and_old_profile_cannot_return() {
    let (_a, authority, operator, owner) = checkpoint_fixture::fixture_with_owner();
    let (policy, response) = envelope(&authority, &operator);
    let dir = tempfile::tempdir().unwrap();
    let replica = TransactionalTransparencyStore::open(dir.path()).unwrap();
    let now = response.checkpoint.created_at;
    replica.pin_resolution_policy(&policy, now).unwrap();
    replica
        .import_verified_resolution(&policy, &[link(0, &response)], &response, now)
        .unwrap();
    let mut profile = response.signed_profile.profile.clone();
    profile.revoked = true;
    profile.sequence = Some(1);
    let signed = sign_profile(profile, &owner.secret_key).unwrap();
    let mut event = response.name_events[0].clone();
    event.action = NameAction::Revoke;
    event.sequence = 1;
    event.previous_event_hash = Some(response.name_events[0].event_hash().unwrap());
    event.profile_hash = profile_hash(&signed).unwrap();
    event.sign(&owner.secret_key).unwrap();
    let checkpoint = authority
        .load_log()
        .unwrap()
        .prepare_append(event.clone(), &signed)
        .unwrap()
        .prepare_checkpoint(&operator.secret_key)
        .unwrap();
    authority
        .commit_profile_event_checkpoint("alice@example.com", &signed, &event, &checkpoint)
        .unwrap();
    let (_, mut revoked) = envelope(&authority, &operator);
    revoked.namespace_descriptor = policy.descriptor.clone();
    let mut advance = link(1, &revoked);
    advance.consistency = Some(authority.load_log().unwrap().consistency(1, 2).unwrap());
    replica
        .import_verified_resolution(&policy, &[advance], &revoked, now)
        .unwrap();
    drop(replica);
    let replica = TransactionalTransparencyStore::open(dir.path()).unwrap();
    assert!(matches!(
        replica.verified_replica_resolution(&policy, "alice@example.com", now),
        Err(SatsPathError::Transparency(
            TransparencyError::RevokedIdentifier
        ))
    ));
    assert!(matches!(
        replica.import_verified_resolution(&policy, &[link(0, &response)], &response, now),
        Err(SatsPathError::Transparency(
            TransparencyError::CheckpointHistoryGap
        ))
    ));
}
