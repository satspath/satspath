use satspath_core::{lab::*, transparency::*, *};

pub const ALICE: &str = "alice@lab.satspath.test";

pub struct Lab {
    pub dir: tempfile::TempDir,
    pub store: TransactionalTransparencyStore,
    pub owner: IdentityKeypair,
    pub operator: IdentityKeypair,
    pub challenge: RegistrationChallenge,
    pub signed: SignedPaymentProfile,
    pub event: NameEvent,
    pub checkpoint: TransparencyCheckpoint,
}

impl Lab {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        let owner = generate_identity_keypair();
        let operator = generate_identity_keypair();
        let now = chrono::Utc::now().timestamp();
        let key = owner.public_key.to_string();
        let expiry = now + 300;
        let approval = sign_message(
            &admission_message(store.log_id(), ALICE, &key, expiry),
            &operator.secret_key,
        );
        let challenge = store
            .reserve_lab_name(
                "regtest",
                true,
                ALICE,
                &key,
                &operator.public_key.to_string(),
                &approval,
                expiry,
            )
            .unwrap();
        let signed = sign_profile(
            PaymentProfile {
                alias: ALICE.into(),
                identity_pubkey: key,
                methods: vec![PaymentMethod::Lightning {
                    label: "LN".into(),
                    lightning_address: Some("alice@example.com".into()),
                    lnurl: None,
                    bolt12: None,
                    receiver_pubkey: None,
                }],
                updated_at: now,
                expires_at: Some(now + 3600),
                sequence: Some(0),
                preferences: vec![],
                nonce: Some(generate_nonce()),
                rotation: None,
                method_verifications: vec![],
                hybrid_pubkey: None,
                pqc_required: false,
                revoked: false,
            },
            &owner.secret_key,
        )
        .unwrap();
        let mut event = NameEvent {
            version: 1,
            identifier_hash: identifier_hash(ALICE),
            action: NameAction::Register,
            identity_pubkey: signed.profile.identity_pubkey.clone(),
            profile_hash: profile_hash(&signed).unwrap(),
            sequence: 0,
            previous_event_hash: None,
            created_at: now,
            identifier_attestation_hash: None,
            removed_method_hashes: vec![],
            rotation: None,
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
        Self {
            dir,
            store,
            owner,
            operator,
            challenge,
            signed,
            event,
            checkpoint,
        }
    }
    pub fn finish(&self) -> Result<()> {
        self.store.complete_lab_registration(
            "regtest",
            true,
            &self.challenge,
            &sign_message(&self.challenge.signing_message()?, &self.owner.secret_key),
            &self.signed,
            &self.event,
            &self.checkpoint,
        )
    }
    pub fn envelope(&self) -> ResolutionEnvelope {
        let now = chrono::Utc::now().timestamp();
        let mut descriptor = NamespaceDescriptor {
            version: 2,
            domain: LAB_NAMESPACE.into(),
            log_id: self.store.log_id().into(),
            authority_pubkey: self.operator.public_key.to_string(),
            endpoint_urls: vec!["https://authority.example".into()],
            witness_quorum: 0,
            witness_pubkeys: vec![],
            valid_from: now - 1,
            expires_at: now + 3600,
            signature: String::new(),
        };
        descriptor.sign(&self.operator.secret_key).unwrap();
        let log = self.store.load_log().unwrap();
        ResolutionEnvelope {
            version: 2,
            identifier: ALICE.into(),
            namespace_descriptor: descriptor,
            signed_profile: self.signed.clone(),
            name_events: log
                .history(&identifier_hash(ALICE))
                .into_iter()
                .cloned()
                .collect(),
            inclusion_proof: log
                .inclusion(&self.event.event_hash().unwrap(), None)
                .unwrap(),
            checkpoint: self.checkpoint.clone(),
            consistency_proof: None,
            current_state_proof: Some(log.prove_state(&identifier_hash(ALICE)).unwrap()),
            witness_cosignatures: vec![],
            served_at: now,
        }
    }
    pub fn empty(&self) {
        assert!(self.store.profile(ALICE).unwrap().is_none());
        assert!(self.store.load_log().unwrap().events().is_empty());
    }
}
