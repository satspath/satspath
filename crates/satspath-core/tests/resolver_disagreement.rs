use async_trait::async_trait;
use satspath_core::crypto::{sign_profile, verify_signed_profile};
use satspath_core::resolver::{ChainResolver, ProfileResolver, ResolverRole};
use satspath_core::{
    BitcoinNetwork, PaymentMethod, PaymentProfile, SatsPathError, SignedPaymentProfile,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

struct StaticResolver(satspath_core::Result<SignedPaymentProfile>);

#[async_trait]
impl ProfileResolver for StaticResolver {
    async fn resolve_alias(&self, _: &str) -> satspath_core::Result<SignedPaymentProfile> {
        match &self.0 {
            Ok(profile) => Ok(profile.clone()),
            Err(SatsPathError::AliasNotFound(message)) => {
                Err(SatsPathError::AliasNotFound(message.clone()))
            }
            Err(SatsPathError::NetworkError(message)) => {
                Err(SatsPathError::NetworkError(message.clone()))
            }
            Err(error) => panic!("unsupported test error: {error}"),
        }
    }
}

fn signed_profile(key: &SecretKey, sequence: u64, address: &str) -> SignedPaymentProfile {
    let pubkey = PublicKey::from_secret_key(&Secp256k1::new(), key);
    sign_profile(
        PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: pubkey.to_string(),
            methods: vec![PaymentMethod::Onchain {
                label: "bitcoin".into(),
                network: BitcoinNetwork::Testnet,
                address: Some(address.into()),
                silent_payment_pubkey: None,
                pubkey_hint: None,
                descriptor_hint: None,
                address_list: vec![],
            }],
            updated_at: 1_700_000_000,
            expires_at: None,
            sequence: Some(sequence),
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
        key,
    )
    .unwrap()
}

#[tokio::test]
async fn matching_sources_return_deterministic_report_and_signed_profile() {
    let signed = signed_profile(&SecretKey::from_slice(&[1; 32]).unwrap(), 7, "tb1qexample");
    let resolver = ChainResolver::new()
        .push_authoritative("https", StaticResolver(Ok(signed.clone())))
        .push_supplementary("nostr", StaticResolver(Ok(signed.clone())))
        .with_continuity_pin(signed.profile.identity_pubkey.clone(), 7);
    let first = resolver
        .resolve_with_report("alice@example.com")
        .await
        .unwrap();
    let second = resolver
        .resolve_with_report("alice@example.com")
        .await
        .unwrap();
    assert!(verify_signed_profile(&first.profile).unwrap());
    assert_eq!(first.observations, second.observations);
    assert_eq!(first.observations[0].role, ResolverRole::Authoritative);
    assert_eq!(first.observations[1].source, "nostr");
    assert!(first
        .observations
        .iter()
        .all(|observation| observation.found));
}

#[tokio::test]
async fn conflict_vectors_fail_closed() {
    let key = SecretKey::from_slice(&[1; 32]).unwrap();
    let other = SecretKey::from_slice(&[2; 32]).unwrap();
    let base = signed_profile(&key, 7, "tb1qexample");
    let cases = [
        (signed_profile(&other, 7, "tb1qexample"), "disagrees"),
        (signed_profile(&key, 6, "tb1qexample"), "disagrees"),
        (signed_profile(&key, 7, "tb1qother"), "disagrees"),
    ];
    for (conflict, message) in cases {
        let resolver = ChainResolver::new()
            .push_authoritative("https", StaticResolver(Ok(base.clone())))
            .push_supplementary("nostr", StaticResolver(Ok(conflict)));
        assert!(resolver
            .resolve_alias("alice@example.com")
            .await
            .unwrap_err()
            .to_string()
            .contains(message));
    }
    let mut invalid = base.clone();
    invalid.profile.methods.clear();
    let resolver = ChainResolver::new().push_authoritative("https", StaticResolver(Ok(invalid)));
    assert!(matches!(
        resolver.resolve_alias("alice@example.com").await,
        Err(SatsPathError::InvalidSignature)
    ));

    let mut expired = base.clone().profile;
    expired.expires_at = Some(1);
    let resolver = ChainResolver::new().push_authoritative(
        "https",
        StaticResolver(Ok(sign_profile(expired, &key).unwrap())),
    );
    assert!(resolver.resolve_alias("alice@example.com").await.is_err());
}

#[tokio::test]
async fn outages_and_pins_never_trigger_downgrade() {
    let key = SecretKey::from_slice(&[1; 32]).unwrap();
    let base = signed_profile(&key, 7, "tb1qexample");
    let unavailable = || StaticResolver(Err(SatsPathError::NetworkError("blocked".into())));
    let resolver = ChainResolver::new()
        .push_authoritative("https", unavailable())
        .push_supplementary("nostr", StaticResolver(Ok(base.clone())));
    assert!(resolver
        .resolve_alias("alice@example.com")
        .await
        .unwrap_err()
        .to_string()
        .contains("refusing downgrade"));
    let resolver = ChainResolver::new()
        .push_authoritative("https", StaticResolver(Ok(base.clone())))
        .push_supplementary("nostr", unavailable());
    assert!(resolver.resolve_alias("alice@example.com").await.is_err());
    let resolver =
        ChainResolver::new().push_supplementary("nostr", StaticResolver(Ok(base.clone())));
    assert!(resolver.resolve_alias("alice@example.com").await.is_err());
    let resolver = ChainResolver::new()
        .push_authoritative("https", StaticResolver(Ok(base.clone())))
        .with_continuity_pin(base.profile.identity_pubkey.clone(), 8);
    assert!(resolver
        .resolve_alias("alice@example.com")
        .await
        .unwrap_err()
        .to_string()
        .contains("stale"));
    let resolver = ChainResolver::new()
        .push_authoritative("https", StaticResolver(Ok(base.clone())))
        .with_continuity_pin("different-key".into(), 7);
    assert!(matches!(
        resolver.resolve_alias("alice@example.com").await,
        Err(SatsPathError::UnauthorizedKeyReplacement)
    ));
    let resolver = ChainResolver::new()
        .push_authoritative("https", StaticResolver(Ok(base.clone())))
        .with_required_capabilities(vec!["onchain:testnet:tb1qprevious".into()]);
    assert!(resolver
        .resolve_alias("alice@example.com")
        .await
        .unwrap_err()
        .to_string()
        .contains("suppressed"));
    let resolver = ChainResolver::new()
        .push_authoritative(
            "https",
            StaticResolver(Err(SatsPathError::AliasNotFound(
                "alice@example.com".into(),
            ))),
        )
        .push_authoritative("bip353", StaticResolver(Ok(base)));
    assert!(resolver.resolve_alias("alice@example.com").await.is_ok());
}
