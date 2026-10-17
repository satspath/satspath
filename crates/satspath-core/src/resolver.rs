use async_trait::async_trait;

use crate::crypto::{canonical_profile_bytes, check_profile_expiry, verify_signed_profile};
use crate::privacy::canonical_identifier;
use crate::{Result, SatsPathError, SignedPaymentProfile};
use serde::{Deserialize, Serialize};

use crate::transparency::{
    IdentifierAttestation, MerkleConsistencyProof, MerkleInclusionProof, NameEvent,
    TransparencyCheckpoint,
};
use crate::{MethodTrust, TrustTier};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolverSource {
    LocalRegistry,
    Http,
    Bip353,
    Nostr,
    P2p,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStates {
    pub profile_signature_verified: bool,
    pub identifier_verified: bool,
    pub key_continuity_verified: bool,
    pub transparency_inclusion_verified: bool,
    pub checkpoint_binding_verified: bool,
    pub checkpoint_consistency_verified: bool,
    pub operator_continuity_verified: bool,
    pub payment_methods_verified: bool,
    pub payment_method_states: Vec<PaymentMethodVerificationState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethodVerificationState {
    pub descriptor: String,
    pub verified: bool,
    pub trust_tier: Option<TrustTier>,
    pub reason: String,
}

pub fn verify_payment_method_states(
    profile: &crate::PaymentProfile,
    now: i64,
) -> Vec<PaymentMethodVerificationState> {
    profile
        .methods
        .iter()
        .map(|method| {
            let descriptor = method.ownership_descriptor();
            let matches = profile
                .method_verifications
                .iter()
                .filter(|proof| proof.method_descriptor == descriptor)
                .count();
            if matches > 1 {
                return PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason: "duplicate ownership proofs".into(),
                };
            }
            match crate::evaluate_method_trust_for_profile(profile, method, now, None) {
                MethodTrust::Verified(tier) => PaymentMethodVerificationState {
                    descriptor,
                    verified: true,
                    trust_tier: Some(tier),
                    reason: format!("valid {} ownership proof", tier.label()),
                },
                MethodTrust::SelfAsserted => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: Some(TrustTier::SelfAsserted),
                    reason: "self-attestation is not independent ownership proof".into(),
                },
                MethodTrust::NeedsNetworkCheck(tier) => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: Some(tier),
                    reason: "domain proof requires fresh network verification".into(),
                },
                MethodTrust::Unverified => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason: "ownership proof missing or bound to another descriptor".into(),
                },
                MethodTrust::Expired => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason: "ownership proof expired".into(),
                },
                MethodTrust::Invalid(reason) => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason,
                },
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedTransparentProfile {
    pub signed_profile: SignedPaymentProfile,
    pub latest_event: NameEvent,
    pub inclusion_proof: MerkleInclusionProof,
    pub checkpoint: TransparencyCheckpoint,
    pub consistency_proof: Option<MerkleConsistencyProof>,
    pub identifier_attestation: Option<IdentifierAttestation>,
    pub resolver_source: ResolverSource,
    pub verification: VerificationStates,
}

/// A resolver capable of resolving a SatsPath alias to a `SignedPaymentProfile`.
///
/// Implementations could be local (e.g. `LocalRegistryResolver`) or remote
/// (e.g. `HttpResolver` for NIP-05 style public resolution).
#[async_trait]
pub trait ProfileResolver {
    /// Attempt to resolve the alias to a signed profile.
    ///
    /// # Returns
    /// - `Ok(SignedPaymentProfile)` if the alias is found.
    /// - `Err(SatsPathError::AliasNotFound)` if the alias is explicitly not found.
    /// - `Err(SatsPathError::NetworkError)` (or similar) on fetch failure.
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile>;
}

/// Whether a source is eligible to establish the alias or only corroborate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverRole {
    Authoritative,
    Supplementary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverObservation {
    pub source: String,
    pub role: ResolverRole,
    pub found: bool,
}

/// Report returned alongside an agreed, signed profile. A rejection returns
/// `ResolverDisagreement` or the original error, never a payable candidate.
#[derive(Debug, Clone)]
pub struct ResolutionReport {
    pub profile: SignedPaymentProfile,
    pub observations: Vec<ResolverObservation>,
}

struct ResolverEntry {
    source: String,
    role: ResolverRole,
    resolver: Box<dyn ProfileResolver + Send + Sync>,
}

/// A strict composite resolver. All configured sources are queried in order;
/// an outage, invalid signature, divergent key, stale sequence or different
/// capability set blocks payment instead of silently choosing a fallback.
/// Configure only sources actually expected for this identifier.
pub struct ChainResolver {
    resolvers: Vec<ResolverEntry>,
    pinned_key: Option<String>,
    minimum_sequence: Option<u64>,
    required_capabilities: Vec<String>,
}

impl ChainResolver {
    pub fn new() -> Self {
        Self {
            resolvers: Vec::new(),
            pinned_key: None,
            minimum_sequence: None,
            required_capabilities: Vec::new(),
        }
    }

    pub fn push<R: ProfileResolver + Send + Sync + 'static>(mut self, resolver: R) -> Self {
        let source = format!("resolver-{}", self.resolvers.len());
        self.resolvers.push(ResolverEntry {
            source,
            role: ResolverRole::Authoritative,
            resolver: Box::new(resolver),
        });
        self
    }

    /// Register a source which may establish identity on first contact.
    pub fn push_authoritative<R: ProfileResolver + Send + Sync + 'static>(
        mut self,
        source: impl Into<String>,
        resolver: R,
    ) -> Self {
        self.resolvers.push(ResolverEntry {
            source: source.into(),
            role: ResolverRole::Authoritative,
            resolver: Box::new(resolver),
        });
        self
    }

    /// Register an additional source which can corroborate but not establish
    /// identity on its own. Its absence is permitted; its outage is not.
    pub fn push_supplementary<R: ProfileResolver + Send + Sync + 'static>(
        mut self,
        source: impl Into<String>,
        resolver: R,
    ) -> Self {
        self.resolvers.push(ResolverEntry {
            source: source.into(),
            role: ResolverRole::Supplementary,
            resolver: Box::new(resolver),
        });
        self
    }

    /// Set the currently trusted identity key and minimum observed sequence.
    /// Updating a pin after rotation requires independently verified history;
    /// a single resolver's rotation claim never updates it automatically.
    pub fn with_continuity_pin(mut self, key: String, sequence: u64) -> Self {
        self.pinned_key = Some(key);
        self.minimum_sequence = Some(sequence);
        self
    }

    /// Descriptors previously accepted by the wallet. A source suppressing
    /// any of them cannot silently force a lower-capability payment route.
    pub fn with_required_capabilities(mut self, descriptors: Vec<String>) -> Self {
        self.required_capabilities = descriptors;
        self
    }

    pub async fn resolve_with_report(&self, alias: &str) -> Result<ResolutionReport> {
        let canonical = canonical_identifier(alias);
        let mut observations = Vec::with_capacity(self.resolvers.len());
        let mut agreed: Option<Vec<u8>> = None;
        let mut selected = None;
        for entry in &self.resolvers {
            match entry.resolver.resolve_alias(alias).await {
                Ok(signed) => {
                    let profile = &signed.profile;
                    // Never treat unauthenticated revocation, expiry or alias
                    // claims as authoritative protocol outcomes.
                    if !verify_signed_profile(&signed)? {
                        return Err(SatsPathError::InvalidSignature);
                    }
                    if canonical_identifier(&profile.alias) != canonical {
                        return Err(SatsPathError::ResolverDisagreement(format!(
                            "{} returned alias {} instead of {}",
                            entry.source, profile.alias, alias
                        )));
                    }
                    if profile.revoked {
                        return Err(SatsPathError::RegistryError(format!(
                            "Alias {} has been revoked",
                            profile.alias
                        )));
                    }
                    if check_profile_expiry(profile).is_err() {
                        return Err(SatsPathError::ResolverDisagreement(format!(
                            "{} returned an expired profile",
                            entry.source
                        )));
                    }
                    if self
                        .pinned_key
                        .as_ref()
                        .is_some_and(|key| key != &profile.identity_pubkey)
                    {
                        return Err(SatsPathError::UnauthorizedKeyReplacement);
                    }
                    if self
                        .minimum_sequence
                        .is_some_and(|seq| profile.sequence.is_none_or(|n| n < seq))
                    {
                        return Err(SatsPathError::ResolverDisagreement(format!(
                            "{} returned a stale sequence",
                            entry.source
                        )));
                    }
                    if !self.required_capabilities.iter().all(|descriptor| {
                        profile
                            .methods
                            .iter()
                            .any(|method| method.ownership_descriptor() == *descriptor)
                    }) {
                        return Err(SatsPathError::ResolverDisagreement(format!(
                            "{} suppressed a pinned payment capability",
                            entry.source
                        )));
                    }
                    // Equality of the entire signed payload also detects
                    // capability suppression, replay and equal-sequence forks.
                    let bytes = canonical_profile_bytes(profile)?;
                    if agreed.as_ref().is_some_and(|prev| prev != &bytes) {
                        return Err(SatsPathError::ResolverDisagreement(format!(
                            "{} disagrees on identity, sequence or capabilities",
                            entry.source
                        )));
                    }
                    agreed = Some(bytes);
                    if selected.is_none() && entry.role == ResolverRole::Authoritative {
                        selected = Some(signed);
                    }
                    observations.push(ResolverObservation {
                        source: entry.source.clone(),
                        role: entry.role,
                        found: true,
                    });
                }
                Err(SatsPathError::AliasNotFound(_)) => observations.push(ResolverObservation {
                    source: entry.source.clone(),
                    role: entry.role,
                    found: false,
                }),
                Err(SatsPathError::NetworkError(reason)) => {
                    return Err(SatsPathError::NetworkError(format!(
                        "{} unavailable; refusing downgrade: {reason}",
                        entry.source
                    )));
                }
                Err(error) => return Err(error),
            }
        }
        let profile = selected.ok_or_else(|| {
            if agreed.is_some() {
                SatsPathError::ResolverDisagreement(
                    "only supplementary sources returned a profile".into(),
                )
            } else {
                SatsPathError::AliasNotFound(alias.into())
            }
        })?;
        Ok(ResolutionReport {
            profile,
            observations,
        })
    }
}

impl Default for ChainResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProfileResolver for ChainResolver {
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        Ok(self.resolve_with_report(alias).await?.profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_identity_keypair, sign_profile};
    use crate::profile::{PaymentMethod, PaymentProfile};

    struct MockResolver {
        should_succeed: bool,
        returned_alias: Option<String>,
    }

    #[async_trait]
    impl ProfileResolver for MockResolver {
        async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
            if self.should_succeed {
                let kp = generate_identity_keypair();
                let pubkey_hex = hex::encode(kp.public_key.serialize());
                let profile_alias = self
                    .returned_alias
                    .clone()
                    .unwrap_or_else(|| alias.to_string());
                let profile = PaymentProfile {
                    alias: profile_alias.clone(),
                    identity_pubkey: pubkey_hex,
                    methods: vec![PaymentMethod::Lightning {
                        label: "LN".into(),
                        lightning_address: Some(profile_alias),
                        lnurl: None,
                        bolt12: None,
                        receiver_pubkey: None,
                    }],
                    updated_at: 1_700_000_000,
                    expires_at: None,
                    sequence: None,
                    preferences: vec![],
                    nonce: None,
                    rotation: None,
                    method_verifications: Vec::new(),
                    hybrid_pubkey: None,
                    pqc_required: false,
                    revoked: false,
                    recovery_policy: None,
                    recovery: None,
                };
                Ok(sign_profile(profile, &kp.secret_key).unwrap())
            } else {
                Err(SatsPathError::AliasNotFound(alias.to_string()))
            }
        }
    }

    #[tokio::test]
    async fn chain_resolver_success() {
        let chain = ChainResolver::new()
            .push(MockResolver {
                should_succeed: false,
                returned_alias: None,
            })
            .push(MockResolver {
                should_succeed: true,
                returned_alias: None,
            });

        let res = chain.resolve_alias("test@domain.com").await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap().profile.alias, "test@domain.com");
    }

    #[tokio::test]
    async fn chain_resolver_failure() {
        let chain = ChainResolver::new()
            .push(MockResolver {
                should_succeed: false,
                returned_alias: None,
            })
            .push(MockResolver {
                should_succeed: false,
                returned_alias: None,
            });

        let res = chain.resolve_alias("test@domain.com").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn chain_resolver_rejects_substituted_alias() {
        // We ask the mock resolver to succeed, which always returns a profile
        // for "test@domain.com".
        let chain = ChainResolver::new().push(MockResolver {
            should_succeed: true,
            returned_alias: Some("test@domain.com".to_string()),
        });

        // But we request "alice@domain.com".
        // The resolver will return "test@domain.com", which should trigger
        // the SEC-02 Profile Substitution Attack mitigation.
        let res = chain.resolve_alias("alice@domain.com").await;

        assert!(res.is_err());
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("resolver disagreement"),
            "Expected security failure message, got: {}",
            err
        );
        assert!(err.contains("alice@domain.com"));
        assert!(err.contains("test@domain.com"));
    }
}
