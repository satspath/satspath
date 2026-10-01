//! BIP-353 record **publishing** — kept strictly separate from resolving.
//!
//! Builds the DNS name and TXT payload for a profile, splits it into DNS
//! character-strings, and produces a [`PublishingPlan`] (direct TXT or
//! CNAME/DNAME delegation). Actual DNS mutation goes through the [`DnsPublisher`]
//! trait; only a [`MockDnsPublisher`] ships here — real provider credentials are
//! never committed.
//!
//! Record changes require a cryptographic identity-key signature (see
//! [`authorize_dns_update`]); email verification alone is rejected.
//!
//! Nothing here ever publishes private material — [`assert_public_payment_instruction`]
//! screens every payload before it can be planned.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bip353::Bip353Name;
use crate::crypto::verify_message_signature;
use crate::errors::{Result, SatsPathError};

/// Max bytes per DNS TXT character-string.
pub const TXT_STRING_MAX: usize = 255;

/// Recommended TTL for rotating on-chain addresses (seconds).
pub const TTL_ROTATING_ONCHAIN: u32 = 300;
/// Recommended TTL for reusable BOLT12 / Silent Payment instructions (seconds).
pub const TTL_REUSABLE: u32 = 1800;

/// Terms that must never appear in a published DNS payload.
const FORBIDDEN_TERMS: &[&str] = &[
    "seed",
    "mnemonic",
    "xprv",
    "tprv",
    "private_key",
    "privkey",
    "macaroon",
    "cert",
    "api_key",
    "secret",
    "password",
    "claim_key",
    "refund_key",
    "preimage",
];

/// Reject any payload that is not a safe, public `bitcoin:` payment instruction.
pub fn assert_public_payment_instruction(payload: &str) -> Result<()> {
    if !payload.starts_with("bitcoin:") {
        return Err(SatsPathError::InvalidPaymentUri(
            "DNS payment payload must start with bitcoin:".into(),
        ));
    }
    let lower = payload.to_ascii_lowercase();
    if let Some(term) = FORBIDDEN_TERMS.iter().find(|t| lower.contains(**t)) {
        return Err(SatsPathError::PrivateMaterialRejected((*term).into()));
    }
    // A single TXT RR can hold many character-strings, but a runaway payload is a
    // red flag — keep DNS records sane.
    if payload.len() > TXT_STRING_MAX * 8 {
        return Err(SatsPathError::InvalidPaymentUri(
            "payment payload too large for a DNS TXT record".into(),
        ));
    }
    Ok(())
}

/// Split a payload into `<=255`-byte DNS character-strings (RDATA order).
pub fn chunk_txt(payload: &str) -> Vec<String> {
    let bytes = payload.as_bytes();
    if bytes.is_empty() {
        return vec![String::new()];
    }
    // Chunk on byte boundaries that stay valid UTF-8. BIP-321 URIs are ASCII in
    // practice, so simple byte chunking is safe; guard for multibyte anyway.
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let mut end = (start + TXT_STRING_MAX).min(bytes.len());
        while end > start && std::str::from_utf8(&bytes[start..end]).is_err() {
            end -= 1;
        }
        chunks.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        start = end;
    }
    chunks
}

// ─── Publishing plans ────────────────────────────────────────────────────────────

/// A concrete plan for publishing a BIP-353 record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum PublishingPlan {
    /// The receiver controls their domain and publishes the TXT directly.
    DirectTxt {
        fqdn: String,
        txt_chunks: Vec<String>,
        ttl_seconds: u32,
        warnings: Vec<String>,
    },
    /// The receiver delegates the BIP-353 label to a SatsPath-managed zone via a
    /// one-time CNAME; SatsPath maintains the TXT.
    CnameDelegation {
        /// CNAME the receiver adds once, under their own domain.
        receiver_cname_fqdn: String,
        /// Target the CNAME points to, in the managed zone.
        managed_target_fqdn: String,
        /// TXT record SatsPath maintains in the managed zone.
        managed_txt_fqdn: String,
        txt_chunks: Vec<String>,
        ttl_seconds: u32,
        warnings: Vec<String>,
    },
}

/// Pick a TTL: short for on-chain (rotating) addresses, longer for reusable
/// BOLT12 / Silent Payment style instructions. Adds a rotation warning for
/// on-chain payloads.
fn ttl_and_warnings(bitcoin_uri: &str) -> (u32, Vec<String>) {
    let has_onchain = bitcoin_uri
        .strip_prefix("bitcoin:")
        .map(|rest| !rest.starts_with('?') && !rest.is_empty())
        .unwrap_or(false);
    if has_onchain {
        (
            TTL_ROTATING_ONCHAIN,
            vec![
                "On-chain address present: treat as rotating. Use a fresh address \
                 per payment and a short TTL to preserve privacy."
                    .into(),
            ],
        )
    } else {
        (TTL_REUSABLE, Vec::new())
    }
}

/// Build a **direct TXT** publishing plan for a name the receiver's domain owns.
pub fn plan_direct_txt(name: &Bip353Name, bitcoin_uri: &str) -> Result<PublishingPlan> {
    assert_public_payment_instruction(bitcoin_uri)?;
    let (ttl_seconds, warnings) = ttl_and_warnings(bitcoin_uri);
    Ok(PublishingPlan::DirectTxt {
        fqdn: name.dns_name.clone(),
        txt_chunks: chunk_txt(bitcoin_uri),
        ttl_seconds,
        warnings,
    })
}

/// Build a **CNAME delegation** plan: the receiver points their BIP-353 label at
/// a SatsPath-managed zone, which then serves the TXT.
pub fn plan_cname_delegation(
    name: &Bip353Name,
    managed_domain: &str,
    bitcoin_uri: &str,
) -> Result<PublishingPlan> {
    assert_public_payment_instruction(bitcoin_uri)?;
    let (ttl_seconds, mut warnings) = ttl_and_warnings(bitcoin_uri);
    warnings.push(
        "Both the receiver's domain chain and the SatsPath managed zone must be \
         DNSSEC-signed; resolution fails closed if the CNAME chain is not validated."
            .into(),
    );
    let managed_target = format!(
        "{}.{}.{}",
        name.user,
        crate::bip353::BIP353_LABEL,
        managed_domain
    );
    Ok(PublishingPlan::CnameDelegation {
        receiver_cname_fqdn: name.dns_name.clone(),
        managed_target_fqdn: managed_target.clone(),
        managed_txt_fqdn: managed_target,
        txt_chunks: chunk_txt(bitcoin_uri),
        ttl_seconds,
        warnings,
    })
}

// ─── DNS provider adapter ─────────────────────────────────────────────────────────

/// A DNS provider capable of mutating TXT records and checking DNSSEC.
#[async_trait]
pub trait DnsPublisher {
    async fn upsert_txt(&self, fqdn: &str, chunks: Vec<String>, ttl_seconds: u32) -> Result<()>;
    async fn delete_txt(&self, fqdn: &str) -> Result<()>;
    async fn verify_dnssec_enabled(&self, domain: &str) -> Result<bool>;
}

/// In-memory publisher for tests and dry runs. Holds no real credentials.
#[derive(Debug, Default)]
pub struct MockDnsPublisher {
    pub records: std::sync::Mutex<std::collections::HashMap<String, (Vec<String>, u32)>>,
    pub dnssec_domains: std::collections::HashSet<String>,
}

impl MockDnsPublisher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_dnssec_domain(mut self, domain: &str) -> Self {
        self.dnssec_domains.insert(domain.to_string());
        self
    }
}

#[async_trait]
impl DnsPublisher for MockDnsPublisher {
    async fn upsert_txt(&self, fqdn: &str, chunks: Vec<String>, ttl_seconds: u32) -> Result<()> {
        self.records
            .lock()
            .unwrap()
            .insert(fqdn.to_string(), (chunks, ttl_seconds));
        Ok(())
    }

    async fn delete_txt(&self, fqdn: &str) -> Result<()> {
        self.records.lock().unwrap().remove(fqdn);
        Ok(())
    }

    async fn verify_dnssec_enabled(&self, domain: &str) -> Result<bool> {
        Ok(self.dnssec_domains.contains(domain))
    }
}

// ─── Identity-signed update authorization ────────────────────────────────────────

/// The canonical challenge a receiver must sign with their SatsPath identity key
/// to authorize a DNS payment-instruction change.
pub fn dns_update_challenge(
    alias: &str,
    dns_name: &str,
    new_uri: &str,
    nonce: &str,
    expires_at: i64,
) -> String {
    let new_uri_hash = hex::encode(Sha256::digest(new_uri.as_bytes()));
    format!("satspath-dns-update:{alias}:{dns_name}:{new_uri_hash}:{nonce}:{expires_at}")
}

/// How a DNS update was authorized. Email access alone is **not** sufficient.
pub enum DnsUpdateAuth<'a> {
    /// A signature over [`dns_update_challenge`] by the profile's identity key.
    IdentitySignature {
        challenge: &'a str,
        signature_hex: &'a str,
        identity_pubkey: &'a str,
        expires_at: i64,
        now: i64,
    },
    /// Inbox access only — explicitly rejected for DNS payment changes.
    EmailVerificationOnly,
}

/// Authorize (or reject) a DNS payment-instruction update.
///
/// DNS record changes require a cryptographic identity-key signature. Email
/// verification may gate account access elsewhere, but never DNS payment changes.
pub fn authorize_dns_update(auth: DnsUpdateAuth) -> Result<()> {
    match auth {
        DnsUpdateAuth::EmailVerificationOnly => Err(SatsPathError::Bip353(
            "email verification alone cannot authorize a DNS payment-instruction \
             update; a SatsPath identity-key signature is required"
                .into(),
        )),
        DnsUpdateAuth::IdentitySignature {
            challenge,
            signature_hex,
            identity_pubkey,
            expires_at,
            now,
        } => {
            if now > expires_at {
                return Err(SatsPathError::Bip353("update challenge expired".into()));
            }
            if verify_message_signature(challenge, signature_hex, identity_pubkey)? {
                Ok(())
            } else {
                Err(SatsPathError::InvalidSignature)
            }
        }
    }
}

/// Append-only audit entry recorded for every DNS payment-instruction change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsUpdateAudit {
    pub alias: String,
    pub dns_name: String,
    pub old_uri_hash: Option<String>,
    pub new_uri_hash: String,
    pub timestamp: i64,
    pub identity_fingerprint: String,
}

impl DnsUpdateAudit {
    pub fn record(
        alias: &str,
        dns_name: &str,
        old_uri: Option<&str>,
        new_uri: &str,
        identity_pubkey: &str,
        timestamp: i64,
    ) -> Result<Self> {
        Ok(Self {
            alias: alias.to_string(),
            dns_name: dns_name.to_string(),
            old_uri_hash: old_uri.map(|u| hex::encode(Sha256::digest(u.as_bytes()))),
            new_uri_hash: hex::encode(Sha256::digest(new_uri.as_bytes())),
            timestamp,
            identity_fingerprint: crate::crypto::fingerprint_pubkey(identity_pubkey)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip353::parse_bip353_name;
    use crate::crypto::{generate_identity_keypair, sign_message};

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn chunks_txt_into_255_byte_strings() {
        let payload = format!("bitcoin:?lno={}", "a".repeat(600));
        let chunks = chunk_txt(&payload);
        assert!(chunks.len() >= 3);
        assert!(chunks.iter().all(|c| c.len() <= TXT_STRING_MAX));
        assert_eq!(chunks.concat(), payload);
    }

    #[test]
    fn rejects_private_material_in_payload() {
        assert!(assert_public_payment_instruction("bitcoin:?lno=lno1&x=my xprv9 secret").is_err());
        assert!(assert_public_payment_instruction("bitcoin:?note=refund_key=abc").is_err());
        assert!(assert_public_payment_instruction("bitcoin:?note=preimage=deadbeef").is_err());
        // A clean public payload passes.
        assert!(assert_public_payment_instruction("bitcoin:?lno=lno1qoffer").is_ok());
    }

    #[test]
    fn rejects_non_bitcoin_payload() {
        assert!(assert_public_payment_instruction("lightning:lnbc1").is_err());
    }

    #[test]
    fn direct_txt_plan_for_reusable_uses_long_ttl() {
        let name = parse_bip353_name("rodrigo@satspath.dev").unwrap();
        let plan = plan_direct_txt(&name, "bitcoin:?lno=lno1qoffer").unwrap();
        match plan {
            PublishingPlan::DirectTxt {
                fqdn,
                txt_chunks,
                ttl_seconds,
                ..
            } => {
                assert_eq!(fqdn, "rodrigo.user._bitcoin-payment.satspath.dev");
                assert_eq!(txt_chunks.concat(), "bitcoin:?lno=lno1qoffer");
                assert_eq!(ttl_seconds, TTL_REUSABLE);
            }
            _ => panic!("expected DirectTxt"),
        }
    }

    #[test]
    fn direct_txt_plan_for_onchain_uses_short_ttl_and_warns() {
        let name = parse_bip353_name("rodrigo@satspath.dev").unwrap();
        let plan = plan_direct_txt(&name, "bitcoin:bc1qaddr?amount=0.00021000").unwrap();
        match plan {
            PublishingPlan::DirectTxt {
                ttl_seconds,
                warnings,
                ..
            } => {
                assert_eq!(ttl_seconds, TTL_ROTATING_ONCHAIN);
                assert!(!warnings.is_empty());
            }
            _ => panic!("expected DirectTxt"),
        }
    }

    #[test]
    fn cname_delegation_plan_links_receiver_to_managed_zone() {
        let name = parse_bip353_name("rodrigo@example.com").unwrap();
        let plan = plan_cname_delegation(&name, "satspath.dev", "bitcoin:?lno=lno1qoffer").unwrap();
        match plan {
            PublishingPlan::CnameDelegation {
                receiver_cname_fqdn,
                managed_target_fqdn,
                managed_txt_fqdn,
                warnings,
                ..
            } => {
                assert_eq!(
                    receiver_cname_fqdn,
                    "rodrigo.user._bitcoin-payment.example.com"
                );
                assert_eq!(
                    managed_target_fqdn,
                    "rodrigo.user._bitcoin-payment.satspath.dev"
                );
                assert_eq!(
                    managed_txt_fqdn,
                    "rodrigo.user._bitcoin-payment.satspath.dev"
                );
                assert!(warnings.iter().any(|w| w.contains("DNSSEC")));
            }
            _ => panic!("expected CnameDelegation"),
        }
    }

    #[test]
    fn verifies_identity_signed_update_challenge() {
        let kp = generate_identity_keypair();
        let pubkey = hex::encode(kp.public_key.serialize());
        let challenge = dns_update_challenge(
            "rodrigo@satspath.dev",
            "rodrigo.user._bitcoin-payment.satspath.dev",
            "bitcoin:?lno=lno1qnew",
            "nonce-123",
            NOW + 600,
        );
        let signature = sign_message(&challenge, &kp.secret_key);
        let auth = DnsUpdateAuth::IdentitySignature {
            challenge: &challenge,
            signature_hex: &signature,
            identity_pubkey: &pubkey,
            expires_at: NOW + 600,
            now: NOW,
        };
        assert!(authorize_dns_update(auth).is_ok());
    }

    #[test]
    fn rejects_email_only_update_attempt() {
        let err = authorize_dns_update(DnsUpdateAuth::EmailVerificationOnly).unwrap_err();
        assert!(matches!(err, SatsPathError::Bip353(_)));
    }

    #[test]
    fn rejects_update_signed_by_wrong_key() {
        let kp = generate_identity_keypair();
        let other = generate_identity_keypair();
        let other_pubkey = hex::encode(other.public_key.serialize());
        let challenge = dns_update_challenge("a@b.dev", "x", "bitcoin:?lno=lno1", "n", NOW + 600);
        let signature = sign_message(&challenge, &kp.secret_key);
        let auth = DnsUpdateAuth::IdentitySignature {
            challenge: &challenge,
            signature_hex: &signature,
            identity_pubkey: &other_pubkey,
            expires_at: NOW + 600,
            now: NOW,
        };
        assert!(authorize_dns_update(auth).is_err());
    }
}
