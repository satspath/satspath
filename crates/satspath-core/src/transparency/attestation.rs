use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{sign_message, verify_message_signature};
use crate::Result;

use super::TransparencyError;

pub const ATTESTATION_DOMAIN: &str = "SatsPathIdentifierAttestationV1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierVerificationMethod {
    Email,
    Dns,
    Nip05,
    Platform,
    Domain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedVerifier {
    pub verifier_id: String,
    pub public_key: String,
    pub allowed_methods: Vec<IdentifierVerificationMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentifierAttestation {
    pub version: u16,
    pub identifier_hash: String,
    pub identity_pubkey: String,
    pub profile_hash: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub method: IdentifierVerificationMethod,
    pub verifier_pubkey: String,
    pub verifier_signature: String,
}

pub fn verify_attestation_binding(
    attestation: &IdentifierAttestation,
    event: &super::NameEvent,
    trusted: &[TrustedVerifier],
    now: i64,
) -> Result<bool> {
    let Some(verifier) = trusted.iter().find(|verifier| {
        verifier.public_key == attestation.verifier_pubkey
            && verifier.allowed_methods.contains(&attestation.method)
    }) else {
        return Ok(false);
    };
    let attestation_hash = attestation.attestation_hash()?;
    if verifier.verifier_id.is_empty()
        || attestation.identifier_hash != event.identifier_hash
        || attestation.identity_pubkey != event.identity_pubkey
        || attestation.profile_hash != event.profile_hash
        || event.identifier_attestation_hash.as_deref() != Some(attestation_hash.as_str())
    {
        return Ok(false);
    }
    attestation.verify(now)
}

impl IdentifierAttestation {
    pub fn signing_message(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.verifier_signature.clear();
        let canonical = canonical_json::to_string(&serde_json::to_value(unsigned)?)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        Ok(format!("{ATTESTATION_DOMAIN}\n{canonical}"))
    }

    pub fn sign(&mut self, key: &SecretKey) -> Result<()> {
        self.verifier_signature = sign_message(&self.signing_message()?, key);
        Ok(())
    }

    pub fn verify(&self, now: i64) -> Result<bool> {
        if self.version != 1
            || self.nonce.len() < 32
            || self.issued_at > now
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
        {
            return Err(TransparencyError::InvalidAttestation(
                "invalid version, nonce, or validity window".into(),
            )
            .into());
        }
        verify_message_signature(
            &self.signing_message()?,
            &self.verifier_signature,
            &self.verifier_pubkey,
        )
    }

    pub fn attestation_hash(&self) -> Result<String> {
        let mut h = Sha256::new();
        h.update(b"SatsPathIdentifierAttestationHashV1");
        h.update(self.signing_message()?.as_bytes());
        h.update(self.verifier_signature.as_bytes());
        Ok(hex::encode(h.finalize()))
    }
}
