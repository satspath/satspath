//! Shared types for post-quantum cryptographic operations.

use serde::{Deserialize, Serialize};

/// Identifies the PQC algorithm suite used.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PqcSuite {
    /// ML-KEM-768 + X25519 (hybrid KEM, NIST security level 3)
    #[serde(rename = "mlkem768_x25519")]
    MlKem768X25519,
    /// ML-DSA-65 + Schnorr secp256k1 (hybrid signature, NIST security level 3)
    #[serde(rename = "mldsa65_schnorr")]
    MlDsa65Schnorr,
}

/// A hybrid signature that contains both classical and post-quantum components.
///
/// Verifiers MUST check **both** signatures. The profile is valid only if
/// both the Schnorr signature and the ML-DSA signature verify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Classical Schnorr signature (secp256k1) — hex-encoded
    pub schnorr_sig: String,
    /// ML-DSA-65 (Dilithium) signature — hex-encoded
    pub pqc_sig: String,
    /// Algorithm suite identifier
    pub suite: PqcSuite,
}

/// A hybrid public key bundle containing both classical and PQC keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// Classical secp256k1 public key (33-byte compressed, hex)
    pub classical_pubkey: String,
    /// ML-DSA-65 verification key — hex-encoded
    pub pqc_verification_key: String,
    /// Algorithm suite identifier
    pub suite: PqcSuite,
}

/// A hybrid KEM encapsulation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridEncapsulation {
    /// X25519 ephemeral public key (32 bytes, hex)
    pub x25519_public: String,
    /// ML-KEM-768 ciphertext — hex-encoded
    pub mlkem_ciphertext: String,
    /// The combined shared secret (SHA-256 of X25519 || ML-KEM secrets)
    /// is NOT serialized — it's only held in memory.
    #[serde(skip)]
    pub shared_secret: Vec<u8>,
    /// Algorithm suite identifier
    pub suite: PqcSuite,
}

/// Extension to the SatsPath `PaymentProfile` for PQC migration.
///
/// When a profile includes this field, resolvers and verifiers can check
/// the hybrid signature in addition to the classical one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcProfileExtension {
    /// The hybrid public key bundle
    pub hybrid_pubkey: HybridPublicKey,
    /// Hybrid signature over the canonical profile JSON
    pub hybrid_signature: Option<HybridSignature>,
    /// Whether this profile REQUIRES PQC verification (vs. optional/transitional)
    #[serde(default)]
    pub pqc_required: bool,
}
