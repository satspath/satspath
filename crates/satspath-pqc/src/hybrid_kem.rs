//! Hybrid Key Encapsulation: X25519 + ML-KEM-768 (Kyber)
//!
//! Produces a shared secret by combining:
//! 1. X25519 Diffie-Hellman (classical, 128-bit post-quantum security estimate)
//! 2. ML-KEM-768 (lattice-based KEM, NIST security level 3)
//!
//! The combined shared secret is `SHA-256(x25519_secret || mlkem_secret)`.
//! This ensures that even if one algorithm is broken, the shared secret
//! remains unpredictable to an attacker.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use satspath_pqc::hybrid_kem::*;
//!
//! // Receiver generates a hybrid KEM keypair
//! let (receiver_sk, receiver_pk) = generate_hybrid_kem_keypair();
//!
//! // Sender encapsulates a shared secret to the receiver's public key
//! let (ciphertext, sender_secret) = hybrid_encapsulate(&receiver_pk);
//!
//! // Receiver decapsulates to recover the same shared secret
//! let receiver_secret = hybrid_decapsulate(&ciphertext, &receiver_sk);
//!
//! assert_eq!(sender_secret, receiver_secret);
//! ```

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

/// Combined hybrid KEM public key.
pub struct HybridKemPublicKey {
    pub x25519: X25519PublicKey,
    pub mlkem: ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,
}

/// Combined hybrid KEM secret key.
pub struct HybridKemSecretKey {
    pub x25519: StaticSecret,
    pub mlkem: ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,
}

/// Combined hybrid ciphertext (X25519 ephemeral pubkey + ML-KEM ciphertext).
pub struct HybridCiphertext {
    pub x25519_ephemeral: X25519PublicKey,
    pub mlkem_ciphertext: ml_kem::Ciphertext<MlKem768>,
}

/// Generate a hybrid KEM keypair (X25519 + ML-KEM-768).
pub fn generate_hybrid_kem_keypair() -> (HybridKemSecretKey, HybridKemPublicKey) {
    let mut rng = rand::thread_rng();

    // Classical: X25519
    let x25519_sk = StaticSecret::random_from_rng(&mut rng);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    // Post-quantum: ML-KEM-768
    let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut rng);

    (
        HybridKemSecretKey {
            x25519: x25519_sk,
            mlkem: mlkem_dk,
        },
        HybridKemPublicKey {
            x25519: x25519_pk,
            mlkem: mlkem_ek,
        },
    )
}

/// Encapsulate a shared secret to a receiver's hybrid public key.
///
/// Returns (ciphertext, shared_secret) where shared_secret = SHA-256(x25519 || mlkem).
pub fn hybrid_encapsulate(receiver_pk: &HybridKemPublicKey) -> (HybridCiphertext, [u8; 32]) {
    let mut rng = rand::thread_rng();

    // Classical: X25519 ephemeral key exchange
    let x25519_eph_sk = EphemeralSecret::random_from_rng(&mut rng);
    let x25519_eph_pk = X25519PublicKey::from(&x25519_eph_sk);
    let x25519_shared = x25519_eph_sk.diffie_hellman(&receiver_pk.x25519);

    // Post-quantum: ML-KEM-768 encapsulation
    let (mlkem_ct, mlkem_shared) = receiver_pk
        .mlkem
        .encapsulate(&mut rng)
        .expect("ML-KEM encapsulation");

    // Combine: SHA-256(x25519_shared || mlkem_shared)
    let combined = combine_secrets(x25519_shared.as_bytes(), mlkem_shared.as_ref());

    let ciphertext = HybridCiphertext {
        x25519_ephemeral: x25519_eph_pk,
        mlkem_ciphertext: mlkem_ct,
    };

    (ciphertext, combined)
}

/// Decapsulate a shared secret from a hybrid ciphertext using the receiver's secret key.
///
/// Returns the same shared_secret = SHA-256(x25519 || mlkem).
pub fn hybrid_decapsulate(
    ciphertext: &HybridCiphertext,
    receiver_sk: &HybridKemSecretKey,
) -> [u8; 32] {
    // Classical: X25519 DH
    let x25519_shared = receiver_sk
        .x25519
        .diffie_hellman(&ciphertext.x25519_ephemeral);

    // Post-quantum: ML-KEM-768 decapsulation
    let mlkem_shared = receiver_sk
        .mlkem
        .decapsulate(&ciphertext.mlkem_ciphertext)
        .expect("ML-KEM decapsulation");

    // Combine: SHA-256(x25519_shared || mlkem_shared)
    combine_secrets(x25519_shared.as_bytes(), mlkem_shared.as_ref())
}

/// Combine two shared secrets into one via SHA-256.
fn combine_secrets(classical: &[u8], pqc: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SatsPathHybridKEM-v1:");
    hasher.update(classical);
    hasher.update(pqc);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let (sk, pk) = generate_hybrid_kem_keypair();
        let (ct, sender_secret) = hybrid_encapsulate(&pk);
        let receiver_secret = hybrid_decapsulate(&ct, &sk);
        assert_eq!(sender_secret, receiver_secret);
    }

    #[test]
    fn different_keys_produce_different_secrets() {
        let (_sk1, pk1) = generate_hybrid_kem_keypair();
        let (_sk2, pk2) = generate_hybrid_kem_keypair();
        let (_ct1, secret1) = hybrid_encapsulate(&pk1);
        let (_ct2, secret2) = hybrid_encapsulate(&pk2);
        // Different public keys → different secrets
        assert_ne!(secret1, secret2);
        // Decapsulating ct2 with sk1 should NOT produce secret2
        // (it will panic or produce garbage depending on the impl)
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let (_sk, pk) = generate_hybrid_kem_keypair();
        let (_, secret) = hybrid_encapsulate(&pk);
        assert_eq!(secret.len(), 32);
    }
}
