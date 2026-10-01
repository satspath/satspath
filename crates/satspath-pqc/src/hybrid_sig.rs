//! Hybrid Signatures: Schnorr (secp256k1) + ML-DSA-65 (Dilithium)
//!
//! A valid hybrid signature requires BOTH components to verify.
//! This provides security against:
//! - Classical attacks (protected by Schnorr/secp256k1)
//! - Quantum attacks via Shor's algorithm (protected by ML-DSA lattice-based sig)

use crate::types::{HybridPublicKey, HybridSignature, PqcSuite};

use ml_dsa::{Generate, Keypair as MlKeypair, MlDsa65, Signer, Verifier};
use ml_dsa::{Signature, SigningKey, VerifyingKey};
use secp256k1::schnorr::Signature as SchnorrSignature;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// A hybrid keypair containing both classical and PQC signing keys.
pub struct HybridSigningKeyPair {
    /// Classical secp256k1 secret key
    pub classical_sk: SecretKey,
    /// Classical secp256k1 public key (compressed)
    pub classical_pk: PublicKey,
    /// ML-DSA-65 signing key
    pub pqc_sk: SigningKey<MlDsa65>,
    /// ML-DSA-65 verification key
    pub pqc_vk: VerifyingKey<MlDsa65>,
}

impl HybridSigningKeyPair {
    /// Export the public key bundle for inclusion in profiles.
    pub fn public_key(&self) -> HybridPublicKey {
        let classical_bytes = self.classical_pk.serialize();
        HybridPublicKey {
            classical_pubkey: hex::encode(classical_bytes),
            pqc_verification_key: hex::encode(self.pqc_vk.encode()),
            suite: PqcSuite::MlDsa65Schnorr,
        }
    }
    /// Export the PQC seed to store it. (32 bytes usually)
    pub fn pqc_seed(&self) -> Vec<u8> {
        self.pqc_sk.to_seed().as_slice().to_vec()
    }

    /// Reconstruct from a classical secret key and a PQC seed.
    pub fn from_seeds(classical_sk_bytes: &[u8], pqc_seed_bytes: &[u8]) -> Option<Self> {
        let secp = Secp256k1::new();
        let classical_sk = SecretKey::from_slice(classical_sk_bytes).ok()?;
        let classical_pk = classical_sk.public_key(&secp);

        let seed: ml_dsa::Seed = pqc_seed_bytes.try_into().ok()?;
        let pqc_sk = SigningKey::<MlDsa65>::from_seed(&seed);
        let pqc_vk = pqc_sk.verifying_key();

        Some(Self {
            classical_sk,
            classical_pk,
            pqc_sk,
            pqc_vk,
        })
    }
}

/// Generate a fresh hybrid keypair (secp256k1 + ML-DSA-65).
pub fn generate_hybrid_keypair() -> HybridSigningKeyPair {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();

    // Classical: secp256k1
    let (classical_sk, classical_pk) = secp.generate_keypair(&mut rng);

    // Post-quantum: ML-DSA-65 (Dilithium)
    let pqc_sk = SigningKey::<MlDsa65>::generate();
    let pqc_vk = pqc_sk.verifying_key();

    HybridSigningKeyPair {
        classical_sk,
        classical_pk,
        pqc_sk,
        pqc_vk,
    }
}

/// Create a hybrid signature over a message.
pub fn hybrid_sign(message: &[u8], keypair: &HybridSigningKeyPair) -> HybridSignature {
    let secp = Secp256k1::new();

    // 1. Classical Schnorr signature (over SHA-256 hash)
    let hash = Sha256::digest(message);
    let msg = Message::from_digest_slice(&hash).expect("32 bytes");
    let kp = Keypair::from_secret_key(&secp, &keypair.classical_sk);
    let schnorr_sig = secp.sign_schnorr(&msg, &kp);

    // 2. Post-quantum ML-DSA-65 signature (signs raw message; internal hashing)
    let pqc_sig: Signature<MlDsa65> = keypair.pqc_sk.sign(message);

    HybridSignature {
        schnorr_sig: hex::encode(schnorr_sig.as_ref()),
        pqc_sig: hex::encode(pqc_sig.encode()),
        suite: PqcSuite::MlDsa65Schnorr,
    }
}

/// Verify a hybrid signature. Returns true ONLY if BOTH components verify.
pub fn hybrid_verify(message: &[u8], sig: &HybridSignature, pubkey: &HybridPublicKey) -> bool {
    if sig.suite != PqcSuite::MlDsa65Schnorr
        || pubkey.suite != PqcSuite::MlDsa65Schnorr
        || sig.suite != pubkey.suite
    {
        return false;
    }

    // 1. Verify classical Schnorr
    let classical_ok = (|| -> Option<()> {
        let secp = Secp256k1::new();
        let pk_bytes = hex::decode(&pubkey.classical_pubkey).ok()?;
        let pk = PublicKey::from_slice(&pk_bytes).ok()?;
        let (x_only, _) = pk.x_only_public_key();
        let sig_bytes = hex::decode(&sig.schnorr_sig).ok()?;
        let schnorr_sig = SchnorrSignature::from_slice(&sig_bytes).ok()?;
        let hash = Sha256::digest(message);
        let msg = Message::from_digest_slice(&hash).ok()?;
        secp.verify_schnorr(&schnorr_sig, &msg, &x_only).ok()
    })();

    if classical_ok.is_none() {
        return false;
    }

    // 2. Verify ML-DSA-65
    let pqc_ok = (|| -> Option<()> {
        let vk_bytes = hex::decode(&pubkey.pqc_verification_key).ok()?;
        let vk_array = vk_bytes.as_slice().try_into().ok()?;
        let vk = VerifyingKey::<MlDsa65>::decode(&vk_array);

        let sig_bytes = hex::decode(&sig.pqc_sig).ok()?;
        let pqc_sig = Signature::<MlDsa65>::decode(&sig_bytes.try_into().ok()?)?;
        vk.verify(message, &pqc_sig).ok()
    })();

    pqc_ok.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_hybrid_sign_verify() {
        let kp = generate_hybrid_keypair();
        let message = b"SatsPathProfileV1:canonical_json_here";
        let sig = hybrid_sign(message, &kp);
        let pk = kp.public_key();
        assert!(hybrid_verify(message, &sig, &pk));
    }

    #[test]
    fn tampered_message_fails() {
        let kp = generate_hybrid_keypair();
        let sig = hybrid_sign(b"original", &kp);
        let pk = kp.public_key();
        assert!(!hybrid_verify(b"tampered", &sig, &pk));
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = generate_hybrid_keypair();
        let kp2 = generate_hybrid_keypair();
        let message = b"test message";
        let sig = hybrid_sign(message, &kp1);
        let pk2 = kp2.public_key();
        assert!(!hybrid_verify(message, &sig, &pk2));
    }
}
