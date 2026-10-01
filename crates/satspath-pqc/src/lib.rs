//! # satspath-pqc — Post-Quantum Cryptography for SatsPath
//!
//! This crate provides hybrid (classical + post-quantum) cryptographic
//! primitives to future-proof SatsPath against quantum computing threats.
//!
//! ## Design Philosophy
//!
//! **Hybrid-first**: All operations combine a classical algorithm with a
//! post-quantum algorithm. If either is broken, the other still provides
//! security. This matches NIST's recommended migration strategy.
//!
//! ## Modules
//!
//! - [`hybrid_sig`] — Hybrid signatures (Schnorr + ML-DSA/Dilithium)
//! - [`hybrid_kem`] — Hybrid key encapsulation (X25519 + ML-KEM/Kyber)
//! - [`types`] — Shared types for PQC-enabled profiles

pub mod hybrid_kem;
pub mod hybrid_sig;
pub mod types;
