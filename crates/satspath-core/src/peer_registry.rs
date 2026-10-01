use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::{Result, SatsPathError};
use crate::profile::SignedPaymentProfile;

/// Canonicalize an identifier before hashing.
///
/// Rules:
///   - Trim whitespace
///   - Lowercase the full string
///   - For email-style identifiers (user@domain): lowercase both parts
///
/// This prevents `Rodrigo@Gmail.com` and `rodrigo@gmail.com` from
/// resolving differently while not claiming stronger anonymity than this provides.
pub fn canonicalize_identifier(identifier: &str) -> String {
    let s = identifier.trim().to_lowercase();
    // Normalize email-style: split on first @, clean each part
    if let Some((local, domain)) = s.split_once('@') {
        let domain_clean = domain.trim();
        // Convert domain to punycode/ascii using IDNA standard
        let ascii_domain =
            idna::domain_to_ascii(domain_clean).unwrap_or_else(|_| domain_clean.to_string());
        format!("{}@{}", local.trim(), ascii_domain)
    } else {
        s
    }
}

/// SHA-256 hash of the canonical identifier (hex-encoded).
pub fn hash_identifier(identifier: &str) -> String {
    let canonical = canonicalize_identifier(identifier);
    let digest = Sha256::digest(canonical.as_bytes());
    hex::encode(digest)
}

/// A short display hint that does not expose the full identifier.
/// e.g. "rodrigodiazgt7@gmail.com" → "r***@gmail.com"
pub fn display_hint(identifier: &str) -> String {
    let canonical = canonicalize_identifier(identifier);
    if let Some((local, domain)) = canonical.split_once('@') {
        let first = local.chars().next().unwrap_or('?');
        format!("{}***@{}", first, domain)
    } else {
        let first = canonical.chars().next().unwrap_or('?');
        format!("{}***", first)
    }
}

/// Payment pointers for a single peer — the public endpoints for each rail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPointers {
    pub lightning: Option<LightningPointer>,
    pub onchain: Option<OnchainPointer>,
    pub ark: Option<ArkPointer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningPointer {
    /// "lnurl_pay" | "lightning_address" | "bolt12"
    pub pointer_type: String,
    pub value: String,
    pub receiver_pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnchainPointer {
    pub network: String, // "mainnet" | "testnet" | "signet"
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArkPointer {
    pub server: String,
    pub pubkey: String,
    pub vtxo_pointer: Option<String>,
}

/// A signed peer record stored in the local registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub version: u32,
    /// SHA-256 of canonicalized identifier (never stores raw identifier).
    pub identifier_hash: String,
    /// Safe display hint (first char + *** + domain).
    pub display_hint: String,
    /// secp256k1 compressed public key (hex) — identity key, not payment key.
    pub identity_pubkey: String,
    /// Signature over the canonical JSON of this record.
    pub profile_signature: String,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
    pub pointers: PeerPointers,
}

impl PeerRecord {
    /// Build from an existing SignedPaymentProfile (adapter for backwards compat).
    pub fn from_signed_profile(identifier: &str, signed: &SignedPaymentProfile) -> Self {
        let p = &signed.profile;

        let mut lightning = None;
        let mut onchain = None;
        let mut ark = None;

        for method in &p.methods {
            match method {
                crate::profile::PaymentMethod::Lightning {
                    lightning_address,
                    lnurl,
                    bolt12,
                    ..
                } => {
                    if lightning.is_none() {
                        let (ptype, value) = if let Some(la) = lightning_address {
                            ("lightning_address".into(), la.clone())
                        } else if let Some(lu) = lnurl {
                            ("lnurl_pay".into(), lu.clone())
                        } else if let Some(b) = bolt12 {
                            ("bolt12".into(), b.clone())
                        } else {
                            continue;
                        };
                        lightning = Some(LightningPointer {
                            pointer_type: ptype,
                            value,
                            receiver_pubkey: Some(p.identity_pubkey.clone()),
                        });
                    }
                }
                crate::profile::PaymentMethod::Onchain {
                    address,
                    silent_payment_pubkey,
                    ..
                } => {
                    if onchain.is_none() {
                        onchain = Some(OnchainPointer {
                            network: "mainnet".into(),
                            address: silent_payment_pubkey
                                .clone()
                                .unwrap_or_else(|| address.clone().unwrap_or_default()),
                        });
                    }
                }
                crate::profile::PaymentMethod::Ark { server, pubkey, .. } => {
                    if ark.is_none() {
                        ark = Some(ArkPointer {
                            server: server.clone(),
                            pubkey: pubkey.clone(),
                            vtxo_pointer: None,
                        });
                    }
                }
                crate::profile::PaymentMethod::Bolt12(_offer_data) => {
                    // Handle Bolt12 if necessary for record building
                }
            }
        }

        PeerRecord {
            version: 1,
            identifier_hash: hash_identifier(identifier),
            display_hint: display_hint(identifier),
            identity_pubkey: p.identity_pubkey.clone(),
            profile_signature: signed.signature.clone(),
            updated_at: p.updated_at,
            expires_at: None,
            pointers: PeerPointers {
                lightning,
                onchain,
                ark,
            },
        }
    }
}

// ─── Registry ────────────────────────────────────────────────────────────────

/// Trait for pluggable peer registry implementations.
pub trait PeerRegistryBackend {
    fn get(&self, identifier: &str) -> Result<Option<PeerRecord>>;
    fn put(&mut self, identifier: &str, record: PeerRecord) -> Result<()>;
    fn list_hashes(&self) -> Result<Vec<String>>;
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct LocalRegistryData {
    /// Key: SHA-256(canonical identifier)
    records: HashMap<String, PeerRecord>,
}

/// File-backed local peer registry at `.satspath/peers/registry.local.json`.
///
/// Uses identifier hashes as keys — the raw identifier is never persisted.
pub struct LocalPeerRegistry {
    path: PathBuf,
    data: LocalRegistryData,
}

impl LocalPeerRegistry {
    pub fn open(dir: &Path) -> Result<Self> {
        let path = dir.join("peers").join("registry.local.json");
        let data = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            serde_json::from_str(&raw)?
        } else {
            LocalRegistryData::default()
        };
        Ok(LocalPeerRegistry { path, data })
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| SatsPathError::SerializationError(e.to_string()))?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    pub fn get_hash(&self, identifier_hash: &str) -> Option<PeerRecord> {
        self.data.records.get(identifier_hash).cloned()
    }
}

impl PeerRegistryBackend for LocalPeerRegistry {
    fn get(&self, identifier: &str) -> Result<Option<PeerRecord>> {
        let key = hash_identifier(identifier);
        Ok(self.data.records.get(&key).cloned())
    }

    fn put(&mut self, identifier: &str, record: PeerRecord) -> Result<()> {
        let key = hash_identifier(identifier);
        // Conflict check: if a record exists and has a different identity_pubkey, warn.
        if let Some(existing) = self.data.records.get(&key) {
            if existing.identity_pubkey != record.identity_pubkey {
                return Err(SatsPathError::RegistryError(format!(
                    "Conflicting record for identifier hash {}. \
                     Existing pubkey: {} — new pubkey: {}. \
                     Manual resolution required.",
                    &key[..16],
                    &existing.identity_pubkey[..16],
                    &record.identity_pubkey[..16],
                )));
            }
        }
        self.data.records.insert(key, record);
        self.save()
    }

    fn list_hashes(&self) -> Result<Vec<String>> {
        Ok(self.data.records.keys().cloned().collect())
    }
}

/// In-memory mock registry for tests.
#[derive(Default)]
pub struct MockPeerRegistry {
    records: HashMap<String, PeerRecord>,
}

impl PeerRegistryBackend for MockPeerRegistry {
    fn get(&self, identifier: &str) -> Result<Option<PeerRecord>> {
        let key = hash_identifier(identifier);
        Ok(self.records.get(&key).cloned())
    }

    fn put(&mut self, identifier: &str, record: PeerRecord) -> Result<()> {
        let key = hash_identifier(identifier);
        self.records.insert(key, record);
        Ok(())
    }

    fn list_hashes(&self) -> Result<Vec<String>> {
        Ok(self.records.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalization_lowercases_and_trims() {
        assert_eq!(
            canonicalize_identifier("  Rodrigo@Gmail.COM  "),
            "rodrigo@gmail.com"
        );
        assert_eq!(
            canonicalize_identifier("ALICE@EXAMPLE.COM"),
            "alice@example.com"
        );
    }

    #[test]
    fn same_identifier_different_case_same_hash() {
        let h1 = hash_identifier("Rodrigo@Gmail.com");
        let h2 = hash_identifier("rodrigo@gmail.com");
        let h3 = hash_identifier("  RODRIGO@GMAIL.COM  ");
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn different_identifiers_different_hashes() {
        assert_ne!(
            hash_identifier("alice@example.com"),
            hash_identifier("bob@example.com")
        );
    }

    #[test]
    fn display_hint_hides_local_part() {
        assert_eq!(display_hint("rodrigo@gmail.com"), "r***@gmail.com");
        assert_eq!(display_hint("alice@example.com"), "a***@example.com");
    }

    #[test]
    fn mock_registry_put_and_get() {
        let mut reg = MockPeerRegistry::default();
        let record = PeerRecord {
            version: 1,
            identifier_hash: hash_identifier("test@example.com"),
            display_hint: display_hint("test@example.com"),
            identity_pubkey: "02aabb".into(),
            profile_signature: "sig".into(),
            updated_at: 1_700_000_000,
            expires_at: None,
            pointers: PeerPointers {
                lightning: Some(LightningPointer {
                    pointer_type: "lightning_address".into(),
                    value: "test@blink.sv".into(),
                    receiver_pubkey: None,
                }),
                onchain: None,
                ark: None,
            },
        };
        reg.put("test@example.com", record.clone()).unwrap();

        // Case-insensitive get
        let found = reg.get("TEST@EXAMPLE.COM").unwrap().unwrap();
        assert_eq!(found.identity_pubkey, "02aabb");
        assert_eq!(found.display_hint, "t***@example.com");
    }

    #[test]
    fn invite_flow_returns_none_for_unknown() {
        let reg = MockPeerRegistry::default();
        let result = reg.get("unknown@example.com").unwrap();
        assert!(result.is_none());
        // Callers should generate an invite, not a seed.
    }

    #[test]
    fn local_registry_persists() {
        let dir = tempfile::tempdir().unwrap();
        let record = PeerRecord {
            version: 1,
            identifier_hash: hash_identifier("persist@example.com"),
            display_hint: display_hint("persist@example.com"),
            identity_pubkey: "02ccdd".into(),
            profile_signature: "sig2".into(),
            updated_at: 1_700_000_000,
            expires_at: None,
            pointers: PeerPointers {
                lightning: None,
                onchain: None,
                ark: None,
            },
        };
        {
            let mut reg = LocalPeerRegistry::open(dir.path()).unwrap();
            reg.put("persist@example.com", record).unwrap();
        }
        let reg2 = LocalPeerRegistry::open(dir.path()).unwrap();
        assert!(reg2.get("persist@example.com").unwrap().is_some());
    }
}
