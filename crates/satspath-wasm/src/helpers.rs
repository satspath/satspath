//! Helper functions for WASM bindings

use sha2::{Digest, Sha256};

/// Compute SHA-256 hash of an identifier (for alias hashing)
/// Returns hex-encoded 32-byte hash
pub fn identifier_hash(alias: &str) -> String {
    let lower = alias.to_lowercase();
    let canonical = lower.trim();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Mask an identifier for display (e.g., "alice@domain.com" -> "a***e@domain.com")
pub fn mask_identifier(alias: &str) -> String {
    let parts: Vec<&str> = alias.split('@').collect();
    if parts.len() != 2 {
        return "***".to_string();
    }
    let local = parts[0];
    let domain = parts[1];
    if local.len() <= 2 {
        return format!("***@{}", domain);
    }
    format!("{}***{}@{}", &local[..1], &local[local.len() - 1..], domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifier_hash() {
        let h1 = identifier_hash("alice@example.com");
        let h2 = identifier_hash("ALICE@EXAMPLE.COM");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_mask_identifier() {
        assert_eq!(mask_identifier("alice@example.com"), "a***e@example.com");
        assert_eq!(mask_identifier("ab@example.com"), "***@example.com");
        assert_eq!(mask_identifier("a@example.com"), "***@example.com");
        assert_eq!(mask_identifier("invalid"), "***");
    }
}
