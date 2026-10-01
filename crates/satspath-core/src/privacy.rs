use crate::errors::{Result, SatsPathError};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Default pepper for identifier hashing.
/// In production, this MUST be replaced with a securely generated random value
/// stored in a config file or environment variable.
///
/// The default is a well-known value for development ONLY.
const DEFAULT_PEPPER: &[u8] = b"satspath-dev-pepper-change-in-production";

/// Get the pepper for identifier hashing.
/// Reads from SATSPATH_PEPPER env var (hex-encoded 32 bytes) or uses default.
fn get_pepper() -> Vec<u8> {
    std::env::var("SATSPATH_PEPPER")
        .ok()
        .and_then(|s| hex::decode(s).ok())
        .filter(|b| b.len() == 32)
        .unwrap_or_else(|| DEFAULT_PEPPER.to_vec())
}

/// Canonicalize an identifier for consistent hashing/lookup.
/// Lowercases ASCII; preserves non-ASCII (validation should reject earlier).
pub fn canonical_identifier(identifier: &str) -> String {
    let trimmed = identifier.trim();
    // SEC: Reject non-ASCII to prevent homograph attacks (e.g., alíce vs alice)
    // Note: Validation layer should reject non-ASCII before this is called.
    trimmed.to_ascii_lowercase()
}

/// Validate that an identifier is ASCII-only (prevents homograph attacks).
pub fn validate_ascii_identifier(identifier: &str) -> Result<()> {
    let trimmed = identifier.trim();
    if !trimmed.is_ascii() {
        return Err(SatsPathError::InvalidPaymentPointer(
            "identifier contains non-ASCII characters (homograph attack prevention)".into(),
        ));
    }
    Ok(())
}

/// Hash an identifier with HMAC-SHA256 using a secret pepper.
/// This prevents rainbow table attacks on low-entropy identifiers (emails).
///
/// The pepper is loaded from SATSPATH_PEPPER env var or uses a dev default.
pub fn identifier_hash(identifier: &str) -> String {
    let canonical = canonical_identifier(identifier);
    let data = canonical.as_bytes();
    let pepper = get_pepper();

    let mut mac = HmacSha256::new_from_slice(&pepper).expect("HMAC key must be valid");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Hash an identifier with a custom pepper (for testing).
pub fn identifier_hash_with_pepper(identifier: &str, pepper: &[u8]) -> String {
    let canonical = canonical_identifier(identifier);
    let data = canonical.as_bytes();

    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC key must be valid");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

pub fn mask_identifier(identifier: &str) -> String {
    let trimmed = identifier.trim();
    if let Some((local, domain)) = trimmed.split_once('@') {
        let first = local.chars().next().unwrap_or('*');
        return format!("{first}***@{domain}");
    }
    mask_middle(trimmed, 3, 3)
}

pub fn mask_address(address: &str) -> String {
    mask_middle(address, 6, 3)
}

pub fn mask_pubkey(pubkey: &str) -> String {
    mask_middle(pubkey, 6, 4)
}

pub fn mask_invoice(invoice: &str) -> String {
    mask_middle(invoice, 8, 6)
}

fn mask_middle(value: &str, head: usize, tail: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= head + tail + 3 {
        return "***".into();
    }
    let start: String = chars.iter().take(head).collect();
    let end: String = chars.iter().skip(chars.len() - tail).collect();
    format!("{start}...{end}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_output_does_not_reveal_full_email_or_pubkey() {
        let email = "rodrigo@gmail.com";
        let pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let masked_email = mask_identifier(email);
        let masked_pubkey = mask_pubkey(pubkey);

        assert_eq!(masked_email, "r***@gmail.com");
        assert!(!masked_email.contains("rodrigo"));
        assert_eq!(masked_pubkey, "0279be...1798");
        assert!(!masked_pubkey.contains("667ef9dcbbac55"));
    }

    #[test]
    fn identifier_hash_uses_canonical_identifier() {
        // Use a fixed pepper for deterministic test
        let pepper = b"test-pepper-32-bytes-long!!!!!"; // 32 bytes
        assert_eq!(
            identifier_hash_with_pepper(" Rodrigo@Gmail.com ", pepper),
            identifier_hash_with_pepper("rodrigo@gmail.com", pepper)
        );
    }

    #[test]
    fn identifier_hash_different_peppers_different_hash() {
        let pepper1 = b"pepper-one-32-bytes-long!!!!!!";
        let pepper2 = b"pepper-two-32-bytes-long!!!!!!";
        let hash1 = identifier_hash_with_pepper("test@example.com", pepper1);
        let hash2 = identifier_hash_with_pepper("test@example.com", pepper2);
        assert_ne!(hash1, hash2);
    }
}
