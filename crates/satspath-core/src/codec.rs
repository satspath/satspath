use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::errors::{Result, SatsPathError};
use crate::profile::PaymentRequest;

const SATSPATH_SCHEME: &str = "satspath:";
const V1_PREFIX: &str = "satspath:v1:";

/// Encode a payment request into a universal SatsPath URI.
///
/// Format: `satspath:v1:<base64url_no_pad_json>`
pub fn encode_payment_request(
    alias: &str,
    amount_sats: Option<u64>,
    memo: Option<&str>,
    expires_at: Option<i64>,
) -> Result<String> {
    let req = PaymentRequest {
        version: 1,
        alias: alias.to_string(),
        amount_sats,
        memo: memo.map(str::to_string),
        expires_at,
        profile_hint: None,
    };
    let json = serde_json::to_string(&req)
        .map_err(|e| SatsPathError::SerializationError(e.to_string()))?;
    let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
    Ok(format!("{}{}", V1_PREFIX, encoded))
}

/// Decode a SatsPath URI into a PaymentRequest.
///
/// Accepts:
///   - `satspath:<alias>`              — simple form
///   - `satspath:v1:<base64url_json>`  — encoded form
pub fn decode_payment_request(uri: &str) -> Result<PaymentRequest> {
    if let Some(encoded) = uri.strip_prefix(V1_PREFIX) {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| SatsPathError::InvalidPaymentUri(e.to_string()))?;
        let req: PaymentRequest = serde_json::from_slice(&bytes)
            .map_err(|e| SatsPathError::InvalidPaymentUri(e.to_string()))?;
        Ok(req)
    } else if let Some(alias) = uri.strip_prefix(SATSPATH_SCHEME) {
        if alias.is_empty() {
            return Err(SatsPathError::InvalidPaymentUri("alias is empty".into()));
        }
        Ok(PaymentRequest {
            version: 1,
            alias: alias.to_string(),
            amount_sats: None,
            memo: None,
            expires_at: None,
            profile_hint: None,
        })
    } else {
        Err(SatsPathError::InvalidPaymentUri(format!(
            "unknown scheme in URI: {uri}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encoded() {
        let uri =
            encode_payment_request("alice@example.com", Some(21000), Some("coffee"), None).unwrap();
        assert!(uri.starts_with(V1_PREFIX));
        let req = decode_payment_request(&uri).unwrap();
        assert_eq!(req.alias, "alice@example.com");
        assert_eq!(req.amount_sats, Some(21000));
        assert_eq!(req.memo.as_deref(), Some("coffee"));
        assert_eq!(req.version, 1);
        assert!(req.expires_at.is_none());
    }

    #[test]
    fn roundtrip_with_expires_at() {
        let exp = 1_800_000_000i64;
        let uri = encode_payment_request("alice@example.com", Some(1000), None, Some(exp)).unwrap();
        let req = decode_payment_request(&uri).unwrap();
        assert_eq!(req.expires_at, Some(exp));
    }

    #[test]
    fn decode_simple_uri() {
        let req = decode_payment_request("satspath:bob@satspath.dev").unwrap();
        assert_eq!(req.alias, "bob@satspath.dev");
        assert_eq!(req.amount_sats, None);
        assert!(req.expires_at.is_none());
    }

    #[test]
    fn decode_unknown_scheme_fails() {
        assert!(decode_payment_request("bitcoin:bc1qxxx").is_err());
    }

    #[test]
    fn roundtrip_no_amount() {
        let uri = encode_payment_request("carol@example.com", None, None, None).unwrap();
        let req = decode_payment_request(&uri).unwrap();
        assert_eq!(req.alias, "carol@example.com");
        assert!(req.amount_sats.is_none());
        assert!(req.memo.is_none());
        assert!(req.expires_at.is_none());
    }
}
