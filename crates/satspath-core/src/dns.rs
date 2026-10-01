use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DnsError {
    #[error("DNSSEC validation failed or AD bit not set")]
    ValidationFailed,
    #[error("Invalid TXT record format")]
    InvalidFormat,
    #[error("Missing mandatory field: {0}")]
    MissingField(String),
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(String),
}

/// Represents the parsed DNS descriptor for a SatsPath namespace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsDescriptor {
    pub version: String,
    pub endpoints: Vec<String>,
    pub authority_pubkey: String,
    pub log_id: String,
    pub witness_policy: Option<String>,
}

impl DnsDescriptor {
    /// Parses a TXT record string into a `DnsDescriptor`.
    ///
    /// The string is expected to be semicolon-separated key-value pairs.
    /// Example: `v=sp2; e=https://satspath.example.com; k=xpub...; l=log_id...;`
    pub fn parse_txt(txt: &str) -> Result<Self, DnsError> {
        let mut version = None;
        let mut endpoints = Vec::new();
        let mut authority_pubkey = None;
        let mut log_id = None;
        let mut witness_policy = None;

        for part in txt.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "v" => {
                        if value != "sp2" {
                            return Err(DnsError::UnsupportedVersion(value.to_string()));
                        }
                        version = Some(value.to_string());
                    }
                    "e" => endpoints.push(value.to_string()),
                    "k" => authority_pubkey = Some(value.to_string()),
                    "l" => log_id = Some(value.to_string()),
                    "w" => witness_policy = Some(value.to_string()),
                    _ => {} // Ignore unknown fields for forward compatibility
                }
            }
        }

        let version = version.ok_or_else(|| DnsError::MissingField("v".to_string()))?;
        if endpoints.is_empty() {
            return Err(DnsError::MissingField("e".to_string()));
        }
        let authority_pubkey =
            authority_pubkey.ok_or_else(|| DnsError::MissingField("k".to_string()))?;
        let log_id = log_id.ok_or_else(|| DnsError::MissingField("l".to_string()))?;

        Ok(Self {
            version,
            endpoints,
            authority_pubkey,
            log_id,
            witness_policy,
        })
    }
}
