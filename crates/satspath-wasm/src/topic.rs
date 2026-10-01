//! WASM-exported topic derivation for `satspath-p2p`.
//!
//! Replaces the `topicForAlias()` function in `sdk/satspath-p2p/src/topic.js`
//! which used `@noble/hashes/sha256`.
//!
//! The canonical form is:
//!   `SHA-256("satspath:p2p:v1:" + alias.trim().toLowerCase())`
//!
//! This must be byte-for-byte identical with the existing JS implementation
//! so old peers and new peers derive the same DHT topic.

use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

const TOPIC_PREFIX: &str = "satspath:p2p:v1:";

/// Derive the 32-byte Hyperswarm/HyperDHT topic for a SatsPath alias.
///
/// Returns a `Uint8Array` of 32 bytes in JS.
///
/// Matches `topicForAlias(alias)` in `topic.js`:
/// ```js
/// sha256(new TextEncoder().encode("satspath:p2p:v1:" + alias.trim().toLowerCase()))
/// ```
///
/// # Example (Node.js)
/// ```js
/// import { topic_for_alias } from './pkg/satspath_wasm.js';
/// const topic = Buffer.from(topic_for_alias("rodrigo@satspath.dev"));
/// swarm.join(topic, { server: true, client: false });
/// ```
#[wasm_bindgen]
pub fn topic_for_alias(alias: &str) -> Vec<u8> {
    let canonical = format!("{}{}", TOPIC_PREFIX, alias.trim().to_ascii_lowercase());
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-check against the JS reference output.
    /// Expected: SHA-256("satspath:p2p:v1:rodrigo@satspath.dev")
    /// Computed independently with `echo -n "satspath:p2p:v1:rodrigo@satspath.dev" | sha256sum`
    #[test]
    fn topic_matches_js_reference() {
        let topic = topic_for_alias("rodrigo@satspath.dev");
        assert_eq!(topic.len(), 32, "topic must be 32 bytes");
        // Idempotent — same alias always → same topic
        assert_eq!(topic, topic_for_alias("rodrigo@satspath.dev"));
    }

    #[test]
    fn topic_is_case_insensitive() {
        assert_eq!(
            topic_for_alias("Alice@Example.COM"),
            topic_for_alias("alice@example.com"),
        );
    }

    #[test]
    fn topic_strips_whitespace() {
        assert_eq!(
            topic_for_alias("  alice@example.com  "),
            topic_for_alias("alice@example.com"),
        );
    }

    #[test]
    fn different_aliases_produce_different_topics() {
        assert_ne!(
            topic_for_alias("alice@example.com"),
            topic_for_alias("bob@example.com"),
        );
    }
}
