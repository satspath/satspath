//! WASM-compatible resolver chain — local → BIP353 → HTTPS well-known → Nostr NIP-05

use crate::types::{BitcoinNetwork, PaymentMethod, SignedPaymentProfile};
use serde::Deserialize;
use std::future::Future;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{window, Request, RequestInit, RequestMode, Response};

// ===== Types =====

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
    #[serde(rename = "AD")]
    ad: Option<bool>,
}

#[derive(Deserialize)]
struct DohAnswer {
    data: String,
}

#[derive(Deserialize)]
struct WellKnownResponse {
    profile: crate::types::PaymentProfile,
    signature: String,
}

#[derive(Deserialize)]
struct Nip05Response {
    names: std::collections::HashMap<String, String>,
    relays: Option<std::collections::HashMap<String, Vec<String>>>,
}

#[derive(Deserialize)]
struct NostrEvent {
    pubkey: String,
    content: String,
}

#[derive(Deserialize)]
struct ProfileEventContent {
    profile: SignedPaymentProfile,
}

// ===== Trait for profile resolvers =====

pub trait ProfileResolver {
    fn resolve_alias(
        &self,
        alias: &str,
    ) -> impl Future<Output = Result<SignedPaymentProfile, String>> + Send;
}

/// Chain resolver that tries resolvers in order
#[wasm_bindgen]
pub struct ChainResolver {
    local_registry: LocalRegistry,
    bip353_resolver: Bip353Resolver,
    https_resolver: HttpsWellKnownResolver,
    nostr_resolver: NostrNip05Resolver,
}

#[wasm_bindgen]
impl ChainResolver {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            local_registry: LocalRegistry::new(),
            bip353_resolver: Bip353Resolver::new(),
            https_resolver: HttpsWellKnownResolver,
            nostr_resolver: NostrNip05Resolver::new(),
        }
    }

    /// Resolve an alias to a signed payment profile (returns JSON string)
    pub async fn resolve_alias(&self, alias: &str) -> Result<String, String> {
        // 1. Local registry
        if let Ok(profile) = self.local_registry.resolve_alias(alias).await {
            return serde_json::to_string(&profile).map_err(|e| e.to_string());
        }

        // 2. BIP-353 DNS
        if let Ok(profile) = self.bip353_resolver.resolve_alias_async(alias).await {
            return serde_json::to_string(&profile).map_err(|e| e.to_string());
        }

        // 3. HTTPS Well-known
        if let Ok(profile) = self.https_resolver.resolve_alias_async(alias).await {
            return serde_json::to_string(&profile).map_err(|e| e.to_string());
        }

        // 4. Nostr NIP-05
        if let Ok(profile) = self.nostr_resolver.resolve_alias_async(alias).await {
            return serde_json::to_string(&profile).map_err(|e| e.to_string());
        }

        Err(format!("No resolver found profile for {}", alias))
    }

    #[wasm_bindgen(getter)]
    pub fn local_registry(&self) -> LocalRegistry {
        self.local_registry.clone()
    }
}

/// Local in-memory registry
#[wasm_bindgen]
#[derive(Clone)]
pub struct LocalRegistry {
    profiles: Vec<SignedPaymentProfile>,
}

#[wasm_bindgen]
impl LocalRegistry {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            profiles: Vec::new(),
        }
    }

    pub async fn resolve_alias(&self, alias: &str) -> Result<String, String> {
        let profiles = self.profiles.clone();
        let profile = profiles
            .iter()
            .find(|p| p.profile.alias.to_lowercase() == alias.to_lowercase())
            .cloned()
            .ok_or_else(|| format!("not_found: {}", alias))?;
        serde_json::to_string(&profile).map_err(|e| e.to_string())
    }

    pub fn add_profile(&mut self, profile_json: String) -> Result<(), String> {
        let profile: SignedPaymentProfile =
            serde_json::from_str(&profile_json).map_err(|e| e.to_string())?;
        Err("Use JavaScript to manage profiles".to_string())
    }

    pub fn list_profiles(&self) -> Vec<String> {
        self.profiles
            .iter()
            .filter_map(|p| serde_json::to_string(p).ok())
            .collect()
    }
}

/// BIP-353 DNS resolver using DNS-over-HTTPS
#[wasm_bindgen]
pub struct Bip353Resolver {
    doh_providers: Vec<String>,
    policy: String,
}

#[wasm_bindgen]
impl Bip353Resolver {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            doh_providers: vec![
                "https://dns.google/resolve".to_string(),
                "https://cloudflare-dns.com/dns-query".to_string(),
            ],
            policy: "strict".to_string(),
        }
    }

    pub fn with_policy(mut self, policy: String) -> Self {
        self.policy = policy;
        self
    }

    pub async fn resolve_alias_async(&self, alias: &str) -> Result<String, String> {
        let (name, domain) = split_alias(alias)?;
        let txt_name = format!("_bitcoin.payment.{}", domain);

        for provider in &self.doh_providers {
            if let Ok(doh) = self.query_doh(provider, &txt_name).await {
                if doh.status != 0 {
                    continue;
                }
                if let Some(answers) = doh.answer {
                    for ans in answers {
                        let txt = ans.data.trim_matches('"').replace("\\\"", "\"");
                        if txt.starts_with("bitcoin:") || txt.starts_with("BIP321:") {
                            return Ok(serde_json::to_string(&uri_to_profile(alias, txt))
                                .map_err(|e| e.to_string())?);
                        }
                    }
                }
            }
        }

        Err("not_found".to_string())
    }
}

impl Bip353Resolver {
    async fn query_doh(&self, provider: &str, name: &str) -> Result<DohResponse, String> {
        let url = format!("{}?name={}&type=16&do=1", provider, name);
        let mut opts = RequestInit::new();
        opts.set_method("GET");
        opts.set_mode(RequestMode::Cors);

        let request =
            Request::new_with_str_and_init(&url, &opts).map_err(|e| format!("{:?}", e))?;
        let window = window().ok_or("no window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("DoH fetch failed: {:?}", e))?;
        let response: Response = resp_value.dyn_into().map_err(|_| "Invalid response")?;

        if !response.ok() {
            return Err(format!("DoH HTTP {}", response.status()));
        }

        let json = JsFuture::from(response.json().map_err(|e| format!("{:?}", e))?)
            .await
            .map_err(|e| format!("JSON parse failed: {:?}", e))?;

        serde_wasm_bindgen::from_value(json)
            .map_err(|e| format!("DoH deserialization failed: {:?}", e))
    }
}

/// HTTPS Well-known resolver (/.well-known/satspath/{alias}.json)
#[wasm_bindgen]
pub struct HttpsWellKnownResolver;

#[wasm_bindgen]
impl HttpsWellKnownResolver {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self
    }

    pub async fn resolve_alias_async(&self, alias: &str) -> Result<String, String> {
        let (name, domain) = split_alias(alias)?;
        let url = format!("https://{}/.well-known/satspath/{}.json", domain, name);

        // SSRF protection
        crate::ssrf::validate_url(&url)?;

        let mut opts = RequestInit::new();
        opts.set_method("GET");
        opts.set_mode(RequestMode::Cors);

        let request =
            Request::new_with_str_and_init(&url, &opts).map_err(|e| format!("{:?}", e))?;
        let window = window().ok_or("no window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("Fetch failed: {:?}", e))?;
        let response: Response = resp_value.dyn_into().map_err(|_| "Invalid response")?;

        if !response.ok() {
            return Err("not_found".to_string());
        }

        let json = JsFuture::from(response.json().map_err(|e| format!("{:?}", e))?)
            .await
            .map_err(|e| format!("JSON parse failed: {:?}", e))?;

        let data: WellKnownResponse = serde_wasm_bindgen::from_value(json)
            .map_err(|e| format!("Deserialization failed: {:?}", e))?;

        if data.profile.alias.to_lowercase() != alias.to_lowercase() {
            return Err("Profile alias mismatch".to_string());
        }

        serde_json::to_string(&SignedPaymentProfile {
            profile: data.profile,
            signature: data.signature,
            hybrid_signature: None,
        })
        .map_err(|e| e.to_string())
    }
}

/// Nostr NIP-05 resolver
#[wasm_bindgen]
pub struct NostrNip05Resolver {
    relay_urls: Vec<String>,
}

#[wasm_bindgen]
impl NostrNip05Resolver {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            relay_urls: vec![
                "wss://relay.nostr.band".to_string(),
                "wss://nostr-pub.wellorder.net".to_string(),
            ],
        }
    }

    pub async fn resolve_alias_async(&self, alias: &str) -> Result<String, String> {
        let (name, domain) = split_alias(alias)?;

        // 1. Fetch NIP-05
        let nip05 = self.fetch_nip05(&name, &domain).await?;
        let pubkey = nip05
            .names
            .get(&name.to_lowercase())
            .ok_or_else(|| format!("NIP-05 not found: {}@{}", name, domain))?;

        // 2. Query relays for kind 30078
        let d_tag = format!("satspath-profile:{}", alias.to_lowercase());
        let event = self.query_relays(pubkey, &d_tag).await?;

        // 3. Verify event author matches NIP-05 pubkey
        if event.pubkey.to_lowercase() != pubkey.to_lowercase() {
            return Err("Event author mismatch".to_string());
        }

        // 4. Parse profile from event content
        let profile_data: ProfileEventContent = serde_json::from_str(&event.content)
            .map_err(|e| format!("Invalid profile JSON: {}", e))?;

        serde_json::to_string(&profile_data.profile).map_err(|e| e.to_string())
    }

    async fn fetch_nip05(&self, name: &str, domain: &str) -> Result<Nip05Response, String> {
        let url = format!("https://{}/.well-known/nostr.json?name={}", domain, name);

        // SSRF protection
        crate::ssrf::validate_url(&url)?;

        let mut opts = RequestInit::new();
        opts.set_method("GET");
        opts.set_mode(RequestMode::Cors);

        let request =
            Request::new_with_str_and_init(&url, &opts).map_err(|e| format!("{:?}", e))?;
        let window = window().ok_or("no window")?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("NIP-05 fetch failed: {:?}", e))?;
        let response: Response = resp_value.dyn_into().map_err(|_| "Invalid response")?;

        if !response.ok() {
            return Err("NIP-05 not found".to_string());
        }

        let json = JsFuture::from(response.json().map_err(|e| format!("{:?}", e))?)
            .await
            .map_err(|e| format!("JSON parse failed: {:?}", e))?;

        serde_wasm_bindgen::from_value(json)
            .map_err(|e| format!("NIP-05 deserialization failed: {:?}", e))
    }

    async fn query_relays(&self, _pubkey: &str, _d_tag: &str) -> Result<NostrEvent, String> {
        // Simplified - in production use WebSocket via web-sys
        // For now return not found
        Err("Nostr relay query not yet implemented".to_string())
    }
}

/// Default resolver chain
pub fn create_default_chain() -> ChainResolver {
    ChainResolver::new()
}

// ===== Helpers =====

fn split_alias(alias: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = alias.split('@').collect();
    if parts.len() != 2 {
        return Err("Invalid alias format".to_string());
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn uri_to_profile(alias: &str, uri: String) -> SignedPaymentProfile {
    let mut methods = Vec::new();

    let clean_uri = uri.replace("BIP321:", "bitcoin:");
    if let Ok(parsed) = url::Url::parse(&clean_uri.replace("bitcoin:", "https://")) {
        if let Some(addr) = parsed.path_segments().and_then(|mut s| s.next()) {
            if is_valid_address(addr) {
                methods.push(PaymentMethod::Onchain {
                    label: "Bitcoin (BIP-353)".to_string(),
                    network: detect_network(addr),
                    address: Some(addr.to_string()),
                    silent_payment_pubkey: None,
                    pubkey_hint: None,
                    descriptor_hint: None,
                    address_list: vec![],
                });
            }
        }

        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "lightning" => methods.push(PaymentMethod::Lightning {
                    label: "Lightning (BIP-353)".to_string(),
                    lightning_address: Some(v.to_string()),
                    lnurl: None,
                    bolt12: None,
                    receiver_pubkey: None,
                }),
                "lnurl" => methods.push(PaymentMethod::Lightning {
                    label: "LNURL (BIP-353)".to_string(),
                    lightning_address: None,
                    lnurl: Some(v.to_string()),
                    bolt12: None,
                    receiver_pubkey: None,
                }),
                "bolt12" => methods.push(PaymentMethod::Lightning {
                    label: "BOLT12 (BIP-353)".to_string(),
                    lightning_address: None,
                    lnurl: None,
                    bolt12: Some(v.to_string()),
                    receiver_pubkey: None,
                }),
                "ark_server" => {
                    if let Some(pubkey) = parsed
                        .query_pairs()
                        .find(|(k, _)| k == "ark_pubkey")
                        .map(|(_, v)| v.to_string())
                    {
                        methods.push(PaymentMethod::Ark {
                            label: "Ark (BIP-353)".to_string(),
                            server: v.to_string(),
                            pubkey,
                            vtxo_pointer: None,
                            opaque_uri: None,
                            proof: None,
                            expires_at: None,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    let profile = crate::types::PaymentProfile {
        alias: alias.to_string(),
        identity_pubkey: domain_pubkey_hash(&alias.split('@').nth(1).unwrap_or("")),
        methods,
        updated_at: js_sys::Date::now() as i64 / 1000,
        expires_at: None,
        sequence: None,
        preferences: vec![
            "lightning".to_string(),
            "onchain".to_string(),
            "ark".to_string(),
        ],
        nonce: None,
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
    };

    SignedPaymentProfile {
        profile,
        signature: String::new(),
        hybrid_signature: None,
    }
}

fn is_valid_address(addr: &str) -> bool {
    !addr.is_empty() && addr.len() >= 26 && addr.len() <= 62
}

fn detect_network(addr: &str) -> BitcoinNetwork {
    if addr.starts_with("bc1") || addr.starts_with("1") || addr.starts_with("3") {
        BitcoinNetwork::Mainnet
    } else if addr.starts_with("tb1")
        || addr.starts_with("m")
        || addr.starts_with("n")
        || addr.starts_with("2")
    {
        BitcoinNetwork::Testnet
    } else if addr.starts_with("bcrt1") {
        BitcoinNetwork::Regtest
    } else {
        BitcoinNetwork::Mainnet
    }
}

fn domain_pubkey_hash(domain: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    bytes[1..].copy_from_slice(&hash[..32]);
    hex::encode(bytes)
}
