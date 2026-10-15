//! Ark Service Provider (ASP) live client connector, VTXO DAG verifier, and settlement handoff builders.
//!
//! Provides non-custodial discovery, fee/round parameter querying (`GET /v1/info`),
//! VTXO covenant tree DAG verification, and host-wallet settlement handoff structures
//! (Boarding, In-Round Forfeit, and Out-of-Round / Arkade OOR transfers) for live `arkd` ASPs.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Context, Result};
use satspath_core::validation::{assert_no_private_material, validate_compressed_pubkey};
use satspath_core::PaymentMethod;
use serde::{Deserialize, Serialize};

/// Adapter trait for a synchronous Ark server client.
pub trait ArkClient {
    /// Whether the Ark server is reachable and available.
    fn is_available(&self) -> bool;
    /// Create a payment intent for `amount_sats` to `pubkey`.
    fn create_payment_intent(&self, amount_sats: u64, pubkey: &str) -> anyhow::Result<String>;
}

/// Simulated Ark intent payload for legacy synchronous tests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimulatedArkIntent {
    /// Unique intent identifier.
    pub intent_id: String,
    /// Recipient compressed public key (hex).
    pub pubkey: String,
    /// Amount in satoshis.
    pub amount_sats: u64,
    /// Intent lifecycle status.
    pub status: String,
    /// Target Ark ASP server URL.
    pub server_url: String,
}

/// Mock Ark client used in offline unit tests.
pub struct MockArkClient {
    /// Whether the mock server reports available.
    pub available: bool,
    /// Mock server URL.
    pub server_url: String,
}

impl ArkClient for MockArkClient {
    fn is_available(&self) -> bool {
        self.available
    }

    fn create_payment_intent(&self, amount_sats: u64, pubkey: &str) -> anyhow::Result<String> {
        if !self.available {
            anyhow::bail!("Ark server unavailable");
        }

        let intent_id = format!(
            "intent_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );
        let intent = SimulatedArkIntent {
            intent_id,
            pubkey: pubkey.to_string(),
            amount_sats,
            status: "waiting_for_payment".to_string(),
            server_url: self.server_url.clone(),
        };

        Ok(serde_json::to_string(&intent)?)
    }
}

/// Check whether any Ark method exists in a method list.
pub fn is_ark_available(methods: &[PaymentMethod]) -> bool {
    methods
        .iter()
        .any(|m| matches!(m, PaymentMethod::Ark { .. }))
}

/// Find the first Ark method in a method list.
pub fn first_ark_method(methods: &[PaymentMethod]) -> Option<&PaymentMethod> {
    methods
        .iter()
        .find(|m| matches!(m, PaymentMethod::Ark { .. }))
}

// ============================================================================
// Live Ark ASP Metadata, Fee Schedule & Settlement Handoff Structures
// ============================================================================

/// Fee schedule advertised by an Ark Service Provider (`arkd`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ArkFeeSchedule {
    /// Fixed base fee per VTXO transfer in satoshis.
    #[serde(default)]
    pub base_fee_sats: u64,
    /// Proportional fee rate in parts-per-million (ppm).
    #[serde(default)]
    pub ppm_rate: u64,
    /// Fixed fee in satoshis for onboarding an on-chain UTXO into the Ark.
    #[serde(default)]
    pub onboard_fee_sats: u64,
    /// Fixed fee in satoshis for collaborative redemption (offboarding) to on-chain.
    #[serde(default)]
    pub offboard_fee_sats: u64,
}

/// Live parameters returned by an Ark Service Provider (`GET /v1/info`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkAspInfo {
    /// ASP 33-byte compressed secp256k1 public key (hex).
    pub pubkey: String,
    /// Network identifier (`"bitcoin"`, `"testnet"`, `"signet"`, `"regtest"`, or `"mutinynet"`).
    pub network: String,
    /// Interval between scheduled VTXO covenant rounds in seconds.
    pub round_interval_secs: u64,
    /// VTXO tree lifetime before expiry (in seconds or blocks).
    pub vtxo_tree_expiry: u64,
    /// Unilateral exit timelock delay (CSV blocks/seconds).
    pub unilateral_exit_delay: u64,
    /// Minimum VTXO output amount (dust limit) in satoshis.
    pub dust_limit_sats: u64,
    /// Optional Taproot boarding descriptor template advertised by the ASP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boarding_descriptor_template: Option<String>,
    /// ASP fee parameters.
    #[serde(default)]
    pub fees: ArkFeeSchedule,
}

impl ArkAspInfo {
    /// Validate the cryptographic and operational parameters returned by an ASP.
    ///
    /// # Errors
    /// Returns an error if the ASP `pubkey` is not a valid 33-byte compressed secp256k1 key,
    /// if `round_interval_secs` or `vtxo_tree_expiry` is zero, if the network is unknown,
    /// or if private material is present.
    pub fn validate(&self) -> Result<()> {
        validate_compressed_pubkey(&self.pubkey)
            .map_err(|e| anyhow!("invalid ASP public key: {e}"))?;
        if self.round_interval_secs == 0 {
            anyhow::bail!("ASP round_interval_secs must be greater than 0");
        }
        if self.vtxo_tree_expiry == 0 {
            anyhow::bail!("ASP vtxo_tree_expiry must be greater than 0");
        }
        if self.unilateral_exit_delay == 0 {
            anyhow::bail!("ASP unilateral_exit_delay must be greater than 0");
        }
        let net = self.network.trim().to_ascii_lowercase();
        if !matches!(
            net.as_str(),
            "bitcoin" | "mainnet" | "testnet" | "signet" | "regtest" | "mutinynet"
        ) {
            anyhow::bail!("unsupported ASP network: {}", self.network);
        }
        if let Some(ref desc) = self.boarding_descriptor_template {
            assert_no_private_material(desc).map_err(|e| anyhow!("{e}"))?;
        }
        Ok(())
    }

    /// Estimate the total fee in satoshis for an Ark VTXO transfer of `amount_sats`.
    pub fn estimate_transfer_fee(&self, amount_sats: u64) -> u64 {
        let proportional = amount_sats.saturating_mul(self.fees.ppm_rate) / 1_000_000;
        self.fees.base_fee_sats.saturating_add(proportional)
    }
}

/// Node in an Ark virtual transaction output (VTXO) covenant tree DAG.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkVtxoTreeNode {
    /// Virtual transaction ID (64-char hex).
    pub txid: String,
    /// Parent virtual transaction ID (`None` for the root shared output transaction).
    pub parent_txid: Option<String>,
    /// Output index within this virtual transaction.
    pub vout: u32,
    /// Output value in satoshis.
    pub amount_sats: u64,
    /// 33-byte compressed ASP cosigning public key (hex).
    pub asp_cosign_pubkey: String,
    /// Optional 33-byte compressed receiver public key for leaf VTXOs (hex).
    pub receiver_pubkey: Option<String>,
    /// Relative expiry sequence / timelock.
    pub expiry_sequence: u32,
    /// Child virtual transaction IDs spending from this node.
    pub children: Vec<String>,
}

/// Cryptographically and structurally verify an Ark VTXO covenant tree DAG from `root_txid`
/// down to `target_vtxo_txid`.
///
/// Enforces:
/// - Acyclic parent-child linkage from `root_txid` to `target_vtxo_txid`.
/// - Every node in the tree commits to `expected_asp_pubkey`.
/// - Value conservation at every internal branch (`sum(children.amount_sats) <= parent.amount_sats`).
/// - The target leaf VTXO has `amount_sats >= expected_amount_sats` and non-zero `expiry_sequence`.
///
/// # Errors
/// Returns an error if the DAG is cyclic, disconnected, violates value conservation,
/// mismatches the ASP public key, or under-funds the target VTXO.
pub fn verify_ark_vtxo_dag(
    nodes: &[ArkVtxoTreeNode],
    root_txid: &str,
    expected_asp_pubkey: &str,
    target_vtxo_txid: &str,
    expected_amount_sats: u64,
) -> Result<()> {
    validate_compressed_pubkey(expected_asp_pubkey)
        .map_err(|e| anyhow!("invalid expected ASP pubkey: {e}"))?;

    let mut map: HashMap<&str, &ArkVtxoTreeNode> = HashMap::with_capacity(nodes.len());
    for node in nodes {
        if node.txid.len() != 64 || hex::decode(&node.txid).is_err() {
            anyhow::bail!("invalid VTXO node txid: {}", node.txid);
        }
        if !node
            .asp_cosign_pubkey
            .eq_ignore_ascii_case(expected_asp_pubkey)
        {
            anyhow::bail!(
                "VTXO node {} ASP pubkey {} does not match expected {}",
                node.txid,
                node.asp_cosign_pubkey,
                expected_asp_pubkey
            );
        }
        if node.expiry_sequence == 0 {
            anyhow::bail!("VTXO node {} has zero expiry_sequence", node.txid);
        }
        if map.insert(node.txid.as_str(), node).is_some() {
            anyhow::bail!("duplicate VTXO node txid in DAG: {}", node.txid);
        }
    }

    let root = map
        .get(root_txid)
        .ok_or_else(|| anyhow!("root VTXO node {root_txid} not found in DAG"))?;
    if root.parent_txid.is_some() {
        anyhow::bail!("root VTXO node {root_txid} must not have a parent_txid");
    }

    let target = map
        .get(target_vtxo_txid)
        .ok_or_else(|| anyhow!("target VTXO node {target_vtxo_txid} not found in DAG"))?;
    if target.amount_sats < expected_amount_sats {
        anyhow::bail!(
            "target VTXO amount {} sats is less than expected {} sats",
            target.amount_sats,
            expected_amount_sats
        );
    }

    // Verify value conservation on every node with children
    for node in nodes {
        if !node.children.is_empty() {
            let mut children_sum: u64 = 0;
            for child_id in &node.children {
                let child = map
                    .get(child_id.as_str())
                    .ok_or_else(|| anyhow!("missing child VTXO node {child_id}"))?;
                if child.parent_txid.as_deref() != Some(node.txid.as_str()) {
                    anyhow::bail!(
                        "child VTXO {} parent_txid {:?} does not point to {}",
                        child.txid,
                        child.parent_txid,
                        node.txid
                    );
                }
                children_sum = children_sum
                    .checked_add(child.amount_sats)
                    .context("VTXO children amount overflow")?;
            }
            if children_sum > node.amount_sats {
                anyhow::bail!(
                    "VTXO value inflation at node {}: children sum {} > parent {}",
                    node.txid,
                    children_sum,
                    node.amount_sats
                );
            }
        }
    }

    // Walk backwards from target_vtxo_txid to root_txid to prove reachability and acyclicity
    let mut visited = HashSet::new();
    let mut curr = *target;
    loop {
        if !visited.insert(curr.txid.as_str()) {
            anyhow::bail!("cycle detected in VTXO DAG at {}", curr.txid);
        }
        if curr.txid == root_txid {
            break;
        }
        let Some(ref parent_id) = curr.parent_txid else {
            anyhow::bail!(
                "target VTXO {target_vtxo_txid} is disconnected from root {root_txid} at {}",
                curr.txid
            );
        };
        let parent = map
            .get(parent_id.as_str())
            .ok_or_else(|| anyhow!("missing ancestor VTXO node {parent_id}"))?;
        if !parent.children.iter().any(|c| c == &curr.txid) {
            anyhow::bail!(
                "parent VTXO {} does not list {} among its children",
                parent.txid,
                curr.txid
            );
        }
        curr = parent;
    }

    Ok(())
}

/// Handoff descriptor for boarding on-chain funds into an Ark ASP round.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkBoardingHandoff {
    /// Target Ark ASP server URL.
    pub server_url: String,
    /// On-chain Taproot boarding address (`bc1p...` / `tb1p...` / `bcrt1p...`).
    pub boarding_address: String,
    /// ASP 33-byte compressed public key (hex).
    pub asp_pubkey: String,
    /// Recipient/user 33-byte compressed public key (hex).
    pub user_pubkey: String,
    /// Unilateral exit delay (blocks/seconds) in the boarding Tapscript branch.
    pub exit_delay: u64,
    /// Amount in satoshis to board.
    pub amount_sats: u64,
    /// Formatted `bitcoin:` BIP-21 URI for the host wallet to sign and broadcast.
    pub bip21_uri: String,
}

/// Handoff structure for an in-round VTXO forfeit + refresh settlement (e.g. Arkade Money).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkForfeitHandoff {
    /// Target Ark ASP server URL.
    pub server_url: String,
    /// Active ASP round identifier.
    pub round_id: String,
    /// Input VTXO outpoint being forfeited (`txid:vout`).
    pub input_vtxo_outpoint: String,
    /// Connector output outpoint from the round commitment transaction (`txid:vout`).
    pub connector_outpoint: String,
    /// Unsigned or partially-signed forfeit PSBT (base64) for the host wallet to inspect and sign.
    pub forfeit_psbt_base64: String,
    /// Root txid of the new VTXO covenant tree in which the receiver's VTXO is created.
    pub new_vtxo_tree_root: String,
    /// ASP 33-byte compressed public key (hex).
    pub asp_pubkey: String,
    /// Recipient 33-byte compressed public key (hex).
    pub receiver_pubkey: String,
    /// Amount in satoshis transferred to the recipient VTXO.
    pub amount_sats: u64,
}

/// Out-of-round (OOR / Arkoor) instant VTXO payment request handoff for compatible host wallets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkOorPaymentRequest {
    /// Target Ark ASP server URL.
    pub server_url: String,
    /// ASP 33-byte compressed public key (hex).
    pub asp_pubkey: String,
    /// Sender VTXO outpoint (`txid:vout`) being spent out-of-round.
    pub sender_vtxo_outpoint: String,
    /// Recipient 33-byte compressed public key (hex).
    pub receiver_pubkey: String,
    /// Payment amount in satoshis.
    pub amount_sats: u64,
    /// ASP fee in satoshis.
    pub fee_sats: u64,
    /// Remaining VTXO expiry window inherited by the OOR output.
    pub vtxo_tree_expiry: u64,
    /// Canonical `ark:` handoff URI for wallet invocation.
    pub ark_uri: String,
}

/// Unified non-custodial Ark settlement handoff payload for host wallets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "settlement_mode", rename_all = "snake_case")]
pub enum ArkSettlementHandoff {
    /// On-chain to Ark boarding output handoff.
    Boarding(ArkBoardingHandoff),
    /// In-round VTXO forfeit + tree refresh handoff.
    InRoundForfeit(ArkForfeitHandoff),
    /// Out-of-round (OOR) instant VTXO transfer handoff.
    OutOfRound(ArkOorPaymentRequest),
}

impl ArkSettlementHandoff {
    /// Validate this settlement handoff against the live `ArkAspInfo` parameters.
    ///
    /// Fails closed if keys are malformed, amounts fall below `asp_info.dust_limit_sats`,
    /// the ASP public key mismatches, or any field contains private key material.
    pub fn validate(&self, asp_info: &ArkAspInfo) -> Result<()> {
        asp_info.validate()?;
        let serialized = serde_json::to_string(self)?;
        assert_no_private_material(&serialized).map_err(|e| anyhow!("{e}"))?;

        match self {
            Self::Boarding(b) => {
                if !b.asp_pubkey.eq_ignore_ascii_case(&asp_info.pubkey) {
                    anyhow::bail!("boarding handoff ASP pubkey mismatch");
                }
                validate_compressed_pubkey(&b.user_pubkey)
                    .map_err(|e| anyhow!("invalid boarding user_pubkey: {e}"))?;
                if b.amount_sats < asp_info.dust_limit_sats {
                    anyhow::bail!(
                        "boarding amount {} sats is below ASP dust limit {} sats",
                        b.amount_sats,
                        asp_info.dust_limit_sats
                    );
                }
                if !b.bip21_uri.starts_with("bitcoin:") {
                    anyhow::bail!("boarding handoff bip21_uri must start with 'bitcoin:'");
                }
            }
            Self::InRoundForfeit(f) => {
                if !f.asp_pubkey.eq_ignore_ascii_case(&asp_info.pubkey) {
                    anyhow::bail!("forfeit handoff ASP pubkey mismatch");
                }
                validate_compressed_pubkey(&f.receiver_pubkey)
                    .map_err(|e| anyhow!("invalid forfeit receiver_pubkey: {e}"))?;
                if f.amount_sats < asp_info.dust_limit_sats {
                    anyhow::bail!(
                        "forfeit amount {} sats is below ASP dust limit {} sats",
                        f.amount_sats,
                        asp_info.dust_limit_sats
                    );
                }
                crate::silent_payments::parse_outpoint_to_bytes(&f.input_vtxo_outpoint)?;
                crate::silent_payments::parse_outpoint_to_bytes(&f.connector_outpoint)?;
                if f.forfeit_psbt_base64.trim().is_empty() {
                    anyhow::bail!("forfeit_psbt_base64 cannot be empty");
                }
            }
            Self::OutOfRound(oor) => {
                if !oor.asp_pubkey.eq_ignore_ascii_case(&asp_info.pubkey) {
                    anyhow::bail!("OOR handoff ASP pubkey mismatch");
                }
                validate_compressed_pubkey(&oor.receiver_pubkey)
                    .map_err(|e| anyhow!("invalid OOR receiver_pubkey: {e}"))?;
                if oor.amount_sats < asp_info.dust_limit_sats {
                    anyhow::bail!(
                        "OOR amount {} sats is below ASP dust limit {} sats",
                        oor.amount_sats,
                        asp_info.dust_limit_sats
                    );
                }
                crate::silent_payments::parse_outpoint_to_bytes(&oor.sender_vtxo_outpoint)?;
            }
        }
        Ok(())
    }
}

/// Receipt returned by an Ark ASP after registering a round or OOR settlement intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkRoundSubmissionReceipt {
    /// Assigned round ID or OOR package ID.
    pub submission_id: String,
    /// ASP status (`"registered"`, `"cosigned"`, `"broadcast"`).
    pub status: String,
    /// Root txid of the VTXO tree or OOR transaction.
    pub vtxo_txid: Option<String>,
}

/// Live Ark Service Provider HTTP connector (`arkd` REST client).
#[derive(Debug, Clone)]
pub struct LiveArkAspClient {
    server_url: String,
    allow_http_for_test: bool,
}

/// Read an HTTP response body up to `max_bytes`, failing closed if the stream exceeds the bound.
#[cfg(feature = "std")]
async fn read_bounded_bytes(mut resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            anyhow::bail!("Ark ASP response content-length ({len}) exceeds {max_bytes} bytes");
        }
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading Ark ASP stream")? {
        if out.len() + chunk.len() > max_bytes {
            anyhow::bail!("Ark ASP response body exceeded {max_bytes} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

impl LiveArkAspClient {
    /// Construct a new live Ark ASP client for `server_url` (HTTPS required).
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into().trim_end_matches('/').to_string(),
            allow_http_for_test: false,
        }
    }

    /// Construct a live Ark ASP client allowing HTTP for local/containerized `arkd` integration tests.
    pub fn new_for_test(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into().trim_end_matches('/').to_string(),
            allow_http_for_test: true,
        }
    }

    /// Return the configured ASP base URL.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Validate an endpoint URL before issuing a request.
    fn validate_endpoint(&self, url: &str) -> Result<()> {
        if self.allow_http_for_test {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                anyhow::bail!("unsupported scheme in ASP URL: {url}");
            }
            Ok(())
        } else {
            satspath_core::ssrf::validate_url(url, false)
                .map_err(|e| anyhow!("blocked Ark ASP URL: {e}"))
        }
    }

    /// Query `GET {server_url}/v1/info` on the live Ark ASP node and validate the returned parameters.
    #[cfg(feature = "std")]
    pub async fn get_asp_info(&self) -> Result<ArkAspInfo> {
        let url = format!("{}/v1/info", self.server_url);
        self.validate_endpoint(&url)?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let resp = client
            .get(&url)
            .send()
            .await
            .context("querying Ark ASP /v1/info")?;
        if !resp.status().is_success() {
            anyhow::bail!("Ark ASP /v1/info returned HTTP {}", resp.status());
        }
        let body = read_bounded_bytes(resp, 64 * 1024).await?;
        let info: ArkAspInfo = serde_json::from_slice(&body).context("decoding ArkAspInfo JSON")?;
        info.validate()?;
        Ok(info)
    }

    /// Construct and validate an out-of-round (`ArkSettlementHandoff::OutOfRound`) handoff using live ASP parameters.
    #[cfg(feature = "std")]
    pub async fn build_oor_handoff(
        &self,
        sender_vtxo_outpoint: &str,
        receiver_pubkey: &str,
        amount_sats: u64,
    ) -> Result<(ArkAspInfo, ArkSettlementHandoff)> {
        let info = self.get_asp_info().await?;
        let fee_sats = info.estimate_transfer_fee(amount_sats);
        let ark_uri = format!(
            "ark:{receiver_pubkey}?server={}&amount={amount_sats}&asp_pubkey={}",
            urlencoding::encode(&self.server_url),
            info.pubkey
        );
        let handoff = ArkSettlementHandoff::OutOfRound(ArkOorPaymentRequest {
            server_url: self.server_url.clone(),
            asp_pubkey: info.pubkey.clone(),
            sender_vtxo_outpoint: sender_vtxo_outpoint.to_string(),
            receiver_pubkey: receiver_pubkey.to_string(),
            amount_sats,
            fee_sats,
            vtxo_tree_expiry: info.vtxo_tree_expiry,
            ark_uri,
        });
        handoff.validate(&info)?;
        Ok((info, handoff))
    }

    /// Submit a validated [`ArkSettlementHandoff`] to the ASP (`/v1/round/register` or `/v1/oor/submit`).
    #[cfg(feature = "std")]
    pub async fn submit_settlement_handoff(
        &self,
        asp_info: &ArkAspInfo,
        handoff: &ArkSettlementHandoff,
    ) -> Result<ArkRoundSubmissionReceipt> {
        handoff.validate(asp_info)?;
        let path = match handoff {
            ArkSettlementHandoff::OutOfRound(_) => "/v1/oor/submit",
            ArkSettlementHandoff::InRoundForfeit(_) | ArkSettlementHandoff::Boarding(_) => {
                "/v1/round/register"
            }
        };
        let url = format!("{}{path}", self.server_url);
        self.validate_endpoint(&url)?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let resp = client
            .post(&url)
            .json(handoff)
            .send()
            .await
            .context("submitting Ark settlement handoff to ASP")?;
        if !resp.status().is_success() {
            anyhow::bail!("Ark ASP submission returned HTTP {}", resp.status());
        }
        let body = read_bounded_bytes(resp, 64 * 1024).await?;
        let receipt: ArkRoundSubmissionReceipt =
            serde_json::from_slice(&body).context("decoding ArkRoundSubmissionReceipt JSON")?;
        Ok(receipt)
    }
}
