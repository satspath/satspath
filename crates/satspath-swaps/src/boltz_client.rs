use std::collections::HashMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::errors::{Result, SwapError};
use crate::types::{MinerFees, PairFees, PairLimits, SwapStatus};

// ─── Configuration ────────────────────────────────────────────────────────────

/// Boltz Exchange API base URLs.
pub const BOLTZ_MAINNET: &str = "https://api.boltz.exchange";
pub const BOLTZ_TESTNET: &str = "https://testnet.boltz.exchange";
pub const BOLTZ_WS_MAINNET: &str = "wss://api.boltz.exchange/v2/ws";
pub const BOLTZ_WS_TESTNET: &str = "wss://testnet.boltz.exchange/v2/ws";

/// Asset pair identifiers used by Boltz.
pub const PAIR_BTC_BTC: &str = "BTC/BTC";

// ─── HTTP Request / Response Types ───────────────────────────────────────────

// --- Fees ---

/// Raw response from GET /v2/swap/fees
/// Structure: { "BTC": { "BTC": { "percentage": 0.1, "minerFees": { ... } } } }
#[derive(Debug, Deserialize)]
pub struct FeesResponse(pub HashMap<String, HashMap<String, RawPairFees>>);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawPairFees {
    pub percentage: f64,
    pub miner_fees: RawMinerFees,
}

#[derive(Debug, Deserialize)]
pub struct RawMinerFees {
    pub claim: u64,
    pub refund: u64,
}

/// Raw response from GET /v2/swap/limits
#[derive(Debug, Deserialize)]
pub struct LimitsResponse(pub HashMap<String, HashMap<String, RawPairLimits>>);

#[derive(Debug, Deserialize)]
pub struct RawPairLimits {
    pub minimal: u64,
    pub maximal: u64,
}

// --- Submarine Swap ---

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmarineSwapRequest {
    /// Lightning invoice to pay.
    pub invoice: String,
    /// Source asset (e.g. "BTC").
    pub from: String,
    /// Destination asset (e.g. "BTC").
    pub to: String,
    /// Client's refund public key (hex-compressed secp256k1).
    pub refund_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmarineSwapResponse {
    /// Boltz-assigned swap ID.
    pub id: String,
    /// Address where the sender must deposit BTC.
    pub address: String,
    /// Exact amount in satoshis to deposit at `address`.
    pub expected_amount: u64,
    /// Block height at which the HTLC timelock expires.
    pub timeout_block_height: u32,
    /// Boltz's public key in the HTLC (hex).
    pub claim_public_key: String,
    /// Redeem script (hex) or null for Taproot swaps.
    #[serde(default)]
    pub redeem_script: Option<String>,
}

// --- Reverse Swap ---

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseSwapRequest {
    /// Source asset (e.g. "BTC" for Lightning).
    pub from: String,
    /// Destination asset (e.g. "BTC" for on-chain).
    pub to: String,
    /// Amount to receive in satoshis (what Boltz will lock on-chain).
    pub invoice_amount: u64,
    /// SHA-256 of the client's preimage (hex). Boltz will lock against this hash.
    pub preimage_hash: String,
    /// Client's claim public key (hex-compressed secp256k1).
    pub claim_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseSwapResponse {
    /// Boltz-assigned swap ID.
    pub id: String,
    /// Hold invoice for the sender to pay via Lightning.
    pub invoice: String,
    /// Address where Boltz will lock the on-chain BTC.
    pub lockup_address: String,
    /// Boltz's refund public key in the HTLC.
    #[serde(default)]
    pub refund_public_key: Option<String>,
    /// Block height timeout.
    pub timeout_block_height: u32,
    /// Redeem script (hex) or null for Taproot.
    #[serde(default)]
    pub redeem_script: Option<String>,
    /// For Taproot swaps: the internal key of the Taproot output.
    #[serde(default)]
    pub blinding_key: Option<String>,
}

// --- Chain Swap ---

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSwapRequest {
    /// Source layer asset (e.g. "BTC").
    pub from: String,
    /// Destination layer asset (e.g. "BTC").
    pub to: String,
    /// SHA-256 of the client's preimage (hex).
    pub preimage_hash: String,
    /// Client's claim public key for the server-side lockup.
    pub claim_public_key: String,
    /// Client's refund public key for the user-side lockup.
    pub refund_public_key: String,
    /// One of sender_lock_amount or receiver_lock_amount must be set.
    /// If sender_lock_amount: sender sends this exact amount; fees deducted from receiver side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_lock_amount: Option<u64>,
    /// If receiver_lock_amount: guaranteed net delivery; sender pays more to cover fees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_lock_amount: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSwapResponse {
    pub id: String,
    /// Nested "claim" and "lockup" leg details.
    pub claim_details: ChainSwapLeg,
    pub lockup_details: ChainSwapLeg,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSwapLeg {
    pub swap_tree: Option<serde_json::Value>,
    pub lockup_address: String,
    pub server_public_key: Option<String>,
    pub timeout_block_height: u32,
    pub amount: u64,
    pub blinding_key: Option<String>,
}

// --- Chain Swap Quote (renegotiation) ---

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSwapQuoteResponse {
    pub amount: u64,
}

// --- WebSocket messages ---

#[derive(Debug, Serialize)]
pub struct WsSubscribeMessage {
    pub op: String,
    pub channel: String,
    pub args: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct WsUpdateMessage {
    pub event: String,
    pub channel: Option<String>,
    pub args: Option<Vec<WsSwapUpdate>>,
}

#[derive(Debug, Deserialize)]
pub struct WsSwapUpdate {
    pub id: String,
    pub status: SwapStatus,
    /// Present when a new lockup transaction is detected.
    #[serde(default)]
    pub transaction: Option<WsTransaction>,
}

#[derive(Debug, Deserialize)]
pub struct WsTransaction {
    pub id: Option<String>,
    pub hex: Option<String>,
}

// --- Error response ---

#[derive(Debug, Deserialize)]
pub struct BoltzErrorResponse {
    pub error: String,
}

// ─── BoltzClient ─────────────────────────────────────────────────────────────

/// HTTP client for Boltz Exchange API v2.
#[derive(Debug, Clone)]
pub struct BoltzClient {
    http: Client,
    base_url: String,
    ws_url: String,
}

impl BoltzClient {
    /// Create a client targeting Boltz mainnet.
    pub fn mainnet() -> Self {
        Self::new(BOLTZ_MAINNET, BOLTZ_WS_MAINNET)
    }

    /// Create a client targeting Boltz testnet.
    pub fn testnet() -> Self {
        Self::new(BOLTZ_TESTNET, BOLTZ_WS_TESTNET)
    }

    pub fn new(base_url: &str, ws_url: &str) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("satspath/0.1 (+https://github.com/Truja503/satspath)")
            .build()
            .expect("Failed to build HTTP client");

        BoltzClient {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            ws_url: ws_url.to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v2{}", self.base_url, path)
    }

    // ── Helper: check for Boltz API error responses ───────────────────────

    async fn check_response<T: for<'de> Deserialize<'de>>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T> {
        let status = resp.status().as_u16();
        let body = resp.text().await.map_err(SwapError::Http)?;

        if status >= 400 {
            // Try to extract Boltz error message
            let msg = serde_json::from_str::<BoltzErrorResponse>(&body)
                .map(|e| e.error)
                .unwrap_or(body);
            return Err(SwapError::BoltzApi {
                status,
                message: msg,
            });
        }

        serde_json::from_str(&body).map_err(SwapError::Json)
    }

    // ── GET /v2/swap/fees ─────────────────────────────────────────────────

    /// Fetch current service fees and estimated miner fees for all pairs.
    pub async fn get_fees(&self) -> Result<PairFees> {
        let resp = self
            .http
            .get(self.url("/swap/fees"))
            .send()
            .await
            .map_err(SwapError::Http)?;

        let raw: FeesResponse = self.check_response(resp).await?;

        // Extract BTC/BTC pair
        let btc = raw
            .0
            .get("BTC")
            .and_then(|inner| inner.get("BTC"))
            .ok_or_else(|| SwapError::BoltzApi {
                status: 200,
                message: "BTC/BTC pair not found in fees response".into(),
            })?;

        Ok(PairFees {
            percentage: btc.percentage,
            miner_fees: MinerFees {
                claim: btc.miner_fees.claim,
                refund: btc.miner_fees.refund,
            },
        })
    }

    // ── GET /v2/swap/limits ───────────────────────────────────────────────

    /// Fetch min/max limits for the BTC/BTC pair.
    pub async fn get_limits(&self) -> Result<PairLimits> {
        let resp = self
            .http
            .get(self.url("/swap/limits"))
            .send()
            .await
            .map_err(SwapError::Http)?;

        let raw: LimitsResponse = self.check_response(resp).await?;

        let btc = raw
            .0
            .get("BTC")
            .and_then(|inner| inner.get("BTC"))
            .ok_or_else(|| SwapError::BoltzApi {
                status: 200,
                message: "BTC/BTC pair not found in limits response".into(),
            })?;

        Ok(PairLimits {
            minimal: btc.minimal,
            maximal: btc.maximal,
        })
    }

    // ── POST /v2/swap/submarine ───────────────────────────────────────────

    /// Create a submarine swap: on-chain BTC → Lightning invoice payment.
    pub async fn create_submarine(
        &self,
        req: &SubmarineSwapRequest,
    ) -> Result<SubmarineSwapResponse> {
        let resp = self
            .http
            .post(self.url("/swap/submarine"))
            .json(req)
            .send()
            .await
            .map_err(SwapError::Http)?;

        self.check_response(resp).await
    }

    // ── POST /v2/swap/reverse ─────────────────────────────────────────────

    /// Create a reverse swap: Lightning payment → on-chain BTC delivery.
    pub async fn create_reverse(&self, req: &ReverseSwapRequest) -> Result<ReverseSwapResponse> {
        let resp = self
            .http
            .post(self.url("/swap/reverse"))
            .json(req)
            .send()
            .await
            .map_err(SwapError::Http)?;

        self.check_response(resp).await
    }

    // ── POST /v2/swap/chain ───────────────────────────────────────────────

    /// Create a chain swap: on-chain/Ark → on-chain BTC (no Lightning).
    pub async fn create_chain(&self, req: &ChainSwapRequest) -> Result<ChainSwapResponse> {
        let resp = self
            .http
            .post(self.url("/swap/chain"))
            .json(req)
            .send()
            .await
            .map_err(SwapError::Http)?;

        self.check_response(resp).await
    }

    // ── GET /v2/swap/chain/{id}/quote ─────────────────────────────────────

    /// Fetch a new quote for a chain swap after a lockup amount mismatch.
    pub async fn get_chain_swap_quote(&self, swap_id: &str) -> Result<ChainSwapQuoteResponse> {
        let resp = self
            .http
            .get(self.url(&format!("/swap/chain/{}/quote", swap_id)))
            .send()
            .await
            .map_err(SwapError::Http)?;

        self.check_response(resp).await
    }

    /// Accept a renegotiated quote for a chain swap.
    pub async fn accept_chain_swap_quote(
        &self,
        swap_id: &str,
        quote: &ChainSwapQuoteResponse,
    ) -> Result<()> {
        let resp = self
            .http
            .post(self.url(&format!("/swap/chain/{}/quote", swap_id)))
            .json(quote)
            .send()
            .await
            .map_err(SwapError::Http)?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let msg = resp.text().await.unwrap_or_default();
            Err(SwapError::BoltzApi {
                status,
                message: msg,
            })
        }
    }

    // ── WebSocket: wait for swap status transition ────────────────────────

    /// Subscribe to swap updates via WebSocket and wait for a terminal or
    /// specified target status. Returns the last update received.
    ///
    /// # Timeout
    /// `max_wait` caps the total wait time. Returns `SwapError::Timeout` if
    /// exceeded.
    pub async fn wait_for_status(
        &self,
        swap_id: &str,
        target: Option<&[SwapStatus]>,
        max_wait: Duration,
    ) -> Result<WsSwapUpdate> {
        let ws_url = self.ws_url.to_string();

        let (mut ws, _) = connect_async(&ws_url)
            .await
            .map_err(|e| SwapError::WebSocket(e.to_string()))?;

        // Subscribe to swap.update channel for this swap ID
        let subscribe = WsSubscribeMessage {
            op: "subscribe".into(),
            channel: "swap.update".into(),
            args: vec![swap_id.to_string()],
        };
        let sub_json = serde_json::to_string(&subscribe).map_err(SwapError::Json)?;
        ws.send(Message::Text(sub_json.into()))
            .await
            .map_err(|e| SwapError::WebSocket(e.to_string()))?;

        let wait = timeout(max_wait, async {
            while let Some(msg) = ws.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        let Ok(update) = serde_json::from_str::<WsUpdateMessage>(&text) else {
                            continue;
                        };

                        if update.event == "update" {
                            if let Some(args) = update.args {
                                for arg in args {
                                    if arg.id != swap_id {
                                        continue;
                                    }

                                    // Return if we reached a terminal state or the target state
                                    let reached_target =
                                        target.map(|t| t.contains(&arg.status)).unwrap_or(false);
                                    let is_terminal = arg.status.is_terminal();

                                    if reached_target || is_terminal {
                                        return Ok(arg);
                                    }
                                }
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        return Err(SwapError::WebSocket("WebSocket closed by server".into()));
                    }
                    Err(e) => {
                        return Err(SwapError::WebSocket(e.to_string()));
                    }
                    _ => {}
                }
            }
            Err(SwapError::WebSocket(
                "WebSocket stream ended unexpectedly".into(),
            ))
        })
        .await;

        match wait {
            Ok(result) => result,
            Err(_elapsed) => Err(SwapError::Timeout {
                id: swap_id.to_string(),
                last_status: "unknown".into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builds_correct_urls_mainnet() {
        let client = BoltzClient::mainnet();
        assert_eq!(
            client.url("/swap/submarine"),
            "https://api.boltz.exchange/v2/swap/submarine"
        );
    }

    #[test]
    fn client_builds_correct_urls_testnet() {
        let client = BoltzClient::testnet();
        assert_eq!(
            client.url("/swap/fees"),
            "https://testnet.boltz.exchange/v2/swap/fees"
        );
    }
}
