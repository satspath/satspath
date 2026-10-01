use std::time::Duration;

use crate::ark_bridge::ArkBridge;
use crate::boltz_client::BoltzClient;
use crate::chain_swap::{
    create_chain_swap, wait_and_claim_chain, ChainSwapCreated, ChainSwapParams,
};
use crate::errors::{Result, SwapError};
use crate::reverse::{create_reverse, wait_and_claim_reverse, ReverseParams, ReverseSwapCreated};
use crate::submarine::{create_submarine, wait_submarine, SubmarineParams, SubmarineSwapCreated};
use crate::swap_store::SwapStore;
use crate::types::{SwapKind, SwapRecord, SwapResult};

/// SwapManager orchestrates the lifecycle of Boltz swaps.
///
/// It holds references to the Boltz API client, the encrypted local storage,
/// and the ARK Node.js bridge.
pub struct SwapManager {
    client: BoltzClient,
    store: SwapStore,
    bridge: Option<ArkBridge>,
}

impl SwapManager {
    /// Create a new SwapManager.
    pub fn new(client: BoltzClient, store: SwapStore) -> Self {
        Self {
            client,
            store,
            bridge: None,
        }
    }

    /// Attach the ARK Node.js bridge to this SwapManager.
    pub fn with_ark_bridge(mut self, bridge: ArkBridge) -> Self {
        self.bridge = Some(bridge);
        self
    }

    // ─── Creation ─────────────────────────────────────────────────────────────

    pub async fn create_submarine(&self, params: SubmarineParams) -> Result<SubmarineSwapCreated> {
        create_submarine(&self.client, &self.store, params).await
    }

    pub async fn create_reverse(&self, params: ReverseParams) -> Result<ReverseSwapCreated> {
        create_reverse(&self.client, &self.store, params).await
    }

    pub async fn create_chain_swap(&self, params: ChainSwapParams) -> Result<ChainSwapCreated> {
        create_chain_swap(&self.client, &self.store, params).await
    }

    // ─── Waiting & Claiming ───────────────────────────────────────────────────

    /// Wait for a swap to reach a terminal state.
    ///
    /// For Submarine: waits for invoice.paid or invoice.failedToPay.
    /// For Reverse: waits for lockup confirmation, claims on-chain.
    /// For Chain: waits for lockup confirmation, claims cooperatively.
    pub async fn wait_and_claim(&self, swap_id: &str, max_wait: Duration) -> Result<SwapResult> {
        let record = self
            .store
            .get(swap_id)?
            .ok_or_else(|| SwapError::NotFound(swap_id.to_string()))?;

        match record.kind {
            SwapKind::Submarine => {
                wait_submarine(&self.client, &self.store, swap_id, max_wait).await
            }
            SwapKind::Reverse => {
                wait_and_claim_reverse(&self.client, &self.store, swap_id, max_wait).await
            }
            SwapKind::Chain => {
                wait_and_claim_chain(&self.client, &self.store, swap_id, max_wait).await
            }
        }
    }

    // ─── Recovery ─────────────────────────────────────────────────────────────

    /// Scan local storage for swaps that are in a recoverable failure state.
    pub fn scan_recoverable(&self) -> Result<Vec<SwapRecord>> {
        self.store.list_recoverable()
    }

    /// Scan local storage for pending swaps that might need continued tracking.
    pub fn scan_pending(&self) -> Result<Vec<SwapRecord>> {
        self.store.list_pending(None)
    }
}
