//! WASM-compatible fee estimation using web-sys fetch
//!
//! Replaces the tokio/reqwest-based fetcher with browser-compatible fetch API.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

/// Recommended fee rates from mempool.space (camelCase for JSON)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MempoolFeeEstimate {
    pub fastest_fee: u64,
    pub half_hour_fee: u64,
    pub hour_fee: u64,
    pub economy_fee: u64,
    pub minimum_fee: u64,
}

/// Internal fee estimate type used by the router
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub fastest_fee: u64,
    pub half_hour_fee: u64,
    pub hour_fee: u64,
    pub economy_fee: u64,
    pub minimum_fee: u64,
}

impl From<MempoolFeeEstimate> for FeeEstimate {
    fn from(e: MempoolFeeEstimate) -> Self {
        FeeEstimate {
            fastest_fee: e.fastest_fee,
            half_hour_fee: e.half_hour_fee,
            hour_fee: e.hour_fee,
            economy_fee: e.economy_fee,
            minimum_fee: e.minimum_fee,
        }
    }
}

/// Fallback fees when network is unavailable (conservative estimates)
const FALLBACK_FEES: FeeEstimate = FeeEstimate {
    fastest_fee: 20,
    half_hour_fee: 15,
    hour_fee: 10,
    economy_fee: 5,
    minimum_fee: 1,
};

/// Fetch fee estimates from mempool.space using browser fetch API
pub async fn fetch_fee_estimate() -> Result<FeeEstimate, JsValue> {
    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(
        "https://mempool.space/api/v1/fees/recommended",
        &opts,
    )?;

    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let response_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let response: Response = response_value.dyn_into()?;

    if !response.ok() {
        return Ok(FALLBACK_FEES);
    }

    let json_value = JsFuture::from(response.json()?).await?;
    let estimate: MempoolFeeEstimate = serde_wasm_bindgen::from_value(json_value)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(estimate.into())
}

/// Synchronous getter for fallback fees (useful for tests)
#[wasm_bindgen]
pub fn fallback_fees() -> FeeEstimate {
    FALLBACK_FEES
}