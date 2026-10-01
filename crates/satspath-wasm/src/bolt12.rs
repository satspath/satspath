//! BOLT12 HTTP proxy scaffold.
//!
/// Fallback default proxy for BOLT12 resolution if none is explicitly provided.
/// In production, this would be a Cloudflare Worker or AWS Lambda instance.
pub const DEFAULT_BOLT12_PROXY: &str = "https://satspath-bolt12-proxy.workers.dev/resolve";

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

pub fn build_bolt12_proxy_url(offer: &str, amount_sats: u64, proxy_url: &str) -> String {
    format!(
        "{}/invoice?offer={}&amount_msats={}",
        proxy_url,
        offer,
        amount_sats * 1000
    )
}

/// Fetch a real BOLT11 invoice for a BOLT12 offer via a proxy.
pub async fn fetch_bolt12_invoice(
    offer: &str,
    amount_sats: u64,
    proxy_url: &str,
) -> Result<String, String> {
    let url = build_bolt12_proxy_url(offer, amount_sats, proxy_url);

    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| format!("BOLT12 proxy request failed: {:?}", e))?;

    let win = web_sys::window().ok_or("no window")?;
    let resp_value = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| format!("BOLT12 proxy fetch failed: {:?}", e))?;
    let response: Response = resp_value.dyn_into().map_err(|_| "Invalid response")?;

    if !response.ok() {
        return Err("BOLT12 proxy fetch failed".to_string());
    }

    let json_value = JsFuture::from(
        response
            .json()
            .map_err(|e| format!("JSON failed: {:?}", e))?,
    )
    .await
    .map_err(|e| format!("JSON parse failed: {:?}", e))?;

    let inv_data: serde_json::Value = serde_wasm_bindgen::from_value(json_value)
        .map_err(|e| format!("Deserialize failed: {:?}", e))?;

    inv_data["invoice"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No invoice in response".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_bolt12_proxy_url() {
        let offer = "lno1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let proxy = "https://proxy.example.com";
        let amount = 500; // sats

        let url = build_bolt12_proxy_url(offer, amount, proxy);
        assert_eq!(url, "https://proxy.example.com/invoice?offer=lno1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq&amount_msats=500000");
    }
}
