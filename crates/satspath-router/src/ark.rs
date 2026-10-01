use satspath_core::PaymentMethod;

/// Adapter trait for an Ark server client.
pub trait ArkClient {
    fn is_available(&self) -> bool;
    fn create_payment_intent(&self, amount_sats: u64, pubkey: &str) -> anyhow::Result<String>;
}

use serde::Serialize;

#[derive(Serialize)]
pub struct SimulatedArkIntent {
    pub intent_id: String,
    pub pubkey: String,
    pub amount_sats: u64,
    pub status: String,
    pub server_url: String,
}

/// Mock Ark client used in the prototype.
pub struct MockArkClient {
    pub available: bool,
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

/// Find the first Ark method.
pub fn first_ark_method(methods: &[PaymentMethod]) -> Option<&PaymentMethod> {
    methods
        .iter()
        .find(|m| matches!(m, PaymentMethod::Ark { .. }))
}
