use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::BitcoinNetwork;

#[cfg(feature = "std")]
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BitcoinAnchor {
    pub network: BitcoinNetwork,
    pub txid: String,
    pub block_hash: Option<String>,
    pub block_height: Option<u64>,
    pub confirmations: u32,
    pub commitment: String,
    pub verified: bool,
}

pub fn anchor_commitment(checkpoint_hash: &str) -> Result<String, hex::FromHexError> {
    let mut h = Sha256::new();
    h.update(b"SatsPathCheckpointAnchorV1");
    h.update(hex::decode(checkpoint_hash)?);
    Ok(hex::encode(h.finalize()))
}

#[cfg(feature = "std")]
pub struct RegtestAnchorClient {
    rpc_url: String,
    rpc_user: String,
    rpc_password: String,
    client: reqwest::Client,
}

#[cfg(feature = "std")]
impl RegtestAnchorClient {
    pub fn from_env() -> crate::Result<Self> {
        let network = std::env::var("SATSPATH_BITCOIN_NETWORK").unwrap_or_default();
        if network != "regtest" {
            return Err(crate::SatsPathError::ValidationError(
                "Bitcoin checkpoint anchoring is disabled unless SATSPATH_BITCOIN_NETWORK=regtest"
                    .into(),
            ));
        }
        let required = |name: &str| {
            std::env::var(name)
                .map_err(|_| crate::SatsPathError::ValidationError(format!("missing {name}")))
        };
        Ok(Self {
            rpc_url: required("SATSPATH_BITCOIN_RPC_URL")?,
            rpc_user: required("SATSPATH_BITCOIN_RPC_USER")?,
            rpc_password: required("SATSPATH_BITCOIN_RPC_PASSWORD")?,
            client: reqwest::Client::new(),
        })
    }

    async fn rpc(&self, method: &str, params: Value) -> crate::Result<Value> {
        let response = self
            .client
            .post(&self.rpc_url)
            .basic_auth(&self.rpc_user, Some(&self.rpc_password))
            .json(
                &json!({"jsonrpc":"2.0","id":"satspath-anchor-v1","method":method,"params":params}),
            )
            .send()
            .await
            .map_err(|e| crate::SatsPathError::NetworkError(e.to_string()))?;
        let status = response.status();
        let value: Value = response
            .json()
            .await
            .map_err(|e| crate::SatsPathError::NetworkError(e.to_string()))?;
        if !status.is_success() || !value["error"].is_null() {
            return Err(crate::SatsPathError::NetworkError(format!(
                "Bitcoin RPC {method}: {}",
                value["error"]
            )));
        }
        Ok(value["result"].clone())
    }

    /// Create, fund, sign, broadcast and mine a regtest-only OP_RETURN commitment.
    pub async fn anchor_checkpoint(&self, checkpoint_hash: &str) -> crate::Result<BitcoinAnchor> {
        let commitment = anchor_commitment(checkpoint_hash)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        let raw = self
            .rpc("createrawtransaction", json!([[], [{"data": commitment}]] ))
            .await?;
        let funded = self.rpc("fundrawtransaction", json!([raw])).await?;
        let signed = self
            .rpc("signrawtransactionwithwallet", json!([funded["hex"]]))
            .await?;
        if signed["complete"] != true {
            return Err(crate::SatsPathError::NetworkError(
                "Bitcoin Core did not fully sign anchor transaction".into(),
            ));
        }
        let txid = self
            .rpc("sendrawtransaction", json!([signed["hex"]]))
            .await?
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing anchor txid".into()))?
            .to_owned();
        let address = self.rpc("getnewaddress", json!([])).await?;
        self.rpc("generatetoaddress", json!([1, address])).await?;
        self.verify_anchor(&txid, &commitment).await
    }

    pub async fn verify_anchor(
        &self,
        txid: &str,
        commitment: &str,
    ) -> crate::Result<BitcoinAnchor> {
        let tx = self.rpc("getrawtransaction", json!([txid, true])).await?;
        let expected_script = format!("6a20{commitment}");
        let matched = tx["vout"].as_array().is_some_and(|outputs| {
            outputs
                .iter()
                .any(|out| out["scriptPubKey"]["hex"].as_str() == Some(&expected_script))
        });
        let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid: txid.to_owned(),
            block_hash: tx["blockhash"].as_str().map(str::to_owned),
            block_height: None,
            confirmations,
            commitment: commitment.to_owned(),
            verified: matched && confirmations > 0,
        })
    }
}

#[derive(Default)]
pub struct MockAnchorClient;

impl MockAnchorClient {
    pub fn confirmed(checkpoint_hash: &str) -> crate::Result<BitcoinAnchor> {
        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid: "11".repeat(32),
            block_hash: Some("22".repeat(32)),
            block_height: Some(101),
            confirmations: 1,
            commitment: anchor_commitment(checkpoint_hash)
                .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?,
            verified: true,
        })
    }
}
