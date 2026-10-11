use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::catena::{catena_commitment, CONTINUATION_BTC, CONTINUATION_SATOSHIS};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_txid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_vout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_vout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_index: Option<u64>,
}

pub fn anchor_commitment(checkpoint_hash: &str) -> Result<String, hex::FromHexError> {
    let mut h = Sha256::new();
    h.update(b"SatsPathCheckpointAnchorV1");
    h.update(hex::decode(checkpoint_hash)?);
    Ok(hex::encode(h.finalize()))
}

#[cfg(feature = "std")]
fn find_continuation_vout(tx: &Value) -> Option<u32> {
    tx["vout"].as_array().and_then(|outputs| {
        outputs.iter().find_map(|out| {
            let sats = (out["value"].as_f64().unwrap_or(0.0) * 100_000_000.0).round() as u64;
            if sats == CONTINUATION_SATOSHIS {
                out["n"].as_u64().map(|n| n as u32)
            } else {
                None
            }
        })
    })
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

    /// Create, fund, sign, broadcast and mine a legacy standalone OP_RETURN commitment.
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

    /// Create, fund, sign, broadcast and mine a Catena Genesis anchor transaction.
    ///
    /// Outputs:
    /// - Output 0: OP_RETURN with Catena commitment at index 0.
    /// - Output 1: Continuation UTXO of 1,000 satoshis locked to a new address.
    pub async fn anchor_catena_genesis(
        &self,
        checkpoint_hash: &str,
    ) -> crate::Result<BitcoinAnchor> {
        let commitment = catena_commitment(checkpoint_hash, 0)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        let continuation_addr = self
            .rpc("getnewaddress", json!([]))
            .await?
            .as_str()
            .ok_or_else(|| {
                crate::SatsPathError::NetworkError("missing continuation address".into())
            })?
            .to_owned();

        let outputs = json!([
            {"data": commitment},
            {continuation_addr: CONTINUATION_BTC}
        ]);
        let raw = self
            .rpc("createrawtransaction", json!([[], outputs]))
            .await?;
        let funded = self.rpc("fundrawtransaction", json!([raw])).await?;
        let signed = self
            .rpc("signrawtransactionwithwallet", json!([funded["hex"]]))
            .await?;
        if signed["complete"] != true {
            return Err(crate::SatsPathError::NetworkError(
                "Bitcoin Core did not fully sign genesis anchor transaction".into(),
            ));
        }
        let txid = self
            .rpc("sendrawtransaction", json!([signed["hex"]]))
            .await?
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing anchor txid".into()))?
            .to_owned();

        let miner_address = self.rpc("getnewaddress", json!([])).await?;
        self.rpc("generatetoaddress", json!([1, miner_address]))
            .await?;

        let tx = self.rpc("getrawtransaction", json!([txid, true])).await?;
        let continuation_vout = find_continuation_vout(&tx).ok_or_else(|| {
            crate::SatsPathError::NetworkError(
                "could not locate 1000-sat continuation UTXO in genesis tx".into(),
            )
        })?;
        let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
        let block_hash = tx["blockhash"].as_str().map(str::to_owned);

        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid,
            block_hash,
            block_height: None,
            confirmations,
            commitment,
            verified: confirmations > 0,
            prev_txid: None,
            prev_vout: None,
            continuation_vout: Some(continuation_vout),
            chain_index: Some(0),
        })
    }

    /// Create, fund, sign, broadcast and mine the next Catena anchor transaction in sequence.
    ///
    /// Spends the previous continuation UTXO `(prev_anchor.txid, prev_anchor.continuation_vout)`.
    /// Creates a new continuation UTXO of 1,000 satoshis and an OP_RETURN with the next commitment.
    pub async fn anchor_catena_next(
        &self,
        checkpoint_hash: &str,
        prev_anchor: &BitcoinAnchor,
    ) -> crate::Result<BitcoinAnchor> {
        let prev_continuation_vout = prev_anchor.continuation_vout.ok_or_else(|| {
            crate::SatsPathError::ValidationError(
                "previous anchor is missing continuation_vout for chaining".into(),
            )
        })?;
        let next_index = prev_anchor.chain_index.unwrap_or(0) + 1;
        let commitment = catena_commitment(checkpoint_hash, next_index)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;

        let continuation_addr = self
            .rpc("getnewaddress", json!([]))
            .await?
            .as_str()
            .ok_or_else(|| {
                crate::SatsPathError::NetworkError("missing continuation address".into())
            })?
            .to_owned();

        let inputs = json!([
            {"txid": prev_anchor.txid, "vout": prev_continuation_vout}
        ]);
        let outputs = json!([
            {"data": commitment},
            {continuation_addr: CONTINUATION_BTC}
        ]);
        let raw = self
            .rpc("createrawtransaction", json!([inputs, outputs]))
            .await?;
        let funded = self.rpc("fundrawtransaction", json!([raw])).await?;
        let signed = self
            .rpc("signrawtransactionwithwallet", json!([funded["hex"]]))
            .await?;
        if signed["complete"] != true {
            return Err(crate::SatsPathError::NetworkError(
                "Bitcoin Core did not fully sign chained anchor transaction".into(),
            ));
        }
        let txid = self
            .rpc("sendrawtransaction", json!([signed["hex"]]))
            .await?
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing anchor txid".into()))?
            .to_owned();

        let miner_address = self.rpc("getnewaddress", json!([])).await?;
        self.rpc("generatetoaddress", json!([1, miner_address]))
            .await?;

        let tx = self.rpc("getrawtransaction", json!([txid, true])).await?;
        let next_continuation_vout = find_continuation_vout(&tx).ok_or_else(|| {
            crate::SatsPathError::NetworkError(
                "could not locate 1000-sat continuation UTXO in chained tx".into(),
            )
        })?;
        let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
        let block_hash = tx["blockhash"].as_str().map(str::to_owned);

        // Verify that one of the vin inputs spent prev_anchor.txid:prev_continuation_vout
        let inputs_spent = tx["vin"]
            .as_array()
            .map(|vins| {
                vins.iter().any(|vin| {
                    vin["txid"].as_str() == Some(&prev_anchor.txid)
                        && vin["vout"].as_u64() == Some(prev_continuation_vout as u64)
                })
            })
            .unwrap_or(false);

        if !inputs_spent {
            return Err(crate::SatsPathError::ValidationError(
                "Chained anchor transaction did not spend the required predecessor continuation UTXO".into(),
            ));
        }

        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid,
            block_hash,
            block_height: None,
            confirmations,
            commitment,
            verified: confirmations > 0 && inputs_spent,
            prev_txid: Some(prev_anchor.txid.clone()),
            prev_vout: Some(prev_continuation_vout),
            continuation_vout: Some(next_continuation_vout),
            chain_index: Some(next_index),
        })
    }

    /// Trace backwards through Bitcoin transactions from `latest_txid` to `genesis_txid`,
    /// verifying that each anchor spent the previous continuation UTXO.
    pub async fn verify_catena_chain(
        &self,
        latest_txid: &str,
        genesis_txid: &str,
    ) -> crate::Result<Vec<BitcoinAnchor>> {
        let mut chain = Vec::new();
        let mut curr_txid = latest_txid.to_string();

        loop {
            let tx = self
                .rpc("getrawtransaction", json!([curr_txid, true]))
                .await?;
            let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
            if confirmations == 0 {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "Catena anchor tx {curr_txid} is unconfirmed"
                )));
            }

            let commitment = tx["vout"]
                .as_array()
                .and_then(|vouts| {
                    vouts.iter().find_map(|vout| {
                        let hex = vout["scriptPubKey"]["hex"].as_str()?;
                        if let Some(stripped) = hex.strip_prefix("6a20") {
                            Some(stripped.to_string())
                        } else {
                            hex.strip_prefix("6a").map(|stripped| stripped.to_string())
                        }
                    })
                })
                .ok_or_else(|| {
                    crate::SatsPathError::ValidationError(format!(
                        "missing OP_RETURN in tx {curr_txid}"
                    ))
                })?;

            let continuation_vout = find_continuation_vout(&tx);
            let block_hash = tx["blockhash"].as_str().map(str::to_owned);

            if curr_txid == genesis_txid {
                chain.push(BitcoinAnchor {
                    network: BitcoinNetwork::Regtest,
                    txid: curr_txid,
                    block_hash,
                    block_height: None,
                    confirmations,
                    commitment,
                    verified: true,
                    prev_txid: None,
                    prev_vout: None,
                    continuation_vout,
                    chain_index: Some(0),
                });
                break;
            }

            // Find which input spent the predecessor's 1000-sat continuation output
            let mut found_prev: Option<(String, u32)> = None;
            if let Some(vins) = tx["vin"].as_array() {
                for vin in vins {
                    if let (Some(vin_txid), Some(vin_vout)) =
                        (vin["txid"].as_str(), vin["vout"].as_u64())
                    {
                        let parent_tx = self
                            .rpc("getrawtransaction", json!([vin_txid, true]))
                            .await?;
                        if let Some(parent_vouts) = parent_tx["vout"].as_array() {
                            if let Some(parent_out) = parent_vouts.get(vin_vout as usize) {
                                let sats = (parent_out["value"].as_f64().unwrap_or(0.0)
                                    * 100_000_000.0)
                                    .round() as u64;
                                if sats == CONTINUATION_SATOSHIS {
                                    found_prev = Some((vin_txid.to_string(), vin_vout as u32));
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            let (prev_txid, prev_vout) = found_prev.ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!(
                    "Tx {curr_txid} does not spend a continuation UTXO"
                ))
            })?;

            chain.push(BitcoinAnchor {
                network: BitcoinNetwork::Regtest,
                txid: curr_txid.clone(),
                block_hash,
                block_height: None,
                confirmations,
                commitment,
                verified: true,
                prev_txid: Some(prev_txid.clone()),
                prev_vout: Some(prev_vout),
                continuation_vout,
                chain_index: None,
            });

            curr_txid = prev_txid;
        }

        chain.reverse();
        for (idx, anchor) in chain.iter_mut().enumerate() {
            anchor.chain_index = Some(idx as u64);
        }

        Ok(chain)
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
            prev_txid: None,
            prev_vout: None,
            continuation_vout: None,
            chain_index: None,
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
            prev_txid: None,
            prev_vout: None,
            continuation_vout: None,
            chain_index: None,
        })
    }

    pub fn catena_genesis(checkpoint_hash: &str) -> crate::Result<BitcoinAnchor> {
        let commitment = catena_commitment(checkpoint_hash, 0)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid: "10".repeat(32),
            block_hash: Some("20".repeat(32)),
            block_height: Some(101),
            confirmations: 1,
            commitment,
            verified: true,
            prev_txid: None,
            prev_vout: None,
            continuation_vout: Some(1),
            chain_index: Some(0),
        })
    }

    pub fn catena_next(
        checkpoint_hash: &str,
        prev: &BitcoinAnchor,
    ) -> crate::Result<BitcoinAnchor> {
        let chain_index = prev.chain_index.unwrap_or(0) + 1;
        let commitment = catena_commitment(checkpoint_hash, chain_index)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        let hex_byte = format!("{:02x}", (chain_index as u8) + 0x10);
        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid: hex_byte.repeat(32),
            block_hash: Some("20".repeat(32)),
            block_height: Some(101 + chain_index),
            confirmations: 1,
            commitment,
            verified: true,
            prev_txid: Some(prev.txid.clone()),
            prev_vout: prev.continuation_vout,
            continuation_vout: Some(1),
            chain_index: Some(chain_index),
        })
    }
}
