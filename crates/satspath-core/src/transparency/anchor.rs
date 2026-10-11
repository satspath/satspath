use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::catena::{catena_commitment, CONTINUATION_BTC, CONTINUATION_SATOSHIS, MAX_CATENA_HOPS};
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
fn parse_sats(val: &Value) -> Option<u64> {
    val.as_u64()
        .or_else(|| val.as_f64().map(|btc| (btc * 100_000_000.0).round() as u64))
}

#[cfg(feature = "std")]
fn find_continuation_vout_for_address(tx: &Value, addr: &str) -> Option<u32> {
    tx["vout"].as_array().and_then(|outputs| {
        outputs.iter().find_map(|out| {
            let matched_addr = out["scriptPubKey"]["address"].as_str() == Some(addr)
                || out["scriptPubKey"]["addresses"]
                    .as_array()
                    .is_some_and(|arr| arr.iter().any(|a| a.as_str() == Some(addr)));
            let sats = parse_sats(&out["value"]).unwrap_or(0);
            if matched_addr && sats == CONTINUATION_SATOSHIS {
                out["n"].as_u64().map(|n| n as u32)
            } else {
                None
            }
        })
    })
}

#[cfg(feature = "std")]
fn find_continuation_vout(tx: &Value) -> Option<u32> {
    tx["vout"].as_array().and_then(|outputs| {
        outputs.iter().find_map(|out| {
            let is_op_return = out["scriptPubKey"]["type"].as_str() == Some("nulldata")
                || out["scriptPubKey"]["hex"]
                    .as_str()
                    .map(|h| h.starts_with("6a"))
                    .unwrap_or(false);
            if is_op_return {
                return None;
            }
            let sats = parse_sats(&out["value"]).unwrap_or(0);
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
            {&continuation_addr: CONTINUATION_BTC}
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
        let signed_hex = signed["hex"]
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing signed hex".into()))?;

        // Pre-broadcast validation: verify continuation UTXO output exists before broadcasting
        let decoded = self
            .rpc("decoderawtransaction", json!([signed_hex]))
            .await?;
        let continuation_vout = find_continuation_vout_for_address(&decoded, &continuation_addr)
            .or_else(|| find_continuation_vout(&decoded))
            .ok_or_else(|| {
                crate::SatsPathError::NetworkError(
                    "could not locate 1000-sat continuation UTXO in decoded genesis tx".into(),
                )
            })?;

        let txid = self
            .rpc("sendrawtransaction", json!([signed_hex]))
            .await?
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing anchor txid".into()))?
            .to_owned();

        // Lock the continuation output so wallet coin selection cannot accidentally spend it
        let _ = self
            .rpc(
                "lockunspent",
                json!([false, [{"txid": &txid, "vout": continuation_vout}]]),
            )
            .await;

        let miner_address = self.rpc("getnewaddress", json!([])).await?;
        self.rpc("generatetoaddress", json!([1, miner_address]))
            .await?;

        let tx = self.rpc("getrawtransaction", json!([txid, true])).await?;
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
        // Unlock previous continuation UTXO so Bitcoin Core wallet can spend it
        let _ = self
            .rpc(
                "lockunspent",
                json!([true, [{"txid": &prev_anchor.txid, "vout": prev_continuation_vout}]]),
            )
            .await;

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
            {&continuation_addr: CONTINUATION_BTC}
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
        let signed_hex = signed["hex"]
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing signed hex".into()))?;

        // Pre-broadcast validation: verify vin[0] and continuation output before broadcast
        let decoded = self
            .rpc("decoderawtransaction", json!([signed_hex]))
            .await?;
        let inputs_spent = decoded["vin"]
            .as_array()
            .and_then(|vins| vins.first())
            .map(|vin| {
                vin["txid"].as_str() == Some(&prev_anchor.txid)
                    && vin["vout"].as_u64() == Some(prev_continuation_vout as u64)
            })
            .unwrap_or(false);

        if !inputs_spent {
            return Err(crate::SatsPathError::ValidationError(
                "Chained anchor transaction vin[0] does not spend the required predecessor continuation UTXO".into(),
            ));
        }

        let next_continuation_vout =
            find_continuation_vout_for_address(&decoded, &continuation_addr)
                .or_else(|| find_continuation_vout(&decoded))
                .ok_or_else(|| {
                    crate::SatsPathError::NetworkError(
                        "could not locate 1000-sat continuation UTXO in decoded chained tx".into(),
                    )
                })?;

        let txid = self
            .rpc("sendrawtransaction", json!([signed_hex]))
            .await?
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing anchor txid".into()))?
            .to_owned();

        // Lock newly created continuation output to protect it from wallet coin selection
        let _ = self
            .rpc(
                "lockunspent",
                json!([false, [{"txid": &txid, "vout": next_continuation_vout}]]),
            )
            .await;

        let miner_address = self.rpc("getnewaddress", json!([])).await?;
        self.rpc("generatetoaddress", json!([1, miner_address]))
            .await?;

        let tx = self.rpc("getrawtransaction", json!([txid, true])).await?;
        let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
        let block_hash = tx["blockhash"].as_str().map(str::to_owned);

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
        let mut successor_continuation_vout: Option<u32> = None;

        loop {
            if chain.len() >= MAX_CATENA_HOPS {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "Catena chain traversal exceeded maximum allowed hops ({MAX_CATENA_HOPS})"
                )));
            }

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
                        let stripped = hex.strip_prefix("6a20")?;
                        (stripped.len() == 64).then(|| stripped.to_string())
                    })
                })
                .ok_or_else(|| {
                    crate::SatsPathError::ValidationError(format!(
                        "missing valid Catena OP_RETURN commitment (6a20 + 32-byte hash) in tx {curr_txid}"
                    ))
                })?;

            let continuation_vout =
                successor_continuation_vout.or_else(|| find_continuation_vout(&tx));
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

            // In Catena, vin[0] MUST spend the predecessor's continuation UTXO
            let vins = tx["vin"].as_array().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!("missing vin in tx {curr_txid}"))
            })?;
            let vin_0 = vins.first().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!("empty vin in tx {curr_txid}"))
            })?;
            let vin_txid = vin_0["txid"].as_str().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!(
                    "missing txid in vin[0] of tx {curr_txid}"
                ))
            })?;
            let vin_vout = vin_0["vout"].as_u64().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!(
                    "missing vout in vin[0] of tx {curr_txid}"
                ))
            })? as u32;

            let parent_tx = self
                .rpc("getrawtransaction", json!([vin_txid, true]))
                .await?;

            // Verify parent transaction contains a valid Catena OP_RETURN output (6a20 + 32-byte hash)
            let parent_has_op_return = parent_tx["vout"].as_array().is_some_and(|outputs| {
                outputs.iter().any(|out| {
                    out["scriptPubKey"]["hex"]
                        .as_str()
                        .map(|h| h.starts_with("6a20") && h.len() == 68)
                        .unwrap_or(false)
                })
            });
            if !parent_has_op_return {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "Parent tx {vin_txid} does not contain a valid Catena OP_RETURN output (6a20 + 32-byte hash)"
                )));
            }

            // Verify parent output vin_0.vout is the 1000-sat continuation UTXO
            let parent_vouts = parent_tx["vout"].as_array().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!(
                    "missing vout in parent tx {vin_txid}"
                ))
            })?;
            let parent_out = parent_vouts.get(vin_vout as usize).ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!(
                    "vout {vin_vout} out of bounds in parent tx {vin_txid}"
                ))
            })?;
            let sats = parse_sats(&parent_out["value"]).unwrap_or(0);
            if sats != CONTINUATION_SATOSHIS {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "Tx {curr_txid} vin[0] spent output {vin_txid}:{vin_vout} with {sats} sats, expected continuation UTXO of {CONTINUATION_SATOSHIS} sats"
                )));
            }

            let prev_txid = vin_txid.to_string();
            let prev_vout = vin_vout;

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
            successor_continuation_vout = Some(prev_vout);
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
        let txid = format!("{:064x}", chain_index + 0x10);
        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid,
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
