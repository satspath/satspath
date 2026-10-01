use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::errors::{Result, SwapError};

// ─── RPC Types ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RpcRequest<T> {
    id: u64,
    method: String,
    params: T,
}

#[derive(Deserialize, Debug)]
struct RpcResponse<T> {
    #[serde(rename = "id")]
    _id: serde_json::Value,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize, Debug)]
struct RpcError {
    code: i64,
    message: String,
}

// ─── Request / Response Structs ───────────────────────────────────────────────

#[derive(Serialize)]
pub struct InitKeyParams {
    pub password: String,
}

#[derive(Serialize)]
pub struct VerifyVtxoParams {
    pub txid: String,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confirmations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arkd_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btc_rpc_url: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct VerifyVtxoResult {
    pub valid: bool,
    pub commitment_txid: String,
    pub vtxo_root_txid: String,
    pub diagnostics: Vec<String>,
}

#[derive(Serialize)]
pub struct OnReceiveVtxoParams {
    pub txid: String,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arkd_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btc_rpc_url: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct OnReceiveVtxoResult {
    pub success: bool,
    pub diagnostics: Vec<String>,
    pub error: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct GetReceivePubkeyResult {
    pub pubkey: String,
    pub server: Option<String>,
}

#[derive(Serialize)]
pub struct SignArkChallengeParams {
    pub alias: String,
    pub server: String,
    pub receiver_pubkey: String,
    pub nonce: String,
}

#[derive(Deserialize, Debug)]
pub struct SignArkChallengeResult {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
    pub expires_at: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateReceiveVtxoParams {
    pub amount_sats: u64,
    pub receiver_pubkey: String,
    pub server: String,
}

#[derive(Deserialize, Debug)]
pub struct CreateReceiveVtxoResult {
    pub request_id: String,
    pub receiver_pubkey: String,
    pub server: String,
    pub expires_at: i64,
}

#[derive(Serialize)]
pub struct SendVtxoParams {
    pub amount_sats: u64,
    pub receiver_pubkey: String,
    pub server: String,
    pub vtxo_pointer: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct SendVtxoResult {
    pub intent_id: String,
    pub txid: Option<String>,
    pub status: String,
}

#[derive(Serialize)]
pub struct ListVtxosParams {
    pub server: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ListVtxosResult {
    pub vtxos: Vec<serde_json::Value>,
}

#[derive(Serialize)]
pub struct EstimateArkFeeParams {
    pub route_kind: String,
    pub amount_sats: u64,
    pub server: String,
}

#[derive(Deserialize, Debug)]
pub struct EstimateArkFeeResult {
    pub fee_sats: u64,
    pub diagnostics: Vec<String>,
}

// ─── Bridge Client ────────────────────────────────────────────────────────────

/// A JSON-RPC client that spawns and communicates with the Node.js ark-bridge.
pub struct ArkBridge {
    process: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    next_id: AtomicU64,
}

impl ArkBridge {
    /// Spawns the Node.js bridge process.
    /// Expects `node` to be available in PATH and the `ark-bridge` directory
    /// to be properly configured (e.g., `npm run start`).
    pub fn spawn(bridge_dir: PathBuf) -> Result<Self> {
        let mut child = Command::new("npm")
            .arg("run")
            .arg("start")
            .current_dir(bridge_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // Let stderr pass through for logs
            .spawn()
            .map_err(|e| SwapError::Key(format!("Failed to spawn ARK bridge: {}", e)))?;

        let stdin = child.stdin.take().expect("Failed to open stdin");
        let stdout = BufReader::new(child.stdout.take().expect("Failed to open stdout"));

        let bridge = Self {
            process: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(stdout),
            next_id: AtomicU64::new(1),
        };

        Ok(bridge)
    }

    /// Perform a synchronous JSON-RPC call over stdin/stdout.
    fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req = RpcRequest {
            id,
            method: method.to_string(),
            params,
        };

        let req_json = serde_json::to_string(&req).map_err(SwapError::Json)?;

        // Send request
        {
            let mut stdin = self.stdin.lock().unwrap();
            writeln!(stdin, "{}", req_json).map_err(SwapError::Io)?;
            stdin.flush().map_err(SwapError::Io)?;
        }

        // Read response
        let mut line = String::new();
        {
            let mut stdout = self.stdout.lock().unwrap();
            stdout.read_line(&mut line).map_err(SwapError::Io)?;
        }

        let resp: RpcResponse<R> = serde_json::from_str(&line).map_err(SwapError::Json)?;

        if let Some(err) = resp.error {
            return Err(map_ark_bridge_error(err));
        }

        resp.result
            .ok_or_else(|| SwapError::Key("ARK bridge returned neither result nor error".into()))
    }

    // ─── API Wrapper ──────────────────────────────────────────────────────────

    pub fn ping(&self) -> Result<()> {
        let _res: serde_json::Value = self.call("ping", serde_json::json!({}))?;
        Ok(())
    }

    pub fn init_key(&self, password: &str) -> Result<()> {
        let params = InitKeyParams {
            password: password.to_string(),
        };
        let _res: serde_json::Value = self.call("initKey", params)?;
        Ok(())
    }

    pub fn verify_vtxo(&self, params: VerifyVtxoParams) -> Result<VerifyVtxoResult> {
        self.call("verifyVtxo", params)
    }

    pub fn on_receive_vtxo(&self, params: OnReceiveVtxoParams) -> Result<OnReceiveVtxoResult> {
        self.call("onReceiveVtxo", params)
    }

    pub fn get_receive_pubkey(&self) -> Result<GetReceivePubkeyResult> {
        self.call("getReceivePubkey", serde_json::json!({}))
    }

    pub fn sign_ownership_challenge(
        &self,
        params: SignArkChallengeParams,
    ) -> Result<SignArkChallengeResult> {
        self.call("signOwnershipChallenge", params)
    }

    pub fn create_receive_vtxo_request(
        &self,
        params: CreateReceiveVtxoParams,
    ) -> Result<CreateReceiveVtxoResult> {
        self.call("createReceiveVtxoRequest", params)
    }

    pub fn send_vtxo(&self, params: SendVtxoParams) -> Result<SendVtxoResult> {
        self.call("sendVtxo", params)
    }

    pub fn list_vtxos(&self, params: ListVtxosParams) -> Result<ListVtxosResult> {
        self.call("listVtxos", params)
    }

    pub fn estimate_ark_fee(&self, params: EstimateArkFeeParams) -> Result<EstimateArkFeeResult> {
        self.call("estimateArkFee", params)
    }
}

fn map_ark_bridge_error(err: RpcError) -> SwapError {
    if err.code == -32601 || err.message.to_ascii_lowercase().contains("not implemented") {
        SwapError::Key("Ark method not implemented by bridge".into())
    } else {
        SwapError::Key(format!("ARK bridge error ({}): {}", err.code, err.message))
    }
}

impl Drop for ArkBridge {
    fn drop(&mut self) {
        if let Ok(mut process) = self.process.lock() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}
