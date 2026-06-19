// src/cosmos/rpc.rs
//
// Cosmos LCD (REST) request shaping + response parsing. Pure: no I/O — the wasm
// service layer owns the LCD base URL + secret injection and issues the actual
// GET/POST. Builders return a [`CosmosRestRequest`] descriptor; parsers consume
// the raw JSON response (`RpcResponse` = `serde_json::Value`) and tolerate
// hostile/garbage input (Err, never panic). A chain-level rejection (a sim
// failure, a nonzero broadcast `code`, a not-yet-indexed tx) is a *value*, not a
// transport error — mirrors the EVM adapter's parse philosophy.
use crate::types::{AdapterError, RpcResponse, Simulation};
use base64::Engine;
use serde_json::json;

// ---------------------------------------------------------------------------
// Request descriptor
// ---------------------------------------------------------------------------

/// A shaped Cosmos LCD REST request. The service layer prepends the LCD base URL
/// to `path` and issues `method` with `body` (JSON) when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosmosRestRequest {
    pub method: &'static str, // "GET" | "POST"
    pub path: String,
    pub body: Option<serde_json::Value>, // Some(..) for POST, None for GET
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Parse a decimal string as `u64`. LCD encodes account_number/sequence/gas/height
/// as decimal strings (`"12345"`); be defensive about non-string/garbage input.
fn parse_dec_u64(v: &serde_json::Value, field: &str) -> Result<u64, AdapterError> {
    let s = v
        .as_str()
        .ok_or_else(|| AdapterError::Rpc(format!("missing or non-string {field}")))?;
    s.parse::<u64>()
        .map_err(|e| AdapterError::Rpc(format!("{field} parse error: {e}")))
}

/// Returns an LCD error-envelope message if present. LCD error bodies look like
/// `{"code":N,"message":"...","details":[...]}`; some gateways use `{"error":"..."}`.
fn lcd_error(resp: &RpcResponse) -> Option<String> {
    if let Some(msg) = resp["message"].as_str() {
        if resp["code"].is_number() {
            return Some(msg.to_owned());
        }
    }
    resp["error"].as_str().map(|s| s.to_owned())
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

/// GET `/cosmos/auth/v1beta1/accounts/{address}` — fetch account_number + sequence.
pub fn account_request(address: &str) -> CosmosRestRequest {
    CosmosRestRequest {
        method: "GET",
        path: format!("/cosmos/auth/v1beta1/accounts/{address}"),
        body: None,
    }
}

/// POST `/cosmos/tx/v1beta1/simulate` — estimate gas for a (signed) tx.
pub fn simulate_request(tx_bytes: &[u8]) -> CosmosRestRequest {
    CosmosRestRequest {
        method: "POST",
        path: "/cosmos/tx/v1beta1/simulate".to_owned(),
        body: Some(json!({ "tx_bytes": b64(tx_bytes) })),
    }
}

/// POST `/cosmos/tx/v1beta1/txs` (BROADCAST_MODE_SYNC) — broadcast a signed tx.
pub fn broadcast_request(tx_bytes: &[u8]) -> CosmosRestRequest {
    CosmosRestRequest {
        method: "POST",
        path: "/cosmos/tx/v1beta1/txs".to_owned(),
        body: Some(json!({
            "tx_bytes": b64(tx_bytes),
            "mode": "BROADCAST_MODE_SYNC",
        })),
    }
}

/// GET `/cosmos/tx/v1beta1/txs/{hash}` — poll a broadcast tx by hash.
pub fn tx_status_request(hash: &str) -> CosmosRestRequest {
    CosmosRestRequest {
        method: "GET",
        path: format!("/cosmos/tx/v1beta1/txs/{hash}"),
        body: None,
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosmosAccount {
    pub account_number: u64,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastResult {
    pub txhash: String,
    pub code: u32,
    pub raw_log: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxStatus {
    pub success: bool,
    pub height: u64,
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

/// Parse `/cosmos/auth/v1beta1/accounts/{addr}`. Numbers are decimal strings under
/// `account` (BaseAccount). Module/vesting accounts nest the fields under
/// `account.base_account`; try that before erroring. Missing/garbage → Err.
pub fn parse_account(resp: &RpcResponse) -> Result<CosmosAccount, AdapterError> {
    if let Some(msg) = lcd_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    let account = &resp["account"];
    if account.is_null() {
        return Err(AdapterError::Rpc("missing account".into()));
    }
    // BaseAccount: fields directly under `account`. Otherwise vesting/module
    // accounts wrap a BaseAccount under `account.base_account`.
    let src = if account.get("account_number").is_some() {
        account
    } else {
        let nested = &account["base_account"];
        if nested.is_null() {
            return Err(AdapterError::Rpc("missing account_number".into()));
        }
        nested
    };
    let account_number = parse_dec_u64(&src["account_number"], "account_number")?;
    let sequence = parse_dec_u64(&src["sequence"], "sequence")?;
    Ok(CosmosAccount { account_number, sequence })
}

/// Parse `/cosmos/tx/v1beta1/simulate`. Gas is at `gas_info.gas_used` (decimal
/// string). A sim failure (LCD error envelope) is a `Simulation{success:false}`
/// value, not an Err — only truly unparseable JSON is Err.
pub fn parse_simulate(resp: &RpcResponse) -> Result<Simulation, AdapterError> {
    if let Some(gas_v) = resp["gas_info"].get("gas_used") {
        let gas = parse_dec_u64(gas_v, "gas_used")?;
        return Ok(Simulation { success: true, gas_used: Some(gas), error: None });
    }
    if let Some(msg) = lcd_error(resp) {
        return Ok(Simulation { success: false, gas_used: None, error: Some(msg) });
    }
    Err(AdapterError::Rpc("missing gas_info or error".into()))
}

/// Parse `/cosmos/tx/v1beta1/txs` broadcast response. Data under `tx_response`:
/// `txhash`, `code` (0 = accepted), `raw_log`. A nonzero `code` is a real chain
/// rejection returned to the caller (not an Err). Missing tx_response/txhash → Err.
pub fn parse_broadcast(resp: &RpcResponse) -> Result<BroadcastResult, AdapterError> {
    if let Some(msg) = lcd_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    let tx_response = &resp["tx_response"];
    if tx_response.is_null() {
        return Err(AdapterError::Rpc("missing tx_response".into()));
    }
    let txhash = tx_response["txhash"]
        .as_str()
        .ok_or_else(|| AdapterError::Rpc("missing tx_response.txhash".into()))?
        .to_owned();
    // `code` is absent on success in some LCD versions → treat as 0 (accepted).
    let code = match tx_response.get("code") {
        Some(serde_json::Value::Null) | None => 0u64,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| AdapterError::Rpc("tx_response.code is not a number".into()))?,
    };
    let raw_log = tx_response["raw_log"].as_str().unwrap_or("").to_owned();
    Ok(BroadcastResult { txhash, code: code as u32, raw_log })
}

/// Parse `/cosmos/tx/v1beta1/txs/{hash}`. Not-yet-indexed (LCD error envelope,
/// often code 5 / "not found", or a null/absent tx_response) → `Ok(None)`. A
/// present tx_response → `Ok(Some)` with `success = code==0` and `height`
/// (decimal string). Unparseable height when tx_response present → Err.
pub fn parse_tx_status(resp: &RpcResponse) -> Result<Option<TxStatus>, AdapterError> {
    // Not yet indexed: LCD returns an error envelope (e.g. code 5 "tx not found").
    if lcd_error(resp).is_some() {
        return Ok(None);
    }
    let tx_response = &resp["tx_response"];
    if tx_response.is_null() {
        return Ok(None);
    }
    let code = match tx_response.get("code") {
        Some(serde_json::Value::Null) | None => 0u64,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| AdapterError::Rpc("tx_response.code is not a number".into()))?,
    };
    let height = parse_dec_u64(&tx_response["height"], "height")?;
    Ok(Some(TxStatus { success: code == 0, height }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- request builders ---

    #[test]
    fn account_request_shape() {
        let req = account_request("cosmos1abc");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/cosmos/auth/v1beta1/accounts/cosmos1abc");
        assert!(req.body.is_none());
    }

    #[test]
    fn simulate_request_base64_encodes() {
        let req = simulate_request(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/cosmos/tx/v1beta1/simulate");
        let body = req.body.expect("body");
        assert_eq!(body["tx_bytes"], json!("3q2+7w==")); // STANDARD base64 of deadbeef
    }

    #[test]
    fn broadcast_request_sets_sync_mode_and_base64() {
        let req = broadcast_request(&[0x01, 0x02, 0x03]);
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/cosmos/tx/v1beta1/txs");
        let body = req.body.expect("body");
        assert_eq!(body["mode"], json!("BROADCAST_MODE_SYNC"));
        assert_eq!(body["tx_bytes"], json!("AQID")); // STANDARD base64 of 010203
    }

    #[test]
    fn tx_status_request_shape() {
        let req = tx_status_request("ABCDEF");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/cosmos/tx/v1beta1/txs/ABCDEF");
        assert!(req.body.is_none());
    }

    // --- parse_account ---

    #[test]
    fn parse_account_base_account() {
        let resp = json!({
            "account": {
                "@type": "/cosmos.auth.v1beta1.BaseAccount",
                "address": "cosmos1abc",
                "account_number": "12345",
                "sequence": "7"
            }
        });
        let acc = parse_account(&resp).expect("ok");
        assert_eq!(acc.account_number, 12345);
        assert_eq!(acc.sequence, 7);
    }

    #[test]
    fn parse_account_nested_base_account() {
        // Vesting/module account wraps a BaseAccount under base_account.
        let resp = json!({
            "account": {
                "@type": "/cosmos.vesting.v1beta1.PeriodicVestingAccount",
                "base_vesting_account": {},
                "base_account": {
                    "address": "cosmos1abc",
                    "account_number": "99",
                    "sequence": "3"
                }
            }
        });
        let acc = parse_account(&resp).expect("ok");
        assert_eq!(acc.account_number, 99);
        assert_eq!(acc.sequence, 3);
    }

    #[test]
    fn parse_account_missing_account_errs() {
        assert!(parse_account(&json!({})).is_err());
    }

    #[test]
    fn parse_account_garbage_number_errs() {
        let resp = json!({"account": {"account_number": "not-a-number", "sequence": "0"}});
        assert!(parse_account(&resp).is_err());
    }

    #[test]
    fn parse_account_number_not_string_errs() {
        // Numbers must be JSON strings; a bare integer is rejected defensively.
        let resp = json!({"account": {"account_number": 12345, "sequence": "0"}});
        assert!(parse_account(&resp).is_err());
    }

    #[test]
    fn parse_account_missing_sequence_errs() {
        let resp = json!({"account": {"account_number": "1"}});
        assert!(parse_account(&resp).is_err());
    }

    #[test]
    fn parse_account_lcd_error_envelope_errs() {
        let resp = json!({"code": 5, "message": "account cosmos1xyz not found"});
        assert!(parse_account(&resp).is_err());
    }

    // --- parse_simulate ---

    #[test]
    fn parse_simulate_success() {
        let resp = json!({
            "gas_info": { "gas_wanted": "0", "gas_used": "84512" },
            "result": {}
        });
        let sim = parse_simulate(&resp).expect("ok");
        assert!(sim.success);
        assert_eq!(sim.gas_used, Some(84512));
        assert!(sim.error.is_none());
    }

    #[test]
    fn parse_simulate_error_envelope_is_value_not_err() {
        let resp = json!({"code": 11, "message": "out of gas", "details": []});
        let sim = parse_simulate(&resp).expect("envelope is a value");
        assert!(!sim.success);
        assert_eq!(sim.error.as_deref(), Some("out of gas"));
        assert!(sim.gas_used.is_none());
    }

    #[test]
    fn parse_simulate_empty_errs() {
        assert!(parse_simulate(&json!({})).is_err());
    }

    #[test]
    fn parse_simulate_garbage_gas_errs() {
        let resp = json!({"gas_info": {"gas_used": "xyz"}});
        assert!(parse_simulate(&resp).is_err());
    }

    // --- parse_broadcast ---

    #[test]
    fn parse_broadcast_accepted() {
        let resp = json!({
            "tx_response": {
                "txhash": "ABC123DEADBEEF",
                "code": 0,
                "raw_log": "",
                "height": "0"
            }
        });
        let r = parse_broadcast(&resp).expect("ok");
        assert_eq!(r.txhash, "ABC123DEADBEEF");
        assert_eq!(r.code, 0);
    }

    #[test]
    fn parse_broadcast_nonzero_code_returned_not_err() {
        let resp = json!({
            "tx_response": {
                "txhash": "FEEDFACE",
                "code": 5,
                "raw_log": "insufficient funds"
            }
        });
        let r = parse_broadcast(&resp).expect("nonzero code is a value");
        assert_eq!(r.code, 5);
        assert_eq!(r.raw_log, "insufficient funds");
        assert_eq!(r.txhash, "FEEDFACE");
    }

    #[test]
    fn parse_broadcast_missing_tx_response_errs() {
        assert!(parse_broadcast(&json!({})).is_err());
    }

    #[test]
    fn parse_broadcast_missing_txhash_errs() {
        let resp = json!({"tx_response": {"code": 0}});
        assert!(parse_broadcast(&resp).is_err());
    }

    #[test]
    fn parse_broadcast_lcd_error_envelope_errs() {
        let resp = json!({"code": 3, "message": "decoding bech32 failed"});
        assert!(parse_broadcast(&resp).is_err());
    }

    // --- parse_tx_status ---

    #[test]
    fn parse_tx_status_success() {
        let resp = json!({
            "tx_response": {
                "txhash": "ABC",
                "code": 0,
                "height": "1048576"
            }
        });
        let st = parse_tx_status(&resp).expect("ok").expect("some");
        assert!(st.success);
        assert_eq!(st.height, 1048576);
    }

    #[test]
    fn parse_tx_status_failed_tx() {
        let resp = json!({
            "tx_response": { "txhash": "ABC", "code": 5, "height": "200" }
        });
        let st = parse_tx_status(&resp).expect("ok").expect("some");
        assert!(!st.success);
        assert_eq!(st.height, 200);
    }

    #[test]
    fn parse_tx_status_not_found_envelope_is_none() {
        let resp = json!({"code": 5, "message": "tx not found: ABC"});
        assert_eq!(parse_tx_status(&resp).expect("ok"), None);
    }

    #[test]
    fn parse_tx_status_null_tx_response_is_none() {
        let resp = json!({"tx_response": null});
        assert_eq!(parse_tx_status(&resp).expect("ok"), None);
    }

    #[test]
    fn parse_tx_status_absent_tx_response_is_none() {
        assert_eq!(parse_tx_status(&json!({})).expect("ok"), None);
    }

    #[test]
    fn parse_tx_status_garbage_height_errs() {
        let resp = json!({"tx_response": {"code": 0, "height": "not-a-height"}});
        assert!(parse_tx_status(&resp).is_err());
    }

    // --- hostile / garbage input: no panic ---

    #[test]
    fn hostile_inputs_no_panic() {
        let hostile = [json!([1, 2, 3]), json!("string"), json!(null), json!(42), json!(true)];
        for v in &hostile {
            // parse_account / parse_broadcast: must Err (no value extractable).
            assert!(parse_account(v).is_err(), "parse_account on {v:?}");
            assert!(parse_broadcast(v).is_err(), "parse_broadcast on {v:?}");
            // parse_simulate: must Err (no gas, no recognizable envelope).
            assert!(parse_simulate(v).is_err(), "parse_simulate on {v:?}");
            // parse_tx_status: well-formed result (Ok(None)) — no tx_response, no envelope.
            let _ = parse_tx_status(v).expect("tx_status must not Err on hostile input");
        }
    }
}
