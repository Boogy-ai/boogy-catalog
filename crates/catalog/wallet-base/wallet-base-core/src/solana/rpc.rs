// src/solana/rpc.rs
//
// Solana JSON-RPC 2.0 request shaping + response parsing. Pure: no I/O — the
// wasm service layer owns the RPC base URL + secret injection and issues the
// actual POST. Builders return an [`RpcRequest`] (`{method, params}`); parsers
// consume the raw JSON response (`RpcResponse` = `serde_json::Value`) and
// tolerate hostile/garbage input (Err, never panic).
//
// Like EVM, Solana speaks JSON-RPC (unlike Cosmos's REST). It encodes tx /
// message blobs as base64 (not hex). The parse philosophy mirrors the EVM
// adapter: a chain-level "didn't succeed" that still carries data (a failed
// simulation, an on-chain tx failure) is a *value*, not a transport error; a
// JSON-RPC `error` envelope or unparseable JSON is an `Err`; a "not yet seen"
// (null signature status, expired blockhash fee) is `Ok(None)`.
use crate::types::{AdapterError, RpcRequest, RpcResponse, Simulation};
use base64::Engine;
use serde_json::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Returns the JSON-RPC `error.message` string if the response carries an error
/// envelope (`{"error":{"code":N,"message":"..."}}`).
pub fn rpc_error(resp: &RpcResponse) -> Option<String> {
    resp["error"]["message"].as_str().map(|s| s.to_owned())
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

/// `getLatestBlockhash` — fetch a recent blockhash + its last-valid block height.
/// Pin commitment to "finalized" so the blockhash is durable.
pub fn latest_blockhash_request() -> RpcRequest {
    RpcRequest {
        method: "getLatestBlockhash".into(),
        params: json!([{ "commitment": "finalized" }]),
    }
}

/// `getBalance` — lamport balance of an account (base58 address).
pub fn balance_request(addr: &str) -> RpcRequest {
    RpcRequest {
        method: "getBalance".into(),
        params: json!([addr]),
    }
}

/// `simulateTransaction` — dry-run a (signed) tx. `sigVerify:false` so an
/// unsigned/placeholder-signed tx still simulates; `encoding:base64` matches the
/// base64 tx blob.
pub fn simulate_request(tx_bytes: &[u8]) -> RpcRequest {
    RpcRequest {
        method: "simulateTransaction".into(),
        params: json!([b64(tx_bytes), { "encoding": "base64", "sigVerify": false }]),
    }
}

/// `getFeeForMessage` — fee (lamports) for a serialized Message blob at a given
/// blockhash. Returns null when the blockhash is unknown/expired.
pub fn fee_for_message_request(message_bytes: &[u8]) -> RpcRequest {
    RpcRequest {
        method: "getFeeForMessage".into(),
        params: json!([b64(message_bytes), { "commitment": "finalized" }]),
    }
}

/// `sendTransaction` — broadcast a fully-signed tx (base64). Returns the base58
/// signature string on accept.
pub fn send_transaction_request(tx_bytes: &[u8]) -> RpcRequest {
    RpcRequest {
        method: "sendTransaction".into(),
        params: json!([b64(tx_bytes), { "encoding": "base64" }]),
    }
}

/// `getSignatureStatuses` — poll the status of one signature. The signature is
/// wrapped in a nested array (the RPC takes a batch); `searchTransactionHistory`
/// looks beyond the recent-status cache.
pub fn signature_status_request(signature: &str) -> RpcRequest {
    RpcRequest {
        method: "getSignatureStatuses".into(),
        params: json!([[signature], { "searchTransactionHistory": true }]),
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestBlockhash {
    /// Base58-encoded recent blockhash (used as the tx's recent_blockhash).
    pub blockhash: String,
    /// Last block height at which this blockhash is still valid.
    pub last_valid_block_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureStatus {
    /// `confirmationStatus` is "confirmed" or "finalized".
    pub confirmed: bool,
    /// The tx failed on-chain (non-null `err`).
    pub err: bool,
    /// Slot in which the tx was processed.
    pub slot: u64,
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

/// Parse `getLatestBlockhash`. Data lives under `result.value`:
/// `blockhash` (base58 string) + `lastValidBlockHeight` (number). A JSON-RPC
/// `error` envelope or any missing field → Err.
pub fn parse_latest_blockhash(resp: &RpcResponse) -> Result<LatestBlockhash, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    let value = &resp["result"]["value"];
    let blockhash = value["blockhash"]
        .as_str()
        .ok_or_else(|| AdapterError::Rpc("missing result.value.blockhash".into()))?
        .to_owned();
    let last_valid_block_height = value["lastValidBlockHeight"]
        .as_u64()
        .ok_or_else(|| AdapterError::Rpc("missing result.value.lastValidBlockHeight".into()))?;
    Ok(LatestBlockhash { blockhash, last_valid_block_height })
}

/// Parse `getBalance`. Lamports live at `result.value` (a JSON number). A
/// JSON-RPC `error` envelope or a missing/non-numeric value → Err.
pub fn parse_balance(resp: &RpcResponse) -> Result<u64, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    resp["result"]["value"]
        .as_u64()
        .ok_or_else(|| AdapterError::Rpc("missing or non-numeric result.value".into()))
}

/// Parse `simulateTransaction`. Data under `result.value`: `err` (null on
/// success), `unitsConsumed` (compute units → `gas_used`). A non-null `err` is a
/// failed simulation returned as a `Simulation{success:false}` *value* (mirrors
/// EVM's revert-as-value), carrying `unitsConsumed` when present. A top-level
/// JSON-RPC `error` envelope → Err; a totally missing `result` with no envelope
/// → Err.
pub fn parse_simulate(resp: &RpcResponse) -> Result<Simulation, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    let value = &resp["result"]["value"];
    if value.is_null() {
        return Err(AdapterError::Rpc("missing result.value".into()));
    }
    let gas_used = value["unitsConsumed"].as_u64();
    let err = &value["err"];
    if !err.is_null() {
        // Chain-level failure: a value, not an Err. `err` is an object/string/code.
        return Ok(Simulation {
            success: false,
            gas_used,
            error: Some(err.to_string()),
        });
    }
    Ok(Simulation { success: true, gas_used, error: None })
}

/// Parse `getFeeForMessage`. `result.value` is the fee in lamports, OR `null`
/// when the blockhash is unknown/expired → `Ok(None)`. A JSON-RPC `error`
/// envelope → Err; a present-but-non-numeric value → Err.
pub fn parse_fee_for_message(resp: &RpcResponse) -> Result<Option<u64>, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    let value = &resp["result"]["value"];
    if value.is_null() {
        // Blockhash unknown/expired — not an error, the caller refreshes + retries.
        return Ok(None);
    }
    let fee = value
        .as_u64()
        .ok_or_else(|| AdapterError::Rpc("result.value is not a number".into()))?;
    Ok(Some(fee))
}

/// Parse `sendTransaction`. `result` is the base58 transaction signature string.
/// A JSON-RPC `error` envelope → Err (Solana send errors are meaningful, e.g.
/// "blockhash not found"); a missing/non-string result → Err.
pub fn parse_send_result(resp: &RpcResponse) -> Result<String, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    resp["result"]
        .as_str()
        .map(|s| s.to_owned())
        .ok_or_else(|| AdapterError::Rpc("missing result".into()))
}

/// Parse `getSignatureStatuses`. The status sits at `result.value[0]`:
/// `null` → the signature is not yet seen → `Ok(None)` (mirrors EVM
/// `parse_receipt` / cosmos `parse_tx_status`). A present (non-null) entry reads
/// `confirmationStatus` ("confirmed"/"finalized" → confirmed), `err` (non-null =
/// the tx failed on-chain), and `slot`. A JSON-RPC `error` envelope → Err; a
/// present-but-garbage entry (no usable `slot`) → Err.
pub fn parse_signature_status(
    resp: &RpcResponse,
) -> Result<Option<SignatureStatus>, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    let entry = &resp["result"]["value"][0];
    if entry.is_null() {
        // Not yet seen by the cluster — caller keeps polling.
        return Ok(None);
    }
    let slot = entry["slot"]
        .as_u64()
        .ok_or_else(|| AdapterError::Rpc("missing result.value[0].slot".into()))?;
    let confirmed = matches!(
        entry["confirmationStatus"].as_str(),
        Some("confirmed") | Some("finalized")
    );
    let err = !entry["err"].is_null();
    Ok(Some(SignatureStatus { confirmed, err, slot }))
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
    fn latest_blockhash_request_shape() {
        let req = latest_blockhash_request();
        assert_eq!(req.method, "getLatestBlockhash");
        assert_eq!(req.params, json!([{ "commitment": "finalized" }]));
    }

    #[test]
    fn balance_request_shape() {
        let req = balance_request("So1anaAddr");
        assert_eq!(req.method, "getBalance");
        assert_eq!(req.params, json!(["So1anaAddr"]));
    }

    #[test]
    fn simulate_request_base64_and_flags() {
        let req = simulate_request(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(req.method, "simulateTransaction");
        assert_eq!(req.params[0], json!("3q2+7w==")); // STANDARD base64 of deadbeef
        assert_eq!(req.params[1]["encoding"], json!("base64"));
        assert_eq!(req.params[1]["sigVerify"], json!(false));
    }

    #[test]
    fn fee_for_message_request_base64() {
        let req = fee_for_message_request(&[0x01, 0x02, 0x03]);
        assert_eq!(req.method, "getFeeForMessage");
        assert_eq!(req.params[0], json!("AQID")); // STANDARD base64 of 010203
        assert_eq!(req.params[1]["commitment"], json!("finalized"));
    }

    #[test]
    fn send_transaction_request_base64_and_encoding() {
        let req = send_transaction_request(&[0x01, 0x02, 0x03]);
        assert_eq!(req.method, "sendTransaction");
        assert_eq!(req.params[0], json!("AQID"));
        assert_eq!(req.params[1]["encoding"], json!("base64"));
    }

    #[test]
    fn signature_status_request_wraps_sig_in_nested_array() {
        let req = signature_status_request("5sig...");
        assert_eq!(req.method, "getSignatureStatuses");
        assert_eq!(req.params[0], json!(["5sig..."]));
        assert_eq!(req.params[1]["searchTransactionHistory"], json!(true));
    }

    // --- parse_latest_blockhash ---

    #[test]
    fn parse_latest_blockhash_happy() {
        let resp = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "context": { "slot": 2792 },
                "value": {
                    "blockhash": "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N",
                    "lastValidBlockHeight": 3090
                }
            }
        });
        let bh = parse_latest_blockhash(&resp).expect("ok");
        assert_eq!(bh.blockhash, "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N");
        assert_eq!(bh.last_valid_block_height, 3090);
    }

    #[test]
    fn parse_latest_blockhash_missing_field_errs() {
        let resp = json!({"result": {"value": {"blockhash": "abc"}}});
        assert!(parse_latest_blockhash(&resp).is_err());
    }

    #[test]
    fn parse_latest_blockhash_error_envelope_errs() {
        let resp = json!({"error": {"code": -32602, "message": "Invalid params"}});
        assert!(parse_latest_blockhash(&resp).is_err());
    }

    // --- parse_balance ---

    #[test]
    fn parse_balance_happy() {
        let resp = json!({
            "result": { "context": { "slot": 1 }, "value": 1234567890u64 }
        });
        assert_eq!(parse_balance(&resp).expect("ok"), 1234567890);
    }

    #[test]
    fn parse_balance_error_envelope_errs() {
        let resp = json!({"error": {"message": "node behind"}});
        assert!(parse_balance(&resp).is_err());
    }

    #[test]
    fn parse_balance_missing_errs() {
        assert!(parse_balance(&json!({"result": {}})).is_err());
    }

    // --- parse_simulate ---

    #[test]
    fn parse_simulate_clean_success() {
        let resp = json!({
            "result": {
                "context": { "slot": 218 },
                "value": {
                    "err": null,
                    "logs": ["Program 11111111111111111111111111111111 invoke [1]"],
                    "unitsConsumed": 150
                }
            }
        });
        let sim = parse_simulate(&resp).expect("ok");
        assert!(sim.success);
        assert_eq!(sim.gas_used, Some(150));
        assert!(sim.error.is_none());
    }

    #[test]
    fn parse_simulate_chain_failure_is_value_not_err() {
        let resp = json!({
            "result": {
                "context": { "slot": 218 },
                "value": {
                    "err": { "InstructionError": [0, { "Custom": 1 }] },
                    "logs": [],
                    "unitsConsumed": 200
                }
            }
        });
        let sim = parse_simulate(&resp).expect("chain failure is a value");
        assert!(!sim.success);
        assert_eq!(sim.gas_used, Some(200)); // carries unitsConsumed
        assert!(sim.error.is_some());
    }

    #[test]
    fn parse_simulate_top_level_error_envelope_errs() {
        let resp = json!({"error": {"message": "blockhash not found"}});
        assert!(parse_simulate(&resp).is_err());
    }

    #[test]
    fn parse_simulate_missing_result_errs() {
        assert!(parse_simulate(&json!({})).is_err());
    }

    // --- parse_fee_for_message ---

    #[test]
    fn parse_fee_for_message_some() {
        let resp = json!({"result": {"context": {"slot": 5068}, "value": 5000}});
        assert_eq!(parse_fee_for_message(&resp).expect("ok"), Some(5000));
    }

    #[test]
    fn parse_fee_for_message_null_is_none() {
        // Expired/unknown blockhash → value null → Ok(None).
        let resp = json!({"result": {"context": {"slot": 5068}, "value": null}});
        assert_eq!(parse_fee_for_message(&resp).expect("ok"), None);
    }

    #[test]
    fn parse_fee_for_message_error_envelope_errs() {
        let resp = json!({"error": {"message": "boom"}});
        assert!(parse_fee_for_message(&resp).is_err());
    }

    #[test]
    fn parse_fee_for_message_non_numeric_errs() {
        let resp = json!({"result": {"value": "not-a-number"}});
        assert!(parse_fee_for_message(&resp).is_err());
    }

    // --- parse_send_result ---

    #[test]
    fn parse_send_result_returns_signature() {
        let resp = json!({"result": "2id3YC2jK9G5Wo2phDx4gJVAew8DcY5NAojnVuao8rkxwPYPe8cSwE5GzhEgJA2y8fVjDEo6iR6ykBvDxrTQrtpb"});
        let sig = parse_send_result(&resp).expect("ok");
        assert!(sig.starts_with("2id3YC2jK9G5"));
    }

    #[test]
    fn parse_send_result_error_envelope_errs() {
        let resp = json!({"error": {"code": -32002, "message": "Transaction simulation failed: Blockhash not found"}});
        assert!(parse_send_result(&resp).is_err());
    }

    #[test]
    fn parse_send_result_missing_errs() {
        assert!(parse_send_result(&json!({})).is_err());
    }

    // --- parse_signature_status ---

    #[test]
    fn parse_signature_status_not_yet_seen_is_none() {
        let resp = json!({"result": {"context": {"slot": 82}, "value": [null]}});
        assert_eq!(parse_signature_status(&resp).expect("ok"), None);
    }

    #[test]
    fn parse_signature_status_confirmed_ok() {
        let resp = json!({
            "result": {
                "context": { "slot": 82 },
                "value": [{
                    "slot": 48,
                    "confirmations": null,
                    "err": null,
                    "confirmationStatus": "finalized"
                }]
            }
        });
        let st = parse_signature_status(&resp).expect("ok").expect("some");
        assert!(st.confirmed);
        assert!(!st.err);
        assert_eq!(st.slot, 48);
    }

    #[test]
    fn parse_signature_status_failed_tx() {
        let resp = json!({
            "result": {
                "context": { "slot": 82 },
                "value": [{
                    "slot": 50,
                    "err": { "InstructionError": [0, "InvalidAccountData"] },
                    "confirmationStatus": "confirmed"
                }]
            }
        });
        let st = parse_signature_status(&resp).expect("ok").expect("some");
        assert!(st.confirmed);
        assert!(st.err); // failed on-chain
        assert_eq!(st.slot, 50);
    }

    #[test]
    fn parse_signature_status_processed_not_confirmed() {
        let resp = json!({
            "result": {
                "value": [{ "slot": 51, "err": null, "confirmationStatus": "processed" }]
            }
        });
        let st = parse_signature_status(&resp).expect("ok").expect("some");
        assert!(!st.confirmed);
        assert!(!st.err);
    }

    #[test]
    fn parse_signature_status_present_garbage_errs() {
        // A present (non-null) entry with no usable slot is malformed → Err.
        let resp = json!({"result": {"value": [{ "confirmationStatus": "confirmed" }]}});
        assert!(parse_signature_status(&resp).is_err());
    }

    #[test]
    fn parse_signature_status_error_envelope_errs() {
        let resp = json!({"error": {"message": "boom"}});
        assert!(parse_signature_status(&resp).is_err());
    }

    // --- hostile / garbage input: no panic ---

    #[test]
    fn hostile_inputs_no_panic() {
        let hostile = [json!([1, 2, 3]), json!("x"), json!(null), json!(42), json!(true)];
        for v in &hostile {
            // Strict parsers: must Err (no value extractable, no recognized envelope).
            assert!(parse_latest_blockhash(v).is_err(), "parse_latest_blockhash on {v:?}");
            assert!(parse_balance(v).is_err(), "parse_balance on {v:?}");
            assert!(parse_simulate(v).is_err(), "parse_simulate on {v:?}");
            assert!(parse_send_result(v).is_err(), "parse_send_result on {v:?}");
            // Tolerant parsers: a well-formed value (Ok) — null/absent maps to None.
            let _ = parse_fee_for_message(v).expect("fee must not Err on hostile input");
            let _ = parse_signature_status(v).expect("sig status must not Err on hostile input");
        }
    }
}
