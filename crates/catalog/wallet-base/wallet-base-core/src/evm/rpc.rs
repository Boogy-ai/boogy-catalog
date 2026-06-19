// src/evm/rpc.rs
use crate::types::{AdapterError, FeeEstimate, RpcRequest, RpcResponse, Simulation};
use serde_json::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the `error.message` string if the response carries an RPC error.
pub fn rpc_error(resp: &RpcResponse) -> Option<String> {
    resp["error"]["message"].as_str().map(|s| s.to_owned())
}

/// Parse a `0x`-prefixed hex string as `u128`.
pub fn parse_hex_u128(s: &str) -> Result<u128, AdapterError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(stripped, 16)
        .map_err(|e| AdapterError::Rpc(format!("hex u128 parse error: {e}")))
}

/// Parse a `0x`-prefixed hex string as `u64`.
pub fn parse_hex_u64(s: &str) -> Result<u64, AdapterError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(stripped, 16)
        .map_err(|e| AdapterError::Rpc(format!("hex u64 parse error: {e}")))
}

/// Returns `resp["result"].as_str()` or surfaces the RPC error / a generic error.
pub fn result_str(resp: &RpcResponse) -> Result<&str, AdapterError> {
    if let Some(s) = resp["result"].as_str() {
        return Ok(s);
    }
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    Err(AdapterError::Rpc("missing result".into()))
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

pub fn nonce_request(addr: &str) -> RpcRequest {
    RpcRequest {
        method: "eth_getTransactionCount".into(),
        params: json!([addr, "pending"]),
    }
}

pub fn max_priority_fee_request() -> RpcRequest {
    RpcRequest {
        method: "eth_maxPriorityFeePerGas".into(),
        params: json!([]),
    }
}

pub fn base_fee_request() -> RpcRequest {
    RpcRequest {
        method: "eth_getBlockByNumber".into(),
        params: json!(["pending", false]),
    }
}

pub fn estimate_gas_request(call_obj: serde_json::Value) -> RpcRequest {
    RpcRequest {
        method: "eth_estimateGas".into(),
        params: json!([call_obj]),
    }
}

pub fn call_request(call_obj: serde_json::Value) -> RpcRequest {
    RpcRequest {
        method: "eth_call".into(),
        params: json!([call_obj, "latest"]),
    }
}

pub fn send_raw_transaction_request(raw_hex: &str) -> RpcRequest {
    RpcRequest {
        method: "eth_sendRawTransaction".into(),
        params: json!([raw_hex]),
    }
}

pub fn receipt_request(tx_hash: &str) -> RpcRequest {
    RpcRequest {
        method: "eth_getTransactionReceipt".into(),
        params: json!([tx_hash]),
    }
}

// ---------------------------------------------------------------------------
// Receipt status type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptStatus {
    pub success: bool,
    pub block_number: u64,
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

pub fn parse_nonce(resp: &RpcResponse) -> Result<u64, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    parse_hex_u64(result_str(resp)?)
}

pub fn parse_max_priority_fee(resp: &RpcResponse) -> Result<u128, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    parse_hex_u128(result_str(resp)?)
}

pub fn parse_base_fee(resp: &RpcResponse) -> Result<u128, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    let hex_str = resp["result"]["baseFeePerGas"]
        .as_str()
        .ok_or_else(|| AdapterError::Rpc("missing result.baseFeePerGas".into()))?;
    parse_hex_u128(hex_str)
}

pub fn parse_send_result(resp: &RpcResponse) -> Result<String, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    Ok(result_str(resp)?.to_owned())
}

pub fn parse_estimate_gas(resp: &RpcResponse) -> Result<Simulation, AdapterError> {
    if let Some(result_hex) = resp["result"].as_str() {
        let gas = parse_hex_u64(result_hex)?;
        return Ok(Simulation { success: true, gas_used: Some(gas), error: None });
    }
    if let Some(msg) = rpc_error(resp) {
        return Ok(Simulation { success: false, gas_used: None, error: Some(msg) });
    }
    Err(AdapterError::Rpc("missing result or error".into()))
}

/// Parse an `eth_call` response.
pub fn parse_simulation(resp: &RpcResponse) -> Result<Simulation, AdapterError> {
    if resp["result"].is_string() {
        return Ok(Simulation { success: true, gas_used: None, error: None });
    }
    if let Some(msg) = rpc_error(resp) {
        return Ok(Simulation { success: false, gas_used: None, error: Some(msg) });
    }
    Err(AdapterError::Rpc("missing result or error".into()))
}

/// Parse `eth_maxPriorityFeePerGas` response into a `FeeEstimate` tip.
pub fn parse_fees(resp: &RpcResponse) -> Result<FeeEstimate, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    let tip = parse_hex_u128(result_str(resp)?)?;
    Ok(FeeEstimate { max_priority_fee_per_gas: Some(tip), ..Default::default() })
}

pub fn parse_receipt(resp: &RpcResponse) -> Result<Option<ReceiptStatus>, AdapterError> {
    if let Some(msg) = rpc_error(resp) {
        return Err(AdapterError::Rpc(msg));
    }
    // Not yet mined: result is null
    if resp["result"].is_null() {
        return Ok(None);
    }
    let status_str = resp["result"]["status"]
        .as_str()
        .ok_or_else(|| AdapterError::Rpc("missing receipt status".into()))?;
    let success = status_str == "0x1";
    let block_number_str = resp["result"]["blockNumber"]
        .as_str()
        .ok_or_else(|| AdapterError::Rpc("missing receipt blockNumber".into()))?;
    let block_number = parse_hex_u64(block_number_str)?;
    Ok(Some(ReceiptStatus { success, block_number }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_revert_reason() {
        let resp = json!({"error": {"code": 3, "message": "execution reverted: insufficient balance"}});
        let sim = parse_simulation(&resp).unwrap();
        assert!(!sim.success);
        assert_eq!(sim.error.as_deref(), Some("execution reverted: insufficient balance"));
    }

    #[test]
    fn parse_successful_call_is_success() {
        let resp = json!({"result": "0x0000000000000000000000000000000000000000000000000000000000000001"});
        let sim = parse_simulation(&resp).unwrap();
        assert!(sim.success);
        assert!(sim.error.is_none());
    }

    #[test]
    fn parse_estimate_gas_sets_gas_used() {
        // estimateGas returns a hex quantity as `result`.
        let resp = json!({"result": "0x5208"}); // 21000
        let sim = parse_estimate_gas(&resp).unwrap();
        assert_eq!(sim.gas_used, Some(21000));
        assert!(sim.success);
    }

    #[test]
    fn send_raw_tx_request_shape() {
        let req = send_raw_transaction_request("0xdeadbeef");
        assert_eq!(req.method, "eth_sendRawTransaction");
        assert_eq!(req.params, json!(["0xdeadbeef"]));
    }

    #[test]
    fn nonce_request_shape() {
        let req = nonce_request("0xabc");
        assert_eq!(req.method, "eth_getTransactionCount");
        assert_eq!(req.params, json!(["0xabc", "pending"]));
    }

    #[test]
    fn parse_nonce_decodes_hex() {
        assert_eq!(parse_nonce(&json!({"result": "0x9"})).unwrap(), 9);
    }

    #[test]
    fn parse_fees_from_max_priority_and_base() {
        // eth_maxPriorityFeePerGas result + a base fee supplied separately.
        let tip = json!({"result": "0x3b9aca00"});   // 1 gwei
        let fees = parse_max_priority_fee(&tip).unwrap();
        assert_eq!(fees, 1_000_000_000u128);
    }

    #[test]
    fn parse_send_result_returns_hash() {
        let h = parse_send_result(&json!({"result": "0xabc123"})).unwrap();
        assert_eq!(h, "0xabc123");
    }

    #[test]
    fn rpc_error_is_surfaced() {
        let err = parse_nonce(&json!({"error": {"message": "boom"}}));
        assert!(err.is_err());
    }
}
