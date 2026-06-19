//! Outbound EVM JSON-RPC client.
//!
//! Sends a `wallet_base_core::types::RpcRequest` as a JSON-RPC 2.0 POST
//! and returns the raw `RpcResponse` (`serde_json::Value`) for the caller to
//! parse with the typed parsers in `wallet_base_core::evm::rpc`.
//!
//! # Secret injection
//!
//! The API key is NOT in wasm. We pass `("Authorization", "evm_rpc_key")` in
//! `secret_headers`; the host resolves the manifest-declared secret and injects
//! its value VERBATIM as the `Authorization` header at the wire edge. The
//! operator therefore binds the full header value (`Bearer <key>`) — this code
//! adds no prefix.

use boogy_sdk::error::ApiError;
use wallet_base_core::btc::rpc::{BtcRestBody, BtcRestRequest};
use wallet_base_core::cosmos::rpc::CosmosRestRequest;
use wallet_base_core::types::{RpcRequest, RpcResponse};

use crate::bindings::boogy::platform::outbound_http;

/// The EVM RPC endpoint URL. This is a PLACEHOLDER host matching the manifest
/// `[outbound] allowed_hosts` entry; the provisioner overrides both with the
/// real chain RPC endpoint (and binds the `evm_rpc_key` secret for it) at deploy
/// time. The two must agree — outbound to a host not in `allowed_hosts` is
/// denied by the host.
const EVM_RPC_URL: &str = "https://rpc.example.com";

/// The Solana JSON-RPC endpoint URL. PLACEHOLDER host matching the manifest
/// `[outbound] allowed_hosts` entry; the provisioner overrides it with the real
/// chain RPC endpoint (and binds the `solana_rpc_key` secret for it) at deploy
/// time. Solana speaks JSON-RPC 2.0 like EVM (unlike Cosmos's REST).
const SOLANA_RPC_URL: &str = "https://solana-rpc.example.com";

/// The Cosmos LCD (REST) base URL. PLACEHOLDER host matching the manifest
/// `[outbound] allowed_hosts` entry; the provisioner overrides it with the real
/// LCD endpoint (and binds the `cosmos_rpc_key` secret for it) at deploy time.
const COSMOS_LCD_URL: &str = "https://lcd.example.com";

/// The Bitcoin Esplora (REST) base URL. PLACEHOLDER host matching the manifest
/// `[outbound] allowed_hosts` entry; the provisioner overrides it with the real
/// Esplora endpoint (and binds the `btc_rpc_key` secret for it) at deploy time.
/// Esplora is REST (not JSON-RPC) and is NOT JSON-uniform: GETs return JSON,
/// but `POST /tx` takes the raw-tx hex as a plain-text body and returns the
/// bare txid as plain text — hence the json/text split below.
const BTC_ESPLORA_URL: &str = "https://esplora.example.com";

/// Send `req` as a JSON-RPC 2.0 POST to `url` and return the parsed response
/// body. `secret_name` is the manifest-declared secret the host injects as the
/// `Authorization` header value VERBATIM — the wasm never sees the credential.
///
/// Shared by the EVM and Solana clients (both speak JSON-RPC 2.0); only the URL
/// + secret name differ.
fn call_jsonrpc(
    url: &str,
    secret_name: &str,
    req: &RpcRequest,
) -> Result<RpcResponse, ApiError> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": req.method,
        "params": req.params,
    });

    let request = outbound_http::OutboundRequest {
        method: "POST".to_string(),
        url: url.to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: Some(
            serde_json::to_vec(&body)
                .map_err(|e| ApiError::internal(format!("rpc encode: {e}")))?,
        ),
        timeout_ms: Some(8000),
        // The host resolves the named secret from the service secrets store and
        // injects its value as the Authorization header value verbatim.
        secret_headers: vec![("Authorization".to_string(), secret_name.to_string())],
    };

    let resp = outbound_http::fetch(&request)
        .map_err(|e| ApiError::service_unavailable(format!("rpc: {e:?}")))?;

    if !(200..300).contains(&resp.status) {
        return Err(ApiError::service_unavailable(format!(
            "rpc status {}",
            resp.status
        )));
    }

    let bytes = resp
        .body
        .ok_or_else(|| ApiError::service_unavailable("rpc: empty body"))?;

    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::service_unavailable(format!("rpc decode: {e}")))
}

/// Send `req` as a JSON-RPC 2.0 POST to the configured EVM RPC endpoint and
/// return the parsed response body.
///
/// The host injects the `evm_rpc_key` secret as the `Authorization` header —
/// the wasm never sees the credential.
pub fn call_evm_rpc(req: &RpcRequest) -> Result<RpcResponse, ApiError> {
    call_jsonrpc(EVM_RPC_URL, "evm_rpc_key", req)
}

/// Send `req` as a JSON-RPC 2.0 POST to the configured Solana RPC endpoint and
/// return the parsed response body.
///
/// The host injects the `solana_rpc_key` secret as the `Authorization` header —
/// the wasm never sees the credential.
pub fn call_solana_rpc(req: &RpcRequest) -> Result<RpcResponse, ApiError> {
    call_jsonrpc(SOLANA_RPC_URL, "solana_rpc_key", req)
}

/// Issue a Cosmos LCD (REST) request and return the parsed JSON response body
/// for the typed parsers in `wallet_base_core::cosmos::rpc`.
///
/// Cosmos LCD is REST (not JSON-RPC): the descriptor carries the HTTP method,
/// the path (appended to `COSMOS_LCD_URL`), and an optional JSON body. The host
/// injects the `cosmos_rpc_key` secret as the `Authorization` header — the wasm
/// never sees the credential.
pub fn call_cosmos_rpc(req: &CosmosRestRequest) -> Result<RpcResponse, ApiError> {
    let body = match &req.body {
        Some(v) => Some(
            serde_json::to_vec(v).map_err(|e| ApiError::internal(format!("rpc encode: {e}")))?,
        ),
        None => None,
    };

    let request = outbound_http::OutboundRequest {
        method: req.method.to_string(),
        url: format!("{COSMOS_LCD_URL}{}", req.path),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
        timeout_ms: Some(8000),
        // The host resolves "cosmos_rpc_key" from the service secrets store and
        // injects its value as the Authorization header value verbatim.
        secret_headers: vec![("Authorization".to_string(), "cosmos_rpc_key".to_string())],
    };

    let resp = outbound_http::fetch(&request)
        .map_err(|e| ApiError::service_unavailable(format!("rpc: {e:?}")))?;

    if !(200..300).contains(&resp.status) {
        return Err(ApiError::service_unavailable(format!(
            "rpc status {}",
            resp.status
        )));
    }

    let bytes = resp
        .body
        .ok_or_else(|| ApiError::service_unavailable("rpc: empty body"))?;

    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::service_unavailable(format!("rpc decode: {e}")))
}

/// Issue a Bitcoin Esplora (REST) request and return the raw `(status, body)`.
/// Shared by the JSON and text Esplora clients (the wire request is identical;
/// only how the body is interpreted differs).
///
/// The descriptor carries the HTTP method, the path (appended to
/// `BTC_ESPLORA_URL`), and an optional plain-text body. A `Some(Text(..))` body
/// (only `POST /tx`) is sent with `Content-Type: text/plain`; a `None` body
/// (the GETs) carries no body and no content-type. The host injects the
/// `btc_rpc_key` secret as the `Authorization` header verbatim — the wasm never
/// sees the credential. The status check is left to the callers so the text
/// client can surface a non-2xx body verbatim (Esplora puts the chain's reject
/// reason in the plain-text body).
fn btc_fetch(req: &BtcRestRequest) -> Result<(u16, Vec<u8>), ApiError> {
    let (headers, body) = match &req.body {
        Some(BtcRestBody::Text(text)) => (
            vec![("Content-Type".to_string(), "text/plain".to_string())],
            Some(text.clone().into_bytes()),
        ),
        None => (Vec::new(), None),
    };

    let request = outbound_http::OutboundRequest {
        method: req.method.to_string(),
        url: format!("{BTC_ESPLORA_URL}{}", req.path),
        headers,
        body,
        timeout_ms: Some(8000),
        // The host resolves "btc_rpc_key" from the service secrets store and
        // injects its value as the Authorization header value verbatim.
        secret_headers: vec![("Authorization".to_string(), "btc_rpc_key".to_string())],
    };

    let resp = outbound_http::fetch(&request)
        .map_err(|e| ApiError::service_unavailable(format!("rpc: {e:?}")))?;
    let bytes = resp.body.unwrap_or_default();
    Ok((resp.status, bytes))
}

/// Issue a Bitcoin Esplora request and parse the response body as JSON for the
/// typed parsers in `wallet_base_core::btc::rpc` (utxos / tx status / fee
/// estimates). Use for the GET endpoints (`/address/{addr}/utxo`,
/// `/tx/{txid}/status`, `/fee-estimates`). A non-2xx response → error.
pub fn call_btc_rpc_json(req: &BtcRestRequest) -> Result<RpcResponse, ApiError> {
    let (status, bytes) = btc_fetch(req)?;
    if !(200..300).contains(&status) {
        return Err(ApiError::service_unavailable(format!("rpc status {status}")));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::service_unavailable(format!("rpc decode: {e}")))
}

/// Issue a Bitcoin Esplora request and return the response body as a UTF-8
/// string. Use for `POST /tx`, which returns the bare txid as plain text (and a
/// plain-text error string on a chain rejection). The body is returned for ALL
/// statuses — a non-2xx body carries the chain's reject reason verbatim, which
/// `parse_broadcast_txid` then surfaces (it treats a non-txid body as an error).
pub fn call_btc_rpc_text(req: &BtcRestRequest) -> Result<String, ApiError> {
    let (_status, bytes) = btc_fetch(req)?;
    String::from_utf8(bytes)
        .map_err(|e| ApiError::service_unavailable(format!("rpc decode (non-utf8): {e}")))
}
