// src/btc/rpc.rs
//
// Esplora REST (Blockstream / mempool.space-compatible) request shaping +
// response parsing for the Bitcoin UTXO adapter. Pure: no I/O — the wasm
// service layer owns the Esplora base URL and issues the actual GET/POST.
// Builders return a [`BtcRestRequest`] descriptor; parsers consume the raw
// response and tolerate hostile/garbage input (Err, never panic) — mirrors the
// Cosmos/EVM adapters' parse philosophy.
//
// Esplora is NOT JSON-uniform like the Cosmos LCD:
//   - `POST /tx` takes the raw-tx **hex as a plain-text body** (not JSON) and
//     returns the **txid as plain text** (not JSON). So the request descriptor
//     carries an optional TEXT body (distinct from a JSON body), and
//     `parse_broadcast_txid` consumes the response as `&str`, not `RpcResponse`.
//   - `GET /fee-estimates` returns a JSON object keyed by stringified block
//     targets (`{"1":12.3,"6":4.1,…}`) with sat/vB float values.
use crate::btc::Utxo;
use crate::types::{AdapterError, RpcResponse};

// ---------------------------------------------------------------------------
// Request descriptor
// ---------------------------------------------------------------------------

/// The body of a shaped Esplora request. Esplora mixes JSON-returning GETs with
/// a single plain-text POST (`/tx`), so the body is one of:
///   - `None` — a GET (no body).
///   - `Text(hex)` — the `POST /tx` raw-tx hex body. The service layer sets
///     `Content-Type: text/plain` for this variant. (Esplora's only write
///     endpoint; we keep a dedicated variant rather than smuggling raw text
///     through a JSON string.)
///
/// A `Json` variant is intentionally NOT defined: Esplora has no JSON-body
/// endpoints in this adapter's surface. Add one here if that changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtcRestBody {
    /// Plain-text body — the raw-tx hex for `POST /tx`. Served with
    /// `Content-Type: text/plain`.
    Text(String),
}

/// A shaped Esplora REST request. The service layer prepends the Esplora base
/// URL to `path` and issues `method`; when `body` is `Some(Text(..))` it sends
/// the text with `Content-Type: text/plain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcRestRequest {
    pub method: &'static str, // "GET" | "POST"
    pub path: String,
    pub body: Option<BtcRestBody>, // Some(Text(..)) for POST /tx; None for GET
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// True iff `s` is exactly 64 lowercase hex chars — the canonical Esplora txid
/// shape. Used to discriminate a success body (bare txid) from an error body
/// (an RPC error string / JSON). Strict: uppercase is rejected (Esplora emits
/// lowercase), so a stray uppercase response surfaces as an error rather than
/// being silently normalized.
fn is_txid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Read an optional `block_height` field as `u64`. Esplora encodes heights as
/// JSON numbers (unlike the Cosmos LCD's decimal strings). Absent/null → `None`
/// (unconfirmed txs carry no height); present-but-non-integer → Err (garbage).
fn opt_block_height(v: &serde_json::Value) -> Result<Option<u64>, AdapterError> {
    match v.get("block_height") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(h) => h
            .as_u64()
            .map(Some)
            .ok_or_else(|| AdapterError::Rpc("block_height is not an integer".into())),
    }
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

/// GET `/address/{address}/utxo` — list the address's spendable UTXOs.
pub fn list_utxos_request(address: &str) -> BtcRestRequest {
    BtcRestRequest {
        method: "GET",
        path: format!("/address/{address}/utxo"),
        body: None,
    }
}

/// POST `/tx` — broadcast a raw transaction. The body is the raw-tx **hex as
/// plain text** (Esplora's wire format for this endpoint); the service layer
/// sends it with `Content-Type: text/plain`.
pub fn broadcast_request(raw_tx_hex: &str) -> BtcRestRequest {
    BtcRestRequest {
        method: "POST",
        path: "/tx".to_owned(),
        body: Some(BtcRestBody::Text(raw_tx_hex.to_owned())),
    }
}

/// GET `/tx/{txid}/status` — confirmation status of a broadcast tx.
pub fn tx_status_request(txid: &str) -> BtcRestRequest {
    BtcRestRequest {
        method: "GET",
        path: format!("/tx/{txid}/status"),
        body: None,
    }
}

/// GET `/fee-estimates` — sat/vB fee estimates keyed by confirmation target.
pub fn fee_estimates_request() -> BtcRestRequest {
    BtcRestRequest {
        method: "GET",
        path: "/fee-estimates".to_owned(),
        body: None,
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// One UTXO row from `/address/{addr}/utxo`. Wraps the adapter's [`Utxo`]
/// (`txid`/`vout`/`value_sat`) with Esplora's confirmation metadata. `confirmed`
/// is `status.confirmed`; `block_height` is `status.block_height` (None while
/// unconfirmed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoEntry {
    pub utxo: Utxo,
    pub confirmed: bool,
    pub block_height: Option<u64>,
}

/// Confirmation status from `/tx/{txid}/status`. `confirmed:true` is the
/// terminal "mined" state for the job poller; `confirmed:false` means seen but
/// still in the mempool (keep polling).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxConfirmation {
    pub confirmed: bool,
    pub block_height: Option<u64>,
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

/// Parse `/address/{addr}/utxo`. The response is a JSON array of
/// `{"txid","vout","value","status":{"confirmed","block_height"}}`. `value`
/// (sats) maps to [`Utxo::value_sat`]. A non-array body or any malformed entry
/// (missing `txid`/`vout`/`value`, wrong types) → Err (no partial result, no
/// panic).
pub fn parse_utxos(resp: &RpcResponse) -> Result<Vec<UtxoEntry>, AdapterError> {
    let arr = resp
        .as_array()
        .ok_or_else(|| AdapterError::Rpc("utxo response is not an array".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let txid = entry["txid"]
            .as_str()
            .ok_or_else(|| AdapterError::Rpc("utxo missing txid".into()))?
            .to_owned();
        let vout = entry["vout"]
            .as_u64()
            .ok_or_else(|| AdapterError::Rpc("utxo missing or non-integer vout".into()))?;
        // Esplora caps vout well within u32; reject anything that doesn't fit.
        let vout = u32::try_from(vout)
            .map_err(|_| AdapterError::Rpc("utxo vout out of range".into()))?;
        let value_sat = entry["value"]
            .as_u64()
            .ok_or_else(|| AdapterError::Rpc("utxo missing or non-integer value".into()))?;
        // `status` is an object on confirmed UTXOs; on unconfirmed ones Esplora
        // still emits `{"confirmed":false}`. Default-absent → unconfirmed.
        let status = &entry["status"];
        let confirmed = status["confirmed"].as_bool().unwrap_or(false);
        let block_height = opt_block_height(status)?;
        out.push(UtxoEntry {
            utxo: Utxo { txid, vout, value_sat },
            confirmed,
            block_height,
        });
    }
    Ok(out)
}

/// Parse the `POST /tx` response. **Takes the plain-text body** (`&str`), NOT an
/// `RpcResponse`: on success Esplora returns the bare txid as text/plain, and on
/// failure a plain error string (e.g. `sendrawtransaction RPC error: …`) — never
/// JSON we'd want to walk. We validate the (trimmed) body is a 64-char lowercase
/// hex txid; anything else (an error message, empty, wrong length, uppercase) →
/// Err surfacing the body verbatim so the caller sees the chain's reason.
pub fn parse_broadcast_txid(body: &str) -> Result<String, AdapterError> {
    let trimmed = body.trim();
    if is_txid(trimmed) {
        Ok(trimmed.to_owned())
    } else {
        Err(AdapterError::Rpc(format!("broadcast rejected: {body}")))
    }
}

/// Parse `/tx/{txid}/status` → `{"confirmed":bool,"block_height":H?,…}`.
///
/// Semantics for the job poller:
///   - `confirmed:true`  → `Ok(Some{confirmed:true, ..})` — terminal (mined).
///   - `confirmed:false` → `Ok(Some{confirmed:false, ..})` — in mempool, keep polling.
///   - object WITHOUT a `confirmed` field (Esplora returns an empty `{}` / 404
///     text for a not-yet-seen txid) → `Ok(None)` — treat as "not seen yet",
///     keep polling. A clean miss is a value, not an error.
///   - anything that isn't a JSON object (array/string/number/null), or a
///     `confirmed` field that isn't a bool, or a non-integer `block_height` →
///     Err (garbage; not a status we can trust).
pub fn parse_tx_status(resp: &RpcResponse) -> Result<Option<TxConfirmation>, AdapterError> {
    let obj = resp
        .as_object()
        .ok_or_else(|| AdapterError::Rpc("tx status is not an object".into()))?;
    let confirmed = match obj.get("confirmed") {
        // Clean miss: object with no `confirmed` field → not seen yet.
        None => return Ok(None),
        Some(v) => v
            .as_bool()
            .ok_or_else(|| AdapterError::Rpc("confirmed is not a bool".into()))?,
    };
    let block_height = opt_block_height(resp)?;
    Ok(Some(TxConfirmation { confirmed, block_height }))
}

/// Parse `/fee-estimates` (`{"1":12.3,"6":4.1,…}`, sat/vB floats keyed by
/// stringified confirmation target) for `target_blocks`. Reads the value at key
/// `target_blocks.to_string()`; if that exact key is absent, falls back to the
/// NEAREST available HIGHER target (a slower confirmation target → a lower/safe
/// fee; we never silently pick a faster, costlier one). The float is rounded UP
/// to the next integer sat/vB (`.ceil()`), floored at 1 (a valid tx needs ≥ 1
/// sat/vB). A non-object body, an empty map, no target ≥ the request, or a
/// non-numeric value → Err.
pub fn parse_fee_estimate(resp: &RpcResponse, target_blocks: u32) -> Result<u64, AdapterError> {
    let obj = resp
        .as_object()
        .ok_or_else(|| AdapterError::Rpc("fee-estimates is not an object".into()))?;
    if obj.is_empty() {
        return Err(AdapterError::Rpc("fee-estimates is empty".into()));
    }
    // Exact-key hit, else the nearest available higher target.
    let value = match obj.get(&target_blocks.to_string()) {
        Some(v) => v,
        None => {
            // Find the smallest numeric key >= target_blocks.
            let mut best: Option<(u32, &serde_json::Value)> = None;
            for (k, v) in obj {
                if let Ok(kn) = k.parse::<u32>() {
                    if kn >= target_blocks && best.map_or(true, |(b, _)| kn < b) {
                        best = Some((kn, v));
                    }
                }
            }
            match best {
                Some((_, v)) => v,
                None => {
                    return Err(AdapterError::Rpc(format!(
                        "no fee estimate at or above target {target_blocks}"
                    )))
                }
            }
        }
    };
    let rate = value
        .as_f64()
        .ok_or_else(|| AdapterError::Rpc("fee estimate is not numeric".into()))?;
    if !rate.is_finite() || rate < 0.0 {
        return Err(AdapterError::Rpc(format!("fee estimate is invalid: {rate}")));
    }
    let ceiled = rate.ceil() as u64;
    Ok(ceiled.max(1))
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
    fn list_utxos_request_shape() {
        let req = list_utxos_request("bc1qabc");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/address/bc1qabc/utxo");
        assert!(req.body.is_none());
    }

    #[test]
    fn broadcast_request_carries_hex_text_body() {
        let req = broadcast_request("0200000000deadbeef");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/tx");
        assert_eq!(req.body, Some(BtcRestBody::Text("0200000000deadbeef".to_owned())));
    }

    #[test]
    fn tx_status_request_shape() {
        let req = tx_status_request("ff00");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/tx/ff00/status");
        assert!(req.body.is_none());
    }

    #[test]
    fn fee_estimates_request_shape() {
        let req = fee_estimates_request();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/fee-estimates");
        assert!(req.body.is_none());
    }

    // --- parse_utxos ---

    #[test]
    fn parse_utxos_two_entries() {
        let resp = json!([
            {
                "txid": "aa00",
                "vout": 0,
                "value": 100000,
                "status": { "confirmed": true, "block_height": 800000 }
            },
            {
                "txid": "bb11",
                "vout": 3,
                "value": 50000,
                "status": { "confirmed": false }
            }
        ]);
        let utxos = parse_utxos(&resp).expect("ok");
        assert_eq!(utxos.len(), 2);
        assert_eq!(
            utxos[0],
            UtxoEntry {
                utxo: Utxo { txid: "aa00".into(), vout: 0, value_sat: 100000 },
                confirmed: true,
                block_height: Some(800000),
            }
        );
        assert_eq!(
            utxos[1],
            UtxoEntry {
                utxo: Utxo { txid: "bb11".into(), vout: 3, value_sat: 50000 },
                confirmed: false,
                block_height: None,
            }
        );
    }

    #[test]
    fn parse_utxos_empty_array_ok() {
        assert_eq!(parse_utxos(&json!([])).expect("ok"), vec![]);
    }

    #[test]
    fn parse_utxos_missing_value_errs() {
        let resp = json!([{ "txid": "aa", "vout": 0, "status": {"confirmed": true} }]);
        assert!(parse_utxos(&resp).is_err());
    }

    #[test]
    fn parse_utxos_missing_txid_errs() {
        let resp = json!([{ "vout": 0, "value": 1, "status": {"confirmed": true} }]);
        assert!(parse_utxos(&resp).is_err());
    }

    #[test]
    fn parse_utxos_non_array_errs() {
        assert!(parse_utxos(&json!({})).is_err());
        assert!(parse_utxos(&json!("x")).is_err());
    }

    // --- parse_broadcast_txid ---

    #[test]
    fn parse_broadcast_txid_valid() {
        let txid = "a".repeat(64);
        assert_eq!(parse_broadcast_txid(&txid).expect("ok"), txid);
    }

    #[test]
    fn parse_broadcast_txid_trims_whitespace() {
        let txid = "0".repeat(64);
        let body = format!("  {txid}\n");
        assert_eq!(parse_broadcast_txid(&body).expect("ok"), txid);
    }

    #[test]
    fn parse_broadcast_txid_error_string_errs() {
        let err = parse_broadcast_txid(
            "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"dust\"}",
        )
        .expect_err("err");
        // The error surfaces the body so the caller sees the chain reason.
        assert!(format!("{err}").contains("sendrawtransaction"));
    }

    #[test]
    fn parse_broadcast_txid_empty_errs() {
        assert!(parse_broadcast_txid("").is_err());
        assert!(parse_broadcast_txid("   ").is_err());
    }

    #[test]
    fn parse_broadcast_txid_wrong_length_errs() {
        assert!(parse_broadcast_txid(&"a".repeat(63)).is_err());
        assert!(parse_broadcast_txid(&"a".repeat(65)).is_err());
    }

    #[test]
    fn parse_broadcast_txid_uppercase_errs() {
        // Esplora emits lowercase; uppercase is rejected, not normalized.
        assert!(parse_broadcast_txid(&"A".repeat(64)).is_err());
    }

    // --- parse_tx_status ---

    #[test]
    fn parse_tx_status_confirmed_with_height() {
        let resp = json!({
            "confirmed": true,
            "block_height": 800123,
            "block_hash": "00aa",
            "block_time": 1700000000u64
        });
        let st = parse_tx_status(&resp).expect("ok").expect("some");
        assert!(st.confirmed);
        assert_eq!(st.block_height, Some(800123));
    }

    #[test]
    fn parse_tx_status_unconfirmed() {
        let resp = json!({ "confirmed": false });
        let st = parse_tx_status(&resp).expect("ok").expect("some");
        assert!(!st.confirmed);
        assert_eq!(st.block_height, None);
    }

    #[test]
    fn parse_tx_status_missing_confirmed_is_none() {
        // A not-yet-seen txid returns an empty object → "not seen yet".
        assert_eq!(parse_tx_status(&json!({})).expect("ok"), None);
    }

    #[test]
    fn parse_tx_status_confirmed_not_bool_errs() {
        let resp = json!({ "confirmed": "yes" });
        assert!(parse_tx_status(&resp).is_err());
    }

    #[test]
    fn parse_tx_status_garbage_height_errs() {
        let resp = json!({ "confirmed": true, "block_height": "high" });
        assert!(parse_tx_status(&resp).is_err());
    }

    #[test]
    fn parse_tx_status_non_object_errs() {
        assert!(parse_tx_status(&json!([1, 2, 3])).is_err());
        assert!(parse_tx_status(&json!("x")).is_err());
    }

    // --- parse_fee_estimate ---

    #[test]
    fn parse_fee_estimate_exact_key() {
        let resp = json!({ "1": 12.3, "6": 4.1, "144": 1.0 });
        // 12.3 → ceil → 13.
        assert_eq!(parse_fee_estimate(&resp, 1).expect("ok"), 13);
        // 4.1 → ceil → 5.
        assert_eq!(parse_fee_estimate(&resp, 6).expect("ok"), 5);
    }

    #[test]
    fn parse_fee_estimate_fallback_to_higher_target() {
        // No "3" key; nearest higher is "6" → 4.1 → 5.
        let resp = json!({ "1": 12.3, "6": 4.1, "144": 1.0 });
        assert_eq!(parse_fee_estimate(&resp, 3).expect("ok"), 5);
    }

    #[test]
    fn parse_fee_estimate_floor_at_one() {
        // 0.5 → ceil → 1; a sub-1 estimate must not floor to 0.
        let resp = json!({ "1008": 0.5 });
        assert_eq!(parse_fee_estimate(&resp, 1008).expect("ok"), 1);
    }

    #[test]
    fn parse_fee_estimate_no_target_at_or_above_errs() {
        // Requesting a target above every available key → Err.
        let resp = json!({ "1": 12.3, "6": 4.1 });
        assert!(parse_fee_estimate(&resp, 100).is_err());
    }

    #[test]
    fn parse_fee_estimate_empty_errs() {
        assert!(parse_fee_estimate(&json!({}), 1).is_err());
    }

    #[test]
    fn parse_fee_estimate_non_numeric_errs() {
        let resp = json!({ "1": "fast" });
        assert!(parse_fee_estimate(&resp, 1).is_err());
    }

    #[test]
    fn parse_fee_estimate_non_object_errs() {
        assert!(parse_fee_estimate(&json!([1, 2, 3]), 1).is_err());
    }

    // --- hostile / garbage input: no panic ---

    #[test]
    fn hostile_inputs_no_panic() {
        let hostile = [json!([1, 2, 3]), json!("string"), json!(null), json!(42), json!(true)];
        for v in &hostile {
            // parse_utxos: array-of-garbage / non-array → Err.
            assert!(parse_utxos(v).is_err(), "parse_utxos on {v:?}");
            // parse_tx_status: non-object → Err; an object would be a value.
            assert!(parse_tx_status(v).is_err(), "parse_tx_status on {v:?}");
            // parse_fee_estimate: non-object / empty / non-numeric → Err.
            assert!(parse_fee_estimate(v, 6).is_err(), "parse_fee_estimate on {v:?}");
        }
    }
}
