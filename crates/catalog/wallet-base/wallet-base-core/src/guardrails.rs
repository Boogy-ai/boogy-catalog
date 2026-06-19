//! App-level spend guardrails. Enforced in-wasm BEFORE signing. NOT
//! host/credops-enforced (a future credops policy engine moves these host-side);
//! a compromised wasm could bypass them — but credops never exports the key.
//! Fail-closed: any parse ambiguity REJECTS.

use crate::types::AdapterError;

/// Inputs to a spend decision. All amounts are decimal wei strings.
#[derive(Debug, Clone)]
pub struct PolicyInput {
    pub value_wei: String,
    /// Resolved transaction fee for this send (EVM `gas_limit × max_fee_per_gas`,
    /// Cosmos `fee_amount`, BTC `fee_sat`, Solana network fee), as a decimal
    /// string. `""` = no fee declared (treated as 0). A set-but-unparseable fee
    /// fails closed. The fee is bounded by `max_fee_wei` AND counts toward the
    /// daily cap alongside `value_wei` (total outflow = value + fee).
    pub fee_wei: String,
    pub max_value_wei: String,       // "0" or "" = no per-tx cap
    /// Per-transaction fee cap. `"0"`/`""` = no fee cap. A node- or
    /// caller-supplied fee above this is rejected before the key is touched —
    /// this is the fund-drain guard (a huge fee can empty a wallet even when the
    /// transferred value is tiny).
    pub max_fee_wei: String,
    pub daily_cap_wei: String,       // "0" or "" = no daily cap
    pub daily_spent_wei: String,     // already spent in the window
    pub recipient: String,           // 0x address (lowercased by caller)
    pub recipient_allowlist: Vec<String>, // empty = no restriction
    /// Allowed contract addresses. Empty = no restriction. Checked as part of the
    /// recipient UNION (see step 4) — NOT gated on a node-derived contract flag.
    pub contract_allowlist: Vec<String>,
    pub sim_success: bool,
    pub refuse_on_revert: bool,
}

/// Parse a decimal wei string as `u128`. The empty string is always an error
/// from this function — callers decide whether "" means "unset" before calling.
fn parse_wei_strict(s: &str) -> Result<u128, AdapterError> {
    let trimmed = s.trim();
    trimmed.parse::<u128>().map_err(|_| {
        AdapterError::BadIntent(format!("unparseable wei amount: {s:?}"))
    })
}

/// Pure spend-policy decision. Returns `Ok(())` iff the spend is permitted.
/// Fail-closed: any unrecognised/unparseable amount yields `Err`.
///
/// Check order:
/// 1. `value_wei` — must be a valid decimal u128 (empty or non-numeric → reject).
///    `fee_wei` is also parsed here: empty = 0, set-but-unparseable → reject.
/// 2. Per-tx value cap — if `max_value_wei` is non-empty and != "0", parse it
///    (reject on error) and reject if `value > cap`.
/// 2b. Per-tx fee cap — if `max_fee_wei` is non-empty and != "0", parse it
///    (reject on error) and reject if `fee > cap` (the fund-drain guard).
/// 3. Daily cap — if `daily_cap_wei` is non-empty and != "0", parse cap +
///    `daily_spent_wei` (reject on error), reject on overflow, reject if
///    `spent + value + fee > cap` (bounds total outflow, not value alone).
/// 4. Allowlist (UNION) — if EITHER `recipient_allowlist` or `contract_allowlist`
///    is non-empty, `recipient` must appear in the union of the two. Not gated on
///    any node-derived contract flag (the node is untrusted).
/// 5. Simulation revert — if `!sim_success && refuse_on_revert` → reject.
pub fn check_policy(p: &PolicyInput) -> Result<(), AdapterError> {
    // Step 1: value_wei — must parse; empty string is not valid here.
    if p.value_wei.trim().is_empty() {
        return Err(AdapterError::BadIntent("value_wei is empty".into()));
    }
    let value = parse_wei_strict(&p.value_wei)?;

    // The resolved tx fee. Empty = no fee declared (0); a set-but-unparseable
    // fee fails closed. The fee is bounded by `max_fee_wei` (step 2b) AND counts
    // toward the daily cap (step 3) — a huge fee drains a wallet even when the
    // transferred value is within the value cap.
    let fee = {
        let f = p.fee_wei.trim();
        if f.is_empty() { 0u128 } else { parse_wei_strict(f)? }
    };

    // Step 2: per-tx value cap.
    let max_trimmed = p.max_value_wei.trim();
    if !max_trimmed.is_empty() && max_trimmed != "0" {
        let cap = parse_wei_strict(max_trimmed)?;
        if value > cap {
            return Err(AdapterError::BadIntent(format!(
                "value {value} exceeds per-tx cap {cap}"
            )));
        }
    }

    // Step 2b: per-tx fee cap (the fund-drain guard).
    let max_fee_trimmed = p.max_fee_wei.trim();
    if !max_fee_trimmed.is_empty() && max_fee_trimmed != "0" {
        let cap = parse_wei_strict(max_fee_trimmed)?;
        if fee > cap {
            return Err(AdapterError::BadIntent(format!(
                "fee {fee} exceeds per-tx fee cap {cap}"
            )));
        }
    }

    // Step 3: daily cap — bounds total OUTFLOW (value + fee), not value alone.
    let daily_trimmed = p.daily_cap_wei.trim();
    if !daily_trimmed.is_empty() && daily_trimmed != "0" {
        let cap = parse_wei_strict(daily_trimmed)?;
        // daily_spent_wei must also parse; treat empty as 0 here (no prior spend).
        let spent_str = p.daily_spent_wei.trim();
        let spent = if spent_str.is_empty() {
            0u128
        } else {
            parse_wei_strict(spent_str)?
        };
        let outflow = value.checked_add(fee).ok_or_else(|| {
            AdapterError::BadIntent("value + fee overflow (u128)".into())
        })?;
        let total = spent.checked_add(outflow).ok_or_else(|| {
            AdapterError::BadIntent("daily spend overflow (u128)".into())
        })?;
        if total > cap {
            return Err(AdapterError::BadIntent(format!(
                "daily spend {total} (value + fee) would exceed cap {cap}"
            )));
        }
    }

    // Step 4: recipient / contract allowlist — UNION semantics (#4).
    //
    // A node-derived "is this address a contract?" signal is untrustworthy (the
    // RPC node controls both `eth_estimateGas` and `eth_getCode`), so the
    // allowlists are NOT gated on it. When EITHER list is non-empty the recipient
    // must appear in the UNION of the two lists; both empty = no restriction. A
    // contract_allowlist therefore can't be bypassed by a node lying that a
    // contract is an EOA.
    let recipient_restricted =
        !p.recipient_allowlist.is_empty() || !p.contract_allowlist.is_empty();
    if recipient_restricted
        && !p.recipient_allowlist.contains(&p.recipient)
        && !p.contract_allowlist.contains(&p.recipient)
    {
        return Err(AdapterError::BadIntent(format!(
            "recipient {:?} not in the allowlist (recipient ∪ contract)",
            p.recipient
        )));
    }

    // Step 6: simulation revert.
    if !p.sim_success && p.refuse_on_revert {
        return Err(AdapterError::BadIntent(
            "simulation reverted and refuse_on_revert is set".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PolicyInput {
        PolicyInput {
            value_wei: "1000".into(),
            fee_wei: "0".into(),
            max_value_wei: "0".into(),
            max_fee_wei: "0".into(),
            daily_cap_wei: "0".into(),
            daily_spent_wei: "0".into(),
            recipient: "0xabc".into(),
            recipient_allowlist: vec![],
            contract_allowlist: vec![],
            sim_success: true,
            refuse_on_revert: true,
        }
    }

    #[test]
    fn clean_passes() {
        assert!(check_policy(&base()).is_ok());
    }

    #[test]
    fn over_per_tx_cap_rejected() {
        let p = PolicyInput { value_wei: "2000".into(), max_value_wei: "1000".into(), ..base() };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn at_cap_ok() {
        let p = PolicyInput { value_wei: "1000".into(), max_value_wei: "1000".into(), ..base() };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn over_daily_cap_rejected() {
        let p = PolicyInput {
            value_wei: "600".into(),
            daily_cap_wei: "1000".into(),
            daily_spent_wei: "500".into(),
            ..base()
        };
        assert!(check_policy(&p).is_err()); // 500+600 > 1000
    }

    #[test]
    fn disallowed_recipient_rejected() {
        let p = PolicyInput {
            recipient: "0xbad".into(),
            recipient_allowlist: vec!["0xgood".into()],
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn allowed_recipient_ok() {
        let p = PolicyInput {
            recipient: "0xgood".into(),
            recipient_allowlist: vec!["0xgood".into()],
            ..base()
        };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn disallowed_contract_rejected() {
        // contract_allowlist set, recipient not in it (and no recipient_allowlist)
        // → rejected. (Union semantics: not in recipient ∪ contract.)
        let p = PolicyInput {
            recipient: "0xctr".into(),
            contract_allowlist: vec!["0xok".into()],
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn revert_with_refuse_rejected() {
        let p = PolicyInput { sim_success: false, refuse_on_revert: true, ..base() };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn revert_without_refuse_ok() {
        let p = PolicyInput { sim_success: false, refuse_on_revert: false, ..base() };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn unparseable_value_fails_closed() {
        let p = PolicyInput {
            value_wei: "notanumber".into(),
            max_value_wei: "1000".into(),
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn unparseable_cap_fails_closed() {
        let p = PolicyInput { value_wei: "1".into(), max_value_wei: "garbage".into(), ..base() };
        assert!(check_policy(&p).is_err()); // a set-but-unparseable cap must reject, not be ignored
    }

    // --- Additional adversarial cases ---

    #[test]
    fn empty_value_fails_closed() {
        let p = PolicyInput { value_wei: "".into(), ..base() };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn whitespace_only_value_fails_closed() {
        let p = PolicyInput { value_wei: "   ".into(), ..base() };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn negative_value_string_fails_closed() {
        let p = PolicyInput { value_wei: "-1".into(), max_value_wei: "1000".into(), ..base() };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn hex_value_fails_closed() {
        // hex is not decimal — must reject, not silently permit
        let p = PolicyInput { value_wei: "0xFF".into(), max_value_wei: "1000".into(), ..base() };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn float_value_fails_closed() {
        let p = PolicyInput { value_wei: "1.5".into(), max_value_wei: "1000".into(), ..base() };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn unparseable_daily_spent_fails_closed() {
        let p = PolicyInput {
            daily_cap_wei: "1000".into(),
            daily_spent_wei: "bad".into(),
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn daily_spend_overflow_rejected() {
        let p = PolicyInput {
            value_wei: "1".into(),
            daily_cap_wei: "1000".into(),
            daily_spent_wei: u128::MAX.to_string(),
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn empty_recipient_allowlist_permits_any_recipient() {
        // empty list = no restriction
        let p = PolicyInput { recipient: "0xanything".into(), recipient_allowlist: vec![], ..base() };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn union_only_contract_list_unlisted_rejected() {
        // #4: a configured contract_allowlist must NOT be bypassable by an
        // (untrustworthy) node claiming the destination is an EOA. With only a
        // contract_allowlist set, any recipient not in it is rejected — no
        // reliance on a node-derived contract flag.
        let p = PolicyInput {
            recipient: "0xunlisted".into(),
            contract_allowlist: vec!["0xok".into()],
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn contract_in_allowlist_ok() {
        let p = PolicyInput {
            recipient: "0xcontract".into(),
            contract_allowlist: vec!["0xcontract".into()],
            ..base()
        };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn union_both_lists_recipient_in_contract_only_ok() {
        // both lists set; recipient is in the CONTRACT list only → allowed (union).
        let p = PolicyInput {
            recipient: "0xc".into(),
            recipient_allowlist: vec!["0xe".into()],
            contract_allowlist: vec!["0xc".into()],
            ..base()
        };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn union_both_lists_recipient_in_recipient_only_ok() {
        let p = PolicyInput {
            recipient: "0xe".into(),
            recipient_allowlist: vec!["0xe".into()],
            contract_allowlist: vec!["0xc".into()],
            ..base()
        };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn union_both_lists_recipient_in_neither_rejected() {
        let p = PolicyInput {
            recipient: "0xx".into(),
            recipient_allowlist: vec!["0xe".into()],
            contract_allowlist: vec!["0xc".into()],
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn exactly_at_daily_cap_ok() {
        // spent=500, value=500, cap=1000 — exactly at cap, should pass
        let p = PolicyInput {
            value_wei: "500".into(),
            daily_cap_wei: "1000".into(),
            daily_spent_wei: "500".into(),
            ..base()
        };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn zero_value_with_no_cap_passes() {
        let p = PolicyInput { value_wei: "0".into(), ..base() };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn unparseable_cap_with_zero_value_still_fails_closed() {
        // Even if value is 0, a set-but-unparseable cap must reject (fail-closed)
        let p = PolicyInput {
            value_wei: "0".into(),
            max_value_wei: "NOTANUMBER".into(),
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    // --- Fee bounding (#2: a huge fee can drain a wallet past the value cap) ---

    #[test]
    fn fee_over_fee_cap_rejected() {
        // value is tiny and within caps, but the fee exceeds the fee cap → reject.
        let p = PolicyInput {
            value_wei: "1".into(),
            fee_wei: "2000".into(),
            max_fee_wei: "1000".into(),
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn fee_at_fee_cap_ok() {
        let p = PolicyInput {
            value_wei: "1".into(),
            fee_wei: "1000".into(),
            max_fee_wei: "1000".into(),
            ..base()
        };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn no_fee_cap_permits_any_fee() {
        // max_fee_wei "0"/"" = no fee cap (back-compat with fee-less policies).
        let p = PolicyInput {
            value_wei: "1".into(),
            fee_wei: "999999999".into(),
            max_fee_wei: "0".into(),
            ..base()
        };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn fee_counts_toward_daily_cap() {
        // value 500 + fee 600 = 1100 > daily cap 1000. Under value-only accounting
        // this wrongly passed; total outflow must include the fee.
        let p = PolicyInput {
            value_wei: "500".into(),
            fee_wei: "600".into(),
            daily_cap_wei: "1000".into(),
            daily_spent_wei: "0".into(),
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn value_plus_fee_within_daily_cap_ok() {
        let p = PolicyInput {
            value_wei: "300".into(),
            fee_wei: "200".into(),
            daily_cap_wei: "1000".into(),
            daily_spent_wei: "0".into(),
            ..base()
        };
        assert!(check_policy(&p).is_ok()); // 300+200 = 500 ≤ 1000
    }

    #[test]
    fn unparseable_fee_with_fee_cap_fails_closed() {
        let p = PolicyInput {
            value_wei: "1".into(),
            fee_wei: "notanumber".into(),
            max_fee_wei: "1000".into(),
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn unparseable_fee_with_daily_cap_fails_closed() {
        // A set daily cap forces fee accounting; an unparseable fee must reject.
        let p = PolicyInput {
            value_wei: "1".into(),
            fee_wei: "bad".into(),
            daily_cap_wei: "1000".into(),
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }

    #[test]
    fn empty_fee_treated_as_zero() {
        // No fee declared and no fee cap / daily cap → fee is 0, passes.
        let p = PolicyInput { value_wei: "1".into(), fee_wei: "".into(), ..base() };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn value_plus_fee_daily_overflow_rejected() {
        let p = PolicyInput {
            value_wei: "1".into(),
            fee_wei: u128::MAX.to_string(),
            daily_cap_wei: "1000".into(),
            daily_spent_wei: "0".into(),
            ..base()
        };
        assert!(check_policy(&p).is_err());
    }
}
