//! App-level spend guardrails. Enforced in-wasm BEFORE signing. NOT
//! host/credops-enforced (a future credops policy engine moves these host-side);
//! a compromised wasm could bypass them — but credops never exports the key.
//! Fail-closed: any parse ambiguity REJECTS.

use crate::types::AdapterError;

/// Inputs to a spend decision. All amounts are decimal wei strings.
#[derive(Debug, Clone)]
pub struct PolicyInput {
    pub value_wei: String,
    pub max_value_wei: String,       // "0" or "" = no per-tx cap
    pub daily_cap_wei: String,       // "0" or "" = no daily cap
    pub daily_spent_wei: String,     // already spent in the window
    pub recipient: String,           // 0x address (lowercased by caller)
    pub recipient_allowlist: Vec<String>, // empty = no restriction
    pub to_is_contract: bool,
    pub contract_allowlist: Vec<String>, // empty = no restriction; checked when to_is_contract
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
/// 2. Per-tx cap — if `max_value_wei` is non-empty and != "0", parse it (reject on
///    error) and reject if `value > cap`.
/// 3. Daily cap — if `daily_cap_wei` is non-empty and != "0", parse cap +
///    `daily_spent_wei` (reject on error), reject on overflow, reject if
///    `spent + value > cap`.
/// 4. Recipient allowlist — if non-empty, `recipient` must be in the list.
/// 5. Contract allowlist — if `to_is_contract` and list is non-empty, `recipient`
///    must be in the list.
/// 6. Simulation revert — if `!sim_success && refuse_on_revert` → reject.
pub fn check_policy(p: &PolicyInput) -> Result<(), AdapterError> {
    // Step 1: value_wei — must parse; empty string is not valid here.
    if p.value_wei.trim().is_empty() {
        return Err(AdapterError::BadIntent("value_wei is empty".into()));
    }
    let value = parse_wei_strict(&p.value_wei)?;

    // Step 2: per-tx cap.
    let max_trimmed = p.max_value_wei.trim();
    if !max_trimmed.is_empty() && max_trimmed != "0" {
        let cap = parse_wei_strict(max_trimmed)?;
        if value > cap {
            return Err(AdapterError::BadIntent(format!(
                "value {value} exceeds per-tx cap {cap}"
            )));
        }
    }

    // Step 3: daily cap.
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
        let total = spent.checked_add(value).ok_or_else(|| {
            AdapterError::BadIntent("daily spend overflow (u128)".into())
        })?;
        if total > cap {
            return Err(AdapterError::BadIntent(format!(
                "daily spend {total} would exceed cap {cap}"
            )));
        }
    }

    // Step 4: recipient allowlist.
    if !p.recipient_allowlist.is_empty() && !p.recipient_allowlist.contains(&p.recipient) {
        return Err(AdapterError::BadIntent(format!(
            "recipient {:?} not in allowlist",
            p.recipient
        )));
    }

    // Step 5: contract allowlist (only when destination is a contract).
    if p.to_is_contract
        && !p.contract_allowlist.is_empty()
        && !p.contract_allowlist.contains(&p.recipient)
    {
        return Err(AdapterError::BadIntent(format!(
            "contract {:?} not in contract allowlist",
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
            max_value_wei: "0".into(),
            daily_cap_wei: "0".into(),
            daily_spent_wei: "0".into(),
            recipient: "0xabc".into(),
            recipient_allowlist: vec![],
            to_is_contract: false,
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
        let p = PolicyInput {
            to_is_contract: true,
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
    fn contract_allowlist_not_checked_for_eoa() {
        // to_is_contract = false → contract_allowlist should not be consulted
        let p = PolicyInput {
            to_is_contract: false,
            recipient: "0xeoa".into(),
            contract_allowlist: vec!["0xother".into()],
            ..base()
        };
        assert!(check_policy(&p).is_ok());
    }

    #[test]
    fn contract_in_allowlist_ok() {
        let p = PolicyInput {
            to_is_contract: true,
            recipient: "0xcontract".into(),
            contract_allowlist: vec!["0xcontract".into()],
            ..base()
        };
        assert!(check_policy(&p).is_ok());
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
}
