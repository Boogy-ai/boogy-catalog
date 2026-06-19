//! Signing-key SUBJECT (label) derivation. The label identifies WHOSE key
//! signs; it must derive only from the host-attested principal + chain, never
//! from request input — otherwise a caller could sign as another subject.

use crate::types::AdapterError;

const SEP: char = '#';
const CHAINS: &[&str] = &["evm", "btc", "cosmos", "solana"];

/// Unchecked join — callers MUST pass an already-validated principal.
pub fn wallet_label(principal: &str, chain: &str) -> String {
    format!("{principal}{SEP}{chain}")
}

/// Validate a host-attested principal + chain, then derive the label.
/// Rejects anything that could forge or confuse a subject.
pub fn wallet_label_checked(principal: &str, chain: &str) -> Result<String, AdapterError> {
    let p = principal;
    if p.trim().is_empty() {
        return Err(AdapterError::BadIntent("empty principal".into()));
    }
    if p.chars().any(|c| c == SEP || c.is_whitespace() || c.is_control()) {
        return Err(AdapterError::BadIntent("principal contains a forbidden character".into()));
    }
    if !CHAINS.contains(&chain) {
        return Err(AdapterError::BadIntent(format!("unknown chain: {chain}")));
    }
    Ok(wallet_label(p, chain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_is_principal_hash_chain() {
        assert_eq!(wallet_label("agent_abc", "evm"), "agent_abc#evm");
    }

    #[test]
    fn checked_accepts_normal_principal() {
        assert_eq!(wallet_label_checked("agent_abc", "evm").unwrap(), "agent_abc#evm");
        assert_eq!(wallet_label_checked("boogy://alice/services/govern", "evm").unwrap(),
                   "boogy://alice/services/govern#evm");
    }

    #[test]
    fn checked_rejects_empty_principal() {
        assert!(wallet_label_checked("", "evm").is_err());
        assert!(wallet_label_checked("   ", "evm").is_err());
    }

    #[test]
    fn checked_rejects_separator_injection() {
        // A principal containing the '#' separator could forge another subject.
        assert!(wallet_label_checked("agent_abc#evm", "evm").is_err());
        assert!(wallet_label_checked("a#b", "btc").is_err());
    }

    #[test]
    fn checked_rejects_whitespace_and_control() {
        assert!(wallet_label_checked("agent abc", "evm").is_err());
        assert!(wallet_label_checked("agent\nabc", "evm").is_err());
    }

    #[test]
    fn checked_rejects_bad_chain() {
        assert!(wallet_label_checked("agent_abc", "").is_err());
        assert!(wallet_label_checked("agent_abc", "ethereum").is_err()); // only evm|btc|cosmos|solana
        assert!(wallet_label_checked("agent_abc", "evm#x").is_err());
    }
}
