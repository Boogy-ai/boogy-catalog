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

/// Parse a bare workload URI `boogy://<owner>/services/<name>[@ver]` into
/// `(owner, service)`. Returns `None` for anything that is NOT exactly a
/// 3-segment `services` workload URI: agent principals (`agent_…`), `modules`
/// URIs, or URIs with extra path segments. An optional `@version` is stripped.
///
/// Used by the `/admin` gate to detect an ATTESTED workload caller — `/admin`
/// is agent-only, so any workload (even one of the service owner's own apps) is
/// rejected. Mirrors the stripe-base parser.
pub fn parse_workload_owner_service(uri: &str) -> Option<(String, String)> {
    let rest = uri.strip_prefix("boogy://")?; // "<owner>/services/<name>[@ver]"
    let mut parts = rest.split('/');
    let owner = parts.next().filter(|s| !s.is_empty())?;
    if parts.next()? != "services" {
        return None;
    }
    let name_ver = parts.next().filter(|s| !s.is_empty())?;
    if parts.next().is_some() {
        return None; // extra path segments → not a bare workload URI
    }
    let name = name_ver.split('@').next().filter(|s| !s.is_empty())?;
    Some((owner.to_string(), name.to_string()))
}

/// `(owner, service)` of the attested caller workload — the `principal` (direct
/// peer call) or the OBO `actor` (delegated hop), tried in that order. `None`
/// for an agent/anonymous caller.
pub fn workload_owner_service(principal: &str, actor: Option<&str>) -> Option<(String, String)> {
    parse_workload_owner_service(principal)
        .or_else(|| actor.and_then(parse_workload_owner_service))
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

    // --- Workload-URI parsing (#5: /admin must reject attested workloads) ---

    #[test]
    fn parses_bare_services_workload() {
        assert_eq!(
            parse_workload_owner_service("boogy://alice/services/wallet"),
            Some(("alice".into(), "wallet".into()))
        );
    }

    #[test]
    fn strips_version_suffix() {
        assert_eq!(
            parse_workload_owner_service("boogy://alice/services/wallet@3"),
            Some(("alice".into(), "wallet".into()))
        );
    }

    #[test]
    fn agent_principal_is_not_a_workload() {
        assert_eq!(parse_workload_owner_service("agent_018f2a"), None);
    }

    #[test]
    fn modules_uri_is_not_a_services_workload() {
        assert_eq!(parse_workload_owner_service("boogy://alice/modules/x"), None);
    }

    #[test]
    fn extra_path_segments_rejected() {
        assert_eq!(parse_workload_owner_service("boogy://alice/services/wallet/extra"), None);
    }

    #[test]
    fn empty_segments_rejected() {
        assert_eq!(parse_workload_owner_service("boogy:///services/wallet"), None);
        assert_eq!(parse_workload_owner_service("boogy://alice/services/"), None);
    }

    #[test]
    fn workload_owner_service_falls_back_to_actor() {
        // direct principal is an agent; the OBO actor is the workload.
        assert_eq!(
            workload_owner_service("agent_018f", Some("boogy://bob/services/api")),
            Some(("bob".into(), "api".into()))
        );
        assert_eq!(workload_owner_service("agent_018f", None), None);
    }
}
