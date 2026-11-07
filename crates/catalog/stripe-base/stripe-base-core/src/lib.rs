//! Pure, host-testable logic for the stripe-base catalog service.

pub struct CheckoutInput {
    pub amount: i64,        // minor units
    pub currency: String,
    pub product_name: String,
    pub success_url: String,
    pub cancel_url: String,
}

/// Percent-encode a value per `application/x-www-form-urlencoded`.
/// RFC 3986 unreserved chars (`A-Z a-z 0-9 - _ . ~`) pass through; every
/// other byte becomes `%XX`. Space → `%20` (Stripe accepts it; avoids the
/// `+`/literal-`+` ambiguity). Keys are written literally by the caller, so
/// Stripe's bracket syntax (`line_items[0][price_data][currency]`) is preserved.
fn encode_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
        }
    }
    out
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Build the `application/x-www-form-urlencoded` body for Stripe
/// `POST /v1/checkout/sessions` (single line item, mode=payment).
pub fn checkout_form_body(input: &CheckoutInput) -> String {
    let pairs: [(&str, String); 7] = [
        ("mode", "payment".to_string()),
        ("line_items[0][price_data][currency]", encode_value(&input.currency)),
        ("line_items[0][price_data][unit_amount]", input.amount.to_string()),
        (
            "line_items[0][price_data][product_data][name]",
            encode_value(&input.product_name),
        ),
        ("line_items[0][quantity]", "1".to_string()),
        ("success_url", encode_value(&input.success_url)),
        ("cancel_url", encode_value(&input.cancel_url)),
    ];
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Derive the attested `client_service` (which of the provisioner's apps a
/// call belongs to) from the caller's identity.
///
/// A peer call from one of the provisioner's apps carries a workload identity:
/// either the `principal` itself is `boogy://<owner>/services/<name>` (direct
/// peer call), or on an OBO/delegated hop the `principal` is an `agent_*` and
/// the `actor` is the workload doing the delegating. In BOTH cases the ATTESTED
/// service name is host-set and unspoofable, so it takes precedence — a caller
/// can never set this via a request body. The `principal` workload is tried
/// first, then the `actor`.
///
/// Returns `Some(<name>)` when an attested workload is present, else `None`
/// (a direct agent/provisioner caller with no workload — the handler then falls
/// back to an explicit `client_ref` or the owner sentinel).
pub fn client_service_from_workload(principal: &str, actor: Option<&str>) -> Option<String> {
    parse_workload_service(principal).or_else(|| actor.and_then(parse_workload_service))
}

/// Parse `(owner, service_name)` out of a workload URI
/// `boogy://<owner>/services/<name>[@ver]`. Returns `None` for agent principals
/// (`agent_…`), malformed URIs, non-`services` kinds, or URIs with extra path
/// segments. An optional `@version` is stripped.
///
/// The `owner` segment is what the in-handler audience check compares against
/// `self_identity().owner` — to confirm an attested caller is one of the SERVICE
/// OWNER's own apps (cross-owner isolation: a different owner's workload is not a
/// client app of this deployment).
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

/// `(owner, service)` of the ATTESTED caller workload — the `principal` (direct
/// peer call) or the OBO `actor` (delegated hop), tried in that order. `None` for
/// an agent/anonymous caller. The audience check uses `owner` to enforce that the
/// caller is one of THIS service owner's apps, and `service` as the partition key.
pub fn workload_owner_service(principal: &str, actor: Option<&str>) -> Option<(String, String)> {
    parse_workload_owner_service(principal)
        .or_else(|| actor.and_then(parse_workload_owner_service))
}

/// Parse the `<name>` out of a workload URI (DRY wrapper over
/// [`parse_workload_owner_service`]).
fn parse_workload_service(principal: &str) -> Option<String> {
    parse_workload_owner_service(principal).map(|(_, name)| name)
}

#[cfg(test)]
mod client_service_tests {
    use super::*;

    #[test]
    fn derives_from_direct_workload_principal() {
        assert_eq!(
            client_service_from_workload("boogy://alice/services/storefront", None),
            Some("storefront".to_string())
        );
    }

    #[test]
    fn strips_optional_version() {
        assert_eq!(
            client_service_from_workload("boogy://alice/services/storefront@3", None),
            Some("storefront".to_string())
        );
    }

    #[test]
    fn derives_from_actor_on_obo_hop() {
        // Delegated/OBO: principal is an agent, the actor is the workload.
        assert_eq!(
            client_service_from_workload(
                "agent_018f2c3d",
                Some("boogy://alice/services/storefront")
            ),
            Some("storefront".to_string())
        );
    }

    #[test]
    fn principal_workload_wins_over_actor() {
        // If both are workloads, the principal (the immediate caller) is used.
        assert_eq!(
            client_service_from_workload(
                "boogy://alice/services/storefront",
                Some("boogy://alice/services/gateway")
            ),
            Some("storefront".to_string())
        );
    }

    #[test]
    fn none_for_direct_agent_caller() {
        // A direct provisioner/agent call with no workload anywhere → None
        // (the handler falls back to client_ref / the owner sentinel).
        assert_eq!(client_service_from_workload("agent_018f2c3d", None), None);
    }

    #[test]
    fn rejects_malformed_and_non_service_uris() {
        assert_eq!(parse_workload_service("boogy://alice/modules/x"), None);
        assert_eq!(parse_workload_service("boogy://alice/services/"), None);
        assert_eq!(parse_workload_service("boogy://"), None);
        assert_eq!(parse_workload_service(""), None);
        assert_eq!(parse_workload_service("boogy://a/services/x/extra"), None);
        // A malformed principal with a valid actor still resolves via the actor.
        assert_eq!(
            client_service_from_workload("garbage", Some("boogy://alice/services/x")),
            Some("x".to_string())
        );
    }

    #[test]
    fn workload_owner_service_extracts_both() {
        assert_eq!(
            parse_workload_owner_service("boogy://alice/services/storefront"),
            Some(("alice".to_string(), "storefront".to_string()))
        );
        assert_eq!(
            parse_workload_owner_service("boogy://alice/services/storefront@3"),
            Some(("alice".to_string(), "storefront".to_string()))
        );
        // OBO: principal is an agent, the actor carries the workload.
        assert_eq!(
            workload_owner_service("agent_018f", Some("boogy://bob/services/api")),
            Some(("bob".to_string(), "api".to_string()))
        );
        // Agents / malformed → None (so the audience falls through to the
        // owner-agent or denied branch — never silently a client app).
        assert_eq!(parse_workload_owner_service("agent_018f"), None);
        assert_eq!(parse_workload_owner_service("boogy://alice/modules/x"), None);
        assert_eq!(workload_owner_service("agent_018f", None), None);
    }
}

/// The shared `Stripe-Signature` parser; the webhook route calls
/// `stripe_sig::parse`.
pub use boogy_stripe_sig as stripe_sig;

/// True when any `v1` signature in `signed` verifies. `verify` is handed the
/// signed message and one candidate hex signature, and is called for each
/// candidate in header order until one returns `true`. Stripe sends one `v1`
/// per active signing secret, so a rotated secret is accepted whichever
/// position its signature takes.
pub fn any_v1_verifies<F>(signed: &stripe_sig::SignedPayload, mut verify: F) -> bool
where
    F: FnMut(&[u8], &str) -> bool,
{
    signed.v1.iter().any(|sig| verify(&signed.message, sig))
}

#[cfg(test)]
mod sig_tests {
    use super::*;

    #[test]
    fn catalog_accepts_a_rotated_secret() {
        // The header carries a signature for the old secret first and the new
        // one second; only the second verifies against the configured secret.
        let signed = stripe_sig::parse("t=1000,v1=old,v1=new", b"{}", 1000, 300).unwrap();
        let mut tried = Vec::new();
        let ok = any_v1_verifies(&signed, |msg, sig| {
            assert_eq!(msg, b"1000.{}");
            tried.push(sig.to_string());
            sig == "new"
        });
        assert!(ok);
        assert_eq!(tried, ["old", "new"]);
    }

    #[test]
    fn no_matching_v1_is_refused() {
        let signed = stripe_sig::parse("t=1000,v1=a,v1=b", b"{}", 1000, 300).unwrap();
        assert!(!any_v1_verifies(&signed, |_, _| false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encodes_single_line_item_checkout() {
        let b = checkout_form_body(&CheckoutInput {
            amount: 2000, currency: "usd".into(), product_name: "Pro Plan".into(),
            success_url: "https://app/ok".into(), cancel_url: "https://app/no".into(),
        });
        assert!(b.contains("mode=payment"));
        assert!(b.contains("line_items[0][price_data][currency]=usd"));
        assert!(b.contains("line_items[0][price_data][unit_amount]=2000"));
        assert!(b.contains("line_items[0][quantity]=1"));
        assert!(b.contains("success_url=https%3A%2F%2Fapp%2Fok"));
    }

    #[test]
    fn percent_encodes_special_chars_in_product_name() {
        // A product name containing space, `&`, and `=` must not break the
        // form structure: each is percent-encoded inside the value only.
        let b = checkout_form_body(&CheckoutInput {
            amount: 999,
            currency: "eur".into(),
            product_name: "A & B = C".into(),
            success_url: "https://x".into(),
            cancel_url: "https://y".into(),
        });
        assert!(
            b.contains("line_items[0][price_data][product_data][name]=A%20%26%20B%20%3D%20C"),
            "got: {b}"
        );
        // Exactly two `=` separators from our own pairs touch the name region;
        // the value's `=` is encoded, so the structural key/value count is intact.
        assert_eq!(b.matches("&line_items[0][price_data][product_data][name]=").count(), 1);
        assert!(b.contains("line_items[0][price_data][currency]=eur"));
        assert!(b.contains("line_items[0][price_data][unit_amount]=999"));
    }

    #[test]
    fn different_currency_and_amount() {
        let b = checkout_form_body(&CheckoutInput {
            amount: 150_000,
            currency: "jpy".into(),
            product_name: "Annual".into(),
            success_url: "https://app/done?ref=abc".into(),
            cancel_url: "https://app/back".into(),
        });
        assert!(b.contains("line_items[0][price_data][currency]=jpy"));
        assert!(b.contains("line_items[0][price_data][unit_amount]=150000"));
        // `?`, `=` in the URL query are encoded so they can't be mistaken for
        // form delimiters.
        assert!(b.contains("success_url=https%3A%2F%2Fapp%2Fdone%3Fref%3Dabc"), "got: {b}");
    }
}
