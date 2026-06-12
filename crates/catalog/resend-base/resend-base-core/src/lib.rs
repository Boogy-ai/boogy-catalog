//! Pure, host-testable logic for the resend-base catalog service.
//!
//! Three pieces, all unit-tested off-wasm:
//! - [`render`] — `{{ variable }}` template substitution via the `upon` engine.
//! - [`resend_body`] — shapes the Resend `POST /emails` JSON body.
//! - [`workload_owner`] — extracts the owner from a workload URI (the
//!   operator-identity check).

use std::collections::BTreeMap;

/// A template render failure. The service maps this onto a `400` — a template
/// that references a variable the caller didn't supply is a caller error, not
/// something to ship to the recipient as a literal `{{placeholder}}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderError {
    pub message: String,
}

impl RenderError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RenderError {}

/// Render a `{{ variable }}` template against `vars` (key/value pairs).
///
/// Uses the `upon` engine: `{{ name }}` and `{{name}}` are equivalent
/// (whitespace-insensitive), and substitution is single-pass — a substituted
/// value is never re-scanned, so a value like `{{other}}` injected via `vars`
/// is emitted literally, not expanded (an injection guard).
///
/// Unlike a leave-unknown-placeholders-intact renderer, a **missing variable
/// is an error** (`upon` resolves strictly): the caller finds out at send time
/// rather than a customer receiving a raw `{{code}}`.
pub fn render(template: &str, vars: &[(String, String)]) -> Result<String, RenderError> {
    let engine = upon::Engine::new();
    let compiled = engine
        .compile(template)
        .map_err(|e| RenderError::new(format!("template compile: {e}")))?;
    let ctx: BTreeMap<&str, &str> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    compiled
        .render(&engine, &ctx)
        .to_string()
        .map_err(|e| RenderError::new(format!("template render: {e}")))
}

#[derive(Debug, Clone, PartialEq)]
pub struct SendInput {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub html: Option<String>,
    pub text: Option<String>,
}

/// Build the Resend `POST /emails` JSON body bytes.
pub fn resend_body(input: &SendInput) -> Vec<u8> {
    let mut map = serde_json::Map::new();
    map.insert("from".into(), input.from.clone().into());
    map.insert("to".into(), serde_json::json!([input.to]));
    map.insert("subject".into(), input.subject.clone().into());
    if let Some(html) = &input.html { map.insert("html".into(), html.clone().into()); }
    if let Some(text) = &input.text { map.insert("text".into(), text.clone().into()); }
    serde_json::to_vec(&serde_json::Value::Object(map)).expect("serialize resend body")
}

/// Extract the `<owner>` from a workload URI `boogy://<owner>/services/<name>[@ver]`.
///
/// Returns `None` for agent principals (`agent_…`), malformed URIs, non-`services`
/// kinds, or URIs with extra path segments. Used by the service's operator check:
/// a caller whose attested workload owner matches the instance owner is the
/// operator (the provisioner's own backend or dashboard).
pub fn workload_owner(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("boogy://")?; // "<owner>/services/<name>[@ver]"
    let mut parts = rest.split('/');
    let owner = parts.next().filter(|s| !s.is_empty())?;
    if parts.next()? != "services" {
        return None;
    }
    // Require a non-empty service-name segment, but reject extra path segments
    // (a bare workload URI is exactly three components).
    parts.next().filter(|s| !s.is_empty())?;
    if parts.next().is_some() {
        return None;
    }
    Some(owner.to_string())
}

#[cfg(test)]
mod render_tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn substitutes_known_vars() {
        let out = render(
            "Hi {{name}}, your code is {{ code }}.",
            &vars(&[("name", "Ada"), ("code", "42")]),
        )
        .unwrap();
        assert_eq!(out, "Hi Ada, your code is 42.");
    }

    #[test]
    fn whitespace_insensitive() {
        let a = render("{{ name }}", &vars(&[("name", "Ada")])).unwrap();
        let b = render("{{name}}", &vars(&[("name", "Ada")])).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, "Ada");
    }

    #[test]
    fn missing_var_is_an_error() {
        let err = render("Hi {{name}} {{missing}}", &vars(&[("name", "Ada")]))
            .expect_err("missing var must error");
        assert!(err.to_string().contains("render"), "err = {err}");
    }

    #[test]
    fn does_not_resubstitute_substituted_values() {
        // `a` resolves to the literal "{{b}}"; it must NOT be expanded to "INJECTED".
        let out = render("{{a}}", &vars(&[("a", "{{b}}"), ("b", "INJECTED")])).unwrap();
        assert_eq!(out, "{{b}}");
    }

    #[test]
    fn malformed_template_is_an_error() {
        // An unbalanced delimiter fails to compile.
        assert!(render("Hi {{ name ", &vars(&[("name", "Ada")])).is_err());
    }
}

#[cfg(test)]
mod resend_tests {
    use super::*;

    #[test]
    fn builds_minimal_resend_body() {
        let body = resend_body(&SendInput {
            from: "a@x.com".into(), to: "b@y.com".into(), subject: "Hi".into(),
            html: Some("<p>Hi</p>".into()), text: None,
        });
        let s = String::from_utf8(body).unwrap();
        assert!(s.contains("\"from\":\"a@x.com\""));
        assert!(s.contains("\"to\":[\"b@y.com\"]"));
        assert!(s.contains("\"subject\":\"Hi\""));
        assert!(s.contains("\"html\":\"<p>Hi</p>\""));
        assert!(!s.contains("\"text\""), "text omitted when None");
    }
}

#[cfg(test)]
mod workload_owner_tests {
    use super::*;

    #[test]
    fn extracts_owner_from_workload() {
        assert_eq!(
            workload_owner("boogy://alice/services/storefront"),
            Some("alice".to_string())
        );
    }

    #[test]
    fn strips_optional_version() {
        assert_eq!(
            workload_owner("boogy://alice/services/storefront@3"),
            Some("alice".to_string())
        );
    }

    #[test]
    fn rejects_agents_and_malformed() {
        assert_eq!(workload_owner("agent_018f2c3d"), None);
        assert_eq!(workload_owner("boogy://alice/modules/x"), None);
        assert_eq!(workload_owner("boogy://alice/services/"), None);
        assert_eq!(workload_owner("boogy://"), None);
        assert_eq!(workload_owner(""), None);
        assert_eq!(workload_owner("boogy://a/services/x/extra"), None);
    }
}
