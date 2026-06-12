//! Pure, host-testable logic for the email-sender catalog service.

/// Substitute `{{var}}` placeholders in `template` from `vars`.
/// Unknown placeholders are left intact. `{{ name }}` == `{{name}}`.
/// Single-pass: substituted values are never re-scanned for further substitution.
pub fn render(template: &str, vars: &[(String, String)]) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        // Look for `{{` at position i.
        if i + 1 < len && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            // Find the closing `}}`.
            if let Some(rel) = template[i + 2..].find("}}") {
                let close = i + 2 + rel;
                let inner = &template[i + 2..close];
                let key = inner.trim();
                // Look up the trimmed key in vars.
                if let Some((_, v)) = vars.iter().find(|(k, _)| k == key) {
                    out.push_str(v);
                } else {
                    // Unknown placeholder — emit verbatim (original spacing preserved).
                    out.push_str(&template[i..close + 2]);
                }
                i = close + 2;
                continue;
            }
        }
        // Not the start of a placeholder — emit one char literally.
        out.push(template[i..].chars().next().unwrap());
        i += template[i..].chars().next().unwrap().len_utf8();
    }
    out
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
mod tests {
    use super::*;

    #[test]
    fn substitutes_known_vars_and_keeps_unknown() {
        let out = render(
            "Hi {{name}}, your code is {{ code }}. {{missing}}",
            &[("name".into(), "Ada".into()), ("code".into(), "42".into())],
        );
        assert_eq!(out, "Hi Ada, your code is 42. {{missing}}");
    }

    #[test]
    fn does_not_resubstitute_substituted_values() {
        let out = render(
            "{{a}}",
            &[("a".into(), "{{b}}".into()), ("b".into(), "INJECTED".into())],
        );
        assert_eq!(out, "{{b}}");
    }
}
