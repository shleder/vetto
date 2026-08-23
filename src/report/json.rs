//! JSON report (pretty-printed serde output of SessionStats).

use super::stats::SessionStats;
use crate::logger::sanitizer;
use serde_json::Value;

pub fn render(stats: &SessionStats) -> String {
    let Ok(mut value) = serde_json::to_value(stats) else {
        return "{}\n".to_string();
    };
    sanitize_value(&mut value);
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}\n".to_string())
}

/// Redact every JSON string value, including strings nested in maps and
/// records. Walking the serialized value keeps the report schema and all
/// non-string JSON types unchanged while ensuring a newly added user-facing
/// string field cannot accidentally bypass the report sanitizer.
fn sanitize_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = sanitizer::sanitize_line(text),
        Value::Array(items) => {
            for item in items {
                sanitize_value(item);
            }
        }
        Value::Object(fields) => {
            let entries = std::mem::take(fields);
            for (key, mut value) in entries {
                let key = sanitizer::sanitize_line(&key);
                sanitize_value(&mut value);
                fields.insert(key, value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn redacts_secrets_in_every_user_string_without_changing_schema_types() {
        let secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        let mut counts = BTreeMap::new();
        counts.insert("event".to_string(), 7);
        counts.insert(format!("secret-{secret}"), 1);
        let mut op_counts = BTreeMap::new();
        op_counts.insert("other".to_string(), 2);
        let stats = SessionStats {
            tier: format!("tier-{secret}"),
            net_mode: format!("token={secret}"),
            profile: format!("profile-{secret}"),
            counts,
            op_counts,
            blocked_attempts: vec![super::super::stats::BlockedRecord {
                path: format!("/tmp/{secret}"),
                comm: format!("comm-{secret}"),
                source: format!("source-{secret}"),
                count: 3,
            }],
            net_requests: vec![super::super::stats::NetRecord {
                host: format!("{secret}.example"),
                port: 443,
                allowed: false,
            }],
            notices: vec![format!("password={secret}")],
            ..SessionStats::default()
        };

        let rendered = render(&stats);
        assert!(
            !rendered.contains(secret),
            "secret leaked in JSON: {rendered}"
        );
        let value: Value = serde_json::from_str(&rendered).expect("rendered JSON is valid");
        assert!(value["tier"].is_string());
        assert!(value["duration_secs"].is_number());
        assert!(value["blocked_attempts"][0]["count"].is_number());
        assert!(value["net_requests"][0]["allowed"].is_boolean());
        assert_eq!(value["counts"]["event"].as_u64(), Some(7));
        assert!(
            rendered.lines().all(|line| !line.contains(secret)),
            "secret map key leaked: {rendered}"
        );
    }

    #[test]
    fn ordinary_json_strings_are_preserved() {
        let stats = SessionStats {
            profile: "/workspace/project".to_string(),
            notices: vec!["completed successfully".to_string()],
            ..SessionStats::default()
        };
        let value: Value = serde_json::from_str(&render(&stats)).expect("valid JSON");
        assert_eq!(value["profile"], "/workspace/project");
        assert_eq!(value["notices"][0], "completed successfully");
    }

    #[test]
    fn rendered_report_contains_every_schema_required_field() {
        let stats = SessionStats::default();
        let value: Value = serde_json::from_str(&render(&stats)).expect("valid JSON");
        let schema: Value =
            serde_json::from_str(include_str!("../../docs/schema/session-stats.schema.json"))
                .expect("valid session stats schema");
        for required in schema["required"].as_array().expect("required array") {
            let field = required.as_str().expect("required field name");
            assert!(value.get(field).is_some(), "missing schema field {field}");
        }
    }
}
