//! Public Rescue JSON contract and privacy checks.
//!
//! These tests deliberately exercise the binary boundary instead of private
//! report helpers.  They keep the public shape and the best-effort redaction
//! promise covered without adding a JSON-Schema runtime dependency.

#![allow(clippy::all)]

use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ROOT: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = NEXT_TEMP_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vetto-rescue-output-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create rescue output fixture root");
        Self(path)
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture parent");
        fs::write(&path, bytes).expect("fixture bytes");
        path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_rescue(root: &Path, args: &[String]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vetto"));
    command.arg("rescue").arg("--root").arg(root).arg("--json");
    for arg in args {
        command.arg(OsString::from(arg));
    }
    command.output().expect("run vetto rescue")
}

fn stdout_json(output: &Output) -> (String, Value) {
    assert!(
        output.status.success(),
        "rescue command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout.clone()).expect("UTF-8 rescue JSON");
    let value = serde_json::from_str(&text).expect("parse rescue JSON");
    (text, value)
}

fn assert_no_internal_source_field(value: &Value) {
    match value {
        Value::Object(fields) => {
            assert!(!fields.contains_key("source_path"));
            assert!(!fields.contains_key("sourcePath"));
            for child in fields.values() {
                assert_no_internal_source_field(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_no_internal_source_field(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn assert_scan_shape(value: &Value) {
    let object = value.as_object().expect("scan object");
    assert!(object.contains_key("status"));
    assert!(object.contains_key("sessions"));
    assert!(object.contains_key("discovery"));

    let status = value["status"].as_object().expect("scan status");
    for key in ["adapter", "availability", "support_level", "reason"] {
        assert!(status.contains_key(key), "missing status.{key}");
    }

    let sessions = value["sessions"].as_array().expect("scan sessions");
    for session in sessions {
        let session = session.as_object().expect("session object");
        for key in [
            "adapter",
            "key",
            "relative_path",
            "bytes",
            "modified_unix_secs",
        ] {
            assert!(session.contains_key(key), "missing session.{key}");
        }
    }

    let discovery = value["discovery"].as_object().expect("scan discovery");
    for key in [
        "mode",
        "scope",
        "source",
        "complete",
        "limit",
        "candidate_count",
        "returned_count",
    ] {
        assert!(discovery.contains_key(key), "missing discovery.{key}");
    }
}

fn assert_diagnose_shape(value: &Value) {
    let object = value.as_object().expect("diagnose object");
    for key in [
        "adapter",
        "key",
        "relative_path",
        "bytes",
        "sha256",
        "health",
        "records",
        "malformed_records",
        "oversized_records",
        "terminated_with_newline",
        "findings",
        "notices",
    ] {
        assert!(object.contains_key(key), "missing diagnose.{key}");
    }
    assert_eq!(value["sha256"].as_str().expect("diagnose hash").len(), 64);
    assert!(value["findings"].is_array());
    assert!(value["notices"].is_array());
}

fn assert_receipt_shape(value: &Value) {
    let object = value.as_object().expect("receipt object");
    for key in [
        "adapter",
        "source_key",
        "destination",
        "bytes",
        "sha256",
        "source_preserved",
    ] {
        assert!(object.contains_key(key), "missing receipt.{key}");
    }
    assert_eq!(value["sha256"].as_str().expect("receipt hash").len(), 64);
    assert_eq!(value["source_preserved"], true);
}

#[test]
fn schema_declares_scan_diagnose_and_copy_receipt_variants() {
    let schema_text = include_str!("../docs/schema/rescue-output-v1.schema.json");
    assert!(!schema_text.contains("\"source_path\""));
    assert!(!schema_text.contains("\"sourcePath\""));

    let schema: Value = serde_json::from_str(schema_text).expect("valid Rescue output schema");
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["type"], "object");

    let variants = schema["anyOf"].as_array().expect("schema variants");
    assert_eq!(variants.len(), 3);
    for variant in variants {
        let reference = variant["$ref"].as_str().expect("schema variant ref");
        assert!(reference.starts_with("#/$defs/"));
    }

    let definitions = schema["$defs"].as_object().expect("schema definitions");
    for name in ["scan", "diagnose", "receipt"] {
        let definition = definitions.get(name).expect("public result definition");
        assert_eq!(definition["type"], "object");
        assert_eq!(definition["additionalProperties"], true);
    }
}

#[test]
fn scan_json_is_public_repeatable_and_redacts_secret_shaped_names() {
    let temp = TempRoot::new("scan");
    let secret = "ghp_0123456789abcdefghijklmnopqrstuv";
    temp.write(
        &format!("sessions/{secret}.jsonl"),
        b"{\"type\":\"turn\"}\n",
    );

    let args = vec!["scan".to_string(), "--all".to_string()];
    let first = run_rescue(&temp.0, &args);
    let second = run_rescue(&temp.0, &args);
    let (first_text, first_json) = stdout_json(&first);
    let (second_text, second_json) = stdout_json(&second);

    assert_eq!(
        first_text, second_text,
        "stable input must produce stable JSON"
    );
    assert_eq!(first_json, second_json);
    assert_scan_shape(&first_json);
    assert_no_internal_source_field(&first_json);
    assert!(first_text.contains("ghp_[REDACTED]"));
    assert!(!first_text.contains(secret));
}

#[test]
fn diagnose_snapshot_and_fork_match_public_shapes() {
    let temp = TempRoot::new("operations");
    let session_key = "sessions/example.jsonl";
    temp.write(
        session_key,
        b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"synthetic\"}}\n",
    );

    let diagnose = run_rescue(&temp.0, &["diagnose".to_string(), session_key.to_string()]);
    let (_, diagnose_json) = stdout_json(&diagnose);
    assert_diagnose_shape(&diagnose_json);
    assert_no_internal_source_field(&diagnose_json);

    // Recovery output must live OUTSIDE the agent state root: the rescue
    // contract refuses copy destinations inside it (fail-closed).
    let recovery_root = TempRoot::new("recovery");
    let recovery = recovery_root.0.join("out");
    fs::create_dir_all(&recovery).expect("recovery directory");
    let snapshot_path = recovery.join("snapshot.jsonl");
    let snapshot_args = vec![
        "snapshot".to_string(),
        session_key.to_string(),
        "--output".to_string(),
        snapshot_path.to_string_lossy().into_owned(),
    ];
    let snapshot = run_rescue(&temp.0, &snapshot_args);
    let (_, snapshot_json) = stdout_json(&snapshot);
    assert_receipt_shape(&snapshot_json);
    assert_no_internal_source_field(&snapshot_json);

    let fork_path = recovery.join("fork.jsonl");
    let fork_args = vec![
        "fork".to_string(),
        session_key.to_string(),
        "--output".to_string(),
        fork_path.to_string_lossy().into_owned(),
    ];
    let fork = run_rescue(&temp.0, &fork_args);
    let (_, fork_json) = stdout_json(&fork);
    assert_receipt_shape(&fork_json);
    assert_no_internal_source_field(&fork_json);
}
