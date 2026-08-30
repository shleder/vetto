//! Integration tests for `vetto redteam` command.

use crate::common::*;

#[test]
fn test_redteam_command_text_output() {
    let proj = TempProject::new("redteam_test");
    let out = run_vetto_in(proj.path(), &["redteam"]);
    let text = stdout(&out);
    assert!(text.contains("vetto redteam"), "output: {text}");
    assert!(text.contains("Redteam Battery:"), "output: {text}");
}

#[test]
fn test_redteam_command_json_output() {
    let proj = TempProject::new("redteam_json");
    let out = run_vetto_in(proj.path(), &["redteam", "--json"]);
    let text = stdout(&out);
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid json output");
    assert!(json.get("results").is_some());
    assert!(json.get("passed").is_some());
    assert!(json.get("success").is_some());
    let results = json["results"].as_array().expect("results array");
    assert_eq!(results.len(), 8, "must contain exactly 8 attacks");
}
