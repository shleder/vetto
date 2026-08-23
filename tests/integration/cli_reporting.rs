//! CLI-only reporting/completion tests; these do not require a sandbox tier.

use crate::common::*;
use std::process::Command;

#[test]
fn completions_are_available_for_all_requested_shells() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let output = Command::new(vetto_bin())
            .args(["completions", shell])
            .output()
            .expect("spawn completion command");
        assert!(
            output.status.success(),
            "completion failed for {shell}: {}",
            stderr(&output)
        );
        assert!(
            !output.stdout.is_empty(),
            "completion output empty for {shell}"
        );
    }
}

#[test]
fn report_compare_emits_numeric_deltas() {
    let project = TempProject::new("report-compare");
    let left = project.path().join("left.json");
    let right = project.path().join("right.json");
    write_file(
        &left,
        r#"{"duration_secs":2,"exit_code":0,"events_total":4,"file_reads":1,"file_writes":1,"blocked_attempts":[{"count":1}],"net_requests":[{"allowed":false}]}"#,
    );
    write_file(
        &right,
        r#"{"duration_secs":5,"exit_code":1,"events_total":9,"file_reads":3,"file_writes":2,"blocked_attempts":[{"count":3}],"net_requests":[{"allowed":false},{"allowed":true}]}"#,
    );

    let output = Command::new(vetto_bin())
        .args(["report", "compare"])
        .arg(&left)
        .arg(&right)
        .output()
        .expect("spawn report compare");
    assert!(
        output.status.success(),
        "report compare failed: {}",
        stderr(&output)
    );
    let text = stdout(&output);
    assert!(text.contains(r#""duration_secs": 3"#), "stdout: {text}");
    assert!(text.contains(r#""blocked_attempts": 2"#), "stdout: {text}");
    assert!(text.contains(r#""net_denied": 0"#), "stdout: {text}");
}
