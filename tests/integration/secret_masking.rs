//! BEST-EFFORT secret sanitizer in artifacts (jsonl + json report).
//! The sanitizer is a courtesy layer; these tests pin its obvious wins.

use crate::common::*;

#[test]
fn jsonl_redacts_aws_key_in_agent_argv() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("sanit");
    let jsonl = proj.path().join("s.jsonl");
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--jsonl",
            jsonl.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &format!("echo argv-carrying {secret}; sleep 2"),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let log = std::fs::read_to_string(&jsonl).unwrap_or_default();
    assert!(!log.contains(secret), "AWS key leaked into jsonl: {log}");
    assert!(
        log.contains("AKIA[REDACTED]"),
        "redaction marker missing: {log}"
    );
}

#[test]
fn json_report_is_sanitized_and_written() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("repjson");
    let secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--report",
            "json",
            "--",
            "/bin/sh",
            "-c",
            &format!("echo {secret}"),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let mut found = false;
    for entry in std::fs::read_dir(proj.path()).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("vetto-report-") && name.ends_with(".json") {
            found = true;
            let body = std::fs::read_to_string(entry.path()).unwrap_or_default();
            assert!(!body.contains(secret), "token leaked into report: {body}");
        }
    }
    assert!(found, "no json report written");
}
