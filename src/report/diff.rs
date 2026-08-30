//! Session comparison (`vetto diff-sessions <id1> <id2>`) (Feature 43).
//!
//! Compares two JSON session audit reports to surface changed metric counters,
//! newly observed security violations, resolved violations, and network differences.
//! Essential for policy A/B testing and regression detection.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::clean;
pub use super::diff_project::{ProjectDiff, ProjectManifest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDelta {
    pub left: i64,
    pub right: i64,
    pub delta: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDiffReport {
    pub session1: String,
    pub session2: String,
    pub duration_secs: MetricDelta,
    pub exit_code: MetricDelta,
    pub events_total: MetricDelta,
    pub file_reads: MetricDelta,
    pub file_writes: MetricDelta,
    pub blocked_attempts: MetricDelta,
    pub net_denied: MetricDelta,
    pub suspicious_signals: MetricDelta,
    pub new_blocked_attempts: Vec<serde_json::Value>,
    pub resolved_blocked_attempts: Vec<serde_json::Value>,
    pub new_network_requests: Vec<serde_json::Value>,
    pub removed_network_requests: Vec<serde_json::Value>,
    pub new_suspicious_signals: Vec<serde_json::Value>,
}

/// Resolves a session reference (exact path, report filename, or session ID) to a JSON file.
pub fn resolve_report_path(arg: &Path) -> Result<PathBuf> {
    if arg.is_file() {
        return Ok(arg.to_path_buf());
    }
    let with_json = arg.with_extension("json");
    if with_json.is_file() {
        return Ok(with_json);
    }

    // Check in .vetto/reports/
    let in_dot_vetto = Path::new(".vetto").join("reports").join(arg);
    if in_dot_vetto.is_file() {
        return Ok(in_dot_vetto);
    }
    let in_dot_vetto_json = Path::new(".vetto").join("reports").join(&with_json);
    if in_dot_vetto_json.is_file() {
        return Ok(in_dot_vetto_json);
    }

    // Check ~/.vetto/reports/
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let in_home = home.join(".vetto").join("reports").join(arg);
        if in_home.is_file() {
            return Ok(in_home);
        }
        let in_home_json = home.join(".vetto").join("reports").join(&with_json);
        if in_home_json.is_file() {
            return Ok(in_home_json);
        }
    }

    Ok(arg.to_path_buf())
}

/// Computes the structured diff between two JSON session reports.
pub fn compute_session_diff(
    left_json: &serde_json::Value,
    right_json: &serde_json::Value,
    name1: &str,
    name2: &str,
) -> SessionDiffReport {
    fn get_i64(v: &serde_json::Value, key: &str) -> i64 {
        v.get(key).and_then(serde_json::Value::as_i64).unwrap_or(0)
    }

    fn metric_delta(l: &serde_json::Value, r: &serde_json::Value, key: &str) -> MetricDelta {
        let left = get_i64(l, key);
        let right = get_i64(r, key);
        MetricDelta {
            left,
            right,
            delta: right.saturating_sub(left),
        }
    }

    fn count_blocked(v: &serde_json::Value) -> i64 {
        v.get("blocked_attempts")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| r.get("count").and_then(serde_json::Value::as_i64))
                    .sum()
            })
            .unwrap_or(0)
    }

    fn count_net_denied(v: &serde_json::Value) -> i64 {
        v.get("net_requests")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter(|r| {
                        r.get("allowed").and_then(serde_json::Value::as_bool) == Some(false)
                    })
                    .count() as i64
            })
            .unwrap_or(0)
    }

    fn count_suspicious(v: &serde_json::Value) -> i64 {
        v.get("suspicious_signals")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| r.get("count").and_then(serde_json::Value::as_i64))
                    .sum()
            })
            .unwrap_or(0)
    }

    let left_blocked = count_blocked(left_json);
    let right_blocked = count_blocked(right_json);

    let left_net_denied = count_net_denied(left_json);
    let right_net_denied = count_net_denied(right_json);

    let left_suspicious = count_suspicious(left_json);
    let right_suspicious = count_suspicious(right_json);

    let new_blocked = set_difference(
        right_json,
        left_json,
        "blocked_attempts",
        &["path", "comm", "source"],
    );
    let resolved_blocked = set_difference(
        left_json,
        right_json,
        "blocked_attempts",
        &["path", "comm", "source"],
    );

    let new_network = set_difference(
        right_json,
        left_json,
        "net_requests",
        &["host", "port", "allowed"],
    );
    let removed_network = set_difference(
        left_json,
        right_json,
        "net_requests",
        &["host", "port", "allowed"],
    );

    let new_suspicious = set_difference(
        right_json,
        left_json,
        "suspicious_signals",
        &["category", "severity", "subject", "reason"],
    );

    SessionDiffReport {
        session1: name1.to_string(),
        session2: name2.to_string(),
        duration_secs: metric_delta(left_json, right_json, "duration_secs"),
        exit_code: metric_delta(left_json, right_json, "exit_code"),
        events_total: metric_delta(left_json, right_json, "events_total"),
        file_reads: metric_delta(left_json, right_json, "file_reads"),
        file_writes: metric_delta(left_json, right_json, "file_writes"),
        blocked_attempts: MetricDelta {
            left: left_blocked,
            right: right_blocked,
            delta: right_blocked.saturating_sub(left_blocked),
        },
        net_denied: MetricDelta {
            left: left_net_denied,
            right: right_net_denied,
            delta: right_net_denied.saturating_sub(left_net_denied),
        },
        suspicious_signals: MetricDelta {
            left: left_suspicious,
            right: right_suspicious,
            delta: right_suspicious.saturating_sub(left_suspicious),
        },
        new_blocked_attempts: new_blocked,
        resolved_blocked_attempts: resolved_blocked,
        new_network_requests: new_network,
        removed_network_requests: removed_network,
        new_suspicious_signals: new_suspicious,
    }
}

fn set_difference(
    source: &serde_json::Value,
    reference: &serde_json::Value,
    array_key: &str,
    fields: &[&str],
) -> Vec<serde_json::Value> {
    fn key_of(record: &serde_json::Value, fields: &[&str]) -> String {
        fields
            .iter()
            .map(|f| record.get(*f).map(|v| v.to_string()).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("||")
    }

    let ref_keys: BTreeSet<String> = reference
        .get(array_key)
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .map(|rec| key_of(rec, fields))
        .collect();

    source
        .get(array_key)
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|rec| !ref_keys.contains(&key_of(rec, fields)))
        .cloned()
        .collect()
}

pub fn run_diff_sessions(id1: &Path, id2: &Path, json_output: bool) -> Result<()> {
    let p1 = resolve_report_path(id1)?;
    let p2 = resolve_report_path(id2)?;

    let text1 = std::fs::read_to_string(&p1)
        .with_context(|| format!("read session report {}", p1.display()))?;
    let text2 = std::fs::read_to_string(&p2)
        .with_context(|| format!("read session report {}", p2.display()))?;

    let json1: serde_json::Value = serde_json::from_str(&text1)
        .with_context(|| format!("parse JSON from {}", p1.display()))?;
    let json2: serde_json::Value = serde_json::from_str(&text2)
        .with_context(|| format!("parse JSON from {}", p2.display()))?;

    let diff = compute_session_diff(
        &json1,
        &json2,
        &clean(&p1.display().to_string()),
        &clean(&p2.display().to_string()),
    );

    if json_output {
        println!("{}", serde_json::to_string_pretty(&diff)?);
        return Ok(());
    }

    println!("=== vetto session diff ===");
    println!("Base (Left):    {}", diff.session1);
    println!("Target (Right): {}\n", diff.session2);

    println!(
        "{:<22}  {:>10}  {:>10}  {:>10}",
        "METRIC", "BASE", "TARGET", "DELTA"
    );
    println!("{:-<22}  {:-<10}  {:-<10}  {:-<10}", "", "", "", "");

    let rows = [
        ("Duration (s)", diff.duration_secs),
        ("Exit Code", diff.exit_code),
        ("Events Total", diff.events_total),
        ("File Reads", diff.file_reads),
        ("File Writes", diff.file_writes),
        ("Blocked Access", diff.blocked_attempts),
        ("Network Denied", diff.net_denied),
        ("Suspicious Signals", diff.suspicious_signals),
    ];

    for (label, d) in rows {
        let delta_str = if d.delta > 0 {
            format!("+{}", d.delta)
        } else {
            d.delta.to_string()
        };
        println!(
            "{:<22}  {:>10}  {:>10}  {:>10}",
            label, d.left, d.right, delta_str
        );
    }

    if !diff.new_blocked_attempts.is_empty() {
        println!("\n[!] New Blocked Attempts in Target:");
        for b in &diff.new_blocked_attempts {
            let path = b
                .get("path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let comm = b
                .get("comm")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let source = b
                .get("source")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            println!("  + {} (comm={}, source={})", path, comm, source);
        }
    }

    if !diff.resolved_blocked_attempts.is_empty() {
        println!("\n[-] Resolved Blocked Attempts (present in base, absent in target):");
        for b in &diff.resolved_blocked_attempts {
            let path = b
                .get("path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let comm = b
                .get("comm")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            println!("  - {} (comm={})", path, comm);
        }
    }

    if !diff.new_network_requests.is_empty() {
        println!("\n[+] New Network Requests:");
        for n in &diff.new_network_requests {
            let host = n
                .get("host")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let port = n
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let allowed = n
                .get("allowed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            println!(
                "  + {}:{} ({})",
                host,
                port,
                if allowed { "allow" } else { "DENIED" }
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_diff_calculates_metric_deltas_and_set_differences() {
        let left = serde_json::json!({
            "duration_secs": 10,
            "exit_code": 0,
            "events_total": 50,
            "file_reads": 20,
            "file_writes": 5,
            "blocked_attempts": [{
                "path": "/tmp/secret.env",
                "comm": "cat",
                "source": "landlock",
                "count": 1
            }],
            "net_requests": [],
            "suspicious_signals": []
        });

        let right = serde_json::json!({
            "duration_secs": 15,
            "exit_code": 1,
            "events_total": 70,
            "file_reads": 25,
            "file_writes": 5,
            "blocked_attempts": [{
                "path": "/etc/shadow",
                "comm": "cat",
                "source": "landlock",
                "count": 2
            }],
            "net_requests": [{
                "host": "evil.com",
                "port": 443,
                "allowed": false
            }],
            "suspicious_signals": []
        });

        let diff = compute_session_diff(&left, &right, "left.json", "right.json");
        assert_eq!(diff.duration_secs.delta, 5);
        assert_eq!(diff.exit_code.delta, 1);
        assert_eq!(diff.events_total.delta, 20);
        assert_eq!(diff.file_reads.delta, 5);
        assert_eq!(diff.file_writes.delta, 0);
        assert_eq!(diff.blocked_attempts.delta, 1);
        assert_eq!(diff.net_denied.delta, 1);

        assert_eq!(diff.new_blocked_attempts.len(), 1);
        assert_eq!(diff.new_blocked_attempts[0]["path"], "/etc/shadow");
        assert_eq!(diff.resolved_blocked_attempts.len(), 1);
        assert_eq!(diff.resolved_blocked_attempts[0]["path"], "/tmp/secret.env");
        assert_eq!(diff.new_network_requests.len(), 1);
    }
}
