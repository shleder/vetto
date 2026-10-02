//! SARIF 2.1.0 report renderer.
//!
//! Blocked file attempts and denied CONNECT requests are represented as
//! SARIF results. Allowed observations remain session properties rather than
//! findings, keeping SARIF consumers focused on actionable violations.

use super::{clean, stats::SessionStats};

/// Normalizes an artifact file path for GitHub Code Scanning:
/// Converts absolute host paths to clean relative paths anchored to `%SRCROOT%`.
fn normalize_path(raw_path: &str) -> String {
    let cleaned = clean(raw_path);
    let p = std::path::Path::new(&cleaned);

    // If path is inside current working directory, strip prefix to get repo-relative path
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rel) = p.strip_prefix(&cwd) {
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if !rel_str.is_empty() {
                return rel_str;
            }
        }
        if let Ok(canonical_cwd) = cwd.canonicalize() {
            if let Ok(rel) = p.strip_prefix(&canonical_cwd) {
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                if !rel_str.is_empty() {
                    return rel_str;
                }
            }
        }
    }

    // Strip leading root slashes / Windows drive letters to make path relative to %SRCROOT%
    let s = cleaned.as_str();
    #[cfg(windows)]
    let s = if s.len() >= 2 && s.as_bytes()[1] == b':' {
        &s[2..]
    } else {
        s
    };
    let s = s.trim_start_matches(|c| c == '/' || c == '\\');
    let normalized = s.replace('\\', "/");

    if normalized.is_empty() {
        ".vetto/policy.toml".to_string()
    } else {
        normalized
    }
}

pub fn render(stats: &SessionStats) -> String {
    let mut results = Vec::new();
    for blocked in &stats.blocked_attempts {
        let uri = normalize_path(&blocked.path);
        results.push(serde_json::json!({
            "ruleId": "vetto.blocked-attempt",
            "ruleIndex": 0,
            "level": "error",
            "message": {
                "text": format!(
                    "Blocked file attempt by {} from {} ({} occurrence(s))",
                    clean(&blocked.comm),
                    clean(&blocked.source),
                    blocked.count
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%"
                    }
                }
            }],
            "properties": {
                "count": blocked.count,
                "process": clean(&blocked.comm),
                "source": clean(&blocked.source)
            }
        }));
    }
    for request in stats.net_requests.iter().filter(|request| !request.allowed) {
        let host = clean(&request.host);
        results.push(serde_json::json!({
            "ruleId": "vetto.network-denied",
            "ruleIndex": 1,
            "level": "error",
            "message": {
                "text": format!("Denied network CONNECT to {host}:{}", request.port)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ".vetto/policy.toml",
                        "uriBaseId": "%SRCROOT%"
                    }
                }
            }],
            "properties": {
                "host": host,
                "port": request.port,
                "allowed": false
            }
        }));
    }
    for signal in &stats.suspicious_signals {
        results.push(serde_json::json!({
            "ruleId": "vetto.suspicious-signal",
            "ruleIndex": 2,
            "level": match signal.severity.as_str() {
                "high" => "warning",
                _ => "note",
            },
            "message": {
                "text": format!(
                    "Best-effort suspicious signal: {} ({}, {} occurrence(s))",
                    clean(&signal.reason),
                    clean(&signal.subject),
                    signal.count
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ".vetto/policy.toml",
                        "uriBaseId": "%SRCROOT%"
                    }
                }
            }],
            "properties": {
                "category": clean(&signal.category),
                "severity": clean(&signal.severity),
                "subject": clean(&signal.subject),
                "count": signal.count,
                "advisoryOnly": true
            }
        }));
    }

    let payload = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vetto",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/shleder/vetto",
                    "rules": [
                        {
                            "id": "vetto.blocked-attempt",
                            "name": "BlockedAttempt",
                            "shortDescription": { "text": "A sandbox policy blocked a file attempt." },
                            "defaultConfiguration": { "level": "error" }
                        },
                        {
                            "id": "vetto.network-denied",
                            "name": "NetworkDenied",
                            "shortDescription": { "text": "The network broker denied a CONNECT request." },
                            "defaultConfiguration": { "level": "error" }
                        },
                        {
                            "id": "vetto.suspicious-signal",
                            "name": "SuspiciousSignal",
                            "shortDescription": { "text": "Best-effort advisory pattern classifier signal." },
                            "defaultConfiguration": { "level": "note" }
                        }
                    ]
                }
            },
            "originalUriBaseIds": {
                "%SRCROOT%": {
                    "uri": "file:///"
                }
            },
            "results": results,
            "properties": {
                "tier": clean(&stats.tier),
                "networkMode": clean(&stats.net_mode),
                "profile": clean(&stats.profile),
                "exitCode": stats.exit_code,
                "durationSecs": stats.duration_secs,
                "eventsTotal": stats.events_total,
                "fileReads": stats.file_reads,
                "fileWrites": stats.file_writes,
                "blockedAttempts": stats.blocked_attempts.iter().map(|record| record.count).sum::<u64>(),
                "networkDenied": stats.net_requests.iter().filter(|request| !request.allowed).count() as u64,
                "suspiciousSignals": stats.suspicious_signals.iter().map(|record| record.count).sum::<u64>()
            }
        }]
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}\n".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::stats::{BlockedRecord, NetRecord, SuspiciousRecord};

    #[test]
    fn emits_sarif_findings_for_blocked_records() {
        let stats = SessionStats {
            blocked_attempts: vec![BlockedRecord {
                path: "/tmp/secret\nvalue".into(),
                comm: "agent".into(),
                source: "landlock".into(),
                count: 2,
            }],
            net_requests: vec![NetRecord {
                host: "example.test".into(),
                port: 22,
                allowed: false,
            }],
            suspicious_signals: vec![SuspiciousRecord {
                category: "syscall".into(),
                severity: "high".into(),
                subject: "ptrace".into(),
                reason: "unauthorized tracing attempt".into(),
                count: 1,
            }],
            ..SessionStats::default()
        };
        let value: serde_json::Value = serde_json::from_str(&render(&stats)).expect("SARIF JSON");
        assert_eq!(value["version"], "2.1.0");
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);

        // Result 0: blocked-attempt
        assert_eq!(results[0]["ruleId"], "vetto.blocked-attempt");
        assert_eq!(results[0]["ruleIndex"], 0);
        assert_eq!(results[0]["level"], "error");
        assert!(results[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("2 occurrence"));
        let loc0 = &results[0]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(loc0["uri"], "tmp/secret value");
        assert_eq!(loc0["uriBaseId"], "%SRCROOT%");

        // Result 1: network-denied
        assert_eq!(results[1]["ruleId"], "vetto.network-denied");
        assert_eq!(results[1]["ruleIndex"], 1);
        assert_eq!(results[1]["level"], "error");
        let loc1 = &results[1]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(loc1["uri"], ".vetto/policy.toml");
        assert_eq!(loc1["uriBaseId"], "%SRCROOT%");

        // Result 2: suspicious-signal
        assert_eq!(results[2]["ruleId"], "vetto.suspicious-signal");
        assert_eq!(results[2]["ruleIndex"], 2);
        assert_eq!(results[2]["level"], "warning");
        let loc2 = &results[2]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(loc2["uri"], ".vetto/policy.toml");
        assert_eq!(loc2["uriBaseId"], "%SRCROOT%");

        // Verify originalUriBaseIds
        assert!(value["runs"][0]["originalUriBaseIds"]["%SRCROOT%"].is_object());
    }

    #[test]
    fn path_normalization_handles_cwd_and_absolute_paths() {
        if let Ok(cwd) = std::env::current_dir() {
            let child = cwd.join("src").join("report").join("sarif.rs");
            assert_eq!(
                normalize_path(&child.to_string_lossy()),
                "src/report/sarif.rs"
            );
        }
        assert_eq!(normalize_path("/etc/passwd"), "etc/passwd");
        assert_eq!(normalize_path("src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_path("/"), ".vetto/policy.toml");
    }
}
