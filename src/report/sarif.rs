//! SARIF 2.1.0 report renderer.
//!
//! Blocked file attempts and denied CONNECT requests are represented as
//! SARIF results. Allowed observations remain session properties rather than
//! findings, keeping SARIF consumers focused on actionable violations.

use super::{clean, stats::SessionStats};

pub fn render(stats: &SessionStats) -> String {
    let mut results = Vec::new();
    for blocked in &stats.blocked_attempts {
        results.push(serde_json::json!({
            "ruleId": "vetto.blocked-attempt",
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
                    "artifactLocation": { "uri": clean(&blocked.path) }
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
            "level": "error",
            "message": {
                "text": format!("Denied network CONNECT to {host}:{}", request.port)
            },
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
                "networkDenied": stats.net_requests.iter().filter(|request| !request.allowed).count() as u64
                ,"suspiciousSignals": stats.suspicious_signals.iter().map(|record| record.count).sum::<u64>()
            }
        }]
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}\n".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::stats::{BlockedRecord, NetRecord};

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
            ..SessionStats::default()
        };
        let value: serde_json::Value = serde_json::from_str(&render(&stats)).expect("SARIF JSON");
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["results"].as_array().unwrap().len(), 2);
        assert!(value["runs"][0]["results"][0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("2 occurrence"));
    }
}
