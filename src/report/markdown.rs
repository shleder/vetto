//! Markdown report.

use super::{clean, stats::SessionStats};

pub fn render(stats: &SessionStats) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("# vetto session report\n\n");
    out.push_str(&format!(
        "- tier: `{}` · net: `{}` · profile: `{}`\n",
        markdown_inline(&stats.tier),
        markdown_inline(&stats.net_mode),
        markdown_inline(&stats.profile)
    ));
    out.push_str(&format!(
        "- exit code: `{}` · duration: `{}s`\n\n",
        stats.exit_code, stats.duration_secs
    ));

    out.push_str("## Event counts\n\n");
    out.push_str("| event | count |\n|---|---|\n");
    for (kind, count) in &stats.counts {
        out.push_str(&format!("| {} | {count} |\n", markdown_cell(kind)));
    }
    out.push_str(&format!(
        "\nObserved file reads: {} · writes: {} (best-effort /proc polling).\n\n",
        stats.file_reads, stats.file_writes
    ));

    
    if stats.io_metrics.file_writes > 0 || stats.io_metrics.file_reads > 0 {
        out.push_str("## File I/O summary\n\n");
        out.push_str("| Metric | Count | Bytes |\n|---|---|---|\n");
        out.push_str(&format!("| Files Created | {} | - |\n", stats.io_metrics.files_created));
        out.push_str(&format!("| Files Modified | {} | - |\n", stats.io_metrics.files_modified));
        out.push_str(&format!("| Files Deleted | {} | - |\n", stats.io_metrics.files_deleted));
        out.push_str(&format!("| Total Writes | {} | {} |\n", stats.io_metrics.file_writes, stats.io_metrics.bytes_written));
        out.push_str(&format!("| Total Reads | {} | {} |\n", stats.io_metrics.file_reads, stats.io_metrics.bytes_read));
        out.push('\n');
    }

    out.push_str("## Blocked attempts\n\n");
    if stats.blocked_attempts.is_empty() {
        out.push_str(
            "None observed. Observation channels are optional (see notices); \
             enforcement is active regardless.\n\n",
        );
    } else {
        out.push_str("| path | process | source | count |\n|---|---|---|---|\n");
        for b in &stats.blocked_attempts {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                markdown_cell(&b.path),
                markdown_cell(&b.comm),
                markdown_cell(&b.source),
                b.count
            ));
        }
        out.push('\n');
    }

    out.push_str("## Network requests\n\n");
    if stats.net_requests.is_empty() {
        out.push_str("None (network is off by default).\n\n");
    } else {
        out.push_str("| host | port | decision |\n|---|---|---|\n");
        for r in &stats.net_requests {
            let decision = if r.allowed { "allow" } else { "DENIED" };
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                markdown_cell(&r.host),
                r.port,
                decision
            ));
        }
        out.push('\n');
    }

    if !stats.dns_resolutions.is_empty() {
        out.push_str("## DNS resolutions\n\n");
        out.push_str("| host | resolved IPs |\n|---|---|\n");
        for d in &stats.dns_resolutions {
            out.push_str(&format!(
                "| {} | {} |\n",
                markdown_cell(&d.host),
                markdown_cell(&d.ips.join(", "))
            ));
        }
        out.push('\n');
    }

    if !stats.egress_connections.is_empty() {
        out.push_str("## Egress traffic\n\n");
        out.push_str("| host | IP | port | tx bytes | rx bytes |\n|---|---|---|---|---|\n");
        for e in &stats.egress_connections {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                markdown_cell(&e.host),
                markdown_cell(&e.ip),
                e.port,
                e.bytes_tx,
                e.bytes_rx
            ));
        }
        out.push('\n');
    }

    if !stats.domain_egress.is_empty() {
        out.push_str("## Network traffic summary\n\n");
        out.push_str("| Domain | Requests | TX | RX | Total |\n|---|---|---|---|---|\n");
        let mut entries: Vec<_> = stats.domain_egress.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (domain, d) in entries {
            let total = d.bytes_tx.saturating_add(d.bytes_rx);
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                markdown_cell(domain),
                d.requests,
                d.bytes_tx,
                d.bytes_rx,
                total
            ));
        }
        out.push('\n');
    }

    out.push_str("## Suspicious signals (best-effort)\n\n");
    if stats.suspicious_signals.is_empty() {
        out.push_str("None observed. This classifier is advisory and incomplete.\n\n");
    } else {
        out.push_str("| severity | category | subject | reason | count |\n|---|---|---|---|---|\n");
        for signal in &stats.suspicious_signals {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                markdown_cell(&signal.severity),
                markdown_cell(&signal.category),
                markdown_cell(&signal.subject),
                markdown_cell(&signal.reason),
                signal.count
            ));
        }
        out.push('\n');
    }

    out.push_str("## Notices\n\n");
    if stats.notices.is_empty() {
        out.push_str("- none\n");
    } else {
        for n in &stats.notices {
            out.push_str(&format!("- {}\n", markdown_cell(n)));
        }
    }

    out.push_str(
        "\n---\nGenerated by vetto. Observations are BEST-EFFORT and never carry \
enforcement authority. Secret sanitizer: BEST-EFFORT.\n",
    );
    out
}

/// Keep attacker-controlled strings in one Markdown cell. Sanitization is
/// best-effort redaction; escaping only protects report structure and does
/// not make the source string trusted.
fn markdown_cell(value: &str) -> String {
    clean(value)
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn markdown_inline(value: &str) -> String {
    markdown_cell(value).replace(char::from(96), "'")
}

#[cfg(test)]
mod tests {

    #[test]
    fn file_io_summary_is_rendered_in_markdown() {
        let mut stats = SessionStats::default();
        stats.io_metrics.file_writes = 5;
        stats.io_metrics.files_created = 2;
        stats.io_metrics.files_modified = 2;
        stats.io_metrics.files_deleted = 1;
        stats.io_metrics.bytes_written = 2048;
        
        let report = render(&stats);
        assert!(report.contains("## File I/O summary"));
        assert!(report.contains("| Files Created | 2 | - |"));
        assert!(report.contains("| Total Writes | 5 | 2048 |"));
    }

    use super::*;

    #[test]
    fn user_strings_are_redacted_and_table_structure_is_escaped() {
        let secret = "Bearer abcdefghijklmnop";
        let stats = SessionStats {
            tier: format!("tier-{secret}"),
            net_mode: "off".into(),
            profile: "profile".into(),
            notices: vec!["row | injected\nnext".into()],
            ..SessionStats::default()
        };
        let report = render(&stats);
        assert!(
            !report.contains("abcdefghijklmnop"),
            "secret leaked: {report}"
        );
        assert!(report.contains("row \\| injected\\nnext"));
    }

    #[test]
    fn dns_and_egress_logs_are_rendered_in_markdown() {
        let stats = SessionStats {
            dns_resolutions: vec![super::super::stats::DnsRecord {
                host: "api.anthropic.com".into(),
                ips: vec!["104.18.2.1".into(), "104.18.3.1".into()],
            }],
            egress_connections: vec![super::super::stats::EgressRecord {
                host: "api.anthropic.com".into(),
                ip: "104.18.2.1".into(),
                port: 443,
                bytes_tx: 1200,
                bytes_rx: 8500,
            }],
            ..SessionStats::default()
        };
        let report = render(&stats);
        assert!(report.contains("## DNS resolutions"));
        assert!(report.contains("| api.anthropic.com | 104.18.2.1, 104.18.3.1 |"));
        assert!(report.contains("## Egress traffic"));
        assert!(report.contains("| api.anthropic.com | 104.18.2.1 | 443 | 1200 | 8500 |"));
    }

    #[test]
    fn network_traffic_summary_is_rendered_in_markdown() {
        let mut domain_egress = std::collections::HashMap::new();
        domain_egress.insert(
            "api.anthropic.com".into(),
            super::super::stats::DomainTransferStats {
                requests: 2,
                bytes_tx: 1200,
                bytes_rx: 8500,
            },
        );
        let stats = SessionStats {
            domain_egress,
            total_egress_bytes_tx: 1200,
            total_egress_bytes_rx: 8500,
            ..SessionStats::default()
        };
        let report = render(&stats);
        assert!(report.contains("## Network traffic summary"));
        assert!(report.contains("| Domain | Requests | TX | RX | Total |"));
        assert!(report.contains("| api.anthropic.com | 2 | 1200 | 8500 | 9700 |"));
    }
}
