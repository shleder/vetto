//! Audit history log index (~/.vetto/history.jsonl) and `vetto audit` subcommand (Feature 40).
//!
//! Every completed sandboxed session appends an audit summary line to `~/.vetto/history.jsonl`.
//! The `vetto audit` subcommand displays this history with filtering and search.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: DateTime<Utc>,
    pub session_id: String,
    pub agent: String,
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<String>,
    pub exit_code: i32,
    pub duration_secs: u64,
    pub tier: String,
    pub net_mode: String,
    pub blocked_count: u64,
    pub events_total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_path: Option<String>,
}

/// Resolves the default global audit history path (~/.vetto/history.jsonl).
pub fn default_history_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .map(|home| home.join(".vetto").join("history.jsonl"))
}

/// Appends a session audit record to the global history file.
pub fn record_session_history(record: &AuditRecord) -> Result<()> {
    let Some(path) = default_history_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    append_record_to_file(&path, record)
}

/// Appends a record to a specific JSONL file.
pub fn append_record_to_file(path: &Path, record: &AuditRecord) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open history file {}", path.display()))?;

    let mut line = serde_json::to_string(record)?;
    line.push('\n');
    file.write_all(line.as_bytes())
        .with_context(|| format!("write to history file {}", path.display()))?;
    Ok(())
}

/// Reads all audit records from a history file.
pub fn read_history(path: &Path) -> Result<Vec<AuditRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<AuditRecord>(trimmed) {
            records.push(rec);
        }
    }
    Ok(records)
}

/// Filter and sort history records.
pub fn filter_records<'a>(
    records: &'a [AuditRecord],
    since: Option<DateTime<Utc>>,
    agent_filter: Option<&str>,
    query: Option<&str>,
) -> Vec<&'a AuditRecord> {
    let agent_filter = agent_filter.map(|a| a.trim().to_ascii_lowercase());
    let query = query.map(|q| q.trim().to_ascii_lowercase());

    records
        .iter()
        .filter(|rec| {
            if let Some(cutoff) = since {
                if rec.ts < cutoff {
                    return false;
                }
            }
            if let Some(ref agent) = agent_filter {
                if !rec.agent.to_ascii_lowercase().contains(agent) {
                    return false;
                }
            }
            if let Some(ref q) = query {
                if q.is_empty() {
                    return true;
                }
                let in_policy = rec
                    .policy_path
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains(q);
                let in_profile = rec.profile.to_ascii_lowercase().contains(q);
                let in_agent = rec.agent.to_ascii_lowercase().contains(q);
                let in_session = rec.session_id.to_ascii_lowercase().contains(q);
                if !in_policy && !in_profile && !in_agent && !in_session {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Parse `--since` into a cutoff `DateTime<Utc>`.
pub fn parse_since_duration(s: &str) -> Result<DateTime<Utc>> {
    let s = s.trim();
    let now = Utc::now();

    // Check if it is a relative duration like 24h, 7d, 30m, 90s
    if let Some(rest) = s.strip_suffix('h') {
        let hours: i64 = rest.parse().context("invalid hours in --since")?;
        return Ok(now - Duration::hours(hours));
    }
    if let Some(rest) = s.strip_suffix('d') {
        let days: i64 = rest.parse().context("invalid days in --since")?;
        return Ok(now - Duration::days(days));
    }
    if let Some(rest) = s.strip_suffix('m') {
        let mins: i64 = rest.parse().context("invalid minutes in --since")?;
        return Ok(now - Duration::minutes(mins));
    }
    if let Some(rest) = s.strip_suffix('s') {
        let secs: i64 = rest.parse().context("invalid seconds in --since")?;
        return Ok(now - Duration::seconds(secs));
    }

    // Try parsing date/datetime e.g. "2026-08-30" or ISO
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        if let Some(dt) = d.and_hms_opt(0, 0, 0) {
            return Ok(DateTime::from_naive_utc_and_offset(dt, Utc));
        }
    }

    anyhow::bail!("invalid --since value '{s}'; expected e.g. 24h, 7d, 30m, or YYYY-MM-DD")
}

/// Execute the `vetto audit` CLI subcommand.
pub fn run_audit(
    since: Option<&str>,
    agent: Option<&str>,
    limit: Option<usize>,
    query: Option<&str>,
    json_output: bool,
) -> Result<()> {
    let history_file = default_history_path()
        .ok_or_else(|| anyhow::anyhow!("could not resolve history file path"))?;

    let records = read_history(&history_file)?;
    let cutoff = match since {
        Some(s) => Some(parse_since_duration(s)?),
        None => None,
    };

    let mut filtered = filter_records(&records, cutoff, agent, query);
    // Sort reverse chronological
    filtered.sort_by_key(|a| std::cmp::Reverse(a.ts));

    if let Some(lim) = limit {
        filtered.truncate(lim);
    }

    if json_output {
        for record in filtered {
            println!("{}", serde_json::to_string(record)?);
        }
        return Ok(());
    }

    if filtered.is_empty() {
        println!(
            "No matching audit history entries found in {}.",
            history_file.display()
        );
        return Ok(());
    }

    println!(
        "{:<19}  {:<12}  {:<10}  {:<10}  {:<4}  {:<7}  {:<8}  {:<6}",
        "TIMESTAMP", "SESSION ID", "AGENT", "PROFILE", "EXIT", "BLOCKED", "TIER", "DUR"
    );
    println!(
        "{:-<19}  {:-<12}  {:-<10}  {:-<10}  {:-<4}  {:-<7}  {:-<8}  {:-<6}",
        "", "", "", "", "", "", "", ""
    );

    for r in filtered {
        let ts_str = r.ts.format("%Y-%m-%d %H:%M:%S").to_string();
        let dur_str = format!("{}s", r.duration_secs);
        println!(
            "{:<19}  {:<12}  {:<10}  {:<10}  {:<4}  {:<7}  {:<8}  {:<6}",
            ts_str,
            truncate_str(&r.session_id, 12),
            truncate_str(&r.agent, 10),
            truncate_str(&r.profile, 10),
            r.exit_code,
            r.blocked_count,
            truncate_str(&r.tier, 8),
            dur_str,
        );
    }

    Ok(())
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_since_supports_various_units() {
        let now = Utc::now();
        let dt_h = parse_since_duration("24h").expect("24h");
        assert!(now - dt_h >= Duration::hours(23));

        let dt_d = parse_since_duration("7d").expect("7d");
        assert!(now - dt_d >= Duration::days(6));

        let dt_m = parse_since_duration("30m").expect("30m");
        assert!(now - dt_m >= Duration::minutes(29));

        let dt_s = parse_since_duration("60s").expect("60s");
        assert!(now - dt_s >= Duration::seconds(59));

        assert!(parse_since_duration("invalid").is_err());
    }

    #[test]
    fn filtering_records_matches_agent_and_query() {
        let records = vec![
            AuditRecord {
                ts: Utc::now(),
                session_id: "session-1".into(),
                agent: "codex".into(),
                profile: "default".into(),
                policy_path: Some("/home/user/vetto.toml".into()),
                exit_code: 0,
                duration_secs: 10,
                tier: "full".into(),
                net_mode: "off".into(),
                blocked_count: 0,
                events_total: 10,
                report_path: None,
            },
            AuditRecord {
                ts: Utc::now() - Duration::hours(48),
                session_id: "session-2".into(),
                agent: "claude".into(),
                profile: "strict".into(),
                policy_path: None,
                exit_code: 1,
                duration_secs: 5,
                tier: "fs-only".into(),
                net_mode: "off".into(),
                blocked_count: 2,
                events_total: 8,
                report_path: None,
            },
        ];

        // Filter by since 24h
        let cutoff = Utc::now() - Duration::hours(24);
        let recent = filter_records(&records, Some(cutoff), None, None);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].session_id, "session-1");

        // Filter by agent
        let claude_only = filter_records(&records, None, Some("claude"), None);
        assert_eq!(claude_only.len(), 1);
        assert_eq!(claude_only[0].agent, "claude");

        // Filter by substring query
        let query_strict = filter_records(&records, None, None, Some("strict"));
        assert_eq!(query_strict.len(), 1);
        assert_eq!(query_strict[0].profile, "strict");
    }
}
