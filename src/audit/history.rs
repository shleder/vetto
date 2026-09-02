//! Audit history log index (~/.vetto/history.jsonl) and `vetto audit` session inspector.
//!
//! Inspects recorded session events, filesystem denials, blocked egress, and filtered syscalls.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAuditDetail {
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub agent: String,
    pub profile: String,
    pub tier: String,
    pub net_mode: String,
    pub exit_code: i32,
    pub duration_secs: u64,
    pub violations_total: u64,
    pub events_total: u64,
    pub filesystem_denials: Vec<FilesystemDenial>,
    pub blocked_network: Vec<BlockedNetworkDestination>,
    pub filtered_syscalls: Vec<FilteredSyscall>,
    pub suspicious_signals: Vec<SuspiciousSignalDetail>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemDenial {
    pub path: String,
    pub process: String,
    pub source: String,
    pub count: u64,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedNetworkDestination {
    pub destination: String,
    pub host: String,
    pub port: u16,
    pub count: u64,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteredSyscall {
    pub syscall: String,
    pub comm: String,
    pub source: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousSignalDetail {
    pub category: String,
    pub severity: String,
    pub subject: String,
    pub reason: String,
    pub count: u64,
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
        let _ = fs::create_dir_all(parent);
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

/// Reads all audit records from a history file (or auto-discovers from logs if empty).
pub fn read_history(path: &Path) -> Result<Vec<AuditRecord>> {
    let mut records = Vec::new();
    if path.exists() {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let reader = BufReader::new(file);

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
    }

    if records.is_empty() {
        let discovered = discover_history_from_logs();
        if !discovered.is_empty() {
            return Ok(discovered);
        }
    }

    Ok(records)
}

/// Auto-discovers past session records from ~/.vetto/logs/*.jsonl.
pub fn discover_history_from_logs() -> Vec<AuditRecord> {
    let mut records = Vec::new();
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);

    if let Some(h) = home {
        let logs_dir = h.join(".vetto").join("logs");
        if logs_dir.exists() {
            if let Ok(entries) = fs::read_dir(&logs_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                        if let Ok(detail) = parse_jsonl_log(&path, "") {
                            records.push(AuditRecord {
                                ts: detail.timestamp,
                                session_id: detail.session_id,
                                agent: detail.agent,
                                command: detail.command,
                                profile: detail.profile,
                                policy_path: None,
                                exit_code: detail.exit_code,
                                duration_secs: detail.duration_secs,
                                tier: detail.tier,
                                net_mode: detail.net_mode,
                                blocked_count: detail.violations_total,
                                events_total: detail.events_total,
                                report_path: None,
                                log_path: Some(path.display().to_string()),
                            });
                        }
                    }
                }
            }
        }
    }
    records.sort_by_key(|r| r.ts);
    records
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
                let in_command = rec
                    .command
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains(q);
                if !in_policy && !in_profile && !in_agent && !in_session && !in_command {
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

/// Inspects a session by session ID, report path, or log path.
pub fn inspect_session(target: &str) -> Result<SessionAuditDetail> {
    if target == "latest" || target.trim().is_empty() {
        return inspect_latest_session();
    }

    let target_path = Path::new(target);
    if target_path.exists() && target_path.is_file() {
        let ext = target_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if ext == "jsonl" {
            return parse_jsonl_log(target_path, target);
        } else if ext == "json" {
            return parse_json_report(target_path, target);
        }
    }

    // Try finding matching log or report in known directories
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);

    let stripped = target.strip_prefix("session-").unwrap_or(target);

    // 1. Check ~/.vetto/logs/<target>.jsonl
    if let Some(ref h) = home {
        let log_file = h
            .join(".vetto")
            .join("logs")
            .join(format!("{target}.jsonl"));
        if log_file.exists() {
            return parse_jsonl_log(&log_file, target);
        }
        let log_file_raw = h.join(".vetto").join("logs").join(target);
        if log_file_raw.exists() {
            return parse_jsonl_log(&log_file_raw, target);
        }
    }

    // 2. Search logs in ~/.vetto/logs/ for matching filename
    if let Some(ref h) = home {
        let logs_dir = h.join(".vetto").join("logs");
        if logs_dir.exists() {
            if let Ok(entries) = fs::read_dir(&logs_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if (name.contains(target) || name.contains(stripped))
                        && name.ends_with(".jsonl")
                    {
                        return parse_jsonl_log(&path, target);
                    }
                }
            }
        }
    }

    // 3. Check reports in current directory, .vetto/reports/, or ~/.vetto/reports/
    let report_candidates = vec![
        PathBuf::from("."),
        PathBuf::from(".vetto/reports"),
        PathBuf::from(".vetto-reports"),
        home.as_ref()
            .map(|h| h.join(".vetto").join("reports"))
            .unwrap_or_default(),
    ];

    for rep_dir in report_candidates {
        if rep_dir.exists() {
            if let Ok(entries) = fs::read_dir(&rep_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if (name.contains(target)
                        || name.contains(stripped)
                        || (target == "latest"
                            && (name.starts_with(".vetto-report-")
                                || name.starts_with("vetto-report-"))))
                        && (name.ends_with(".json") || name.ends_with(".jsonl"))
                    {
                        if name.ends_with(".jsonl") {
                            return parse_jsonl_log(&path, target);
                        } else {
                            return parse_json_report(&path, target);
                        }
                    }
                }
            }
        }
    }

    // 4. Check ~/.vetto/history.jsonl for matching session
    if let Some(history_file) = default_history_path() {
        let records = read_history(&history_file)?;
        let matched = records.iter().find(|r| {
            r.session_id == target
                || r.session_id.contains(target)
                || r.session_id.strip_prefix("session-") == Some(target)
        });

        if let Some(rec) = matched {
            if let Some(ref lp) = rec.log_path {
                let p = Path::new(lp);
                if p.exists() {
                    return parse_jsonl_log(p, &rec.session_id);
                }
            }
            if let Some(ref rp) = rec.report_path {
                let p = Path::new(rp);
                if p.exists() {
                    return parse_json_report(p, &rec.session_id);
                }
            }
            return Ok(build_detail_from_history_record(rec));
        }
    }

    anyhow::bail!(
        "session '{target}' not found in logs (~/.vetto/logs/*.jsonl), reports, or history. Run 'vetto audit' to view available sessions."
    )
}

/// Inspects the most recent recorded session.
pub fn inspect_latest_session() -> Result<SessionAuditDetail> {
    if let Some(history_file) = default_history_path() {
        let records = read_history(&history_file)?;
        if let Some(latest) = records.last() {
            return inspect_session(&latest.session_id);
        }
    }

    // Fallback: check latest file in ~/.vetto/logs/
    if let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
    {
        let logs_dir = home.join(".vetto").join("logs");
        if logs_dir.exists() {
            let mut log_files = Vec::new();
            if let Ok(entries) = fs::read_dir(&logs_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                        if let Ok(meta) = path.metadata() {
                            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                            log_files.push((path, mtime));
                        }
                    }
                }
            }
            log_files.sort_by_key(|(_, mtime)| std::cmp::Reverse(*mtime));
            if let Some((path, _)) = log_files.first() {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("latest");
                return parse_jsonl_log(path, stem);
            }
        }
    }

    anyhow::bail!("no past session logs or history found. Run a sandboxed session first with 'vetto -- <command>'.")
}

fn parse_jsonl_log(path: &Path, session_hint: &str) -> Result<SessionAuditDetail> {
    let file = File::open(path).with_context(|| format!("open log {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut session_id = Path::new(session_hint)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(session_hint)
        .to_string();
    let mut timestamp = Utc::now();
    let mut command = None;
    let mut agent = "default".to_string();
    let mut profile = "default".to_string();
    let mut tier = "unknown".to_string();
    let mut net_mode = "unknown".to_string();
    let mut exit_code = 0;
    let mut duration_secs = 0;
    let mut events_total = 0u64;

    let mut denials_map: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    let mut network_map: BTreeMap<(String, u16), u64> = BTreeMap::new();
    let mut syscalls_map: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    let mut suspicious_map: BTreeMap<(String, String, String, String), u64> = BTreeMap::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let ev_res = serde_json::from_str::<crate::events::Event>(trimmed);
        if let Ok(ev) = ev_res {
            events_total += 1;

            if let Some(signal) = crate::classifier::classify_event(&ev) {
                let key = (
                    signal.category.to_string(),
                    signal.severity.label().to_string(),
                    signal.subject,
                    signal.reason.to_string(),
                );
                *suspicious_map.entry(key).or_insert(0) += 1;
            }

            match ev {
                crate::events::Event::SessionStarted {
                    ts,
                    pid,
                    tier: t,
                    net_mode: nm,
                    profile: p,
                } => {
                    timestamp = ts;
                    if session_id.is_empty()
                        || session_id == "latest"
                        || session_id.contains('/')
                        || session_id.contains('\\')
                    {
                        session_id = format!("session-{pid}");
                    }
                    tier = t;
                    net_mode = nm;
                    profile = p;
                }
                crate::events::Event::ExecObserved { argv, .. } => {
                    if command.is_none() && !argv.is_empty() {
                        command = Some(argv.join(" "));
                        if let Some(first) = argv.first() {
                            agent = Path::new(first)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or(first)
                                .to_string();
                        }
                    }
                }
                crate::events::Event::BlockedAttempt {
                    comm, path, source, ..
                } => {
                    let is_syscall = source.contains("seccomp")
                        || path.starts_with("syscall:")
                        || source == "syscall";
                    if is_syscall {
                        let sys_name = path.strip_prefix("syscall:").unwrap_or(&path).to_string();
                        *syscalls_map.entry((sys_name, comm, source)).or_insert(0) += 1;
                    } else {
                        *denials_map.entry((path, comm, source)).or_insert(0) += 1;
                    }
                }
                crate::events::Event::NetRequest {
                    host,
                    port,
                    allowed,
                    ..
                } => {
                    if !allowed {
                        *network_map.entry((host, port)).or_insert(0) += 1;
                    }
                }
                crate::events::Event::NetQuotaExceeded { host, .. } => {
                    *network_map.entry((host, 0)).or_insert(0) += 1;
                }
                crate::events::Event::SessionEnded {
                    exit_code: code,
                    duration_secs: dur,
                    ..
                } => {
                    exit_code = code;
                    duration_secs = dur;
                }
                _ => {}
            }
        } else if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let event_type = val
                .get("event")
                .or_else(|| val.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !event_type.is_empty() {
                events_total += 1;
                match event_type {
                    "session_started" => {
                        if let Some(ts_str) = val.get("ts").and_then(|v| v.as_str()) {
                            if let Ok(dt) = DateTime::parse_from_rfc3339(ts_str) {
                                timestamp = dt.with_timezone(&Utc);
                            }
                        }
                        if let Some(pid) = val.get("pid").and_then(|v| v.as_u64()) {
                            if session_id.is_empty()
                                || session_id == "latest"
                                || session_id.contains('/')
                                || session_id.contains('\\')
                            {
                                session_id = format!("session-{pid}");
                            }
                        }
                        if let Some(t) = val.get("tier").and_then(|v| v.as_str()) {
                            tier = t.to_string();
                        }
                        if let Some(nm) = val.get("net_mode").and_then(|v| v.as_str()) {
                            net_mode = nm.to_string();
                        }
                        if let Some(p) = val.get("profile").and_then(|v| v.as_str()) {
                            profile = p.to_string();
                        }
                    }
                    "exec_observed" => {
                        if let Some(arr) = val.get("argv").and_then(|v| v.as_array()) {
                            let argv: Vec<String> = arr
                                .iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect();
                            if command.is_none() && !argv.is_empty() {
                                command = Some(argv.join(" "));
                                if let Some(first) = argv.first() {
                                    agent = Path::new(first)
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or(first)
                                        .to_string();
                                }
                            }
                        }
                    }
                    "blocked_attempt" => {
                        let path = val
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let comm = val
                            .get("comm")
                            .and_then(|v| v.as_str())
                            .unwrap_or("agent")
                            .to_string();
                        let source = val
                            .get("source")
                            .and_then(|v| v.as_str())
                            .unwrap_or("landlock")
                            .to_string();
                        let is_syscall = source.contains("seccomp")
                            || path.starts_with("syscall:")
                            || source == "syscall";
                        if is_syscall {
                            let sys_name =
                                path.strip_prefix("syscall:").unwrap_or(&path).to_string();
                            *syscalls_map.entry((sys_name, comm, source)).or_insert(0) += 1;
                        } else {
                            *denials_map.entry((path, comm, source)).or_insert(0) += 1;
                        }
                    }
                    "net_request" => {
                        let host = val
                            .get("host")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let port = val.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                        let allowed = val.get("allowed").and_then(|v| v.as_bool()).unwrap_or(true);
                        if !allowed {
                            *network_map.entry((host, port)).or_insert(0) += 1;
                        }
                    }
                    "session_ended" => {
                        if let Some(code) = val.get("exit_code").and_then(|v| v.as_i64()) {
                            exit_code = code as i32;
                        }
                        if let Some(dur) = val.get("duration_secs").and_then(|v| v.as_u64()) {
                            duration_secs = dur;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let filesystem_denials = denials_map
        .into_iter()
        .map(|((p, comm, src), count)| FilesystemDenial {
            path: p.clone(),
            process: comm,
            source: src,
            count,
            remediation: format!("vetto allow {p}"),
        })
        .collect::<Vec<_>>();

    let blocked_network = network_map
        .into_iter()
        .map(|((h, port), count)| BlockedNetworkDestination {
            destination: if port > 0 {
                format!("{h}:{port}")
            } else {
                h.clone()
            },
            host: h.clone(),
            port,
            count,
            remediation: format!("vetto allow --net {h}"),
        })
        .collect::<Vec<_>>();

    let filtered_syscalls = syscalls_map
        .into_iter()
        .map(|((sys, comm, src), count)| FilteredSyscall {
            syscall: sys,
            comm,
            source: src,
            count,
        })
        .collect::<Vec<_>>();

    let suspicious_signals = suspicious_map
        .into_iter()
        .map(|((cat, sev, subj, reason), count)| SuspiciousSignalDetail {
            category: cat,
            severity: sev,
            subject: subj,
            reason,
            count,
        })
        .collect::<Vec<_>>();

    let violations_total = (filesystem_denials.iter().map(|d| d.count).sum::<u64>())
        + (blocked_network.iter().map(|n| n.count).sum::<u64>())
        + (filtered_syscalls.iter().map(|s| s.count).sum::<u64>());

    let mut recommendations = Vec::new();
    for d in &filesystem_denials {
        recommendations.push(format!("Grant filesystem access: {}", d.remediation));
    }
    for n in &blocked_network {
        recommendations.push(format!("Grant network domain: {}", n.remediation));
    }
    if exit_code == 124 {
        recommendations.push("Session timed out: consider extending --timeout".to_string());
    }

    if session_id.is_empty() || session_id == "latest" {
        session_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
    }

    Ok(SessionAuditDetail {
        session_id,
        timestamp,
        command,
        agent,
        profile,
        tier,
        net_mode,
        exit_code,
        duration_secs,
        violations_total,
        events_total,
        filesystem_denials,
        blocked_network,
        filtered_syscalls,
        suspicious_signals,
        recommendations,
    })
}

fn parse_json_report(path: &Path, session_hint: &str) -> Result<SessionAuditDetail> {
    let content =
        fs::read_to_string(path).with_context(|| format!("read report {}", path.display()))?;
    let val: serde_json::Value =
        serde_json::from_str(&content).with_context(|| "parse report JSON")?;

    let session_id = val
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(session_hint);
            let clean = stem
                .strip_prefix('.')
                .unwrap_or(stem)
                .strip_prefix("vetto-report-")
                .unwrap_or(stem);
            if clean.is_empty() || clean == "latest" {
                session_hint.to_string()
            } else if clean.starts_with("session-") {
                clean.to_string()
            } else {
                format!("session-{clean}")
            }
        });

    let timestamp = val
        .get("started_at")
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let profile = val
        .get("profile")
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();
    let tier = val
        .get("tier")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let net_mode = val
        .get("net_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let exit_code = val.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let duration_secs = val
        .get("duration_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let events_total = val
        .get("events_total")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let mut filesystem_denials = Vec::new();
    let mut filtered_syscalls = Vec::new();

    if let Some(blocks) = val.get("blocked_attempts").and_then(|v| v.as_array()) {
        for b in blocks {
            let path_str = b.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let comm = b
                .get("comm")
                .and_then(|v| v.as_str())
                .unwrap_or("agent")
                .to_string();
            let source = b
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("landlock")
                .to_string();
            let count = b.get("count").and_then(|v| v.as_u64()).unwrap_or(1);

            if source.contains("seccomp") || path_str.starts_with("syscall:") {
                filtered_syscalls.push(FilteredSyscall {
                    syscall: path_str
                        .strip_prefix("syscall:")
                        .unwrap_or(path_str)
                        .to_string(),
                    comm,
                    source,
                    count,
                });
            } else {
                filesystem_denials.push(FilesystemDenial {
                    path: path_str.to_string(),
                    process: comm,
                    source,
                    count,
                    remediation: format!("vetto allow {path_str}"),
                });
            }
        }
    }

    let mut net_map: BTreeMap<(String, u16), u64> = BTreeMap::new();
    if let Some(nets) = val.get("net_requests").and_then(|v| v.as_array()) {
        for n in nets {
            let allowed = n.get("allowed").and_then(|v| v.as_bool()).unwrap_or(true);
            if !allowed {
                let host = n.get("host").and_then(|v| v.as_str()).unwrap_or("");
                let port = n.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16;
                *net_map.entry((host.to_string(), port)).or_insert(0) += 1;
            }
        }
    }

    let blocked_network = net_map
        .into_iter()
        .map(|((host, port), count)| BlockedNetworkDestination {
            destination: if port > 0 {
                format!("{host}:{port}")
            } else {
                host.clone()
            },
            host: host.clone(),
            port,
            count,
            remediation: format!("vetto allow --net {host}"),
        })
        .collect::<Vec<_>>();

    let mut suspicious_signals = Vec::new();
    if let Some(sigs) = val.get("suspicious_signals").and_then(|v| v.as_array()) {
        for s in sigs {
            let category = s.get("category").and_then(|v| v.as_str()).unwrap_or("");
            let severity = s.get("severity").and_then(|v| v.as_str()).unwrap_or("low");
            let subject = s.get("subject").and_then(|v| v.as_str()).unwrap_or("");
            let reason = s.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            let count = s.get("count").and_then(|v| v.as_u64()).unwrap_or(1);

            suspicious_signals.push(SuspiciousSignalDetail {
                category: category.to_string(),
                severity: severity.to_string(),
                subject: subject.to_string(),
                reason: reason.to_string(),
                count,
            });
        }
    }

    let violations_total = (filesystem_denials.iter().map(|d| d.count).sum::<u64>())
        + (blocked_network.iter().map(|n| n.count).sum::<u64>())
        + (filtered_syscalls.iter().map(|s| s.count).sum::<u64>());

    let mut recommendations = Vec::new();
    for d in &filesystem_denials {
        recommendations.push(format!("Grant filesystem access: {}", d.remediation));
    }
    for n in &blocked_network {
        recommendations.push(format!("Grant network domain: {}", n.remediation));
    }

    let command = val
        .get("command")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let agent = val
        .get("agent")
        .or_else(|| val.get("agent_preset"))
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();

    Ok(SessionAuditDetail {
        session_id,
        timestamp,
        command,
        agent,
        profile,
        tier,
        net_mode,
        exit_code,
        duration_secs,
        violations_total,
        events_total,
        filesystem_denials,
        blocked_network,
        filtered_syscalls,
        suspicious_signals,
        recommendations,
    })
}

fn build_detail_from_history_record(rec: &AuditRecord) -> SessionAuditDetail {
    let mut recommendations = Vec::new();
    if rec.blocked_count > 0 {
        recommendations.push(format!(
            "Session encountered {} intercepted violations. Check session log for full stream.",
            rec.blocked_count
        ));
    }
    if rec.exit_code == 124 {
        recommendations.push("Session timed out: consider extending --timeout".to_string());
    }

    SessionAuditDetail {
        session_id: rec.session_id.clone(),
        timestamp: rec.ts,
        command: rec.command.clone(),
        agent: rec.agent.clone(),
        profile: rec.profile.clone(),
        tier: rec.tier.clone(),
        net_mode: rec.net_mode.clone(),
        exit_code: rec.exit_code,
        duration_secs: rec.duration_secs,
        violations_total: rec.blocked_count,
        events_total: rec.events_total,
        filesystem_denials: Vec::new(),
        blocked_network: Vec::new(),
        filtered_syscalls: Vec::new(),
        suspicious_signals: Vec::new(),
        recommendations,
    }
}

/// Dispatches the `vetto audit` CLI subcommand with session inspection or listing.
pub fn run_audit_command(
    session_id: Option<&str>,
    latest: bool,
    since: Option<&str>,
    agent: Option<&str>,
    limit: Option<usize>,
    query: Option<&str>,
    json_output: bool,
) -> Result<()> {
    if latest || session_id.is_some() {
        let detail = if latest {
            inspect_latest_session()?
        } else {
            let id = session_id.unwrap();
            match inspect_session(id) {
                Ok(d) => d,
                Err(e) => {
                    // If target wasn't found as a direct session, attempt query listing
                    if since.is_none() && agent.is_none() && query.is_none() {
                        if let Ok(()) = run_audit(None, None, limit, Some(id), json_output) {
                            return Ok(());
                        }
                    }
                    return Err(e);
                }
            }
        };

        if json_output {
            println!("{}", serde_json::to_string_pretty(&detail)?);
        } else {
            render_session_audit(&detail);
        }
        return Ok(());
    }

    run_audit(since, agent, limit, query, json_output)
}

/// Formats and renders a detailed session audit to stdout.
pub fn render_session_audit(detail: &SessionAuditDetail) {
    let status_str = if detail.exit_code == 0 {
        "0 (Success)".to_string()
    } else if detail.exit_code == 124 {
        "124 (Timeout)".to_string()
    } else {
        format!("{} (Failed)", detail.exit_code)
    };

    println!("=== Vetto Session Audit: {} ===", detail.session_id);
    println!(
        "Timestamp:    {}",
        detail.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(ref cmd) = detail.command {
        println!("Command:      {cmd} (preset: {})", detail.agent);
    } else {
        println!("Agent Preset: {}", detail.agent);
    }
    println!(
        "Sandbox Tier: {} (Profile: {})",
        detail.tier, detail.profile
    );
    println!("Network Mode: {}", detail.net_mode);
    println!("Exit Status:  {status_str}");
    println!("Duration:     {}s", detail.duration_secs);
    println!(
        "Violations:   {} intercepted security event(s) (out of {} total events)",
        detail.violations_total, detail.events_total
    );
    println!();

    // 1. Filesystem Denials
    println!("[1] Denied Filesystem Access (Landlock / Sandbox Boundary):");
    if detail.filesystem_denials.is_empty() {
        println!("  • None observed");
    } else {
        for d in &detail.filesystem_denials {
            println!(
                "  • {} ({} attempt(s) by '{}', source: {})",
                d.path, d.count, d.process, d.source
            );
            println!("    └─ Remediation: {}", d.remediation);
        }
    }
    println!();

    // 2. Blocked Network
    println!("[2] Blocked Outbound Network Destinations:");
    if detail.blocked_network.is_empty() {
        println!("  • None observed");
    } else {
        for n in &detail.blocked_network {
            println!("  • {} ({} denied connection(s))", n.destination, n.count);
            println!("    └─ Remediation: {}", n.remediation);
        }
    }
    println!();

    // 3. Filtered Syscalls
    println!("[3] Filtered Syscalls & Kernel Violations (Seccomp / Audit):");
    if detail.filtered_syscalls.is_empty() {
        println!("  • None observed");
    } else {
        for s in &detail.filtered_syscalls {
            println!(
                "  • Syscall: {} (comm: '{}', source: {}, {} occurrence(s))",
                s.syscall, s.comm, s.source, s.count
            );
        }
    }
    println!();

    // 4. Suspicious Signals
    if !detail.suspicious_signals.is_empty() {
        println!("[4] Suspicious Signals Intercepted:");
        for sig in &detail.suspicious_signals {
            println!(
                "  • [{}] {} on '{}': {} ({} count)",
                sig.severity.to_ascii_uppercase(),
                sig.category,
                sig.subject,
                sig.reason,
                sig.count
            );
        }
        println!();
    }

    // 5. Policy Recommendations
    if !detail.recommendations.is_empty() {
        println!("[*] Policy Recommendations:");
        for rec in &detail.recommendations {
            println!("  • {rec}");
        }
        println!();
    }
}

/// Execute the `vetto audit` session listing CLI subcommand.
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
    filtered.sort_by_key(|a| std::cmp::Reverse(a.ts));

    if let Some(lim) = limit {
        filtered.truncate(lim);
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
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
        "{:<19}  {:<14}  {:<12}  {:<10}  {:<4}  {:<7}  {:<8}  {:<6}",
        "TIMESTAMP", "SESSION ID", "AGENT", "PROFILE", "EXIT", "BLOCKED", "TIER", "DUR"
    );
    println!(
        "{:-<19}  {:-<14}  {:-<12}  {:-<10}  {:-<4}  {:-<7}  {:-<8}  {:-<6}",
        "", "", "", "", "", "", "", ""
    );

    for r in &filtered {
        let ts_str = r.ts.format("%Y-%m-%d %H:%M:%S").to_string();
        let dur_str = format!("{}s", r.duration_secs);
        println!(
            "{:<19}  {:<14}  {:<12}  {:<10}  {:<4}  {:<7}  {:<8}  {:<6}",
            ts_str,
            truncate_str(&r.session_id, 14),
            truncate_str(&r.agent, 12),
            truncate_str(&r.profile, 10),
            r.exit_code,
            r.blocked_count,
            truncate_str(&r.tier, 8),
            dur_str,
        );
    }

    println!();
    println!(
        "Tip: run 'vetto audit <session_id>' or 'vetto audit --latest' for detailed breakdown."
    );

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
                command: Some("python agent.py".into()),
                profile: "default".into(),
                policy_path: Some("/home/user/vetto.toml".into()),
                exit_code: 0,
                duration_secs: 10,
                tier: "full".into(),
                net_mode: "off".into(),
                blocked_count: 0,
                events_total: 10,
                report_path: None,
                log_path: None,
            },
            AuditRecord {
                ts: Utc::now() - Duration::hours(48),
                session_id: "session-2".into(),
                agent: "claude".into(),
                command: Some("claude".into()),
                profile: "strict".into(),
                policy_path: None,
                exit_code: 1,
                duration_secs: 5,
                tier: "fs-only".into(),
                net_mode: "off".into(),
                blocked_count: 2,
                events_total: 8,
                report_path: None,
                log_path: None,
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

    #[test]
    fn session_audit_detail_serialization() {
        let detail = SessionAuditDetail {
            session_id: "session-123".into(),
            timestamp: Utc::now(),
            command: Some("python run.py".into()),
            agent: "claude".into(),
            profile: "default".into(),
            tier: "full".into(),
            net_mode: "allowlist:api.anthropic.com".into(),
            exit_code: 0,
            duration_secs: 12,
            violations_total: 1,
            events_total: 45,
            filesystem_denials: vec![FilesystemDenial {
                path: "/home/user/.ssh/id_rsa".into(),
                process: "python".into(),
                source: "landlock".into(),
                count: 1,
                remediation: "vetto allow /home/user/.ssh/id_rsa".into(),
            }],
            blocked_network: vec![BlockedNetworkDestination {
                destination: "evil.example.com:443".into(),
                host: "evil.example.com".into(),
                port: 443,
                count: 1,
                remediation: "vetto allow --net evil.example.com".into(),
            }],
            filtered_syscalls: vec![FilteredSyscall {
                syscall: "ptrace".into(),
                comm: "python".into(),
                source: "seccomp".into(),
                count: 1,
            }],
            suspicious_signals: vec![],
            recommendations: vec!["vetto allow /home/user/.ssh/id_rsa".into()],
        };

        let json = serde_json::to_string(&detail).expect("serialize");
        assert!(json.contains("session-123"));
        assert!(json.contains("id_rsa"));
        assert!(json.contains("evil.example.com"));
        assert!(json.contains("ptrace"));
    }

    #[test]
    fn parse_json_report_extracts_security_violations() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto_audit_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let rep_file = temp_dir.join("test-report.json");

        let report_json = r#"{
            "session_id": "test-session-99",
            "command": "python agent.py --run",
            "agent": "claude",
            "started_at": "2026-09-02T12:00:00Z",
            "duration_secs": 15,
            "exit_code": 0,
            "tier": "full",
            "net_mode": "allowlist",
            "profile": "default",
            "events_total": 50,
            "blocked_attempts": [
                {
                    "path": "/home/user/.aws/credentials",
                    "comm": "agent",
                    "source": "landlock",
                    "count": 2
                },
                {
                    "path": "syscall:ptrace",
                    "comm": "agent",
                    "source": "seccomp",
                    "count": 1
                }
            ],
            "net_requests": [
                {
                    "host": "malicious.com",
                    "port": 443,
                    "allowed": false
                },
                {
                    "host": "malicious.com",
                    "port": 443,
                    "allowed": false
                }
            ]
        }"#;

        fs::write(&rep_file, report_json).expect("write report");
        let parsed = parse_json_report(&rep_file, "test-session-99").expect("parse report");

        assert_eq!(parsed.session_id, "test-session-99");
        assert_eq!(parsed.command.as_deref(), Some("python agent.py --run"));
        assert_eq!(parsed.agent, "claude");
        assert_eq!(parsed.filesystem_denials.len(), 1);
        assert_eq!(
            parsed.filesystem_denials[0].path,
            "/home/user/.aws/credentials"
        );
        assert_eq!(parsed.filesystem_denials[0].count, 2);

        assert_eq!(parsed.filtered_syscalls.len(), 1);
        assert_eq!(parsed.filtered_syscalls[0].syscall, "ptrace");

        assert_eq!(parsed.blocked_network.len(), 1);
        assert_eq!(parsed.blocked_network[0].host, "malicious.com");
        assert_eq!(parsed.blocked_network[0].count, 2);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn inspect_session_matches_stripped_session_prefix() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto_audit_prefix_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let log_file = temp_dir.join("session-4567.jsonl");

        let log_content = r#"{"event":"session_started","ts":"2026-09-02T12:00:00Z","pid":4567,"tier":"full","net_mode":"off","profile":"default"}
{"event":"blocked_attempt","ts":"2026-09-02T12:00:01Z","pid":4567,"comm":"codex","path":"/etc/shadow","source":"landlock"}
{"event":"session_ended","ts":"2026-09-02T12:00:02Z","exit_code":0,"duration_secs":2}
"#;
        fs::write(&log_file, log_content).expect("write log");

        let parsed = parse_jsonl_log(&log_file, "4567").expect("parse log");
        assert_eq!(parsed.session_id, "session-4567");
        assert_eq!(parsed.filesystem_denials.len(), 1);
        assert_eq!(parsed.filesystem_denials[0].path, "/etc/shadow");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn parse_jsonl_log_handles_fallback_type_field() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto_audit_fallback_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let log_file = temp_dir.join("session-7890.jsonl");

        let log_content = r#"{"type":"session_started","ts":"2026-09-02T12:00:00Z","pid":7890,"tier":"full","net_mode":"off","profile":"default"}
{"type":"blocked_attempt","ts":"2026-09-02T12:00:01Z","comm":"codex","path":"/root/.ssh/id_rsa","source":"landlock"}
{"type":"session_ended","ts":"2026-09-02T12:00:02Z","exit_code":0,"duration_secs":3}
"#;
        fs::write(&log_file, log_content).expect("write fallback log");

        let parsed = parse_jsonl_log(&log_file, "7890").expect("parse fallback log");
        assert_eq!(parsed.session_id, "session-7890");
        assert_eq!(parsed.filesystem_denials.len(), 1);
        assert_eq!(parsed.filesystem_denials[0].path, "/root/.ssh/id_rsa");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn parse_json_report_derives_session_from_filename_when_omitted() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto_audit_stem_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let rep_file = temp_dir.join(".vetto-report-5555.json");

        let report_json = r#"{
            "started_at": "2026-09-02T12:00:00Z",
            "duration_secs": 10,
            "exit_code": 0,
            "tier": "full",
            "net_mode": "off",
            "profile": "default",
            "events_total": 20
        }"#;

        fs::write(&rep_file, report_json).expect("write stem report");
        let parsed =
            parse_json_report(&rep_file, ".vetto-report-5555.json").expect("parse stem report");
        assert_eq!(parsed.session_id, "session-5555");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
