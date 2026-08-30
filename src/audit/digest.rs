//! Daily and periodic audit digest (`vetto digest`) (Feature 42).
//!
//! Aggregates session history from `~/.vetto/history.jsonl` across a time window (default 24h)
//! to produce a structured summary of sessions, blocked attempts, and top agents/policies.

use std::collections::HashMap;

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

use super::history::{
    default_history_path, filter_records, parse_since_duration, read_history, AuditRecord,
};

#[derive(Debug, Clone, Serialize)]
pub struct DigestSummary {
    pub window: String,
    pub total_sessions: usize,
    pub successful_sessions: usize,
    pub failed_sessions: usize,
    pub total_duration_secs: u64,
    pub total_blocked_attempts: u64,
    pub sessions_with_blocks: usize,
    pub total_events: u64,
    pub top_agents: Vec<(String, usize)>,
    pub top_profiles: Vec<(String, usize)>,
}

pub fn generate_digest(records: &[AuditRecord], window_label: &str) -> DigestSummary {
    let mut total_duration = 0u64;
    let mut successful = 0usize;
    let mut failed = 0usize;
    let mut total_blocked = 0u64;
    let mut sessions_with_blocks = 0usize;
    let mut total_events = 0u64;
    let mut agent_counts: HashMap<String, usize> = HashMap::new();
    let mut profile_counts: HashMap<String, usize> = HashMap::new();

    for r in records {
        total_duration = total_duration.saturating_add(r.duration_secs);
        if r.exit_code == 0 {
            successful += 1;
        } else {
            failed += 1;
        }
        if r.blocked_count > 0 {
            sessions_with_blocks += 1;
            total_blocked = total_blocked.saturating_add(r.blocked_count);
        }
        total_events = total_events.saturating_add(r.events_total);
        *agent_counts.entry(r.agent.clone()).or_insert(0) += 1;
        *profile_counts.entry(r.profile.clone()).or_insert(0) += 1;
    }

    let mut top_agents: Vec<_> = agent_counts.into_iter().collect();
    top_agents.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let mut top_profiles: Vec<_> = profile_counts.into_iter().collect();
    top_profiles.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    DigestSummary {
        window: window_label.to_string(),
        total_sessions: records.len(),
        successful_sessions: successful,
        failed_sessions: failed,
        total_duration_secs: total_duration,
        total_blocked_attempts: total_blocked,
        sessions_with_blocks,
        total_events,
        top_agents,
        top_profiles,
    }
}

/// Execute the `vetto digest` CLI subcommand.
pub fn run_digest(since: Option<&str>, json_output: bool) -> Result<()> {
    let window_str = since.unwrap_or("24h");
    let cutoff = parse_since_duration(window_str)?;

    let history_file = default_history_path()
        .ok_or_else(|| anyhow::anyhow!("could not resolve history file path"))?;
    let records = read_history(&history_file)?;
    let filtered_refs = filter_records(&records, Some(cutoff), None, None);
    let filtered_owned: Vec<AuditRecord> = filtered_refs.into_iter().cloned().collect();

    let digest = generate_digest(&filtered_owned, window_str);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&digest)?);
        return Ok(());
    }

    println!("=== vetto audit digest (past {}) ===", digest.window);
    println!(
        "Total Sessions:       {} ({} success, {} failed)",
        digest.total_sessions, digest.successful_sessions, digest.failed_sessions
    );
    println!(
        "Total Duration:       {}",
        format_duration(digest.total_duration_secs)
    );
    println!("Total Events:         {}", digest.total_events);
    println!(
        "Blocked Attempts:     {} (across {} session{})",
        digest.total_blocked_attempts,
        digest.sessions_with_blocks,
        if digest.sessions_with_blocks == 1 {
            ""
        } else {
            "s"
        }
    );

    if !digest.top_agents.is_empty() {
        println!("\nTop Agents:");
        for (agent, count) in &digest.top_agents {
            println!(
                "  - {:<16} {} session{}",
                agent,
                count,
                if *count == 1 { "" } else { "s" }
            );
        }
    }

    if !digest.top_profiles.is_empty() {
        println!("\nTop Profiles:");
        for (profile, count) in &digest.top_profiles {
            println!(
                "  - {:<16} {} session{}",
                profile,
                count,
                if *count == 1 { "" } else { "s" }
            );
        }
    }

    Ok(())
}

fn format_duration(secs: u64) -> String {
    if secs >= 3600 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        format!("{h}h {m}m {s}s")
    } else if secs >= 60 {
        let m = secs / 60;
        let s = secs % 60;
        format!("{m}m {s}s")
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_correctly_aggregates_session_stats() {
        let records = vec![
            AuditRecord {
                ts: Utc::now(),
                session_id: "s1".into(),
                agent: "codex".into(),
                profile: "default".into(),
                policy_path: None,
                exit_code: 0,
                duration_secs: 60,
                tier: "full".into(),
                net_mode: "off".into(),
                blocked_count: 0,
                events_total: 20,
                report_path: None,
            },
            AuditRecord {
                ts: Utc::now(),
                session_id: "s2".into(),
                agent: "codex".into(),
                profile: "strict".into(),
                policy_path: None,
                exit_code: 1,
                duration_secs: 40,
                tier: "full".into(),
                net_mode: "off".into(),
                blocked_count: 3,
                events_total: 15,
                report_path: None,
            },
            AuditRecord {
                ts: Utc::now(),
                session_id: "s3".into(),
                agent: "claude".into(),
                profile: "default".into(),
                policy_path: None,
                exit_code: 0,
                duration_secs: 100,
                tier: "full".into(),
                net_mode: "off".into(),
                blocked_count: 2,
                events_total: 30,
                report_path: None,
            },
        ];

        let digest = generate_digest(&records, "24h");
        assert_eq!(digest.total_sessions, 3);
        assert_eq!(digest.successful_sessions, 2);
        assert_eq!(digest.failed_sessions, 1);
        assert_eq!(digest.total_duration_secs, 200);
        assert_eq!(digest.total_blocked_attempts, 5);
        assert_eq!(digest.sessions_with_blocks, 2);
        assert_eq!(digest.total_events, 65);
        assert_eq!(digest.top_agents[0], ("codex".to_string(), 2));
        assert_eq!(digest.top_profiles[0], ("default".to_string(), 2));
    }
}
