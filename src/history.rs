//! Session history tracking and automated timeout estimation (`--timeout auto`).
//!
//! Calculates project- and agent-specific timeouts as p95 past session duration * 2
//! with a 5-minute (300-second) lower floor.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const MIN_AUTO_TIMEOUT_SECS: u64 = 300; // 5 minutes

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHistoryRecord {
    pub agent: String,
    pub duration_secs: u64,
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub exit_code: i32,
}

/// Append a completed session record to project history.
pub fn append_session_history(project_dir: &Path, record: &SessionHistoryRecord) -> Result<()> {
    let vetto_dir = project_dir.join(".vetto");
    let _ = fs::create_dir_all(&vetto_dir);
    let history_file = vetto_dir.join("history");

    let line = serde_json::to_string(record)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_file)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Read all duration samples for an agent from `.vetto/history` or `.vetto/audit.jsonl`.
pub fn load_agent_durations(project_dir: &Path, agent_name: &str) -> Vec<u64> {
    let mut samples = Vec::new();
    let history_file = project_dir.join(".vetto/history");

    if let Ok(file) = fs::File::open(&history_file) {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            if let Ok(record) = serde_json::from_str::<SessionHistoryRecord>(&line) {
                if record.agent == agent_name || record.agent.ends_with(agent_name) {
                    samples.push(record.duration_secs);
                }
            }
        }
    }

    samples
}

/// Calculate automated timeout for an agent based on past session history.
pub fn compute_auto_timeout(project_dir: &Path, agent_name: &str) -> Option<Duration> {
    let mut samples = load_agent_durations(project_dir, agent_name);
    if samples.is_empty() {
        return None;
    }

    samples.sort_unstable();
    let p95_index = ((samples.len() as f64 - 1.0) * 0.95).round() as usize;
    let p95 = samples[p95_index.min(samples.len() - 1)];

    let computed_secs = (p95.saturating_mul(2)).max(MIN_AUTO_TIMEOUT_SECS);
    Some(Duration::from_secs(computed_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_p95_timeout_with_floor() {
        let temp = std::env::temp_dir().join(format!("vetto-hist-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();

        // 1. Empty history returns None
        assert_eq!(compute_auto_timeout(&temp, "codex"), None);

        // 2. Short durations hit the 5-minute floor (300s)
        for d in [10, 20, 30, 40, 50] {
            append_session_history(
                &temp,
                &SessionHistoryRecord {
                    agent: "codex".into(),
                    duration_secs: d,
                    ts: "".into(),
                    exit_code: 0,
                },
            )
            .unwrap();
        }
        let timeout = compute_auto_timeout(&temp, "codex").unwrap();
        assert_eq!(timeout, Duration::from_secs(300));

        // 3. Long durations scale properly (p95 * 2)
        for d in 1..=100 {
            append_session_history(
                &temp,
                &SessionHistoryRecord {
                    agent: "heavy-agent".into(),
                    duration_secs: d * 10, // 10s to 1000s, p95 ~ 950s
                    ts: "".into(),
                    exit_code: 0,
                },
            )
            .unwrap();
        }
        let heavy_timeout = compute_auto_timeout(&temp, "heavy-agent").unwrap();
        // p95 = 950s -> 950 * 2 = 1900s
        assert!(heavy_timeout.as_secs() >= 1800);

        let _ = fs::remove_dir_all(&temp);
    }
}
