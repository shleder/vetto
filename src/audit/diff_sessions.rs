use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::audit::history::{inspect_session, SessionAuditDetail};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDiff {
    pub profile_a: String,
    pub profile_b: String,
    pub net_mode_a: String,
    pub net_mode_b: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocksDiff {
    pub a_only_paths: Vec<String>,
    pub b_only_paths: Vec<String>,
    pub common_paths: Vec<String>,
    pub a_only_domains: Vec<String>,
    pub b_only_domains: Vec<String>,
    pub common_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IoDiff {
    pub writes_a: u64,
    pub writes_b: u64,
    pub created_a: u64,
    pub created_b: u64,
    pub modified_a: u64,
    pub modified_b: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitCodeDiff {
    pub a: i32,
    pub b: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDiff {
    pub session_a_id: String,
    pub session_b_id: String,
    pub policy_diff: PolicyDiff,
    pub blocks_diff: BlocksDiff,
    pub io_diff: IoDiff,
    pub exit_code_diff: ExitCodeDiff,
}

fn calculate_blocks_diff(a: &SessionAuditDetail, b: &SessionAuditDetail) -> BlocksDiff {
    let mut paths_a = HashSet::new();
    for d in &a.filesystem_denials {
        paths_a.insert(d.path.clone());
    }
    let mut paths_b = HashSet::new();
    for d in &b.filesystem_denials {
        paths_b.insert(d.path.clone());
    }
    let mut domains_a = HashSet::new();
    for d in &a.blocked_network {
        domains_a.insert(d.destination.clone());
    }
    let mut domains_b = HashSet::new();
    for d in &b.blocked_network {
        domains_b.insert(d.destination.clone());
    }

    let mut a_only_paths: Vec<_> = paths_a.difference(&paths_b).cloned().collect();
    let mut b_only_paths: Vec<_> = paths_b.difference(&paths_a).cloned().collect();
    let mut common_paths: Vec<_> = paths_a.intersection(&paths_b).cloned().collect();

    let mut a_only_domains: Vec<_> = domains_a.difference(&domains_b).cloned().collect();
    let mut b_only_domains: Vec<_> = domains_b.difference(&domains_a).cloned().collect();
    let mut common_domains: Vec<_> = domains_a.intersection(&domains_b).cloned().collect();

    a_only_paths.sort();
    b_only_paths.sort();
    common_paths.sort();
    a_only_domains.sort();
    b_only_domains.sort();
    common_domains.sort();

    BlocksDiff {
        a_only_paths,
        b_only_paths,
        common_paths,
        a_only_domains,
        b_only_domains,
        common_domains,
    }
}

fn get_session_log_path(session_id: &str, reports_dir: &Path) -> Option<std::path::PathBuf> {
    if Path::new(session_id).exists()
        && Path::new(session_id).extension().map_or(false, |e| e == "jsonl") {
        return Some(Path::new(session_id).to_path_buf());
    }
    if let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
    {
        let p = home.join(".vetto").join("logs").join(format!("{}.jsonl", session_id));
        if p.exists() { return Some(p); }
        let p2 = home.join(".vetto").join("logs").join(format!("session-{}.jsonl", session_id));
        if p2.exists() { return Some(p2); }
    }
    let p = reports_dir.join(format!("{}.jsonl", session_id));
    if p.exists() { return Some(p); }
    let p2 = reports_dir.join(format!("session-{}.jsonl", session_id));
    if p2.exists() { return Some(p2); }
    None
}

fn count_fs_mutations(session_id: &str, reports_dir: &Path) -> (u64, u64, u64) {
    let mut writes = 0;
    let mut created = 0;
    let mut modified = 0;

    if let Some(path) = get_session_log_path(session_id, reports_dir) {
        if let Ok(file) = File::open(&path) {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            if line.contains("\"fs_mutation\"") || line.contains("\"FsMutation\"") {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                    let mut is_mutation = false;
                    if let Some(t) = val.get("type").and_then(|v| v.as_str()) {
                        if t == "fs_mutation" {
                            is_mutation = true;
                        }
                    } else if val.get("FsMutation").is_some() {
                        is_mutation = true;
                    }

                    if is_mutation {
                        writes += 1;
                        let mutation_type = val.get("mutation_type")
                            .or_else(|| val.pointer("/FsMutation/mutation_type"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        
                        if mutation_type == "Created" {
                            created += 1;
                        } else if mutation_type == "Modified" {
                            modified += 1;
                        }
                    }
                }
            }
        }
    }
    }
    (writes, created, modified)
}

pub fn compare_sessions(
    session_a_id: &str,
    session_b_id: &str,
    reports_dir: &Path,
) -> Result<SessionDiff> {
    let a = inspect_session(session_a_id).context("inspect session A")?;
    let b = inspect_session(session_b_id).context("inspect session B")?;

    let blocks_diff = calculate_blocks_diff(&a, &b);

    let (writes_a, created_a, modified_a) = count_fs_mutations(session_a_id, reports_dir);
    let (writes_b, created_b, modified_b) = count_fs_mutations(session_b_id, reports_dir);

    Ok(SessionDiff {
        session_a_id: a.session_id.clone(),
        session_b_id: b.session_id.clone(),
        policy_diff: PolicyDiff {
            profile_a: a.profile.clone(),
            profile_b: b.profile.clone(),
            net_mode_a: a.net_mode.clone(),
            net_mode_b: b.net_mode.clone(),
        },
        blocks_diff,
        io_diff: IoDiff {
            writes_a,
            writes_b,
            created_a,
            created_b,
            modified_a,
            modified_b,
        },
        exit_code_diff: ExitCodeDiff {
            a: a.exit_code,
            b: b.exit_code,
        },
    })
}

pub fn format_diff_text(diff: &SessionDiff) -> String {
    let mut out = String::new();
    out.push_str(&format!("Session A: {}\n", diff.session_a_id));
    out.push_str(&format!("Session B: {}\n", diff.session_b_id));
    out.push_str("\n[Policy Diff]\n");
    if diff.policy_diff.profile_a != diff.policy_diff.profile_b {
        out.push_str(&format!(
            "Profile: {} -> {}\n",
            diff.policy_diff.profile_a, diff.policy_diff.profile_b
        ));
    } else {
        out.push_str(&format!("Profile: {} (unchanged)\n", diff.policy_diff.profile_a));
    }
    if diff.policy_diff.net_mode_a != diff.policy_diff.net_mode_b {
        out.push_str(&format!(
            "Net Mode: {} -> {}\n",
            diff.policy_diff.net_mode_a, diff.policy_diff.net_mode_b
        ));
    } else {
        out.push_str(&format!("Net Mode: {} (unchanged)\n", diff.policy_diff.net_mode_a));
    }

    out.push_str("\n[Exit Code Diff]\n");
    out.push_str(&format!("Session A: {}\n", diff.exit_code_diff.a));
    out.push_str(&format!("Session B: {}\n", diff.exit_code_diff.b));

    out.push_str("\n[I/O Diff]\n");
    out.push_str(&format!("Writes: A={} B={}\n", diff.io_diff.writes_a, diff.io_diff.writes_b));
    out.push_str(&format!("Created: A={} B={}\n", diff.io_diff.created_a, diff.io_diff.created_b));
    out.push_str(&format!(
        "Modified: A={} B={}\n",
        diff.io_diff.modified_a, diff.io_diff.modified_b
    ));

    out.push_str("\n[Blocks Diff - Paths]\n");
    out.push_str(&format!("A only: {}\n", diff.blocks_diff.a_only_paths.join(", ")));
    out.push_str(&format!("B only: {}\n", diff.blocks_diff.b_only_paths.join(", ")));
    out.push_str(&format!("Common: {}\n", diff.blocks_diff.common_paths.join(", ")));

    out.push_str("\n[Blocks Diff - Domains]\n");
    out.push_str(&format!("A only: {}\n", diff.blocks_diff.a_only_domains.join(", ")));
    out.push_str(&format!("B only: {}\n", diff.blocks_diff.b_only_domains.join(", ")));
    out.push_str(&format!("Common: {}\n", diff.blocks_diff.common_domains.join(", ")));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_blocks_diff() {
        let mut a = SessionAuditDetail {
            session_id: "A".into(),
            timestamp: Utc::now(),
            command: None,
            agent: "".into(),
            profile: "".into(),
            tier: "".into(),
            net_mode: "".into(),
            exit_code: 0,
            duration_secs: 0,
            violations_total: 0,
            events_total: 0,
            filesystem_denials: vec![],
            blocked_network: vec![],
            filtered_syscalls: vec![],
            suspicious_signals: vec![],
            recommendations: vec![],
        };
        let mut b = a.clone();
        b.session_id = "B".into();

        a.filesystem_denials.push(crate::audit::history::FilesystemDenial {
            path: "/a".into(),
            process: "".into(),
            source: "".into(),
            count: 1,
            remediation: "".into(),
        });
        a.filesystem_denials.push(crate::audit::history::FilesystemDenial {
            path: "/common".into(),
            process: "".into(),
            source: "".into(),
            count: 1,
            remediation: "".into(),
        });

        b.filesystem_denials.push(crate::audit::history::FilesystemDenial {
            path: "/b".into(),
            process: "".into(),
            source: "".into(),
            count: 1,
            remediation: "".into(),
        });
        b.filesystem_denials.push(crate::audit::history::FilesystemDenial {
            path: "/common".into(),
            process: "".into(),
            source: "".into(),
            count: 1,
            remediation: "".into(),
        });

        let diff = calculate_blocks_diff(&a, &b);
        assert_eq!(diff.a_only_paths, vec!["/a"]);
        assert_eq!(diff.b_only_paths, vec!["/b"]);
        assert_eq!(diff.common_paths, vec!["/common"]);
    }
}
