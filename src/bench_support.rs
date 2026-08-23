//! Deterministic input builders shared by the Criterion suite.
//!
//! These helpers intentionally do not create files, install a sandbox, or
//! inspect the host. Benchmarks decide which setup belongs outside the timed
//! region, while unit tests can verify the generated data as pure values.

use std::path::PathBuf;

use crate::report::stats::{BlockedRecord, NetRecord, SessionStats};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInputs {
    pub allow_write: Vec<PathBuf>,
    pub allow_read: Vec<PathBuf>,
}

/// Build a stable set of path names with exactly `rule_count` distinct paths.
/// Even-indexed paths are write roots and odd-indexed paths are read roots.
pub fn policy_inputs(rule_count: usize) -> PolicyInputs {
    let root = std::env::temp_dir().join("vetto-criterion-policy");
    let mut allow_write = Vec::with_capacity(rule_count.div_ceil(2));
    let mut allow_read = Vec::with_capacity(rule_count / 2);
    for index in 0..rule_count {
        let path = root.join(format!("rule-{index:04}"));
        if index % 2 == 0 {
            allow_write.push(path);
        } else {
            allow_read.push(path);
        }
    }
    PolicyInputs {
        allow_write,
        allow_read,
    }
}

/// Build a deterministic session snapshot with `record_count` records in the
/// maps/lists used by report renderers.
pub fn session_stats(record_count: usize) -> SessionStats {
    let mut stats = SessionStats {
        tier: "full".into(),
        net_mode: "off".into(),
        profile: "benchmark".into(),
        duration_secs: record_count as u64,
        exit_code: 0,
        events_total: (record_count as u64).saturating_mul(3),
        file_reads: record_count as u64,
        file_writes: record_count as u64 / 2,
        ..SessionStats::default()
    };
    for index in 0..record_count {
        stats
            .counts
            .insert(format!("event-{index:04}"), (index + 1) as u64);
        stats
            .op_counts
            .insert(format!("operation-{index:04}"), (index + 2) as u64);
        stats.blocked_attempts.push(BlockedRecord {
            path: format!("/tmp/benchmark/path-{index:04}"),
            comm: format!("agent-{index:04}"),
            source: "benchmark".into(),
            count: (index + 1) as u64,
        });
        stats.net_requests.push(NetRecord {
            host: format!("host-{index:04}.example"),
            port: 443,
            allowed: index % 2 == 0,
        });
        stats.notices.push(format!("notice-{index:04}"));
    }
    stats
}

/// Keep this module's public builders honest if their representation changes.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_inputs_are_stable_and_partitioned() {
        let first = policy_inputs(5);
        let second = policy_inputs(5);
        assert_eq!(first, second);
        assert_eq!(first.allow_write.len(), 3);
        assert_eq!(first.allow_read.len(), 2);
        assert_eq!(
            first.allow_write[0],
            first.allow_write[0].parent().unwrap().join("rule-0000")
        );
        assert_eq!(
            first.allow_read[1],
            first.allow_read[1].parent().unwrap().join("rule-0003")
        );
    }

    #[test]
    fn session_stats_builder_scales_every_report_collection() {
        let stats = session_stats(7);
        assert_eq!(stats.counts.len(), 7);
        assert_eq!(stats.op_counts.len(), 7);
        assert_eq!(stats.blocked_attempts.len(), 7);
        assert_eq!(stats.net_requests.len(), 7);
        assert_eq!(stats.notices.len(), 7);
        assert_eq!(stats.events_total, 21);
        assert!(stats.net_requests[0].allowed);
        assert!(!stats.net_requests[1].allowed);
    }

    #[test]
    fn zero_scale_has_no_variable_records() {
        let stats = session_stats(0);
        assert!(stats.counts.is_empty());
        assert!(stats.blocked_attempts.is_empty());
        assert!(stats.net_requests.is_empty());
        assert!(stats.notices.is_empty());
    }
}
