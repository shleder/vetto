//! End-of-session security recap: 3-5 lines from in-memory stats.
//!
//! Pure formatter, no I/O. Called from the exit path in `main.rs` with the
//! already-available snapshot — zero extra syscalls, zero log parsing.
//! Post-hoc mode (`vetto audit --latest --recap`) reuses the same rendering
//! over [`SessionRecapInput`] built from [`crate::audit::SessionAuditDetail`].

use std::collections::BTreeMap;

/// Top-N truncation for recap lists (counters are never truncated).
pub const RECAP_TOP_N: usize = 3;

/// Pre-aggregated input for the recap formatter.
///
/// Built either from the live [`crate::report::SessionStats`] snapshot
/// (exit path) or from [`crate::audit::SessionAuditDetail`] (post-hoc).
#[derive(Debug, Clone, Default)]
pub struct SessionRecapInput {
    pub exit_code: i32,
    pub duration_secs: u64,
    pub events_total: u64,
    /// (path, count) sorted desc by count.
    pub top_denied: Vec<(String, u64)>,
    pub denials_total: u64,
    /// (host:port, count) for denied egress, sorted desc.
    pub egress_denied: Vec<(String, u64)>,
    /// Allowed egress hosts (deduped).
    pub egress_allowed: Vec<String>,
    /// op name -> count (fs-read, fs-write, exec, net).
    pub op_counts: BTreeMap<String, u64>,
    pub files_changed: usize,
    /// verify preflight status ("off" when disabled).
    pub verify_status: String,
}

/// Render the recap lines (without the `vetto: recap: ` prefix).
/// Returns `None` when the session was fully clean — stay silent like before.
pub fn format_session_recap(input: &SessionRecapInput) -> Option<Vec<String>> {
    if input.denials_total == 0
        && input.egress_denied.is_empty()
        && input.files_changed == 0
    {
        return None;
    }
    let mut lines = Vec::with_capacity(5);
    lines.push(format!(
        "exit {}, {} denial{} contained, net denied {} (events {}, {}s)",
        input.exit_code,
        input.denials_total,
        if input.denials_total == 1 { "" } else { "s" },
        input.egress_denied.iter().map(|(_, c)| c).sum::<u64>(),
        input.events_total,
        input.duration_secs,
    ));
    if !input.top_denied.is_empty() {
        let top: Vec<String> = input
            .top_denied
            .iter()
            .take(RECAP_TOP_N)
            .map(|(p, c)| format!("{p} x{c}"))
            .collect();
        let rest = input.top_denied.len().saturating_sub(RECAP_TOP_N);
        lines.push(format!(
            "top denied: {}{}",
            top.join(", "),
            if rest > 0 {
                format!(" (+{rest} more)")
            } else {
                String::new()
            }
        ));
    }
    if !input.egress_denied.is_empty() || !input.egress_allowed.is_empty() {
        let denied: Vec<String> = input
            .egress_denied
            .iter()
            .take(RECAP_TOP_N)
            .map(|(h, c)| format!("{h} x{c}"))
            .collect();
        let mut seg = String::new();
        if !denied.is_empty() {
            seg.push_str(&format!("denied: {}", denied.join(", ")));
        }
        if !input.egress_allowed.is_empty() {
            let allowed: Vec<String> =
                input.egress_allowed.iter().take(RECAP_TOP_N).cloned().collect();
            if !seg.is_empty() {
                seg.push_str("; ");
            }
            seg.push_str(&format!("allowed: {}", allowed.join(", ")));
        }
        lines.push(format!("egress {seg}"));
    }
    if !input.op_counts.is_empty() || input.files_changed > 0 {
        let ops: Vec<String> = ["fs-read", "fs-write", "exec", "net"]
            .iter()
            .filter_map(|k| input.op_counts.get(*k).map(|c| format!("{k} {c}")))
            .collect();
        lines.push(format!(
            "intent: {}files changed {} → 'vetto audit --latest'",
            if ops.is_empty() {
                String::new()
            } else {
                format!("{}, ", ops.join(" / "))
            },
            input.files_changed,
        ));
    }
    Some(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SessionRecapInput {
        SessionRecapInput {
            exit_code: 0,
            duration_secs: 4,
            events_total: 340,
            top_denied: vec![
                ("/etc/shadow".into(), 5),
                ("~/.aws/credentials".into(), 3),
                ("/proc/x".into(), 2),
                ("/other".into(), 1),
            ],
            denials_total: 11,
            egress_denied: vec![("api.example.com:443".into(), 2)],
            egress_allowed: vec!["registry.npmjs.org".into()],
            op_counts: [("fs-read".into(), 120), ("exec".into(), 6)]
                .into_iter()
                .collect(),
            files_changed: 4,
            verify_status: "off".into(),
        }
    }

    #[test]
    fn clean_session_stays_silent() {
        assert!(format_session_recap(&SessionRecapInput::default()).is_none());
    }

    #[test]
    fn recap_top_is_truncated_counters_intact() {
        let lines = format_session_recap(&sample()).expect("recap");
        assert!(lines[0].contains("11 denials"));
        assert!(lines[1].contains("/etc/shadow x5"));
        assert!(lines[1].contains("(+1 more)"));
        assert!(lines[2].contains("api.example.com:443 x2"));
        assert!(lines[2].contains("registry.npmjs.org"));
        assert!(lines[3].contains("files changed 4"));
    }
}
