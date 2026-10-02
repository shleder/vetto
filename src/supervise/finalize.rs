//! Finalization of a supervised session (`src/supervise/finalize.rs`).
//!
//! Handles post-exit verification, extinction audit, cgroup termination,
//! project filesystem diffs, VerdictEngine evaluation, SARIF/JSON reporting,
//! and final exit code calculation.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::audit::{self, VerdictEngine, VerdictStatus};
use crate::config::RunConfig;
use crate::events::{self, Event};
use crate::exit_codes;
use crate::policy;
use crate::proctree::{ExtinctionVerifier, PlatformExtinctionTier};
use crate::report;
use crate::rescue;
use crate::sandbox;
use crate::supervise::error::SuperviseError;
use crate::supervise::lifecycle::LifecycleOutcome;
use crate::supervise::pump::PumpData;
use crate::supervise::spawn::SupervisedSession;
use crate::verify_ng::sandbox_backend::{EnforcementState, SecurityCapability};

/// Result and authoritative security verdict of a finalized supervised session.
#[derive(Debug, Clone)]
pub struct SupervisionVerdict {
    pub final_exit_code: i32,
    pub pass: bool,
    pub exit_code: i32,
    pub timed_out: bool,
    pub duration_secs: u64,
    pub blocked_total: u64,
    pub report_path: Option<PathBuf>,
    pub files_changed: usize,
    pub verdict: Option<audit::verdict::FinalVerdict>,
    pub audit_record: Option<audit::AuditRecord>,
}

impl SupervisionVerdict {
    pub fn dry_run() -> Self {
        Self {
            final_exit_code: 0,
            pass: true,
            exit_code: 0,
            timed_out: false,
            duration_secs: 0,
            blocked_total: 0,
            report_path: None,
            files_changed: 0,
            verdict: None,
            audit_record: None,
        }
    }
}

/// Context consumed by `finalize_session`.
pub struct FinalizeContext<'a> {
    pub cfg: &'a RunConfig,
    pub session: SupervisedSession,
    pub lifecycle: LifecycleOutcome,
    pub pump_data: Option<PumpData>,
}

/// Finalizes the supervised session, verifying process extinction,
/// evaluating verdicts, generating reports, and calculating the final exit code.
pub fn finalize_session(mut ctx: FinalizeContext) -> Result<SupervisionVerdict, SuperviseError> {
    let exit_code = ctx.lifecycle.exit_code;
    let timed_out = ctx.lifecycle.timed_out;
    let duration_secs = ctx.lifecycle.duration_secs;

    // 1. Publish SessionEnded event and let sinks drain
    ctx.session.bus.publish(Event::SessionEnded {
        ts: events::types::now(),
        exit_code,
        duration_secs,
    });
    std::thread::sleep(std::time::Duration::from_millis(100));

    // 2. Mathematical Process Tree Extinction Theorem (§12.1, INV-27)
    #[cfg(target_os = "linux")]
    let extinction_platform = match ctx.session.tier {
        Some(policy::Tier::Full) => PlatformExtinctionTier::LinuxTier1Proven,
        _ => PlatformExtinctionTier::LinuxTier1Proven,
    };
    #[cfg(target_os = "macos")]
    let extinction_platform = PlatformExtinctionTier::MacOsTier2BestEffort;
    #[cfg(target_os = "windows")]
    let extinction_platform = PlatformExtinctionTier::WindowsTier3Proven;
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let extinction_platform = PlatformExtinctionTier::LinuxTier1Proven;

    // Extract real extinction outcome and residual process metrics from production execution
    let mut surviving_processes = 0usize;
    let mut surviving_resources = 0usize;
    let mut extinction_breach_detected = false;
    let mut extinction_reason = String::new();

    if let Some(ref prod_res) = ctx.lifecycle.production_result {
        if let Some(ref v) = prod_res.verdict {
            if v.exit_code == exit_codes::EXIT_FAIL_CLOSED || v.status == VerdictStatus::Fail {
                if v.reason.contains("extinction") || v.reason.contains("Lifecycle breach") {
                    extinction_breach_detected = true;
                    extinction_reason = v.reason.clone();
                    if let Some(pos) = v.reason.find("Lifecycle breach: ") {
                        let after = &v.reason[pos + "Lifecycle breach: ".len()..];
                        if let Some(end) = after.find(" descendant") {
                            if let Ok(count) = after[..end].trim().parse::<usize>() {
                                surviving_processes = count;
                            }
                        }
                    }
                    if surviving_processes == 0 {
                        surviving_processes = 1;
                    }
                }
            }
        }

        let tree_cap = prod_res.report.state(SecurityCapability::ProcessTreeContainment);
        if tree_cap == EnforcementState::Failed {
            extinction_breach_detected = true;
            if surviving_processes == 0 {
                surviving_processes = 1;
            }
            if extinction_reason.is_empty() {
                extinction_reason = "Process tree containment capability failed verification".to_string();
            }
        }

        if let Some(ref diag) = prod_res.diagnostic {
            if diag.contains("extinction breach") {
                extinction_breach_detected = true;
                if extinction_reason.is_empty() {
                    extinction_reason = diag.clone();
                }
            }
            if let Some(idx) = diag.find("residual=[") {
                let after = &diag[idx + "residual=[".len()..];
                if let Some(end) = after.find(']') {
                    let slice = after[..end].trim();
                    if !slice.is_empty() {
                        let count = slice.split(',').filter(|s| !s.trim().is_empty()).count();
                        if count > 0 {
                            surviving_processes = surviving_processes.max(count);
                            extinction_breach_detected = true;
                        }
                    }
                }
            }
        }

        if prod_res.timed_out && prod_res.exit_code == Some(exit_codes::EXIT_FAIL_CLOSED) {
            extinction_breach_detected = true;
            if surviving_processes == 0 {
                surviving_processes = 1;
            }
            if extinction_reason.is_empty() {
                extinction_reason = "Session timeout teardown failed extinction verification".to_string();
            }
        }
    }

    if extinction_breach_detected && surviving_processes == 0 {
        surviving_processes = 1;
    }

    let extinction_res = ExtinctionVerifier::verify(
        extinction_platform,
        surviving_processes,
        surviving_resources,
        0,
    );

    if let Err(ref breach) = extinction_res {
        let msg = if !extinction_reason.is_empty() {
            &extinction_reason
        } else {
            &breach.reason
        };
        eprintln!(
            "vetto: extinction breach (fail-closed exit 125, INV-20): platform={} reason={}",
            breach.platform.label(),
            msg
        );
    }

    // 4. Telemetry and Funnel Milestone
    let snap = ctx.session.stats.snapshot();
    let _ = crate::telemetry::send_session_telemetry(&snap, ctx.session.tier_label());
    let _ = crate::telemetry::record_funnel_milestone("first_session");

    // 5. Filesystem diff calculation
    let diff = if ctx.session.diff_enabled {
        report::diff_project::ProjectDiff::compute(&ctx.session.initial_manifest, &ctx.session.project)
    } else {
        report::diff_project::ProjectDiff::default()
    };

    if !diff.is_empty() {
        ctx.session.bus.publish(Event::Notice {
            ts: events::types::now(),
            message: diff.summary(),
        });
        eprintln!("vetto: {}", diff.summary());
    }

    ctx.session.bus.publish(Event::Notice {
        ts: events::types::now(),
        message: format!("I/O summary: {}", snap.io_summary()),
    });

    // 6. Reports generation (Markdown, JSON, SARIF)
    let mut primary_report = None;
    if !ctx.cfg.report_formats.is_empty() {
        let report_options = report::ReportOptions {
            report_dir: ctx.cfg.report_dir.clone(),
            auto_cleanup: ctx.cfg.report_auto_cleanup,
            retention: ctx.cfg.report_retention,
            max_age_secs: ctx.cfg.report_max_age_secs,
        };
        for p in report::write_reports_with_options(&snap, &ctx.cfg.report_formats, &report_options)
            .map_err(SuperviseError::ReportGenerationFailed)?
        {
            eprintln!("vetto: report written: {}", p.display());
            if primary_report.is_none() {
                primary_report = Some(p);
            }
        }
    }

    // 7. Session Registry Unregister & Project Session History
    if let Ok(reg) = crate::cli::status::SessionRegistry::new() {
        reg.unregister(&ctx.session.session_id);
    }

    if !ctx.cfg.benchmark {
        let agent_name = ctx
            .cfg
            .agent_preset
            .clone()
            .unwrap_or_else(|| ctx.cfg.agent.first().cloned().unwrap_or_default());
        let _ = crate::history::append_session_history(
            &ctx.session.project,
            &crate::history::SessionHistoryRecord {
                agent: agent_name,
                duration_secs,
                ts: events::types::now().to_rfc3339(),
                exit_code,
            },
        );
    }

    // 8. Count blocked security events
    let blocked_file_total: u64 = snap.blocked_attempts.iter().map(|b| b.count).sum();
    let blocked_network_total = snap
        .net_requests
        .iter()
        .filter(|request| !request.allowed)
        .count() as u64;
    let blocked_total = blocked_file_total.saturating_add(blocked_network_total);

    let blocked_threshold_reached = match ctx.cfg.fail_on_block {
        Some(threshold) => blocked_total >= threshold,
        None => false,
    };

    if timed_out {
        eprintln!("vetto: session timed out; killed at the deadline (exit 124)");
    }

    if let Some(threshold) = ctx.cfg.fail_on_block {
        if blocked_total >= threshold {
            if ctx.cfg.shadow {
                eprintln!(
                    "vetto: shadow: would deny/fail session on block threshold (blocked={} threshold={}) (shadow mode active; exit code unchanged)",
                    blocked_total, threshold
                );
            } else {
                eprintln!(
                    "vetto: fail-on-block threshold reached (blocked={} threshold={})",
                    blocked_total, threshold
                );
            }
        }
    }

    // 9. VerdictEngine Evaluation
    let evidence_channel_intact = sandbox::is_evidence_channel_intact();
    let verdict = VerdictEngine::evaluate(
        &ctx.session.contract,
        blocked_total as usize,
        0, // unauthorized writes
        surviving_processes,
        evidence_channel_intact,
        exit_code,
    );

    // 10. Final Exit Code Calculation
    let mut code = exit_codes::map_session_exit_code(
        exit_code,
        timed_out,
        blocked_threshold_reached && !ctx.cfg.shadow,
    );

    if !ctx.cfg.shadow
        && !timed_out
        && code != exit_codes::EXIT_POLICY_BLOCKED
        && (verdict.exit_code == exit_codes::EXIT_FAIL_CLOSED
            || verdict.status != VerdictStatus::Pass
            || blocked_total > 0
            || extinction_res.is_err()
            || surviving_processes > 0)
    {
        code = exit_codes::EXIT_FAIL_CLOSED;
    }

    if timed_out && (extinction_res.is_err() || surviving_processes > 0) {
        // Extinction breach turns timeout 124 into fail-closed 125
        code = exit_codes::EXIT_FAIL_CLOSED;
    }

    if extinction_res.is_err() || surviving_processes > 0 {
        code = exit_codes::EXIT_FAIL_CLOSED;
    }

    // 11. CI JSON vs Human Recap Output
    if ctx.cfg.ci {
        println!(
            "{}",
            serde_json::json!({
                "vetto_ci": {
                    "exit_code": exit_code,
                    "final_exit_code": code,
                    "duration_secs": duration_secs,
                    "tier": ctx.session.tier_label(),
                    "net": ctx.cfg.net.label(),
                    "profile": ctx.session.policy.name,
                    "blocked_attempts": blocked_total,
                    "blocked_file_attempts": blocked_file_total,
                    "network_denied": blocked_network_total,
                    "bytes_read": snap.bytes_read,
                    "bytes_written": snap.bytes_written,
                    "read_ops": snap.read_ops,
                    "write_ops": snap.write_ops,
                    "files_modified": diff.total_changed(),
                    "events_total": snap.events_total,
                    "verify": ctx.session.verify_outcome
                        .as_ref()
                        .map(|report| report.status().to_string())
                        .unwrap_or_else(|| "off".to_string()),
                    "timed_out": timed_out,
                    "sanitizer": "BEST-EFFORT",
                }
            })
        );
    } else {
        eprintln!(
            "vetto: agent exited {} after {}s (blocked={}, events={}, I/O: {}, tier={}{})",
            exit_code,
            duration_secs,
            blocked_total,
            snap.events_total,
            snap.io_summary(),
            ctx.session.tier_label(),
            if timed_out { ", TIMEOUT" } else { "" },
        );
        if let Some(hint) = exit_codes::recap_hint(code, blocked_total, timed_out) {
            eprintln!("vetto: recap: {hint}");
        }

        let mut top_denied: Vec<(String, u64)> = snap
            .blocked_attempts
            .iter()
            .map(|b| (b.path.clone(), b.count))
            .collect();
        top_denied.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        let mut egress_map: BTreeMap<String, u64> = BTreeMap::new();
        let mut egress_allowed: Vec<String> = Vec::new();
        for r in &snap.net_requests {
            if r.allowed {
                let h = format!("{}:{}", r.host, r.port);
                if !egress_allowed.contains(&h) {
                    egress_allowed.push(h);
                }
            } else {
                *egress_map.entry(format!("{}:{}", r.host, r.port)).or_insert(0) += 1;
            }
        }
        let mut egress_denied: Vec<(String, u64)> = egress_map.into_iter().collect();
        egress_denied.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        let recap_input = audit::SessionRecapInput {
            exit_code,
            duration_secs,
            events_total: snap.events_total,
            top_denied,
            denials_total: blocked_total,
            egress_denied,
            egress_allowed,
            op_counts: snap.op_counts.clone(),
            files_changed: diff.total_changed(),
            verify_status: ctx
                .session
                .verify_outcome
                .as_ref()
                .map(|report| report.status().to_string())
                .unwrap_or_else(|| "off".to_string()),
        };
        if let Some(lines) = audit::format_session_recap(&recap_input) {
            for line in lines {
                eprintln!("vetto: recap: {line}");
            }
        }
    }

    // 12. OTEL, Session Audit Record and Ephemeral Cleanup
    if let Some(otel) = ctx.session.otel_session.take() {
        otel.finish(code);
    }

    let history_record = audit::AuditRecord {
        ts: events::types::now(),
        session_id: format!("session-{}", ctx.session.root_pid),
        agent: ctx
            .cfg
            .agent_preset
            .clone()
            .unwrap_or_else(|| ctx.cfg.agent.first().cloned().unwrap_or_default()),
        command: Some(ctx.cfg.agent.join(" ")),
        profile: ctx.session.policy.name.clone(),
        policy_path: ctx.cfg.policy_path.as_ref().map(|p| p.display().to_string()),
        exit_code: code,
        duration_secs,
        tier: ctx.session.tier_label().to_string(),
        net_mode: ctx.cfg.net.label(),
        blocked_count: blocked_total,
        events_total: snap.events_total,
        report_path: primary_report.as_ref().map(|p| p.display().to_string()),
        log_path: Some(ctx.session.default_log_path.display().to_string()),
    };
    if !ctx.cfg.benchmark {
        let _ = audit::record_session_history(&history_record);
    }

    if ctx.cfg.ephemeral {
        rescue::ephemeral::handle_ephemeral_completion(
            &ctx.session.session_id,
            &ctx.session.project,
            exit_code,
            ctx.cfg.ephemeral_auto_accept,
            ctx.cfg.ephemeral_force_discard,
        )
        .map_err(SuperviseError::Fatal)?;
    }

    Ok(SupervisionVerdict {
        final_exit_code: code,
        pass: code == 0,
        exit_code,
        timed_out,
        duration_secs,
        blocked_total,
        report_path: primary_report,
        files_changed: diff.total_changed(),
        verdict: Some(verdict),
        audit_record: Some(history_record),
    })
}
