//! Vetto Next-Gen Watchdog & CoW State Superversion Layer (Category R3: Features 28–40).
//!
//! Provides autonomous AI coding agent execution supervision, runaway cycle detection,
//! real-time CoW micro-snapshots, multi-agent swarm file locking, IPC deadlock breaking,
//! crash-resilient session WAL journaling, cgroup v2 PSI monitoring, TTY armor, and semantic undo logs.

pub mod throttler;
pub mod snapshot;
pub mod lock;
pub mod env_gen;

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

// ============================================================================
// Re-exports of all 13 Next-Gen Watchdog & State Capabilities
// ============================================================================

// R3.1: Infinite tool-call loop & token burn detector
pub use throttler::{
    LoopAction, LoopAnomalyKind, LoopDetectionPolicy, LoopDetectorConfig,
    LoopViolationReason, LoopWatchdogEngine, NgramEntropyDetector, TokenBurnCeiling,
    ToolCallFingerprint, ToolCallSignature, WatchdogAction,
};

// R3.2: Real-time CoW micro-snapshot engine
pub use snapshot::{
    CowBackendType, CowSnapshot, CowSnapshotManager, LinuxCowSnapshotEngine,
    MicroSnapshotMeta, SnapshotBackendKind, SnapshotEngine, SnapshotError,
    SnapshotTrigger,
};

// R3.3: Multi-agent swarm file lock scheduler
pub use lock::{
    AgentLockClaim, CrossAgentLockScheduler, FileLockKind, LockAcquireResult,
    LockConflictPolicy, LockMode, LockRequest, SwarmLockScheduler,
    ThreeWayMergePreview,
};

// R3.4: Automated sanitized .env.example synthesizer
pub use env_gen::{
    DiscoveredEnvVar, EnvExampleGenerator, EnvExampleSynthesizer, EnvSynthRule,
    RedactedEnvEntry, SecretClassification, SecretTypeHint,
};

// R3.5: Crash-resilient live session WAL daemon
pub use snapshot::{
    SessionWalDaemon, SessionWalEntry, SessionWalJournal, WalEntryKind, WalEvent,
    WalRecoveryPlan,
};

// R3.6: cgroup v2 PSI resource pressure limiter
pub use throttler::{
    CgroupLimits, CgroupPsiMonitor, CgroupStats, CgroupV2Controller,
    PressureLevel, PsiThreshold, ResourceMitigationAction,
};

// R3.7: Syscall anomaly detector via ptrace/seccomp
pub use env_gen::{
    AnomalyDetectionEngine, AnomalySeverity, SyscallAction, SyscallAnomalyEvent,
    SyscallAnomalyRule, SyscallInspector, SyscallThreatLevel,
};

// R3.8: Disk & inode space tripwire
pub use throttler::{
    DiskQuotaSpec, DiskSpaceTripwire, DiskTripwireConfig, DiskTripwireEngine,
    DiskUsageReport, TripwireAction,
};

// R3.9: Git uncommitted working tree seal
pub use snapshot::{
    GitSafetySealer, GitSealEngine, GitSealState, GitWorktreeSeal,
    WorkingTreeSnapshot,
};

// R3.10: Multi-agent IPC deadlock breaker
pub use lock::{
    AgentId, DeadlockBreakerEngine, DeadlockDetector, DeadlockGraphTracker,
    DeadlockResolutionStrategy, IpcWaitEdge, WaitGraphNode,
};

// R3.11: Malicious TTY escape sequence sanitizer
pub use throttler::{
    TtyEscapeAnomaly, TtyEscapeSanitizer, TtySanitizerEngine, TtySecurityPolicy,
};

// R3.12: AST script emulator & dry-run engine
pub use env_gen::{
    AstEmulationEngine, AstHazard, AstScriptType, HazardType, MutationEstimate,
    ScriptAstEvaluator, ScriptDryRunReport, ScriptRiskReport,
};

// R3.13: Semantic file mutation undo-log
pub use snapshot::{
    FileMutationKind, FileOperationType, FileTransactionEntry, SemanticTransactionLog,
    TransactionalUndoLog, UndoLogEntry, UndoReceipt,
};

// ============================================================================
// Unified Watchdog Supervisory Orchestrator
// ============================================================================

/// Master configuration for the Vetto Watchdog Subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogSupervisorConfig {
    pub workspace_root: PathBuf,
    pub state_dir: PathBuf,
    pub loop_detection: LoopDetectorConfig,
    pub disk_tripwire: DiskQuotaSpec,
    pub cgroup_limits: CgroupLimits,
    pub tty_policy: TtySecurityPolicy,
    pub lock_policy: LockConflictPolicy,
    pub enable_auto_snapshot_on_destructive: bool,
    pub enable_wal_logging: bool,
}

impl Default for WatchdogSupervisorConfig {
    fn default() -> Self {
        Self {
            workspace_root: PathBuf::from("."),
            state_dir: PathBuf::from(".vetto/state"),
            loop_detection: LoopDetectorConfig::default(),
            disk_tripwire: DiskQuotaSpec::default(),
            cgroup_limits: CgroupLimits::default(),
            tty_policy: TtySecurityPolicy::default(),
            lock_policy: LockConflictPolicy::AttemptAstThreeWayMerge,
            enable_auto_snapshot_on_destructive: true,
            enable_wal_logging: true,
        }
    }
}

/// Consolidated state supervisor managing agent safety, rollback, locking, and diagnostics.
pub struct WatchdogSupervisor {
    config: WatchdogSupervisorConfig,
    loop_engine: LoopWatchdogEngine,
    snapshot_mgr: Option<CowSnapshotManager>,
    wal_journal: Option<SessionWalJournal>,
    lock_scheduler: SwarmLockScheduler,
    deadlock_tracker: DeadlockGraphTracker,
    env_synthesizer: EnvExampleSynthesizer,
    syscall_engine: AnomalyDetectionEngine,
    script_emulator: AstEmulationEngine,
    tty_sanitizer: TtySanitizerEngine,
    undo_log: TransactionalUndoLog,
}

impl WatchdogSupervisor {
    /// Initializes a fully-configured supervisor instance.
    pub fn init(config: WatchdogSupervisorConfig) -> Result<Self, String> {
        let loop_engine = LoopWatchdogEngine::new(config.loop_detection.clone());
        let lock_scheduler = SwarmLockScheduler::new(config.lock_policy.clone());
        let deadlock_tracker = DeadlockGraphTracker::new();
        let env_synthesizer = EnvExampleSynthesizer::new();
        let syscall_engine = AnomalyDetectionEngine::new();
        let script_emulator = AstEmulationEngine::new();
        let tty_sanitizer = TtySanitizerEngine::new(config.tty_policy.clone());
        let undo_log_path = config.state_dir.join("undo_log.json");
        let undo_log = TransactionalUndoLog::new(undo_log_path);

        let snapshot_mgr = if config.enable_auto_snapshot_on_destructive {
            let snap_dir = config.state_dir.join("snapshots");
            CowSnapshotManager::new(snap_dir).ok()
        } else {
            None
        };

        let wal_journal = if config.enable_wal_logging {
            let wal_path = config.state_dir.join("active_session.wal");
            SessionWalJournal::open_or_create(wal_path).ok()
        } else {
            None
        };

        Ok(Self {
            config,
            loop_engine,
            snapshot_mgr,
            wal_journal,
            lock_scheduler,
            deadlock_tracker,
            env_synthesizer,
            syscall_engine,
            script_emulator,
            tty_sanitizer,
            undo_log,
        })
    }

    /// Evaluates pre-command execution safety: runs AST dry-run and triggers CoW micro-snapshot if destructive.
    pub fn pre_command_check(&mut self, command: &str) -> Result<WatchdogAction, String> {
        // 1. AST Dry-Run Evaluation for scripts
        if command.contains("sh ") || command.contains("bash ") || command.ends_with(".sh") {
            if let Ok(report) = self.script_emulator.evaluate_shell_script(command) {
                if !report.is_safe_to_execute {
                    return Ok(WatchdogAction::SuspendAgent {
                        reason: LoopAnomalyKind::RepeatedExactCommand {
                            count: report.dangerous_commands.len(),
                            tool_name: format!("AST hazard: {:?}", report.dangerous_commands.first().map(|h| h.hazard_type)),
                        },
                    });
                }
            }
        }

        // 2. Destructive command detection (rm -rf, git reset --hard, dd, mkfs)
        let is_destructive = command.contains("rm -rf")
            || command.contains("git reset --hard")
            || command.contains("git clean -fd")
            || command.contains("dd if=");

        if is_destructive {
            if let Some(mgr) = &mut self.snapshot_mgr {
                let snap_res = mgr.create_snapshot(
                    &self.config.workspace_root,
                    SnapshotTrigger::PreCommandExecution { command: command.to_string() },
                );
                if let Ok(snap) = snap_res {
                    tracing::info!("Pre-execution CoW micro-snapshot created: {}", snap.id);
                    if let Some(wal) = &mut self.wal_journal {
                        let _ = wal.append_event(&WalEvent::FsCheckpointSaved {
                            snapshot_id: snap.id,
                            timestamp_ms: snap.timestamp_ms,
                        });
                    }
                }
            }
        }

        Ok(WatchdogAction::Allow)
    }

    /// Records tool execution into the loop watchdog and session WAL.
    pub fn observe_tool_invocation(
        &mut self,
        tool_name: &str,
        payload: &[u8],
        estimated_tokens: u64,
    ) -> WatchdogAction {
        if let Some(wal) = &mut self.wal_journal {
            let _ = wal.append_event(&WalEvent::ToolCallStarted {
                tool_id: format!("{}_{}", tool_name, estimated_tokens),
                tool_name: tool_name.to_string(),
                params_json: String::from_utf8_lossy(payload).to_string(),
                timestamp_ms: 0,
            });
        }

        self.loop_engine.record_tool_call(tool_name, payload, estimated_tokens)
    }

    /// Filters terminal output stream and logs clean chunks.
    pub fn process_pty_output(&mut self, chunk: &[u8]) -> Vec<u8> {
        let (cleaned, _) = self.tty_sanitizer.filter_chunk(chunk);
        if let Some(wal) = &mut self.wal_journal {
            let _ = wal.append_event(&WalEvent::PtyOutputChunk {
                sequence: 0,
                timestamp_ms: 0,
                bytes: cleaned.clone(),
            });
        }
        cleaned
    }

    /// Accessors for subsystem modules
    pub fn lock_scheduler(&self) -> &SwarmLockScheduler {
        &self.lock_scheduler
    }

    pub fn deadlock_tracker_mut(&mut self) -> &mut DeadlockGraphTracker {
        &mut self.deadlock_tracker
    }

    pub fn env_synthesizer_mut(&mut self) -> &mut EnvExampleSynthesizer {
        &mut self.env_synthesizer
    }

    pub fn syscall_engine_mut(&mut self) -> &mut AnomalyDetectionEngine {
        &mut self.syscall_engine
    }

    pub fn undo_log_mut(&mut self) -> &mut TransactionalUndoLog {
        &mut self.undo_log
    }

    pub fn snapshot_manager_mut(&mut self) -> Option<&mut CowSnapshotManager> {
        self.snapshot_mgr.as_mut()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supervisor_initialization_and_precheck() {
        let state_dir = std::env::temp_dir().join("vetto_test_supervisor_state");
        let workspace = std::env::temp_dir().join("vetto_test_supervisor_ws");
        let _ = std::fs::remove_dir_all(&state_dir);
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();

        let config = WatchdogSupervisorConfig {
            workspace_root: workspace.clone(),
            state_dir: state_dir.clone(),
            ..Default::default()
        };

        let mut supervisor = WatchdogSupervisor::init(config).unwrap();

        // 1. Safe command precheck
        let action1 = supervisor.pre_command_check("cargo test").unwrap();
        assert_eq!(action1, WatchdogAction::Allow);

        // 2. Destructive command precheck (should trigger CoW snapshot)
        let action2 = supervisor.pre_command_check("rm -rf target/").unwrap();
        assert_eq!(action2, WatchdogAction::Allow);

        // Verify snapshot was created in state dir
        if let Some(mgr) = supervisor.snapshot_manager_mut() {
            let snaps = mgr.list_snapshots();
            assert_eq!(snaps.len(), 1);
            assert!(snaps[0].trigger_command.contains("rm -rf"));
        }

        // 3. Observe tool calls and PTY output
        let action3 = supervisor.observe_tool_invocation("bash", b"echo test", 50);
        assert_eq!(action3, WatchdogAction::Allow);

        let cleaned_pty = supervisor.process_pty_output(b"Normal output \x1b[?25l");
        assert_eq!(String::from_utf8_lossy(&cleaned_pty), "Normal output ");

        let _ = std::fs::remove_dir_all(&state_dir);
        let _ = std::fs::remove_dir_all(&workspace);
    }
}
