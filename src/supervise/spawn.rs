//! Session spawn and initialization boundary for the supervisor (`src/supervise/spawn.rs`).
//!
//! Responsibilities:
//! 1. Validate agent command and resolve binary in PATH (fail 127 on missing).
//! 2. Detect platform isolation backend (Linux Landlock/Namespaces, macOS Seatbelt, Windows LPAC).
//! 3. Load and lower security policies (hierarchical layered loader, network allowlist bridge).
//! 4. Perform preflight boundary checks (detect leaked environment variables and unmasked secrets before spawn).
//! 5. Allocate PTY / cloexec stdio pipes with zero-deadlock guarantees.
//! 6. Prepare and spawn the sandboxed process via `UnpreparedProductionExecution` -> `PreparedProductionExecution` -> `SpawnedProductionExecution`.
//! 7. Drop parent write/slave descriptors to maintain EOF semantics.
//! 8. Initialize Phase 2 runtime infrastructure (EventBus, sinks, telemetry, observation threads).
//! 9. Package state into `SupervisedSession`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::fd::IntoRawFd;

use crate::config::{NetMode, RunConfig, TuiMode};
use crate::events::EventBus;
use crate::policy::{self, Policy, Tier};
use crate::policy_ir::contract::SecurityContract;
use crate::report::diff_project::ProjectManifest;
use crate::sandbox::production::{
    PreparedProductionExecution, SpawnedProductionExecution, UnpreparedProductionExecution,
    PROD_SCENARIO_ID,
};
use crate::sandbox::{self, Backend, StdioMode};
use crate::verify::VerifyReport;

use super::error::SuperviseError;

/// Encapsulates child stdio descriptors and terminal settings.
#[derive(Debug)]
pub struct SupervisedStdio {
    #[cfg(unix)]
    pub pty_master: Option<OwnedFd>,
    #[cfg(not(unix))]
    pub pty_master: Option<()>,

    #[cfg(unix)]
    pub stdout_r: Option<OwnedFd>,
    #[cfg(not(unix))]
    pub stdout_r: Option<()>,

    #[cfg(unix)]
    pub stderr_r: Option<OwnedFd>,
    #[cfg(not(unix))]
    pub stderr_r: Option<()>,

    pub mask_secrets: bool,
}

/// The state of a successfully launched supervised session.
pub struct SupervisedSession {
    /// Spawned production execution boundary object (owns handle, contract, FSM, root pid, nonce, backend capability).
    pub spawned: Option<SpawnedProductionExecution>,
    /// Stdio descriptors and secret masking state for the I/O pump.
    pub stdio: SupervisedStdio,
    /// Effective security policy for the session.
    pub policy: Policy,
    /// Sealed SecurityContract for the session.
    pub contract: SecurityContract,
    /// Unique session identifier (e.g. 20261002-182523-<pid>).
    pub session_id: String,
    /// Root PID of the sandboxed agent.
    pub root_pid: u32,
    /// Workspace root / project directory.
    pub project: PathBuf,
    /// User home directory.
    pub home: PathBuf,
    /// Detected sandbox tier (Full, FsOnly, Seccomp, or None for macOS Seatbelt).
    pub tier: Option<Tier>,
    /// Instant when session execution was initiated.
    pub started: Instant,
    /// Pre-spawn workspace manifest snapshot for project change diffing.
    pub initial_manifest: ProjectManifest,
    /// Whether project workspace diff calculation is active.
    pub diff_enabled: bool,
    /// Preflight verification report, if preflight was enabled.
    pub verify_outcome: Option<VerifyReport>,
    /// Shared event bus for asynchronous sinks and telemetry.
    pub bus: std::sync::Arc<crate::events::EventBus>,
    /// Statistics collector attached to event bus.
    pub stats: std::sync::Arc<crate::report::stats::StatsCollector>,
    /// OpenTelemetry session, if configured.
    pub otel_session: Option<std::sync::Arc<crate::telemetry::TelemetrySession>>,
    /// Default log path for this session.
    pub default_log_path: PathBuf,
    /// Unix domain socket path for credential broker, if active.
    #[cfg(unix)]
    pub cred_sock: Option<PathBuf>,
    /// Background credential broker thread handle, if active.
    #[cfg(unix)]
    pub cred_broker_handle: Option<std::thread::JoinHandle<()>>,
    /// Cloned run configuration.
    pub cfg: RunConfig,
}

impl SupervisedSession {
    /// PID of the sandboxed root process.
    pub fn root_pid(&self) -> u32 {
        self.root_pid
    }

    /// Access the sealed SecurityContract.
    pub fn contract(&self) -> &SecurityContract {
        &self.contract
    }

    /// Access the session tier.
    pub fn tier(&self) -> Option<Tier> {
        self.tier
    }

    /// Access the tier label string.
    pub fn tier_label(&self) -> &'static str {
        tier_label(self.tier)
    }

    /// Access the effective policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

/// Returns a human-readable label for the sandbox tier.
pub fn tier_label(tier: Option<Tier>) -> &'static str {
    match tier {
        Some(Tier::Full) => Tier::Full.label(),
        Some(Tier::FsOnly) => Tier::FsOnly.label(),
        Some(Tier::Seccomp) => Tier::Seccomp.label(),
        None => "macos-seatbelt",
    }
}

/// Formats a duration nicely (e.g. 1h, 15m, 30s).
pub fn format_duration(limit: std::time::Duration) -> String {
    let secs = limit.as_secs();
    if secs % 3600 == 0 && secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 && secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Counts explicit policy display_only_deny paths in a TOML file.
pub fn explicit_policy_deny_count(path: &Path) -> Option<usize> {
    let text = std::fs::read_to_string(path).ok()?;
    let document: toml::Value = toml::from_str(&text).ok()?;
    let paths = document.get("display_only_deny")?.get("paths")?;
    Some(match paths {
        toml::Value::Array(values) => values.len(),
        toml::Value::String(_) => 1,
        _ => 0,
    })
}

/// Opt-in background staging hook for direct-binary installs.
pub fn stage_update_if_available(user_config: &crate::version::UserConfig) {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    if crate::version::detect_install_method(&exe_path) != crate::version::InstallMethod::Binary {
        return;
    }
    let Some(notice) =
        crate::version::check_version(env!("CARGO_PKG_VERSION"), &user_config.channel, false)
    else {
        return;
    };
    let Some((url, ext)) = crate::version::binary_archive_url(&notice.latest_version) else {
        return;
    };
    match crate::version::stage_update(&notice.latest_version, &url, ext) {
        Ok(dir) => println!(
            "vetto: update v{} staged, applies on next startup ({}).",
            notice.latest_version,
            dir.display()
        ),
        Err(e) => eprintln!("vetto: warning: background staging failed: {e:#}"),
    }
}

/// Resolves an executable binary candidate from PATH or absolute/relative path.
pub fn resolve_in_path(cmd: &str) -> std::io::Result<String> {
    let command_path = Path::new(cmd);
    if command_path.is_absolute() || command_path.components().count() > 1 {
        if command_path.exists() {
            return Ok(cmd.to_string());
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("agent binary '{cmd}' does not exist"),
            ));
        }
    }
    if let Ok(real) = crate::shim::find_real_binary(cmd) {
        return Ok(real.to_string_lossy().into_owned());
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(cmd);
            if is_executable_file(&candidate) {
                return Ok(candidate.to_string_lossy().into_owned());
            }
            #[cfg(windows)]
            if candidate.extension().is_none() {
                let extensions =
                    std::env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
                for extension in extensions.to_string_lossy().split(';') {
                    let extension = extension.trim().trim_start_matches('.');
                    if extension.is_empty() {
                        continue;
                    }
                    let candidate = candidate.with_extension(extension);
                    if is_executable_file(&candidate) {
                        return Ok(candidate.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("agent command '{cmd}' not found in PATH"),
    ))
}

fn is_executable_file(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(p) {
            Ok(m) => m.is_file() && (m.permissions().mode() & 0o111) != 0,
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        match std::fs::metadata(p) {
            Ok(m) => m.is_file(),
            Err(_) => false,
        }
    }
}

/// Preflight boundary checks (detect leaked environment variables or unmasked secrets before spawn).
pub fn preflight_boundary_checks(
    contract: &SecurityContract,
    policy: &Policy,
    env: &BTreeMap<String, String>,
    cfg: &RunConfig,
) -> Result<Option<VerifyReport>, SuperviseError> {
    let mut leak_count = 0;

    // 1. Verify sealed security contract digest (INV-36)
    if !contract.verify_digest() {
        eprintln!("vetto: preflight: sealed security contract digest verification failed");
        return Err(SuperviseError::PreflightVerificationFailed { leaks: 1 });
    }

    // 2. Audit environment variables for leaks (INV-27)
    for (key, _val) in env {
        if crate::sandbox::envfilter::is_hard_denied(key) {
            if !policy.environment.allows(std::ffi::OsStr::new(key)) {
                eprintln!("vetto: preflight: detected leaked secret in environment: {key}");
                leak_count += 1;
            }
        }
    }

    // 3. Audit host filesystem unmasked secrets against policy denials (INV-08)
    for mask_path in &contract.filesystem.mask_paths {
        if mask_path.exists() {
            let is_covered = policy
                .deny_resolved
                .iter()
                .any(|d| d.path == *mask_path || mask_path.starts_with(&d.path));
            if !is_covered {
                eprintln!(
                    "vetto: preflight: unmasked secret path exists on host without denial: {}",
                    mask_path.display()
                );
                leak_count += 1;
            }
        }
    }

    // 4. Preflight contract battery check if requested
    let mut verify_report = None;
    if cfg.verify_preflight {
        let report = crate::verify::preflight_contract(contract)
            .map_err(|_| SuperviseError::PreflightVerificationFailed { leaks: 1 })?;
        eprintln!("vetto: verify: {}", report.summary());
        let report_leaks = report.leaks();
        if report_leaks > 0 {
            eprintln!("vetto: preflight: contract battery detected {report_leaks} leak(s)");
            leak_count += report_leaks;
        }
        verify_report = Some(report);
    }

    // 5. Fail-closed decision (INV-01)
    if leak_count > 0 {
        if cfg.shadow {
            eprintln!(
                "vetto: shadow: would deny session startup due to boundary verification leaks ({leak_count} found); shadow mode active, continuing"
            );
        } else {
            return Err(SuperviseError::PreflightVerificationFailed { leaks: leak_count });
        }
    }

    Ok(verify_report)
}

/// Prepares the environment, loads policy, performs preflight boundary checks,
/// allocates stdio pipes/PTY, spawns the supervised agent process, and hooks event sinks.
pub fn spawn_supervised_session(cfg: &mut RunConfig) -> Result<SupervisedSession, SuperviseError> {
    if cfg.agent.is_empty() {
        return Err(SuperviseError::EmptyAgentCommand);
    }

    // 1. Resolve agent executable in PATH (fail-closed with 127 if missing)
    let mut agent_cmd = cfg.agent.clone();
    agent_cmd[0] = resolve_in_path(&agent_cmd[0]).map_err(|source| {
        SuperviseError::ExecutableNotFound {
            cmd: agent_cmd[0].clone(),
            source,
        }
    })?;

    // 2. Banner and auto-update staging
    let user_config = crate::version::load_user_config().unwrap_or_default();
    if !cfg.benchmark {
        crate::version::print_banner_if_update_available(
            env!("CARGO_PKG_VERSION"),
            &user_config.channel,
        );
        if crate::version::auto_update_enabled(&user_config) {
            stage_update_if_available(&user_config);
        }
    }

    // 3. Detect sandbox backend
    let backend_res = Backend::detect_with_backend(
        cfg.net.clone(),
        cfg.observe_seccomp,
        cfg.backend.as_deref(),
    );
    let (mut backend_opt, tier) = match backend_res {
        Ok(b) => {
            let t = b.tier();
            (Some(Box::new(b)), t)
        }
        Err(e) => {
            return Err(SuperviseError::ProcessSpawnFailed(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )));
        }
    };

    // 4. Resolve workspace and home directories
    let project = std::env::current_dir().map_err(|e| {
        SuperviseError::Fatal(anyhow::anyhow!("getcwd failed: {e}"))
    })?;
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            SuperviseError::Fatal(anyhow::anyhow!(
                "neither $HOME nor %USERPROFILE% is set; vetto needs it to resolve policy variables"
            ))
        })?;

    // 5. Load layered policy
    let tier_for_policy = match tier {
        Some(t) => t,
        None => Tier::Full,
    };
    let overrides = policy::loader::PolicyOverrides {
        deny_glob: cfg.deny_glob.clone(),
        git_guard: if cfg.git_guard { Some(true) } else { None },
        snapshot: if cfg.snapshot || cfg.ephemeral {
            Some(true)
        } else {
            None
        },
        auto_deny_secrets: if cfg.auto_deny_secrets {
            Some(true)
        } else {
            None
        },
        read_only_caches: if cfg.read_only_caches {
            Some(true)
        } else {
            None
        },
        shadow: if cfg.shadow { Some(true) } else { None },
        tmpfs_tmp: if cfg.tmpfs_tmp { Some(true) } else { None },
        net_quota: cfg.net_quota.clone(),
        ..policy::loader::PolicyOverrides::default()
    };
    let policy_options = policy::loader::PolicyLoadOptions {
        agent: cfg.agent_preset.clone(),
        preset: cfg.preset,
        include_project_policy: true,
        overrides,
        ..policy::loader::PolicyLoadOptions::default()
    };
    let mut pol = policy::loader::load_with_options(
        &cfg.profile,
        cfg.policy_path.as_deref(),
        &project,
        &home,
        tier_for_policy,
        &policy_options,
    )
    .map_err(SuperviseError::PolicyLoadFailed)?;

    // 6. Bridge network allowlist into runtime configuration if not explicitly given on CLI
    if !cfg.explicit_net {
        if pol.deny_network || pol.network_mode.as_deref() == Some("off") {
            cfg.net = NetMode::Off;
        } else if !pol.network_allow.is_empty() {
            let mut domains = match &cfg.net {
                NetMode::Allowlist(existing) => existing.clone(),
                _ => Vec::new(),
            };
            domains.extend(pol.network_allow.clone());
            domains.sort();
            domains.dedup();
            if !domains.is_empty() {
                cfg.net = NetMode::Allowlist(domains);
            }
        }
        if backend_opt.is_some() {
            backend_opt = Some(Box::new(Backend::detect_with_backend(
                cfg.net.clone(),
                cfg.observe_seccomp,
                cfg.backend.as_deref(),
            ).map_err(|e| {
                SuperviseError::ProcessSpawnFailed(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?));
        }
    }

    // 7. Git-guard verification on protected branches
    if (pol.git_guard || cfg.git_guard) && !pol.allow_write.is_empty() {
        if let Some(branch) = policy::conditions::detect_git_branch(&project) {
            if branch == "main" || branch == "master" {
                return Err(SuperviseError::Fatal(anyhow::anyhow!(
                    "git_guard: working copy is on branch '{branch}'; refusing to run with write permissions (create a feature branch, e.g. 'git checkout -b feature/...')"
                )));
            }
        }
    }

    // 8. Session ID and snapshot / branch management
    let session_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        std::process::id()
    );

    if cfg.auto_branch || cfg.git_guard {
        if let Ok(Some(branch)) = crate::shim::ensure_session_branch(&project, &session_id) {
            eprintln!("vetto: git-guard: switched from main to session branch {branch} to protect default branch");
        }
    }

    let is_home_or_root = project == home
        || project.parent().is_none()
        || match (
            std::fs::canonicalize(&project),
            std::fs::canonicalize(&home),
        ) {
            (Ok(cp), Ok(ch)) => cp == ch || cp.parent().is_none(),
            _ => false,
        };

    let diff_requested =
        (cfg.snapshot || cfg.ephemeral || !cfg.report_formats.is_empty()) && !cfg.benchmark;
    let diff_enabled = diff_requested && !is_home_or_root;

    let initial_manifest = if diff_enabled {
        crate::report::diff_project::ProjectManifest::capture_fast(
            &project,
            1000,
            std::time::Duration::from_millis(150),
        )
    } else {
        crate::report::diff_project::ProjectManifest::default()
    };

    if !cfg.benchmark
        && (pol.snapshot || cfg.snapshot || cfg.ephemeral || !cfg.agent.is_empty())
        && !is_home_or_root
    {
        match crate::rescue::snapshot::create_snapshot(
            &project,
            &session_id,
            crate::rescue::snapshot::DEFAULT_MAX_SNAPSHOT_SIZE,
        ) {
            Ok(meta) => {
                tracing::debug!(
                    "created snapshot for session {session_id} ({} files, {} bytes)",
                    meta.file_count,
                    meta.total_size_bytes
                );
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("exceeds maximum snapshot limit") {
                    tracing::debug!("vetto: snapshot skipped (project exceeds 50MB limit): {msg}");
                } else {
                    tracing::debug!("vetto: snapshot creation skipped: {e}");
                }
            }
        }
    }

    // 9. Warnings and binary path adjustments
    if tier == Some(Tier::FsOnly) && !pol.deny_resolved.is_empty() {
        pol.warnings.push(
            "fs-only tier: display_only_deny paths cannot be masked with mount overlays here."
                .to_string(),
        );
    }
    if let Some(spec) = &cfg.limits_spec {
        policy::limits_spec::apply_cli(&mut pol, spec).map_err(SuperviseError::Fatal)?;
    }

    use std::io::Write;
    for w in &pol.warnings {
        eprint!("vetto: policy warning: {w}\r\n");
    }
    let _ = std::io::stderr().flush();
    let _ = std::io::stdout().flush();

    let bin_path = PathBuf::from(&agent_cmd[0]);
    if let Some(parent) = bin_path.parent() {
        if !pol.in_read_scope(&bin_path) {
            pol.allow_read.push(parent.to_path_buf());
        }
    }
    if pol.in_write_scope(Path::new(&agent_cmd[0])) {
        pol.deny_write.push(bin_path.clone());
    }

    // 10. Check backend and tier invariants (INV-01)
    let backend = match backend_opt {
        Some(b) => b,
        None => Box::new(Backend::detect_with_backend(
            cfg.net.clone(),
            cfg.observe_seccomp,
            cfg.backend.as_deref(),
        ).map_err(|e| {
            SuperviseError::ProcessSpawnFailed(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?),
    };
    tracing::debug!("backend: {}", backend.describe());

    if cfg.net.uses_relay()
        && (tier == Some(Tier::FsOnly) || tier == Some(Tier::Seccomp))
    {
        return Err(SuperviseError::NetworkRelayTierMismatch {
            tier: tier_label(tier).to_string(),
        });
    }

    #[cfg(not(target_os = "linux"))]
    if cfg.git_ssh {
        return Err(SuperviseError::Fatal(anyhow::anyhow!(
            "--git-ssh is available on Linux only"
        )));
    }

    // 11. Assemble environment variables
    let mut env_extra: HashMap<String, String> = {
        let mut env_extra = HashMap::new();
        env_extra.insert("VETTO_SANDBOX".into(), "1".into());
        env_extra.insert("VETTO_SANDBOXED".into(), "1".into());
        env_extra.insert("VETTO_SESSION_ID".into(), session_id.clone());
        env_extra.insert("VETTO_TIER".into(), tier_label(tier).into());
        env_extra.insert("VETTO_PROFILE".into(), pol.name.clone());
        env_extra.insert("VETTO_VERSION".into(), env!("CARGO_PKG_VERSION").into());
        #[cfg(target_os = "linux")]
        {
            if cfg.net.uses_relay() {
                for (k, v) in sandbox::linux::net_relay::build_proxy_env(
                    sandbox::linux::net_relay::RELAY_PORT_BASE,
                ) {
                    env_extra.insert(k, v);
                }
            }
            if cfg.git_ssh {
                let exe = std::env::current_exe().map_err(|e| {
                    SuperviseError::Fatal(anyhow::anyhow!("resolve vetto executable for SSH helper: {e}"))
                })?;
                env_extra.insert(
                    "GIT_SSH_COMMAND".into(),
                    sandbox::linux::net_relay::build_git_ssh_command(&exe),
                );
            }
        }
        env_extra
    };

    if pol.git_guard || cfg.git_guard {
        env_extra.insert("VETTO_GIT_GUARD".into(), "1".into());
    }

    #[cfg(not(unix))]
    if !pol.secret_proxies.is_empty() {
        return Err(SuperviseError::Fatal(anyhow::anyhow!(
            "secrets.proxy requires the Unix credential broker, which is not supported on this platform"
        )));
    }

    #[cfg(unix)]
    let cred_sock = if !pol.secret_proxies.is_empty() {
        let sock = std::env::temp_dir().join(format!("vetto-cred-{}.sock", std::process::id()));
        env_extra.insert(
            "VETTO_CRED_BROKER_SOCK".into(),
            sock.to_string_lossy().to_string(),
        );
        Some(sock)
    } else {
        None
    };

    // 12. Allocate stdio descriptors (PTY or Cloexec pipes)
    #[cfg(unix)]
    let mut pty_master: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut pty_slave: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stdout_r: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stdout_w: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stderr_r: Option<OwnedFd> = None;
    #[cfg(unix)]
    let mut stderr_w: Option<OwnedFd> = None;

    #[cfg(unix)]
    let stdio = match cfg.tui {
        TuiMode::Statusline => {
            let (rows, cols) = crossterm::terminal::size().unwrap_or((24, 80));
            let p = crate::pty::Pty::open(rows.saturating_sub(1).max(1), cols)
                .map_err(|e| {
                    SuperviseError::StdioAllocationFailed(std::io::Error::other(e.to_string()))
                })?;
            let crate::pty::Pty { master, slave } = p;
            let slave_fd = slave.as_raw_fd();
            pty_master = Some(master);
            pty_slave = Some(slave);
            StdioMode::Pty { slave_fd }
        }
        TuiMode::None => {
            let is_interactive = crate::config::is_interactive_agent_command(
                cfg.agent_preset.as_deref(),
                &cfg.agent,
            );
            if !is_interactive && cfg.mask_secrets {
                let (r1, w1) = sandbox::create_cloexec_pipe()
                    .map_err(|e| {
                        SuperviseError::StdioAllocationFailed(std::io::Error::other(e.to_string()))
                    })?;
                let (r2, w2) = sandbox::create_cloexec_pipe()
                    .map_err(|e| {
                        SuperviseError::StdioAllocationFailed(std::io::Error::other(e.to_string()))
                    })?;
                let stdio = StdioMode::Captured {
                    stdout_w: w1.as_raw_fd(),
                    stderr_w: w2.as_raw_fd(),
                };
                stdout_r = Some(r1);
                stdout_w = Some(w1);
                stderr_r = Some(r2);
                stderr_w = Some(w2);
                stdio
            } else {
                StdioMode::Inherit
            }
        }
    };
    #[cfg(windows)]
    let stdio = {
        if cfg.tui != TuiMode::None {
            return Err(SuperviseError::Fatal(anyhow::anyhow!(
                "the Windows backend currently requires --tui=none or --ci"
            )));
        }
        StdioMode::Inherit
    };

    // 13. Construct and prepare execution boundary
    let frozen_timeout = cfg.session_timeout;
    let unprepared = UnpreparedProductionExecution::new(
        *backend,
        pol.clone(),
        agent_cmd.clone(),
        project.clone(),
        env_extra,
        cfg.net.clone(),
        frozen_timeout,
        stdio,
        PROD_SCENARIO_ID.to_string(),
    );
    let prepared = unprepared.prepare().map_err(|e| {
        SuperviseError::ProcessSpawnFailed(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;

    // 14. Contract validation & Preflight boundary checks
    let contract = prepared.contract().clone();
    let production = contract
        .production
        .as_ref()
        .expect("validated production contract")
        .clone();
    let pol = production.installation_policy.clone();

    let verify_outcome = preflight_boundary_checks(
        prepared.contract(),
        &pol,
        &prepared.env,
        cfg,
    )?;

    // 15. Spawn the sandbox process
    let started = Instant::now();
    #[allow(unused_mut)]
    let mut spawned = prepared.spawn().map_err(|e| {
        SuperviseError::ProcessSpawnFailed(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;

    // 16. Drop parent-side write/slave descriptors to ensure clean EOF
    #[cfg(unix)]
    {
        drop(pty_slave.take());
        drop(stdout_w.take());
        drop(stderr_w.take());
    }

    // 17. Phase 2: Runtime infrastructure & sinks
    let bus = std::sync::Arc::new(EventBus::new());
    let root_pid = spawned.handle.root_pid;

    #[cfg(target_os = "linux")]
    let relay_port = spawned.relay_port();
    #[cfg(not(target_os = "linux"))]
    let relay_port: Option<u16> = None;

    if !cfg.benchmark {
        if let Ok(reg) = crate::cli::status::SessionRegistry::new() {
            let agent_name = cfg.agent_preset.as_deref().unwrap_or_else(|| &cfg.agent[0]);
            let _ = reg.register(
                &session_id,
                root_pid,
                agent_name,
                &pol.name,
                tier_label(tier),
                &project,
            );
        }
    }

    if cfg.system_log || pol.system_log {
        crate::logger::system_log::SystemLogSink::spawn(&bus);
    }

    if cfg.auto_timeout_requested {
        if let Some(t) = cfg.session_timeout {
            bus.publish(crate::events::Event::Notice {
                ts: crate::events::types::now(),
                message: format!("auto-timeout selected: {}", format_duration(t)),
            });
        } else {
            bus.publish(crate::events::Event::Notice {
                ts: crate::events::types::now(),
                message: "no past history found for agent; running without timeout".to_string(),
            });
        }
    }

    let default_log_path = home
        .join(".vetto")
        .join("logs")
        .join(format!("session-{root_pid}.jsonl"));
    if !cfg.benchmark {
        if let Some(parent) = default_log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        crate::logger::jsonl::JsonlSink::spawn(&bus, default_log_path.clone());
    }

    let jsonl_path = cfg.jsonl_path.clone();
    if let Some(path) = &jsonl_path {
        if path != &default_log_path {
            crate::logger::jsonl::JsonlSink::spawn(&bus, path.clone());
        }
    }
    if cfg.oslog || pol.oslog {
        crate::logger::oslog::OsLogSink::spawn(&bus);
    }
    let stats = crate::report::stats::StatsCollector::spawn(&bus);

    let otel_session = std::sync::Arc::new(crate::telemetry::TelemetrySession::start(
        cfg.otel,
        cfg.otel_endpoint.as_deref(),
        &format!("session-{root_pid}"),
        tier_label(tier),
        &cfg.net.label(),
        &pol.name,
    ).map_err(SuperviseError::Fatal)?);
    crate::telemetry::spawn_telemetry_subscriber(&bus, otel_session.clone());

    if cfg.notify {
        crate::notify::DesktopNotifier::spawn(&bus, true);
    }
    bus.publish(crate::events::Event::SessionStarted {
        ts: crate::events::types::now(),
        pid: root_pid,
        tier: tier_label(tier).to_string(),
        net_mode: cfg.net.label(),
        profile: pol.name.clone(),
        shadow: pol.shadow,
    });

    #[cfg(unix)]
    let mut cred_broker_handle = None;
    #[cfg(unix)]
    if let Some(ref sock) = cred_sock {
        let mut host_secrets = HashMap::new();
        for key in &pol.secret_proxies {
            if let Ok(val) = std::env::var(key) {
                host_secrets.insert(key.clone(), val);
            }
        }
        let allowlist_domains = match &production.net {
            crate::config::NetMode::Allowlist(d) => d.clone(),
            crate::config::NetMode::Strict(rules) => {
                rules.iter().map(|r| r.domain.clone()).collect()
            }
            crate::config::NetMode::Off | crate::config::NetMode::Ask => Vec::new(),
        };
        let broker_config = crate::cred_broker::CredBrokerConfig {
            proxy_secrets: pol.secret_proxies.clone(),
            allowlist_domains,
        };
        match crate::cred_broker::spawn_credential_broker(
            sock.clone(),
            broker_config,
            host_secrets,
            (*bus).clone(),
        ) {
            Ok(h) => cred_broker_handle = Some(h),
            Err(e) => eprintln!("vetto: warning: failed to spawn credential broker: {e}"),
        }
    }

    match tier {
        Some(policy::Tier::Full) => {
            for d in &pol.deny_resolved {
                bus.publish(crate::events::Event::SecretMasked {
                    ts: crate::events::types::now(),
                    path: d.path.display().to_string(),
                });
            }
        }
        Some(policy::Tier::Seccomp) => {
            bus.publish(crate::events::Event::Notice {
                ts: crate::events::types::now(),
                message: "WARNING: Running in Tier SECCOMP (micro-mode). Filesystem isolation is NOT enforced on this system because Landlock is unavailable. Only syscall filtering and network blocking are active."
                    .to_string(),
            });
        }
        _ => {
            bus.publish(crate::events::Event::Notice {
                ts: crate::events::types::now(),
                message: "fs-only/macos tier: intra-project secrets are masked \
                          by load-time policy rules, not mount overlays"
                    .to_string(),
            });
            if tier == Some(policy::Tier::FsOnly) && !pol.deny_resolved.is_empty() {
                bus.publish(crate::events::Event::Notice {
                    ts: crate::events::types::now(),
                    message: "fs-only tier: denied secret paths are allowlist-carved, \
                              not masked — entry names may be visible and files created \
                              directly at a write root cannot be read back this session"
                        .to_string(),
                });
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(fd) = spawned.take_broker_ctrl_fd() {
            let broker_policy = match &production.net {
                NetMode::Allowlist(d) => {
                    sandbox::linux::net_relay::BrokerPolicy::Allowlist(d.clone())
                }
                NetMode::Strict(rules) => {
                    sandbox::linux::net_relay::BrokerPolicy::Strict(rules.clone())
                }
                NetMode::Ask => {
                    sandbox::linux::net_relay::BrokerPolicy::Ask(pol.network_allow.clone())
                }
                NetMode::Off => sandbox::linux::net_relay::BrokerPolicy::Allowlist(Vec::new()),
            };
            let mut broker_config = sandbox::linux::net_relay::BrokerConfig::from(broker_policy);
            broker_config.allow_cidr = pol.allow_cidr.clone();
            broker_config.quotas = pol.net_quota.clone();
            broker_config.policy_path = cfg.policy_path.clone();
            broker_config.block_doh = cfg.block_doh;
            sandbox::linux::net_relay::spawn_broker(fd.into_raw_fd(), broker_config, (*bus).clone());
        }
        let _ = relay_port;
        if let Some(fd) = spawned.take_notif_listener() {
            let notifier_policy = std::sync::Arc::new(pol.clone());
            if let Some(notify_cfg) = &pol.seccomp_notify {
                if notify_cfg.enabled {
                    sandbox::linux::observe_seccomp::spawn_enforcement_supervisor(
                        fd,
                        (*bus).clone(),
                        notify_cfg.clone(),
                        notifier_policy,
                        project.clone(),
                    );
                    bus.publish(crate::events::Event::Notice {
                        ts: crate::events::types::now(),
                        message: "seccomp user-notify supervisor enforcement active (default deny)"
                            .to_string(),
                    });
                } else {
                    sandbox::linux::observe_seccomp::spawn_notifier(
                        fd,
                        (*bus).clone(),
                        notifier_policy,
                        project.clone(),
                    );
                }
            } else {
                sandbox::linux::observe_seccomp::spawn_notifier(
                    fd,
                    (*bus).clone(),
                    notifier_policy,
                    project.clone(),
                );
                bus.publish(crate::events::Event::Notice {
                    ts: crate::events::types::now(),
                    message: "blocked-attempt observation via --observe-seccomp \
                              (BEST-EFFORT; paths are racy; Landlock stays the sole enforcer)"
                        .to_string(),
                });
            }
        }
        let audit_reason = sandbox::linux::audit_reader::spawn_reader_if_available((*bus).clone());
        if !cfg.observe_seccomp {
            if let Some(reason) = audit_reason {
                bus.publish(crate::events::Event::Notice {
                    ts: crate::events::types::now(),
                    message: format!(
                        "blocked-attempt feed unavailable ({reason}). Enforcement is ACTIVE."
                    ),
                });
            }
        }
        sandbox::linux::visibility::spawn_poller((*bus).clone(), vec![root_pid]);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = &relay_port;
        if let Some(reason) = sandbox::macos::fsevents::spawn_watcher_if_available(&bus) {
            bus.publish(crate::events::Event::Notice {
                ts: crate::events::types::now(),
                message: reason,
            });
        }
    }
    #[cfg(target_os = "windows")]
    let _ = &relay_port;

    let stdio_holder = SupervisedStdio {
        #[cfg(unix)]
        pty_master,
        #[cfg(not(unix))]
        pty_master: None,
        #[cfg(unix)]
        stdout_r,
        #[cfg(not(unix))]
        stdout_r: None,
        #[cfg(unix)]
        stderr_r,
        #[cfg(not(unix))]
        stderr_r: None,
        mask_secrets: cfg.mask_secrets,
    };

    Ok(SupervisedSession {
        spawned: Some(spawned),
        stdio: stdio_holder,
        policy: pol,
        contract,
        session_id,
        root_pid,
        project,
        home,
        tier,
        started,
        initial_manifest,
        diff_enabled,
        verify_outcome,
        bus,
        stats: std::sync::Arc::new(stats),
        otel_session: Some(otel_session),
        default_log_path,
        #[cfg(unix)]
        cred_sock,
        #[cfg(unix)]
        cred_broker_handle,
        cfg: cfg.clone(),
    })
}

/// Executes dry-run diagnostics and prints the plan without launching any process.
pub fn execute_dry_run(cfg: &RunConfig) -> Result<(), SuperviseError> {
    if cfg.agent.is_empty() {
        return Err(SuperviseError::EmptyAgentCommand);
    }
    let mut agent_cmd = cfg.agent.clone();
    agent_cmd[0] = resolve_in_path(&agent_cmd[0]).map_err(|source| {
        SuperviseError::ExecutableNotFound {
            cmd: agent_cmd[0].clone(),
            source,
        }
    })?;

    let backend_res = Backend::detect_with_backend(
        cfg.net.clone(),
        cfg.observe_seccomp,
        cfg.backend.as_deref(),
    );
    let tier = backend_res.ok().and_then(|b| b.tier());

    let project = std::env::current_dir().map_err(|e| {
        SuperviseError::Fatal(anyhow::anyhow!("getcwd failed: {e}"))
    })?;
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            SuperviseError::Fatal(anyhow::anyhow!("HOME not set"))
        })?;

    let tier_for_policy = tier.unwrap_or(Tier::Full);
    let policy_options = policy::loader::PolicyLoadOptions {
        agent: cfg.agent_preset.clone(),
        preset: cfg.preset,
        include_project_policy: true,
        overrides: policy::loader::PolicyOverrides {
            deny_glob: cfg.deny_glob.clone(),
            git_guard: if cfg.git_guard { Some(true) } else { None },
            snapshot: if cfg.snapshot || cfg.ephemeral { Some(true) } else { None },
            auto_deny_secrets: if cfg.auto_deny_secrets { Some(true) } else { None },
            read_only_caches: if cfg.read_only_caches { Some(true) } else { None },
            shadow: if cfg.shadow { Some(true) } else { None },
            tmpfs_tmp: if cfg.tmpfs_tmp { Some(true) } else { None },
            net_quota: cfg.net_quota.clone(),
            ..policy::loader::PolicyOverrides::default()
        },
        ..policy::loader::PolicyLoadOptions::default()
    };
    let pol = policy::loader::load_with_options(
        &cfg.profile,
        cfg.policy_path.as_deref(),
        &project,
        &home,
        tier_for_policy,
        &policy_options,
    )
    .map_err(SuperviseError::PolicyLoadFailed)?;

    let label = match tier {
        Some(_) => tier_label(tier),
        None => "unknown (dry-run)",
    };

    println!("vetto dry-run — NOT ENFORCED, nothing executed");
    println!("  tier:  {label}");
    println!("  net:   {}", cfg.net.label());
    println!("  git ssh: {}", if cfg.git_ssh { "enabled" } else { "off" });
    println!(
        "  shadow: {}",
        if cfg.shadow {
            "enabled (policy layer only)"
        } else {
            "off"
        }
    );
    if let Some(preset) = cfg.preset {
        println!("  preset: {}", preset.as_str());
    }
    println!("  tui:   {:?}", cfg.tui);
    println!("  policy: {}", pol.summary());
    println!("  write roots:");
    for p in &pol.allow_write {
        println!("    {}", p.display());
    }
    println!("  read roots ({}):", pol.allow_read.len());
    for p in pol.allow_read.iter().take(50) {
        println!("    {}", p.display());
    }
    println!("  deny paths resolved: {}", pol.deny_resolved.len());
    for d in pol.deny_resolved.iter().take(50) {
        println!(
            "    {}{}",
            d.path.display(),
            if d.is_dir { "/" } else { "" }
        );
    }
    if let Some(path) = cfg.policy_path.as_deref() {
        if let Some(count) = explicit_policy_deny_count(path) {
            let noun = if count == 1 { "path" } else { "paths" };
            println!("  explicit CLI policy: {count} deny {noun} included above");
        }
    }
    println!(
        "  agent: {}",
        crate::logger::sanitizer::sanitize_line(&agent_cmd.join(" "))
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_in_path_nonexistent() {
        let err = resolve_in_path("definitely_non_existent_binary_987654321").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_resolve_in_path_existing() {
        #[cfg(unix)]
        {
            let res = resolve_in_path("sh");
            assert!(res.is_ok());
        }
    }

    #[test]
    fn test_tier_label() {
        assert_eq!(tier_label(Some(Tier::Full)), "full");
        assert_eq!(tier_label(Some(Tier::FsOnly)), "fs-only");
        assert_eq!(tier_label(Some(Tier::Seccomp)), "seccomp");
        assert_eq!(tier_label(None), "macos-seatbelt");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(std::time::Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(std::time::Duration::from_secs(120)), "2m");
        assert_eq!(format_duration(std::time::Duration::from_secs(45)), "45s");
    }
}
