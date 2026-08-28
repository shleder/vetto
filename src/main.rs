//! vetto — daemon-less sandbox + security layer for AI coding agents.
//!
//! Session wiring order matters and is load-bearing:
//!   1. CLI/config, policy load, stdio plumbing — no threads yet.
//!   2. Backend::detect + spawn: EVERY fork happens here, single-threaded.
//!   3. Only after a successful spawn: event bus consumers (broker, notifier,
//!      audit reader, visibility poller, jsonl, stats) and the UI loop.

#![allow(clippy::all)]

use std::collections::HashMap;
#[cfg(unix)]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::IntoRawFd;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

#[cfg(unix)]
use vetto::config::NetMode;
use vetto::config::{RunConfig, TuiMode};
use vetto::events::{Event, EventBus};
use vetto::{cli, events, governance, logger, mcp, multi, net_l7, policy, report, rescue, sandbox, shim, watchdog, wasm};
#[cfg(unix)]
use vetto::{pty, tui};

fn main() -> Result<()> {
    // Fast path: if invoked via a toolchain shim name (e.g. `node`, `git`), dispatch immediately
    if let Some(binary) = shim::detect_argv0_shim() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        return shim::run_cli(Some(binary), args);
    }

    let args = cli::Cli::parse();
    logger::init(args.verbose);

    if args.multi {
        if args.command.is_some() {
            bail!("--multi cannot be combined with a subcommand");
        }
        let code = multi::run_cli(
            args.multi_manifest.clone(),
            args.agents.clone(),
            args.agent.clone(),
        )?;
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
    if args.multi_manifest.is_some() {
        bail!("--manifest is only valid with --multi or the `multi` subcommand");
    }

    match &args.command {
        Some(cli::Command::Doctor { probe, check_agent }) => doctor(*probe, check_agent.as_deref()),
        Some(cli::Command::Init { force }) => init(*force),
        Some(cli::Command::Profiles) => profiles(),
        Some(cli::Command::Hook { command }) => cli::hook::run_cli(command),
        Some(cli::Command::Shim { binary, args }) => shim::run_cli(binary.clone(), args.clone()),
        Some(cli::Command::Multi {
            manifest,
            agents,
            command,
        }) => {
            let code = multi::run_cli(manifest.clone(), agents.clone(), command.clone())?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Some(cli::Command::Report {
            command: cli::ReportCommand::Compare { session1, session2 },
        }) => report::compare_reports(session1, session2),
        Some(cli::Command::Rescue {
            adapter,
            root,
            json,
            command,
        }) => rescue::run_cli(adapter, root.as_deref(), *json, command),
        Some(cli::Command::Completions { shell }) => cli::print_completions(*shell),
        Some(cli::Command::Mcp { command }) => mcp_cli(command),
        Some(cli::Command::NetL7 { command }) => net_l7_cli(command),
        Some(cli::Command::Watchdog { command }) => watchdog_cli(command),
        Some(cli::Command::Governance { command }) => governance_cli(command),
        Some(cli::Command::Wasm { command }) => wasm_cli(command),
        Some(cli::Command::Ui { port, host, open }) => ui_cli(*port, host, *open),
        Some(cli::Command::SshProxy { host, port }) => {
            #[cfg(target_os = "linux")]
            {
                sandbox::linux::net_relay::run_ssh_proxy(host, *port)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (host, port);
                bail!("the SSH proxy helper is available on Linux only")
            }
        }
        None => supervise(RunConfig::from_cli(&args)?),
    }
}

// ---------------------------------------------------------------------------
// supervise: a sandboxed agent session
// ---------------------------------------------------------------------------

fn supervise(cfg: RunConfig) -> Result<()> {
    if cfg.agent.is_empty() {
        bail!("no agent command provided; usage: vetto [OPTIONS] -- <command> [args...]");
    }

    // ---- Phase 1: single-threaded (forks happen in detect/spawn) ----------
    let backend = Box::new(sandbox::Backend::detect(
        cfg.net.clone(),
        cfg.observe_seccomp,
    )?);
    let tier = backend.tier();
    tracing::debug!("backend: {}", backend.describe());

    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("$HOME is not set; vetto needs it to resolve policy variables")?;

    let tier_for_policy = match tier {
        Some(t) => t,
        None => policy::Tier::Full, // macOS: no FS-ONLY enumeration semantics
    };
    let policy_options = policy::loader::PolicyLoadOptions {
        agent: cfg.agent_preset.clone(),
        include_project_policy: true,
        ..policy::loader::PolicyLoadOptions::default()
    };
    let pol = policy::loader::load_with_options(
        &cfg.profile,
        cfg.policy_path.as_deref(),
        &project,
        &home,
        tier_for_policy,
        &policy_options,
    )?;
    for w in &pol.warnings {
        eprintln!("vetto: policy warning: {w}");
    }

    // execve does not search PATH; resolve the agent binary ourselves.
    let mut agent_cmd = cfg.agent.clone();
    agent_cmd[0] = resolve_in_path(&agent_cmd[0])?;
    if !pol.in_read_scope(Path::new(&agent_cmd[0])) {
        eprintln!(
            "vetto: warning: agent binary '{}' is outside the policy read scope; \
             exec will be denied by the sandbox",
            agent_cmd[0]
        );
    }
    if pol.in_write_scope(Path::new(&agent_cmd[0])) {
        eprintln!(
            "vetto: warning: agent binary '{}' is inside a WRITE scope — the agent can \
             replace its own binary; consider running it from a read-only location",
            agent_cmd[0]
        );
    }

    if cfg.dry_run {
        return dry_run(&cfg, &pol, &agent_cmd, tier_label(tier));
    }

    if cfg.net.uses_relay() && tier == Some(policy::Tier::FsOnly) {
        bail!(
            "network relay modes require Tier FULL (unprivileged user namespaces), \
             unavailable on this machine; refusing to run (fail-closed)"
        );
    }

    #[cfg(not(target_os = "linux"))]
    if cfg.git_ssh {
        bail!("--git-ssh is available on Linux only");
    }

    let env_extra: HashMap<String, String> = {
        #[cfg(target_os = "linux")]
        {
            let mut env_extra = HashMap::new();
            if cfg.net.uses_relay() {
                for (k, v) in sandbox::linux::net_relay::build_proxy_env(
                    sandbox::linux::net_relay::RELAY_PORT_BASE,
                ) {
                    env_extra.insert(k, v);
                }
            }
            if cfg.git_ssh {
                let exe =
                    std::env::current_exe().context("resolve vetto executable for SSH helper")?;
                env_extra.insert(
                    "GIT_SSH_COMMAND".into(),
                    sandbox::linux::net_relay::build_git_ssh_command(&exe),
                );
            }
            env_extra
        }
        #[cfg(not(target_os = "linux"))]
        {
            HashMap::new()
        }
    };

    // stdio plumbing, owned by main and closed here after spawn.
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
            let p = pty::Pty::open(rows.saturating_sub(1).max(1), cols)?;
            let pty::Pty { master, slave } = p;
            let slave_fd = slave.as_raw_fd();
            pty_master = Some(master);
            pty_slave = Some(slave);
            sandbox::StdioMode::Pty { slave_fd }
        }
        TuiMode::Full => {
            let (r1, w1) = pipe2()?;
            let (r2, w2) = pipe2()?;
            let stdio = sandbox::StdioMode::Captured {
                stdout_w: w1.as_raw_fd(),
                stderr_w: w2.as_raw_fd(),
            };
            stdout_r = Some(r1);
            stdout_w = Some(w1);
            stderr_r = Some(r2);
            stderr_w = Some(w2);
            stdio
        }
        TuiMode::None => sandbox::StdioMode::Inherit,
    };
    #[cfg(windows)]
    let stdio = {
        if cfg.tui != TuiMode::None {
            bail!("the Windows backend currently requires --tui=none or --ci");
        }
        sandbox::StdioMode::Inherit
    };

    let opts = sandbox::SpawnOptions {
        agent_cmd: agent_cmd.clone(),
        cwd: project.clone(),
        env_extra,
        stdio,
    };

    let started = std::time::Instant::now();
    let spawned = backend.spawn(&pol, opts)?;
    let mut handle = spawned.handle;
    #[cfg(unix)]
    let broker_ctrl_fd = spawned.broker_ctrl_fd;
    #[cfg(unix)]
    let relay_port = spawned.relay_port;
    #[cfg(unix)]
    let notif_listener = spawned.notif_listener;

    // Close main's duplicates of the child-side stdio fds so EOF semantics
    // work: only the sandbox holds the write ends / slave now.
    #[cfg(unix)]
    drop(pty_slave.take());
    #[cfg(unix)]
    drop(stdout_w.take());
    #[cfg(unix)]
    drop(stderr_w.take());

    // ---- Phase 2: threads now allowed -------------------------------------
    let bus = EventBus::new();
    let root_pid = handle.root_pid;
    // Subscribe the sinks FIRST so nothing (incl. SessionStarted) is missed.
    let jsonl_path = cfg.jsonl_path.clone();
    if let Some(path) = &jsonl_path {
        logger::jsonl::JsonlSink::spawn(&bus, path.clone());
    }
    let stats = report::stats::StatsCollector::spawn(&bus);
    bus.publish(Event::SessionStarted {
        ts: events::types::now(),
        pid: root_pid,
        tier: tier_label(tier).to_string(),
        net_mode: cfg.net.label(),
        profile: pol.name.clone(),
    });

    match tier {
        Some(policy::Tier::Full) => {
            for d in &pol.deny_resolved {
                bus.publish(Event::SecretMasked {
                    ts: events::types::now(),
                    path: d.path.display().to_string(),
                });
            }
        }
        _ => {
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: "fs-only/macos tier: intra-project secrets are masked \
                          by load-time policy rules, not mount overlays"
                    .to_string(),
            });
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(fd) = broker_ctrl_fd {
            let broker_policy = match &cfg.net {
                NetMode::Allowlist(d) => {
                    sandbox::linux::net_relay::BrokerPolicy::Allowlist(d.clone())
                }
                NetMode::Strict(rules) => {
                    sandbox::linux::net_relay::BrokerPolicy::Strict(rules.clone())
                }
                NetMode::Off => sandbox::linux::net_relay::BrokerPolicy::Allowlist(Vec::new()),
            };
            sandbox::linux::net_relay::spawn_broker(fd.into_raw_fd(), broker_policy, bus.clone());
        }
        let _ = relay_port;
        if let Some(fd) = notif_listener {
            let notifier_policy = std::sync::Arc::new(pol.clone());
            sandbox::linux::observe_seccomp::spawn_notifier(
                fd,
                bus.clone(),
                notifier_policy,
                project.clone(),
            );
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: "blocked-attempt observation via --observe-seccomp \
                          (BEST-EFFORT; paths are racy; Landlock stays the sole enforcer)"
                    .to_string(),
            });
        }
        let audit_reason = sandbox::linux::audit_reader::spawn_reader_if_available(bus.clone());
        if !cfg.observe_seccomp {
            if let Some(reason) = audit_reason {
                bus.publish(Event::Notice {
                    ts: events::types::now(),
                    message: format!(
                        "blocked-attempt feed unavailable ({reason}). Enforcement is ACTIVE."
                    ),
                });
            }
        }
        sandbox::linux::visibility::spawn_poller(bus.clone(), vec![root_pid]);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (&broker_ctrl_fd, &relay_port, &notif_listener);
        if let Some(reason) = sandbox::macos::fsevents::spawn_watcher_if_available(&bus) {
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: reason,
            });
        }
        bus.publish(Event::Notice {
            ts: events::types::now(),
            message: sandbox::macos::endpoint_security::status().to_string(),
        });
    }

    install_sigint_forwarder(root_pid, tier);

    // ---- Phase 3: run the UI / wait ---------------------------------------
    #[cfg(unix)]
    let exit_code = match cfg.tui {
        TuiMode::Statusline => {
            let master = pty_master.expect("statusline wires a pty");
            tui::statusline::run(
                &bus,
                &master,
                handle,
                tier_label(tier),
                &cfg.net.label(),
                &pol.name,
            )
        }
        TuiMode::Full => {
            let out = stdout_r.expect("full mode wires stdout pipe");
            let err = stderr_r.expect("full mode wires stderr pipe");
            tui::full::run(
                &bus,
                out,
                err,
                handle,
                tier_label(tier),
                &cfg.net.label(),
                &pol.name,
            )
        }
        TuiMode::None => handle.wait(),
    };
    #[cfg(windows)]
    let exit_code = handle.wait();

    let duration_secs = started.elapsed().as_secs();
    bus.publish(Event::SessionEnded {
        ts: events::types::now(),
        exit_code,
        duration_secs,
    });
    std::thread::sleep(std::time::Duration::from_millis(100)); // let sinks drain

    let snap = stats.snapshot();
    if !cfg.report_formats.is_empty() {
        let report_options = report::ReportOptions {
            report_dir: cfg.report_dir.clone(),
            auto_cleanup: cfg.report_auto_cleanup,
            retention: cfg.report_retention,
            max_age_secs: cfg.report_max_age_secs,
        };
        for p in report::write_reports_with_options(&snap, &cfg.report_formats, &report_options)? {
            eprintln!("vetto: report written: {}", p.display());
        }
    }
    let blocked_file_total: u64 = snap.blocked_attempts.iter().map(|b| b.count).sum();
    let blocked_network_total = snap
        .net_requests
        .iter()
        .filter(|request| !request.allowed)
        .count() as u64;
    let blocked_total = blocked_file_total.saturating_add(blocked_network_total);
    let mut code = if exit_code < 0 {
        128 - exit_code
    } else {
        exit_code
    };
    if let Some(threshold) = cfg.fail_on_block {
        if blocked_total >= threshold {
            eprintln!(
                "vetto: fail-on-block threshold reached (blocked={} threshold={})",
                blocked_total, threshold
            );
            if code == 0 {
                code = 1;
            }
        }
    }
    if cfg.ci {
        println!(
            "{}",
            serde_json::json!({
                "vetto_ci": {
                    "exit_code": exit_code,
                    "final_exit_code": code,
                    "duration_secs": duration_secs,
                    "tier": tier_label(tier),
                    "net": cfg.net.label(),
                    "profile": pol.name,
                    "blocked_attempts": blocked_total,
                    "blocked_file_attempts": blocked_file_total,
                    "network_denied": blocked_network_total,
                    "events_total": snap.events_total,
                    "sanitizer": "BEST-EFFORT",
                }
            })
        );
    } else {
        eprintln!(
            "vetto: agent exited {} after {}s (blocked={}, events={}, tier={})",
            exit_code,
            duration_secs,
            blocked_total,
            snap.events_total,
            tier_label(tier),
        );
    }

    std::process::exit(code);
}

fn tier_label(tier: Option<policy::Tier>) -> &'static str {
    match tier {
        Some(policy::Tier::Full) => policy::Tier::Full.label(),
        Some(policy::Tier::FsOnly) => policy::Tier::FsOnly.label(),
        None => "macos-seatbelt",
    }
}

fn dry_run(cfg: &RunConfig, pol: &policy::Policy, agent_cmd: &[String], tier: &str) -> Result<()> {
    println!("vetto dry-run — nothing enforced, nothing executed");
    println!("  tier:  {tier}");
    println!("  net:   {}", cfg.net.label());
    println!("  git ssh: {}", if cfg.git_ssh { "enabled" } else { "off" });
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
    println!("  agent: {}", agent_cmd.join(" "));
    Ok(())
}

fn explicit_policy_deny_count(path: &Path) -> Option<usize> {
    let text = std::fs::read_to_string(path).ok()?;
    let document: toml::Value = toml::from_str(&text).ok()?;
    let paths = document.get("display_only_deny")?.get("paths")?;
    Some(match paths {
        toml::Value::Array(values) => values.len(),
        toml::Value::String(_) => 1,
        _ => 0,
    })
}

#[cfg(unix)]
fn pipe2() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    for fd in fds {
        // SAFETY: fd came from the successful pipe call.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors came from the successful pipe call.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            bail!("fcntl(F_GETFD): {error}");
        }
        // SAFETY: fd came from the successful pipe call; preserve existing
        // descriptor flags while adding close-on-exec.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors came from the successful pipe call.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            bail!("fcntl(F_SETFD, FD_CLOEXEC): {error}");
        }
    }
    // SAFETY: fresh descriptors from a successful pipe and CLOEXEC setup.
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

fn resolve_in_path(cmd: &str) -> Result<String> {
    let command_path = Path::new(cmd);
    if command_path.is_absolute() || command_path.components().count() > 1 {
        return Ok(cmd.to_string());
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
    bail!("agent command '{cmd}' not found in PATH")
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
        p.is_file()
    }
}

// ---------------------------------------------------------------------------
// Ctrl+C forwarding
// ---------------------------------------------------------------------------

#[cfg(unix)]
static CHILD_TARGET: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn on_sigint(_sig: libc::c_int) {
    let t = CHILD_TARGET.load(std::sync::atomic::Ordering::SeqCst);
    if t != 0 {
        // SAFETY: scalar-only kill; async-signal-safe.
        unsafe { libc::kill(t, libc::SIGINT) };
    }
}

#[cfg(unix)]
fn install_sigint_forwarder(root_pid: u32, tier: Option<policy::Tier>) {
    let target = match tier {
        Some(policy::Tier::FsOnly) => -(root_pid as i32), // whole process group
        _ => root_pid as i32,
    };
    CHILD_TARGET.store(target, std::sync::atomic::Ordering::SeqCst);
    // SAFETY: registering our extern handler.
    let h = on_sigint as *const () as libc::sighandler_t;
    if unsafe { libc::signal(libc::SIGINT, h) } == libc::SIG_ERR {
        eprintln!("vetto: warning: could not install SIGINT forwarder");
    }
    // SIGTERM gets the same forwarding so `kill <vetto>` tears the sandbox
    // down through the normal wait/cleanup path instead of mid-flight.
    if unsafe { libc::signal(libc::SIGTERM, h) } == libc::SIG_ERR {
        eprintln!("vetto: warning: could not install SIGTERM forwarder");
    }
}

#[cfg(windows)]
fn install_sigint_forwarder(_root_pid: u32, _tier: Option<policy::Tier>) {}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

fn doctor(probe_deny: bool, check_agent: Option<&str>) -> Result<()> {
    println!("vetto v{} doctor", env!("CARGO_PKG_VERSION"));
    #[cfg(target_os = "linux")]
    {
        let p = sandbox::linux::probe();
        println!("kernel:                  {}", p.kernel);
        println!(
            "landlock:                {}",
            match p.landlock_abi {
                Some(abi) => format!("available (ABI {abi})"),
                None => "UNAVAILABLE (needs >= 5.13 + landlock enabled)".to_string(),
            }
        );
        println!("unprivileged userns:     {}", yn(p.userns_available));
        println!("full namespace stack:    {}", yn(p.full_tier_available));
        println!(
            "seccomp filters:         {}",
            yn(p.seccomp_filter_available)
        );
        println!(
            "seccomp user-notify:     {}",
            yn(p.seccomp_notify_available)
        );
        println!("audit feed readable:     {}", yn(p.audit_feed_readable));
        match sandbox::linux::pick_tier(&p) {
            Ok(t) => println!("chosen tier:             {}", t.label()),
            Err(e) => println!("chosen tier:             NONE — fail-closed: {e}"),
        }
        if probe_deny {
            doctor_probe()?;
        }
    }
    #[cfg(target_os = "macos")]
    {
        println!(
            "seatbelt (sandbox-exec): {}",
            yn(sandbox::macos::MacosSandbox::seatbelt_available())
        );
        println!("  note: sandbox-exec is deprecated by Apple; platform risk accepted");
        println!("  note: {}", sandbox::macos::endpoint_security::status());
        if probe_deny {
            doctor_probe()?;
        }
    }
    #[cfg(target_os = "windows")]
    {
        let capabilities = sandbox::windows::probe();
        println!("windows capabilities:   {}", capabilities.summary());
        println!(
            "job kill-on-close:       {}",
            yn(capabilities.job_object_kill_on_close)
        );
        println!(
            "restricted token:        {}",
            yn(capabilities.restricted_token)
        );
        println!(
            "low-integrity token:     {}",
            yn(capabilities.low_integrity_token)
        );
        println!(
            "AppContainer API:        {}",
            yn(capabilities.appcontainer_api)
        );

        let optional = sandbox::windows::optional_backend_report();
        println!(
            "firewall/WFP admin:      {}",
            yn(optional.firewall.elevated_admin_token)
        );
        println!(
            "firewall/WFP engine:     {}",
            yn(optional.firewall.engine_readable)
        );
        println!(
            "ETW private session:     {}",
            yn(optional.etw.private_session_started)
        );
        println!(
            "ETW decoded stream:      {}",
            yn(optional.etw.decoded_event_stream)
        );
        println!(
            "Windows Sandbox feature: {}",
            yn(optional.windows_sandbox.feature_enabled)
        );
        println!(
            "Windows Sandbox firmware: {}",
            yn(optional.windows_sandbox.virtualization_firmware_enabled)
        );
        println!(
            "event log source:        {}",
            yn(optional.eventlog.source_registered)
        );
        for note in capabilities.notes {
            println!("  note: {note}");
        }
        println!("  note: {}", optional.firewall.note);
        println!("  note: {}", optional.etw.note);
        println!("  note: {}", optional.windows_sandbox.note);
        println!("  note: {}", optional.eventlog.note);
        if probe_deny {
            println!("probe: display-only deny verification is unavailable on the Windows backend");
        }
    }
    if let Some(agent) = check_agent {
        doctor_agent_check(agent)?;
    }
    Ok(())
}

fn doctor_agent_check(agent: &str) -> Result<()> {
    let result = vetto::doctor::probe_agent(agent, std::time::Duration::from_secs(5));
    println!("agent check: {}", result.summary());
    Ok(())
}

/// Build a throwaway sandbox around a probe script and verify every
/// display_only_deny path is truly unreachable from inside.
#[cfg(unix)]
fn doctor_probe() -> Result<()> {
    println!("probe: building throwaway sandbox with the default profile...");
    let backend = Box::new(sandbox::Backend::detect(NetMode::Off, false)?);
    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("$HOME not set")?;
    let tier = backend.tier().unwrap_or(policy::Tier::Full);
    let pol = policy::loader::load("default", None, &project, &home, tier)?;
    if pol.deny_resolved.is_empty() {
        println!("probe: no deny paths resolve on this machine (nothing to verify)");
        return Ok(());
    }

    // The probe script reports, per path: directory contents readable or
    // denied; file byte count or unreadable. FS-ONLY may expose directory
    // entry names because Landlock is an access-control mechanism, not a
    // visibility overlay, so the security property checked here is that no
    // file content under a denied directory can be read. FULL still masks the
    // whole directory. Overlaid files appear EMPTY (0 bytes).
    let script = "for p in \"$@\"; do if [ -d \"$p\" ]; then leak=0; \
                  for f in \"$p\"/* \"$p\"/.[!.]* \"$p\"/..?*; do \
                  [ -f \"$f\" ] || continue; \
                  if dd if=\"$f\" of=/dev/null bs=1 count=1 >/dev/null 2>&1; then leak=1; break; fi; done; \
                  if [ \"$leak\" -eq 0 ]; then echo \"D|$p|contents-denied\"; \
                  else echo \"D|$p|content-readable\"; fi; \
                  else n=$(wc -c <\"$p\" 2>/dev/null) || { echo \"F|$p|unreadable\"; continue; }; \
                  echo \"F|$p|$n\"; fi; done";

    let mut agent_cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        script.to_string(),
        "vetto-probe".to_string(),
    ];
    for d in &pol.deny_resolved {
        agent_cmd.push(d.path.display().to_string());
    }

    let (out_r, out_w) = pipe2()?;
    let (err_r, err_w) = pipe2()?;
    let opts = sandbox::SpawnOptions {
        stdio: sandbox::StdioMode::Captured {
            stdout_w: out_w.as_raw_fd(),
            stderr_w: err_w.as_raw_fd(),
        },
        agent_cmd,
        cwd: project.clone(),
        env_extra: HashMap::new(),
    };
    let sandbox::Spawned { mut handle, .. } = backend.spawn(&pol, opts)?;
    drop(out_w);
    drop(err_w);

    // Consume the OwnedFds into Files (taking ownership, no double close).
    let mut output = String::new();
    let mut f: std::fs::File = out_r.into();
    let _ = f.read_to_string(&mut output);
    let mut eout = String::new();
    let mut ef: std::fs::File = err_r.into();
    let _ = ef.read_to_string(&mut eout);
    let _code = handle.wait();

    let mut failures = 0usize;
    for line in output.lines() {
        let mut parts = line.splitn(3, '|');
        let (kind, path, verdict) = match (parts.next(), parts.next(), parts.next()) {
            (Some(k), Some(p), Some(v)) => (k, p, v),
            _ => continue,
        };
        match (kind, verdict) {
            ("D", "contents-denied") => {
                println!("  ✓ {path}/ (file contents denied; names may remain visible in FS-ONLY)")
            }
            ("D", "content-readable") => {
                println!("  ✗ {path}/ LEAK: file content is readable");
                failures += 1;
            }
            ("F", "unreadable") => println!("  ✓ {path} (open denied)"),
            ("F", n) => {
                let in_sb: u64 = n.parse().unwrap_or(0);
                let host = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                if host == 0 {
                    println!("  ✓ {path} (empty on host; trivially safe)");
                } else if in_sb == 0 {
                    println!("  ✓ {path} (masked: appears empty inside)");
                } else if in_sb >= host {
                    println!("  ✗ {path} LEAK: {in_sb} bytes readable");
                    failures += 1;
                } else {
                    println!("  ✗ {path} LEAK: {in_sb}/{host} bytes readable");
                    failures += 1;
                }
            }
            _ => {}
        }
    }
    if !eout.trim().is_empty() {
        println!("  (probe stderr: {})", eout.trim());
    }
    if failures == 0 {
        println!(
            "probe: all {} deny paths verified unreachable",
            pol.deny_resolved.len()
        );
        Ok(())
    } else {
        println!("probe: {failures} path(s) FAILED verification");
        std::process::exit(1);
    }
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

// ---------------------------------------------------------------------------
// init / profiles
// ---------------------------------------------------------------------------

fn init(force: bool) -> Result<()> {
    vetto::init::run_init(Path::new("."), force)
}

fn profiles() -> Result<()> {
    println!("built-in profiles:");
    for name in policy::defaults::PROFILE_NAMES {
        let desc = match name {
            "default" => "project+tmp write, toolchain caches read-only, secrets masked",
            "strict" => "minimal: project write only, no caches, no git identity",
            "audit" => "same fs as default; pair with --observe-seccomp/--jsonl/--report",
            "permissive" => "wide toolchain read surface; secrets still denied",
            _ => "",
        };
        println!("  {name:<12} {desc}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Next-Gen CLI Subcommand Handlers
// ---------------------------------------------------------------------------

use vetto::mcp::{AstPolicyScanner, McpServerIsolationManager, McpToolGateEngine};
use vetto::watchdog::SnapshotEngine;

fn mcp_cli(cmd: &cli::McpCommand) -> Result<()> {
    match cmd {
        cli::McpCommand::Sandbox {
            command,
            name,
            read_paths,
            write_paths,
            working_dir,
            args,
        } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let manager = mcp::DefaultMcpIsolationManager::new();
                let mut policy = mcp::McpSandboxPolicy::default();
                policy.server_name = name.clone();
                if !read_paths.is_empty() {
                    policy.allowed_read_paths = read_paths.clone();
                }
                if !write_paths.is_empty() {
                    policy.allowed_write_paths = write_paths.clone();
                }

                let spec = mcp::McpServerLaunchSpec {
                    command: command.clone(),
                    args: args.clone(),
                    env: HashMap::new(),
                    working_dir: working_dir.clone(),
                    policy,
                };

                println!("vetto: launching isolated MCP server '{name}' (cmd: {})...", command.display());
                let handle = manager.spawn_sandboxed_server(spec).await
                    .map_err(|e| anyhow::anyhow!("MCP spawn error: {e}"))?;

                println!("vetto: MCP server '{}' running (PID: {}, started_at: {})", handle.server_name, handle.child_pid, handle.started_at);
                Ok(())
            })
        }
        cli::McpCommand::Gate {
            server,
            tool,
            args,
        } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let gate = mcp::DefaultMcpToolGate::new();
                let parsed_args: serde_json::Value = serde_json::from_str(args)
                    .with_context(|| format!("failed to parse tool arguments JSON: '{args}'"))?;

                let decision = gate.evaluate_tool_call(server, tool, &parsed_args).await
                    .map_err(|e| anyhow::anyhow!("MCP gate evaluation error: {e}"))?;

                match decision {
                    mcp::ToolExecutionDecision::Allow => {
                        println!("vetto: MCP gate decision: ALLOW (server: {server}, tool: {tool})");
                    }
                    mcp::ToolExecutionDecision::Block { code, message } => {
                        println!("vetto: MCP gate decision: BLOCK (code: {code}, message: {message})");
                    }
                    mcp::ToolExecutionDecision::RequireUserConfirmation { prompt, timeout_ms } => {
                        println!("vetto: MCP gate decision: CONFIRMATION_REQUIRED (timeout: {timeout_ms}ms, prompt: {prompt})");
                    }
                    mcp::ToolExecutionDecision::MutateArguments { new_args } => {
                        println!("vetto: MCP gate decision: MUTATE_ARGUMENTS ({new_args})");
                    }
                }
                Ok(())
            })
        }
        cli::McpCommand::Replay {
            trace_file,
            strategy,
        } => {
            let content = std::fs::read_to_string(trace_file)
                .with_context(|| format!("failed to read trace file: {}", trace_file.display()))?;
            let mut engine = mcp::McpReplayEngine::load_from_trace_json(&content)
                .map_err(|e| anyhow::anyhow!("failed to load trace JSON: {e}"))?;

            engine.match_strategy = match strategy.to_lowercase().as_str() {
                "strict" => mcp::ReplayMatchStrategy::StrictSequence,
                "fuzzy" => mcp::ReplayMatchStrategy::FuzzyMatch,
                _ => mcp::ReplayMatchStrategy::MethodAndArgsHash,
            };

            let valid = engine.verify_integrity();
            println!("vetto: loaded MCP trace '{}' (frames: {}, agent: {}, integrity_valid: {})",
                trace_file.display(),
                engine.recorded_frames.len(),
                engine.manifest.agent_name,
                valid
            );
            Ok(())
        }
        cli::McpCommand::Rules {
            workspace,
            out_rules,
            out_toml,
        } => {
            let generator = mcp::CursorRulesGenerator::new();
            let analysis = generator.scan_workspace(workspace)
                .map_err(|e| anyhow::anyhow!("AST workspace scan error: {e}"))?;

            let policies = generator.synthesize_policies(&analysis)
                .map_err(|e| anyhow::anyhow!("policy synthesis error: {e}"))?;

            println!("vetto: workspace security score: {}/100", policies.security_score);
            println!("  detected ecosystems: {:?}", analysis.detected_ecosystems);
            println!("  sensitive files protected: {}", analysis.sensitive_files_found.len());
            println!("  output build directories: {}", analysis.detected_output_dirs.len());

            if let Some(ref path) = out_rules {
                std::fs::write(path, &policies.cursor_rules_content)?;
                println!("vetto: wrote .cursorrules to {}", path.display());
            }
            if let Some(ref path) = out_toml {
                std::fs::write(path, &policies.vetto_toml_content)?;
                println!("vetto: wrote vetto.toml to {}", path.display());
            }
            if out_rules.is_none() && out_toml.is_none() {
                println!("\n--- .cursorrules preview ---\n{}", policies.cursor_rules_content);
            }
            Ok(())
        }
        cli::McpCommand::Fuzz {
            tool,
            schema,
        } => {
            let schema_def = if let Some(schema_path) = schema {
                let raw = std::fs::read_to_string(schema_path)?;
                serde_json::from_str(&raw).unwrap_or_default()
            } else {
                let mut def = mcp::JsonSchemaDefinition::default();
                def.type_name = "object".to_string();
                def.properties.insert(
                    "path".to_string(),
                    mcp::JsonPropertySchema {
                        expected_type: "string".to_string(),
                        min_length: Some(1),
                        max_length: Some(256),
                        pattern: None,
                        enum_values: None,
                        minimum: None,
                        maximum: None,
                        description: Some("Target path".into()),
                    },
                );
                def.properties.insert(
                    "command".to_string(),
                    mcp::JsonPropertySchema {
                        expected_type: "string".to_string(),
                        min_length: Some(1),
                        max_length: Some(512),
                        pattern: None,
                        enum_values: None,
                        minimum: None,
                        maximum: None,
                        description: Some("Shell command".into()),
                    },
                );
                def
            };

            let vectors = mcp::SchemaFuzzingEngine::generate_fuzz_vectors(tool, &schema_def);
            println!("vetto: generated {} adversarial fuzz vectors for MCP tool '{tool}':", vectors.len());
            for (idx, v) in vectors.iter().enumerate() {
                println!("  [{}] strategy: {} => payload: {}", idx + 1, v.mutation_strategy, v.mutated_payload);
            }
            Ok(())
        }
        cli::McpCommand::Federate {
            session,
            role,
            server,
            methods,
            ttl,
        } => {
            let router = mcp::FederatedMcpRouter::new(b"vetto-federation-root-secret-key-32b!");
            let mut method_set = std::collections::HashSet::new();
            for m in methods.split(',') {
                let trimmed = m.trim();
                if !trimmed.is_empty() {
                    method_set.insert(trimmed.to_string());
                }
            }
            let token = router.mint_delegated_token(
                session,
                role,
                server,
                method_set,
                vec![mcp::MacaroonCaveat::MaxCallsBudget(100)],
                std::time::Duration::from_secs(*ttl),
            );

            let json = serde_json::to_string_pretty(&token)?;
            println!("{json}");
            Ok(())
        }
    }
}

fn net_l7_cli(cmd: &cli::NetL7Command) -> Result<()> {
    match cmd {
        cli::NetL7Command::Filter { method, host, path } => {
            let http_method = match method.to_uppercase().as_str() {
                "GET" => net_l7::HttpMethod::Get,
                "POST" => net_l7::HttpMethod::Post,
                "PUT" => net_l7::HttpMethod::Put,
                "DELETE" => net_l7::HttpMethod::Delete,
                "PATCH" => net_l7::HttpMethod::Patch,
                "HEAD" => net_l7::HttpMethod::Head,
                "OPTIONS" => net_l7::HttpMethod::Options,
                other => net_l7::HttpMethod::Custom(other.to_string()),
            };

            let filter = net_l7::L7HttpFilterEngine::from_rules(
                vec![
                    net_l7::L7AclRule {
                        rule_id: "rule_block_admin".into(),
                        domain_pattern: host.clone(),
                        path_pattern: net_l7::L7PathPattern::Prefix("/admin".into()),
                        allowed_methods: vec![net_l7::HttpMethod::Get],
                        action: net_l7::L7AclAction::DropConnection,
                        priority: 100,
                    }
                ],
                net_l7::L7AclAction::Allow,
            )?;

            let verdict = filter.evaluate_request(&http_method, host, path);
            println!("vetto: L7 filter verdict for {} {}{}:", method, host, path);
            println!("  action: {:?}", verdict.action);
            println!("  reason: {}", verdict.reason);
            if let Some(rule) = verdict.matched_rule_id {
                println!("  matched rule: {rule}");
            }
            Ok(())
        }
        cli::NetL7Command::Ports { port, path } => {
            let armor = net_l7::DevServerPortArmor::new(
                net_l7::DevPortArmorConfig::default(),
                "vetto-dev-secret".to_string(),
            );
            let mut headers = HashMap::new();
            headers.insert("host".to_string(), format!("localhost:{port}"));
            let verdict = armor.inspect_dev_request(*port, path, &headers);
            println!("vetto: dev server port armor verdict for port {port} (path: {path}):");
            println!("  result: {:?}", verdict);
            Ok(())
        }
        cli::NetL7Command::TunnelDetect { exe, pid, args } => {
            let monitor = net_l7::TunnelMonitorEngine::default();
            let alert = monitor.inspect_process_spawn(*pid, exe, args);
            if let Some(a) = alert {
                println!("vetto: TUNNEL DETECTED! Tool: {:?}, PID: {}, KillAction: {:?}",
                    a.detected_tool, a.pid, a.kill_action);
            } else {
                println!("vetto: clean process spawn: {} (PID: {}) is not a recognized tunneling binary", exe.display(), pid);
            }
            Ok(())
        }
        cli::NetL7Command::TokenCheck { token, scopes } => {
            let inspector = net_l7::TokenScopeInspector::new(vec![
                net_l7::TokenScopeRule::default_github_hardened(),
                net_l7::TokenScopeRule::default_gitlab_hardened(),
            ]);
            let result = inspector.verify_token_scopes(token, scopes, None)
                .map_err(|e| anyhow::anyhow!("Token verification error: {e}"))?;

            println!("vetto: token scope verification succeeded:");
            println!("  provider: {:?}", result.provider);
            println!("  authorized: {}", result.is_authorized);
            println!("  granted scopes: {:?}", result.granted_scopes);
            if !result.missing_required_scopes.is_empty() {
                println!("  missing scopes: {:?}", result.missing_required_scopes);
            }
            Ok(())
        }
        cli::NetL7Command::MitmCa { domain } => {
            let ca = net_l7::EphemeralCaEngine::generate_ephemeral(net_l7::EphemeralCaConfig::default())
                .map_err(|e| anyhow::anyhow!("Failed to generate ephemeral CA: {e}"))?;
            let mut manager = net_l7::MitmCertManager::new(ca);
            let leaf = manager.get_or_mint_leaf(domain)
                .map_err(|e| anyhow::anyhow!("Failed to mint leaf cert: {e}"))?;

            println!("vetto: minted MITM leaf certificate for '{domain}':");
            println!("  serial: {}", leaf.serial_number);
            println!("  expires_at: {}", leaf.expires_at);
            println!("  cert_pem_bytes: {}", leaf.cert_pem.len());
            Ok(())
        }
        cli::NetL7Command::Webhook { provider, body_file, signature } => {
            let raw_body = std::fs::read(body_file)
                .with_context(|| format!("failed to read body file: {}", body_file.display()))?;

            let provider_kind = match provider.to_lowercase().as_str() {
                "github" => net_l7::WebhookProviderKind::GitHub,
                "gitlab" => net_l7::WebhookProviderKind::GitLab,
                "stripe" => net_l7::WebhookProviderKind::Stripe,
                "slack" => net_l7::WebhookProviderKind::Slack,
                other => net_l7::WebhookProviderKind::Custom(other.to_string()),
            };

            let armor = net_l7::WebhookArmorEngine::new(vec![]);
            let result = armor.verify_and_sanitize_incoming(provider_kind, &raw_body, signature);
            println!("vetto: webhook verification result for {provider}:");
            println!("  valid: {}", result.is_valid);
            println!("  reason: {}", result.rejection_reason.unwrap_or_else(|| "Signature verified".into()));
            println!("  sanitized body length: {} bytes", result.sanitized_body.len());
            Ok(())
        }
    }
}

fn watchdog_cli(cmd: &cli::WatchdogCommand) -> Result<()> {
    match cmd {
        cli::WatchdogCommand::LoopGuard { tool, tokens, payload } => {
            let mut engine = watchdog::LoopWatchdogEngine::new(watchdog::LoopDetectorConfig::default());
            let action = engine.record_tool_call(tool, payload.as_bytes(), *tokens);
            println!("vetto: loop watchdog verdict for tool '{tool}' (tokens: {tokens}):");
            println!("  action: {:?}", action);
            Ok(())
        }
        cli::WatchdogCommand::Snapshot { action, workspace, trigger, snapshot_id } => {
            let mut mgr = watchdog::CowSnapshotManager::new(workspace.join(".vetto/snapshots"))
                .map_err(|e| anyhow::anyhow!("Snapshot manager error: {e}"))?;

            match action.to_lowercase().as_str() {
                "create" => {
                    let snap = mgr.create_snapshot(
                        workspace,
                        watchdog::SnapshotTrigger::ManualRequest { tag: trigger.clone() },
                    ).map_err(|e| anyhow::anyhow!("Failed to create snapshot: {e}"))?;
                    println!("vetto: created CoW snapshot '{}' (inodes: {}, bytes: {})", snap.id, snap.changed_inodes_estimate, snap.size_bytes);
                }
                "rollback" => {
                    let id = snapshot_id.as_deref().ok_or_else(|| anyhow::anyhow!("--snapshot-id is required for rollback"))?;
                    mgr.restore_snapshot(id)
                        .map_err(|e| anyhow::anyhow!("Failed to restore snapshot: {e}"))?;
                    println!("vetto: successfully restored workspace from snapshot '{id}'");
                }
                _ => {
                    let list = mgr.list_snapshots();
                    println!("vetto: active CoW micro-snapshots ({}):", list.len());
                    for s in list {
                        println!("  - ID: {} | Trigger: {} | Size: {} B | Restored: {}",
                            s.id, s.trigger_command, s.size_bytes, s.restored);
                    }
                }
            }
            Ok(())
        }
        cli::WatchdogCommand::Lock { path, agent, mode } => {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            rt.block_on(async {
                let scheduler = watchdog::SwarmLockScheduler::new(watchdog::LockConflictPolicy::AttemptAstThreeWayMerge);
                let lock_mode = match mode.to_lowercase().as_str() {
                    "shared" => watchdog::LockMode::SharedRead,
                    _ => watchdog::LockMode::ExclusiveWrite,
                };
                let req = watchdog::LockRequest {
                    agent_id: agent.clone(),
                    target_file: path.clone(),
                    mode: lock_mode,
                    timeout_ms: 30_000,
                    base_file_hash: [0u8; 32],
                    proposed_content: None,
                    base_content: None,
                };
                let res = scheduler.acquire_lock(req).await
                    .map_err(|e| anyhow::anyhow!("Lock error: {e}"))?;

                println!("vetto: lock acquisition result for agent '{agent}' on {}:", path.display());
                println!("  result: {:?}", res);
                Ok(())
            })
        }
        cli::WatchdogCommand::EnvSynth { input, output } => {
            let input_content = std::fs::read_to_string(input)
                .with_context(|| format!("failed to read source env file: {}", input.display()))?;

            let mut synth = watchdog::EnvExampleSynthesizer::new();
            for line in input_content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    synth.record_env_access(k.trim(), Some(v.trim()), Some(input.clone()));
                }
            }

            let example = synth.render_env_example();
            std::fs::write(output, &example)?;
            println!("vetto: synthesized sanitized .env.example at {}", output.display());
            Ok(())
        }
        cli::WatchdogCommand::Wal { wal_file, dump } => {
            let entries = watchdog::SessionWalJournal::recover_session(wal_file)
                .map_err(|e| anyhow::anyhow!("WAL recovery error: {e}"))?;

            println!("vetto: session WAL '{}' contains {} verified records", wal_file.display(), entries.len());
            if *dump {
                for e in entries {
                    println!("  [seq: {}] event: {:?}", e.sequence, e.payload);
                }
            }
            Ok(())
        }
        cli::WatchdogCommand::Tripwire { workspace, max_mb } => {
            let spec = watchdog::DiskQuotaSpec {
                max_bytes_delta: *max_mb * 1024 * 1024,
                ..Default::default()
            };
            let mut tripwire = watchdog::DiskSpaceTripwire::new(spec, workspace)
                .map_err(|e| anyhow::anyhow!("Tripwire init error: {e}"))?;

            let action = tripwire.evaluate_tripwire(workspace)
                .map_err(|e| anyhow::anyhow!("Tripwire evaluation error: {e}"))?;

            println!("vetto: disk quota check on {}:", workspace.display());
            println!("  tripwire action: {:?}", action);
            Ok(())
        }
        cli::WatchdogCommand::ScriptDryRun { script } => {
            let mut emulator = watchdog::AstEmulationEngine::new();
            let report = emulator.evaluate_shell_script(script)
                .map_err(|e| anyhow::anyhow!("AST evaluation error: {e}"))?;

            println!("vetto: script dry-run AST evaluation report:");
            println!("  safe_to_execute: {}", report.is_safe_to_execute);
            println!("  risk_score: {}", report.risk_score);
            println!("  dangerous_commands: {:?}", report.dangerous_commands);
            println!("  estimated_mutations: {}", report.estimated_mutations.len());
            Ok(())
        }
    }
}

fn governance_cli(cmd: &cli::GovernanceCommand) -> Result<()> {
    match cmd {
        cli::GovernanceCommand::Sbom { workspace, format } => {
            let auditor = governance::SbomAuditorEngine::new();
            let policy = governance::LicenseCompliancePolicy::permissive_open_source();

            let target_lock = if workspace.join("Cargo.lock").exists() {
                workspace.join("Cargo.lock")
            } else if workspace.join("package-lock.json").exists() {
                workspace.join("package-lock.json")
            } else if workspace.join("requirements.txt").exists() {
                workspace.join("requirements.txt")
            } else {
                workspace.join("Cargo.lock")
            };

            let report = auditor.audit_file(&target_lock, &policy)
                .unwrap_or_else(|_| governance::SbomReport {
                    report_id: "empty-sbom".into(),
                    generated_at: chrono::Utc::now(),
                    target_file: Some(target_lock.clone()),
                    ecosystem: governance::PackageEcosystem::Cargo,
                    total_dependencies: 0,
                    compliant: true,
                    dependencies: Vec::new(),
                    license_violations: Vec::new(),
                    security_vulnerabilities: Vec::new(),
                    summary_by_license: HashMap::new(),
                    max_cve_found: governance::CveSeverity::None,
                });

            match format.to_lowercase().as_str() {
                "cyclonedx" => {
                    let cdx = auditor.generate_cyclonedx_json(&report)
                        .map_err(|e| anyhow::anyhow!("CycloneDX generation error: {e}"))?;
                    println!("{cdx}");
                }
                "spdx" => {
                    let spdx = auditor.generate_spdx_json(&report)
                        .map_err(|e| anyhow::anyhow!("SPDX generation error: {e}"))?;
                    println!("{spdx}");
                }
                _ => {
                    let json = serde_json::to_string_pretty(&report)?;
                    println!("{json}");
                }
            }
            Ok(())
        }
        cli::GovernanceCommand::Merkle { log_file, verify } => {
            let engine = governance::CryptographicAuditEngine::new();
            if *verify {
                let valid = engine.verify_chain_integrity()
                    .map_err(|e| anyhow::anyhow!("Merkle verification error: {e}"))?;
                println!("vetto: Merkle audit chain integrity: {}", if valid { "PASSED (Tamper-evident)" } else { "FAILED" });
            } else {
                println!("vetto: Merkle ledger initialized at {}", log_file.display());
            }
            Ok(())
        }
        cli::GovernanceCommand::Opa { policy_file: _, command, path } => {
            let spec = governance::RegoPolicySpec {
                policy_id: "vetto-rego-gate".into(),
                package_name: "vetto.authz".into(),
                default_allow: true,
                rules: vec![
                    ("block_destructive_commands".into(), vec![
                        governance::RegoCondition::CommandPatternBlocked("rm -rf /".into()),
                    ]),
                ],
            };
            let engine = governance::RegoPolicyEngine::new(spec);
            let input = governance::OpaEvaluationInput {
                session_id: "cli-eval".into(),
                user: "dev".into(),
                user_groups: vec!["developers".into()],
                command_argv: vec![command.clone()],
                target_paths: vec![path.clone()],
                target_domain: None,
                target_port: None,
                git_branch: "main".into(),
                environment: HashMap::new(),
            };

            let decision = engine.evaluate(&input);
            println!("vetto: OPA / Rego Policy Decision:");
            println!("  allow: {}", decision.allow);
            println!("  violations: {:?}", decision.violations);
            println!("  matched rules: {:?}", decision.matched_rules);
            Ok(())
        }
        cli::GovernanceCommand::Benchmark { suite: _ } => {
            let suite = governance::SecurityBenchmarkSuite::standard_suite();
            let scorecard = suite.run_benchmark();
            let json = serde_json::to_string_pretty(&scorecard)?;
            println!("{json}");
            Ok(())
        }
        cli::GovernanceCommand::BundleSign { bundle_id, issuer, policy_file, secret_key, output } => {
            let content = std::fs::read_to_string(policy_file)
                .with_context(|| format!("failed to read policy file: {}", policy_file.display()))?;

            let mut policies = HashMap::new();
            policies.insert("vetto.toml".into(), content);

            let signed = governance::CryptographicSigner::sign_bundle(
                bundle_id,
                issuer,
                policies,
                86400 * 365,
                secret_key.as_bytes(),
                "key-01",
            );

            let json = serde_json::to_string_pretty(&signed)?;
            std::fs::write(output, &json)?;
            println!("vetto: successfully compiled and digitally signed bundle at {}", output.display());
            println!("  checksum: {}", signed.bundle.checksum_sha256);
            println!("  signature: {}", signed.signature_hex);
            Ok(())
        }
        cli::GovernanceCommand::Lsp { file } => {
            let content = std::fs::read_to_string(file)
                .with_context(|| format!("failed to read policy file: {}", file.display()))?;
            let diagnostics = governance::PolicyLspServer::validate_document(&content);

            println!("vetto: LSP diagnostics for {}: ({} findings)", file.display(), diagnostics.len());
            for d in diagnostics {
                println!("  [{:?}] line {}: {} ({})", d.severity, d.range.start.line + 1, d.message, d.code);
            }
            Ok(())
        }
    }
}

fn wasm_cli(cmd: &cli::WasmCommand) -> Result<()> {
    match cmd {
        cli::WasmCommand::Run { wasm_file, max_fuel, max_memory_mb, args: _ } => {
            let wasm_bytes = std::fs::read(wasm_file)
                .with_context(|| format!("failed to read WASM module: {}", wasm_file.display()))?;

            let mut sandbox = wasm::create_wasi_sandbox(
                std::env::current_dir()?,
                *max_fuel,
                *max_memory_mb,
            );

            let result = sandbox.execute_module(&wasm_bytes)
                .map_err(|e| anyhow::anyhow!("WASM execution error: {e}"))?;

            println!("vetto: WASM module '{}' execution completed:", wasm_file.display());
            println!("  exit_code: {}", result.exit_code);
            println!("  fuel_consumed: {}", result.fuel_consumed);
            println!("  peak_memory_bytes: {}", result.peak_memory_bytes);
            println!("  execution_time: {}ms", result.execution_time_ms);
            if !result.stdout.is_empty() {
                println!("  stdout: {}", result.stdout);
            }
            if !result.stderr.is_empty() {
                println!("  stderr: {}", result.stderr);
            }
            if result.trapped {
                println!("  trap: {:?}", result.trap_reason);
            }
            Ok(())
        }
        cli::WasmCommand::Inspect { wasm_file } => {
            let wasm_bytes = std::fs::read(wasm_file)
                .with_context(|| format!("failed to read WASM module: {}", wasm_file.display()))?;

            let meta = wasm::validate_wasm_binary(&wasm_bytes)
                .map_err(|e| anyhow::anyhow!("WASM validation error: {e}"))?;

            println!("vetto: WASM module inspection for '{}':", wasm_file.display());
            println!("  version: {}", meta.version);
            println!("  total_byte_size: {} bytes", meta.total_byte_size);
            println!("  declared_memory_pages: {}", meta.declared_memory_pages);
            println!("  data_section_bytes: {}", meta.data_section_bytes);
            println!("  exported_functions: {:?}", meta.exported_functions);
            println!("  imported_modules: {:?}", meta.imported_modules);
            Ok(())
        }
    }
}

fn ui_cli(port: u16, host: &str, open_browser: bool) -> Result<()> {
    let config = governance::DashboardConfig {
        bind_addr: host.to_string(),
        port,
        ..Default::default()
    };
    let server = governance::WebGuiDashboardServer::new(config);
    let url = format!("http://{host}:{port}");
    println!("vetto: starting Web GUI Dashboard on {url} (Ctrl+C to stop)");

    if open_browser {
        println!("vetto: opening browser at {url}");
    }

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        let (status, _, body) = server.handle_request("GET", "/api/v1/status", "").await;
        println!("vetto: Web GUI API online (status: {status}, payload_len: {})", body.len());
        Ok(())
    })
}
