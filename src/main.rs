//! vetto — daemon-less sandbox + security layer for AI coding agents.
//!
//! Session wiring order matters and is load-bearing:
//!   1. CLI/config, policy load, stdio plumbing — no threads yet.
//!   2. Backend::detect + spawn: EVERY fork happens here, single-threaded.
//!   3. Only after a successful spawn: event bus consumers (broker, notifier,
//!      audit reader, visibility poller, jsonl, stats) and the UI loop.

mod classifier;
mod cli;
mod config;
mod error;
mod events;
mod logger;
mod policy;
mod pty;
mod report;
mod sandbox;
mod tui;

use std::collections::HashMap;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::config::{NetMode, RunConfig, TuiMode};
use crate::events::{Event, EventBus};

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    logger::init(args.verbose);
    match &args.command {
        Some(cli::Command::Doctor { probe }) => doctor(*probe),
        Some(cli::Command::Init) => init(),
        Some(cli::Command::Profiles) => profiles(),
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
    let backend = Box::new(sandbox::Backend::detect(cfg.net.clone(), cfg.observe_seccomp)?);
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
    let pol = policy::loader::load(
        &cfg.profile,
        cfg.policy_path.as_deref(),
        &project,
        &home,
        tier_for_policy,
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

    if matches!(cfg.net, NetMode::Allowlist(_)) && tier == Some(policy::Tier::FsOnly) {
        bail!(
            "--net=allowlist requires Tier FULL (unprivileged user namespaces), \
             unavailable on this machine; refusing to run (fail-closed)"
        );
    }

    let mut env_extra: HashMap<String, String> = HashMap::new();
    #[cfg(target_os = "linux")]
    if matches!(cfg.net, NetMode::Allowlist(_)) {
        for (k, v) in
            sandbox::linux::net_relay::build_proxy_env(sandbox::linux::net_relay::RELAY_PORT_BASE)
        {
            env_extra.insert(k, v);
        }
    }

    // stdio plumbing, owned by main and closed here after spawn.
    let mut pty_master: Option<OwnedFd> = None;
    let mut pty_slave: Option<OwnedFd> = None;
    let mut stdout_r: Option<OwnedFd> = None;
    let mut stdout_w: Option<OwnedFd> = None;
    let mut stderr_r: Option<OwnedFd> = None;
    let mut stderr_w: Option<OwnedFd> = None;
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

    let opts = sandbox::SpawnOptions {
        agent_cmd: agent_cmd.clone(),
        cwd: project.clone(),
        env_extra,
        stdio,
    };

    let started = std::time::Instant::now();
    let sandbox::Spawned {
        mut handle,
        broker_ctrl_fd,
        relay_port,
        notif_listener,
    } = backend.spawn(&pol, opts)?;

    // Close main's duplicates of the child-side stdio fds so EOF semantics
    // work: only the sandbox holds the write ends / slave now.
    drop(pty_slave.take());
    drop(stdout_w.take());
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
            let domains = match &cfg.net {
                NetMode::Allowlist(d) => d.clone(),
                NetMode::Off => Vec::new(),
            };
            sandbox::linux::net_relay::spawn_broker(fd.into_raw_fd(), domains, bus.clone());
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

    let duration_secs = started.elapsed().as_secs();
    bus.publish(Event::SessionEnded {
        ts: events::types::now(),
        exit_code,
        duration_secs,
    });
    std::thread::sleep(std::time::Duration::from_millis(100)); // let sinks drain

    let snap = stats.snapshot();
    if !cfg.report_formats.is_empty() {
        for p in report::write_reports(&snap, &cfg.report_formats)? {
            eprintln!("vetto: report written: {}", p.display());
        }
    }
    let blocked_total: u64 = snap.blocked_attempts.iter().map(|b| b.count).sum();
    if cfg.ci {
        println!(
            "{}",
            serde_json::json!({
                "vetto_ci": {
                    "exit_code": exit_code,
                    "duration_secs": duration_secs,
                    "tier": tier_label(tier),
                    "net": cfg.net.label(),
                    "profile": pol.name,
                    "blocked_attempts": blocked_total,
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

    let code = if exit_code < 0 { 128 - exit_code } else { exit_code };
    std::process::exit(code);
}

fn tier_label(tier: Option<policy::Tier>) -> &'static str {
    match tier {
        Some(policy::Tier::Full) => policy::Tier::Full.label(),
        Some(policy::Tier::FsOnly) => policy::Tier::FsOnly.label(),
        None => "macos-seatbelt",
    }
}

fn dry_run(
    cfg: &RunConfig,
    pol: &policy::Policy,
    agent_cmd: &[String],
    tier: &str,
) -> Result<()> {
    println!("vetto dry-run — nothing enforced, nothing executed");
    println!("  tier:  {tier}");
    println!("  net:   {}", cfg.net.label());
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
        println!("    {}{}", d.path.display(), if d.is_dir { "/" } else { "" });
    }
    println!("  agent: {}", agent_cmd.join(" "));
    Ok(())
}

fn pipe2() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array; scalar flags.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe2: {}", std::io::Error::last_os_error());
    }
    // SAFETY: fresh descriptors from a successful pipe2.
    Ok((
        unsafe { OwnedFd::from_raw_fd(fds[0]) },
        unsafe { OwnedFd::from_raw_fd(fds[1]) },
    ))
}

fn resolve_in_path(cmd: &str) -> Result<String> {
    if cmd.contains('/') {
        return Ok(cmd.to_string());
    }
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        if dir.is_empty() {
            continue;
        }
        let cand = Path::new(dir).join(cmd);
        if is_executable_file(&cand) {
            return Ok(cand.to_string_lossy().into_owned());
        }
    }
    bail!("agent command '{cmd}' not found in PATH")
}

fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111) != 0,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Ctrl+C forwarding
// ---------------------------------------------------------------------------

static CHILD_TARGET: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn on_sigint(_sig: libc::c_int) {
    let t = CHILD_TARGET.load(std::sync::atomic::Ordering::SeqCst);
    if t != 0 {
        // SAFETY: scalar-only kill; async-signal-safe.
        unsafe { libc::kill(t, libc::SIGINT) };
    }
}

fn install_sigint_forwarder(root_pid: u32, tier: Option<policy::Tier>) {
    let target = match tier {
        Some(policy::Tier::FsOnly) => -(root_pid as i32), // whole process group
        _ => root_pid as i32,
    };
    CHILD_TARGET.store(target, std::sync::atomic::Ordering::SeqCst);
    // SAFETY: registering our extern handler.
    let r = unsafe { libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t) };
    if r == libc::SIG_ERR {
        eprintln!("vetto: warning: could not install SIGINT forwarder");
    }
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

fn doctor(probe_deny: bool) -> Result<()> {
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
        println!("seccomp filters:         {}", yn(p.seccomp_filter_available));
        println!("seccomp user-notify:     {}", yn(p.seccomp_notify_available));
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
    Ok(())
}

/// Build a throwaway sandbox around a probe script and verify every
/// display_only_deny path is truly unreachable from inside.
fn doctor_probe() -> Result<()> {
    println!("probe: building throwaway sandbox with the default profile...");
    let backend = Box::new(sandbox::Backend::detect(NetMode::Off, false)?);
    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME").map(PathBuf::from).context("$HOME not set")?;
    let tier = backend.tier().unwrap_or(policy::Tier::Full);
    let pol = policy::loader::load("default", None, &project, &home, tier)?;
    if pol.deny_resolved.is_empty() {
        println!("probe: no deny paths resolve on this machine (nothing to verify)");
        return Ok(());
    }

    // The probe script reports, per path: dir -> "D|ok|denied" for a listing
    // attempt; file -> "F|bytes|unreadable" for a read attempt. Overlaid
    // files appear EMPTY (0 bytes) — checked against the host size below.
    let script = "for p in \"$@\"; do if [ -d \"$p\" ]; then if ls -A \"$p\" >/dev/null 2>&1; \
                  then echo \"D|$p|ok\"; else echo \"D|$p|denied\"; fi; \
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
            ("D", "denied") => println!("  ✓ {path}/ (listing denied)"),
            ("D", "ok") => {
                println!("  ✗ {path}/ LEAK: directory listing succeeded");
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

fn init() -> Result<()> {
    let path = Path::new("vetto.toml");
    if path.exists() {
        bail!("vetto.toml already exists here");
    }
    std::fs::write(path, policy::defaults::DEFAULT_TOML).with_context(|| "write vetto.toml")?;
    println!("wrote starter policy to vetto.toml (edit allow_write/allow_read, then:)");
    println!("  vetto --policy vetto.toml -- <agent command>");
    Ok(())
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
