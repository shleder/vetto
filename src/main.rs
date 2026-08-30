//! vetto — daemon-less sandbox + security layer for AI coding agents.
//!
//! Session wiring order matters and is load-bearing:
//!   1. CLI/config, policy load, stdio plumbing — no threads yet.
//!   2. Backend::detect + spawn: EVERY fork happens here, single-threaded.
//!   3. Only after a successful spawn: event bus consumers (broker, notifier,
//!      audit reader, visibility poller, jsonl, stats) and the UI loop.

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::os::fd::IntoRawFd;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

use vetto::config::{NetMode, RunConfig, TuiMode};
use vetto::events::{Event, EventBus};
use vetto::{
    cli, events, exit_codes, history, logger, multi, policy, profile, report, rescue, sandbox, shim,
};
#[cfg(unix)]
use vetto::{pty, tui};

fn main() {
    if let Err(err) = run() {
        eprintln!("vetto: error: {err}");
        let code = exit_codes::map_error_to_exit_code(&err);
        std::process::exit(code);
    }
}

fn fast_tier_detect() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        let p = sandbox::linux::probe();
        match sandbox::linux::pick_tier(&p) {
            Ok(t) => t.label(),
            Err(_) => "none",
        }
    }
    #[cfg(target_os = "macos")]
    {
        "macos-seatbelt"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-sandbox"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "none"
    }
}

fn run() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();
    let has_version = raw_args.iter().any(|a| a == "--version" || a == "-V");
    let has_json = raw_args.iter().any(|a| a == "--json");
    if has_version && has_json {
        let commit = option_env!("VETTO_GIT_HASH").unwrap_or("unknown");
        println!(
            "{}",
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "tier": fast_tier_detect(),
                "commit": commit,
            })
        );
        return Ok(());
    }

    // Fast path: if invoked via a toolchain shim name (e.g. `node`, `git`), dispatch immediately
    if let Some(binary) = shim::detect_argv0_shim() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        return shim::run_cli(Some(binary), args);
    }

    let args = cli::Cli::parse();
    logger::init_flags(args.quiet, args.verbose);

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
        Some(cli::Command::Doctor {
            probe,
            check_agent,
            fix,
        }) => doctor(*probe, check_agent.as_deref(), *fix),
        Some(cli::Command::Init { force, wizard }) => init(*force, *wizard),
        Some(cli::Command::Profiles) => profiles(),
        Some(cli::Command::Hook { command }) => cli::hook::run_cli(command),
        Some(cli::Command::Shim { binary, args }) => shim::run_cli(binary.clone(), args.clone()),
        Some(cli::Command::ShellEnv {
            session_id,
            tier,
            profile,
        }) => cli::shell_env::run_shell_env(
            session_id.as_deref(),
            tier.as_deref(),
            profile.as_deref(),
        ),
        Some(cli::Command::Status { json }) => cli::status::run_cli(*json),
        Some(cli::Command::Profile { command }) => match command {
            cli::ProfileCommand::Save {
                name,
                agent,
                policy,
                net,
                profile,
            } => {
                let agent_vec = agent.as_ref().map(|a| vec![a.clone()]).unwrap_or_default();
                profile::save_profile(
                    name,
                    agent_vec,
                    policy.clone(),
                    net.clone(),
                    profile.clone(),
                )
            }
            cli::ProfileCommand::List { json } => profile::list_profiles(*json),
            cli::ProfileCommand::Rm { name } => profile::remove_profile(name),
        },
        Some(cli::Command::WhySlow { session, json }) => cli::why_slow::run_cli(session, *json),
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
        Some(cli::Command::Verify { json }) => {
            let net = vetto::config::parse_net_mode(args.net.as_deref().unwrap_or("off"))?;
            vetto::verify::run_cli(
                *json,
                &args.profile,
                args.policy.as_deref().map(PathBuf::from).as_deref(),
                &net,
            )
        }
        Some(cli::Command::Policy { command }) => match command {
            cli::PolicyCommand::Explain { json, why } => {
                let net = vetto::config::parse_net_mode(args.net.as_deref().unwrap_or("off"))?;
                vetto::policy::explain::run_cli(
                    *json,
                    why.as_deref(),
                    &args.profile,
                    args.policy.as_deref().map(PathBuf::from).as_deref(),
                    &net,
                )
            }
            cli::PolicyCommand::Show { effective, json } => {
                let net = vetto::config::parse_net_mode(args.net.as_deref().unwrap_or("off"))?;
                vetto::policy::explain::run_show(
                    *effective,
                    *json,
                    &args.profile,
                    args.policy.as_deref().map(PathBuf::from).as_deref(),
                    &net,
                )
            }
            cli::PolicyCommand::Lint { strict } => vetto::policy::lint::run_cli(
                *strict,
                &args.profile,
                args.policy.as_deref().map(PathBuf::from).as_deref(),
            ),
            cli::PolicyCommand::Import { from, path, output } => {
                let home = std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(PathBuf::from)
                    .context(
                        "neither HOME nor USERPROFILE is set; vetto needs it to resolve paths",
                    )?;
                vetto::policy::import::import_policy(from, path.as_deref(), output, &home)?;
                println!("vetto: imported policy written to {}", output.display());
                Ok(())
            }
        },
        Some(cli::Command::Completions { shell }) => cli::print_completions(*shell),
        Some(cli::Command::Man) => cli::print_man(),
        Some(cli::Command::Upgrade {
            channel,
            check,
            dry_run,
        }) => vetto::version::run_upgrade(channel.as_deref(), *check, *dry_run),
        Some(cli::Command::Tour { non_interactive }) => vetto::tour::run_tour(*non_interactive),
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
        Some(cli::Command::External(ext_args)) => {
            if let Some(prof_name) = ext_args.first() {
                let storage = profile::ProfileStorage::new()?;
                let prof = storage.load(prof_name)?;
                let mut cfg = RunConfig::from_cli(&args)?;
                cfg.agent = prof.agent;
                cfg.net = vetto::config::parse_net_mode(&prof.net)?;
                if cfg.policy_path.is_none() {
                    cfg.policy_path = prof.policy_path;
                }
                let _ = std::env::set_current_dir(&prof.cwd);
                supervise(cfg)
            } else {
                bail!("no command provided");
            }
        }
        None => {
            let mut cfg = RunConfig::from_cli(&args)?;
            let mut profile_loaded = false;
            if cfg.agent.is_empty() && args.profile != "default" {
                if let Ok(storage) = profile::ProfileStorage::new() {
                    if let Ok(prof) = storage.load(&args.profile) {
                        cfg.agent = prof.agent;
                        cfg.net = vetto::config::parse_net_mode(&prof.net)?;
                        if cfg.policy_path.is_none() {
                            cfg.policy_path = prof.policy_path;
                        }
                        let _ = std::env::set_current_dir(&prof.cwd);
                        profile_loaded = true;
                    }
                }
            }
            if cfg.agent.is_empty() && !profile_loaded {
                let project = std::env::current_dir().context("getcwd")?;
                let detected = vetto::onboard::detect_agent(&project)?;
                eprintln!(
                    "vetto: zero-config auto-detected agent '{}' ({})",
                    detected.name, detected.reason
                );
                cfg.agent = detected.command;
                if cfg.agent_preset.is_none() {
                    cfg.agent_preset = Some(detected.name.to_string());
                }
                if matches!(cfg.net, NetMode::Off) && !detected.network_domains.is_empty() {
                    cfg.net = NetMode::Allowlist(detected.network_domains);
                }
            }
            supervise(cfg)
        }
    }
}

// ---------------------------------------------------------------------------
// supervise: a sandboxed agent session
// ---------------------------------------------------------------------------

fn supervise(cfg: RunConfig) -> Result<()> {
    if cfg.agent.is_empty() {
        bail!("no agent command provided; usage: vetto [OPTIONS] -- <command> [args...]");
    }

    let user_config = vetto::version::load_user_config().unwrap_or_default();
    vetto::version::print_banner_if_update_available(
        env!("CARGO_PKG_VERSION"),
        &user_config.channel,
    );

    // ---- Phase 1: single-threaded (forks happen in detect/spawn) ----------
    let backend_opt = sandbox::Backend::detect(cfg.net.clone(), cfg.observe_seccomp).ok();
    let tier = backend_opt.as_ref().and_then(|b| b.tier());

    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context(
            "neither $HOME nor %USERPROFILE% is set; vetto needs it to resolve policy variables",
        )?;

    let tier_for_policy = match tier {
        Some(t) => t,
        None => policy::Tier::Full, // macOS: no FS-ONLY enumeration semantics
    };
    let policy_options = policy::loader::PolicyLoadOptions {
        agent: cfg.agent_preset.clone(),
        preset: cfg.preset,
        include_project_policy: true,
        ..policy::loader::PolicyLoadOptions::default()
    };
    let mut pol = policy::loader::load_with_options(
        &cfg.profile,
        cfg.policy_path.as_deref(),
        &project,
        &home,
        tier_for_policy,
        &policy_options,
    )?;
    if tier == Some(policy::Tier::FsOnly) && !pol.deny_resolved.is_empty() {
        pol.warnings.push(
            "fs-only tier: display_only_deny paths cannot be masked with mount \
             overlays here. They are carved out of the read allowlist instead: \
             directory entry NAMES may stay visible (content stays denied), and \
             a file created directly at a write root cannot be read back in this \
             session because read is stripped from write-root rules to keep \
             carved-out secrets unreadable. Prefer the full tier if either \
             property matters for this session."
                .to_string(),
        );
    }
    if let Some(spec) = &cfg.limits_spec {
        policy::limits_spec::apply_cli(&mut pol, spec)?;
    }
    use std::io::Write;
    for w in &pol.warnings {
        eprint!("vetto: policy warning: {w}\r\n");
    }
    let _ = std::io::stderr().flush();
    let _ = std::io::stdout().flush();

    // execve does not search PATH; resolve the agent binary ourselves.
    let mut agent_cmd = cfg.agent.clone();
    agent_cmd[0] = resolve_in_path(&agent_cmd[0])?;
    let bin_path = std::path::PathBuf::from(&agent_cmd[0]);
    if let Some(parent) = bin_path.parent() {
        if !pol.in_read_scope(&bin_path) {
            pol.allow_read.push(parent.to_path_buf());
        }
    }
    if pol.in_write_scope(std::path::Path::new(&agent_cmd[0])) {
        // If binary is in write scope (e.g. running from HOME), protect it automatically by excluding from writes
        pol.deny_write.push(bin_path.clone());
    }

    if cfg.dry_run {
        return dry_run(&cfg, &pol, &agent_cmd, tier_label(tier));
    }

    let backend = match backend_opt {
        Some(b) => Box::new(b),
        None => Box::new(sandbox::Backend::detect(
            cfg.net.clone(),
            cfg.observe_seccomp,
        )?),
    };
    tracing::debug!("backend: {}", backend.describe());

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

    // Optional pre-spawn boundary verification. A leak here is a policy or
    // kernel problem, not an agent problem: fail before the agent starts.
    let verify_outcome = if cfg.verify_preflight {
        let report = vetto::verify::preflight(&pol, &cfg.net)?;
        eprintln!("vetto: verify: {}", report.summary());
        if report.leaks() > 0 {
            if cfg.shadow {
                eprintln!(
                    "vetto: shadow: would deny session startup due to boundary verification leaks (shadow mode active; continuing)"
                );
            } else {
                bail!(
                    "--verify: boundary verification failed; refusing to start the agent (fail-closed)"
                );
            }
        }
        Some(report)
    } else {
        None
    };

    let session_id = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );

    let env_extra: HashMap<String, String> = {
        let mut env_extra = HashMap::new();
        env_extra.insert("VETTO_SANDBOX".into(), "1".into());
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
                let exe =
                    std::env::current_exe().context("resolve vetto executable for SSH helper")?;
                env_extra.insert(
                    "GIT_SSH_COMMAND".into(),
                    sandbox::linux::net_relay::build_git_ssh_command(&exe),
                );
            }
        }
        env_extra
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

    if let Ok(reg) = cli::status::SessionRegistry::new() {
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

    if cfg.system_log || pol.system_log {
        logger::system_log::SystemLogSink::spawn(&bus);
    }

    if cfg.auto_timeout_requested {
        if let Some(t) = cfg.session_timeout {
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: format!("auto-timeout selected: {}", format_duration(t)),
            });
        } else {
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: "no past history found for agent; running without timeout".to_string(),
            });
        }
    }

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
            if tier == Some(policy::Tier::FsOnly) && !pol.deny_resolved.is_empty() {
                bus.publish(Event::Notice {
                    ts: events::types::now(),
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
        if let Some(fd) = broker_ctrl_fd {
            let broker_policy = match &cfg.net {
                NetMode::Allowlist(d) => {
                    sandbox::linux::net_relay::BrokerPolicy::Allowlist(d.clone())
                }
                NetMode::Strict(rules) => {
                    sandbox::linux::net_relay::BrokerPolicy::Strict(rules.clone())
                }
                NetMode::Ask => sandbox::linux::net_relay::BrokerPolicy::Ask,
                NetMode::Off => sandbox::linux::net_relay::BrokerPolicy::Allowlist(Vec::new()),
            };
            let mut broker_config = sandbox::linux::net_relay::BrokerConfig::from(broker_policy);
            broker_config.allow_cidr = pol.allow_cidr.clone();
            broker_config.quotas = pol.net_quota.clone();
            sandbox::linux::net_relay::spawn_broker(fd.into_raw_fd(), broker_config, bus.clone());
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
    }

    install_sigint_forwarder(root_pid, tier);

    if cfg.session_timeout.is_some() && cfg.tui != TuiMode::None {
        bus.publish(Event::Notice {
            ts: events::types::now(),
            message: "--timeout is enforced only with --tui=none; this TUI mode \
                      owns its own wait loop and ignores it"
                .to_string(),
        });
    }

    // ---- Phase 3: run the UI / wait ---------------------------------------
    #[cfg(unix)]
    let (exit_code, timed_out) = match cfg.tui {
        TuiMode::Statusline => {
            let master = pty_master.expect("statusline wires a pty");
            (
                tui::statusline::run(
                    &bus,
                    &master,
                    handle,
                    tier_label(tier),
                    &cfg.net.label(),
                    &pol.name,
                ),
                false,
            )
        }
        TuiMode::Full => {
            let out = stdout_r.expect("full mode wires stdout pipe");
            let err = stderr_r.expect("full mode wires stderr pipe");
            (
                tui::full::run(
                    &bus,
                    out,
                    err,
                    handle,
                    tier_label(tier),
                    &cfg.net.label(),
                    &pol.name,
                ),
                false,
            )
        }
        TuiMode::None => match cfg.session_timeout {
            Some(limit) => wait_with_timeout(&mut handle, &bus, limit),
            None => (handle.wait(), false),
        },
    };
    #[cfg(windows)]
    let (exit_code, timed_out) = match cfg.session_timeout {
        Some(limit) => wait_with_timeout(&mut handle, &bus, limit),
        None => (handle.wait(), false),
    };

    let duration_secs = started.elapsed().as_secs();
    bus.publish(Event::SessionEnded {
        ts: events::types::now(),
        exit_code,
        duration_secs,
    });
    std::thread::sleep(std::time::Duration::from_millis(100)); // let sinks drain

    let snap = stats.snapshot();
    let _ = vetto::telemetry::send_session_telemetry(&snap, tier_label(tier));
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
    if let Ok(reg) = cli::status::SessionRegistry::new() {
        reg.unregister(&session_id);
    }
    let agent_name = cfg
        .agent_preset
        .clone()
        .unwrap_or_else(|| cfg.agent[0].clone());
    let _ = history::append_session_history(
        &project,
        &history::SessionHistoryRecord {
            agent: agent_name,
            duration_secs,
            ts: events::types::now().to_rfc3339(),
            exit_code,
        },
    );

    let blocked_file_total: u64 = snap.blocked_attempts.iter().map(|b| b.count).sum();
    let blocked_network_total = snap
        .net_requests
        .iter()
        .filter(|request| !request.allowed)
        .count() as u64;
    let blocked_total = blocked_file_total.saturating_add(blocked_network_total);

    let blocked_threshold_reached = match cfg.fail_on_block {
        Some(threshold) => blocked_total >= threshold,
        None => false,
    };
    if timed_out {
        // Mirror GNU timeout(1): 124 means "we killed it at the deadline".
        eprintln!("vetto: session timed out; killed at the deadline (exit 124)");
    }
    if let Some(threshold) = cfg.fail_on_block {
        if blocked_total >= threshold {
            if cfg.shadow {
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

    let code = exit_codes::map_session_exit_code(
        exit_code,
        timed_out,
        blocked_threshold_reached && !cfg.shadow,
    );
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
                    "verify": verify_outcome
                        .map(|report| report.status().to_string())
                        .unwrap_or_else(|| "off".to_string()),
                    "timed_out": timed_out,
                    "sanitizer": "BEST-EFFORT",
                }
            })
        );
    } else {
        eprintln!(
            "vetto: agent exited {} after {}s (blocked={}, events={}, tier={}{})",
            exit_code,
            duration_secs,
            blocked_total,
            snap.events_total,
            tier_label(tier),
            if timed_out { ", TIMEOUT" } else { "" },
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

/// Wait for the sandboxed session with a hard deadline. Returns the child
/// exit code plus a flag telling whether vetto tore the sandbox down at the
/// deadline (exit code 124 mirrors GNU timeout(1)). Teardown goes through
/// `SandboxHandle::terminate`, so every platform reuses its own kill strategy.
fn wait_with_timeout(
    handle: &mut sandbox::SandboxHandle,
    bus: &EventBus,
    limit: std::time::Duration,
) -> (i32, bool) {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if let Some(code) = handle.try_wait() {
            return (code, false);
        }
        if std::time::Instant::now() >= deadline {
            eprintln!(
                "vetto: session timeout ({}) reached; terminating the sandbox",
                format_duration(limit)
            );
            bus.publish(Event::SessionTimeout {
                ts: events::types::now(),
            });
            handle.terminate();
            let code = handle.wait();
            return (code, true);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn format_duration(limit: std::time::Duration) -> String {
    let secs = limit.as_secs();
    if secs % 3600 == 0 && secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 && secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

fn dry_run(cfg: &RunConfig, pol: &policy::Policy, agent_cmd: &[String], tier: &str) -> Result<()> {
    println!("vetto dry-run — nothing enforced, nothing executed");
    println!("  tier:  {tier}");
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

fn doctor(probe_deny: bool, check_agent: Option<&str>, fix: bool) -> Result<()> {
    println!("vetto v{} doctor", env!("CARGO_PKG_VERSION"));
    let user_config = vetto::version::load_user_config().unwrap_or_default();
    if let Some(notice) =
        vetto::version::check_version(env!("CARGO_PKG_VERSION"), &user_config.channel, false)
    {
        println!("update available:        {}", notice.banner_message());
    }
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
        if fix {
            let fixes = vetto::doctor::fix::collect_linux_fixes(&p);
            vetto::doctor::print_fixes(&fixes);
        }
        if let Some(abi) = p.landlock_abi {
            for hint in sandbox::linux::landlock::abi_feature_hints(abi) {
                println!("  note: {hint}");
            }
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
        if fix {
            vetto::doctor::print_fixes(&[]);
        }
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
        if fix {
            vetto::doctor::print_fixes(&[]);
        }
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
/// display_only_deny path is truly unreachable from inside. The spawn
/// machinery lives in `doctor::probe`; this prints the per-path verdicts.
#[cfg(unix)]
fn doctor_probe() -> Result<()> {
    println!("probe: building throwaway sandbox with the default profile...");
    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("neither $HOME nor %USERPROFILE% is set")?;
    let tier = sandbox::Backend::detect(NetMode::Off, false)?
        .tier()
        .unwrap_or(policy::Tier::Full);
    let pol = policy::loader::load("default", None, &project, &home, tier)?;
    if pol.deny_resolved.is_empty() {
        println!("probe: no deny paths resolve on this machine (nothing to verify)");
        return Ok(());
    }

    let script_args: Vec<String> = pol
        .deny_resolved
        .iter()
        .map(|d| d.path.display().to_string())
        .collect();
    let output = vetto::doctor::run_probe_script(&pol, &project, script_args)?;

    let mut failures = 0usize;
    for line in output.stdout.lines() {
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
    if !output.stderr.trim().is_empty() {
        println!("  (probe stderr: {})", output.stderr.trim());
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

fn init(force: bool, wizard: bool) -> Result<()> {
    vetto::init::run_init(Path::new("."), force, wizard)
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
