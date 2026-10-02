//! vetto — daemon-less sandbox + security layer for AI coding agents.
//!
//! Session wiring order matters and is load-bearing:
//!   1. CLI/config, policy load, stdio plumbing — no threads yet.
//!   2. Backend::detect + spawn: EVERY fork happens here, single-threaded.
//!   3. Only after a successful spawn: event bus consumers (broker, notifier,
//!      audit reader, visibility poller, jsonl, stats) and the UI loop.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

use vetto::config::{NetMode, RunConfig, TuiMode};
use vetto::{
    cli, doctor, events, exit_codes, logger, mcp, policy, profile, sandbox, shim, supervise,
    watchdog,
};

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

fn preprocess_cli_args(raw_args: &[String]) -> Result<Vec<String>> {
    if raw_args.iter().any(|a| a == "--") {
        return Ok(raw_args.to_vec());
    }

    const KNOWN_SUBCOMMANDS: &[&str] = &[
        "mask",
        "enable",
        "disable",
        "allow",
        "deny",
        "doctor",
        "status",
        "kill",
        "verify",
        "verify-ng",
        "run",
        "exec",
        "undo",
        "ephemeral",
        "bench",
        "diff",
        "watchdog",
        "init",
        "profiles",
        "hook",
        "mcp",
        "shim",
        "redteam",
        "policy",
        "completions",
        "man",
        "shell-env",
        "profile",
        "upgrade",
        "scan-secrets",
        "watch",
        "events",
        "audit",
        "digest",
        "diff-sessions",
        "replay",
        "ssh-proxy",
        "__ssh-proxy",
        "help",
        "version",
    ];

    const OPTIONS_WITH_VALUE: &[&str] = &[
        "--profile",
        "--preset",
        "--policy",
        "--net",
        "--tui",
        "--backend",
        "--jsonl",
        "--report",
        "--report-dir",
        "--report-retention",
        "--report-max-age-secs",
        "--otel-endpoint",
        "--timeout",
        "--limits",
        "--agent",
        "--deny-glob",
    ];

    let mut i = 1;
    while i < raw_args.len() {
        let arg = &raw_args[i];
        if arg.starts_with("--") {
            if arg.contains('=') {
                i += 1;
                continue;
            }
            if arg == "--fail-on-block" {
                if let Some(next) = raw_args.get(i + 1) {
                    if next.chars().all(|c| c.is_ascii_digit()) {
                        i += 2;
                        continue;
                    }
                }
                i += 1;
                continue;
            }
            if OPTIONS_WITH_VALUE.contains(&arg.as_str()) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            if arg == "-a" {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if KNOWN_SUBCOMMANDS.contains(&arg.as_str()) {
            return Ok(raw_args.to_vec());
        }

        if let Some(_canon) =
            vetto::policy::defaults::canonical_agent_name(arg).filter(|&c| c != "custom")
        {
            let mut rewritten = raw_args.to_vec();
            rewritten.insert(i, "--".to_string());
            return Ok(rewritten);
        }

        break;
    }

    Ok(raw_args.to_vec())
}

fn run() -> Result<()> {
    // Activation funnel milestone (issue #27): first-ever run. Once-only via
    // marker file; silent unless telemetry is explicitly opted in.
    let _ = vetto::telemetry::record_funnel_milestone("install");

    // Check if invoked via vetto-bench executable alias
    let is_vetto_bench = std::env::args_os().next().is_some_and(|a| {
        std::path::Path::new(&a)
            .file_stem()
            .and_then(|s| s.to_str())
            .is_some_and(|stem| stem.eq_ignore_ascii_case("vetto-bench"))
    });

    if is_vetto_bench {
        let mut rewritten_args = vec!["vetto".to_string(), "bench".to_string()];
        rewritten_args.extend(std::env::args().skip(1));
        let cli = match cli::Cli::try_parse_from(&rewritten_args) {
            Ok(c) => c,
            Err(e) => e.exit(),
        };
        logger::init_flags(cli.quiet, cli.verbose);
        if let Some(cli::Command::Bench(ref bench_args)) = cli.command {
            return cli::bench::execute_bench(bench_args, &cli);
        }
    }

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

    // Apply a previously staged auto-update before doing anything else.
    // Skipped for shims (agent hot path), --version (observation only) and
    // the upgrade command itself (it manages its own lifecycle).
    let first_arg = raw_args.get(1).map(|s| s.as_str()).unwrap_or("");
    if first_arg != "upgrade" {
        match vetto::version::apply_pending_staged_update() {
            Ok(true) => println!("vetto: continuing with the updated binary on next invocation."),
            Ok(false) => {}
            Err(e) => eprintln!("vetto: warning: staged update not applied: {e:#}"),
        }
    }

    let processed_args = preprocess_cli_args(&raw_args)?;
    let args = cli::Cli::parse_from(&processed_args);
    logger::init_flags(args.quiet, args.verbose);
    if args.is_container {
        let env_info = vetto::doctor::detect_environment();
        if env_info.is_container {
            println!("true");
            std::process::exit(0);
        } else {
            println!("false");
            std::process::exit(1);
        }
    }

    match &args.command {
        Some(cli::Command::Mask(mask_args)) => cli::mask::run_mask(mask_args),
        Some(cli::Command::Enable(enable_args)) => cli::enable::run_enable(enable_args),
        Some(cli::Command::Disable(disable_args)) => cli::enable::run_disable(disable_args),
        Some(cli::Command::Run {
            command,
            args: run_args,
            benchmark,
        }) => {
            let mut cfg = RunConfig::from_cli(&args)?;
            if let Some(cmd) = command {
                if let Some(canon) =
                    vetto::policy::defaults::canonical_agent_name(cmd).filter(|&c| c != "custom")
                {
                    if let Ok(shims_dir) =
                        vetto::cli::hook::get_shims_dir(vetto::cli::hook::HookScope::Global)
                    {
                        let shim_path = shims_dir.join(canon);
                        let is_wrapped =
                            shim_path.exists() && vetto::shim::is_vetto_shim_content(&shim_path);
                        if !is_wrapped {
                            let target_agent =
                                if let Ok((bin, _)) = vetto::onboard::find_real_agent_binary(cmd) {
                                    bin
                                } else {
                                    canon.to_string()
                                };
                            let _ = vetto::cli::enable::enable_agent_silent(
                                &target_agent,
                                false,
                                vetto::cli::hook::HookScope::Global,
                            );
                        }
                    }
                }

                let mut full_cmd = vec![cmd.clone()];
                full_cmd.extend(run_args.clone());
                cfg.agent = full_cmd;
                if cfg.agent_preset.is_none() {
                    cfg.agent_preset = vetto::config::detect_agent_preset(&cfg.agent);
                }
                if matches!(cfg.net, NetMode::Off) && args.net.is_none() {
                    if let Some(ref agent) = cfg.agent_preset {
                        let domains = policy::presets::agent_network_allowlist(agent);
                        if !domains.is_empty() {
                            cfg.net = NetMode::Allowlist(domains);
                        }
                    }
                }
                if args.tui.is_none()
                    && cfg.tui == TuiMode::Statusline
                    && vetto::config::should_default_to_no_tui(
                        cfg.agent_preset.as_deref(),
                        &cfg.agent,
                    )
                {
                    cfg.tui = TuiMode::None;
                }
            } else {
                resolve_target_agent(&mut cfg, &args, run_args, true)?;
            }
            if *benchmark || args.benchmark {
                let bench_args = cli::bench::BenchArgs {
                    workspace: None,
                    timeout: cfg.session_timeout.map(|d| d.as_secs()).unwrap_or(180),
                    memory_mb: 4096,
                    net: args.net.clone(),
                    json: false,
                    instance_id: None,
                    profile: "swebench".to_string(),
                    env: vec![],
                    command: cfg.agent.clone(),
                };
                return cli::bench::execute_bench(&bench_args, &args);
            }
            supervise(cfg)
        }

        Some(cli::Command::Doctor {
            probe,
            check_agent,
            fix,
            preflight,
            json,
        }) => {
            if *preflight || *json {
                let report = vetto::doctor::preflight::run_preflight(*json)?;
                if report.verdict == vetto::doctor::preflight::PreflightVerdict::Fail {
                    std::process::exit(vetto::exit_codes::EXIT_FAIL_CLOSED);
                }
                Ok(())
            } else {
                doctor::run_doctor(*probe, check_agent.as_deref(), *fix)
            }
        }
        Some(cli::Command::Undo(undo_args)) => cli::undo::run_undo(undo_args),
        Some(cli::Command::Ephemeral(ephemeral_args)) => {
            let mut cfg = RunConfig::from_cli(&args)?;
            cfg.ephemeral = true;
            cfg.snapshot = true;
            cfg.ephemeral_auto_accept = ephemeral_args.yes;
            cfg.ephemeral_force_discard = ephemeral_args.discard;
            if !ephemeral_args.command.is_empty() {
                cfg.agent = ephemeral_args.command.clone();
                if cfg.agent_preset.is_none() {
                    cfg.agent_preset = vetto::config::detect_agent_preset(&cfg.agent);
                }
                if matches!(cfg.net, NetMode::Off) && args.net.is_none() {
                    if let Some(ref agent) = cfg.agent_preset {
                        let domains = policy::presets::agent_network_allowlist(agent);
                        if !domains.is_empty() {
                            cfg.net = NetMode::Allowlist(domains);
                        }
                    }
                }
            }
            if cfg.agent.is_empty() {
                let project = std::env::current_dir().context("getcwd")?;
                let detected = match vetto::onboard::detect_agent(&project) {
                    Ok(detected) => detected,
                    Err(e) => bail!(
                        "no AI agent detected in {} ({e})\n\n\
                         Usage: vetto ephemeral [OPTIONS] -- <command> [args...]",
                        project.display()
                    ),
                };
                eprintln!(
                    "vetto: zero-config auto-detected agent '{}' ({})",
                    detected.name, detected.reason
                );
                cfg.agent = detected.command;
                if cfg.agent_preset.is_none() {
                    cfg.agent_preset = Some(detected.name.to_string());
                }
                if !cfg.explicit_net && !detected.network_domains.is_empty() {
                    cfg.net = NetMode::Allowlist(detected.network_domains);
                }
            }
            supervise(cfg)
        }
        Some(cli::Command::Bench(bench_args)) => cli::bench::execute_bench(bench_args, &args),
        Some(cli::Command::Diff(args)) => cli::diff::run_diff(args),
        Some(cli::Command::Watchdog(args)) => watchdog::run_cli(args),
        Some(cli::Command::Init { force }) => init(*force),
        Some(cli::Command::Profiles) => profiles(),
        Some(cli::Command::Hook { command }) => cli::hook::run_cli(command),
        Some(cli::Command::Mcp { command }) => match command {
            None | Some(cli::McpCommand::Serve) => mcp::run_stdio_server(),
            Some(cli::McpCommand::Wrap(args)) => mcp::run_wrap(args),
        },
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
        Some(cli::Command::Kill(kill_args)) => cli::kill::run_cli(kill_args),
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
        Some(cli::Command::Allow {
            target,
            preset,
            quota,
            read_only,
            net,
            cidr,
            global,
        }) => vetto::policy::edit::run_allow(
            target.as_deref(),
            preset.as_deref(),
            quota.as_deref(),
            *read_only,
            *net,
            *cidr,
            *global,
            args.policy.as_deref().map(Path::new),
        ),
        Some(cli::Command::Deny {
            target,
            preset,
            glob,
            global,
        }) => vetto::policy::edit::run_deny(
            target.as_deref(),
            preset.as_deref(),
            *glob,
            *global,
            args.policy.as_deref().map(Path::new),
        ),
        Some(cli::Command::Events {
            session,
            filter,
            follow,
            json,
            table: _,
        }) => events::run_events(session, filter.as_deref(), *follow, *json),
        Some(cli::Command::Audit {
            session_id,
            latest,
            since,
            agent,
            limit,
            query,
            json,
            recap,
            digest,
        }) => {
            if *digest {
                vetto::audit::run_digest(since.as_deref(), *json)
            } else {
                vetto::audit::run_audit_command(
                    session_id.as_deref(),
                    *latest,
                    since.as_deref(),
                    agent.as_deref(),
                    *limit,
                    query.as_deref(),
                    *json,
                    *recap,
                )
            }
        }
        Some(cli::Command::Digest { since, json }) => vetto::audit::run_digest(Some(since), *json),
        Some(cli::Command::DiffSessions {
            session_a,
            session_b,
            json,
        }) => {
            let reports_dir = args
                .report_dir
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".vetto/reports"));
            let diff =
                vetto::audit::diff_sessions::compare_sessions(session_a, session_b, &reports_dir)?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                print!("{}", vetto::audit::diff_sessions::format_diff_text(&diff));
            }
            Ok(())
        }
        Some(cli::Command::Replay {
            session,
            speed,
            json,
        }) => events::run_replay(session, *speed, *json),
        Some(cli::Command::Verify { json }) => {
            let net = vetto::config::parse_net_mode(args.net.as_deref().unwrap_or("off"))?;
            vetto::verify::run_cli(
                *json,
                &args.profile,
                args.policy.as_deref().map(PathBuf::from).as_deref(),
                &net,
            )
        }
        Some(cli::Command::VerifyNg { json, lint }) => {
            vetto::verify_ng::run_verify_ng(*json, *lint)
        }
        Some(cli::Command::Redteam { json }) => {
            let report = vetto::redteam::run_redteam_battery();
            if *json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("vetto redteam — isolation & containment attack battery\n");
                for r in &report.results {
                    println!("[{:?}] #{}: {} — {}", r.status, r.id, r.name, r.description);
                    println!("       detail: {}", r.details);
                }
                println!("\n{}", report.summary());
            }
            if !report.success {
                std::process::exit(1);
            }
            Ok(())
        }
        Some(cli::Command::Policy { command }) => match command {
            cli::PolicyCommand::Explain { json, why, limits } => {
                let net = vetto::config::parse_net_mode(args.net.as_deref().unwrap_or("off"))?;
                let effective_limits = limits.as_deref().or(args.limits.as_deref());
                let detected = sandbox::Backend::detect(net.clone(), false).ok();
                let backend = vetto::policy::explain::ExplainBackend {
                    tier: detected.as_ref().and_then(|b| b.tier()),
                    backend_desc: detected.as_ref().map(|b| b.describe()),
                    observes_seccomp: detected
                        .as_ref()
                        .map(|b| b.observes_seccomp())
                        .unwrap_or(false),
                };
                vetto::policy::explain::run_cli(
                    *json,
                    why.as_deref(),
                    &args.profile,
                    args.policy.as_deref().map(PathBuf::from).as_deref(),
                    &net,
                    effective_limits,
                    backend,
                )
            }
            cli::PolicyCommand::Show { effective, json } => {
                let net = vetto::config::parse_net_mode(args.net.as_deref().unwrap_or("off"))?;
                let detected = sandbox::Backend::detect(net.clone(), false).ok();
                let backend = vetto::policy::explain::ExplainBackend {
                    tier: detected.as_ref().and_then(|b| b.tier()),
                    backend_desc: detected.as_ref().map(|b| b.describe()),
                    observes_seccomp: detected
                        .as_ref()
                        .map(|b| b.observes_seccomp())
                        .unwrap_or(false),
                };
                vetto::policy::explain::run_show(
                    *effective,
                    *json,
                    &args.profile,
                    args.policy.as_deref().map(PathBuf::from).as_deref(),
                    &net,
                    backend,
                )
            }
            cli::PolicyCommand::Lint { strict } => {
                let tier = sandbox::Backend::detect(NetMode::Off, false)
                    .ok()
                    .and_then(|b| b.tier());
                vetto::policy::lint::run_cli(
                    *strict,
                    &args.profile,
                    args.policy.as_deref().map(PathBuf::from).as_deref(),
                    tier,
                )
            }
            cli::PolicyCommand::Import {
                from,
                path,
                claude,
                codex,
                output,
            } => {
                let home = std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(PathBuf::from)
                    .context(
                        "neither HOME nor USERPROFILE is set; vetto needs it to resolve paths",
                    )?;
                let effective_claude = claude.as_deref().or_else(|| {
                    if from.as_deref() == Some("claude") {
                        path.as_deref()
                    } else {
                        None
                    }
                });
                let effective_codex = codex.as_deref().or_else(|| {
                    if from.as_deref() == Some("codex") {
                        path.as_deref()
                    } else {
                        None
                    }
                });
                vetto::policy::import::run_import(
                    effective_claude,
                    effective_codex,
                    output,
                    &home,
                )?;
                println!("vetto: imported policy written to {}", output.display());
                Ok(())
            }
            cli::PolicyCommand::Sign { file, key, out } => {
                let sig_path =
                    policy::crypto::sign_policy_file(file, key.as_deref(), out.as_deref())?;
                println!(
                    "Successfully signed policy file {} -> {}",
                    file.display(),
                    sig_path.display()
                );
                Ok(())
            }
            cli::PolicyCommand::Verify { file, sig, key } => {
                policy::crypto::verify_policy_file(file, sig.as_deref(), key.as_deref())?;
                println!(
                    "Policy cryptographic verification SUCCESS for {}",
                    file.display()
                );
                Ok(())
            }
            cli::PolicyCommand::Use { name, force } => {
                let project = std::env::current_dir().context("getcwd")?;
                let path = policy::community::install_community_policy(name, &project, *force)?;
                println!(
                    "Installed community policy '{}' into {}",
                    name,
                    path.display()
                );
                Ok(())
            }
            cli::PolicyCommand::List => {
                println!("Available community policies in registry:");
                for (name, desc) in policy::community::list_community_policies() {
                    println!("  {:16} {}", name, desc);
                }
                Ok(())
            }
        },
        Some(cli::Command::Completions { shell }) => cli::print_completions(*shell),
        Some(cli::Command::Man) => cli::print_man(),
        Some(cli::Command::Upgrade {
            channel,
            check,
            dry_run,
            rollback,
        }) => {
            if *rollback {
                vetto::version::run_rollback(*dry_run)
            } else {
                vetto::version::run_upgrade(channel.as_deref(), *check, *dry_run)
            }
        }
        Some(cli::Command::ScanSecrets {
            path,
            json,
            max_size,
            max_files,
        }) => scan_secrets_cli(path.as_deref(), *json, *max_size, *max_files),
        Some(cli::Command::Watch { target, path, json }) => {
            vetto::watch::run_watch(target, path.as_deref(), *json)
        }
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
            if !profile_loaded {
                resolve_target_agent(&mut cfg, &args, &[], false)?;
            }
            if args.tui.is_none()
                && cfg.tui == TuiMode::Statusline
                && vetto::config::should_default_to_no_tui(cfg.agent_preset.as_deref(), &cfg.agent)
            {
                cfg.tui = TuiMode::None;
            }
            if args.benchmark {
                let bench_args = cli::bench::BenchArgs {
                    workspace: None,
                    timeout: cfg.session_timeout.map(|d| d.as_secs()).unwrap_or(180),
                    memory_mb: 4096,
                    net: args.net.clone(),
                    json: false,
                    instance_id: None,
                    profile: "swebench".to_string(),
                    env: vec![],
                    command: cfg.agent.clone(),
                };
                return cli::bench::execute_bench(&bench_args, &args);
            }
            supervise(cfg)
        }
    }
}

fn resolve_target_agent(
    cfg: &mut RunConfig,
    args: &cli::Cli,
    extra_args: &[String],
    is_run_subcommand: bool,
) -> Result<()> {
    if !cfg.agent.is_empty() && !cfg.agent[0].starts_with('-') {
        return Ok(());
    }

    if let Some(ref agent_name) = cfg.agent_preset.clone() {
        let (bin, _path) = vetto::onboard::find_real_agent_binary(agent_name)?;
        if cfg.agent.is_empty() {
            cfg.agent = vec![bin];
            cfg.agent.extend(extra_args.iter().cloned());
        } else {
            cfg.agent.insert(0, bin);
        }
        if !cfg.explicit_net {
            let domains = policy::presets::agent_network_allowlist(agent_name);
            if !domains.is_empty() {
                cfg.net = NetMode::Allowlist(domains);
            }
        }
        if args.tui.is_none()
            && cfg.tui == TuiMode::Statusline
            && vetto::config::should_default_to_no_tui(Some(agent_name.as_str()), &cfg.agent)
        {
            cfg.tui = TuiMode::None;
        }
        let canon = vetto::policy::defaults::canonical_agent_name(agent_name).unwrap_or(agent_name);
        if let Ok(shims_dir) = vetto::cli::hook::get_shims_dir(vetto::cli::hook::HookScope::Global)
        {
            let shim_path = shims_dir.join(canon);
            let is_wrapped = shim_path.exists() && vetto::shim::is_vetto_shim_content(&shim_path);
            if !is_wrapped {
                let _ = vetto::cli::enable::enable_agent_silent(
                    canon,
                    false,
                    vetto::cli::hook::HookScope::Global,
                );
            }
        }
        return Ok(());
    }

    let project = std::env::current_dir().context("getcwd")?;
    let detected = match vetto::onboard::detect_agent(&project) {
        Ok(detected) => detected,
        Err(e) => {
            let guidance = if is_run_subcommand {
                "1. `vetto enable` — wrap installed agents (e.g. `vetto enable claude`)\n  \
                 2. `vetto run <command>` — e.g. `vetto run claude` or `vetto run -- python agent.py`\n  \
                 3. `vetto doctor` — see what this kernel can enforce\n\n\
                 Docs: https://shleder.github.io/vetto/"
            } else {
                "1. `vetto enable` — wrap installed agents (e.g. `vetto enable claude`)\n  \
                 2. `vetto doctor` — see what this kernel can enforce\n  \
                 3. `vetto -- <command>` — sandbox any binary, e.g. `vetto -- python agent.py`\n\n\
                 Docs: https://shleder.github.io/vetto/"
            };
            bail!("{e}\n\nGet started:\n  {guidance}");
        }
    };
    eprintln!(
        "vetto: zero-config auto-detected agent '{}' ({})",
        detected.name, detected.reason
    );
    cfg.agent = detected.command;
    cfg.agent.extend(extra_args.iter().cloned());
    cfg.agent_preset = Some(detected.name.to_string());
    if !cfg.explicit_net && !detected.network_domains.is_empty() {
        cfg.net = NetMode::Allowlist(detected.network_domains);
    }
    if args.tui.is_none()
        && cfg.tui == TuiMode::Statusline
        && vetto::config::should_default_to_no_tui(cfg.agent_preset.as_deref(), &cfg.agent)
    {
        cfg.tui = TuiMode::None;
    }
    if let Ok(shims_dir) = vetto::cli::hook::get_shims_dir(vetto::cli::hook::HookScope::Global) {
        let shim_path = shims_dir.join(detected.name);
        let is_wrapped = shim_path.exists() && vetto::shim::is_vetto_shim_content(&shim_path);
        if !is_wrapped {
            let _ = vetto::cli::enable::enable_agent_silent(
                detected.name,
                false,
                vetto::cli::hook::HookScope::Global,
            );
        }
    }
    Ok(())
}

fn scan_secrets_cli(
    path: Option<&Path>,
    json: bool,
    max_size: Option<u64>,
    max_files: Option<usize>,
) -> Result<()> {
    let target = path.unwrap_or(Path::new("."));
    let mut options = policy::secretscan::SecretScanOptions::default();
    if let Some(ms) = max_size {
        options.max_file_size_bytes = ms;
    }
    if let Some(mf) = max_files {
        options.max_files = mf;
    }

    let result = if target.is_file() {
        let findings = policy::secretscan::scan_file(target, options.max_file_size_bytes);
        let bytes_scanned = std::fs::metadata(target).map(|m| m.len()).unwrap_or(0);
        policy::secretscan::SecretScanResult {
            findings,
            files_scanned: 1,
            bytes_scanned,
            timed_out: false,
        }
    } else {
        policy::secretscan::scan_directory(target, &options)
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "vetto scan-secrets: scanned {} file(s) ({} bytes)",
            result.files_scanned, result.bytes_scanned
        );
        if result.timed_out {
            println!("warning: scan hit time or file limit; partial results shown");
        }
        if result.is_clean() {
            println!("clean: no secrets detected");
        } else {
            println!("findings ({}):", result.findings.len());
            for f in &result.findings {
                println!(
                    "  - {}:{} [{}] {}",
                    f.path.display(),
                    f.line,
                    f.rule,
                    f.preview
                );
            }
        }
    }

    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    if !result.is_clean() {
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// supervise: a sandboxed agent session
// ---------------------------------------------------------------------------

fn supervise(cfg: RunConfig) -> Result<()> {
    match vetto::supervise::supervise(cfg) {
        Ok(verdict) => std::process::exit(verdict.final_exit_code),
        Err(err) => {
            eprintln!("vetto: error: {err}");
            std::process::exit(err.exit_code());
        }
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
