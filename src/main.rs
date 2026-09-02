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
    cli, daemon, events, exit_codes, history, logger, mcp, multi, policy, profile, remote, report,
    rescue, sandbox, shim, watchdog,
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

    if let Some(remote_url) = &args.remote {
        return remote::run_remote_client(
            remote_url,
            args.agent.clone(),
            args.policy.clone(),
            args.net.clone(),
        );
    }

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
        Some(cli::Command::Enable(enable_args)) => cli::enable::run_enable(enable_args),
        Some(cli::Command::Disable(disable_args)) => cli::enable::run_disable(disable_args),
        Some(cli::Command::Run {
            command,
            args: run_args,
        }) => {
            let mut cfg = RunConfig::from_cli(&args)?;
            if let Some(cmd) = command {
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
            }
            supervise(cfg)
        }

        Some(cli::Command::Doctor {
            probe,
            check_agent,
            fix,
        }) => doctor(*probe, check_agent.as_deref(), *fix),
        Some(cli::Command::Wizard(args)) => cli::wizard::run_wizard_cli(args),
        Some(cli::Command::Undo(undo_args)) => cli::undo::run_undo(undo_args),
        Some(cli::Command::Watchdog(args)) => watchdog::run_cli(args),
        Some(cli::Command::Init { force, wizard }) => {
            if *wizard {
                cli::wizard::run_wizard_cli(&cli::wizard::WizardArgs {
                    path: ".".to_string(),
                    yes: false,
                    force: *force,
                    preset: None,
                    agent: None,
                })
            } else {
                init(*force, *wizard)
            }
        }
        Some(cli::Command::Profiles) => profiles(),
        Some(cli::Command::Hook { command }) => cli::hook::run_cli(command),
        Some(cli::Command::Plugin { command }) => cli::plugin::run_cli(command),
        Some(cli::Command::Mcp { command }) => match command {
            None | Some(cli::McpCommand::Serve) => mcp::run_stdio_server(),
            Some(cli::McpCommand::Wrap(args)) => mcp::run_wrap(args),
        },
        Some(cli::Command::Daemon { command }) => daemon::run_cli(command),
        Some(cli::Command::Serve { port }) => remote::run_serve(*port),
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
        Some(cli::Command::Allow {
            target,
            read_only,
            net,
            global,
        }) => vetto::policy::edit::run_allow(target, *read_only, *net, *global),
        Some(cli::Command::Deny { target, global }) => {
            vetto::policy::edit::run_deny(target, *global)
        }
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
        }) => vetto::audit::run_audit_command(
            session_id.as_deref(),
            *latest,
            since.as_deref(),
            agent.as_deref(),
            *limit,
            query.as_deref(),
            *json,
        ),
        Some(cli::Command::Digest { since, json }) => vetto::audit::run_digest(Some(since), *json),
        Some(cli::Command::DiffSessions {
            session1,
            session2,
            json,
        }) => report::run_diff_sessions(session1, session2, *json),
        Some(cli::Command::Replay {
            session,
            speed,
            json,
        }) => events::run_replay(session, *speed, *json),
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
        }) => vetto::version::run_upgrade(channel.as_deref(), *check, *dry_run),
        Some(cli::Command::Tour { non_interactive }) => vetto::tour::run_tour(*non_interactive),
        Some(cli::Command::ScanSecrets {
            path,
            json,
            max_size,
            max_files,
        }) => scan_secrets_cli(path.as_deref(), *json, *max_size, *max_files),
        Some(cli::Command::Watch { target, path, json }) => {
            vetto::watch::run_watch(target, path.as_deref(), *json)
        }
        Some(cli::Command::Rollback { session, target }) => {
            let res = vetto::rescue::snapshot::rollback_snapshot(session, target.as_deref())?;
            println!(
                "vetto rollback: successfully restored {} file(s) ({} bytes) to {}",
                res.files_restored,
                res.bytes_restored,
                res.target_dir.display()
            );
            Ok(())
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
            if cfg.agent.is_empty() && !profile_loaded {
                let project = std::env::current_dir().context("getcwd")?;
                let detected = match vetto::onboard::detect_agent(&project) {
                    Ok(detected) => detected,
                    Err(e) => bail!(
                        "no AI agent detected in {} ({e})\n\n\
                         Get started:\n  \
                         1. `vetto enable` — wrap installed agents (e.g. `vetto enable claude`)\n  \
                         2. `vetto doctor` — see what this kernel can enforce\n  \
                         3. `vetto tour` — guided introduction\n  \
                         4. `vetto -- <command>` — sandbox any binary, e.g. `vetto -- python agent.py`\n\n\
                         Docs: https://shleder.github.io/vetto/",
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
                if matches!(cfg.net, NetMode::Off) && !detected.network_domains.is_empty() {
                    cfg.net = NetMode::Allowlist(detected.network_domains);
                }
            }
            supervise(cfg)
        }
    }
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
    if cfg.agent.is_empty() {
        bail!("no agent command provided; usage: vetto [OPTIONS] -- <command> [args...]");
    }

    // Resolve the agent command before sandbox detection so missing commands immediately return exit code 127
    let mut agent_cmd = cfg.agent.clone();
    agent_cmd[0] = resolve_in_path(&agent_cmd[0])?;

    let user_config = vetto::version::load_user_config().unwrap_or_default();
    vetto::version::print_banner_if_update_available(
        env!("CARGO_PKG_VERSION"),
        &user_config.channel,
    );

    let backend_res = sandbox::Backend::detect_with_backend(
        cfg.net.clone(),
        cfg.observe_seccomp,
        cfg.backend.as_deref(),
    );
    let (backend_opt, tier) = match backend_res {
        Ok(b) => {
            let t = b.tier();
            (Some(Box::new(b)), t)
        }
        Err(e) => {
            if cfg.dry_run && cfg.backend.as_deref().unwrap_or("auto") == "auto" {
                (None, Some(policy::Tier::Full))
            } else {
                return Err(e);
            }
        }
    };

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
    let overrides = policy::loader::PolicyOverrides {
        deny_glob: cfg.deny_glob.clone(),
        git_guard: if cfg.git_guard { Some(true) } else { None },
        snapshot: if cfg.snapshot { Some(true) } else { None },
        auto_deny_secrets: if cfg.auto_deny_secrets {
            Some(true)
        } else {
            None
        },
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
    )?;

    if (pol.git_guard || cfg.git_guard) && !pol.allow_write.is_empty() {
        if let Some(branch) = policy::conditions::detect_git_branch(&project) {
            if branch == "main" || branch == "master" {
                bail!(
                    "git_guard: working copy is on branch '{branch}'; refusing to run with write permissions (create a feature branch, e.g. 'git checkout -b feature/...')"
                );
            }
        }
    }

    let initial_manifest = report::diff_project::ProjectManifest::capture(&project);
    let session_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        std::process::id()
    );
    if pol.snapshot || cfg.snapshot || !cfg.agent.is_empty() {
        match rescue::snapshot::create_snapshot(
            &project,
            &session_id,
            rescue::snapshot::DEFAULT_MAX_SNAPSHOT_SIZE,
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
        Some(b) => b,
        None => Box::new(sandbox::Backend::detect_with_backend(
            cfg.net.clone(),
            cfg.observe_seccomp,
            cfg.backend.as_deref(),
        )?),
    };
    tracing::debug!("backend: {}", backend.describe());

    if cfg.net.uses_relay()
        && (tier == Some(policy::Tier::FsOnly) || tier == Some(policy::Tier::Seccomp))
    {
        bail!(
            "network relay modes require Tier FULL (missing unprivileged user namespaces); \
             refusing to run (fail-closed)\n\
             action: enable unprivileged userns (`sysctl -w kernel.unprivileged_userns_clone=1`) or re-run with `--net=off`; run `vetto doctor` for the full capability picture"
        );
    }

    #[cfg(not(target_os = "linux"))]
    if cfg.git_ssh {
        bail!(
            "--git-ssh is available on Linux only\n\
             action: use standard HTTPS git remotes (`--net=allowlist:github.com`) on this OS; run `vetto doctor` for supported network features"
        );
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
                    "--verify: boundary verification failed (detected filesystem or network leaks); \
                     refusing to start the agent (fail-closed)\n\
                     action: review the leak findings above and adjust your policy grants; run `vetto doctor --probe`"
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

    let mut env_extra: HashMap<String, String> = {
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

    if pol.git_guard || cfg.git_guard {
        env_extra.insert("VETTO_GIT_GUARD".into(), "1".into());
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
            bail!(
                "the Windows backend currently requires --tui=none or --ci\n\
                 action: re-run with `--tui=none` or `--ci`"
            );
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
    let default_log_path = home
        .join(".vetto")
        .join("logs")
        .join(format!("session-{root_pid}.jsonl"));
    if let Some(parent) = default_log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    logger::jsonl::JsonlSink::spawn(&bus, default_log_path.clone());

    let jsonl_path = cfg.jsonl_path.clone();
    if let Some(path) = &jsonl_path {
        if path != &default_log_path {
            logger::jsonl::JsonlSink::spawn(&bus, path.clone());
        }
    }
    if cfg.oslog || pol.oslog {
        logger::oslog::OsLogSink::spawn(&bus);
    }
    let stats = report::stats::StatsCollector::spawn(&bus);

    let otel_session = std::sync::Arc::new(vetto::telemetry::TelemetrySession::start(
        cfg.otel_endpoint.as_deref(),
        &format!("session-{root_pid}"),
        tier_label(tier),
        &cfg.net.label(),
        &pol.name,
    )?);
    vetto::telemetry::spawn_telemetry_subscriber(&bus, otel_session.clone());

    if cfg.notify {
        vetto::notify::DesktopNotifier::spawn(&bus, true);
    }
    bus.publish(Event::SessionStarted {
        ts: events::types::now(),
        pid: root_pid,
        tier: tier_label(tier).to_string(),
        net_mode: cfg.net.label(),
        profile: pol.name.clone(),
    });

    #[cfg(unix)]
    let mut _cred_broker_handle = None;
    #[cfg(unix)]
    if let Some(sock) = cred_sock {
        let mut host_secrets = HashMap::new();
        for key in &pol.secret_proxies {
            if let Ok(val) = std::env::var(key) {
                host_secrets.insert(key.clone(), val);
            }
        }
        let allowlist_domains = match &cfg.net {
            vetto::config::NetMode::Allowlist(d) => d.clone(),
            vetto::config::NetMode::Strict(rules) => {
                rules.iter().map(|r| r.domain.clone()).collect()
            }
            vetto::config::NetMode::Off | vetto::config::NetMode::Ask => Vec::new(),
        };
        let broker_config = vetto::cred_broker::CredBrokerConfig {
            proxy_secrets: pol.secret_proxies.clone(),
            allowlist_domains,
        };
        match vetto::cred_broker::spawn_credential_broker(
            sock,
            broker_config,
            host_secrets,
            bus.clone(),
        ) {
            Ok(h) => _cred_broker_handle = Some(h),
            Err(e) => eprintln!("vetto: warning: failed to spawn credential broker: {e}"),
        }
    }

    match tier {
        Some(policy::Tier::Full) => {
            for d in &pol.deny_resolved {
                bus.publish(Event::SecretMasked {
                    ts: events::types::now(),
                    path: d.path.display().to_string(),
                });
            }
        }
        Some(policy::Tier::Seccomp) => {
            bus.publish(Event::Notice {
                ts: events::types::now(),
                message: "WARNING: Running in Tier SECCOMP (micro-mode). Filesystem isolation is NOT enforced on this system because Landlock is unavailable. Only syscall filtering and network blocking are active."
                    .to_string(),
            });
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
            if let Some(notify_cfg) = &pol.seccomp_notify {
                if notify_cfg.enabled {
                    sandbox::linux::observe_seccomp::spawn_enforcement_supervisor(
                        fd,
                        bus.clone(),
                        notify_cfg.clone(),
                        notifier_policy,
                        project.clone(),
                    );
                    bus.publish(Event::Notice {
                        ts: events::types::now(),
                        message: "seccomp user-notify supervisor enforcement active (default deny)"
                            .to_string(),
                    });
                } else {
                    sandbox::linux::observe_seccomp::spawn_notifier(
                        fd,
                        bus.clone(),
                        notifier_policy,
                        project.clone(),
                    );
                }
            } else {
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
    let diff = report::diff_project::ProjectDiff::compute(&initial_manifest, &project);
    if !diff.is_empty() {
        bus.publish(Event::Notice {
            ts: events::types::now(),
            message: diff.summary(),
        });
        eprintln!("vetto: {}", diff.summary());
    }

    bus.publish(Event::Notice {
        ts: events::types::now(),
        message: format!("I/O summary: {}", snap.io_summary()),
    });
    let mut primary_report = None;
    if !cfg.report_formats.is_empty() {
        let report_options = report::ReportOptions {
            report_dir: cfg.report_dir.clone(),
            auto_cleanup: cfg.report_auto_cleanup,
            retention: cfg.report_retention,
            max_age_secs: cfg.report_max_age_secs,
        };
        for p in report::write_reports_with_options(&snap, &cfg.report_formats, &report_options)? {
            eprintln!("vetto: report written: {}", p.display());
            if primary_report.is_none() {
                primary_report = Some(p);
            }
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
                    "bytes_read": snap.bytes_read,
                    "bytes_written": snap.bytes_written,
                    "read_ops": snap.read_ops,
                    "write_ops": snap.write_ops,
                    "files_modified": diff.total_changed(),
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
            "vetto: agent exited {} after {}s (blocked={}, events={}, I/O: {}, tier={}{})",
            exit_code,
            duration_secs,
            blocked_total,
            snap.events_total,
            snap.io_summary(),
            tier_label(tier),
            if timed_out { ", TIMEOUT" } else { "" },
        );
    }

    otel_session.finish(code);

    let history_record = vetto::audit::AuditRecord {
        ts: events::types::now(),
        session_id: format!("session-{root_pid}"),
        agent: cfg
            .agent_preset
            .clone()
            .unwrap_or_else(|| cfg.agent.first().cloned().unwrap_or_default()),
        command: Some(cfg.agent.join(" ")),
        profile: pol.name.clone(),
        policy_path: cfg.policy_path.as_ref().map(|p| p.display().to_string()),
        exit_code: code,
        duration_secs,
        tier: tier_label(tier).to_string(),
        net_mode: cfg.net.label(),
        blocked_count: blocked_total,
        events_total: snap.events_total,
        report_path: primary_report.as_ref().map(|p| p.display().to_string()),
        log_path: Some(default_log_path.display().to_string()),
    };
    let _ = vetto::audit::record_session_history(&history_record);

    std::process::exit(code);
}

fn tier_label(tier: Option<policy::Tier>) -> &'static str {
    match tier {
        Some(policy::Tier::Full) => policy::Tier::Full.label(),
        Some(policy::Tier::FsOnly) => policy::Tier::FsOnly.label(),
        Some(policy::Tier::Seccomp) => policy::Tier::Seccomp.label(),
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
        println!(
            "update available:        {} -> {} (run 'vetto upgrade')",
            notice.current_version, notice.latest_version
        );
    }
    #[cfg(target_os = "linux")]
    {
        let env_info = vetto::doctor::detect_environment();
        println!("environment:             {}", env_info.summary);
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
        let sbpl_status = sandbox::macos::seatbelt::probe_sbpl_read_fragment();
        println!("sbpl-read-fragment:      {}", sbpl_status.as_str());
        println!("  platform status:       Tier 2 (write isolation + process rlimits + network lockdown)");
        println!("  honest security note:  Apple deprecates SBPL and restricts unprivileged read-denial.");
        println!("                         For 100% Landlock read-masking on macOS, run inside OrbStack or WSL2.");
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
        println!("LPAC API:                {}", yn(capabilities.lpac_api));

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
        println!("  platform status:       Tier 3 (Job Objects + Restricted Token + LPAC)");
        println!("  recommendation:        For full 100% Landlock kernel confinement on Windows, run inside WSL2.");
        if fix {
            vetto::doctor::print_fixes(&[]);
        }
        if probe_deny {
            println!("probe: display-only deny verification is unavailable on the Windows backend");
        }
    }
    if let Some(agent) = check_agent {
        doctor_agent_check(agent)?;
    } else {
        let has_any_agent = vetto::onboard::SUPPORTED_AGENTS
            .iter()
            .any(|a| vetto::shim::find_real_binary(a).is_ok());
        if !has_any_agent {
            println!("agents in PATH:          none detected (run `vetto enable` to see supported agents)");
        }
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
