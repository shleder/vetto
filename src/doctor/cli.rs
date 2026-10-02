//! CLI implementation for `vetto doctor`.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Entry point for `vetto doctor`.
pub fn run_doctor(probe_deny: bool, check_agent: Option<&str>, fix: bool) -> Result<()> {
    println!("vetto v{} doctor", env!("CARGO_PKG_VERSION"));
    let user_config = crate::version::load_user_config().unwrap_or_default();
    if let Some(notice) =
        crate::version::check_version(env!("CARGO_PKG_VERSION"), &user_config.channel, false)
    {
        println!(
            "update available:        {} -> {} (run 'vetto upgrade')",
            notice.current_version, notice.latest_version
        );
    }
    #[cfg(target_os = "linux")]
    {
        let env_info = crate::doctor::detect_environment();
        println!("environment:             {}", env_info.summary);
        let p = crate::sandbox::linux::probe();
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
            "namespaces (user/mount/pid/net): {}",
            if p.full_tier_available {
                "available (user, mount, pid, net)"
            } else if p.userns_available {
                "partial (user only; mount/pid/net restricted)"
            } else {
                "UNAVAILABLE"
            }
        );
        println!(
            "cgroups v2 controllers:  {}",
            if p.cgroup_controllers.is_empty() {
                "none detected (or cgroup v2 not mounted)".to_string()
            } else {
                p.cgroup_controllers.join(" ")
            }
        );
        println!(
            "seccomp filters:         {}",
            yn(p.seccomp_filter_available)
        );
        println!(
            "seccomp user-notify:     {}",
            yn(p.seccomp_notify_available)
        );
        println!("audit feed readable:     {}", yn(p.audit_feed_readable));
        match crate::sandbox::linux::pick_tier(&p) {
            Ok(t) => println!("chosen tier:             {}", t.label()),
            Err(e) => println!("chosen tier:             NONE — fail-closed: {e}"),
        }
        println!("  platform status:       Tier 1 (Production: Landlock ABI v1-v6 + namespaces + cgroups v2 + seccomp-bpf)");
        if fix {
            let fixes = crate::doctor::fix::collect_linux_fixes(&p);
            crate::doctor::print_fixes(&fixes);
        }
        if let Some(abi) = p.landlock_abi {
            for hint in crate::sandbox::linux::landlock::abi_feature_hints(abi) {
                println!("  note: {hint}");
            }
        }
        if probe_deny {
            doctor_probe()?;
        }
    }
    #[cfg(target_os = "macos")]
    {
        let seatbelt_available = crate::sandbox::macos::MacosSandbox::seatbelt_available();
        println!(
            "seatbelt (sandbox-exec / libsandbox API): {}",
            yn(seatbelt_available)
        );
        let sbpl_status = crate::sandbox::macos::seatbelt::probe_sbpl_read_fragment();
        println!("sbpl-read-fragment:      {}", sbpl_status.as_str());
        println!("  shape status:          Shape D (allow file-read* broad + tail deny; fragmented dyld aborts)");
        println!("  dyld shared cache:     read-restriction blocked by Apple dyld/libSystem constraints (Issue #62)");
        println!("  resource limits:       best-effort rlimits (Enforced, not Verified; no remote verification API)");
        println!("  platform status:       Tier 2 (Experimental: Seatbelt write isolation + network lockdown + best-effort rlimits)");
        println!("  honest security note:  Apple deprecates SBPL and restricts unprivileged read-denial.");
        println!("                         For 100% Landlock read-masking on macOS, run inside OrbStack or WSL2.");
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        if crate::doctor::fix::is_macos_tcc_protected_path(&cwd) {
            println!("{}", crate::doctor::fix::MACOS_TCC_GUIDANCE);
        }
        if fix {
            let mut macos_fixes = crate::doctor::fix::collect_macos_fixes(
                seatbelt_available,
                sbpl_status != crate::sandbox::macos::seatbelt::SbplFragmentStatus::Ok,
            );
            if let Some(tcc_fix) = crate::doctor::fix::macos_tcc_fix_for_path(&cwd) {
                macos_fixes.push(tcc_fix);
            }
            crate::doctor::print_fixes(&macos_fixes);
        }
        if probe_deny {
            doctor_probe()?;
        }
    }
    #[cfg(target_os = "windows")]
    {
        let capabilities = crate::sandbox::windows::probe();
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

        for note in &capabilities.notes {
            println!("  note: {note}");
        }
        println!(
            "  platform status:       Tier 3 (Experimental: Job Objects + Restricted Token + LPAC)"
        );
        println!(
            "  {}",
            crate::doctor::environment::WINDOWS_TIER3_ISOLATION_NOTICE
        );
        println!(
            "cgroups v2 limits:      {}",
            crate::doctor::environment::windows_cgroup_limits_status().as_str()
        );
        println!("  network warning:       WFP network filtering requires elevated Administrator privileges (Issue #63). Default process sandbox enforces net=off via AppContainer.");
        println!("  recommendation:        For full 100% Landlock kernel confinement on Windows, run inside WSL2.");
        if fix {
            let windows_fixes = crate::doctor::fix::collect_windows_fixes(&capabilities);
            crate::doctor::print_fixes(&windows_fixes);
        }
        if probe_deny {
            doctor_probe_windows()?;
        }
    }
    if let Some(agent) = check_agent {
        doctor_agent_check(agent)?;
    } else {
        let has_any_agent = crate::onboard::SUPPORTED_AGENTS
            .iter()
            .any(|a| crate::onboard::find_real_agent_binary(a).is_ok());
        if !has_any_agent {
            println!("agents in PATH:          none detected (run `vetto enable` to see supported agents)");
        } else {
            for agent in crate::onboard::SUPPORTED_AGENTS {
                if let Some(warning) = crate::doctor::check_path_shadowing(agent, None) {
                    println!("{warning}");
                }
            }
        }
    }
    Ok(())
}

fn doctor_agent_check(agent: &str) -> Result<()> {
    let result = crate::doctor::probe_agent(agent, std::time::Duration::from_secs(5));
    println!("agent check: {}", result.summary());
    if let Some(warning) = crate::doctor::check_path_shadowing(agent, None) {
        println!("{warning}");
    }
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
    let tier = crate::sandbox::Backend::detect(crate::policy::types::NetMode::Off, false)?
        .tier()
        .unwrap_or(crate::policy::Tier::Full);
    let pol = crate::policy::loader::load("default", None, &project, &home, tier)?;
    if pol.deny_resolved.is_empty() {
        println!("probe: no deny paths resolve on this machine (nothing to verify)");
        return Ok(());
    }

    let script_args: Vec<String> = pol
        .deny_resolved
        .iter()
        .map(|d| d.path.display().to_string())
        .collect();
    let output = crate::doctor::run_probe_script(&pol, &project, script_args)?;

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

#[cfg(target_os = "windows")]
fn doctor_probe_windows() -> Result<()> {
    println!("probe: analyzing deny-path overlap against granted roots (Windows AppContainer)...");
    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .context("neither %USERPROFILE% nor $HOME is set")?;
    let pol =
        crate::policy::loader::load("default", None, &project, &home, crate::policy::Tier::Full)?;
    if pol.deny_resolved.is_empty() {
        println!("probe: no deny paths resolve on this machine (nothing to verify)");
        return Ok(());
    }

    let analyses = crate::doctor::probe::analyze_deny_overlap(&pol);
    let mut failures = 0usize;
    for entry in &analyses {
        if entry.inside_grant {
            let root = entry
                .conflicting_root
                .as_ref()
                .map(|r| r.display().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            println!(
                "  ✗ {} OVERLAP CONFLICT: path sits inside granted root {}; AppContainer cannot subtract subpaths",
                entry.denied_path.display(),
                root
            );
            failures += 1;
        } else {
            println!(
                "  ✓ {} (isolated: outside granted roots, enforced by AppContainer default-deny)",
                entry.denied_path.display()
            );
        }
    }
    if failures == 0 {
        println!(
            "probe: all {} deny paths verified isolated outside granted roots (AppContainer default-deny)",
            pol.deny_resolved.len()
        );
        Ok(())
    } else {
        println!("probe: {failures} path(s) FAILED overlap analysis");
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
