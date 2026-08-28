//! Boundary verification battery: prove from inside a throwaway sandbox that
//! the resolved policy actually denies secret reads, host loopback connects,
//! and writes outside every write root.
//!
//! Constraints:
//! - The sandbox under test is the real enforcement backend, one spawn per
//!   battery (`doctor::probe`); there is no simulation.
//! - `preflight` never fails for platform or backend reasons: an unusable
//!   backend yields an "unavailable" report so `--verify` can distinguish
//!   "no leaks" from "could not check".
//! - Leaks fail closed: exit code 1 in the CLI, refused session start for
//!   the supervised preflight.

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::config::NetMode;
use crate::policy::{self, Policy};
use crate::sandbox;

#[cfg(unix)]
use crate::doctor::run_probe_script;
#[cfg(unix)]
use crate::policy::Tier;

#[cfg(unix)]
const STATUS_PASS: &str = "pass";
const STATUS_LEAK: &str = "LEAK";
const STATUS_INFO: &str = "info";
const STATUS_SKIPPED: &str = "skipped";

/// One battery check. `name` is a stable machine-readable identifier; the
/// variable part of the finding (path, byte counts) lives in `detail`.
pub struct CheckResult {
    pub name: &'static str,
    pub status: &'static str,
    pub detail: String,
}

/// Battery outcome for one resolved policy. `tier`/`net` mirror the session
/// context the battery ran under.
pub struct VerifyReport {
    pub tier: String,
    pub net: String,
    pub checks: Vec<CheckResult>,
}

impl VerifyReport {
    pub fn leaks(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == STATUS_LEAK)
            .count()
    }

    /// "failed" on any leak; "unavailable" when every check is info/skipped
    /// AND the backend marked itself unable to run the battery (the
    /// `backend` info check is that marker); "pass" otherwise.
    pub fn status(&self) -> &'static str {
        if self.leaks() > 0 {
            return "failed";
        }
        let backend_marker = self
            .checks
            .iter()
            .any(|check| check.name == "backend" && check.status == STATUS_INFO);
        let no_verdicts = self
            .checks
            .iter()
            .all(|check| check.status == STATUS_INFO || check.status == STATUS_SKIPPED);
        if backend_marker && no_verdicts {
            "unavailable"
        } else {
            "pass"
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "boundary verify: tier={} net={} checks={} leaks={}",
            self.tier,
            self.net,
            self.checks.len(),
            self.leaks()
        )
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tier": self.tier,
            "net": self.net,
            "status": self.status(),
            "leaks": self.leaks(),
            "checks": self
                .checks
                .iter()
                .map(|check| {
                    serde_json::json!({
                        "name": check.name,
                        "status": check.status,
                        "detail": check.detail,
                    })
                })
                .collect::<Vec<serde_json::Value>>(),
        })
    }
}

/// `vetto verify`: resolve the policy exactly like the doctor probe (project
/// = cwd, home = $HOME, tier from the detected backend) and run the battery.
/// Exits 1 on any leak.
pub fn run_cli(
    json: bool,
    profile: &str,
    policy_path: Option<&Path>,
    net: &NetMode,
) -> anyhow::Result<()> {
    // Same detection context as a supervised session: the tier resolved here
    // is the tier the battery will verify.
    let backend = sandbox::Backend::detect(net.clone(), false)?;
    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("$HOME not set")?;
    let tier = backend.tier().unwrap_or(policy::Tier::Full);
    let pol = policy::loader::load(profile, policy_path, &project, &home, tier)?;
    let report = preflight(&pol, net)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report.to_json())?);
    } else {
        println!("{}", report.summary());
        for check in &report.checks {
            println!("  {:<9} {:<14} {}", check.status, check.name, check.detail);
        }
        match report.status() {
            "failed" => println!("boundary verify: FAILED ({} leak(s))", report.leaks()),
            "unavailable" => {
                println!("boundary verify: UNAVAILABLE (backend could not run the battery)")
            }
            _ => println!("boundary verify: PASS"),
        }
    }
    if report.leaks() > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Battery against a caller-resolved policy (supervised `--verify` preflight).
pub fn preflight(pol: &Policy, net: &NetMode) -> anyhow::Result<VerifyReport> {
    #[cfg(not(unix))]
    {
        let _ = pol;
        Ok(unavailable(
            net,
            "n/a",
            "verification battery is unix-only".to_string(),
        ))
    }
    #[cfg(unix)]
    battery(pol, net)
}

fn unavailable(net: &NetMode, tier: &str, detail: String) -> VerifyReport {
    VerifyReport {
        tier: tier.to_string(),
        net: net.label(),
        checks: vec![CheckResult {
            name: "backend",
            status: STATUS_INFO,
            detail,
        }],
    }
}

#[cfg(unix)]
fn pass(name: &'static str, detail: String) -> CheckResult {
    CheckResult {
        name,
        status: STATUS_PASS,
        detail,
    }
}

#[cfg(unix)]
fn leak(name: &'static str, detail: String) -> CheckResult {
    CheckResult {
        name,
        status: STATUS_LEAK,
        detail,
    }
}

#[cfg(unix)]
fn skipped(name: &'static str, detail: String) -> CheckResult {
    CheckResult {
        name,
        status: STATUS_SKIPPED,
        detail,
    }
}

#[cfg(unix)]
fn battery(pol: &Policy, net: &NetMode) -> anyhow::Result<VerifyReport> {
    let project = std::env::current_dir().context("getcwd")?;
    let backend = match sandbox::Backend::detect(net.clone(), false) {
        Ok(backend) => backend,
        Err(error) => {
            return Ok(unavailable(
                net,
                "unknown",
                format!("backend cannot run the battery: {error:#}"),
            ))
        }
    };
    let tier = backend.tier();

    let mut checks: Vec<CheckResult> = Vec::new();
    let mut script_args: Vec<String> = pol
        .deny_resolved
        .iter()
        .map(|entry| entry.path.display().to_string())
        .collect();

    // Host-side loopback listener: bound before the spawn and kept bound for
    // the whole battery, so a connect from inside can only succeed by
    // escaping the sandbox's network isolation.
    let mut listener = None;
    match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(bound) => match bound.local_addr() {
            Ok(addr) => {
                script_args.push(format!("NETCHECK:{}", addr.port()));
                listener = Some(bound);
            }
            Err(error) => checks.push(skipped(
                "net-loopback",
                format!("host listener local_addr failed: {error}"),
            )),
        },
        Err(error) => checks.push(skipped(
            "net-loopback",
            format!("host listener bind failed: {error}"),
        )),
    }

    // Write-outside probe target. Skipped when $HOME is inside a write root:
    // the probe would then test a permission the policy grants on purpose.
    let mut write_probe = None;
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        if !pol.in_write_scope(&home) {
            let path = home.join(format!("vetto-verify-probe-{}", std::process::id()));
            script_args.push(format!("WRITECHECK:{}", path.display()));
            write_probe = Some(path);
        }
    }

    let probe = match run_probe_script(pol, &project, script_args) {
        Ok(probe) => probe,
        Err(error) => {
            return Ok(unavailable(
                net,
                "unknown",
                format!("sandbox spawn failed: {error:#}"),
            ))
        }
    };
    drop(listener); // close the host listener only after the sandbox exited
    if let Some(path) = &write_probe {
        let _ = std::fs::remove_file(path); // exists only if the probe wrote it
    }

    parse_probe_output(&probe.stdout, tier, &mut checks);
    let stderr = probe.stderr.trim();
    if !stderr.is_empty() {
        checks.push(CheckResult {
            name: "probe-stderr",
            status: STATUS_INFO,
            detail: stderr.to_string(),
        });
    }

    Ok(VerifyReport {
        tier: tier_label(tier),
        net: net.label(),
        checks,
    })
}

#[cfg(unix)]
fn tier_label(tier: Option<Tier>) -> String {
    match tier {
        Some(tier) => tier.label().to_string(),
        // macOS reports no FS tier; its enforcement mechanism is seatbelt.
        None if cfg!(target_os = "macos") => "seatbelt".to_string(),
        None => "none".to_string(),
    }
}

#[cfg(unix)]
fn net_pass_detail(tier: Option<Tier>) -> String {
    match tier {
        Some(Tier::Full) => "host loopback listener unreachable (netns isolation)".to_string(),
        Some(Tier::FsOnly) => {
            "host loopback listener unreachable (seccomp socket block)".to_string()
        }
        None if cfg!(target_os = "macos") => {
            "host loopback listener unreachable (seatbelt deny)".to_string()
        }
        None => "host loopback listener unreachable".to_string(),
    }
}

#[cfg(unix)]
fn parse_probe_output(output: &str, tier: Option<Tier>, checks: &mut Vec<CheckResult>) {
    for line in output.lines() {
        let mut parts = line.splitn(3, '|');
        let (kind, path, verdict) = match (parts.next(), parts.next(), parts.next()) {
            (Some(kind), Some(path), Some(verdict)) => (kind, path, verdict),
            _ => continue,
        };
        match (kind, verdict) {
            ("D", "contents-denied") => checks.push(pass(
                "deny-path",
                format!(
                    "{path}/: file contents denied (entry names may remain visible in FS-ONLY)"
                ),
            )),
            ("D", "content-readable") => checks.push(leak(
                "deny-path",
                format!("{path}/: file content is readable"),
            )),
            ("F", "unreadable") => checks.push(pass("deny-path", format!("{path}: open denied"))),
            ("F", bytes) => {
                let in_sandbox: u64 = bytes.parse().unwrap_or(0);
                let host = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
                if host == 0 {
                    checks.push(pass(
                        "deny-path",
                        format!("{path}: empty on host; trivially safe"),
                    ));
                } else if in_sandbox == 0 {
                    checks.push(pass(
                        "deny-path",
                        format!("{path}: masked (appears empty inside)"),
                    ));
                } else {
                    checks.push(leak(
                        "deny-path",
                        format!("{path}: {in_sandbox}/{host} bytes readable"),
                    ));
                }
            }
            ("NET", "unreachable") => checks.push(pass("net-loopback", net_pass_detail(tier))),
            ("NET", "reachable") => checks.push(leak(
                "net-loopback",
                "sandbox reached a host loopback listener".to_string(),
            )),
            ("NET", "nobash") => checks.push(skipped(
                "net-loopback",
                "no bash inside the sandbox; /dev/tcp probe unavailable",
            )),
            ("WRITE", "denied") => checks.push(pass(
                "write-outside",
                format!("write to {path} outside every write root denied"),
            )),
            ("WRITE", "allowed") => checks.push(leak(
                "write-outside",
                format!("wrote outside every write root: {path}"),
            )),
            _ => {}
        }
    }
}
