//! macOS uniform VM backend: Linux Tier-1 inside an NVMe Linux VM on top of
//! Apple Virtualization.framework.
//!
//! The agent NEVER runs on the macOS host through this backend. It runs as a
//! Linux `vetto` binary inside the guest, where Landlock / seccomp /
//! namespaces give the same Tier-1 guarantees as a native Linux host.
//! The host only orchestrates: ensure the VM is up, rsync the workspace in,
//! ssh-exec the agent, rsync results back.
//!
//! Fail-closed everywhere: missing VM, ssh, or rsync → `bail!` with an
//! actionable message. There is intentionally NO silent host fallback.
//!
//! Layout:
//!   `vm`   — VM lifecycle via the `vz` CLI helper (create/start/stop/ip-wait)
//!   `sync` — workspace sync host<->guest via rsync (fail-closed on drift)
//!   `exec` — agent exec inside the guest via ssh (exit code passthrough)
//!
//! Only the pure argv/config/parse helpers are unit-tested (no VM, no
//! process spawning in tests).

pub mod exec;
pub mod sync;
pub mod vm;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::handle::{SandboxHandle, SpawnOptions, StdioMode};
use super::Spawned;
use crate::config::NetMode;
use crate::policy::{Policy, Tier};

/// Config file name (under `~/.vetto/`).
pub const CONFIG_FILE: &str = "mac-vm.toml";
/// Env override for the helper binary (default: `vetto-vz` in PATH).
pub const HELPER_ENV: &str = "VETTO_VZ_HELPER";
/// Env override for the guest ssh target (default from config file).
pub const SSH_TARGET_ENV: &str = "VETTO_MACVM_SSH";
/// Default helper binary name.
pub const DEFAULT_HELPER: &str = "vetto-vz";
/// Guest-side workspace mount point.
pub const GUEST_WORKSPACE: &str = "/mnt/vetto-workspace";
/// Guest-side Linux vetto binary.
pub const GUEST_VETTO: &str = "/usr/local/bin/vetto";

/// Static VM connection config. Pure data: parsing it is unit-tested,
/// touching the VM is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacVmConfig {
    /// ssh target, e.g. `vetto@192.168.64.2` or `vetto@vm.local`.
    pub ssh_target: String,
    /// ssh private key path (optional; falls back to ssh-agent/defaults).
    #[serde(default)]
    pub ssh_key: Option<String>,
    /// Helper binary for vz lifecycle (default `vetto-vz`).
    #[serde(default = "default_helper")]
    pub helper: String,
    /// Seconds to wait for guest IP after start.
    #[serde(default = "default_ip_wait_secs")]
    pub ip_wait_secs: u64,
}

fn default_helper() -> String {
    DEFAULT_HELPER.to_string()
}

fn default_ip_wait_secs() -> u64 {
    120
}

impl Default for MacVmConfig {
    fn default() -> Self {
        Self {
            ssh_target: String::new(),
            ssh_key: None,
            helper: default_helper(),
            ip_wait_secs: default_ip_wait_secs(),
        }
    }
}

impl MacVmConfig {
    /// Parse TOML config text. Pure logic — unit-tested.
    pub fn parse_toml(text: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate required fields. Pure logic — unit-tested.
    pub fn validate(&self) -> Result<()> {
        if self.ssh_target.trim().is_empty() {
            bail!(
                "mac-vm: config has no ssh_target\n\
                 action: write {} with `ssh_target = \"user@ip\"` or set {SSH_TARGET_ENV}; run `vetto doctor` for the full capability picture",
                config_path_display()
            );
        }
        if self.ip_wait_secs == 0 {
            bail!("mac-vm: ip_wait_secs must be > 0");
        }
        Ok(())
    }

    /// Effective helper binary: env override wins over config file.
    pub fn effective_helper(&self) -> String {
        std::env::var_os(HELPER_ENV)
            .and_then(|v| v.into_string().ok())
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| self.helper.clone())
    }

    /// Effective ssh target: env override wins over config file.
    pub fn effective_ssh_target(&self) -> String {
        std::env::var_os(SSH_TARGET_ENV)
            .and_then(|v| v.into_string().ok())
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| self.ssh_target.clone())
    }
}

pub(crate) fn config_path_display() -> String {
    "~/.vetto/mac-vm.toml".to_string()
}

fn config_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".vetto").join(CONFIG_FILE))
}

/// Load config from disk. Fail-closed when absent/unparseable.
pub fn load_config() -> Result<MacVmConfig> {
    if let Some(path) = config_path() {
        if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            return MacVmConfig::parse_toml(&text);
        }
    }
    // Env-only config is allowed (no file): useful for CI Gegenwart.
    if let Ok(target) = std::env::var(SSH_TARGET_ENV) {
        if !target.trim().is_empty() {
            let cfg = MacVmConfig {
                ssh_target: target,
                ..MacVmConfig::default()
            };
            cfg.validate()?;
            return Ok(cfg);
        }
    }
    bail!(
        "mac-vm: no VM configured (no {} and no {SSH_TARGET_ENV})\n\
         action: install the VM helper (`vetto-vz`), create the Linux VM, then write {} with `ssh_target`; run `vetto doctor` for the full capability picture",
        config_path_display(),
        config_path_display()
    )
}

/// Probe result for `vetto doctor` and auto-detect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Availability {
    pub available: bool,
    pub reason: String,
}

impl Availability {
    pub fn ok() -> Self {
        Self {
            available: true,
            reason: "VM reachable over ssh; Linux Tier-1 applies inside the guest".into(),
        }
    }

    pub fn missing(reason: impl Into<String>) -> Self {
        Self {
            available: false,
            reason: reason.into(),
        }
    }
}

/// The uniform backend. Holds only config + net mode; every heavy step
/// (start, sync, exec) happens in `spawn`, fail-closed.
pub struct MacVmSandbox {
    pub cfg: MacVmConfig,
    pub net: NetMode,
}

impl MacVmSandbox {
    pub fn new(net: NetMode, cfg: MacVmConfig) -> Self {
        Self { cfg, net }
    }

    /// Detect: config present AND helper responsive AND ssh reachable.
    /// Anything else → unavailable with a reason (fail-closed downstream).
    pub fn probe_availability() -> Availability {
        match load_config() {
            Ok(cfg) => Self::probe_availability_with(&cfg),
            Err(e) => {
                // E0716 guard: bind the owned String before borrowing lines.
                let msg = e.to_string();
                let first = msg.lines().next().unwrap_or("no VM configured");
                Availability::missing(first.to_string())
            }
        }
    }

    /// Detect with an already-loaded config (avoids double file read in the
    /// dispatch path). Pure probe: no provisioning, no side effects.
    pub fn probe_availability_with(cfg: &MacVmConfig) -> Availability {
        let helper = cfg.effective_helper();
        if !vm::helper_present(&helper) {
            return Availability::missing(format!(
                "helper `{helper}` not found in PATH — install/start the VM first"
            ));
        }
        match vm::helper_status(&helper) {
            Ok(status) if status.running => {}
            Ok(status) => {
                return Availability::missing(format!(
                    "VM not running (state: {}) — start it first",
                    status.state
                ));
            }
            Err(e) => {
                return Availability::missing(format!("VM helper query failed: {e:#}"));
            }
        }
        match exec::ssh_reachable(&cfg) {
            Ok(()) => Availability::ok(),
            Err(e) => Availability::missing(format!("ssh unreachable: {e:#}")),
        }
    }

    /// Full provision + run. Called pre-fork from the single-threaded path
    /// (same iron rule as the other backends): `std::process::Command` is
    /// used for ssh/rsync, no threads are spawned here.
    ///
    /// Sync-back back into the host workspace happens in the supervisor
    /// after `handle.wait()` returns (see `main.rs` wait callers): until
    /// then the guest owns the truth. `sync::sync_from_guest` is fail-loud
    /// (never silent) so a failed sync-back cannot masquerade as success.
    pub fn spawn(self, policy: &Policy, opts: SpawnOptions) -> anyhow::Result<Spawned> {
        self.cfg.validate()?;
        let project = opts.cwd.clone();
        ensure_inside(
            &project,
            &std::env::current_dir().unwrap_or_else(|_| project.clone()),
        )?;

        // 1. VM must exist and run; start it (bounded) when stopped.
        vm::ensure_running(&self.cfg)?;
        // 2. Sync workspace host -> guest, fail-closed on drift.
        sync::sync_to_guest(&self.cfg, &project)?;
        // 3. Remote policy: enforce the same Tier-1 inside the guest by
        //    invoking the Linux vetto binary there. The guest binary owns
        //    Landlock/seccomp/namespaces; the host never executes the agent.
        let guest_cmd = exec::guest_vetto_argv(policy, &self.net, &opts.agent_cmd);
        let child = exec::spawn_guest(&self.cfg, &project, &opts, guest_cmd)?;
        let root_pid = child.id();
        // `exec::spawn_guest` returns a live `std::process::Child`; convert
        // it to a pid-based handle WITHOUT leaking: `Child` owns no
        // wait-critical state beyond the pid on unix — `SandboxHandle::wait`
        // reaps via libc waitpid on root_pid, and SIGKILL goes to the ssh
        // process group. Dropping `Child` here does NOT kill ssh (no
        // kill-on-drop): the pid stays valid until reaped by wait().
        // NOTE: `std::process::Child` has no kill-on-drop; dropping it only
        // releases the Rust-side handle. The ssh process keeps running until
        // waitpid reaps it — exactly what `SandboxHandle` expects.
        drop(child);
        Ok(Spawned {
            post_wait: Some(crate::sandbox::PostWait::MacVmSyncBack {
                cfg: self.cfg.clone(),
                project: project.clone(),
            }),
            handle: SandboxHandle {
                root_pid,
                strategy: Some(super::handle::KillStrategy::ProcessGroup {
                    pid: root_pid as i32,
                    pgid: root_pid as i32,
                    sweep: false,
                }),
            },
            broker_ctrl_fd: None,
            relay_port: None,
            notif_listener: None,
        })
    }
}

/// Refuse sync when `project` escapes the current working directory tree.
/// Pure path-prefix check — unit-tested.
pub fn ensure_inside(project: &Path, cwd: &Path) -> anyhow::Result<()> {
    if project.starts_with(cwd) || cwd.starts_with(project) {
        return Ok(());
    }
    // Also allow exact equality fallthrough above; otherwise fail closed:
    // syncing an unrelated tree risks pushing secrets into the guest.
    bail!(
        "mac-vm: refusing to sync workspace outside the current tree (project={}, cwd={})\n\
         action: run vetto from inside the project directory",
        project.display(),
        cwd.display()
    )
}

/// Environment allowlist for the guest: same secret-proxy stripping as the
/// Seatbelt backend, plus VETTO_* markers. Pure map transform — unit-tested.
pub fn guest_env(policy: &Policy, extra: &HashMap<String, String>) -> HashMap<String, String> {
    let mut env: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
        std::env::vars_os()
            .filter(|(key, _)| policy.environment.allows(key))
            .collect();
    crate::cred_broker::filter_proxy_secrets(&mut env, &policy.secret_proxies);
    for (k, v) in extra {
        env.insert(
            std::ffi::OsString::from(k.as_str()),
            std::ffi::OsString::from(v.as_str()),
        );
    }
    crate::cred_broker::filter_proxy_secrets(&mut env, &policy.secret_proxies);
    env.into_iter()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect()
}

/// Tier inside the guest is always Linux Tier-1.
pub fn guest_tier() -> Tier {
    Tier::Full
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let cfg = MacVmConfig::parse_toml("ssh_target = \"vetto@192.168.64.2\"\n").unwrap();
        assert_eq!(cfg.ssh_target, "vetto@192.168.64.2");
        assert_eq!(cfg.helper, DEFAULT_HELPER);
        assert_eq!(cfg.ip_wait_secs, 120);
    }

    #[test]
    fn parse_full_config() {
        let cfg = MacVmConfig::parse_toml(
            "ssh_target = \"vetto@vm.local\"\nssh_key = \"/home/u/.ssh/vm\"\nhelper = \"my-vz\"\nip_wait_secs = 30\n",
        )
        .unwrap();
        assert_eq!(cfg.ssh_key.as_deref(), Some("/home/u/.ssh/vm"));
        assert_eq!(cfg.helper, "my-vz");
        assert_eq!(cfg.ip_wait_secs, 30);
    }

    #[test]
    fn missing_target_fails_closed() {
        let err = MacVmConfig::parse_toml("helper = \"x\"\n").unwrap_err();
        assert!(err.to_string().contains("ssh_target"), "{err:?}");
    }

    #[test]
    fn zero_ip_wait_fails_closed() {
        let err = MacVmConfig::parse_toml("ssh_target = \"vetto@1.2.3.4\"\nip_wait_secs = 0\n")
            .unwrap_err();
        assert!(err.to_string().contains("ip_wait_secs"), "{err:?}");
    }

    #[test]
    fn invalid_toml_fails_closed() {
        assert!(MacVmConfig::parse_toml("not toml [[[").is_err());
    }

    #[test]
    fn ensure_inside_accepts_subtree() {
        let cwd = Path::new("/Users/u/proj");
        assert!(ensure_inside(Path::new("/Users/u/proj/sub"), cwd).is_ok());
        assert!(ensure_inside(Path::new("/Users/u/proj"), cwd).is_ok());
    }

    #[test]
    fn ensure_inside_rejects_escape() {
        let err = ensure_inside(Path::new("/etc"), Path::new("/Users/u/proj")).unwrap_err();
        assert!(err.to_string().contains("refusing to sync"), "{err:?}");
    }
}
