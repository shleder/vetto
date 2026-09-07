//! Windows uniform VM backend: Linux Tier-1 inside a WSL2 distro.
//!
//! The agent NEVER runs on the Windows host through this backend. It runs as
//! a Linux `vetto` binary inside the WSL2 distro, where Landlock / seccomp /
//! namespaces give the same Tier-1 guarantees as a native Linux host.
//! The host only orchestrates: ensure the distro is running, copy the
//! workspace in, `wsl.exe`-exec the agent, copy results back.
//!
//! Fail-closed everywhere: missing WSL2, distro, or guest vetto → `bail!`
//! with an actionable message. There is intentionally NO silent host
//! fallback (no quiet legacy-process run).
//!
//! Layout:
//!   `distro` — WSL2 lifecycle via `wsl.exe` (status/list/terminate)
//!   `sync`   — workspace sync host<->guest via `\\wsl$\<distro>` (fail-closed)
//!   `exec`   — agent exec inside the guest via `wsl.exe -d` (exit passthrough)
//!
//! Only the pure argv/config/parse helpers are unit-tested (no WSL2, no
//! process spawning in tests).

pub mod distro;
pub mod exec;
pub mod sync;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::handle::{SandboxHandle, SpawnOptions};
use super::Spawned;
use crate::config::NetMode;
use crate::policy::{Policy, Tier};

/// Config file name (under `%USERPROFILE%\.vetto\`).
pub const CONFIG_FILE: &str = "wsl2.toml";
/// Env override for the distro name (default from config file).
pub const DISTRO_ENV: &str = "VETTO_WSL2_DISTRO";
/// Env override for the guest vetto binary (default: `GUEST_VETTO`).
pub const GUEST_VETTO_ENV: &str = "VETTO_WSL2_VETTO";
/// Guest-side Linux vetto binary.
pub const GUEST_VETTO: &str = "/usr/local/bin/vetto";
/// Guest-side workspace mount point (inside the distro).
pub const GUEST_WORKSPACE: &str = "/mnt/vetto-workspace";
/// Default distro name when neither config nor env pins one.
pub const DEFAULT_DISTRO: &str = "vetto";

/// Static WSL2 connection config. Pure data: parsing it is unit-tested,
/// touching WSL2 is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wsl2Config {
    /// WSL2 distro name, e.g. `vetto` or `Ubuntu`.
    pub distro: String,
    /// Guest vetto binary path (default `GUEST_VETTO`).
    #[serde(default = "default_guest_vetto")]
    pub guest_vetto: String,
}

fn default_guest_vetto() -> String {
    GUEST_VETTO.to_string()
}

impl Default for Wsl2Config {
    fn default() -> Self {
        Self {
            distro: DEFAULT_DISTRO.to_string(),
            guest_vetto: default_guest_vetto(),
        }
    }
}

impl Wsl2Config {
    /// Parse TOML config text. Pure logic — unit-tested.
    pub fn parse_toml(text: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate required fields. Pure logic — unit-tested.
    pub fn validate(&self) -> Result<()> {
        if self.distro.trim().is_empty() {
            bail!(
                "wsl2: config has no distro\n\
                 action: write {} with `distro = \"vetto\"` or set {DISTRO_ENV}; run `vetto doctor` for the full capability picture",
                config_path_display()
            );
        }
        if self.guest_vetto.trim().is_empty() {
            bail!("wsl2: guest_vetto must not be empty");
        }
        Ok(())
    }

    /// Effective distro: env override wins over config file.
    pub fn effective_distro(&self) -> String {
        std::env::var(DISTRO_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| self.distro.clone())
    }

    /// Effective guest vetto binary: env override wins over config file.
    pub fn effective_guest_vetto(&self) -> String {
        std::env::var(GUEST_VETTO_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| self.guest_vetto.clone())
    }
}

pub(crate) fn config_path_display() -> String {
    "%USERPROFILE%\\.vetto\\wsl2.toml".to_string()
}

fn config_path() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .map(|h| h.join(".vetto").join(CONFIG_FILE))
}

/// Load config from disk. Fail-closed when absent/unparseable.
pub fn load_config() -> Result<Wsl2Config> {
    if let Some(path) = config_path() {
        if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            return Wsl2Config::parse_toml(&text);
        }
    }
    // Env-only config is allowed (no file): useful for CI.
    if let Ok(distro) = std::env::var(DISTRO_ENV) {
        if !distro.trim().is_empty() {
            let cfg = Wsl2Config {
                distro,
                ..Wsl2Config::default()
            };
            cfg.validate()?;
            return Ok(cfg);
        }
    }
    bail!(
        "wsl2: no distro configured (no {} and no {DISTRO_ENV})\n\
         action: install WSL2, import the Linux distro, then write {} with `distro`; run `vetto doctor` for the full capability picture",
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
            reason: "WSL2 distro running; Linux Tier-1 applies inside the guest".into(),
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
/// (ensure, sync, exec) happens in `spawn`, fail-closed.
pub struct Wsl2Sandbox {
    pub cfg: Wsl2Config,
    pub net: NetMode,
}

impl Wsl2Sandbox {
    pub fn new(net: NetMode, cfg: Wsl2Config) -> Self {
        Self { cfg, net }
    }

    /// Tier inside the guest is always Full: the guest vetto binary owns
    /// Landlock/seccomp/namespaces exactly like native Linux.
    pub fn guest_tier() -> Tier {
        Tier::Full
    }

    /// Detect: WSL2 present AND distro running AND guest vetto present.
    /// Anything else → unavailable with a reason (fail-closed downstream).
    pub fn probe_availability() -> Availability {
        match load_config() {
            Ok(cfg) => Self::probe_availability_with(&cfg),
            Err(e) => {
                // E0716 guard: `unwrap_or` on a temporary String borrows a
                // dead temporary; bind the owned String first.
                let msg = e.to_string();
                let first = msg.lines().next().unwrap_or("no distro configured");
                Availability::missing(first.to_string())
            }
        }
    }

    /// Detect with an already-loaded config (avoids double file read in the
    /// dispatch path). Pure probe: no provisioning, no side effects beyond
    /// read-only `wsl.exe` queries.
    pub fn probe_availability_with(cfg: &Wsl2Config) -> Availability {
        let distro = cfg.effective_distro();
        match distro::query_distro(&distro) {
            Ok(state) if state.running => {}
            Ok(state) => {
                return Availability::missing(format!(
                    "distro `{distro}` not running (state: {}) — start it first",
                    state.state
                ));
            }
            Err(e) => {
                return Availability::missing(format!("WSL2 query failed: {e:#}"));
            }
        }
        match exec::guest_vetto_present(cfg) {
            Ok(()) => Availability::ok(),
            Err(e) => Availability::missing(format!("guest vetto missing: {e:#}")),
        }
    }

    /// Full ensure + run. Spawns `wsl.exe` as the session child; the guest
    /// Linux vetto inside owns Tier-1 enforcement. The host never executes
    /// the agent.
    pub fn spawn(self, policy: &Policy, opts: SpawnOptions) -> anyhow::Result<Spawned> {
        self.cfg.validate()?;
        let project = opts.cwd.clone();
        ensure_inside(
            &project,
            &std::env::current_dir().unwrap_or_else(|_| project.clone()),
        )?;

        // 1. Distro must exist and run.
        distro::ensure_running(&self.cfg)?;
        // 2. Sync workspace host -> guest, fail-closed on drift.
        sync::sync_to_guest(&self.cfg, &project)?;
        // 3. Remote policy: enforce the same Tier-1 inside the guest by
        //    invoking the Linux vetto binary there.
        let guest_cmd = exec::guest_vetto_argv(policy, &self.net, &opts.agent_cmd);
        let child = exec::spawn_guest(&self.cfg, &project, &opts, guest_cmd)?;
        // On Windows the authoritative wait handle is the retained process
        // HANDLE (pids are reusable diagnostics only): keep it in a
        // JobObject strategy with a null job (no extra containment — the
        // guest Linux vetto owns Tier-1). `windows_wait` reads the exit code
        // off this handle, so dropping `child` into parts is load-bearing.
        let root_pid = child.id();
        let handle = exec::child_to_handle(child)?;
        Ok(Spawned {
            post_wait: Some(crate::sandbox::PostWait::Wsl2SyncBack {
                cfg: self.cfg.clone(),
                project: project.clone(),
            }),
            handle: SandboxHandle {
                root_pid,
                strategy: Some(handle),
            },
        })
    }
}

/// Refuse sync when `project` escapes the current working directory tree.
/// Pure path-prefix check — unit-tested.
pub fn ensure_inside(project: &Path, cwd: &Path) -> anyhow::Result<()> {
    if project.starts_with(cwd) || cwd.starts_with(project) {
        return Ok(());
    }
    bail!(
        "wsl2: refusing to sync project outside the current tree (project: {}, cwd: {})\n\
         action: run vetto from inside the project; run `vetto doctor`",
        project.display(),
        cwd.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Wsl2Config {
        Wsl2Config {
            distro: "vetto".into(),
            guest_vetto: GUEST_VETTO.into(),
        }
    }

    #[test]
    fn parse_minimal_config() {
        let c = Wsl2Config::parse_toml("distro = \"Ubuntu\"\n").unwrap();
        assert_eq!(c.distro, "Ubuntu");
        assert_eq!(c.guest_vetto, GUEST_VETTO);
    }

    #[test]
    fn parse_full_config() {
        let c =
            Wsl2Config::parse_toml("distro = \"vetto\"\nguest_vetto = \"/opt/vetto\"\n").unwrap();
        assert_eq!(c.distro, "vetto");
        assert_eq!(c.guest_vetto, "/opt/vetto");
    }

    #[test]
    fn empty_distro_fails_closed() {
        let err = Wsl2Config::parse_toml("distro = \"  \"\n").unwrap_err();
        assert!(err.to_string().contains("no distro"), "{err:?}");
    }

    #[test]
    fn invalid_toml_fails_closed() {
        assert!(Wsl2Config::parse_toml("not toml [[[").is_err());
    }

    #[test]
    fn ensure_inside_accepts_subtree() {
        let cwd = Path::new("/proj");
        assert!(ensure_inside(Path::new("/proj/sub"), cwd).is_ok());
        assert!(ensure_inside(Path::new("/proj"), cwd).is_ok());
    }

    #[test]
    fn ensure_inside_rejects_escape() {
        let err = ensure_inside(Path::new("/etc"), Path::new("/proj")).unwrap_err();
        assert!(err.to_string().contains("refusing to sync"), "{err:?}");
    }

    #[test]
    fn guest_tier_is_full() {
        assert_eq!(Wsl2Sandbox::guest_tier(), Tier::Full);
    }

    #[test]
    fn no_legacy_host_fallback_references() {
        // Split literal: the forbidden token must not appear verbatim in
        // this file (the test reads its own source), so build it at runtime.
        let forbidden = ["app", "container"].concat();
        let src = include_str!("mod.rs").to_lowercase();
        assert!(!src.contains(&forbidden));
    }
}
