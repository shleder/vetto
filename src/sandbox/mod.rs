//! Sandbox backends and the fail-closed factory.
//!
//! Rule #1 of vetto: if no enforcement backend can be established, the agent
//! does NOT run. There is never an unsandboxed fallback.

pub mod handle;
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "macos")]
pub mod macvm;

// Kept outside `macos/mod.rs` so the security worker remains untouched.  The
// broker is an opt-in library surface for later integration, not part of the
// Seatbelt spawn path.
#[cfg(target_os = "macos")]
#[path = "macos/net_proxy.rs"]
pub mod macos_net_proxy;

#[cfg(target_os = "windows")]
pub mod windows;

pub use handle::{SandboxHandle, SpawnOptions, StdioMode};

#[cfg(unix)]
use std::os::fd::OwnedFd;

use crate::config::NetMode;
use crate::policy::{Policy, Tier};

/// Everything `Backend::spawn` hands back to the supervisor besides the
/// waitable handle itself.
///
/// `post_wait` runs in the supervisor AFTER `handle.wait()` returns, while
/// still fail-loud: VM backends pull the workspace back here (guest keeps
/// the truth on failure — the error names the guest path, never silent).
pub struct Spawned {
    pub handle: SandboxHandle,
    /// Post-wait hook (VM sync-back). `None` for host-local backends.
    pub post_wait: Option<PostWait>,
    /// Broker end of the relay control socketpair (`--net=allowlist`).
    /// `main` passes it to `net_relay::spawn_broker` which takes ownership.
    #[cfg(unix)]
    pub broker_ctrl_fd: Option<OwnedFd>,
    /// Loopback port the in-netns relay listens on (allowlist mode).
    #[cfg(unix)]
    pub relay_port: Option<u16>,
    /// seccomp user-notify listener fd (`--observe-seccomp`); `main` passes
    /// it to `observe_seccomp::spawn_notifier` which takes ownership.
    #[cfg(unix)]
    pub notif_listener: Option<OwnedFd>,
}

/// Post-wait action for VM backends: pull the workspace back exactly once
/// after the agent exits. Runs on the supervisor thread (threads allowed).
pub enum PostWait {
    #[cfg(target_os = "macos")]
    MacVmSyncBack {
        cfg: macvm::MacVmConfig,
        project: std::path::PathBuf,
    },
}

impl PostWait {
    /// Run the post-wait hook. Fail-LOUD (error, never silent): a failed
    /// sync-back means the host tree is stale — the guest keeps the truth.
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            #[cfg(target_os = "macos")]
            PostWait::MacVmSyncBack { cfg, project } => {
                macvm::sync::sync_from_guest(&cfg, &project)
            }
        }
    }
}

/// Selected enforcement backend for this session.
///
/// Integration note for the parallel `feat/uniform-mac-vm` / `feat/uniform-win-wsl2`
/// branches: their `Backend::MacVm` / `Backend::Wsl2` variants plug in here.
/// Until those branches merge, `--backend mac-vm|wsl2` parses (see
/// [`parse_backend_name`]) but [`Backend::detect_with_backend`] fails closed
/// with an explicit "not yet integrated" error — never a silent fallback.
pub enum Backend {
    #[cfg(target_os = "linux")]
    Linux(Box<linux::LinuxSandbox>),
    #[cfg(target_os = "macos")]
    Macos(Box<macos::MacosSandbox>),
    #[cfg(target_os = "macos")]
    MacVm(Box<macvm::MacVmSandbox>),
    #[cfg(target_os = "windows")]
    Windows(Box<windows::WindowsSandbox>),
}

/// Canonical `--backend` name set (uniform dispatch surface).
pub const VALID_BACKENDS: &str = "auto, process, mac-vm, wsl2, win-sandbox";

/// Parsed `--backend` selector. Pure value: no I/O, no spawning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendName {
    Auto,
    Process,
    MacVm,
    Wsl2,
    WinSandbox,
}

/// Pure `--backend` name parser (no I/O, no spawning): the unit-testable
/// dispatch surface shared with the `feat/uniform-mac-vm` (`Backend::MacVm`)
/// and `feat/uniform-win-wsl2` (`Backend::Wsl2`) branches.
///
/// `mac-vm` / `wsl2` parse OK so CLI help, doctor matrix, and docs stay in
/// sync; construction fails closed in `detect_with_backend` until the sibling
/// branches land their variants.
pub fn parse_backend_name(name: &str) -> Result<BackendName, String> {
    match name {
        "auto" | "default" => Ok(BackendName::Auto),
        "process" => Ok(BackendName::Process),
        "mac-vm" | "macvm" => Ok(BackendName::MacVm),
        "wsl2" => Ok(BackendName::Wsl2),
        "win-sandbox" | "windows-sandbox" => Ok(BackendName::WinSandbox),
        other => Err(format!(
            "unknown backend '{other}'; valid backends: {VALID_BACKENDS}\n\
             action: select a valid backend or omit the flag; run `vetto doctor` for the full capability picture"
        )),
    }
}

impl Backend {
    /// Detect the strongest usable backend on this platform. Fails closed.
    pub fn detect(net: NetMode, observe_seccomp: bool) -> anyhow::Result<Self> {
        Self::detect_with_backend(net, observe_seccomp, None)
    }

    /// Detect or select requested enforcement backend. Fails closed.
    pub fn detect_with_backend(
        net: NetMode,
        observe_seccomp: bool,
        backend_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        if let Some(name) = backend_name {
            let parsed = parse_backend_name(name).map_err(|msg| anyhow::anyhow!("{msg}"))?;
            match parsed {
                BackendName::Auto | BackendName::Process => {}
                BackendName::MacVm => {
                    #[cfg(target_os = "macos")]
                    {
                        // Uniform default path: Tier-1 inside the Linux VM.
                        // Missing VM fails closed with an action, never a
                        // silent Seatbelt run.
                        let cfg = macvm::load_config()?;
                        let avail = macvm::MacVmSandbox::probe_availability_with(&cfg);
                        if !avail.available {
                            anyhow::bail!(
                                "mac-vm unavailable: {}\n\
                                 action: start the VM (`vetto-vz start`), check ssh, or pass explicit `--backend process` (deprecated legacy); run `vetto doctor` for the enforcement matrix",
                                avail.reason
                            );
                        }
                        return Ok(Backend::MacVm(Box::new(macvm::MacVmSandbox::new(
                            net, cfg,
                        ))));
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        anyhow::bail!(
                            "--backend mac-vm is only available on macOS (Virtualization.framework host)\n\
                             action: use `--backend auto` on this operating system; run `vetto doctor` for supported backends"
                        );
                    }
                }
                BackendName::Wsl2 => {
                    // Integration point for feat/uniform-win-wsl2: construct
                    // `Backend::Wsl2` here once that branch merges its variant.
                    #[cfg(target_os = "windows")]
                    {
                        anyhow::bail!(
                            "--backend wsl2 is not yet integrated (feat/uniform-win-wsl2 not merged)\n\
                             action: omit the flag (legacy AppContainer process backend applies, deprecated) or retry after the wsl2 branch lands; run `vetto doctor` for the enforcement matrix"
                        );
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        anyhow::bail!(
                            "--backend wsl2 is only available on Windows (WSL2 host)\n\
                             action: use `--backend auto` on this operating system; run `vetto doctor` for supported backends"
                        );
                    }
                }
                BackendName::WinSandbox => {
                    #[cfg(target_os = "windows")]
                    {
                        let caps = windows::windows_sandbox::capabilities();
                        if !caps.launcher_present
                            || !caps.virtualization_firmware_enabled
                            || !caps.feature_enabled
                        {
                            anyhow::bail!(
                                "Windows Sandbox feature is not enabled or virtualization firmware is disabled: {}\n\
                                 action: enable Hyper-V / Windows Sandbox in Windows Features and virtualization in BIOS; run `vetto doctor` for the full capability picture",
                                caps.note
                            );
                        }
                        return Ok(Backend::Windows(Box::new(windows::WindowsSandbox::new(
                            net,
                        )?)));
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        anyhow::bail!(
                            "--backend win-sandbox is only available on Windows\n\
                             action: use `--backend auto` or `--backend process` on this operating system; run `vetto doctor` for supported backends"
                        );
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            let probe = linux::probe();
            let tier = linux::pick_tier(&probe)?;
            Ok(Backend::Linux(Box::new(linux::LinuxSandbox {
                probe,
                tier,
                net,
                observe_seccomp,
            })))
        }
        #[cfg(target_os = "macos")]
        {
            // Uniform default: Tier-1 inside the Linux VM when available;
            // explicit `--backend process` keeps the deprecated Seatbelt path.
            let explicit_process = matches!(
                backend_name.map(parse_backend_name),
                Some(Ok(BackendName::Process))
            );
            if !explicit_process {
                if let Ok(cfg) = macvm::load_config() {
                    let avail = macvm::MacVmSandbox::probe_availability_with(&cfg);
                    if avail.available {
                        let _ = observe_seccomp;
                        return Ok(Backend::MacVm(Box::new(macvm::MacVmSandbox::new(
                            net, cfg,
                        ))));
                    }
                    anyhow::bail!(
                        "default enforcement requires Tier-1 via mac-vm, but: {}\n\
                         action: start the VM (`vetto-vz start`), check ssh, or pass explicit `--backend process` (deprecated legacy, Seatbelt write-confinement only); run `vetto doctor` for the enforcement matrix",
                        avail.reason
                    );
                }
                anyhow::bail!(
                    "default enforcement requires Tier-1 via mac-vm (no VM configured)\n\
                     action: install the VM helper (`vetto-vz`), create the Linux VM, write ~/.vetto/mac-vm.toml, or pass explicit `--backend process` (deprecated legacy); run `vetto doctor` for the enforcement matrix"
                );
            }
            let _ = observe_seccomp;
            Ok(Backend::Macos(Box::new(macos::MacosSandbox::new(net))))
        }
        #[cfg(target_os = "windows")]
        {
            let _ = observe_seccomp;
            Ok(Backend::Windows(Box::new(windows::WindowsSandbox::new(
                net,
            )?)))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = (net, observe_seccomp);
            Err(anyhow::anyhow!(
                crate::error::VettoError::UnsupportedPlatform("this platform")
            ))
        }
    }

    pub fn tier(&self) -> Option<Tier> {
        match self {
            #[cfg(target_os = "linux")]
            Backend::Linux(s) => Some(s.tier),
            #[cfg(target_os = "macos")]
            Backend::Macos(_) => None,
            #[cfg(target_os = "macos")]
            Backend::MacVm(_) => Some(Tier::Full),
            #[cfg(target_os = "windows")]
            Backend::Windows(_) => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            #[cfg(target_os = "linux")]
            Backend::Linux(s) => format!(
                "linux tier={} (landlock ABI {:?}, userns={}, full-stack={}, seccomp-notify={}, audit-feed={})",
                s.tier.label(),
                s.probe.landlock_abi,
                s.probe.userns_available,
                s.probe.full_tier_available,
                s.probe.seccomp_notify_available,
                s.probe.audit_feed_readable,
            ),
            #[cfg(target_os = "macos")]
            Backend::Macos(_) => {
                "macos seatbelt (legacy process-only, use mac-vm for Tier-1)".into()
            }
            #[cfg(target_os = "macos")]
            Backend::MacVm(_) => {
                "mac-vm tier-1 (Linux Landlock/seccomp/namespaces inside the VM)".into()
            }
            #[cfg(target_os = "windows")]
            Backend::Windows(s) => format!(
                "windows process sandbox (legacy process-only, use wsl2 for Tier-1) ({})",
                s.capabilities.summary()
            ),
        }
    }

    /// Spawn the agent inside the sandbox. Consumes the backend: enforcement
    /// state is applied in the forked child before exec.
    ///
    /// IRON RULE: must be called before any thread/tokio runtime exists —
    /// every fork inside is only safe from a single-threaded process.
    pub fn spawn(self, policy: &Policy, opts: SpawnOptions) -> anyhow::Result<Spawned> {
        match self {
            #[cfg(target_os = "linux")]
            Backend::Linux(s) => s.spawn(policy, opts),
            #[cfg(target_os = "macos")]
            Backend::Macos(s) => s.spawn(policy, opts),
            #[cfg(target_os = "macos")]
            Backend::MacVm(s) => {
                let project = opts.cwd.clone();
                let mut spawned = s.spawn(policy, opts)?;
                spawned.post_wait = Some(PostWait::MacVmSyncBack {
                    cfg: macvm::load_config().unwrap_or_else(|_| macvm::MacVmConfig::default()),
                    project,
                });
                Ok(spawned)
            }
            #[cfg(target_os = "windows")]
            Backend::Windows(s) => s.spawn(policy, opts),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_backend_name_accepts_uniform_dispatch_set() {
        assert_eq!(parse_backend_name("auto"), Ok(BackendName::Auto));
        assert_eq!(parse_backend_name("default"), Ok(BackendName::Auto));
        assert_eq!(parse_backend_name("process"), Ok(BackendName::Process));
        assert_eq!(parse_backend_name("mac-vm"), Ok(BackendName::MacVm));
        assert_eq!(parse_backend_name("macvm"), Ok(BackendName::MacVm));
        assert_eq!(parse_backend_name("wsl2"), Ok(BackendName::Wsl2));
        assert_eq!(
            parse_backend_name("win-sandbox"),
            Ok(BackendName::WinSandbox)
        );
        assert_eq!(
            parse_backend_name("windows-sandbox"),
            Ok(BackendName::WinSandbox)
        );
    }

    #[test]
    fn parse_backend_name_rejects_unknown_with_valid_list() {
        let err = parse_backend_name("qemu").expect_err("unknown backend must fail");
        assert!(err.contains("unknown backend 'qemu'"), "{err}");
        for name in ["auto", "process", "mac-vm", "wsl2", "win-sandbox"] {
            assert!(err.contains(name), "{err}");
        }
    }

    #[test]
    fn valid_backends_string_lists_uniform_dispatch_set() {
        for name in ["auto", "process", "mac-vm", "wsl2", "win-sandbox"] {
            assert!(VALID_BACKENDS.contains(name), "{VALID_BACKENDS}");
        }
    }
}
