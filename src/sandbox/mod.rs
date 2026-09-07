//! Sandbox backends and the fail-closed factory.
//!
//! Rule #1 of vetto: if no enforcement backend can be established, the agent
//! does NOT run. There is never an unsandboxed fallback.

pub mod handle;
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

// Kept outside `macos/mod.rs` so the security worker remains untouched.  The
// broker is an opt-in library surface for later integration, not part of the
// Seatbelt spawn path.
#[cfg(target_os = "macos")]
#[path = "macos/net_proxy.rs"]
pub mod macos_net_proxy;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "windows")]
pub mod wsl2;

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
    // NOTE: mac-vm sync-back lives on feat/uniform-mac-vm (macOS-only
    // config type). This branch must not reference that crate:
    // Linux/Windows CI would fail with E0433.
    #[cfg(target_os = "windows")]
    Wsl2SyncBack {
        cfg: wsl2::Wsl2Config,
        project: std::path::PathBuf,
    },
}

impl PostWait {
    /// Run the post-wait hook. Fail-LOUD (error, never silent): a failed
    /// sync-back means the host tree is stale — the guest keeps the truth.
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            #[cfg(target_os = "windows")]
            PostWait::Wsl2SyncBack { cfg, project } => {
                wsl2::sync::sync_from_guest(&cfg, &project)
            }
            // Non-VM platform builds: no PostWait variant exists here, so
            // this arm keeps `run` total where the enum is empty.
            #[allow(unreachable_patterns)]
            _ => anyhow::bail!("post-wait: no VM sync-back hook on this platform build"),
        }
    }
}

/// Selected enforcement backend for this session.
pub enum Backend {
    #[cfg(target_os = "linux")]
    Linux(Box<linux::LinuxSandbox>),
    #[cfg(target_os = "macos")]
    Macos(Box<macos::MacosSandbox>),
    #[cfg(target_os = "windows")]
    Windows(Box<windows::WindowsSandbox>),
    #[cfg(target_os = "windows")]
    Wsl2(Box<wsl2::Wsl2Sandbox>),
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
            match name {
                "auto" | "default" => {}
                "process" => {}
                "wsl2" => {
                    #[cfg(target_os = "windows")]
                    {
                        // Uniform path: Tier-1 inside the WSL2 distro.
                        // Missing WSL2 fails closed, never a silent
                        // AppContainer run.
                        let cfg = wsl2::load_config()?;
                        let avail = wsl2::Wsl2Sandbox::probe_availability_with(&cfg);
                        if !avail.available {
                            anyhow::bail!(
                                "wsl2 unavailable: {}\n\
                                 action: start the distro (`wsl -d {}`), check the guest vetto, or pass explicit `--backend process` (deprecated legacy); run `vetto doctor` for the enforcement matrix",
                                avail.reason,
                                cfg.effective_distro()
                            );
                        }
                        return Ok(Backend::Wsl2(Box::new(wsl2::Wsl2Sandbox::new(
                            net, cfg,
                        ))));
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        anyhow::bail!(
                            "--backend wsl2 is only available on Windows (WSL2 host)\n\
                             action: use `--backend auto` on this operating system; run `vetto doctor` for supported backends"
                        );
                    }
                }
                "win-sandbox" | "windows-sandbox" => {
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
                other => {
                    anyhow::bail!(
                        "unknown backend '{other}'; valid backends: auto, process, wsl2, win-sandbox\n\
                         action: select a valid backend or omit the flag; run `vetto doctor` for the full capability picture"
                    );
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
            #[cfg(target_os = "windows")]
            Backend::Windows(_) => None,
            #[cfg(target_os = "windows")]
            Backend::Wsl2(_) => Some(Tier::Full),
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
            Backend::Macos(_) => "macos seatbelt (deprecated sandbox-exec, works today)".into(),
            #[cfg(target_os = "windows")]
            Backend::Windows(s) => format!("windows process sandbox ({})", s.capabilities.summary()),
            #[cfg(target_os = "windows")]
            Backend::Wsl2(s) => format!(
                "wsl2 tier-1 (distro `{}`, guest Linux vetto owns Landlock/seccomp/namespaces)",
                s.cfg.effective_distro()
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
            #[cfg(target_os = "windows")]
            Backend::Windows(s) => s.spawn(policy, opts),
            #[cfg(target_os = "windows")]
            Backend::Wsl2(s) => s.spawn(policy, opts),
        }
    }
}
