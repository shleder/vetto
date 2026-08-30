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

pub use handle::{SandboxHandle, SpawnOptions, StdioMode};

#[cfg(unix)]
use std::os::fd::OwnedFd;

use crate::config::NetMode;
use crate::policy::{Policy, Tier};

/// Everything `Backend::spawn` hands back to the supervisor besides the
/// waitable handle itself.
pub struct Spawned {
    pub handle: SandboxHandle,
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

/// Selected enforcement backend for this session.
pub enum Backend {
    #[cfg(target_os = "linux")]
    Linux(Box<linux::LinuxSandbox>),
    #[cfg(target_os = "macos")]
    Macos(Box<macos::MacosSandbox>),
    #[cfg(target_os = "windows")]
    Windows(Box<windows::WindowsSandbox>),
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
                        "unknown backend '{other}'; valid backends: auto, process, win-sandbox\n\
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
        }
    }
}
