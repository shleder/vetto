//! Sandbox backends and the fail-closed factory.
//!
//! Rule #1 of vetto: if no enforcement backend can be established, the agent
//! does NOT run. There is never an unsandboxed fallback.

pub mod handle;
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

pub use handle::{SandboxHandle, SpawnOptions, StdioMode};

use std::os::fd::OwnedFd;

use crate::config::NetMode;
use crate::policy::{Policy, Tier};

/// Everything `Backend::spawn` hands back to the supervisor besides the
/// waitable handle itself.
pub struct Spawned {
    pub handle: SandboxHandle,
    /// Broker end of the relay control socketpair (`--net=allowlist`).
    /// `main` passes it to `net_relay::spawn_broker` which takes ownership.
    pub broker_ctrl_fd: Option<OwnedFd>,
    /// Loopback port the in-netns relay listens on (allowlist mode).
    pub relay_port: Option<u16>,
    /// seccomp user-notify listener fd (`--observe-seccomp`); `main` passes
    /// it to `observe_seccomp::spawn_notifier` which takes ownership.
    pub notif_listener: Option<OwnedFd>,
}

/// Selected enforcement backend for this session.
pub enum Backend {
    Linux(Box<linux::LinuxSandbox>),
    #[cfg(target_os = "macos")]
    Macos(Box<macos::MacosSandbox>),
}

impl Backend {
    /// Detect the strongest usable backend on this platform. Fails closed.
    pub fn detect(net: NetMode, observe_seccomp: bool) -> anyhow::Result<Self> {
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
            Ok(Backend::Macos(Box::new(macos::MacosSandbox::new(net))))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (net, observe_seccomp);
            Err(anyhow::anyhow!(
                crate::error::VettoError::UnsupportedPlatform("this platform")
            ))
        }
    }

    pub fn tier(&self) -> Option<Tier> {
        match self {
            Backend::Linux(s) => Some(s.tier),
            #[cfg(target_os = "macos")]
            Backend::Macos(_) => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Backend::Linux(s) => format!(
                "linux tier={} (landlock ABI {:?}, userns={}, seccomp-notify={}, audit-feed={})",
                s.tier.label(),
                s.probe.landlock_abi,
                s.probe.userns_available,
                s.probe.seccomp_notify_available,
                s.probe.audit_feed_readable,
            ),
            #[cfg(target_os = "macos")]
            Backend::Macos(_) => "macos seatbelt (deprecated sandbox-exec, works today)".into(),
        }
    }

    /// Spawn the agent inside the sandbox. Consumes the backend: enforcement
    /// state is applied in the forked child before exec.
    ///
    /// IRON RULE: must be called before any thread/tokio runtime exists —
    /// every fork inside is only safe from a single-threaded process.
    pub fn spawn(self, policy: &Policy, opts: SpawnOptions) -> anyhow::Result<Spawned> {
        match self {
            Backend::Linux(s) => s.spawn(policy, opts),
            #[cfg(target_os = "macos")]
            Backend::Macos(s) => s.spawn(policy, opts),
        }
    }
}
