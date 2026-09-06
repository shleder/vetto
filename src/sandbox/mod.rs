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
                    // Integration point for feat/uniform-mac-vm: construct
                    // `Backend::MacVm` here once that branch merges its variant.
                    // cfg-gate keeps every platform building until then.
                    #[cfg(target_os = "macos")]
                    {
                        anyhow::bail!(
                            "--backend mac-vm is not yet integrated (feat/uniform-mac-vm not merged)\n\
                             action: omit the flag (legacy Seatbelt process backend applies, deprecated) or retry after the mac-vm branch lands; run `vetto doctor` for the enforcement matrix"
                        );
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
            Backend::Macos(_) => {
                "macos seatbelt (legacy process-only, use mac-vm for Tier-1)".into()
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
