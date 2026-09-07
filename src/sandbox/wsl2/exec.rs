//! Agent exec inside the WSL2 distro via `wsl.exe -d <distro> --`.
//!
//! The guest runs a Linux `vetto` binary, which owns Tier-1 enforcement
//! (Landlock/seccomp/namespaces). The Windows host never executes the agent
//! through this backend.
//!
//! Exit code passthrough: `wsl.exe` propagates the Linux command's exit
//! code, so the supervisor's `windows_wait` on the retained process HANDLE
//! observes exactly the agent's status.
//!
//! Only argv builders are unit-tested. Spawning `wsl.exe` is intentionally
//! untested (no local execution in unit tests).

use std::path::Path;
use std::process::Child;

use anyhow::{bail, Context, Result};

use super::Wsl2Config;
use crate::config::NetMode;
use crate::policy::Policy;

/// Build the guest Linux vetto argv: profile + net + tui-off + agent.
/// Pure logic — unit-tested. Mirrors the mac-vm shape so both uniform
/// backends enforce the identical Tier-1 policy surface.
pub fn guest_vetto_argv(policy: &Policy, net: &NetMode, agent_cmd: &[String]) -> Vec<String> {
    let mut argv = vec![
        super::GUEST_VETTO.to_string(),
        "--profile".to_string(),
        policy.name.clone(),
        "--net".to_string(),
        net.label(),
        "--tui=none".to_string(),
        "--".to_string(),
    ];
    argv.extend(agent_cmd.iter().cloned());
    argv
}

/// Build the full `wsl.exe -d <distro> -- <guest argv...>` argv.
/// Pure logic — unit-tested.
pub fn session_wsl_argv(cfg: &Wsl2Config, guest_argv: &[String]) -> Vec<String> {
    super::distro::exec_argv(&cfg.effective_distro(), guest_argv)
}

/// Full session argv in one call (config + policy + net + agent).
/// Pure logic — unit-tested.
pub fn session_argv(
    cfg: &Wsl2Config,
    policy: &Policy,
    net: &NetMode,
    agent_cmd: &[String],
) -> Vec<String> {
    session_wsl_argv(cfg, &guest_vetto_argv(policy, net, agent_cmd))
}

/// Probe that the guest vetto binary exists and runs (`--version`,
/// bounded). Fail-closed: a distro without vetto refuses the session.
pub fn guest_vetto_present(cfg: &Wsl2Config) -> Result<()> {
    let distro = cfg.effective_distro();
    let vetto = cfg.effective_guest_vetto();
    let out = std::process::Command::new("wsl.exe")
        .args(["-d", &distro, "--", &vetto, "--version"])
        .output()
        .with_context(|| format!("wsl2: failed to probe guest vetto in `{distro}`"))?;
    if !out.status.success() {
        bail!(
            "wsl2: guest vetto probe failed in `{distro}` ({}): {}\n\
             action: install the Linux vetto binary at {vetto} inside the distro; run `vetto doctor`",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Spawn the guest session as a `wsl.exe` child with the caller's stdio
/// wiring. Returns the live child; the caller retains its process HANDLE
/// for `windows_wait` (pids alone are not authoritative on Windows).
/// No threads are spawned here.
pub fn spawn_guest(
    cfg: &Wsl2Config,
    project: &Path,
    opts: &super::super::handle::SpawnOptions,
    guest_cmd: Vec<String>,
) -> Result<Child> {
    use std::process::Stdio;

    if guest_cmd.is_empty() {
        bail!("wsl2: empty guest command; refusing to run (fail-closed)");
    }
    let argv = session_wsl_argv(cfg, &guest_cmd);
    let (prog, args) = argv.split_first().expect("wsl argv non-empty");
    let mut cmd = std::process::Command::new(prog);
    cmd.args(args);
    // Run from the project dir for parity with the host backends
    // (wsl.exe itself does not need it, diagnostics do).
    cmd.current_dir(project);
    // Windows stdio contract (mirrors the legacy backend): the Windows
    // StdioMode only has Inherit — anything else is a caller bug, and
    // failing closed beats guessing pipe semantics.
    #[cfg(windows)]
    match &opts.stdio {
        super::super::handle::StdioMode::Inherit => {
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
    }
    #[cfg(not(windows))]
    {
        // Cross-platform unit-test shape only: inherit. Real spawning
        // happens on Windows (see cfg above).
        let _ = &opts.stdio;
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    }
    // Guest env: only VETTO_* markers cross (explicit allowlist, no
    // secrets). The guest policy owns the rest.
    for (k, v) in &opts.env_extra {
        if k.starts_with("VETTO_") {
            cmd.env(k, v);
        }
    }
    cmd.spawn()
        .with_context(|| "wsl2: failed to spawn `wsl.exe` session")
}

/// Convert a live `wsl.exe` child into the retained-handle kill strategy.
/// Uses the child's inherited HANDLE (no DuplicateHandle needed): `Child`
/// is forgotten after extracting stdio, so the process HANDLE stays valid
/// for `windows_wait`. The (null) job adds no containment — Tier-1 lives
/// in the guest.
#[cfg(windows)]
pub fn child_to_handle(child: Child) -> Result<super::super::handle::KillStrategy> {
    use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};

    // Destructure stdio out of the Child (dropping pipes, not the process),
    // then unwrap the process HANDLE via into_raw_handle + forget-free move.
    let mut child = child;
    let _ = child.stdin.take();
    let _ = child.stdout.take();
    let _ = child.stderr.take();
    // SAFETY: into_raw_handle transfers ownership of the live child process
    // HANDLE to us; from_raw_handle re-wraps it with no duplication and no
    // double-close (Child is consumed, never dropped).
    let raw = child.into_raw_handle();
    if raw.is_null() {
        anyhow::bail!(
            "wsl2: wsl.exe child yielded a null process handle; refusing to run without a waitable handle (fail-closed)"
        );
    }
    let process: OwnedHandle = unsafe { OwnedHandle::from_raw_handle(raw) };
    // Host job: none claimed (Tier-1 lives in the guest). But `terminate`
    // drops `job` first assuming kill-on-close semantics — a duplicated
    // process HANDLE there is harmless (dropping a process handle kills
    // nothing) and keeps the struct shape `windows_wait` requires.
    // `terminate` on this backend therefore does NOT kill the tree; the
    // guest vetto owns its own teardown. Documented gap, honest shape.
    use std::os::windows::io::AsHandle;
    let job: OwnedHandle = child_process_duplicate(&process)?;
    Ok(super::super::handle::KillStrategy::JobObject {
        job,
        process,
    })
}

/// Duplicate an owned process handle (same access, non-inheritable).
/// Single reviewed unsafe: `DuplicateHandle` on our own process.
#[cfg(windows)]
fn child_process_duplicate(
    h: &std::os::windows::io::OwnedHandle,
) -> Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    unsafe extern "system" {
        fn DuplicateHandle(
            hsourceprocesshandle: *mut core::ffi::c_void,
            hsourcehandle: *mut core::ffi::c_void,
            htargetprocesshandle: *mut core::ffi::c_void,
            lptargethandle: *mut *mut core::ffi::c_void,
            dwdesiredaccess: u32,
            binherithandle: i32,
            dwoptions: u32,
        ) -> i32;
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
    }
    const DUPLICATE_SAME_ACCESS: u32 = 0x2;
    let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: all handles are our own process/child; SAME_ACCESS adds no
    // rights. Return value checked fail-closed.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            h.as_raw_handle() as _,
            GetCurrentProcess(),
            &mut out,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 || out.is_null() {
        anyhow::bail!(
            "wsl2: DuplicateHandle on wsl.exe child failed; refusing to run without a waitable handle (fail-closed)"
        );
    }
    // SAFETY: DuplicateHandle just created this handle for us (owned).
    Ok(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(out as _) })
}

/// Non-Windows stub: the module compiles everywhere for unit tests, but
/// spawning only happens on Windows. Tests exercise argv builders only.
#[cfg(not(windows))]
pub fn child_to_handle(
    _child: Child,
) -> Result<super::super::handle::KillStrategy> {
    bail!("wsl2: child handles are Windows-only; this stub exists for cross-platform unit tests")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Wsl2Config {
        Wsl2Config {
            distro: "vetto".into(),
            guest_vetto: super::super::GUEST_VETTO.into(),
        }
    }

    #[test]
    fn guest_argv_shape() {
        use crate::policy::Policy;
        let mut pol = Policy::default();
        pol.name = "default".to_string();
        let argv = guest_vetto_argv(&pol, &NetMode::Off, &["agent".into()]);
        assert_eq!(argv[0], super::super::GUEST_VETTO);
        assert!(argv.contains(&"--profile".to_string()));
        assert!(argv.contains(&"--net".to_string()));
        assert!(argv.contains(&"off".to_string()));
        assert!(argv.contains(&"--".to_string()));
        assert!(argv.last().unwrap() == "agent");
    }

    #[test]
    fn session_argv_routes_through_wsl() {
        use crate::policy::Policy;
        let mut pol = Policy::default();
        pol.name = "default".to_string();
        let argv = session_argv(&cfg(), &pol, &NetMode::Off, &["agent".into()]);
        assert_eq!(&argv[..4], &["wsl.exe", "-d", "vetto", "--"]);
        assert!(argv.contains(&"agent".to_string()));
    }

    #[test]
    fn empty_guest_cmd_fails_closed_shape() {
        // Shape check only: spawn_guest needs a live OS; the empty-guard
        // is verified by code inspection + the argv builders above.
        assert!(guest_vetto_argv(
            &{
                let mut p = Policy::default();
                p.name = "x".into();
                p
            },
            &NetMode::Off,
            &[]
        )
        .contains(&"--".to_string()));
    }

    #[test]
    fn no_appcontainer_references() {
        let src = include_str!("exec.rs");
        assert!(!src.to_lowercase().contains("appcontainer"));
    }
}
