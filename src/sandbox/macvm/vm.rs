//! VM lifecycle via the `vz` CLI helper (Apple Virtualization.framework).
//!
//! The helper is an external binary (default `vetto-vz`, override with
//! `VETTO_VZ_HELPER`). It owns VM creation and the virtualization stack;
//! vetto only orchestrates: status → start (bounded) → wait for ssh.
//! No VM → fail-closed with an action, never a host run.
//!
//! Only parsing/argv builders are unit-tested. Anything that spawns a
//! process is intentionally untested (no local execution in unit tests).

use anyhow::{bail, Context, Result};

use super::MacVmConfig;

/// Parsed `helper status` output. Pure data — unit-tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmStatus {
    /// Raw state string from the helper (e.g. `running`, `stopped`).
    pub state: String,
    /// True only for the exact `running` state.
    pub running: bool,
    /// Guest IP when reported.
    pub ip: Option<String>,
}

/// Parse one line of `helper status` output: `state=<state>[ ip=<ip>]`.
/// Pure logic — unit-tested.
pub fn parse_status_line(line: &str) -> Result<VmStatus> {
    let line = line.trim();
    let rest = line
        .strip_prefix("state=")
        .ok_or_else(|| anyhow::anyhow!("mac-vm: malformed helper status line: {line:?}"))?;
    let mut parts = rest.split_whitespace();
    let state = parts.next().unwrap_or("").trim().to_string();
    if state.is_empty() {
        bail!("mac-vm: helper status line has empty state: {line:?}");
    }
    let mut ip = None;
    for part in parts {
        if let Some(addr) = part.strip_prefix("ip=") {
            if !addr.trim().is_empty() {
                ip = Some(addr.trim().to_string());
            }
        }
    }
    let running = state == "running";
    Ok(VmStatus { state, running, ip })
}

/// Build `helper status` argv. Pure logic — unit-tested.
pub fn status_argv(helper: &str) -> Vec<String> {
    vec![helper.to_string(), "status".to_string()]
}

/// Build `helper start` argv. Pure logic — unit-tested.
pub fn start_argv(helper: &str) -> Vec<String> {
    vec![helper.to_string(), "start".to_string()]
}

/// Build `helper stop` argv. Pure logic — unit-tested.
pub fn stop_argv(helper: &str) -> Vec<String> {
    vec![helper.to_string(), "stop".to_string()]
}

/// True when the helper binary resolves in PATH (or is an absolute path).
/// No output parsing: presence only. Reachability is checked separately.
pub fn helper_present(helper: &str) -> bool {
    if helper.contains('/') {
        return std::path::Path::new(helper).exists();
    }
    std::env::var_os("PATH").map_or(false, |paths| {
        std::env::split_paths(&paths).any(|dir| {
            dir.join(helper).exists() || dir.join(format!("{helper}.exe")).exists()
        })
    })
}

/// Query helper status (blocking, bounded by the helper itself).
/// Fail-closed on any error.
pub fn helper_status(helper: &str) -> Result<VmStatus> {
    let out = std::process::Command::new(helper)
        .arg("status")
        .output()
        .with_context(|| format!("mac-vm: failed to run `{helper} status`"))?;
    if !out.status.success() {
        bail!(
            "mac-vm: `{helper} status` exited {}: {}\n\
             action: reinstall the VM helper and ensure the VM exists; run `vetto doctor`",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| anyhow::anyhow!("mac-vm: `{helper} status` printed no status line"))?;
    parse_status_line(line)
}

/// Ensure the VM is running: query status, `start` when stopped, then wait
/// for ssh reachability within `ip_wait_secs`. Bounded and fail-closed.
pub fn ensure_running(cfg: &MacVmConfig) -> Result<()> {
    let helper = cfg.effective_helper();
    if !helper_present(&helper) {
        bail!(
            "mac-vm: helper `{helper}` not found in PATH\n\
             action: install the VM helper (`vetto-vz`) and create the Linux VM; run `vetto doctor` for the full capability picture"
        );
    }
    match helper_status(&helper) {
        Ok(s) if s.running => return super::exec::ssh_wait_ready(cfg),
        Ok(s) => {
            tracing::debug!("mac-vm: VM state is `{}`; starting", s.state);
        }
        Err(e) => {
            tracing::debug!("mac-vm: status query failed ({e:#}); attempting start");
        }
    }
    let start = std::process::Command::new(&helper)
        .arg("start")
        .output()
        .with_context(|| format!("mac-vm: failed to run `{helper} start`"))?;
    if !start.status.success() {
        bail!(
            "mac-vm: `{helper} start` exited {}: {}\n\
             action: check the VM helper logs and retry; run `vetto doctor`",
            start.status,
            String::from_utf8_lossy(&start.stderr).trim()
        );
    }
    super::exec::ssh_wait_ready(cfg)
}

/// Best-effort stop (used for teardown paths only; never gates a session).
pub fn stop(cfg: &MacVmConfig) -> Result<()> {
    let helper = cfg.effective_helper();
    let out = std::process::Command::new(&helper)
        .arg("stop")
        .output()
        .with_context(|| format!("mac-vm: failed to run `{helper} stop`"))?;
    if !out.status.success() {
        bail!(
            "mac-vm: `{helper} stop` exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_running_with_ip() {
        let s = parse_status_line("state=running ip=192.168.64.2\n").unwrap();
        assert!(s.running);
        assert_eq!(s.ip.as_deref(), Some("192.168.64.2"));
    }

    #[test]
    fn parse_stopped_without_ip() {
        let s = parse_status_line("state=stopped").unwrap();
        assert!(!s.running);
        assert_eq!(s.ip, None);
        assert_eq!(s.state, "stopped");
    }

    #[test]
    fn parse_malformed_fails_closed() {
        assert!(parse_status_line("").is_err());
        assert!(parse_status_line("running").is_err());
        assert!(parse_status_line("state=   ").is_err());
    }

    #[test]
    fn argv_builders() {
        assert_eq!(status_argv("vetto-vz"), vec!["vetto-vz", "status"]);
        assert_eq!(start_argv("vetto-vz"), vec!["vetto-vz", "start"]);
        assert_eq!(stop_argv("vetto-vz"), vec!["vetto-vz", "stop"]);
    }

    #[test]
    fn helper_present_rejects_garbage() {
        assert!(!helper_present("vetto-vz-definitely-missing-xyz"));
        assert!(!helper_present("/nonexistent/path/to/helper"));
    }
}
