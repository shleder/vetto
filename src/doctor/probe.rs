//! Shared throwaway-sandbox probe: ONE spawn of the real enforcement backend
//! running a POSIX-sh script that self-reports verdicts on stdout.
//!
//! Line protocol (pipe-delimited):
//!   D|<path>|contents-denied|content-readable   deny directory contents
//!   F|<path>|<bytes>|unreadable                 deny file read
//!   NET|reachable|unreachable|nobash            loopback listener connect
//!   WRITE|allowed|denied                        write outside every write root
//!
//! Callers attach variable targets as trailing script arguments: plain deny
//! paths, `NETCHECK:<port>` for the loopback probe, `WRITECHECK:<path>` for
//! the write-outside probe.

pub use crate::policy::types::{analyze_deny_overlap, DenyOverlapReport};

#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use crate::policy::Policy;

#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::os::fd::AsRawFd;

#[cfg(unix)]
use anyhow::Result;

#[cfg(unix)]
use crate::config::NetMode;
#[cfg(unix)]
use crate::sandbox;

#[cfg(unix)]
pub struct ProbeOutput {
    pub stdout: String,
    pub stderr: String,
}

/// FS-ONLY honesty constraint: directory ENTRY NAMES may remain visible
/// (Landlock is access control, not a visibility overlay), so the security
/// property checked for denied directories is that no file CONTENT beneath
/// them can be read. Overlaid files appear EMPTY (0 bytes).
#[cfg(unix)]
const PROBE_SCRIPT: &str = r##"for p in "$@"; do
  case "$p" in
    NETCHECK:*)
      port=${p#NETCHECK:}
      if command -v bash >/dev/null 2>&1; then
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
          echo "NET|reachable"
        else
          echo "NET|unreachable"
        fi
      else
        echo "NET|nobash"
      fi
      ;;
    WRITECHECK:*)
      target=${p#WRITECHECK:}
      if dd if=/dev/null of="$target" bs=1 count=1 2>/dev/null; then
        echo "WRITE|allowed"
      else
        echo "WRITE|denied"
      fi
      ;;
    *)
      if [ -d "$p" ]; then
        leak=0
        for f in "$p"/* "$p"/.[!.]* "$p"/..?*; do
          [ -f "$f" ] || continue
          if dd if="$f" of=/dev/null bs=1 count=1 >/dev/null 2>&1; then leak=1; break; fi
        done
        if [ "$leak" -eq 0 ]; then
          echo "D|$p|contents-denied"
        else
          echo "D|$p|content-readable"
        fi
      else
        n=$(wc -c <"$p" 2>/dev/null) || { echo "F|$p|unreadable"; continue; }
        echo "F|$p|$n"
      fi
      ;;
  esac
done"##;

/// Build the throwaway sandbox from `pol`, run the probe script with
/// `script_args`, and collect its output. The sandbox network mode is always
/// Off: the battery verifies the default-enforced boundary, and relay modes
/// (`allowlist`/`strict`) only add a broker on top of the same
/// netns/seccomp base, so direct-egress isolation is identical.
#[cfg(unix)]
pub fn run_probe_script(
    pol: &Policy,
    project: &Path,
    script_args: Vec<String>,
) -> Result<ProbeOutput> {
    let backend = sandbox::Backend::detect(NetMode::Off, false)?;
    let mut agent_cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        PROBE_SCRIPT.to_string(),
        "vetto-probe".to_string(),
    ];
    agent_cmd.extend(script_args);

    let (out_r, out_w) = sandbox::create_cloexec_pipe()?;
    let (err_r, err_w) = sandbox::create_cloexec_pipe()?;
    let stdio = sandbox::StdioMode::Captured {
        stdout_w: out_w.as_raw_fd(),
        stderr_w: err_w.as_raw_fd(),
    };
    let unprepared = crate::sandbox::production::UnpreparedProductionExecution::new(
        backend,
        pol.clone(),
        agent_cmd,
        project.to_path_buf(),
        HashMap::new(),
        NetMode::Off,
        None,
        stdio,
        "probe".to_string(),
    );
    let prepared = unprepared.prepare()?;
    let spawned = prepared.spawn()?;
    drop(out_w);
    drop(err_w);

    // Concurrently drain captured stdout and stderr using AsyncPipeReader (INV-25).
    // Prevents probe execution deadlock if child writes >64KB to stderr before stdout closes.
    let out_reader = crate::sandbox::production::AsyncPipeReader::spawn(
        out_r,
        crate::sandbox::production::PROD_MAX_STDIO,
        std::time::Duration::from_millis(500),
    );
    let err_reader = crate::sandbox::production::AsyncPipeReader::spawn(
        err_r,
        crate::sandbox::production::PROD_MAX_STDIO,
        std::time::Duration::from_millis(500),
    );
    let _prod_res = spawned.wait_collect();
    out_reader.notify_child_exited();
    err_reader.notify_child_exited();
    let output = String::from_utf8_lossy(&out_reader.join()).to_string();
    let eout = String::from_utf8_lossy(&err_reader.join()).to_string();

    Ok(ProbeOutput {
        stdout: output,
        stderr: eout,
    })
}
