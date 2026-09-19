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

use std::path::{Path, PathBuf};

use crate::policy::Policy;

/// Result of analyzing whether a resolved deny path overlaps with granted roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyOverlapReport {
    pub denied_path: PathBuf,
    pub inside_grant: bool,
    pub conflicting_root: Option<PathBuf>,
}

/// Analyze whether any resolved deny paths overlap with (sit inside) any granted
/// read or write roots.
///
/// On backends where access is default-deny outside explicit grants (such as
/// Windows AppContainer), a deny path outside all granted roots is safely
/// isolated by construction. However, a deny path sitting inside a granted root
/// cannot be carved out by AppContainer capabilities and constitutes a security
/// conflict that must fail closed.
pub fn analyze_deny_overlap(policy: &Policy) -> Vec<DenyOverlapReport> {
    let granted_roots: Vec<&Path> = policy
        .allow_write
        .iter()
        .chain(policy.allow_read.iter())
        .map(|root| root.as_path())
        .collect();

    policy
        .deny_resolved
        .iter()
        .map(|denied| {
            let conflicting = granted_roots
                .iter()
                .copied()
                .find(|root| path_is_inside(&denied.path, root))
                .map(|r| r.to_path_buf());
            let inside_grant = conflicting.is_some();
            DenyOverlapReport {
                denied_path: denied.path.clone(),
                inside_grant,
                conflicting_root: conflicting,
            }
        })
        .collect()
}

fn path_is_inside(candidate: &Path, root: &Path) -> bool {
    let mut roots = root.components();
    let mut candidates = candidate.components();
    loop {
        match (candidates.next(), roots.next()) {
            // Every root component matched: candidate equals the root or lies underneath it.
            (_, None) => return true,
            // Candidate exhausted while root components remain: candidate is a strict prefix of root.
            (None, Some(_)) => return false,
            (Some(cand), Some(root_component)) => {
                if !component_matches(cand, root_component) {
                    return false;
                }
            }
        }
    }
}

fn component_matches(left: std::path::Component<'_>, right: std::path::Component<'_>) -> bool {
    use std::path::Component;
    match (left, right) {
        (Component::Prefix(l), Component::Prefix(r)) => l
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&r.as_os_str().to_string_lossy()),
        (Component::RootDir, Component::RootDir) => true,
        (Component::CurDir, Component::CurDir) => true,
        (Component::ParentDir, Component::ParentDir) => true,
        (Component::Normal(l), Component::Normal(r)) => {
            #[cfg(windows)]
            {
                l.to_string_lossy()
                    .eq_ignore_ascii_case(&r.to_string_lossy())
            }
            #[cfg(not(windows))]
            {
                l == r
            }
        }
        _ => false,
    }
}

#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(unix)]
use anyhow::{bail, Result};

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

    let (out_r, out_w) = pipe2()?;
    let (err_r, err_w) = pipe2()?;
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

    // Consume the OwnedFds into Files (taking ownership, no double close).
    // Read to EOF before waiting: the pipes close when the probe exits.
    let mut output = String::new();
    let mut out_file: std::fs::File = out_r.into();
    let _ = out_file.read_to_string(&mut output);
    let mut eout = String::new();
    let mut err_file: std::fs::File = err_r.into();
    let _ = err_file.read_to_string(&mut eout);
    let _prod_res = spawned.wait_collect();

    Ok(ProbeOutput {
        stdout: output,
        stderr: eout,
    })
}

#[cfg(unix)]
fn pipe2() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    for fd in fds {
        // SAFETY: fd came from the successful pipe call.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors came from the successful pipe call.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            bail!("fcntl(F_GETFD): {error}");
        }
        // SAFETY: fd came from the successful pipe call; preserve existing
        // descriptor flags while adding close-on-exec.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors came from the successful pipe call.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            bail!("fcntl(F_SETFD, FD_CLOEXEC): {error}");
        }
    }
    // SAFETY: fresh descriptors from a successful pipe and CLOEXEC setup.
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}
