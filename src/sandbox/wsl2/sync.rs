//! Workspace sync host<->guest via the `\\wsl$\<distro>` UNC bridge.
//!
//! Invariant: the guest NEVER runs with a stale workspace. `sync_to_guest`
//! verifies the post-sync marker; a mismatch → `bail!`, no exec.
//! `sync_from_guest` is fail-LOUD after the agent exits (a failed pull is
//! an error, never silent — the guest keeps the truth and the error tells
//! where).
//!
//! Only argv builders and marker parse/format are unit-tested. The file
//! copies themselves run on the supervisor thread and are intentionally
//! untested.

use std::path::Path;

use anyhow::{bail, Context, Result};

use super::Wsl2Config;
use super::GUEST_WORKSPACE;

/// Marker file written into the guest workspace after a successful push.
/// Format: `v=1 files=<n> stamp=<unix-secs>\n`. Parsed back fail-closed.
pub const MARKER_NAME: &str = ".vetto-sync";

/// Format the sync marker. Pure logic — unit-tested.
pub fn format_marker(files: u64, stamp: u64) -> String {
    format!("v=1 files={files} stamp={stamp}\n")
}

/// Parse the sync marker back. Pure logic — unit-tested, fail-closed.
pub fn parse_marker(text: &str) -> Result<(u64, u64)> {
    let line = text.trim();
    let rest = line
        .strip_prefix("v=1 ")
        .ok_or_else(|| anyhow::anyhow!("wsl2: malformed sync marker: {line:?}"))?;
    let mut files = None;
    let mut stamp = None;
    for part in rest.split_whitespace() {
        if let Some(v) = part.strip_prefix("files=") {
            files = v.parse::<u64>().ok();
        } else if let Some(v) = part.strip_prefix("stamp=") {
            stamp = v.parse::<u64>().ok();
        }
    }
    match (files, stamp) {
        (Some(f), Some(s)) => Ok((f, s)),
        _ => bail!("wsl2: malformed sync marker: {line:?}"),
    }
}

/// UNC root for the distro, e.g. `\\wsl$\vetto`. Pure logic — unit-tested.
pub fn unc_root(distro: &str) -> String {
    format!(r"\\wsl$\{distro}")
}

/// Translate a guest absolute path to its host UNC path.
/// Pure logic — unit-tested. Only paths under `/` map; anything else fails.
pub fn guest_to_unc(distro: &str, guest_path: &str) -> Result<String> {
    if !guest_path.starts_with('/') {
        bail!("wsl2: guest path must be absolute: {guest_path:?}");
    }
    // `/mnt/vetto-workspace/x` → `\\wsl$\<distro>\mnt\vetto-workspace\x`
    let rel = guest_path.trim_start_matches('/').replace('/', "\\");
    Ok(format!("{}\\{rel}", unc_root(distro)))
}

/// Push workspace host → guest, then verify the marker round-trip.
/// Fail-closed: a push that did not land refuses the exec.
pub fn sync_to_guest(cfg: &Wsl2Config, project: &Path) -> Result<()> {
    let distro = cfg.effective_distro();
    let guest_ws = GUEST_WORKSPACE;
    // Mirror via robocopy through the UNC bridge (available on every
    // Windows host, no extra tools). `/MIR` mirrors the tree; `/XD` skips
    // the partial dir to avoid feedback loops.
    let dst = guest_to_unc(&distro, guest_ws)?;
    let out = std::process::Command::new("robocopy")
        .arg(project)
        .arg(&dst)
        .args([
            "/MIR",
            "/XD",
            ".vetto-partial",
            "/R:2",
            "/W:1",
            "/NFL",
            "/NDL",
        ])
        .output()
        .with_context(|| "wsl2: failed to spawn robocopy push (host → guest)")?;
    // robocopy exit codes 0-7 are success (copied/extra/mismatch classes);
    // >= 8 is failure. See `robocopy /?` for the bitmask.
    if out.status.code().unwrap_or(8) >= 8 {
        bail!(
            "wsl2: robocopy push exited {}: {}\n\
             action: check the distro is running and the UNC bridge works (`dir \\\\wsl$\\{distro}`); run `vetto doctor`",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // Marker round-trip proves the push landed and the bridge is coherent.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let content = format_marker(count_files(project), stamp);
    let marker_unc = format!("{dst}\\{MARKER_NAME}");
    std::fs::write(&marker_unc, &content)
        .with_context(|| format!("wsl2: marker write failed at {marker_unc:?}"))?;
    let back = std::fs::read_to_string(&marker_unc)
        .with_context(|| format!("wsl2: marker re-read failed at {marker_unc:?}"))?;
    parse_marker(&back).with_context(|| {
        "wsl2: workspace sync verification failed (marker did not round-trip); \
         refusing to run on a stale tree (fail-closed)"
    })?;
    Ok(())
}

/// Pull results guest → host after the agent exits. A failure is an error
/// (never silent): the guest keeps the truth, the message says where.
pub fn sync_from_guest(cfg: &Wsl2Config, project: &Path) -> Result<()> {
    let distro = cfg.effective_distro();
    let src = guest_to_unc(&distro, GUEST_WORKSPACE)?;
    let out = std::process::Command::new("robocopy")
        .arg(&src)
        .arg(project)
        .args([
            "/MIR",
            "/XD",
            ".vetto-partial",
            "/XF",
            MARKER_NAME,
            "/R:2",
            "/W:1",
            "/NFL",
            "/NDL",
        ])
        .output()
        .with_context(|| "wsl2: failed to spawn robocopy pull (guest → host)")?;
    if out.status.code().unwrap_or(8) >= 8 {
        bail!(
            "wsl2: robocopy pull exited {} — host tree may be stale, guest keeps the truth at {src}\n\
             action: re-run the pull manually and check disk space; run `vetto doctor`",
            out.status
        );
    }
    Ok(())
}

fn count_files(dir: &Path) -> u64 {
    // Cheap fingerprint only (marker freshness, not integrity): bounded
    // walk, silently capped. Exactness is not a security property here —
    // the marker only proves the push round-tripped.
    fn walk(dir: &Path, budget: &mut u64, acc: &mut u64) {
        if *budget == 0 {
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            if *budget == 0 {
                return;
            }
            *budget -= 1;
            *acc += 1;
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                walk(&entry.path(), budget, acc);
            }
        }
    }
    let mut acc = 0;
    let mut budget = 50_000;
    walk(dir, &mut budget, &mut acc);
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_round_trip() {
        let m = format_marker(42, 1_700_000_000);
        assert_eq!(parse_marker(&m).unwrap(), (42, 1_700_000_000));
    }

    #[test]
    fn marker_malformed_fails_closed() {
        assert!(parse_marker("").is_err());
        assert!(parse_marker("v=2 files=1 stamp=2").is_err());
        assert!(parse_marker("v=1 files=x stamp=2").is_err());
    }

    #[test]
    fn unc_paths() {
        assert_eq!(unc_root("vetto"), r"\\wsl$\vetto");
        assert_eq!(
            guest_to_unc("vetto", "/mnt/vetto-workspace/x").unwrap(),
            r"\\wsl$\vetto\mnt\vetto-workspace\x"
        );
        assert!(guest_to_unc("vetto", "relative").is_err());
    }
}
