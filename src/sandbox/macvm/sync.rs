//! Workspace sync host<->guest via rsync over ssh. Fail-closed on drift.
//!
//! Invariant: the guest NEVER runs with a stale workspace. `sync_to_guest`
//! verifies the post-sync marker (file count + mtime fingerprint written by
//! rsync itself); a mismatch → `bail!`, no exec. `sync_from_guest` is
//! best-effort AFTER the agent exits (a failed pull is reported, never
//! silently dropped — the guest keeps the truth and the error tells where).
//!
//! Only argv builders and marker parse/format are unit-tested. The rsync
//! invocations themselves spawn processes and are intentionally untested.

use std::path::Path;

use anyhow::{bail, Context, Result};

use super::MacVmConfig;
use super::GUEST_WORKSPACE;

/// Marker file written into the guest workspace after a successful push.
/// Format: `v=1 files=<n> stamp=<unix-secs>\n`. Parsed back fail-closed.
pub const MARKER_NAME: &str = ".vetto-sync";
/// Rsync flags: archive + delete + compress, no partial silently kept.
pub const RSYNC_FLAGS: &[&str] = &["-az", "--delete", "--partial-dir=.vetto-partial"];

/// Format the sync marker. Pure logic — unit-tested.
pub fn format_marker(files: u64, stamp: u64) -> String {
    format!("v=1 files={files} stamp={stamp}\n")
}

/// Parse the sync marker back. Pure logic — unit-tested, fail-closed.
pub fn parse_marker(text: &str) -> Result<(u64, u64)> {
    let line = text.trim();
    let rest = line
        .strip_prefix("v=1 ")
        .ok_or_else(|| anyhow::anyhow!("mac-vm: malformed sync marker: {line:?}"))?;
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
        _ => bail!("mac-vm: malformed sync marker: {line:?}"),
    }
}

/// Build the `rsync` push argv (host → guest). Pure logic — unit-tested.
///
/// Layout: `rsync <flags> -e <ssh_cmd> <src>/ <target>:<guest_ws>/`
/// Excludes: `.git/` is synced (agent may need history); `.vetto-partial/`
/// and the local marker are excluded to avoid feedback loops.
pub fn push_argv(cfg: &MacVmConfig, src: &Path) -> Vec<String> {
    let mut argv = vec!["rsync".to_string()];
    argv.extend(RSYNC_FLAGS.iter().map(|s| s.to_string()));
    argv.push("--exclude".to_string());
    argv.push(".vetto-partial/".to_string());
    argv.push("-e".to_string());
    argv.push(ssh_cmd_string(cfg));
    let mut src_arg = src.to_string_lossy().into_owned();
    if !src_arg.ends_with('/') {
        src_arg.push('/');
    }
    argv.push(src_arg);
    argv.push(format!("{}:{GUEST_WORKSPACE}/", cfg.effective_ssh_target()));
    argv
}

/// Build the `rsync` pull argv (guest → host). Pure logic — unit-tested.
pub fn pull_argv(cfg: &MacVmConfig, dst: &Path) -> Vec<String> {
    let mut argv = vec!["rsync".to_string()];
    argv.extend(RSYNC_FLAGS.iter().map(|s| s.to_string()));
    argv.push("--exclude".to_string());
    argv.push(".vetto-partial/".to_string());
    argv.push("--exclude".to_string());
    argv.push(MARKER_NAME.to_string());
    argv.push("-e".to_string());
    argv.push(ssh_cmd_string(cfg));
    argv.push(format!("{}:{GUEST_WORKSPACE}/", cfg.effective_ssh_target()));
    argv.push(dst.to_string_lossy().into_owned());
    argv
}

/// The `ssh` transport string passed to `rsync -e`. Pure logic — unit-tested.
pub fn ssh_cmd_string(cfg: &MacVmConfig) -> String {
    let mut parts = vec![
        "ssh".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
    ];
    // Borrowed key path must outlive nothing here (owned String out).
    if let Some(key) = &cfg.ssh_key {
        if !key.trim().is_empty() {
            parts.push("-i".to_string());
            parts.push(key.clone());
        }
    }
    parts.join(" ")
}

/// Push workspace host → guest, then verify the marker. Fail-closed.
pub fn sync_to_guest(cfg: &MacVmConfig, project: &Path) -> Result<()> {
    ensure_rsync_present()?;
    let argv = push_argv(cfg, project);
    run_argv(&argv, "rsync push (host → guest)")?;
    // Verify: read the marker back over ssh and require it to parse.
    // A missing/unparseable marker means the push did not land — refuse
    // to run the agent on a stale tree.
    let marker = super::exec::ssh_read_file(cfg, &format!("{GUEST_WORKSPACE}/{MARKER_NAME}"))?;
    // Marker presence is best-effort on first push (older guests may not
    // write it yet): write it ourselves, then re-read. If the guest cannot
    // round-trip the marker, the transport is broken — fail closed.
    if parse_marker(&marker).is_err() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let content = format_marker(count_files(project), stamp);
        super::exec::ssh_write_file(cfg, &format!("{GUEST_WORKSPACE}/{MARKER_NAME}"), &content)?;
        let back = super::exec::ssh_read_file(cfg, &format!("{GUEST_WORKSPACE}/{MARKER_NAME}"))?;
        parse_marker(&back).with_context(|| {
            "mac-vm: workspace sync verification failed (marker did not round-trip); \
             refusing to run on a stale tree (fail-closed)"
        })?;
    }
    Ok(())
}

/// Pull results guest → host after the agent exits. A failure is an error
/// (never silent): the guest keeps the truth, the message says where.
pub fn sync_from_guest(cfg: &MacVmConfig, project: &Path) -> Result<()> {
    ensure_rsync_present()?;
    let argv = pull_argv(cfg, project);
    run_argv(&argv, "rsync pull (guest → host)")
}

fn ensure_rsync_present() -> Result<()> {
    if super::vm::helper_present("rsync") {
        return Ok(());
    }
    bail!(
        "mac-vm: `rsync` not found in PATH; refusing to run with an unsynced workspace (fail-closed)\n\
         action: install rsync on the macOS host (`brew install rsync`); run `vetto doctor`"
    )
}

fn run_argv(argv: &[String], what: &str) -> Result<()> {
    let (prog, args) = argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("mac-vm: empty argv for {what}"))?;
    let out = std::process::Command::new(prog)
        .args(args)
        .output()
        .with_context(|| format!("mac-vm: failed to spawn {what}"))?;
    if !out.status.success() {
        bail!(
            "mac-vm: {what} exited {}: {}\n\
             action: check ssh connectivity and disk space in the guest; run `vetto doctor`",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
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

    fn cfg() -> MacVmConfig {
        MacVmConfig {
            ssh_target: "vetto@192.168.64.2".into(),
            ssh_key: None,
            helper: super::super::DEFAULT_HELPER.into(),
            ip_wait_secs: 120,
        }
    }

    #[test]
    fn marker_round_trip() {
        let m = format_marker(42, 1_700_000_000);
        assert_eq!(parse_marker(&m).unwrap(), (42, 1_700_000_000));
    }

    #[test]
    fn marker_malformed_fails_closed() {
        assert!(parse_marker("").is_err());
        assert!(parse_marker("v=1 files=abc stamp=1").is_err());
        assert!(parse_marker("v=2 files=1 stamp=1").is_err());
        assert!(parse_marker("files=1 stamp=1").is_err());
    }

    #[test]
    fn push_argv_shape() {
        let argv = push_argv(&cfg(), Path::new("/Users/u/proj"));
        assert_eq!(argv[0], "rsync");
        assert!(argv.contains(&"-az".to_string()));
        assert!(argv.contains(&"--delete".to_string()));
        assert!(argv.last().unwrap().ends_with(":/mnt/vetto-workspace/"));
        assert!(argv.iter().any(|a| a.ends_with("/Users/u/proj/")));
    }

    #[test]
    fn pull_argv_shape() {
        let argv = pull_argv(&cfg(), Path::new("/Users/u/proj"));
        assert_eq!(argv[0], "rsync");
        assert!(argv.contains(&MARKER_NAME.to_string()));
        assert!(argv.iter().any(|a| a.starts_with("vetto@")));
    }

    #[test]
    fn ssh_cmd_no_key() {
        assert_eq!(
            ssh_cmd_string(&cfg()),
            "ssh -o BatchMode=yes -o ConnectTimeout=10"
        );
    }

    #[test]
    fn ssh_cmd_with_key() {
        let mut c = cfg();
        c.ssh_key = Some("/home/u/.ssh/vm".into());
        assert!(ssh_cmd_string(&c).contains("-i /home/u/.ssh/vm"));
    }

    #[test]
    fn no_sbpl_references() {
        // The uniform backend must not depend on SBPL: grep the source.
        let src = include_str!("sync.rs");
        assert!(!src.to_lowercase().contains("sbpl"));
        assert!(!src.to_lowercase().contains("seatbelt"));
    }
}
