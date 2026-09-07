//! WSL2 distro lifecycle via `wsl.exe`.
//!
//! vetto only orchestrates: query status/list (read-only) → ensure the
//! distro is running → exec inside it. No WSL2 → fail-closed with an action,
//! never a host run.
//!
//! Only parsing/argv builders are unit-tested. Anything that spawns
//! `wsl.exe` is intentionally untested (no local execution in unit tests).

use anyhow::{bail, Context, Result};

use super::Wsl2Config;

/// Parsed distro state. Pure data — unit-tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistroState {
    /// Raw state string from `wsl.exe --list --verbose` (e.g. `Running`).
    pub state: String,
    /// True for `Running` (case-insensitive).
    pub running: bool,
    /// WSL version reported (2 when known).
    pub version: Option<u8>,
}

/// Parse one data line of `wsl.exe --list --verbose` output for `distro`.
/// Pure logic — unit-tested.
///
/// Expected shape (locale-independent parts): `[*] <name> <Running|Stopped> <2>`.
/// Matching is case-insensitive on name and state; `*` default marker is
/// tolerated.
pub fn parse_list_line(output: &str, distro: &str) -> Result<DistroState> {
    for line in output.lines() {
        // Strip UTF-16LE-decoded NULs and the BOM that wsl.exe emits.
        let clean: String = line
            .chars()
            .filter(|&c| c != '\0' && c != '\u{feff}')
            .collect();
        let t = clean.trim().trim_start_matches('*').trim();
        if t.is_empty() {
            continue;
        }
        let mut parts: Vec<&str> = t.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        // First token is the distro name (default marker already stripped).
        if !parts[0].eq_ignore_ascii_case(distro) {
            continue;
        }
        parts.remove(0);
        if parts.is_empty() {
            bail!("wsl2: malformed list line for `{distro}`: {t:?}");
        }
        let state = parts[0].to_string();
        let running = state.eq_ignore_ascii_case("running");
        let version = parts.get(1).and_then(|v| v.parse::<u8>().ok());
        return Ok(DistroState {
            state,
            running,
            version,
        });
    }
    bail!(
        "wsl2: distro `{distro}` not found in `wsl.exe --list --verbose`\n\
         action: import it (`wsl --import`) or fix the distro name; run `vetto doctor`"
    )
}

/// Parse `wsl.exe --status` for the default WSL version line.
/// Pure logic — unit-tested. Returns the default version when found.
pub fn parse_default_version(output: &str) -> Option<u8> {
    for line in output.lines() {
        let clean: String = line
            .chars()
            .filter(|&c| c != '\0' && c != '\u{feff}')
            .collect();
        let t = clean.trim().to_lowercase();
        // e.g. "Default Version: 2"
        if let Some(rest) = t.strip_prefix("default version:") {
            return rest.trim().parse::<u8>().ok();
        }
    }
    None
}

/// Build `wsl.exe --list --verbose` argv. Pure logic — unit-tested.
pub fn list_argv() -> Vec<String> {
    vec![
        "wsl.exe".to_string(),
        "--list".to_string(),
        "--verbose".to_string(),
    ]
}

/// Build `wsl.exe -d <distro> -- <cmd...>` argv. Pure logic — unit-tested.
pub fn exec_argv(distro: &str, cmd: &[String]) -> Vec<String> {
    let mut argv = vec![
        "wsl.exe".to_string(),
        "-d".to_string(),
        distro.to_string(),
        "--".to_string(),
    ];
    argv.extend(cmd.iter().cloned());
    argv
}

/// True when `wsl.exe` resolves in PATH. Presence only — reachability is
/// checked separately.
pub fn wsl_present() -> bool {
    std::env::var_os("PATH").map_or(false, |paths| {
        std::env::split_paths(&paths).any(|dir| {
            dir.join("wsl.exe").exists() || dir.join("wsl").exists()
        })
    })
}

/// Query one distro's state (read-only). Fail-closed on any error.
pub fn query_distro(distro: &str) -> Result<DistroState> {
    if !wsl_present() {
        bail!(
            "wsl2: `wsl.exe` not found in PATH\n\
             action: install WSL2 (https://aka.ms/wsl) and ensure `wsl.exe` is on PATH; run `vetto doctor`"
        );
    }
    let out = std::process::Command::new("wsl.exe")
        .args(["--list", "--verbose"])
        .output()
        .with_context(|| "wsl2: failed to run `wsl.exe --list --verbose`")?;
    if !out.status.success() {
        bail!(
            "wsl2: `wsl.exe --list --verbose` exited {}: {}\n\
             action: repair the WSL2 install and retry; run `vetto doctor`",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // wsl.exe emits UTF-16LE; lossy UTF-8 decode keeps ASCII tokens intact.
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    parse_list_line(&stdout, distro)
}

/// Ensure the distro is running. Query first; when stopped, start it with a
/// bounded foreground probe (`wsl.exe -d <distro> -- true`) and re-query.
/// Fail-closed on timeout/error — never proceed without a running distro.
pub fn ensure_running(cfg: &Wsl2Config) -> Result<()> {
    let distro = cfg.effective_distro();
    match query_distro(&distro) {
        Ok(s) if s.running => return Ok(()),
        Ok(s) => {
            tracing::debug!("wsl2: distro `{distro}` state is `{}`; starting", s.state);
        }
        Err(e) => {
            tracing::debug!("wsl2: list query failed ({e:#}); attempting start probe");
        }
    }
    let probe = std::process::Command::new("wsl.exe")
        .args(["-d", &distro, "--", "true"])
        .output()
        .with_context(|| format!("wsl2: failed to start distro `{distro}`"))?;
    if !probe.status.success() {
        bail!(
            "wsl2: distro `{distro}` start probe exited {}: {}\n\
             action: check `wsl --status` and the distro health; run `vetto doctor`",
            probe.status,
            String::from_utf8_lossy(&probe.stderr).trim()
        );
    }
    let state = query_distro(&distro)?;
    if !state.running {
        bail!(
            "wsl2: distro `{distro}` still not running after start (state: {})\n\
             action: start it manually (`wsl -d {distro}`) and retry; run `vetto doctor`",
            state.state
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "  NAME                   STATE           VERSION\n* Ubuntu                 Running         2\n  vetto                  Stopped         2\n";

    #[test]
    fn parse_running_distro() {
        let s = parse_list_line(SAMPLE, "ubuntu").unwrap();
        assert!(s.running);
        assert_eq!(s.version, Some(2));
    }

    #[test]
    fn parse_stopped_distro() {
        let s = parse_list_line(SAMPLE, "vetto").unwrap();
        assert!(!s.running);
        assert_eq!(s.state, "Stopped");
    }

    #[test]
    fn parse_missing_distro_fails_closed() {
        assert!(parse_list_line(SAMPLE, "nope").is_err());
    }

    #[test]
    fn parse_default_version_two() {
        let out = "Default Distribution: Ubuntu\nDefault Version: 2\n";
        assert_eq!(parse_default_version(out), Some(2));
    }

    #[test]
    fn parse_default_version_absent() {
        assert_eq!(parse_default_version("garbage\n"), None);
    }

    #[test]
    fn argv_builders() {
        assert_eq!(list_argv(), vec!["wsl.exe", "--list", "--verbose"]);
        let argv = exec_argv("vetto", &["echo".into(), "hi".into()]);
        assert_eq!(argv, vec!["wsl.exe", "-d", "vetto", "--", "echo", "hi"]);
    }

    #[test]
    fn wsl_present_rejects_garbage_on_any_os() {
        // PATH lookup only: a nonsense binary name never resolves.
        let saved = std::env::var_os("PATH");
        std::env::set_var("PATH", "/nonexistent-xyz");
        assert!(!wsl_present());
        if let Some(p) = saved {
            std::env::set_var("PATH", p);
        }
    }
}
