//! Safe, honest agent version probes.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const OUTPUT_WAIT: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    /// The command ran successfully. This does not mean registry conflicts
    /// were checked.
    Tested,
    /// The command is not installed or could not be started.
    Unavailable,
    /// The command exceeded the bounded probe timeout and was terminated.
    TimedOut,
    /// The command ran but returned a failure status.
    Failed,
    /// No safe command mapping exists for the requested agent name.
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCheck {
    pub agent: String,
    pub command: Option<String>,
    pub status: ProbeStatus,
    pub version: Option<String>,
    /// Whether a separately versioned compatibility registry was tested.
    /// Version probing alone never sets this to true.
    pub tested_registry: bool,
    /// `None` means conflict testing was not performed. It is never rendered
    /// as a claim that there are no conflicts.
    pub conflicts: Option<Vec<String>>,
    pub message: String,
}

impl AgentCheck {
    pub fn summary(&self) -> String {
        let version = self.version.as_deref().unwrap_or("version unavailable");
        let registry = if self.tested_registry {
            match &self.conflicts {
                Some(conflicts) if conflicts.is_empty() => "registry tested: no conflicts",
                Some(_) => "registry tested: conflicts found",
                None => "registry tested: result unavailable",
            }
        } else {
            "registry not tested"
        };
        format!(
            "{} ({:?}, {version}); {registry}: {}",
            self.agent, self.status, self.message
        )
    }
}

/// Probe the allowlisted executable for an agent's `--version` output.
///
/// The executable is selected from a fixed table and invoked directly without
/// a shell. Both output streams are drained in bounded reader threads and the
/// child is polled until the caller's timeout (capped at 30 seconds).
pub fn probe_agent(agent: &str, timeout: Duration) -> AgentCheck {
    let Some(command) = command_for_agent(agent) else {
        return AgentCheck {
            agent: agent.to_string(),
            command: None,
            status: ProbeStatus::Unsupported,
            version: None,
            tested_registry: false,
            conflicts: None,
            message: "no safe executable mapping for this agent".to_string(),
        };
    };

    probe_command(agent, command, timeout)
}

/// Short alias for callers that expose this as a generic doctor probe.
pub fn probe(agent: &str, timeout: Duration) -> AgentCheck {
    probe_agent(agent, timeout)
}

fn command_for_agent(agent: &str) -> Option<&'static str> {
    match agent {
        "codex" => Some("codex"),
        "claude" => Some("claude"),
        "gemini" => Some("gemini"),
        "antigravity" => Some("antigravity"),
        "aider" => Some("aider"),
        "cursor" => Some("cursor-agent"),
        "cline" => Some("cline"),
        "opencode" => Some("opencode"),
        "copilot" => Some("copilot"),
        "windsurf" => Some("windsurf"),
        "continue" => Some("continue"),
        "goose" => Some("goose"),
        "openhands" => Some("openhands"),
        "swe_agent" => Some("swe-agent"),
        "plandex" => Some("plandex"),
        "mentat" => Some("mentat"),
        "gpt_engineer" => Some("gpt-engineer"),
        "devin" => Some("devin"),
        "crust" => Some("crust"),
        "amp" => Some("amp"),
        // A custom executable cannot be safely inferred from an agent name.
        "custom" => None,
        _ => None,
    }
}

fn probe_command(agent: &str, command: &str, timeout: Duration) -> AgentCheck {
    let bounded_timeout = timeout.min(MAX_PROBE_TIMEOUT);
    let mut command_builder = Command::new(command);
    command_builder
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Preserve only PATH so a normal user installation can be found; no
    // credential or application environment is inherited by the probe.
    if let Some(path) = std::env::var_os("PATH") {
        command_builder.env("PATH", path);
    }
    let mut child = match command_builder.spawn() {
        Ok(child) => child,
        Err(error) => {
            let unavailable = error.kind() == std::io::ErrorKind::NotFound;
            return AgentCheck {
                agent: agent.to_string(),
                command: Some(command.to_string()),
                status: if unavailable {
                    ProbeStatus::Unavailable
                } else {
                    ProbeStatus::Failed
                },
                version: None,
                tested_registry: false,
                conflicts: None,
                message: format!("could not start probe: {error}"),
            };
        }
    };

    // `Child::wait` may deadlock if a broken version command fills a pipe, so
    // drain both streams concurrently while polling the process deadline.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_thread = spawn_reader(stdout);
    let stderr_thread = spawn_reader(stderr);
    let deadline = Instant::now() + bounded_timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };

    // Do not join reader threads after a timeout (or an unusual child that
    // leaves descendants holding the pipe open). The receive deadline keeps
    // the doctor call itself bounded; detached readers retain only their
    // capped buffer until the pipe closes.
    let stdout = if timed_out {
        String::new()
    } else {
        receive_output(stdout_thread)
    };
    let stderr = if timed_out {
        String::new()
    } else {
        receive_output(stderr_thread)
    };
    let version = parse_version(&stdout).or_else(|| parse_version(&stderr));

    let (probe_status, message) = if timed_out {
        (
            ProbeStatus::TimedOut,
            format!(
                "probe exceeded {} ms and was terminated",
                bounded_timeout.as_millis()
            ),
        )
    } else if status.as_ref().is_some_and(|status| status.success()) {
        (ProbeStatus::Tested, "version command completed".to_string())
    } else if status.is_some() {
        (
            ProbeStatus::Failed,
            "version command returned a failure status".to_string(),
        )
    } else {
        (
            ProbeStatus::Failed,
            "probe process status was unavailable".to_string(),
        )
    };

    AgentCheck {
        agent: agent.to_string(),
        command: Some(command.to_string()),
        status: probe_status,
        version,
        tested_registry: false,
        conflicts: None,
        message,
    }
}

fn spawn_reader<R: Read + Send + 'static>(stream: Option<R>) -> Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    match stream {
        Some(stream) => {
            thread::spawn(move || {
                let _ = sender.send(read_output(stream));
            });
        }
        None => {
            let _ = sender.send(String::new());
        }
    }
    receiver
}

fn receive_output(receiver: Receiver<String>) -> String {
    receiver.recv_timeout(OUTPUT_WAIT).unwrap_or_default()
}

fn read_output(mut stream: impl Read) -> String {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4096];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
        if output.len() < MAX_OUTPUT_BYTES {
            let keep = read.min(MAX_OUTPUT_BYTES - output.len());
            output.extend_from_slice(&buffer[..keep]);
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn parse_version(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.chars()
                .filter(|ch| !ch.is_control())
                .collect::<String>()
        })
        .map(|line| line.chars().take(256).collect::<String>())
        .find(|line| !line.is_empty())
}

/// Diagnostic check: verifies whether an unshimmed binary in `$PATH` appears before
/// the Vetto shims directory, shadowing the shim.
///
/// Returns `Some(warning_message)` if an unshimmed executable precedes the shim, or `None` if
/// the shim directory takes precedence or no unshimmed executable precedes it.
pub fn check_path_shadowing(agent: &str, custom_shims_dir: Option<&Path>) -> Option<String> {
    let shims_dir = match custom_shims_dir {
        Some(d) => d.to_path_buf(),
        None => {
            let home = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from)?;
            home.join(".vetto").join("shims")
        }
    };

    let shim_path = shims_dir.join(agent);
    let path_var = std::env::var_os("PATH")?;

    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }

        // If we reached the shims directory, the shim takes precedence
        if dir == shims_dir
            || (dir.exists()
                && shims_dir.exists()
                && dir.canonicalize().ok() == shims_dir.canonicalize().ok())
            || crate::shim::is_shim_directory(&dir)
        {
            return None;
        }

        // Check if an unshimmed binary for this agent exists in this directory
        let candidate = dir.join(agent);
        let mut found_candidate: Option<PathBuf> = None;

        if is_executable_binary(&candidate) {
            found_candidate = Some(candidate);
        } else {
            #[cfg(windows)]
            {
                let pathext =
                    std::env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
                for ext in pathext.to_string_lossy().split(';') {
                    let ext = ext.trim().trim_start_matches('.');
                    if !ext.is_empty() {
                        let ext_candidate = candidate.with_extension(ext);
                        if is_executable_binary(&ext_candidate) {
                            found_candidate = Some(ext_candidate);
                            break;
                        }
                    }
                }
            }
        }

        if let Some(shadow_path) = found_candidate {
            return Some(format!(
                "vetto: warning: '{agent}' in '{}' shadows the vetto shim at '{}'. Prepend '~/.vetto/shims' to your PATH: export PATH=\"$HOME/.vetto/shims:$PATH\"",
                shadow_path.display(),
                shim_path.display()
            ));
        }
    }

    None
}

fn is_executable_binary(p: &Path) -> bool {
    if !p.is_file() {
        return false;
    }
    if crate::shim::is_vetto_shim_content(p) {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(p) {
            return (m.permissions().mode() & 0o111) != 0;
        }
        false
    }
    #[cfg(windows)]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_agents_are_reported_without_claiming_registry_results() {
        let result = probe_agent("custom", Duration::from_millis(1));
        assert_eq!(result.status, ProbeStatus::Unsupported);
        assert!(!result.tested_registry);
        assert!(result.conflicts.is_none());
        assert!(result.summary().contains("registry not tested"));
    }

    #[test]
    fn version_parser_ignores_empty_lines_and_control_bytes() {
        assert_eq!(
            parse_version("\n\u{1b}[?25lvetto 1.2\n"),
            Some("[?25lvetto 1.2".to_string())
        );
        assert_eq!(parse_version("\n\n"), None);
    }

    #[test]
    fn timeout_is_bounded_before_spawn_result_is_reported() {
        // An unavailable command exercises the no-shell error path without
        // relying on a platform-specific executable in the test environment.
        let result = probe_command(
            "test",
            "vetto-command-that-does-not-exist",
            Duration::from_secs(60),
        );
        assert_eq!(result.status, ProbeStatus::Unavailable);
        assert!(!result.tested_registry);
    }
}
