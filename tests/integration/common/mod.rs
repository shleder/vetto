//! Shared helpers for integration tests.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn vetto_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vetto")
}

/// Output of `vetto doctor` (empty when the binary cannot run at all).
pub fn doctor_output() -> String {
    Command::new(vetto_bin())
        .arg("doctor")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// "full" | "fs-only" | None (no enforcement tier possible on this machine).
pub fn detected_tier() -> Option<String> {
    let out = doctor_output();
    out.lines()
        .find(|l| l.trim_start().starts_with("chosen tier:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .filter(|s| s == "full" || s == "fs-only")
}

/// Any enforcement possible here (landlock present)?
pub fn have_landlock() -> bool {
    detected_tier().is_some()
}

/// True when a session log proves the host monotonic clock jumped while the
/// agent ran (VM time-sync step): the wall gap between `session_started`
/// and `session_ended` is under a second while the monotonic
/// `duration_secs` claims a full session. Then every timer fired early
/// (sleeps return instantly, deadlines trip at once) and any
/// timing-dependent assertion — poller windows, live-process samplers,
/// sleeps — is unmeasurable.
///
/// Both conditions are required so a genuinely instant session (wall AND
/// duration near zero, i.e. a real product bug) still FAILS instead of
/// skipping: only their DIVERGENCE proves host pathology. Same spirit as
/// `have_landlock`: skipping an unmeasurable environment is not a pass.
pub fn session_clock_jumped(jsonl: &str) -> bool {
    let (mut started, mut ended, mut duration) = (None, None, None);
    for line in jsonl.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        match value.get("event").and_then(|e| e.as_str()) {
            Some("session_started") => {
                started = value.get("ts").and_then(|t| t.as_str()).map(str::to_string);
            }
            Some("session_ended") => {
                ended = value.get("ts").and_then(|t| t.as_str()).map(str::to_string);
                duration = value.get("duration_secs").and_then(|d| d.as_i64());
            }
            _ => {}
        }
    }
    let (Some(started), Some(ended), Some(duration)) = (started, ended, duration) else {
        return false;
    };
    let parse = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.timestamp_millis())
    };
    let (Some(a), Some(b)) = (parse(&started), parse(&ended)) else {
        return false;
    };
    let wall_secs = (b - a) as f64 / 1000.0;
    wall_secs < 1.0 && duration as f64 > wall_secs
}

/// Force a tier for the duration of one vetto run (testing override).
pub fn run_vetto_env_in(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    Command::new(vetto_bin())
        .args(args)
        .current_dir(cwd)
        .env("HOME", test_home())
        .envs(envs.iter().copied())
        .output()
        .expect("spawn vetto")
}

pub fn run_vetto_in(cwd: &Path, args: &[&str]) -> Output {
    run_vetto_env_in(cwd, args, &[])
}

pub struct TempProject(PathBuf);

impl TempProject {
    pub fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("vetto-it-{}-{}-{n}", tag, std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp project dir");
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, content).expect("write file");
}

#[cfg(target_os = "linux")]
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Copy a fixture INTO the sandboxed project and return its relative path:
/// the sandbox can only read scripts inside its own allowlist.
#[cfg(target_os = "linux")]
pub fn stage_fixture(project: &Path, name: &str) -> String {
    let src = fixture(name);
    let dst = project.join(name);
    std::fs::copy(&src, &dst).expect("stage fixture");
    format!("./{name}")
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

#[cfg(target_os = "linux")]
pub fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Isolated HOME inherited by every integration-test vetto process. Tests
/// must never create credential-shaped fixtures in the runner account's real
/// home directory.
pub fn test_home() -> &'static Path {
    static TEST_HOME: OnceLock<PathBuf> = OnceLock::new();
    TEST_HOME
        .get_or_init(|| {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("vetto-it-home-{}-{nonce}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create isolated test HOME");
            path
        })
        .as_path()
}

/// Create fake key material only inside the isolated integration-test HOME.
pub fn ensure_fake_ssh_key() {
    let ssh = test_home().join(".ssh");
    let _ = std::fs::create_dir_all(&ssh);
    let key = ssh.join("id_rsa");
    if !key.exists() {
        let _ = std::fs::write(&key, "FAKE-TEST-KEY-MATERIAL-FOR-VETTO-IT\n");
    }
}
