//! Fail-closed multi-agent launcher.
//!
//! Every `MultiSession` owns its own `Backend`, `SandboxHandle`, event bus,
//! stats collector and captured stdout/stderr buffers. There is no shared
//! child process or unsandboxed fallback. All backend detection and policy
//! loading happens before any process is spawned; a spawn failure tears down
//! already-created handles and returns an error to the caller.

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use std::time::Instant;

#[cfg(unix)]
use crate::config::NetMode;
#[cfg(unix)]
use crate::events::Event;
use crate::events::EventBus;
use crate::multi::{AgentSpec, Manifest, MultiAggregator, MultiEventStream};
#[cfg(unix)]
use crate::policy;
use crate::report::stats::StatsCollector;
use crate::report::{self, storage::ReportStorage, ReportOptions};
use crate::sandbox::SandboxHandle;
#[cfg(unix)]
use crate::sandbox::{Backend, SpawnOptions, StdioMode};
use anyhow::{bail, Context, Result};

#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::IntoRawFd;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(unix)]
const OUTPUT_CAP: usize = 512 * 1024;

#[derive(Default)]
pub struct OutputBuffers {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl OutputBuffers {
    pub fn text(&self) -> String {
        let mut bytes = self.stdout.clone();
        bytes.extend_from_slice(&self.stderr);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

pub struct MultiSession {
    pub spec: AgentSpec,
    pub bus: EventBus,
    pub stats: StatsCollector,
    pub output: Arc<Mutex<OutputBuffers>>,
    pub handle: Arc<Mutex<SandboxHandle>>,
    pub finished: Arc<AtomicBool>,
    pub started: Instant,
}

#[cfg(unix)]
struct PendingSession {
    spec: AgentSpec,
    net: NetMode,
    tier: policy::Tier,
    policy: policy::Policy,
    bus: EventBus,
    handle: SandboxHandle,
    stdout_r: OwnedFd,
    stderr_r: OwnedFd,
    broker_ctrl_fd: Option<OwnedFd>,
    notif_listener: Option<OwnedFd>,
}

#[cfg(unix)]
impl PendingSession {
    fn terminate(&mut self) {
        self.handle.terminate();
    }
}

impl MultiSession {
    pub fn pause(&self) {
        if let Ok(mut handle) = self.handle.lock() {
            handle.pause();
        }
    }

    pub fn resume(&self) {
        if let Ok(mut handle) = self.handle.lock() {
            handle.resume();
        }
    }

    pub fn terminate(&self) {
        if let Ok(mut handle) = self.handle.lock() {
            handle.terminate();
        }
    }

    pub fn try_wait(&self) -> Option<i32> {
        self.handle.lock().ok()?.try_wait()
    }

    pub fn output_text(&self) -> String {
        self.output
            .lock()
            .map(|output| output.text())
            .unwrap_or_default()
    }
}

pub struct MultiRuntime {
    pub manifest: Manifest,
    pub sessions: Vec<MultiSession>,
    pub stream: MultiEventStream,
    pub aggregator: MultiAggregator,
    pub report_dir: Option<PathBuf>,
}

impl MultiRuntime {
    /// Prepare and launch all agents. The preflight phase deliberately owns
    /// no child handles: invalid policy/network/command input is rejected
    /// before the first fork. Once spawning begins, any failure terminates
    /// every already-created sandbox before returning the error.
    #[cfg(unix)]
    pub fn launch(manifest: Manifest, project: PathBuf, home: PathBuf) -> Result<Self> {
        manifest.validate()?;

        let mut prepared = Vec::with_capacity(manifest.agents.len());
        for spec in &manifest.agents {
            let net = crate::config::parse_net_mode(&spec.net)
                .with_context(|| format!("agent '{}' network mode", spec.name))?;
            let backend = Backend::detect(net.clone(), spec.observe_seccomp)
                .with_context(|| format!("establish sandbox backend for agent '{}'", spec.name))?;
            let tier = backend.tier().unwrap_or(policy::Tier::Full);
            let policy =
                policy::loader::load(&spec.profile, spec.policy.as_deref(), &project, &home, tier)
                    .with_context(|| format!("load policy for agent '{}'", spec.name))?;
            let mut command = spec.command.clone();
            command[0] = resolve_in_path(&command[0])
                .with_context(|| format!("resolve command for agent '{}'", spec.name))?;
            // Do not silently permit a policy to exclude the executable. The
            // sandbox may still reject it, but we surface the reason before
            // spawn and never retry unsandboxed.
            if !policy.in_read_scope(Path::new(&command[0])) {
                tracing::warn!(
                    agent = %spec.name,
                    command = %command[0],
                    "agent executable is outside policy read scope; sandbox exec may be denied"
                );
            }
            prepared.push(Prepared {
                spec: spec.clone(),
                net,
                backend: Some(backend),
                policy,
                command,
                tier,
            });
        }

        // No consumer threads are created until every child has been forked.
        // This preserves the single-threaded fork contract of the sandbox
        // backends even when a manifest contains many agents.
        let mut pending = Vec::with_capacity(prepared.len());
        for prepared in prepared {
            match spawn_one(prepared, &project) {
                Ok(session) => pending.push(session),
                Err(error) => {
                    for session in &mut pending {
                        session.terminate();
                    }
                    bail!("multi-agent launch aborted; no unsandboxed fallback: {error:#}");
                }
            }
        }

        let stream = MultiEventStream::new();
        let aggregator =
            MultiAggregator::new(manifest.agents.iter().map(|agent| agent.name.clone()));
        crate::multi::spawn_aggregator(&stream, aggregator.clone());
        let mut sessions = Vec::with_capacity(pending.len());
        for pending in pending {
            sessions.push(activate_pending(pending, &project, &stream));
        }

        Ok(Self {
            report_dir: manifest.report_dir.clone(),
            manifest,
            sessions,
            stream,
            aggregator,
        })
    }

    #[cfg(not(unix))]
    pub fn launch(_manifest: Manifest, _project: PathBuf, _home: PathBuf) -> Result<Self> {
        bail!("multi-agent mode is unavailable on this platform; refusing to run unsandboxed")
    }

    pub fn terminate(&self, index: usize) -> Result<()> {
        let session = self
            .sessions
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("unknown multi-agent pane {index}"))?;
        session.terminate();
        Ok(())
    }

    pub fn terminate_all(&self) {
        for session in &self.sessions {
            session.terminate();
        }
    }

    pub fn combined_report(&self) -> serde_json::Value {
        self.aggregator.report_json()
    }

    /// Persist one JSON report per agent and one combined report. Each agent's
    /// directory is resolved independently from the manifest, while the
    /// shared storage allocates collision-resistant names without replacing
    /// an existing artifact. A failed write is reported with the exact owner
    /// instead of silently merging reports.
    pub fn write_reports(&self) -> Result<Vec<PathBuf>> {
        let mut written = Vec::new();
        let rows = self.aggregator.snapshot();
        for agent in &self.manifest.agents {
            let dir = agent.report_path(self.report_dir.as_deref());
            let options = ReportOptions {
                report_dir: Some(dir),
                auto_cleanup: false,
                retention: None,
                max_age_secs: None,
            };
            let storage = ReportStorage::new(&options)
                .with_context(|| format!("prepare report directory for agent '{}'", agent.name))?;
            let row = rows
                .iter()
                .find(|stats| stats.name == agent.name)
                .cloned()
                .unwrap_or_else(|| crate::multi::AgentStats::new(agent.name.clone()));
            let mut value = serde_json::to_value(row).context("serialize agent report")?;
            report::sanitize_json_strings(&mut value);
            let text = serde_json::to_string_pretty(&value).context("render agent report")?;
            let path = storage
                .write("json", &text)
                .with_context(|| format!("write report for agent '{}'", agent.name))?;
            written.push(path);
        }
        let combined_dir = self
            .report_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let options = ReportOptions {
            report_dir: Some(combined_dir),
            auto_cleanup: false,
            retention: None,
            max_age_secs: None,
        };
        let storage = ReportStorage::new(&options).context("prepare combined report directory")?;
        let mut combined = self.combined_report();
        report::sanitize_json_strings(&mut combined);
        let combined = serde_json::to_string_pretty(&combined).context("render combined report")?;
        let combined_path = storage
            .write("json", &combined)
            .context("write combined report")?;
        written.push(combined_path);
        Ok(written)
    }
}

#[cfg(unix)]
struct Prepared {
    spec: AgentSpec,
    net: NetMode,
    backend: Option<Backend>,
    policy: policy::Policy,
    command: Vec<String>,
    tier: policy::Tier,
}

#[cfg(unix)]
fn spawn_one(prepared: Prepared, project: &Path) -> Result<PendingSession> {
    let Prepared {
        spec,
        net,
        backend,
        policy,
        command,
        tier,
    } = prepared;
    let backend = backend.ok_or_else(|| anyhow::anyhow!("sandbox backend was consumed"))?;
    let (stdout_r, stdout_w) = pipe2()?;
    let (stderr_r, stderr_w) = pipe2()?;
    let options = SpawnOptions {
        agent_cmd: command,
        cwd: project.to_path_buf(),
        env_extra: relay_env(&net),
        stdio: StdioMode::Captured {
            stdout_w: stdout_w.as_raw_fd(),
            stderr_w: stderr_w.as_raw_fd(),
        },
    };
    let spawned = backend
        .spawn(&policy, options)
        .with_context(|| format!("spawn agent '{}' inside its sandbox", spec.name))?;
    let crate::sandbox::Spawned {
        handle,
        broker_ctrl_fd,
        relay_port: _relay_port,
        notif_listener,
    } = spawned;
    // The child now owns the write ends. Keeping a parent copy would defeat
    // EOF delivery to the readers.
    drop(stdout_w);
    drop(stderr_w);

    Ok(PendingSession {
        spec,
        net,
        tier,
        policy,
        bus: EventBus::new(),
        handle,
        stdout_r,
        stderr_r,
        broker_ctrl_fd,
        notif_listener,
    })
}

#[cfg(unix)]
fn activate_pending(
    pending: PendingSession,
    project: &Path,
    stream: &MultiEventStream,
) -> MultiSession {
    #[cfg(not(target_os = "linux"))]
    let _ = project;
    let PendingSession {
        spec,
        net,
        tier,
        policy,
        bus,
        handle,
        stdout_r,
        stderr_r,
        broker_ctrl_fd,
        notif_listener,
    } = pending;
    let stats = StatsCollector::spawn(&bus);
    let root_pid = handle.root_pid;
    // Subscribe the aggregate bridge before publishing SessionStarted, so
    // the per-agent and combined reports agree on lifecycle counts.
    stream.bridge_agent(spec.name.clone(), &bus);
    bus.publish(Event::SessionStarted {
        ts: crate::events::types::now(),
        pid: root_pid,
        tier: tier.label().to_string(),
        net_mode: net.label(),
        profile: policy.name.clone(),
    });

    #[cfg(target_os = "linux")]
    {
        if let Some(fd) = broker_ctrl_fd {
            let broker_policy = match &net {
                NetMode::Allowlist(domains) => {
                    crate::sandbox::linux::net_relay::BrokerPolicy::Allowlist(domains.clone())
                }
                NetMode::Strict(rules) => {
                    crate::sandbox::linux::net_relay::BrokerPolicy::Strict(rules.clone())
                }
                NetMode::Off => {
                    crate::sandbox::linux::net_relay::BrokerPolicy::Allowlist(Vec::new())
                }
            };
            crate::sandbox::linux::net_relay::spawn_broker(
                fd.into_raw_fd(),
                broker_policy,
                bus.clone(),
            );
        }
        if let Some(fd) = notif_listener {
            crate::sandbox::linux::observe_seccomp::spawn_notifier(
                fd,
                bus.clone(),
                Arc::new(policy.clone()),
                project.to_path_buf(),
            );
        }
        crate::sandbox::linux::visibility::spawn_poller(bus.clone(), vec![root_pid]);
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let _ = (broker_ctrl_fd, notif_listener);
    }

    let output = Arc::new(Mutex::new(OutputBuffers::default()));
    spawn_pipe_reader(stdout_r, Arc::clone(&output), true);
    spawn_pipe_reader(stderr_r, Arc::clone(&output), false);

    let handle = Arc::new(Mutex::new(handle));
    let finished = Arc::new(AtomicBool::new(false));
    let wait_handle = Arc::clone(&handle);
    let wait_finished = Arc::clone(&finished);
    let wait_bus = bus.clone();
    std::thread::Builder::new()
        .name(format!("vetto-multi-wait-{}", spec.name))
        .spawn(move || {
            let code = wait_handle
                .lock()
                .map(|mut handle| handle.wait())
                .unwrap_or(-1);
            wait_bus.publish(Event::SessionEnded {
                ts: crate::events::types::now(),
                exit_code: code,
                duration_secs: 0,
            });
            wait_finished.store(true, Ordering::SeqCst);
        })
        .expect("spawn multi wait thread");

    MultiSession {
        spec,
        bus,
        stats,
        output,
        handle,
        finished,
        started: Instant::now(),
    }
}

#[cfg(unix)]
fn spawn_pipe_reader(fd: OwnedFd, output: Arc<Mutex<OutputBuffers>>, stdout: bool) {
    std::thread::Builder::new()
        .name("vetto-multi-output".into())
        .spawn(move || {
            let mut file: std::fs::File = fd.into();
            let mut chunk = [0u8; 8192];
            loop {
                match file.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut output) = output.lock() {
                            let target = if stdout {
                                &mut output.stdout
                            } else {
                                &mut output.stderr
                            };
                            target.extend_from_slice(&chunk[..n]);
                            if target.len() > OUTPUT_CAP {
                                let excess = target.len() - OUTPUT_CAP;
                                target.drain(..excess);
                            }
                        }
                    }
                }
            }
        })
        .expect("spawn multi output reader");
}

#[cfg(unix)]
fn pipe2() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array for the libc pipe call.
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
        // SAFETY: fd came from the successful pipe call.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors came from the successful pipe call.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            bail!("fcntl(F_SETFD): {error}");
        }
    }
    // SAFETY: fresh descriptors from a successful pipe and CLOEXEC setup.
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

#[cfg(target_os = "linux")]
fn relay_env(net: &NetMode) -> HashMap<String, String> {
    let mut env = HashMap::new();
    if net.uses_relay() {
        for (key, value) in crate::sandbox::linux::net_relay::build_proxy_env(
            crate::sandbox::linux::net_relay::RELAY_PORT_BASE,
        ) {
            env.insert(key, value);
        }
    }
    env
}

#[cfg(all(unix, not(target_os = "linux")))]
fn relay_env(_net: &NetMode) -> HashMap<String, String> {
    HashMap::new()
}

#[cfg(unix)]
fn resolve_in_path(command: &str) -> Result<String> {
    if command.contains('/') {
        return Ok(command.to_string());
    }
    for dir in std::env::var_os("PATH")
        .unwrap_or_default()
        .to_string_lossy()
        .split(':')
    {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(command);
        if std::fs::metadata(&candidate)
            .map(|meta| meta.is_file())
            .unwrap_or(false)
        {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    bail!("agent command '{command}' not found in PATH")
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;
    use crate::multi::parse_manifest_str;
    use std::path::Path;

    #[test]
    fn report_directory_is_per_agent() {
        let manifest = parse_manifest_str(
            r#"
                [[agents]]
                name = "one"
                command = ["one"]
                [[agents]]
                name = "two"
                command = ["two"]
            "#,
        )
        .expect("manifest");
        let root = Path::new("reports");
        assert_ne!(
            manifest.agents[0].report_path(Some(root)),
            manifest.agents[1].report_path(Some(root))
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_reports_refuses_symlinked_agent_directory() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vetto-multi-storage-{nonce}"));
        let real = root.join("real");
        let link = root.join("link");
        std::fs::create_dir_all(&real).expect("create real report directory");
        symlink(&real, &link).expect("create report directory symlink");

        let manifest = Manifest {
            version: 1,
            agents: vec![AgentSpec {
                name: "one".into(),
                command: vec!["agent".into()],
                profile: "default".into(),
                policy: None,
                net: "off".into(),
                observe_seccomp: false,
                report_dir: Some(link.clone()),
            }],
            report_dir: Some(root.join("combined")),
        };
        let runtime = MultiRuntime {
            manifest,
            sessions: Vec::new(),
            stream: MultiEventStream::new(),
            aggregator: MultiAggregator::new(["one".to_string()]),
            report_dir: Some(root.join("combined")),
        };

        assert!(runtime.write_reports().is_err());
        assert!(real
            .read_dir()
            .expect("read real directory")
            .next()
            .is_none());

        std::fs::remove_file(&link).expect("remove report directory symlink");
        std::fs::remove_dir(&real).expect("remove real report directory");
        std::fs::remove_dir(&root).expect("remove report root");
    }
}
