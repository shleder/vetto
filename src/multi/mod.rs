//! Multi-agent orchestration primitives.
//!
//! This module intentionally separates three concerns:
//!
//! * a strict manifest/argv parser (no shell strings);
//! * one event stream and report accumulator per named agent; and
//! * deterministic aggregation for the combined report and split-pane TUI.
//!
//! The actual process launcher lives in [`runtime`]. It accepts only the
//! validated argv produced here and always goes through `sandbox::Backend`.
//!
//! Phase 4 (Step 23 & 24): Virtual port pool, debug port configuration,
//! and cross-agent memory/signal isolation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::events::{Event, EventBus, FileAccess};

pub mod isolation;
pub mod runtime;

const MAX_AGENTS: usize = 32;
const MAX_ARG_BYTES: usize = 64 * 1024;

/// Local loopback debug port configuration per agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugPortConfig {
    #[serde(default = "default_true")]
    pub isolate_devtools: bool,
    #[serde(default = "default_true")]
    pub isolate_node_inspect: bool,
    #[serde(default = "default_true")]
    pub isolate_debugpy: bool,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
}

fn default_true() -> bool {
    true
}

impl Default for DebugPortConfig {
    fn default() -> Self {
        Self {
            isolate_devtools: true,
            isolate_node_inspect: true,
            isolate_debugpy: true,
            allowed_ports: Vec::new(),
        }
    }
}

/// Dynamic virtual port pool allocator for multi-agent network isolation.
#[derive(Debug, Clone)]
pub struct VirtualPortPool {
    base_port: u16,
    range_size: u16,
    allocated: Arc<Mutex<BTreeMap<String, Vec<u16>>>>,
}

impl VirtualPortPool {
    pub fn new(base_port: u16, range_size: u16) -> Self {
        Self {
            base_port,
            range_size,
            allocated: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn default_pool() -> Self {
        Self::new(47200, 16)
    }

    pub fn allocate_ports(&self, agent_name: &str, count: u16) -> Result<Vec<u16>> {
        let mut allocated = self
            .allocated
            .lock()
            .map_err(|_| anyhow::anyhow!("virtual port pool lock poisoned"))?;
        let index = allocated.len() as u16;
        let start = self
            .base_port
            .checked_add(index.saturating_mul(self.range_size))
            .ok_or_else(|| anyhow::anyhow!("virtual port pool exhausted"))?;
        let mut ports = Vec::with_capacity(count as usize);
        for i in 0..count {
            ports.push(start + i);
        }
        allocated.insert(agent_name.to_string(), ports.clone());
        Ok(ports)
    }

    pub fn allocate_relay_port(&self, agent_idx: usize) -> u16 {
        #[cfg(target_os = "linux")]
        {
            crate::sandbox::linux::net_relay::RELAY_PORT_BASE + agent_idx as u16
        }
        #[cfg(not(target_os = "linux"))]
        {
            47129 + agent_idx as u16
        }
    }

    pub fn get_ports(&self, agent_name: &str) -> Option<Vec<u16>> {
        self.allocated.lock().ok()?.get(agent_name).cloned()
    }

    pub fn release(&self, agent_name: &str) {
        if let Ok(mut allocated) = self.allocated.lock() {
            allocated.remove(agent_name);
        }
    }
}

impl Default for VirtualPortPool {
    fn default() -> Self {
        Self::default_pool()
    }
}

/// CLI entry point for `vetto multi`. It returns the worst non-zero exit code
/// after the split-pane dashboard closes; the top-level `main` decides how to
/// map that code to the process exit status.
#[cfg(unix)]
pub fn run_cli(
    manifest_path: Option<PathBuf>,
    repeated_agents: Vec<String>,
    legacy_command: Vec<String>,
) -> Result<i32> {
    let manifest = manifest_from_cli_inputs(manifest_path, repeated_agents, legacy_command)?;
    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("neither $HOME nor %USERPROFILE% is set; vetto needs it to resolve multi-agent policy variables")?;
    let runtime = runtime::MultiRuntime::launch(manifest, project, home)?;
    let code = crate::tui::full::run_multi(runtime);
    Ok(code)
}

fn manifest_from_cli_inputs(
    manifest_path: Option<PathBuf>,
    repeated_agents: Vec<String>,
    legacy_command: Vec<String>,
) -> Result<Manifest> {
    if manifest_path.is_some() && (!repeated_agents.is_empty() || !legacy_command.is_empty()) {
        bail!(
            "ambiguous multi-agent input: --manifest cannot be combined with --agent or a trailing command"
        );
    }
    if !repeated_agents.is_empty() && !legacy_command.is_empty() {
        bail!(
            "ambiguous multi-agent input: repeated --agent entries cannot be combined with a trailing command"
        );
    }
    let manifest = if let Some(path) = manifest_path {
        load_manifest(&path)?
    } else if !repeated_agents.is_empty() {
        Manifest {
            version: 1,
            agents: parse_repeated_agents(&repeated_agents)?,
            report_dir: None,
        }
    } else {
        Manifest {
            version: 1,
            agents: parse_legacy_commands(&legacy_command)?,
            report_dir: None,
        }
    };
    manifest.validate()?;
    Ok(manifest)
}

#[cfg(not(unix))]
pub fn run_cli(
    manifest_path: Option<PathBuf>,
    repeated_agents: Vec<String>,
    legacy_command: Vec<String>,
) -> Result<i32> {
    let _ = manifest_from_cli_inputs(manifest_path, repeated_agents, legacy_command)?;
    bail!("multi-agent mode is unavailable on this platform; refusing to run unsandboxed")
}

/// TOML manifest accepted by `vetto multi --manifest ...`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default = "manifest_version")]
    pub version: u32,
    pub agents: Vec<AgentSpec>,
    #[serde(default)]
    pub report_dir: Option<PathBuf>,
}

fn manifest_version() -> u32 {
    1
}

/// One independently sandboxed agent. `command` is an argv vector, never a
/// shell command string. This is the central injection boundary for multi
/// mode.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub name: String,
    pub command: Vec<String>,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default)]
    pub policy: Option<PathBuf>,
    #[serde(default = "default_net")]
    pub net: String,
    #[serde(default)]
    pub observe_seccomp: bool,
    #[serde(default)]
    pub report_dir: Option<PathBuf>,
    #[serde(default)]
    pub debug_ports: Option<DebugPortConfig>,
}

fn default_profile() -> String {
    "default".to_string()
}

fn default_net() -> String {
    "off".to_string()
}

impl AgentSpec {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.name)?;
        if self.command.is_empty() {
            bail!(
                "agent '{}' has an empty command; use an argv array",
                self.name
            );
        }
        for arg in &self.command {
            if arg.is_empty() {
                bail!("agent '{}' contains an empty argv item", self.name);
            }
            if arg.contains('\0') {
                bail!("agent '{}' contains NUL in argv", self.name);
            }
            if arg.len() > MAX_ARG_BYTES {
                bail!("agent '{}' has an argv item larger than 64 KiB", self.name);
            }
        }
        if self.profile.trim().is_empty() {
            bail!("agent '{}' has an empty profile", self.name);
        }
        Ok(())
    }

    /// Resolve the per-agent report directory without allowing an agent name
    /// to escape the selected base directory.
    pub fn report_path(&self, base: Option<&Path>) -> PathBuf {
        if let Some(path) = &self.report_dir {
            return path.clone();
        }
        let root = base
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".vetto-reports"));
        root.join(&self.name)
    }
}

impl Manifest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!(
                "unsupported multi-agent manifest version {}; expected 1",
                self.version
            );
        }
        if self.agents.is_empty() {
            bail!("multi-agent manifest must contain at least one [[agents]] entry");
        }
        if self.agents.len() > MAX_AGENTS {
            bail!("multi-agent manifest contains more than {MAX_AGENTS} agents");
        }
        let mut names = std::collections::BTreeSet::new();
        let mut report_paths = std::collections::BTreeSet::new();
        for agent in &self.agents {
            agent.validate()?;
            if !names.insert(agent.name.clone()) {
                bail!(
                    "duplicate multi-agent name '{}'; names must be unique",
                    agent.name
                );
            }
            let report_path = agent.report_path(self.report_dir.as_deref());
            if !report_paths.insert(report_path.clone()) {
                bail!(
                    "agents '{}' and another entry share report directory {}; each agent needs an independent report path",
                    agent.name,
                    report_path.display()
                );
            }
        }
        Ok(())
    }
}

pub fn parse_manifest_str(text: &str) -> Result<Manifest> {
    let manifest: Manifest = toml::from_str(text).context("parse multi-agent TOML manifest")?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn load_manifest(path: &Path) -> Result<Manifest> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read multi-agent manifest {}", path.display()))?;
    parse_manifest_str(&text)
}

/// Parse the explicit repeated-command form:
/// `--agent name=/absolute/or/PATH`.
pub fn parse_repeated_agents(entries: &[String]) -> Result<Vec<AgentSpec>> {
    if entries.is_empty() {
        bail!("no --agent entries; use --manifest or --agent NAME=PROGRAM");
    }
    let mut agents = Vec::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        let (name, command) = entry.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "invalid --agent '{entry}'; expected NAME=PROGRAM (argv with arguments belongs in a manifest)"
            )
        })?;
        let spec = AgentSpec {
            name: name.to_string(),
            command: vec![command.to_string()],
            profile: default_profile(),
            policy: None,
            net: default_net(),
            observe_seccomp: false,
            report_dir: None,
            debug_ports: None,
        };
        spec.validate()
            .with_context(|| format!("invalid --agent entry #{idx}"))?;
        agents.push(spec);
    }
    let manifest = Manifest {
        version: 1,
        agents,
        report_dir: None,
    };
    manifest.validate()?;
    Ok(manifest.agents)
}

/// Compatibility parser for legacy syntax.
pub fn parse_legacy_commands(tokens: &[String]) -> Result<Vec<AgentSpec>> {
    if tokens.is_empty() {
        bail!("no multi-agent command provided; use --manifest");
    }
    if tokens.iter().any(|token| token == "--") {
        bail!(
            "ambiguous multi-agent '--' separators; use --manifest or repeated --agent NAME=PROGRAM"
        );
    }
    let spec = AgentSpec {
        name: "agent-1".to_string(),
        command: tokens.to_vec(),
        profile: default_profile(),
        policy: None,
        net: default_net(),
        observe_seccomp: false,
        report_dir: None,
        debug_ports: None,
    };
    spec.validate()?;
    Ok(vec![spec])
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        bail!("agent name must be 1..64 characters");
    }
    if !name
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
    {
        bail!("agent name '{name}' contains an unsafe character; use [A-Za-z0-9_.-]");
    }
    Ok(())
}

/// An event tagged with its originating agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentEvent {
    pub agent: String,
    pub event: Event,
}

#[derive(Clone)]
pub struct MultiEventStream {
    tx: broadcast::Sender<AgentEvent>,
}

impl MultiEventStream {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.tx.subscribe()
    }

    pub fn publish(&self, agent: impl Into<String>, event: Event) {
        let _ = self.tx.send(AgentEvent {
            agent: agent.into(),
            event,
        });
    }

    pub fn bridge_agent(&self, name: String, bus: &EventBus) {
        let mut rx = bus.subscribe();
        let stream = self.clone();
        std::thread::Builder::new()
            .name(format!("vetto-multi-events-{name}"))
            .spawn(move || loop {
                match rx.blocking_recv() {
                    Ok(event) => stream.publish(name.clone(), event),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            })
            .expect("spawn multi event bridge");
    }
}

impl Default for MultiEventStream {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    #[default]
    Pending,
    Running,
    Paused,
    Exited,
    Failed,
    Terminated,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentStats {
    pub name: String,
    pub status: AgentStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub events_total: u64,
    pub blocked_attempts: u64,
    pub files: u64,
    pub file_reads: u64,
    pub file_writes: u64,
    pub execs: u64,
    pub network_total: u64,
    pub network_allowed: u64,
    pub network_blocked: u64,
    pub notices: u64,
    pub suspicious: u64,
}

impl AgentStats {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: AgentStatus::Pending,
            started_at: None,
            ended_at: None,
            exit_code: None,
            events_total: 0,
            blocked_attempts: 0,
            files: 0,
            file_reads: 0,
            file_writes: 0,
            execs: 0,
            network_total: 0,
            network_allowed: 0,
            network_blocked: 0,
            notices: 0,
            suspicious: 0,
        }
    }

    pub fn ingest(&mut self, event: &Event) {
        self.events_total += 1;
        if crate::classifier::classify_event(event).is_some() {
            self.suspicious += 1;
        }
        match event {
            Event::SessionStarted { ts, .. } => {
                self.started_at = Some(*ts);
                self.status = AgentStatus::Running;
            }
            Event::SessionEnded { ts, exit_code, .. } => {
                self.ended_at = Some(*ts);
                self.exit_code = Some(*exit_code);
                self.status = if *exit_code == 0 {
                    AgentStatus::Exited
                } else {
                    AgentStatus::Failed
                };
            }
            Event::FileObserved { access, .. } => {
                self.files += 1;
                match access {
                    FileAccess::Read => self.file_reads += 1,
                    FileAccess::Write => self.file_writes += 1,
                    FileAccess::Unknown => {}
                }
            }
            Event::ExecObserved { .. } => self.execs += 1,
            Event::BlockedAttempt { .. } => self.blocked_attempts += 1,
            Event::NetRequest { allowed, .. } => {
                self.network_total += 1;
                if *allowed {
                    self.network_allowed += 1;
                } else {
                    self.network_blocked += 1;
                }
            }
            Event::Notice { .. } => self.notices += 1,
            // Counted into events_total above like every event; multi-agent
            // rollups have no dedicated timeout field.
            Event::SessionTimeout { .. } => {}
            Event::SecretMasked { .. } => {}
            Event::DnsResolved { .. } => {}
            Event::NetEgress { .. } => {}
            Event::NetQuotaExceeded { .. } => {}
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CombinedStats {
    pub events_total: u64,
    pub blocked_attempts: u64,
    pub files: u64,
    pub file_reads: u64,
    pub file_writes: u64,
    pub execs: u64,
    pub network_total: u64,
    pub network_allowed: u64,
    pub network_blocked: u64,
    pub notices: u64,
    pub suspicious: u64,
}

impl CombinedStats {
    pub fn add(&mut self, stats: &AgentStats) {
        self.events_total += stats.events_total;
        self.blocked_attempts += stats.blocked_attempts;
        self.files += stats.files;
        self.file_reads += stats.file_reads;
        self.file_writes += stats.file_writes;
        self.execs += stats.execs;
        self.network_total += stats.network_total;
        self.network_allowed += stats.network_allowed;
        self.network_blocked += stats.network_blocked;
        self.notices += stats.notices;
        self.suspicious += stats.suspicious;
    }
}

#[derive(Clone, Default)]
pub struct MultiAggregator {
    inner: Arc<Mutex<BTreeMap<String, AgentStats>>>,
}

impl MultiAggregator {
    pub fn new(names: impl IntoIterator<Item = String>) -> Self {
        let stats = names
            .into_iter()
            .map(|name| {
                let value = AgentStats::new(name.clone());
                (name, value)
            })
            .collect();
        Self {
            inner: Arc::new(Mutex::new(stats)),
        }
    }

    pub fn ingest(&self, agent: &str, event: &Event) {
        if let Ok(mut stats) = self.inner.lock() {
            stats
                .entry(agent.to_string())
                .or_insert_with(|| AgentStats::new(agent))
                .ingest(event);
        }
    }

    pub fn set_status(&self, agent: &str, status: AgentStatus) {
        if let Ok(mut stats) = self.inner.lock() {
            stats
                .entry(agent.to_string())
                .or_insert_with(|| AgentStats::new(agent))
                .status = status;
        }
    }

    pub fn snapshot(&self) -> Vec<AgentStats> {
        self.inner
            .lock()
            .map(|stats| stats.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn combined(&self) -> CombinedStats {
        self.snapshot()
            .iter()
            .fold(CombinedStats::default(), |mut total, stats| {
                total.add(stats);
                total
            })
    }

    pub fn report_json(&self) -> serde_json::Value {
        serde_json::json!({
            "format": "vetto-multi-v1",
            "agents": self.snapshot(),
            "combined": self.combined(),
        })
    }
}

pub fn spawn_aggregator(stream: &MultiEventStream, aggregator: MultiAggregator) {
    let mut rx = stream.subscribe();
    std::thread::Builder::new()
        .name("vetto-multi-stats".into())
        .spawn(move || loop {
            match rx.blocking_recv() {
                Ok(agent_event) => aggregator.ingest(&agent_event.agent, &agent_event.event),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        })
        .expect("spawn multi stats collector");
}

#[derive(Debug, Clone)]
pub struct AgentPane {
    pub name: String,
    pub status: AgentStatus,
    pub last_line: String,
    pub output: String,
    pub stats: AgentStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn blocked(path: &str) -> Event {
        Event::BlockedAttempt {
            ts: Utc::now(),
            pid: 1,
            comm: "agent".into(),
            path: path.into(),
            source: "test".into(),
        }
    }

    #[test]
    fn manifest_rejects_ambiguous_separator_and_shell_strings() {
        let tokens = vec!["agent".into(), "--".into(), "other".into()];
        assert!(parse_legacy_commands(&tokens).is_err());
        assert!(parse_manifest_str(
            r#"version = 1
               [[agents]]
               name = "a"
               command = "echo unsafe"
            "#
        )
        .is_err());
    }

    #[test]
    fn duplicate_names_and_path_traversal_are_rejected() {
        let text = r#"
            [[agents]]
            name = "a"
            command = ["one"]
            [[agents]]
            name = "a"
            command = ["two"]
        "#;
        assert!(parse_manifest_str(text).is_err());
        let text = r#"
            [[agents]]
            name = "../a"
            command = ["one"]
        "#;
        assert!(parse_manifest_str(text).is_err());
    }

    #[test]
    fn aggregation_preserves_agent_independence() {
        let agg = MultiAggregator::new(vec!["one".into(), "two".into()]);
        agg.ingest("one", &blocked("/one"));
        agg.ingest(
            "two",
            &Event::NetRequest {
                ts: Utc::now(),
                host: "example.test".into(),
                port: 443,
                allowed: false,
            },
        );
        let rows = agg.snapshot();
        assert_eq!(rows.len(), 2);
        let one = rows.iter().find(|row| row.name == "one").expect("one");
        let two = rows.iter().find(|row| row.name == "two").expect("two");
        assert_eq!(one.blocked_attempts, 1);
        assert_eq!(one.network_total, 0);
        assert_eq!(two.network_blocked, 1);
        assert_eq!(two.blocked_attempts, 0);
        assert_eq!(agg.combined().blocked_attempts, 1);
    }

    #[test]
    fn virtual_port_pool_allocates_non_overlapping_ranges() {
        let pool = VirtualPortPool::new(48000, 10);
        let p1 = pool.allocate_ports("agent-1", 5).expect("allocate agent-1");
        let p2 = pool.allocate_ports("agent-2", 5).expect("allocate agent-2");

        assert_eq!(p1, vec![48000, 48001, 48002, 48003, 48004]);
        assert_eq!(p2, vec![48010, 48011, 48012, 48013, 48014]);
        assert_eq!(pool.allocate_relay_port(0), 47129);
        assert_eq!(pool.allocate_relay_port(1), 47130);
    }
}
