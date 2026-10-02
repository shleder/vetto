//! Policy representation after load-time resolution.

use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Linux capability tier the policy was loaded for (affects masking strategy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// Landlock + namespaces: secrets masked with mount overlays.
    Full,
    /// Landlock only (no userns): project secrets masked by explicit
    /// enumeration into the read allowlist; overlay masking unavailable.
    FsOnly,
    /// Seccomp filter only (no Landlock, no namespaces): syscall hardening
    /// and network blocks only, no filesystem isolation.
    Seccomp,
}

impl Tier {
    pub fn label(&self) -> &'static str {
        match self {
            Tier::Full => "full",
            Tier::FsOnly => "fs-only",
            Tier::Seccomp => "seccomp",
        }
    }
}

/// Seccomp syscall filtering profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeccompProfile {
    #[default]
    Default,
    AgentMin,
}

impl SeccompProfile {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "default" | "standard" => Some(Self::Default),
            "agent-min" | "agent_min" => Some(Self::AgentMin),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::AgentMin => "agent-min",
        }
    }
}

/// Network policy mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetMode {
    /// Default. Enforced on every tier (netns on FULL, seccomp-BPF on FS-ONLY).
    Off,
    /// CONNECT-level domain allowlist via the unix-fd bridge relay.
    Allowlist(Vec<String>),
    /// CONNECT-level domain and exact-port allowlist via the unix-fd bridge
    /// relay. DNS is resolved and validated by the broker before connect.
    Strict(Vec<NetRule>),
    /// Interactive domain confirmation mode with per-session caching.
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetRule {
    pub domain: String,
    pub port: u16,
}

impl NetMode {
    pub fn label(&self) -> String {
        match self {
            NetMode::Off => "off".into(),
            NetMode::Allowlist(domains) => format!("allowlist:{}", domains.join(",")),
            NetMode::Strict(rules) => format!(
                "strict:{}",
                rules
                    .iter()
                    .map(|rule| format!("{}:{}", rule.domain, rule.port))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            NetMode::Ask => "ask".into(),
        }
    }

    pub fn uses_relay(&self) -> bool {
        matches!(self, Self::Allowlist(_) | Self::Strict(_) | Self::Ask)
    }
}

/// Optional cgroup v2 resource limits configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupConfig {
    pub memory_max: Option<String>,
    pub pids_max: Option<String>,
    pub swap_max: Option<String>,
    pub cpu_max: Option<String>,
}

impl CgroupConfig {
    /// Merge another cgroup configuration strictest-wins into `self`.
    /// Concrete ceilings win over "max" and None; smaller numbers win over larger ones.
    pub fn merge_strictest(&mut self, other: &Self) {
        self.memory_max = strictest_memory_str(&self.memory_max, &other.memory_max);
        self.pids_max = strictest_pids_str(&self.pids_max, &other.pids_max);
        self.swap_max = strictest_memory_str(&self.swap_max, &other.swap_max);
        self.cpu_max = strictest_cpu_max(&self.cpu_max, &other.cpu_max);
    }
}

/// Parse human-readable or raw byte amount into bytes.
/// Returns None if string is empty, "max", or unparseable.
pub fn parse_bytes_value(input: &str) -> Option<u64> {
    crate::policy::units::parse_cgroup_memory(input).ok().flatten()
}

/// Parse byte amount supporting decimal suffixes (k/m/g/kb/mb/gb) and binary suffixes (kib/mib/gib).
/// Returns None on unparseable input or u64 multiplication overflow.
pub fn parse_byte_size(value: &str) -> Option<u64> {
    crate::policy::units::parse_bytes(value).ok()
}

/// Format byte count into human-readable string representation (B, KiB, MiB, GiB).
pub fn format_bytes(bytes: u64) -> String {
    crate::policy::units::format_bytes(bytes, crate::policy::units::UnitStandard::IecBinary)
}

/// Parse CPU limit string into an effective core ratio (e.g. 0.5 for 50%, 1.0 for 100%, 2.0 for 200%).
/// Returns None if "max", empty, or unparseable.
pub fn parse_cpu_ratio(input: &str) -> Option<f64> {
    let s = input.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("max") || s.starts_with("max ") {
        return None;
    }
    if let Some(pct_str) = s.strip_suffix('%') {
        let pct: f64 = pct_str.trim().parse().ok()?;
        return Some(pct / 100.0);
    }
    if s.contains(' ') {
        let mut parts = s.split_whitespace();
        let quota_s = parts.next()?;
        let period_s = parts.next()?;
        if quota_s.eq_ignore_ascii_case("max") {
            return None;
        }
        let quota: f64 = quota_s.parse().ok()?;
        let period: f64 = period_s.parse().ok()?;
        if period > 0.0 {
            return Some(quota / period);
        }
        return None;
    }
    if let Ok(num) = s.parse::<f64>() {
        if num > 1000.0 {
            return Some(num / 100_000.0);
        } else {
            return Some(num / 100.0);
        }
    }
    None
}

/// Parse human-readable memory limit into bytes or string representation.
pub fn parse_memory_bytes(input: &str) -> Option<String> {
    match crate::policy::units::parse_cgroup_memory(input).ok()? {
        None => Some("max".to_string()),
        Some(bytes) => Some(bytes.to_string()),
    }
}

/// Parse CPU limit (e.g. "50%", "100%", "200%", or raw quota/period "50000 100000").
pub fn parse_cpu_max(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("max") {
        return Some("max 100000".to_string());
    }
    if s.ends_with('%') {
        let pct_str = s.trim_end_matches('%').trim();
        let pct: f64 = pct_str.parse().ok()?;
        let period = 100_000u64;
        let quota = ((pct / 100.0) * period as f64) as u64;
        return Some(format!("{quota} {period}"));
    }
    if s.contains(' ') {
        return Some(s.to_string());
    }
    if let Ok(quota) = s.parse::<u64>() {
        return Some(format!("{quota} 100000"));
    }
    None
}

/// Strictest merge for memory / swap string options.
pub fn strictest_memory_str(left: &Option<String>, right: &Option<String>) -> Option<String> {
    match (left, right) {
        (Some(l), Some(r)) => {
            let l_trimmed = l.trim();
            let r_trimmed = r.trim();
            let l_bytes = parse_bytes_value(l_trimmed);
            let r_bytes = parse_bytes_value(r_trimmed);
            match (l_bytes, r_bytes) {
                (Some(lb), Some(rb)) => {
                    if lb <= rb {
                        Some(l.clone())
                    } else {
                        Some(r.clone())
                    }
                }
                (Some(_), None) => Some(l.clone()),
                (None, Some(_)) => Some(r.clone()),
                (None, None) => {
                    if l_trimmed.eq_ignore_ascii_case("max")
                        || r_trimmed.eq_ignore_ascii_case("max")
                    {
                        Some("max".to_string())
                    } else {
                        Some(l.clone())
                    }
                }
            }
        }
        (Some(l), None) => Some(l.clone()),
        (None, Some(r)) => Some(r.clone()),
        (None, None) => None,
    }
}

/// Strictest merge for pids string options.
pub fn strictest_pids_str(left: &Option<String>, right: &Option<String>) -> Option<String> {
    match (left, right) {
        (Some(l), Some(r)) => {
            let l_trimmed = l.trim();
            let r_trimmed = r.trim();
            let l_pids = if l_trimmed.eq_ignore_ascii_case("max") {
                None
            } else {
                l_trimmed.parse::<u64>().ok()
            };
            let r_pids = if r_trimmed.eq_ignore_ascii_case("max") {
                None
            } else {
                r_trimmed.parse::<u64>().ok()
            };
            match (l_pids, r_pids) {
                (Some(lp), Some(rp)) => {
                    if lp <= rp {
                        Some(l.clone())
                    } else {
                        Some(r.clone())
                    }
                }
                (Some(_), None) => Some(l.clone()),
                (None, Some(_)) => Some(r.clone()),
                (None, None) => {
                    if l_trimmed.eq_ignore_ascii_case("max")
                        || r_trimmed.eq_ignore_ascii_case("max")
                    {
                        Some("max".to_string())
                    } else {
                        Some(l.clone())
                    }
                }
            }
        }
        (Some(l), None) => Some(l.clone()),
        (None, Some(r)) => Some(r.clone()),
        (None, None) => None,
    }
}

/// Strictest merge for cpu_max string options.
pub fn strictest_cpu_max(left: &Option<String>, right: &Option<String>) -> Option<String> {
    match (left, right) {
        (Some(l), Some(r)) => {
            let l_trimmed = l.trim();
            let r_trimmed = r.trim();
            let l_ratio = parse_cpu_ratio(l_trimmed);
            let r_ratio = parse_cpu_ratio(r_trimmed);
            match (l_ratio, r_ratio) {
                (Some(lr), Some(rr)) => {
                    if lr <= rr {
                        Some(l.clone())
                    } else {
                        Some(r.clone())
                    }
                }
                (Some(_), None) => Some(l.clone()),
                (None, Some(_)) => Some(r.clone()),
                (None, None) => {
                    if l_trimmed.starts_with("max") || r_trimmed.starts_with("max") {
                        Some("max 100000".to_string())
                    } else {
                        Some(l.clone())
                    }
                }
            }
        }
        (Some(l), None) => Some(l.clone()),
        (None, Some(r)) => Some(r.clone()),
        (None, None) => None,
    }
}

/// Optional seccomp user-notify supervisor configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeccompNotifyConfig {
    pub enabled: bool,
    pub default_action: Option<String>,
    #[serde(default)]
    pub allow_syscalls: Vec<String>,
}

/// The 7-level policy hierarchy source classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PolicySourceKind {
    /// 1. System/Org Global Policy (`/etc/vetto/policy.toml` or `%ProgramData%\vetto\policy.toml`)
    SystemGlobal,
    /// 2. User Global Policy (`~/.config/vetto/policy.toml`)
    UserGlobal,
    /// 3. Built-in Profile (`default`, `strict`, `audit`, `permissive`)
    BuiltinProfile,
    /// 3b. Security Preset (`paranoid`, `balanced`, `yolo`)
    Preset,
    /// 4. Agent Preset (`codex`, `claude`, `cursor`, `aider`, `cline`, `opencode`, `copilot`, `custom`)
    AgentPreset,
    /// 5. Repository Policy (`.vetto/policy.toml` or `vetto.toml`)
    Repository,
    /// 5b. Repository Policy Fragment (`.vetto/policy.d/*.toml`)
    RepositoryFragment,
    /// 6. Local Override Policy (`.vetto.override.toml` or `.vetto/local.toml`)
    LocalOverride,
    /// 7a. Explicit CLI Flag (`--policy <file>`)
    CliExplicit,
    /// 7b. Runtime CLI Overrides (`--allow-write`, `--deny-read`, etc.)
    CliOverride,
}

impl PolicySourceKind {
    pub fn precedence(&self) -> u8 {
        match self {
            Self::SystemGlobal => 1,
            Self::UserGlobal => 2,
            Self::BuiltinProfile | Self::Preset => 3,
            Self::AgentPreset => 4,
            Self::Repository | Self::RepositoryFragment => 5,
            Self::LocalOverride => 6,
            Self::CliExplicit | Self::CliOverride => 7,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::SystemGlobal => "system-global",
            Self::UserGlobal => "user-global",
            Self::BuiltinProfile => "builtin-profile",
            Self::Preset => "preset",
            Self::AgentPreset => "agent-preset",
            Self::Repository => "repository",
            Self::RepositoryFragment => "repository-fragment",
            Self::LocalOverride => "local-override",
            Self::CliExplicit => "cli-explicit",
            Self::CliOverride => "cli-override",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyEntry {
    pub path: PathBuf,
    pub is_dir: bool,
}

/// User-facing metadata carried by a loaded policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
    pub description: String,
    pub extends: Vec<String>,
    #[serde(default)]
    pub source_kind: Option<PolicySourceKind>,
    #[serde(default)]
    pub immutable: bool,
}

/// Optional IO rate limits for Windows Job Objects and supported platforms.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoRateLimit {
    pub max_iops: Option<u64>,
    pub max_bandwidth: Option<u64>,
}

impl IoRateLimit {
    pub fn merge_strictest(&mut self, other: &Self) {
        self.max_iops = strictest(self.max_iops, other.max_iops);
        self.max_bandwidth = strictest(self.max_bandwidth, other.max_bandwidth);
    }
}

/// Optional per-agent resource ceilings applied immediately before `execve`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_seconds: Option<u64>,
    pub address_space_bytes: Option<u64>,
    pub processes: Option<u64>,
    pub open_files: Option<u64>,
    /// RLIMIT_FSIZE: maximum size of files the agent may create.
    pub file_size_bytes: Option<u64>,
    #[serde(default)]
    pub io_rate: Option<IoRateLimit>,
}

impl ResourceLimits {
    pub fn merge_strictest(&mut self, other: &Self) {
        self.cpu_seconds = strictest(self.cpu_seconds, other.cpu_seconds);
        self.address_space_bytes = strictest(self.address_space_bytes, other.address_space_bytes);
        self.processes = strictest(self.processes, other.processes);
        self.open_files = strictest(self.open_files, other.open_files);
        self.file_size_bytes = strictest(self.file_size_bytes, other.file_size_bytes);
        match (&mut self.io_rate, &other.io_rate) {
            (Some(existing), Some(incoming)) => existing.merge_strictest(incoming),
            (None, Some(incoming)) => self.io_rate = Some(incoming.clone()),
            _ => {}
        }
    }
}

fn strictest(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// Environment variables explicitly allowed into the agent process, with optional subtractive deny list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentPolicy {
    pub pass_through: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl EnvironmentPolicy {
    pub fn allows(&self, key: &OsStr) -> bool {
        let key = key.to_string_lossy();
        // Deny takes precedence. On Windows env names are case-insensitive
        // (W1): match upper-cased so `aws_secret_access_key` cannot bypass
        // `deny = ["AWS_SECRET*"]`.
        #[cfg(target_os = "windows")]
        let key_cmp: String = key.to_uppercase();
        #[cfg(not(target_os = "windows"))]
        let key_cmp: &str = &key;
        let is_denied = self.deny.iter().any(|pattern| {
            #[cfg(target_os = "windows")]
            let pattern_cmp: String = pattern.to_uppercase();
            #[cfg(not(target_os = "windows"))]
            let pattern_cmp: &str = pattern;
            pattern_cmp.strip_suffix('*').map_or_else(
                || pattern_cmp == key_cmp,
                |prefix| key_cmp.starts_with(prefix),
            )
        });
        if is_denied {
            return false;
        }

        self.pass_through.iter().any(|pattern| {
            pattern
                .strip_suffix('*')
                .map_or_else(|| pattern == key.as_ref(), |prefix| key.starts_with(prefix))
        })
    }
}

/// Subtractive rules explicitly denying read, write, network, or env access.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubtractiveRules {
    pub deny_write: Vec<PathBuf>,
    pub deny_read: Vec<PathBuf>,
    pub deny_env: Vec<String>,
    pub deny_network: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    /// Metadata from the effective policy layers.
    pub metadata: PolicyMetadata,
    /// Resource ceilings applied immediately before the agent `execve`.
    pub limits: ResourceLimits,
    /// Concrete read-write roots.
    pub allow_write: Vec<PathBuf>,
    /// Concrete read-only roots.
    pub allow_read: Vec<PathBuf>,
    /// Subtractive write deny rules.
    pub deny_write: Vec<PathBuf>,
    /// Subtractive read deny rules.
    pub deny_read: Vec<PathBuf>,
    /// Resolved display_only_deny paths that exist on this machine.
    pub deny_resolved: Vec<DenyEntry>,
    /// Environment allowlist applied immediately before agent execve.
    pub environment: EnvironmentPolicy,
    /// True when a policy layer denies direct network access. Session-level
    /// enforcement additionally depends on the CLI `--net` mode, which lives
    /// outside the policy: this field only records policy-layer intent.
    pub deny_network: bool,
    #[serde(default)]
    pub network_mode: Option<String>,
    #[serde(default)]
    pub network_allow: Vec<String>,
    /// CIDR subnets allowed for network connections.
    pub allow_cidr: Vec<String>,
    /// Per-domain byte quotas (in bytes).
    pub net_quota: std::collections::HashMap<String, u64>,
    /// TCP ports allowed for binding in Landlock (ABI >= 4).
    pub net_bind_ports: Vec<u16>,
    /// TCP ports allowed for connecting in Landlock (ABI >= 4).
    pub net_connect_ports: Vec<u16>,
    /// Allowed unix domain socket paths / patterns.
    pub allow_unix_sockets: Vec<String>,
    /// Denied unix domain socket paths to mask with /dev/null.
    pub deny_unix_sockets: Vec<String>,
    /// Seccomp syscall filtering profile ("default" or "agent-min").
    pub seccomp_profile: SeccompProfile,
    /// Optional seccomp user-notify supervisor configuration.
    pub seccomp_notify: Option<SeccompNotifyConfig>,
    /// Optional cgroup v2 resource limits configuration.
    pub cgroup: Option<CgroupConfig>,
    /// CPU quota limit (e.g. "50%").
    pub cpu_max: Option<String>,
    /// I/O priority applied before exec (e.g. "idle", "best-effort").
    pub io_priority: Option<String>,
    /// Allowed device nodes in /dev for mount namespace.
    pub dev_allow: Option<Vec<String>>,
    /// macOS unified log (os_log / logger) opt-in.
    pub oslog: bool,
    /// Windows Less Privileged AppContainer (LPAC) mode opt-in.
    pub lpac: bool,
    /// Whether this policy is in immutable enterprise lockdown mode.
    pub is_immutable: bool,
    /// Whether system-level event logging (journald, EventLog, syslog) is enabled.
    pub system_log: bool,
    /// Automatically scan project for secrets at session start and deny them.
    pub auto_deny_secrets: bool,
    /// Secrets to proxy through host credential broker without exposing to agent.
    pub secret_proxies: Vec<String>,
    /// Read-only mounts inside the mount namespace.
    pub ro_mounts: Vec<PathBuf>,
    /// Protect Git repository from modification on main/master and destructive push.
    pub git_guard: bool,
    /// Create project snapshot at session start with rollback capability.
    pub snapshot: bool,
    /// Read-only caches mounts
    pub read_only_caches: bool,
    /// Shadow mode (audit only, non-blocking)
    pub shadow: bool,
    /// Mount an isolated tmpfs over /tmp for the session.
    pub tmpfs_tmp: bool,
    /// Non-fatal findings surfaced to doctor/statusline/reports.
    pub warnings: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            metadata: PolicyMetadata::default(),
            limits: ResourceLimits::default(),
            allow_write: Vec::new(),
            allow_read: Vec::new(),
            deny_write: Vec::new(),
            deny_read: Vec::new(),
            deny_resolved: Vec::new(),
            environment: EnvironmentPolicy::default(),
            deny_network: false,
            network_mode: None,
            network_allow: Vec::new(),
            allow_cidr: Vec::new(),
            net_quota: std::collections::HashMap::new(),
            net_bind_ports: Vec::new(),
            net_connect_ports: Vec::new(),
            allow_unix_sockets: Vec::new(),
            deny_unix_sockets: Vec::new(),
            seccomp_profile: SeccompProfile::Default,
            seccomp_notify: None,
            cgroup: None,
            cpu_max: None,
            io_priority: None,
            dev_allow: None,
            oslog: false,
            lpac: false,
            is_immutable: false,
            system_log: false,
            auto_deny_secrets: false,
            secret_proxies: Vec::new(),
            ro_mounts: Vec::new(),
            git_guard: false,
            snapshot: false,
            read_only_caches: false,
            shadow: false,
            tmpfs_tmp: true,
            warnings: Vec::new(),
        }
    }
}

impl Policy {
    pub fn summary(&self) -> String {
        format!(
            "profile '{}': {} write root(s), {} read root(s), {} deny path(s) resolved",
            self.name,
            self.allow_write.len(),
            self.allow_read.len(),
            self.deny_resolved.len()
        )
    }

    /// Is `path` inside any write root? (fail-closed normalized prefix check)
    pub fn in_write_scope(&self, path: &Path) -> bool {
        let probed = normalize_scope_path(path);
        if self
            .deny_write
            .iter()
            .any(|denied| probed.starts_with(normalize_scope_path(denied)))
        {
            return false;
        }
        self.allow_write
            .iter()
            .any(|root| probed.starts_with(normalize_scope_path(root)))
    }

    /// Is `path` covered by an allow rule at all?
    pub fn in_read_scope(&self, path: &Path) -> bool {
        let probed = normalize_scope_path(path);
        if self
            .deny_read
            .iter()
            .any(|denied| probed.starts_with(normalize_scope_path(denied)))
        {
            return false;
        }
        let mut allowed = self.allow_read.iter().chain(self.allow_write.iter());
        allowed.any(|root| probed.starts_with(normalize_scope_path(root)))
    }
}

/// Strip trailing dots, square brackets around IPv6 addresses, and trailing ports.
pub fn strip_domain_port(s: &str) -> &str {
    let s = s.trim().trim_end_matches('.');
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end_bracket) = rest.find(']') {
            &rest[..end_bracket]
        } else {
            s
        }
    } else if let Some((host_part, port_part)) = s.rsplit_once(':') {
        if !port_part.is_empty()
            && port_part.chars().all(|c| c.is_ascii_digit())
            && !host_part.contains(':')
        {
            host_part
        } else {
            s
        }
    } else {
        s
    }
}

/// Collapse `.`, `..`, and redundant separators without touching the
/// filesystem (mirrors the loader's containment normalization).
pub fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let has_root = path.has_root();
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() && !has_root {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

/// Fail-closed normalization for scope decisions: resolve the longest
/// existing ancestor (follows symlink parents), then lexically normalize
/// the remainder. Pure lexical fallback when nothing exists, so `..`
/// escapes and symlink-parent escapes cannot evade the prefix comparison.
fn normalize_scope_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        let mut unresolved: Vec<std::ffi::OsString> = Vec::new();
        let mut cursor = path;
        loop {
            if let Ok(canonical) = std::fs::canonicalize(cursor) {
                let mut resolved = canonical;
                for component in unresolved.iter().rev() {
                    resolved.push(component);
                }
                return lexical_normalize(&resolved);
            }
            match (cursor.file_name(), cursor.parent()) {
                (Some(name), Some(parent)) if parent != cursor => {
                    unresolved.push(name.to_os_string());
                    cursor = parent;
                }
                _ => return lexical_normalize(path),
            }
        }
    } else {
        lexical_normalize(path)
    }
}

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

#[cfg(test)]
mod environment_tests {
    use super::EnvironmentPolicy;
    use std::ffi::OsStr;

    #[test]
    fn allowlist_is_exact_and_secrets_are_default_deny() {
        let policy = EnvironmentPolicy {
            pass_through: vec!["PATH".into(), "LC_*".into(), "SAFE_EXACT".into()],
            deny: vec!["LC_SECRET*".into()],
        };
        assert!(policy.allows(OsStr::new("PATH")));
        assert!(policy.allows(OsStr::new("LC_ALL")));
        assert!(!policy.allows(OsStr::new("LC_SECRET_VAL")));
        assert!(policy.allows(OsStr::new("SAFE_EXACT")));
        assert!(!policy.allows(OsStr::new("SAFE_EXACT_EXTRA")));
        for secret in [
            "GH_TOKEN",
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "ANTHROPIC_API_KEY",
        ] {
            assert!(!policy.allows(OsStr::new(secret)), "leaked {secret}");
        }
    }
}

#[cfg(test)]
mod cgroup_tests {
    use super::*;

    #[test]
    fn test_cgroup_merge_memory_strictest() {
        let mut cfg = CgroupConfig {
            memory_max: Some("1G".into()),
            pids_max: None,
            swap_max: None,
            cpu_max: None,
        };
        let other = CgroupConfig {
            memory_max: Some("512M".into()),
            pids_max: None,
            swap_max: None,
            cpu_max: None,
        };
        cfg.merge_strictest(&other);
        assert_eq!(cfg.memory_max.as_deref(), Some("512M"));

        // Concrete wins over "max"
        let mut cfg = CgroupConfig {
            memory_max: Some("max".into()),
            ..Default::default()
        };
        let other = CgroupConfig {
            memory_max: Some("256M".into()),
            ..Default::default()
        };
        cfg.merge_strictest(&other);
        assert_eq!(cfg.memory_max.as_deref(), Some("256M"));

        // Weaker "max" cannot loosen concrete limit
        let mut cfg = CgroupConfig {
            memory_max: Some("256M".into()),
            ..Default::default()
        };
        let other = CgroupConfig {
            memory_max: Some("max".into()),
            ..Default::default()
        };
        cfg.merge_strictest(&other);
        assert_eq!(cfg.memory_max.as_deref(), Some("256M"));

        // None loses to concrete
        let mut cfg = CgroupConfig::default();
        let other = CgroupConfig {
            memory_max: Some("512M".into()),
            ..Default::default()
        };
        cfg.merge_strictest(&other);
        assert_eq!(cfg.memory_max.as_deref(), Some("512M"));
    }

    #[test]
    fn test_cgroup_merge_pids_strictest() {
        let mut cfg = CgroupConfig {
            pids_max: Some("100".into()),
            ..Default::default()
        };
        let other = CgroupConfig {
            pids_max: Some("50".into()),
            ..Default::default()
        };
        cfg.merge_strictest(&other);
        assert_eq!(cfg.pids_max.as_deref(), Some("50"));

        // Concrete number wins over "max"
        let other_max = CgroupConfig {
            pids_max: Some("max".into()),
            ..Default::default()
        };
        cfg.merge_strictest(&other_max);
        assert_eq!(cfg.pids_max.as_deref(), Some("50"));

        let mut cfg_max = CgroupConfig {
            pids_max: Some("max".into()),
            ..Default::default()
        };
        cfg_max.merge_strictest(&cfg);
        assert_eq!(cfg_max.pids_max.as_deref(), Some("50"));
    }

    #[test]
    fn test_cgroup_merge_cpu_max_strictest() {
        let mut cfg = CgroupConfig {
            cpu_max: Some("100%".into()),
            ..Default::default()
        };
        let other = CgroupConfig {
            cpu_max: Some("50%".into()),
            ..Default::default()
        };
        cfg.merge_strictest(&other);
        assert_eq!(cfg.cpu_max.as_deref(), Some("50%"));

        // 50000 100000 (50%) vs 80% -> 50% wins
        let mut cfg = CgroupConfig {
            cpu_max: Some("80%".into()),
            ..Default::default()
        };
        let other = CgroupConfig {
            cpu_max: Some("50000 100000".into()),
            ..Default::default()
        };
        cfg.merge_strictest(&other);
        assert_eq!(cfg.cpu_max.as_deref(), Some("50000 100000"));

        // "max" loses to concrete percentage
        let mut cfg_max = CgroupConfig {
            cpu_max: Some("max 100000".into()),
            ..Default::default()
        };
        cfg_max.merge_strictest(&cfg);
        assert_eq!(cfg_max.cpu_max.as_deref(), Some("50000 100000"));
    }

    #[test]
    fn test_parse_byte_size_and_format_bytes() {
        assert_eq!(parse_byte_size("1024"), Some(1024));
        assert_eq!(parse_byte_size("2k"), Some(2048));
        assert_eq!(parse_byte_size("2kb"), Some(2000));
        assert_eq!(parse_byte_size("4kib"), Some(4096));
        assert_eq!(parse_byte_size("10mb"), Some(10_000_000));
        assert_eq!(parse_byte_size("10mib"), Some(10 * 1024 * 1024));
        assert_eq!(parse_byte_size("1g"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_byte_size("1gb"), Some(1_000_000_000));
        assert_eq!(parse_byte_size("2gib"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_byte_size("invalid"), None);

        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(1024 * 1024 * 5), "5.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024 * 3), "3.0 GiB");
    }
}
