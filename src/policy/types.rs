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
    let s = input.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("max") {
        return None;
    }
    let (num_part, unit_part) = match s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        Some(idx) => (&s[..idx], s[idx..].trim().to_uppercase()),
        None => (s, String::new()),
    };
    let num: f64 = num_part.parse().ok()?;
    let multiplier: f64 = match unit_part.as_str() {
        "" | "B" => 1.0,
        "K" | "KB" | "KIB" => 1024.0,
        "M" | "MB" | "MIB" => 1024.0 * 1024.0,
        "G" | "GB" | "GIB" => 1024.0 * 1024.0 * 1024.0,
        "T" | "TB" | "TIB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((num * multiplier) as u64)
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

/// Collapse `.`, `..`, and redundant separators without touching the
/// filesystem (mirrors the loader's containment normalization).
fn lexical_normalize(path: &Path) -> PathBuf {
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
}
