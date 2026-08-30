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

#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Optional per-agent resource ceilings applied immediately before `execve`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_seconds: Option<u64>,
    pub address_space_bytes: Option<u64>,
    pub processes: Option<u64>,
    pub open_files: Option<u64>,
    /// RLIMIT_FSIZE: maximum size of files the agent may create.
    pub file_size_bytes: Option<u64>,
}

impl ResourceLimits {
    pub fn merge_strictest(&mut self, other: &Self) {
        self.cpu_seconds = strictest(self.cpu_seconds, other.cpu_seconds);
        self.address_space_bytes = strictest(self.address_space_bytes, other.address_space_bytes);
        self.processes = strictest(self.processes, other.processes);
        self.open_files = strictest(self.open_files, other.open_files);
        self.file_size_bytes = strictest(self.file_size_bytes, other.file_size_bytes);
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
        // Deny takes precedence
        let is_denied = self.deny.iter().any(|pattern| {
            pattern
                .strip_suffix('*')
                .map_or_else(|| pattern == key.as_ref(), |prefix| key.starts_with(prefix))
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

#[derive(Debug, Clone)]
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

    /// Is `path` inside any write root? (lexical prefix check, best-effort)
    pub fn in_write_scope(&self, path: &Path) -> bool {
        if self
            .deny_write
            .iter()
            .any(|denied| path.starts_with(denied))
        {
            return false;
        }
        self.allow_write.iter().any(|root| path.starts_with(root))
    }

    /// Is `path` covered by an allow rule at all?
    pub fn in_read_scope(&self, path: &Path) -> bool {
        if self.deny_read.iter().any(|denied| path.starts_with(denied)) {
            return false;
        }
        let mut allowed = self.allow_read.iter().chain(self.allow_write.iter());
        allowed.any(|root| path.starts_with(root))
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
