//! Policy loading: profile name/context -> resolved `Policy`.
//!
//! Loader rules:
//! 1. 7-Tier Precedence Hierarchy:
//!    Tier 1: System/Org Global Policy (/etc/vetto/policy.toml or %ProgramData%\vetto\policy.toml)
//!    Tier 2: User Global Policy (~/.config/vetto/policy.toml)
//!    Tier 3: Built-in Profile (default, strict, audit, permissive) + inherited profiles
//!    Tier 4: Agent Preset (codex, claude, cursor, aider, cline, opencode, copilot, custom)
//!    Tier 5: Repository Policy (.vetto/policy.toml or vetto.toml) + Fragments (.vetto/policy.d/*.toml)
//!    Tier 6: Local Override Policy (.vetto.override.toml or .vetto/local.toml)
//!    Tier 7: Runtime CLI Flags (--policy, --allow-write, --deny-read, PolicyOverrides)
//! 2. Subtractive Rules: deny_read, deny_write, deny_env, deny_network subtract permissions.
//! 3. Enterprise Lockdown: When [security] immutable = true in Tier 1, lower layers cannot
//!    loosen security or override denied paths/limits without failing with PolicyLockdownViolation.
//! 4. FS-ONLY vs FULL tier masking semantics.

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use super::checker;
use super::conditions::{self, ConditionContext, RawConditions};
use super::defaults;
use super::glob_resolve::{self, Vars};
use super::presets;
use super::secretscan;
use super::types::{
    CgroupConfig, DenyEntry, EnvironmentPolicy, Policy, PolicyMetadata, PolicySourceKind,
    ResourceLimits, SeccompNotifyConfig, SeccompProfile, Tier,
};
use crate::error::VettoError;

/// Enumeration budget for FS-ONLY project masking (entries, not bytes).
const FS_ONLY_ENUMERATION_BUDGET: usize = 20_000;

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawLayer {
    #[serde(default)]
    pub metadata: Option<RawMetadata>,
    #[serde(default)]
    pub security: Option<RawSecurity>,
    #[serde(default)]
    pub filesystem: Option<RawFilesystem>,
    #[serde(default)]
    pub secrets: Option<RawSecrets>,
    #[serde(default)]
    pub display_only_deny: Option<RawDeny>,
    #[serde(default)]
    pub environment: Option<RawEnvironment>,
    #[serde(default)]
    pub network: Option<RawNetwork>,
    #[serde(default)]
    pub unix_sockets: Option<RawUnixSockets>,
    #[serde(default)]
    pub net_ports: Option<RawNetPorts>,
    #[serde(default)]
    pub conditions: Option<RawConditions>,
    #[serde(default)]
    pub limits: Option<RawLimits>,
    #[serde(default)]
    pub seccomp_profile: Option<String>,
    #[serde(default)]
    pub seccomp_notify: Option<RawSeccompNotify>,
    #[serde(default)]
    pub cgroup: Option<RawCgroup>,
    #[serde(default)]
    pub cpu_max: Option<String>,
    #[serde(default)]
    pub io_priority: Option<String>,
    #[serde(default)]
    pub dev_allow: Option<RawStringList>,
    #[serde(default)]
    pub platform: Option<RawPlatform>,
    #[serde(default)]
    pub observability: Option<RawObservability>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawMetadata {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub extends: Option<RawStringList>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawSecurity {
    #[serde(default)]
    pub immutable: Option<bool>,
    #[serde(default)]
    pub system_log: Option<bool>,
    #[serde(default)]
    pub auto_deny_secrets: Option<bool>,
    #[serde(default)]
    pub git_guard: Option<bool>,
    #[serde(default)]
    pub snapshot: Option<bool>,
    #[serde(default)]
    pub seccomp_profile: Option<String>,
    #[serde(default)]
    pub seccomp_notify: Option<RawSeccompNotify>,
    #[serde(default)]
    pub lpac: Option<bool>,
    #[serde(default)]
    pub oslog: Option<bool>,
    #[serde(default)]
    pub require_signed: Option<bool>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawSeccompNotify {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub default_action: Option<String>,
    #[serde(default)]
    pub allow_syscalls: Option<RawStringList>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawPlatform {
    #[serde(default)]
    pub oslog: Option<bool>,
    #[serde(default)]
    pub lpac: Option<bool>,
    #[serde(default)]
    pub io_rate: Option<RawIoRate>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawObservability {
    #[serde(default)]
    pub oslog: Option<bool>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawFilesystem {
    #[serde(default)]
    pub allow_write: Option<RawStringList>,
    #[serde(default)]
    pub allow_read: Option<RawStringList>,
    #[serde(default)]
    pub deny_write: Option<RawStringList>,
    #[serde(default)]
    pub deny_read: Option<RawStringList>,
    #[serde(default)]
    pub deny_preset: Option<RawStringList>,
    #[serde(default)]
    pub deny_glob: Option<RawStringList>,
    #[serde(default)]
    pub ro_mounts: Option<RawStringList>,
    #[serde(default)]
    pub tmpfs_tmp: Option<bool>,
    #[serde(default)]
    pub dev_allow: Option<RawStringList>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawSecrets {
    #[serde(default)]
    pub proxy: Option<RawStringList>,
    #[serde(default)]
    pub auto_deny: Option<bool>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawDeny {
    #[serde(default)]
    pub paths: Option<RawStringList>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawEnvironment {
    #[serde(default)]
    pub pass_through: Option<RawStringList>,
    #[serde(default)]
    pub deny: Option<RawStringList>,
    #[serde(default)]
    pub deny_env: Option<RawStringList>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawNetwork {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub allow: Option<RawStringList>,
    #[serde(default)]
    pub deny: Option<RawStringList>,
    #[serde(default)]
    pub deny_network: Option<RawStringList>,
    #[serde(default)]
    pub net_preset: Option<RawStringList>,
    #[serde(default)]
    pub net_presets: Option<RawStringList>,
    #[serde(default)]
    pub preset: Option<RawStringList>,
    #[serde(default)]
    pub presets: Option<RawStringList>,
    #[serde(default)]
    pub allow_cidr: Option<RawStringList>,
    #[serde(default)]
    pub allow_cidrs: Option<RawStringList>,
    #[serde(default)]
    pub net_quota: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub quota: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub net_ports: Option<RawNetPorts>,
    #[serde(default)]
    pub allow_tcp_connect: Option<Vec<u16>>,
    #[serde(default)]
    pub allow_tcp_bind: Option<Vec<u16>>,
}

#[derive(Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawNetPorts {
    #[serde(default)]
    pub allow_tcp_connect: Option<Vec<u16>>,
    #[serde(default)]
    pub allow_tcp_bind: Option<Vec<u16>>,
}

#[derive(Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawUnixSockets {
    #[serde(default)]
    pub allow: Option<RawStringList>,
    #[serde(default)]
    pub deny: Option<RawStringList>,
}

pub fn expand_net_preset(name: &str) -> Result<Vec<String>> {
    match name.trim().to_ascii_lowercase().as_str() {
        "npm" => Ok(vec!["registry.npmjs.org".to_string()]),
        "git" => Ok(vec![
            "github.com".to_string(),
            "api.github.com".to_string(),
            "codeload.github.com".to_string(),
        ]),
        "pip" | "pypi" => Ok(vec![
            "pypi.org".to_string(),
            "files.pythonhosted.org".to_string(),
        ]),
        "huggingface" | "hf" => Ok(vec![
            "huggingface.co".to_string(),
            "cdn-lfs.huggingface.co".to_string(),
        ]),
        unknown => {
            bail!("unknown net preset '{unknown}'; known presets: npm, git, pip, huggingface")
        }
    }
}

pub fn parse_quota_bytes(s: &str) -> Result<u64> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        bail!("empty quota string");
    }
    let (num_part, multiplier) = if let Some(val) = s.strip_suffix("tb") {
        (val, 1024 * 1024 * 1024 * 1024u64)
    } else if let Some(val) = s.strip_suffix("gb") {
        (val, 1024 * 1024 * 1024u64)
    } else if let Some(val) = s.strip_suffix("mb") {
        (val, 1024 * 1024u64)
    } else if let Some(val) = s.strip_suffix("kb") {
        (val, 1024u64)
    } else if let Some(val) = s.strip_suffix('b') {
        (val, 1u64)
    } else {
        (s.as_str(), 1u64)
    };
    let count: u64 = num_part
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid quota value '{s}'"))?;
    Ok(count * multiplier)
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawIoRate {
    #[serde(default)]
    pub max_iops: Option<u64>,
    #[serde(default)]
    pub max_bandwidth: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawLimits {
    #[serde(default)]
    pub cpu_seconds: Option<u64>,
    #[serde(default)]
    pub address_space_bytes: Option<u64>,
    #[serde(default)]
    pub processes: Option<u64>,
    #[serde(default)]
    pub open_files: Option<u64>,
    #[serde(default)]
    pub file_size_bytes: Option<u64>,
    #[serde(default)]
    pub cgroup: Option<RawCgroup>,
    #[serde(default)]
    pub cpu_max: Option<String>,
    #[serde(default)]
    pub io_priority: Option<String>,
    #[serde(default)]
    pub io_rate: Option<RawIoRate>,
    #[serde(default)]
    pub max_iops: Option<u64>,
    #[serde(default)]
    pub max_bandwidth: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RawCgroup {
    #[serde(default)]
    pub memory_max: Option<RawValueOrString>,
    #[serde(default)]
    pub pids_max: Option<RawValueOrString>,
    #[serde(default)]
    pub swap_max: Option<RawValueOrString>,
    #[serde(default)]
    pub cpu_max: Option<RawValueOrString>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawValueOrString {
    Num(u64),
    Str(String),
}

impl RawValueOrString {
    pub fn to_string_repr(&self) -> String {
        match self {
            Self::Num(n) => n.to_string(),
            Self::Str(s) => s.clone(),
        }
    }
}

impl RawLimits {
    fn to_resource_limits(&self) -> ResourceLimits {
        let mut io_rate = None;
        if let Some(rate) = &self.io_rate {
            let max_bandwidth = rate.max_bandwidth.as_deref().and_then(parse_bandwidth_str);
            io_rate = Some(crate::policy::types::IoRateLimit {
                max_iops: rate.max_iops,
                max_bandwidth,
            });
        }
        if self.max_iops.is_some() || self.max_bandwidth.is_some() {
            let mut io = io_rate.unwrap_or_default();
            if let Some(iops) = self.max_iops {
                io.max_iops = Some(iops);
            }
            if let Some(bw_str) = &self.max_bandwidth {
                if let Some(bw) = parse_bandwidth_str(bw_str) {
                    io.max_bandwidth = Some(bw);
                }
            }
            io_rate = Some(io);
        }
        ResourceLimits {
            cpu_seconds: self.cpu_seconds,
            address_space_bytes: self.address_space_bytes,
            processes: self.processes,
            open_files: self.open_files,
            file_size_bytes: self.file_size_bytes,
            io_rate,
        }
    }
}

pub fn parse_bandwidth_str(value: &str) -> Option<u64> {
    let lower = value.trim().to_ascii_lowercase();
    if let Ok(raw) = lower.parse::<u64>() {
        return Some(raw);
    }
    let (number, mult) = if let Some(n) = lower.strip_suffix("gib") {
        (n, 1024u64 * 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("mib") {
        (n, 1024u64 * 1024)
    } else if let Some(n) = lower.strip_suffix("kib") {
        (n, 1024u64)
    } else if let Some(n) = lower.strip_suffix("gb") {
        (n, 1000u64 * 1000 * 1000)
    } else if let Some(n) = lower.strip_suffix("mb") {
        (n, 1000u64 * 1000)
    } else if let Some(n) = lower.strip_suffix("kb") {
        (n, 1000u64)
    } else if let Some(n) = lower.strip_suffix('g') {
        (n, 1000u64 * 1000 * 1000)
    } else if let Some(n) = lower.strip_suffix('m') {
        (n, 1000u64 * 1000)
    } else if let Some(n) = lower.strip_suffix('k') {
        (n, 1000u64)
    } else {
        let n = lower.strip_suffix('b')?;
        (n, 1u64)
    };
    let base: u64 = number.trim().parse().ok()?;
    base.checked_mul(mult)
}

/// String or array form for convenient TOML definitions.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum RawStringList {
    One(String),
    Many(Vec<String>),
}

impl RawStringList {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }

    pub fn as_slice(&self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct MergedPolicy {
    pub metadata: PolicyMetadata,
    pub limits: ResourceLimits,
    pub allow_write: Vec<String>,
    pub allow_read: Vec<String>,
    pub deny_write: Vec<String>,
    pub deny_read: Vec<String>,
    pub deny_paths: Vec<String>,
    pub deny_preset: Vec<String>,
    pub deny_glob: Vec<String>,
    pub ro_mounts: Vec<String>,
    pub pass_through: Vec<String>,
    pub deny_env: Vec<String>,
    pub deny_network: Vec<String>,
    pub secret_proxies: Vec<String>,
    pub network_mode: Option<String>,
    pub network_allow: Vec<String>,
    pub allow_cidr: Vec<String>,
    pub net_quota: std::collections::HashMap<String, u64>,
    pub net_bind_ports: Vec<u16>,
    pub net_connect_ports: Vec<u16>,
    pub allow_unix_sockets: Vec<String>,
    pub oslog: bool,
    pub lpac: bool,
    pub is_immutable: bool,
    pub system_log: bool,
    pub auto_deny_secrets: bool,
    pub git_guard: bool,
    pub snapshot: bool,
    pub tmpfs_tmp: Option<bool>,
    pub seccomp_profile: Option<String>,
    pub seccomp_notify: Option<SeccompNotifyConfig>,
    pub cgroup: Option<CgroupConfig>,
    pub cpu_max: Option<String>,
    pub io_priority: Option<String>,
    pub dev_allow: Option<Vec<String>>,
    pub require_signed: bool,
}

impl MergedPolicy {
    fn apply(&mut self, layer: &RawLayer, source_kind: PolicySourceKind) -> Result<()> {
        // Check enterprise lockdown violation if currently locked down
        if self.is_immutable
            && source_kind.precedence() > PolicySourceKind::SystemGlobal.precedence()
        {
            // Cannot override security immutability or weaken limits
            if let Some(sec) = &layer.security {
                if sec.immutable == Some(false) {
                    return Err(anyhow::Error::new(VettoError::PolicyLockdownViolation(
                        "cannot unset immutable enterprise lockdown".into(),
                    )));
                }
            }
        }

        if let Some(sec) = &layer.security {
            if let Some(true) = sec.immutable {
                self.is_immutable = true;
            }
            if let Some(slog) = sec.system_log {
                self.system_log = slog;
            }
            if let Some(true) = sec.auto_deny_secrets {
                self.auto_deny_secrets = true;
            }
            if let Some(true) = sec.git_guard {
                self.git_guard = true;
            }
            if let Some(true) = sec.snapshot {
                self.snapshot = true;
            }
            if let Some(prof) = &sec.seccomp_profile {
                self.seccomp_profile = Some(prof.clone());
            }
            if let Some(notif) = &sec.seccomp_notify {
                self.seccomp_notify = Some(SeccompNotifyConfig {
                    enabled: notif.enabled.unwrap_or(true),
                    default_action: notif.default_action.clone(),
                    allow_syscalls: notif
                        .allow_syscalls
                        .clone()
                        .map(RawStringList::into_vec)
                        .unwrap_or_default(),
                });
            }
            if let Some(oslog) = sec.oslog {
                self.oslog = oslog;
            }
            if let Some(lpac) = sec.lpac {
                self.lpac = lpac;
            }
            if let Some(true) = sec.require_signed {
                self.require_signed = true;
            }
        }

        if let Some(prof) = &layer.seccomp_profile {
            self.seccomp_profile = Some(prof.clone());
        }
        if let Some(notif) = &layer.seccomp_notify {
            self.seccomp_notify = Some(SeccompNotifyConfig {
                enabled: notif.enabled.unwrap_or(true),
                default_action: notif.default_action.clone(),
                allow_syscalls: notif
                    .allow_syscalls
                    .clone()
                    .map(RawStringList::into_vec)
                    .unwrap_or_default(),
            });
        }

        if let Some(plat) = &layer.platform {
            if let Some(oslog) = plat.oslog {
                self.oslog = oslog;
            }
            if let Some(lpac) = plat.lpac {
                self.lpac = lpac;
            }
            if let Some(io) = &plat.io_rate {
                let max_bandwidth = io.max_bandwidth.as_deref().and_then(parse_bandwidth_str);
                let incoming = crate::policy::types::IoRateLimit {
                    max_iops: io.max_iops,
                    max_bandwidth,
                };
                if let Some(existing) = &mut self.limits.io_rate {
                    existing.merge_strictest(&incoming);
                } else {
                    self.limits.io_rate = Some(incoming);
                }
            }
        }

        if let Some(obs) = &layer.observability {
            if let Some(oslog) = obs.oslog {
                self.oslog = oslog;
            }
        }

        if let Some(metadata) = &layer.metadata {
            if let Some(name) = &metadata.name {
                if !name.is_empty() {
                    self.metadata.name = name.clone();
                }
            }
            if let Some(description) = &metadata.description {
                self.metadata.description = description.clone();
            }
        }

        if let Some(filesystem) = &layer.filesystem {
            if let Some(allow_write) = &filesystem.allow_write {
                self.allow_write.extend(allow_write.clone().into_vec());
            }
            if let Some(allow_read) = &filesystem.allow_read {
                self.allow_read.extend(allow_read.clone().into_vec());
            }
            if let Some(deny_write) = &filesystem.deny_write {
                self.deny_write.extend(deny_write.clone().into_vec());
            }
            if let Some(deny_read) = &filesystem.deny_read {
                self.deny_read.extend(deny_read.clone().into_vec());
            }
            if let Some(deny_preset) = &filesystem.deny_preset {
                self.deny_preset.extend(deny_preset.clone().into_vec());
            }
            if let Some(deny_glob) = &filesystem.deny_glob {
                self.deny_glob.extend(deny_glob.clone().into_vec());
            }
            if let Some(ro_mounts) = &filesystem.ro_mounts {
                self.ro_mounts.extend(ro_mounts.clone().into_vec());
            }
            if let Some(tmpfs) = filesystem.tmpfs_tmp {
                self.tmpfs_tmp = Some(tmpfs);
            }
            if let Some(dev_allow) = &filesystem.dev_allow {
                self.dev_allow = Some(dev_allow.clone().into_vec());
            }
        }

        if let Some(dev_allow) = &layer.dev_allow {
            self.dev_allow = Some(dev_allow.clone().into_vec());
        }

        if let Some(secrets) = &layer.secrets {
            if let Some(proxy) = &secrets.proxy {
                self.secret_proxies.extend(proxy.clone().into_vec());
            }
            if let Some(true) = secrets.auto_deny {
                self.auto_deny_secrets = true;
            }
        }

        if let Some(deny) = &layer.display_only_deny {
            if let Some(paths) = &deny.paths {
                self.deny_paths.extend(paths.clone().into_vec());
            }
        }

        if let Some(environment) = &layer.environment {
            if let Some(pass_through) = &environment.pass_through {
                self.pass_through.extend(pass_through.clone().into_vec());
            }
            if let Some(deny) = &environment.deny {
                self.deny_env.extend(deny.clone().into_vec());
            }
            if let Some(deny_env) = &environment.deny_env {
                self.deny_env.extend(deny_env.clone().into_vec());
            }
        }

        if let Some(network) = &layer.network {
            if let Some(mode) = &network.mode {
                self.network_mode = Some(mode.clone());
            }
            if let Some(allow) = &network.allow {
                self.network_allow.extend(allow.clone().into_vec());
            }
            if let Some(deny) = &network.deny {
                self.deny_network.extend(deny.clone().into_vec());
            }
            if let Some(deny_network) = &network.deny_network {
                self.deny_network.extend(deny_network.clone().into_vec());
            }
            for presets in [
                &network.net_preset,
                &network.net_presets,
                &network.preset,
                &network.presets,
            ]
            .into_iter()
            .flatten()
            {
                for preset_name in presets.clone().into_vec() {
                    let domains = expand_net_preset(&preset_name)?;
                    self.network_allow.extend(domains);
                }
            }
            if let Some(allow_cidr) = &network.allow_cidr {
                self.allow_cidr.extend(allow_cidr.clone().into_vec());
            }
            if let Some(allow_cidrs) = &network.allow_cidrs {
                self.allow_cidr.extend(allow_cidrs.clone().into_vec());
            }
            for quotas in [&network.net_quota, &network.quota].into_iter().flatten() {
                for (domain, val) in quotas {
                    let bytes = parse_quota_bytes(val)?;
                    self.net_quota.insert(domain.clone(), bytes);
                }
            }
            if let Some(ports) = &network.net_ports {
                if let Some(connect) = &ports.allow_tcp_connect {
                    self.net_connect_ports.extend(connect);
                }
                if let Some(bind) = &ports.allow_tcp_bind {
                    self.net_bind_ports.extend(bind);
                }
            }
            if let Some(connect) = &network.allow_tcp_connect {
                self.net_connect_ports.extend(connect);
            }
            if let Some(bind) = &network.allow_tcp_bind {
                self.net_bind_ports.extend(bind);
            }
        }

        if let Some(ports) = &layer.net_ports {
            if let Some(connect) = &ports.allow_tcp_connect {
                self.net_connect_ports.extend(connect);
            }
            if let Some(bind) = &ports.allow_tcp_bind {
                self.net_bind_ports.extend(bind);
            }
        }

        if let Some(unix_socks) = &layer.unix_sockets {
            if let Some(allow) = &unix_socks.allow {
                self.allow_unix_sockets.extend(allow.clone().into_vec());
            }
        }

        if let Some(limits) = &layer.limits {
            self.limits.merge_strictest(&limits.to_resource_limits());
            if let Some(cg) = &limits.cgroup {
                self.cgroup = Some(CgroupConfig {
                    memory_max: cg.memory_max.as_ref().map(|m| m.to_string_repr()),
                    pids_max: cg.pids_max.as_ref().map(|p| p.to_string_repr()),
                    swap_max: cg.swap_max.as_ref().map(|s| s.to_string_repr()),
                    cpu_max: cg.cpu_max.as_ref().map(|c| c.to_string_repr()),
                });
            }
            if let Some(cpu) = &limits.cpu_max {
                self.cpu_max = Some(cpu.clone());
            }
            if let Some(ioprio) = &limits.io_priority {
                self.io_priority = Some(ioprio.clone());
            }
        }
        if let Some(cg) = &layer.cgroup {
            self.cgroup = Some(CgroupConfig {
                memory_max: cg.memory_max.as_ref().map(|m| m.to_string_repr()),
                pids_max: cg.pids_max.as_ref().map(|p| p.to_string_repr()),
                swap_max: cg.swap_max.as_ref().map(|s| s.to_string_repr()),
                cpu_max: cg.cpu_max.as_ref().map(|c| c.to_string_repr()),
            });
        }
        if let Some(cpu) = &layer.cpu_max {
            self.cpu_max = Some(cpu.clone());
        }
        if let Some(ioprio) = &layer.io_priority {
            self.io_priority = Some(ioprio.clone());
        }

        Ok(())
    }

    fn deduplicate(&mut self) {
        deduplicate_strings(&mut self.allow_write);
        deduplicate_strings(&mut self.allow_read);
        deduplicate_strings(&mut self.deny_write);
        deduplicate_strings(&mut self.deny_read);
        deduplicate_strings(&mut self.deny_paths);
        deduplicate_strings(&mut self.deny_preset);
        deduplicate_strings(&mut self.deny_glob);
        deduplicate_strings(&mut self.ro_mounts);
        deduplicate_strings(&mut self.secret_proxies);
        deduplicate_strings(&mut self.pass_through);
        deduplicate_strings(&mut self.deny_env);
        deduplicate_strings(&mut self.deny_network);
        deduplicate_strings(&mut self.network_allow);
        deduplicate_strings(&mut self.allow_cidr);
        deduplicate_strings(&mut self.allow_unix_sockets);
        self.net_bind_ports.sort_unstable();
        self.net_bind_ports.dedup();
        self.net_connect_ports.sort_unstable();
        self.net_connect_ports.dedup();
        deduplicate_strings(&mut self.metadata.extends);
    }
}

/// Additive and subtractive command-line-ready policy changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyOverrides {
    pub allow_write: Vec<String>,
    pub allow_read: Vec<String>,
    pub deny_write: Vec<String>,
    pub deny_read: Vec<String>,
    pub display_only_deny: Vec<String>,
    pub deny_glob: Vec<String>,
    pub ro_mounts: Vec<String>,
    pub pass_through: Vec<String>,
    pub deny_env: Vec<String>,
    pub deny_network: Vec<String>,
    pub oslog: Option<bool>,
    pub lpac: Option<bool>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub limits: Option<ResourceLimits>,
    pub git_guard: Option<bool>,
    pub snapshot: Option<bool>,
    pub auto_deny_secrets: Option<bool>,
}

/// Context for the 7-tier layered policy loader.
#[derive(Debug, Clone)]
pub struct PolicyLoadOptions {
    pub agent: Option<String>,
    pub preset: Option<crate::policy::presets::Preset>,
    pub branch: Option<String>,
    pub git_tag: Option<String>,
    pub project_policy: Option<PathBuf>,
    pub system_policy: Option<PathBuf>,
    pub user_policy: Option<PathBuf>,
    pub include_system_policy: bool,
    pub include_user_policy: bool,
    pub include_project_policy: bool,
    pub include_fragments: bool,
    pub include_local_override: bool,
    pub require_signed: bool,
    pub overrides: PolicyOverrides,
}

impl Default for PolicyLoadOptions {
    fn default() -> Self {
        Self {
            agent: None,
            preset: None,
            branch: None,
            git_tag: None,
            project_policy: None,
            system_policy: None,
            user_policy: None,
            include_system_policy: true,
            include_user_policy: true,
            include_project_policy: true,
            include_fragments: true,
            include_local_override: true,
            require_signed: false,
            overrides: PolicyOverrides::default(),
        }
    }
}

/// The 7-tier Hierarchical Policy Loader.
pub struct LayeredPolicyLoader {
    pub system_policy_path: Option<PathBuf>,
    pub user_policy_path: Option<PathBuf>,
    pub load_system_policy: bool,
    pub load_user_policy: bool,
    pub load_fragments: bool,
    pub load_local_override: bool,
    pub require_signed: bool,
}

impl Default for LayeredPolicyLoader {
    fn default() -> Self {
        Self::new()
    }
}

fn read_layer_file(path: &Path, require_signed: bool) -> Result<String> {
    if require_signed {
        super::crypto::verify_policy_file(path, None, None).with_context(|| {
            format!(
                "policy file '{}' failed signature verification (require_signed is active)",
                path.display()
            )
        })?;
    }
    std::fs::read_to_string(path)
        .with_context(|| format!("failed to read policy file {}", path.display()))
}

impl LayeredPolicyLoader {
    pub fn new() -> Self {
        Self {
            system_policy_path: None,
            user_policy_path: None,
            load_system_policy: true,
            load_user_policy: true,
            load_fragments: true,
            load_local_override: true,
            require_signed: false,
        }
    }

    pub fn load(
        &self,
        profile: &str,
        custom_path: Option<&Path>,
        project: &Path,
        home: &Path,
        tier: Tier,
        options: &PolicyLoadOptions,
    ) -> Result<Policy> {
        let mut merged = MergedPolicy::default();
        merged.metadata.name = if custom_path.is_some() {
            format!("custom:{profile}")
        } else {
            profile.to_string()
        };

        let branch = options
            .branch
            .clone()
            .or_else(|| conditions::detect_git_branch(project));
        let git_tag = options
            .git_tag
            .clone()
            .or_else(|| conditions::detect_git_tag(project));

        let context = ConditionContext {
            project,
            branch: branch.as_deref(),
            git_tag: git_tag.as_deref(),
            agent: options.agent.as_deref(),
            os: None,
            env: None,
        };

        let mut stack = Vec::new();

        // -------------------------------------------------------------------
        // Tier 1: System/Org Global Policy
        // -------------------------------------------------------------------
        if self.load_system_policy && options.include_system_policy {
            let sys_path = options
                .system_policy
                .clone()
                .or_else(|| self.system_policy_path.clone())
                .or_else(default_system_policy_path);
            if let Some(path) = sys_path {
                if path.is_file() {
                    // Security verification on Unix: verify owner root (uid 0) and not world-writable
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        if let Ok(meta) = std::fs::symlink_metadata(&path) {
                            if meta.uid() != 0 {
                                eprintln!(
                                    "vetto: warning: system policy '{}' is not owned by root (uid {})",
                                    path.display(),
                                    meta.uid()
                                );
                            }
                            if (meta.mode() & 0o002) != 0 {
                                eprintln!(
                                    "vetto: warning: system policy '{}' is world-writable (mode {:o})",
                                    path.display(),
                                    meta.mode()
                                );
                            }
                        }
                    }
                    let req_signed = options.require_signed || self.require_signed;
                    if let Ok(text) = read_layer_file(&path, req_signed) {
                        let label = format!("system:{}", path.display());
                        let layer = parse_layer(&text, &label)?;
                        merge_layer(
                            &layer,
                            &label,
                            &context,
                            &mut stack,
                            &mut merged,
                            PolicySourceKind::SystemGlobal,
                        )?;
                    }
                }
            }
        }

        // -------------------------------------------------------------------
        // Tier 2: User Global Policy
        // -------------------------------------------------------------------
        if self.load_user_policy && options.include_user_policy {
            let user_path = options
                .user_policy
                .clone()
                .or_else(|| self.user_policy_path.clone())
                .or_else(|| default_user_policy_path(home));
            if let Some(path) = user_path {
                if path.is_file() {
                    let req_signed =
                        merged.require_signed || options.require_signed || self.require_signed;
                    if let Ok(text) = read_layer_file(&path, req_signed) {
                        let label = format!("user:{}", path.display());
                        let layer = parse_layer(&text, &label)?;
                        merge_layer(
                            &layer,
                            &label,
                            &context,
                            &mut stack,
                            &mut merged,
                            PolicySourceKind::UserGlobal,
                        )?;
                    }
                }
            }
        }

        // -------------------------------------------------------------------
        // Tier 3: Built-in Profile
        // -------------------------------------------------------------------
        let base_profile = defaults::builtin(profile).map(|_| profile);
        if base_profile.is_none() && custom_path.is_none() {
            bail!(
                "unknown profile '{}'; known profiles: {}",
                profile,
                defaults::PROFILE_NAMES.join(", ")
            );
        }

        if let Some(base_profile) = base_profile {
            stack.push(base_profile.to_string());
            let base_text = defaults::builtin(base_profile).expect("base profile checked above");
            let base = parse_layer(base_text, base_profile)?;
            if base.environment.is_none() && merged.pass_through.is_empty() {
                merged.pass_through = defaults::default_env_passthrough();
            }
            merge_layer(
                &base,
                base_profile,
                &context,
                &mut stack,
                &mut merged,
                PolicySourceKind::BuiltinProfile,
            )?;
        }

        // -------------------------------------------------------------------
        // Tier 3b: Security Preset (paranoid, balanced, yolo)
        // -------------------------------------------------------------------
        if let Some(preset) = options.preset {
            let layer = crate::policy::presets::preset_layer(preset, options.agent.as_deref());
            let label = format!("preset:{}", preset.as_str());
            merge_layer(
                &layer,
                &label,
                &context,
                &mut stack,
                &mut merged,
                PolicySourceKind::Preset,
            )?;
        }

        // -------------------------------------------------------------------
        // Tier 4: Agent Preset
        // -------------------------------------------------------------------
        let agent_path = match options.agent.as_deref() {
            Some(agent) => {
                let p = agent_root(home, agent)?;
                let _ = std::fs::create_dir_all(&p);
                Some(p)
            }
            None => None,
        };
        if let Some(agent) = options.agent.as_deref() {
            let text = defaults::agent_builtin(agent).ok_or_else(|| {
                anyhow!(
                    "unknown agent '{}'; known agents: {}",
                    agent,
                    defaults::AGENT_PROFILE_NAMES.join(", ")
                )
            })?;
            let layer = parse_layer(text, &format!("agent:{agent}"))?;
            merge_layer(
                &layer,
                &format!("agent:{agent}"),
                &context,
                &mut stack,
                &mut merged,
                PolicySourceKind::AgentPreset,
            )?;
        }

        // -------------------------------------------------------------------
        // Tier 5: Repository Policy (policy.toml, .vetto/policy.toml, or vetto.toml) + Fragments
        // -------------------------------------------------------------------
        let mut applied_project_path = None;
        if options.include_project_policy {
            let (path, explicit) = match &options.project_policy {
                Some(path) => (Some(path.clone()), true),
                None => {
                    let dot_vetto_policy = project.join(".vetto/policy.toml");
                    let policy_toml = project.join("policy.toml");
                    let vetto_toml = project.join("vetto.toml");
                    if is_usable_file(&dot_vetto_policy) {
                        (Some(dot_vetto_policy), false)
                    } else if is_usable_file(&policy_toml) {
                        (Some(policy_toml), false)
                    } else if is_usable_file(&vetto_toml) {
                        (Some(vetto_toml), false)
                    } else {
                        (None, false)
                    }
                }
            };
            if let Some(path) = path {
                if explicit
                    && std::fs::symlink_metadata(&path)
                        .map(|metadata| metadata.file_type().is_symlink())
                        .unwrap_or(false)
                {
                    bail!(
                        "project policy file '{}' must not be a symlink",
                        path.display()
                    );
                }
                let req_signed =
                    merged.require_signed || options.require_signed || self.require_signed;
                let text = read_layer_file(&path, req_signed)?;
                let label = path.display().to_string();
                let layer = parse_layer(&text, &label)?;
                merge_layer(
                    &layer,
                    &label,
                    &context,
                    &mut stack,
                    &mut merged,
                    PolicySourceKind::Repository,
                )?;
                applied_project_path = Some(path);
            } else if explicit {
                let path = options
                    .project_policy
                    .as_deref()
                    .map_or_else(|| Path::new("vetto.toml"), |path| path);
                bail!("project policy file '{}' was not found", path.display());
            }

            // Fragment Directory (.vetto/policy.d/*.toml)
            if self.load_fragments && options.include_fragments {
                let fragments_dir = project.join(".vetto/policy.d");
                if fragments_dir.is_dir() {
                    let mut fragment_files = Vec::new();
                    if let Ok(entries) = std::fs::read_dir(&fragments_dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_file() && path.extension().is_some_and(|ext| ext == "toml") {
                                fragment_files.push(path);
                            }
                        }
                    }
                    // Sort deterministically alphabetically
                    fragment_files.sort();
                    for frag_path in fragment_files {
                        let req_signed =
                            merged.require_signed || options.require_signed || self.require_signed;
                        if let Ok(text) = read_layer_file(&frag_path, req_signed) {
                            let label = frag_path.display().to_string();
                            let layer = parse_layer(&text, &label)?;
                            merge_layer(
                                &layer,
                                &label,
                                &context,
                                &mut stack,
                                &mut merged,
                                PolicySourceKind::RepositoryFragment,
                            )?;
                        }
                    }
                }
            }
        }

        // -------------------------------------------------------------------
        // Tier 6: Local Override Policy (.vetto.override.toml or .vetto/local.toml)
        // -------------------------------------------------------------------
        if self.load_local_override && options.include_local_override {
            let override_file = project.join(".vetto.override.toml");
            let local_file = project.join(".vetto/local.toml");
            let local_path = if is_usable_file(&override_file) {
                Some(override_file)
            } else if is_usable_file(&local_file) {
                Some(local_file)
            } else {
                None
            };
            if let Some(path) = local_path {
                let req_signed =
                    merged.require_signed || options.require_signed || self.require_signed;
                if let Ok(text) = read_layer_file(&path, req_signed) {
                    let label = format!("override:{}", path.display());
                    let layer = parse_layer(&text, &label)?;
                    merge_layer(
                        &layer,
                        &label,
                        &context,
                        &mut stack,
                        &mut merged,
                        PolicySourceKind::LocalOverride,
                    )?;
                }
            }
        }

        // -------------------------------------------------------------------
        // Tier 7: Runtime CLI Flags & Overrides
        // -------------------------------------------------------------------
        if let Some(path) = custom_path {
            let duplicate_project = applied_project_path
                .as_deref()
                .and_then(|project_path| same_file_path(project_path, path))
                .unwrap_or(false);
            if !duplicate_project {
                let req_signed =
                    merged.require_signed || options.require_signed || self.require_signed;
                let text = read_layer_file(path, req_signed)?;
                let label = format!("cli:{}", path.display());
                let layer = parse_layer(&text, &label)?;
                merge_layer(
                    &layer,
                    &label,
                    &context,
                    &mut stack,
                    &mut merged,
                    PolicySourceKind::CliExplicit,
                )?;
            }
        }

        apply_overrides(&mut merged, &options.overrides)?;
        merged.deduplicate();

        if merged.allow_write.is_empty() {
            bail!("effective policy has no filesystem.allow_write roots");
        }

        build_policy(
            profile,
            custom_path.is_some(),
            project,
            home,
            tier,
            &merged,
            agent_path.as_deref(),
        )
    }
}

fn is_usable_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn default_system_policy_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(PathBuf::from("/etc/vetto/policy.toml"))
    }
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map(|prog_data| PathBuf::from(prog_data).join("vetto/policy.toml"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

fn default_user_policy_path(home: &Path) -> Option<PathBuf> {
    let dot_vetto_config = home.join(".vetto/config.toml");
    if is_usable_file(&dot_vetto_config) {
        return Some(dot_vetto_config);
    }
    let dot_vetto_policy = home.join(".vetto/policy.toml");
    if is_usable_file(&dot_vetto_policy) {
        return Some(dot_vetto_policy);
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let xdg_path = PathBuf::from(xdg).join("vetto/policy.toml");
        if is_usable_file(&xdg_path) {
            return Some(xdg_path);
        }
    }
    let config_policy = home.join(".config/vetto/policy.toml");
    if is_usable_file(&config_policy) {
        return Some(config_policy);
    }
    Some(config_policy)
}

/// Load a policy either from a built-in profile name or a custom TOML path,
/// resolved for the given tier.
pub fn load(
    profile: &str,
    custom_path: Option<&Path>,
    project: &Path,
    home: &Path,
    tier: Tier,
) -> Result<Policy> {
    let options = PolicyLoadOptions {
        include_project_policy: false,
        include_system_policy: false,
        include_user_policy: false,
        include_fragments: false,
        include_local_override: false,
        ..PolicyLoadOptions::default()
    };
    load_with_options(profile, custom_path, project, home, tier, &options)
}

/// Load a policy with optional agent, project, condition, and CLI override context.
pub fn load_with_options(
    profile: &str,
    custom_path: Option<&Path>,
    project: &Path,
    home: &Path,
    tier: Tier,
    options: &PolicyLoadOptions,
) -> Result<Policy> {
    let loader = LayeredPolicyLoader::new();
    loader.load(profile, custom_path, project, home, tier, options)
}

/// Compatibility alias for callers that prefer an explicit context name.
pub fn load_with_context(
    profile: &str,
    custom_path: Option<&Path>,
    project: &Path,
    home: &Path,
    tier: Tier,
    options: &PolicyLoadOptions,
) -> Result<Policy> {
    load_with_options(profile, custom_path, project, home, tier, options)
}

fn parse_layer(text: &str, label: &str) -> Result<RawLayer> {
    toml::from_str(text).with_context(|| format!("failed to parse policy '{label}'"))
}

fn merge_layer(
    layer: &RawLayer,
    source: &str,
    context: &ConditionContext<'_>,
    stack: &mut Vec<String>,
    merged: &mut MergedPolicy,
    source_kind: PolicySourceKind,
) -> Result<()> {
    if let Some(conditions) = &layer.conditions {
        if !conditions::conditions_match(conditions, context) {
            return Ok(());
        }
    }

    let parents = layer
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.extends.clone())
        .map(RawStringList::into_vec)
        .unwrap_or_default();
    for parent in parents {
        validate_parent_name(&parent)?;
        if stack.iter().any(|current| current == &parent) {
            bail!("policy inheritance cycle involving '{parent}' in {source}");
        }
        let text = defaults::builtin(&parent).ok_or_else(|| {
            anyhow!(
                "unknown inherited profile '{}'; only built-in profiles may be extended",
                parent
            )
        })?;
        let parent_layer = parse_layer(text, &format!("inherited:{parent}"))?;
        stack.push(parent.clone());
        merge_layer(
            &parent_layer,
            &format!("inherited:{parent}"),
            context,
            stack,
            merged,
            PolicySourceKind::BuiltinProfile,
        )?;
        stack.pop();
        if !merged.metadata.extends.contains(&parent) {
            merged.metadata.extends.push(parent);
        }
    }

    merged.apply(layer, source_kind)?;
    Ok(())
}

fn validate_parent_name(parent: &str) -> Result<()> {
    if parent.is_empty()
        || parent == "."
        || parent == ".."
        || parent.contains('/')
        || parent.contains('\\')
        || parent
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
    {
        bail!("invalid inherited profile name '{parent}'");
    }
    Ok(())
}

fn apply_overrides(merged: &mut MergedPolicy, overrides: &PolicyOverrides) -> Result<()> {
    if merged.is_immutable
        && (!overrides.allow_write.is_empty() || !overrides.allow_read.is_empty())
    {
        // Check if CLI overrides attempt to widen when locked down
        // In enterprise lockdown mode, adding paths via CLI is prohibited
        return Err(anyhow::Error::new(VettoError::PolicyLockdownViolation(
            "cannot add filesystem allow paths via CLI in enterprise lockdown mode".into(),
        )));
    }

    merged.allow_write.extend(overrides.allow_write.clone());
    merged.allow_read.extend(overrides.allow_read.clone());
    merged.deny_write.extend(overrides.deny_write.clone());
    merged.deny_read.extend(overrides.deny_read.clone());
    merged
        .deny_paths
        .extend(overrides.display_only_deny.clone());
    merged.deny_glob.extend(overrides.deny_glob.clone());
    merged.ro_mounts.extend(overrides.ro_mounts.clone());
    merged.pass_through.extend(overrides.pass_through.clone());
    merged.deny_env.extend(overrides.deny_env.clone());
    merged.deny_network.extend(overrides.deny_network.clone());

    if let Some(true) = overrides.git_guard {
        merged.git_guard = true;
    }
    if let Some(true) = overrides.snapshot {
        merged.snapshot = true;
    }
    if let Some(true) = overrides.auto_deny_secrets {
        merged.auto_deny_secrets = true;
    }

    if let Some(name) = &overrides.name {
        if !name.is_empty() {
            merged.metadata.name = name.clone();
        }
    }
    if let Some(description) = &overrides.description {
        merged.metadata.description = description.clone();
    }
    if let Some(limits) = &overrides.limits {
        merged.limits.merge_strictest(limits);
    }
    if let Some(oslog) = overrides.oslog {
        merged.oslog = oslog;
    }
    if let Some(lpac) = overrides.lpac {
        merged.lpac = lpac;
    }
    Ok(())
}

fn build_policy(
    profile: &str,
    custom: bool,
    project: &Path,
    home: &Path,
    tier: Tier,
    merged: &MergedPolicy,
    agent: Option<&Path>,
) -> Result<Policy> {
    let vars = Vars { project, home };
    let mut warnings = Vec::new();

    let mut allow_write_resolved = resolve_list(&merged.allow_write, &vars, agent)?;
    let mut allow_read_resolved = resolve_list(&merged.allow_read, &vars, agent)?;
    let deny_write_resolved = resolve_list(&merged.deny_write, &vars, agent)?;
    let deny_read_resolved = resolve_list(&merged.deny_read, &vars, agent)?;
    let ro_mounts_resolved = resolve_list(&merged.ro_mounts, &vars, agent)?;

    for ro in &ro_mounts_resolved {
        if !allow_read_resolved.contains(ro) {
            allow_read_resolved.push(ro.clone());
        }
    }

    let mut deny_resolved = Vec::new();
    let mut deny_set = BTreeSet::new();

    // Accumulate all deny sources: deny_paths, deny_read, deny_write, deny_preset, deny_glob
    let mut all_deny_entries: Vec<String> = merged
        .deny_paths
        .iter()
        .chain(merged.deny_read.iter())
        .chain(merged.deny_write.iter())
        .cloned()
        .collect();

    for preset_name in &merged.deny_preset {
        if let Some(paths) = presets::resolve_preset(preset_name) {
            for p in paths {
                all_deny_entries.push((*p).to_string());
            }
        } else {
            warnings.push(format!("unknown deny_preset '{preset_name}'"));
        }
    }

    for glob_pat in &merged.deny_glob {
        all_deny_entries.push(glob_pat.clone());
    }

    for entry in &all_deny_entries {
        for path in resolve_list(std::slice::from_ref(entry), &vars, agent)? {
            if let Some(agent_dir) = agent {
                if &path == agent_dir {
                    continue;
                }
            }
            if deny_set.insert(path.clone()) {
                if let Ok(meta) = std::fs::symlink_metadata(&path) {
                    deny_resolved.push(DenyEntry {
                        path,
                        is_dir: meta.is_dir(),
                    });
                }
            }
        }
    }

    if merged.auto_deny_secrets {
        let scan_result =
            secretscan::scan_directory(project, &secretscan::SecretScanOptions::default());
        if scan_result.timed_out {
            warnings.push("auto_deny_secrets scan timed out; partial scan completed".to_string());
        }
        for secret_path in scan_result.unique_paths() {
            if deny_set.insert(secret_path.clone()) {
                deny_resolved.push(DenyEntry {
                    path: secret_path,
                    is_dir: false,
                });
            }
        }
    }

    // Subtractive rules enforcement on resolved allow roots:
    // 1. Remove deny_write paths from allow_write
    if !deny_write_resolved.is_empty() {
        allow_write_resolved.retain(|allowed| {
            !deny_write_resolved
                .iter()
                .any(|denied| allowed == denied || allowed.starts_with(denied))
        });
    }

    // 2. Remove deny_read paths from allow_read
    if !deny_read_resolved.is_empty() {
        allow_read_resolved.retain(|allowed| {
            !deny_read_resolved
                .iter()
                .any(|denied| allowed == denied || allowed.starts_with(denied))
        });
    }

    if tier == Tier::FsOnly {
        mask_project_reads_for_fs_only(
            &mut allow_read_resolved,
            &allow_write_resolved,
            &deny_set,
            &mut warnings,
            project,
        )?;
    }

    if !merged.allow_unix_sockets.is_empty() {
        if let Ok(unix_paths) = resolve_list(&merged.allow_unix_sockets, &vars, agent) {
            for up in unix_paths {
                if !allow_read_resolved.contains(&up) {
                    allow_read_resolved.push(up.clone());
                }
                if !allow_write_resolved.contains(&up) {
                    allow_write_resolved.push(up);
                }
            }
        }
    }

    allow_write_resolved.sort();
    allow_write_resolved.dedup();
    allow_read_resolved.sort();
    allow_read_resolved.dedup();

    let metadata = merged.metadata.clone();
    let name = if metadata.name.is_empty() {
        if custom {
            format!("custom:{profile}")
        } else {
            profile.to_string()
        }
    } else {
        metadata.name.clone()
    };

    let seccomp_profile = match merged.seccomp_profile.as_deref() {
        Some(name) => match SeccompProfile::parse(name) {
            Some(prof) => prof,
            None => bail!("unknown seccomp_profile '{name}'; known profiles: default, agent-min"),
        },
        None => SeccompProfile::Default,
    };

    let mut policy = Policy {
        name,
        metadata,
        limits: merged.limits.clone(),
        allow_write: allow_write_resolved,
        allow_read: allow_read_resolved,
        deny_write: deny_write_resolved,
        deny_read: deny_read_resolved,
        deny_resolved,
        environment: EnvironmentPolicy {
            pass_through: normalize_env_patterns(merged.pass_through.clone()),
            deny: normalize_env_patterns(merged.deny_env.clone()),
        },
        deny_network: !merged.deny_network.is_empty(),
        allow_cidr: merged.allow_cidr.clone(),
        net_quota: merged.net_quota.clone(),
        net_bind_ports: merged.net_bind_ports.clone(),
        net_connect_ports: merged.net_connect_ports.clone(),
        allow_unix_sockets: merged.allow_unix_sockets.clone(),
        seccomp_profile,
        seccomp_notify: merged.seccomp_notify.clone(),
        cgroup: merged.cgroup.clone(),
        cpu_max: merged.cpu_max.clone(),
        io_priority: merged.io_priority.clone(),
        dev_allow: merged.dev_allow.clone(),
        oslog: merged.oslog,
        lpac: merged.lpac,
        is_immutable: merged.is_immutable,
        system_log: merged.system_log,
        auto_deny_secrets: merged.auto_deny_secrets,
        secret_proxies: merged.secret_proxies.clone(),
        ro_mounts: ro_mounts_resolved,
        git_guard: merged.git_guard,
        snapshot: merged.snapshot,
        tmpfs_tmp: merged.tmpfs_tmp.unwrap_or(true),
        warnings,
    };
    checker::check(&mut policy);
    Ok(policy)
}

fn deduplicate_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn same_file_path(left: &Path, right: &Path) -> Option<bool> {
    let left = std::fs::canonicalize(left).ok()?;
    let right = std::fs::canonicalize(right).ok()?;
    Some(left == right)
}

fn normalize_env_patterns(patterns: Vec<String>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for pattern in patterns {
        let prefix = pattern.strip_suffix('*').unwrap_or(&pattern);
        if prefix.is_empty()
            || pattern == "*"
            || pattern.contains('=')
            || pattern.contains('\0')
            || prefix
                .chars()
                .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_'))
            || (pattern.contains('*') && !pattern.ends_with('*'))
        {
            continue;
        }
        out.insert(pattern);
    }
    out.into_iter().collect()
}

fn resolve_list(entries: &[String], vars: &Vars, agent: Option<&Path>) -> Result<Vec<PathBuf>> {
    let mut out = BTreeSet::new();
    for e in entries {
        if e.contains("$AGENT") && agent.is_none() {
            bail!("policy path '{}' requires an agent context for $AGENT", e);
        }
        for p in glob_resolve::resolve_entry_with_agent(e, vars, agent) {
            out.insert(p);
        }
    }
    Ok(out.into_iter().collect())
}

fn agent_root(home: &Path, agent: &str) -> Result<PathBuf> {
    let canon = defaults::canonical_agent_name(agent).unwrap_or(agent);
    let suffix = match canon {
        "codex" => PathBuf::from(".codex"),
        "claude" => PathBuf::from(".claude"),
        "gemini" => PathBuf::from(".gemini"),
        "aider" => PathBuf::from(".aider"),
        "cursor" => PathBuf::from(".cursor"),
        "cline" => PathBuf::from(".cline"),
        "opencode" => PathBuf::from(".config/opencode"),
        "copilot" => PathBuf::from(".config/github-copilot"),
        "custom" => PathBuf::from(".config/vetto/agents/custom"),
        _ => bail!(
            "unknown agent '{}'; known agents: {}",
            agent,
            defaults::AGENT_PROFILE_NAMES.join(", ")
        ),
    };
    Ok(home.join(suffix))
}

fn absolute_for_containment(path: &Path, base: &Path) -> Option<PathBuf> {
    Some(if path.is_absolute() {
        path.to_path_buf()
    } else {
        let base = if base.is_absolute() {
            base.to_path_buf()
        } else {
            std::env::current_dir().ok()?.join(base)
        };
        base.join(path)
    })
}

fn lexical_for_containment(path: &Path, base: &Path) -> Option<PathBuf> {
    absolute_for_containment(path, base).map(|absolute| lexical_normalize(&absolute))
}

fn normalize_for_containment(path: &Path, base: &Path) -> Option<PathBuf> {
    let absolute = absolute_for_containment(path, base)?;

    if let Ok(canonical) = std::fs::canonicalize(&absolute) {
        return Some(canonical);
    }

    let mut unresolved: Vec<OsString> = Vec::new();
    let mut cursor = absolute.as_path();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(cursor) {
            let mut resolved = canonical;
            for component in unresolved.iter().rev() {
                resolved.push(component);
            }
            return Some(lexical_normalize(&resolved));
        }

        let name = cursor.file_name()?.to_os_string();
        unresolved.push(name);
        let parent = cursor.parent()?;
        if parent == cursor {
            return None;
        }
        cursor = parent;
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
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

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn mask_project_reads_for_fs_only(
    allow_read: &mut Vec<PathBuf>,
    allow_write: &[PathBuf],
    deny_set: &BTreeSet<PathBuf>,
    warnings: &mut Vec<String>,
    project: &Path,
) -> Result<()> {
    let project_roots: Vec<PathBuf> = allow_write
        .iter()
        .filter(|p| !is_temp_root(p))
        .cloned()
        .collect();
    if project_roots.is_empty() {
        return Ok(());
    }

    let normalized_project_roots: Vec<(PathBuf, PathBuf)> = project_roots
        .iter()
        .map(|root| {
            Some((
                lexical_for_containment(root, project)?,
                normalize_for_containment(root, project)?,
            ))
        })
        .collect::<Option<_>>()
        .ok_or_else(|| anyhow!("fs-only tier: could not normalize a project root safely"))?;
    let before = allow_read.len();
    allow_read.retain(|p| {
        let Some(lexical) = lexical_for_containment(p, project) else {
            return false;
        };
        let Some(normalized) = normalize_for_containment(p, project) else {
            return false;
        };
        !normalized_project_roots
            .iter()
            .any(|(root_lexical, root_canonical)| {
                paths_overlap(&lexical, root_lexical) || paths_overlap(&normalized, root_canonical)
            })
    });
    if allow_read.len() != before {
        warnings.push(
            "fs-only tier: removed a read rule that covered a write root \
             wholesale (would have defeated secret masking)"
                .to_string(),
        );
    }

    let mut enumerated = 0usize;
    let mut excluded = 0usize;
    for root in &project_roots {
        match enumerate_tree(root, deny_set, allow_read, &mut enumerated, &mut excluded) {
            Ok(_) => {}
            Err(EnumerationError::BudgetExceeded) => {
                bail!(
                    "fs-only tier: project tree exceeds the {}-entry enumeration budget; refusing to run rather than fall back to whole-tree read access",
                    FS_ONLY_ENUMERATION_BUDGET
                );
            }
            Err(EnumerationError::Io {
                operation,
                path,
                source,
            }) => {
                bail!(
                    "fs-only tier: {operation} failed for '{}': {source}; refusing to run",
                    path.display()
                );
            }
        }
    }

    if excluded > 0 {
        warnings.push(format!(
            "fs-only tier: {excluded} secret-shaped or denied project entry(s) excluded from read access \
             by tree enumeration"
        ));
    }

    debug_assert!(enumerated <= FS_ONLY_ENUMERATION_BUDGET);
    Ok(())
}

#[derive(Debug, PartialEq)]
enum Cleanliness {
    Clean,
    Dirty,
}

#[derive(Debug)]
enum EnumerationError {
    BudgetExceeded,
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

fn is_enumeration_excluded(path: &Path, deny_set: &BTreeSet<PathBuf>) -> bool {
    deny_set.contains(path) || super::glob_resolve::is_secret_shaped(path)
}

fn enumerate_tree(
    dir: &Path,
    deny_set: &BTreeSet<PathBuf>,
    out: &mut Vec<PathBuf>,
    count: &mut usize,
    excluded: &mut usize,
) -> std::result::Result<Cleanliness, EnumerationError> {
    if *count > FS_ONLY_ENUMERATION_BUDGET {
        return Err(EnumerationError::BudgetExceeded);
    }

    if is_enumeration_excluded(dir, deny_set) {
        *excluded += 1;
        return Ok(Cleanliness::Dirty);
    }

    let out_start = out.len();
    let entries = std::fs::read_dir(dir).map_err(|source| EnumerationError::Io {
        operation: "read_dir",
        path: dir.to_path_buf(),
        source,
    })?;

    let mut all_clean = true;
    for entry in entries {
        let entry = entry.map_err(|source| EnumerationError::Io {
            operation: "directory entry iteration",
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        *count += 1;
        if *count > FS_ONLY_ENUMERATION_BUDGET {
            return Err(EnumerationError::BudgetExceeded);
        }

        let meta = std::fs::symlink_metadata(&path).map_err(|source| EnumerationError::Io {
            operation: "symlink_metadata",
            path: path.clone(),
            source,
        })?;
        if meta.is_dir() {
            if is_enumeration_excluded(&path, deny_set) {
                *excluded += 1;
                all_clean = false;
                continue;
            }
            match enumerate_tree(&path, deny_set, out, count, excluded) {
                Err(error) => return Err(error),
                Ok(Cleanliness::Clean) => {}
                Ok(Cleanliness::Dirty) => all_clean = false,
            }
        } else if meta.file_type().is_symlink() {
            all_clean = false;
        } else {
            if is_enumeration_excluded(&path, deny_set) {
                *excluded += 1;
                all_clean = false;
            } else {
                out.push(path);
            }
        }
    }

    if all_clean {
        out.truncate(out_start);
        out.push(dir.to_path_buf());
        Ok(Cleanliness::Clean)
    } else {
        Ok(Cleanliness::Dirty)
    }
}

fn is_temp_root(p: &Path) -> bool {
    p == Path::new("/tmp") || p.starts_with("/dev/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_named_profile_fails_closed_without_a_custom_policy() {
        let root = std::env::temp_dir().join(format!(
            "vetto-policy-unknown-profile-{}",
            std::process::id()
        ));
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(&home).expect("create test home");
        std::fs::create_dir_all(&project).expect("create test project");

        let error = load("definitely-unknown", None, &project, &home, Tier::Full)
            .expect_err("unknown named profile must fail closed");
        assert!(error.to_string().contains("unknown profile"), "{error:#}");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn enumeration_budget_returns_error_instead_of_fallback() {
        let root = std::env::temp_dir().join(format!("vetto-policy-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("ordinary.txt"), "ok").unwrap();

        let mut out = Vec::new();
        let mut count = FS_ONLY_ENUMERATION_BUDGET;
        let mut excluded = 0;
        let result = enumerate_tree(&root, &BTreeSet::new(), &mut out, &mut count, &mut excluded);

        let _ = std::fs::remove_dir_all(&root);
        assert!(result.is_err(), "budget overflow must be an error");
        assert!(out.is_empty(), "overflow must not emit a read root");
    }

    #[test]
    fn supported_policy_sections_load_and_subtractive_rules_applied() {
        let root = std::env::temp_dir().join(format!(
            "vetto-policy-subtractive-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let policy_path = root.join("policy.toml");
        let valid = r#"
[filesystem]
allow_write = ["$PROJECT"]
allow_read = ["/usr", "/bin"]
deny_write = ["$PROJECT/.git"]
deny_read = ["/usr/secret"]

[metadata]
name = "subtractive-test"
description = "subtractive rules test"

[environment]
pass_through = ["HOME", "SAFE_VAR"]
deny = ["SECRET_*"]
"#;
        std::fs::write(&policy_path, valid).unwrap();
        let loaded = load(
            "subtractive-test",
            Some(&policy_path),
            &root,
            &root,
            Tier::Full,
        )
        .expect("subtractive policy should load");
        assert_eq!(loaded.metadata.name, "subtractive-test");
        assert!(loaded.deny_write.contains(&root.join(".git")));
        assert!(loaded.deny_read.contains(&PathBuf::from("/usr/secret")));
        assert!(loaded
            .environment
            .pass_through
            .contains(&"SAFE_VAR".to_string()));
        assert!(loaded.environment.deny.contains(&"SECRET_*".to_string()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn enterprise_lockdown_mode_rejects_weakening_overrides() {
        let root = std::env::temp_dir().join(format!("vetto-lockdown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let mut merged = MergedPolicy::default();
        let sec_layer = RawLayer {
            security: Some(RawSecurity {
                immutable: Some(true),
                ..Default::default()
            }),
            ..RawLayer::default()
        };
        merged
            .apply(&sec_layer, PolicySourceKind::SystemGlobal)
            .unwrap();

        assert!(merged.is_immutable);

        let overrides = PolicyOverrides {
            allow_write: vec!["/etc".into()],
            ..Default::default()
        };
        let err = apply_overrides(&mut merged, &overrides)
            .expect_err("lockdown must reject CLI write additions");
        assert!(err.to_string().contains("enterprise lockdown"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn network_presets_expand_correctly() {
        assert_eq!(
            expand_net_preset("npm").unwrap(),
            vec!["registry.npmjs.org".to_string()]
        );
        let git_domains = expand_net_preset("git").unwrap();
        assert!(git_domains.contains(&"github.com".to_string()));
        assert!(git_domains.contains(&"api.github.com".to_string()));
        assert!(git_domains.contains(&"codeload.github.com".to_string()));

        let pip_domains = expand_net_preset("pip").unwrap();
        assert!(pip_domains.contains(&"pypi.org".to_string()));
        assert!(pip_domains.contains(&"files.pythonhosted.org".to_string()));

        let hf_domains = expand_net_preset("huggingface").unwrap();
        assert!(hf_domains.contains(&"huggingface.co".to_string()));
        assert!(hf_domains.contains(&"cdn-lfs.huggingface.co".to_string()));

        assert!(expand_net_preset("unknown-preset").is_err());
    }

    #[test]
    fn parse_quota_bytes_handles_units() {
        assert_eq!(parse_quota_bytes("1024").unwrap(), 1024);
        assert_eq!(parse_quota_bytes("1024b").unwrap(), 1024);
        assert_eq!(parse_quota_bytes("500kb").unwrap(), 500 * 1024);
        assert_eq!(parse_quota_bytes("100mb").unwrap(), 100 * 1024 * 1024);
        assert_eq!(parse_quota_bytes("1gb").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(
            parse_quota_bytes("2tb").unwrap(),
            2 * 1024 * 1024 * 1024 * 1024
        );
        assert!(parse_quota_bytes("invalid").is_err());
    }

    #[test]
    fn network_policy_sections_load_and_resolve() {
        let root = std::env::temp_dir().join(format!("vetto-policy-net-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let policy_path = root.join("policy.toml");
        let toml_content = r#"
[filesystem]
allow_write = ["$PROJECT"]
allow_read = ["/usr"]

[network]
net_presets = ["npm", "git"]
allow_cidr = ["10.0.0.0/8", "192.168.0.0/16"]
net_quota = { "api.openai.com" = "100mb" }
allow_tcp_connect = [443, 80]
allow_tcp_bind = [8080]

[unix_sockets]
allow = ["$PROJECT/test.sock"]
"#;
        std::fs::write(&policy_path, toml_content).unwrap();
        let loaded = load("net-test", Some(&policy_path), &root, &root, Tier::Full)
            .expect("network policy should load");

        assert!(loaded.allow_cidr.contains(&"10.0.0.0/8".to_string()));
        assert_eq!(
            loaded.net_quota.get("api.openai.com"),
            Some(&(100 * 1024 * 1024))
        );
        assert_eq!(loaded.net_connect_ports, vec![80, 443]);
        assert_eq!(loaded.net_bind_ports, vec![8080]);
        assert!(loaded
            .allow_unix_sockets
            .contains(&"$PROJECT/test.sock".to_string()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_require_signed_policy_enforcement() {
        let root = std::env::temp_dir().join(format!("vetto-signed-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let policy_path = root.join("vetto.toml");
        let content = r#"
[metadata]
name = "signed-test"

[filesystem]
allow_write = ["${PROJECT}"]
allow_read = ["/usr", "${PROJECT}"]
"#;
        std::fs::write(&policy_path, content).unwrap();

        // 1. Loading with require_signed=true when unsigned must fail
        let mut loader = LayeredPolicyLoader::new();
        loader.require_signed = true;
        let options = PolicyLoadOptions {
            require_signed: true,
            ..Default::default()
        };

        let err = loader.load(
            "default",
            Some(&policy_path),
            &root,
            &root,
            Tier::Full,
            &options,
        );
        assert!(
            err.is_err(),
            "unsigned policy must fail when require_signed=true"
        );

        // 2. Sign policy
        use ed25519_dalek::Signer;
        let keys_dir = root.join(".vetto");
        let (signing_key, verifying_key) =
            crate::policy::crypto::ensure_signing_keypair(&keys_dir).unwrap();
        let sig = signing_key.sign(content.as_bytes());
        let sig_text = crate::policy::crypto::create_signature_file_content(&sig, &verifying_key);
        std::fs::write(root.join("vetto.toml.sig"), sig_text).unwrap();

        // 3. Now it should succeed
        let loaded = loader.load(
            "default",
            Some(&policy_path),
            &root,
            &root,
            Tier::Full,
            &options,
        );
        assert!(loaded.is_ok(), "signed policy must load successfully");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn claude_agent_preset_policy_loading() {
        let root = std::env::temp_dir().join(format!("vetto-claude-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Create secrets and claude.json
        let ssh_dir = root.join(".ssh");
        let env_file = root.join(".env");
        let codex_dir = root.join(".codex");
        let claude_json = root.join(".claude.json");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::create_dir_all(&codex_dir).unwrap();
        std::fs::write(&env_file, "SECRET=1").unwrap();
        std::fs::write(&claude_json, "{}").unwrap();

        let claude_dir = root.join(".claude");
        // Do NOT manually create claude_dir — loader must auto-create it

        let options = PolicyLoadOptions {
            agent: Some("claude-code".to_string()),
            ..Default::default()
        };

        let pol = load_with_options("default", None, &root, &root, Tier::Full, &options)
            .expect("claude preset must load");

        // Environment pass_through
        use std::ffi::OsStr;
        assert!(pol.environment.allows(OsStr::new("ANTHROPIC_API_KEY")));
        assert!(pol.environment.allows(OsStr::new("ANTHROPIC_BASE_URL")));
        assert!(pol.environment.allows(OsStr::new("CLAUDE_TEST_FLAG")));
        assert!(pol.environment.allows(OsStr::new("PATH")));
        assert!(!pol.environment.allows(OsStr::new("AWS_SECRET_ACCESS_KEY")));
        assert!(!pol.environment.allows(OsStr::new("GH_TOKEN")));

        // Filesystem permissions
        assert!(pol.allow_write.contains(&claude_dir));
        assert!(pol.allow_read.contains(&claude_json));

        // Secrets must be in deny_resolved, but claude_dir must NOT be in deny_resolved
        let deny_paths: Vec<_> = pol.deny_resolved.iter().map(|d| &d.path).collect();
        assert!(deny_paths.contains(&&ssh_dir));
        assert!(deny_paths.contains(&&env_file));
        assert!(deny_paths.contains(&&codex_dir));
        assert!(!deny_paths.contains(&&claude_dir));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn codex_agent_preset_policy_loading() {
        let root = std::env::temp_dir().join(format!("vetto-codex-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Create secrets and claude_dir
        let ssh_dir = root.join(".ssh");
        let env_file = root.join(".env");
        let claude_dir = root.join(".claude");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(&env_file, "SECRET=1").unwrap();

        let codex_dir = root.join(".codex");
        // Do NOT manually create codex_dir — loader must auto-create it

        let options = PolicyLoadOptions {
            agent: Some("codex-cli".to_string()),
            ..Default::default()
        };

        let pol = load_with_options("default", None, &root, &root, Tier::Full, &options)
            .expect("codex preset must load");

        // Environment pass_through
        use std::ffi::OsStr;
        assert!(pol.environment.allows(OsStr::new("OPENAI_API_KEY")));
        assert!(pol.environment.allows(OsStr::new("OPENAI_BASE_URL")));
        assert!(pol.environment.allows(OsStr::new("CODEX_TEST_FLAG")));
        assert!(pol.environment.allows(OsStr::new("PATH")));
        assert!(!pol.environment.allows(OsStr::new("AWS_SECRET_ACCESS_KEY")));
        assert!(!pol.environment.allows(OsStr::new("GH_TOKEN")));

        // Filesystem permissions
        assert!(pol.allow_write.contains(&codex_dir));

        // Secrets must be in deny_resolved, but codex_dir must NOT be in deny_resolved
        let deny_paths: Vec<_> = pol.deny_resolved.iter().map(|d| &d.path).collect();
        assert!(deny_paths.contains(&&ssh_dir));
        assert!(deny_paths.contains(&&env_file));
        assert!(deny_paths.contains(&&claude_dir));
        assert!(!deny_paths.contains(&&codex_dir));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn gemini_agent_preset_policy_loading() {
        let root = std::env::temp_dir().join(format!("vetto-gemini-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Create secrets and claude_dir
        let ssh_dir = root.join(".ssh");
        let env_file = root.join(".env");
        let claude_dir = root.join(".claude");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(&env_file, "SECRET=1").unwrap();

        let gemini_dir = root.join(".gemini");
        // Do NOT manually create gemini_dir — loader must auto-create it

        let options = PolicyLoadOptions {
            agent: Some("gemini-cli".to_string()),
            ..Default::default()
        };

        let pol = load_with_options("default", None, &root, &root, Tier::Full, &options)
            .expect("gemini preset must load");

        // Environment pass_through
        use std::ffi::OsStr;
        assert!(pol.environment.allows(OsStr::new("GEMINI_API_KEY")));
        assert!(pol.environment.allows(OsStr::new("GOOGLE_API_KEY")));
        assert!(pol.environment.allows(OsStr::new("GEMINI_BASE_URL")));
        assert!(pol.environment.allows(OsStr::new("GEMINI_TEST_FLAG")));
        assert!(pol.environment.allows(OsStr::new("PATH")));
        assert!(!pol.environment.allows(OsStr::new("AWS_SECRET_ACCESS_KEY")));
        assert!(!pol.environment.allows(OsStr::new("GH_TOKEN")));

        // Filesystem permissions
        assert!(pol.allow_write.contains(&gemini_dir));

        // Secrets must be in deny_resolved, but gemini_dir must NOT be in deny_resolved
        let deny_paths: Vec<_> = pol.deny_resolved.iter().map(|d| &d.path).collect();
        assert!(deny_paths.contains(&&ssh_dir));
        assert!(deny_paths.contains(&&env_file));
        assert!(deny_paths.contains(&&claude_dir));
        assert!(!deny_paths.contains(&&gemini_dir));

        let _ = std::fs::remove_dir_all(root);
    }
}
