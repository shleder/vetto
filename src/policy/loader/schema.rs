//! Clean Serde TOML structures for policy layers.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::policy::conditions::RawConditions;
use crate::policy::types::{IoRateLimit, ResourceLimits};

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
    pub cgroup: Option<RawCgroup>,
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
    pub deny: Option<RawStringList>,
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
    pub read_only_caches: Option<bool>,
    #[serde(default)]
    pub shadow: Option<bool>,
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
    pub allow_domains: Option<RawStringList>,
    #[serde(default)]
    pub deny: Option<RawStringList>,
    #[serde(default)]
    pub deny_domains: Option<RawStringList>,
    #[serde(default)]
    pub deny_network: Option<RawStringList>,
    #[serde(default)]
    pub net_preset: Option<RawStringList>,
    #[serde(default)]
    pub net_presets: Option<RawStringList>,
    #[serde(default)]
    pub allow_cidr: Option<RawStringList>,
    #[serde(default)]
    pub net_quota: Option<HashMap<String, String>>,
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

impl RawLimits {
    pub fn to_resource_limits(&self) -> ResourceLimits {
        let mut io_rate = None;
        if let Some(rate) = &self.io_rate {
            let max_bandwidth = rate
                .max_bandwidth
                .as_deref()
                .and_then(crate::policy::types::parse_byte_size);
            io_rate = Some(IoRateLimit {
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
                if let Some(bw) = crate::policy::types::parse_byte_size(bw_str) {
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

pub fn parse_layer(text: &str, label: &str) -> Result<RawLayer> {
    toml::from_str(text).with_context(|| format!("failed to parse policy '{label}'"))
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
        "cargo" | "crates" => Ok(vec![
            "crates.io".to_string(),
            "static.crates.io".to_string(),
            "index.crates.io".to_string(),
        ]),
        "go" | "golang" => Ok(vec![
            "proxy.golang.org".to_string(),
            "sum.golang.org".to_string(),
        ]),
        "maven" => Ok(vec![
            "repo1.maven.org".to_string(),
            "repo.maven.apache.org".to_string(),
        ]),
        "nuget" => Ok(vec!["api.nuget.org".to_string()]),
        unknown => {
            bail!("unknown net preset '{unknown}'; known presets: npm, git, pip, huggingface, cargo, go, maven, nuget")
        }
    }
}

pub fn parse_quota_bytes(s: &str) -> Result<u64> {
    crate::policy::types::parse_bytes_value(s)
        .ok_or_else(|| anyhow::anyhow!("invalid quota value '{s}'"))
}
