//! Deterministic merging of 7 hierarchy policy layers.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use super::resolve;
use super::schema::{
    expand_net_preset, parse_layer, parse_quota_bytes, RawLayer, RawStringList,
};
use crate::error::VettoError;
use crate::policy::conditions::{self, ConditionContext};
use crate::policy::defaults;
use crate::policy::types::{
    CgroupConfig, Policy, PolicyMetadata, PolicySourceKind, ResourceLimits, SeccompNotifyConfig,
    Tier,
};

#[derive(Debug, Default, Clone)]
pub struct MergedPolicy {
    pub metadata: PolicyMetadata,
    pub limits: ResourceLimits,
    pub active_preset: Option<crate::policy::presets::Preset>,
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
    pub net_quota: HashMap<String, u64>,
    pub net_bind_ports: Vec<u16>,
    pub net_connect_ports: Vec<u16>,
    pub allow_unix_sockets: Vec<String>,
    pub deny_unix_sockets: Vec<String>,
    pub oslog: bool,
    pub lpac: bool,
    pub is_immutable: bool,
    pub system_log: bool,
    pub auto_deny_secrets: bool,
    pub git_guard: bool,
    pub snapshot: bool,
    pub read_only_caches: bool,
    pub shadow: bool,
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
    pub fn apply(&mut self, layer: &RawLayer, source_kind: PolicySourceKind) -> Result<()> {
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

        if let Some(plat) = &layer.platform {
            if let Some(oslog) = plat.oslog {
                self.oslog = oslog;
            }
            if let Some(lpac) = plat.lpac {
                self.lpac = lpac;
            }
            if let Some(io) = &plat.io_rate {
                let max_bandwidth = io
                    .max_bandwidth
                    .as_deref()
                    .and_then(crate::policy::types::parse_byte_size);
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
            if source_kind == PolicySourceKind::Repository
                || source_kind == PolicySourceKind::RepositoryFragment
            {
                if let Some(allow_write) = &filesystem.allow_write {
                    let home = std::env::var_os("HOME")
                        .or_else(|| std::env::var_os("USERPROFILE"))
                        .map(PathBuf::from);
                    for w in allow_write.clone().into_vec() {
                        let p = Path::new(&w);
                        let canonical =
                            std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
                        let can_str = canonical.to_string_lossy();
                        if crate::policy::checker::SYSTEM_WRITE_ROOTS.contains(&can_str.as_ref()) {
                            bail!(
                                "fail-closed: repository policy cannot grant write access to system root '{}' (exit 125)",
                                w
                            );
                        }
                        if let Some(ref h) = home {
                            if &canonical == h || w == "$HOME" || w == "~" {
                                bail!(
                                    "fail-closed: repository policy cannot grant write access to $HOME '{}' (exit 125)",
                                    w
                                );
                            }
                        }
                    }
                }
            }
            if let Some(allow_write) = &filesystem.allow_write {
                self.allow_write.extend(allow_write.clone().into_vec());
            }
            if let Some(allow_read) = &filesystem.allow_read {
                self.allow_read.extend(allow_read.clone().into_vec());
            }
            if let Some(deny) = &filesystem.deny {
                let items = deny.clone().into_vec();
                self.deny_write.extend(items.clone());
                self.deny_read.extend(items.clone());
                self.deny_paths.extend(items);
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
            if let Some(ro_caches) = filesystem.read_only_caches {
                self.read_only_caches = ro_caches;
            }
            if let Some(shadow) = filesystem.shadow {
                self.shadow = shadow;
            }
            if let Some(tmpfs) = filesystem.tmpfs_tmp {
                self.tmpfs_tmp = Some(tmpfs);
            }
            if let Some(dev_allow) = &filesystem.dev_allow {
                self.dev_allow = Some(dev_allow.clone().into_vec());
            }
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

        let is_repo = source_kind == PolicySourceKind::Repository
            || source_kind == PolicySourceKind::RepositoryFragment;
        let skip_network =
            is_repo && self.active_preset == Some(crate::policy::presets::Preset::Paranoid);

        if !skip_network {
            if let Some(network) = &layer.network {
                if let Some(mode) = &network.mode {
                    self.network_mode = Some(mode.clone());
                }
                if let Some(allow) = &network.allow {
                    self.network_allow.extend(allow.clone().into_vec());
                }
                if let Some(allow_domains) = &network.allow_domains {
                    self.network_allow.extend(allow_domains.clone().into_vec());
                }
                if let Some(deny) = &network.deny {
                    self.deny_network.extend(deny.clone().into_vec());
                }
                if let Some(deny_domains) = &network.deny_domains {
                    self.deny_network.extend(deny_domains.clone().into_vec());
                }
                if let Some(deny_network) = &network.deny_network {
                    self.deny_network.extend(deny_network.clone().into_vec());
                }
                for presets in [&network.net_preset, &network.net_presets]
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
                if let Some(quotas) = &network.net_quota {
                    for (domain, val) in quotas {
                        let bytes = parse_quota_bytes(val)?;
                        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
                        self.net_quota.insert(clean, bytes);
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
        }

        if let Some(unix_socks) = &layer.unix_sockets {
            if let Some(allow) = &unix_socks.allow {
                self.allow_unix_sockets.extend(allow.clone().into_vec());
            }
            if let Some(deny) = &unix_socks.deny {
                self.deny_unix_sockets.extend(deny.clone().into_vec());
            }
        }

        if let Some(limits) = &layer.limits {
            let mut incoming = limits.to_resource_limits();
            if source_kind == PolicySourceKind::AgentPreset
                || source_kind == PolicySourceKind::Preset
            {
                if let Some(fsize) = incoming.file_size_bytes {
                    self.limits.file_size_bytes = Some(
                        self.limits
                            .file_size_bytes
                            .map_or(fsize, |curr| curr.max(fsize)),
                    );
                    incoming.file_size_bytes = None;
                }
            }
            self.limits.merge_strictest(&incoming);
            if let Some(cg) = &limits.cgroup {
                let incoming = CgroupConfig {
                    memory_max: cg.memory_max.as_ref().map(|m| m.to_string_repr()),
                    pids_max: cg.pids_max.as_ref().map(|p| p.to_string_repr()),
                    swap_max: cg.swap_max.as_ref().map(|s| s.to_string_repr()),
                    cpu_max: cg.cpu_max.as_ref().map(|c| c.to_string_repr()),
                };
                match &mut self.cgroup {
                    Some(existing) => existing.merge_strictest(&incoming),
                    None => self.cgroup = Some(incoming),
                }
            }
            if let Some(cpu) = &limits.cpu_max {
                self.cpu_max =
                    crate::policy::types::strictest_cpu_max(&self.cpu_max, &Some(cpu.clone()));
            }
            if let Some(ioprio) = &limits.io_priority {
                self.io_priority = Some(ioprio.clone());
            }
        }

        if let Some(cg) = &layer.cgroup {
            let incoming = CgroupConfig {
                memory_max: cg.memory_max.as_ref().map(|m| m.to_string_repr()),
                pids_max: cg.pids_max.as_ref().map(|p| p.to_string_repr()),
                swap_max: cg.swap_max.as_ref().map(|s| s.to_string_repr()),
                cpu_max: cg.cpu_max.as_ref().map(|c| c.to_string_repr()),
            };
            match &mut self.cgroup {
                Some(existing) => existing.merge_strictest(&incoming),
                None => self.cgroup = Some(incoming),
            }
        }

        Ok(())
    }

    pub fn deduplicate(&mut self) {
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
        deduplicate_strings(&mut self.deny_unix_sockets);
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
    pub read_only_caches: Option<bool>,
    pub shadow: Option<bool>,
    pub tmpfs_tmp: Option<bool>,
    pub auto_deny_secrets: Option<bool>,
    pub net_quota: HashMap<String, u64>,
    pub deny_unix_sockets: Vec<String>,
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

pub fn read_layer_file(path: &Path, require_signed: bool) -> Result<String> {
    if !is_usable_file(path) {
        bail!(
            "fail-closed: policy file '{}' must be a regular file and not a symlink",
            path.display()
        );
    }
    if require_signed {
        crate::policy::crypto::verify_policy_file(path, None, None).with_context(|| {
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
            let base_text = defaults::builtin(base_profile).with_context(|| {
                format!("built-in profile '{base_profile}' disappeared during load")
            })?;
            let base = parse_layer(base_text, base_profile)?;
            if base.environment.is_none() && merged.pass_through.is_empty() {
                merged.pass_through = defaults::default_env_passthrough();
            }
            merge_layer(
                &base,
                &base_profile,
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
            merged.active_preset = Some(preset);
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
        let _ = std::fs::create_dir_all(home.join(".cache/ms-playwright"));
        let _ = std::fs::create_dir_all(home.join(".cache/puppeteer"));

        let agent_path = match options.agent.as_deref() {
            Some(agent) => {
                let p = resolve::agent_root(home, agent)?;
                let _ = std::fs::create_dir_all(&p);
                match defaults::canonical_agent_name(agent) {
                    Some("codex") => {
                        let _ = std::fs::create_dir_all(home.join(".config/codex"));
                        let _ = std::fs::create_dir_all(home.join(".codex/plugins"));
                        let _ = std::fs::create_dir_all(home.join(".codex/skills"));
                        let _ = std::fs::create_dir_all(home.join(".local/share/codex"));
                    }
                    Some("claude") => {
                        let _ = std::fs::create_dir_all(home.join(".claude/plugins"));
                        let _ = std::fs::create_dir_all(home.join(".claude/skills"));
                        let _ = std::fs::create_dir_all(home.join(".config/claude"));
                        let _ = std::fs::create_dir_all(home.join(".config/claude-code"));
                        let _ = std::fs::create_dir_all(home.join(".local/share/claude"));
                    }
                    Some("antigravity") => {
                        let _ = std::fs::create_dir_all(home.join(".gemini/antigravity/plugins"));
                        let _ = std::fs::create_dir_all(home.join(".gemini/config/plugins"));
                        let _ = std::fs::create_dir_all(home.join(".gemini/config/skills"));
                    }
                    Some("opencode") => {
                        let _ = std::fs::create_dir_all(home.join(".local/share/opencode/log"));
                        let _ = std::fs::create_dir_all(home.join(".local/state/opencode"));
                        let _ = std::fs::create_dir_all(home.join(".config/opencode"));
                        let _ = std::fs::create_dir_all(home.join(".config/opencode/plugins"));
                        let _ = std::fs::create_dir_all(home.join(".local/share/opencode/plugins"));
                    }
                    Some("smolagents") => {
                        let _ = std::fs::create_dir_all(home.join(".cache/huggingface"));
                        let _ = std::fs::create_dir_all(home.join(".cache/transformers"));
                        let _ = std::fs::create_dir_all(home.join(".cache/torch"));
                    }
                    Some("amp") => {
                        let _ = std::fs::create_dir_all(home.join(".amp"));
                        let _ = std::fs::create_dir_all(home.join(".config/amp"));
                        let _ = std::fs::create_dir_all(home.join(".local/share/amp"));
                    }
                    Some("omp") => {
                        let _ = std::fs::create_dir_all(home.join(".config/omp"));
                        let _ = std::fs::create_dir_all(home.join(".omp"));
                    }
                    Some("zcode") => {
                        let _ = std::fs::create_dir_all(home.join(".zcode"));
                        let _ = std::fs::create_dir_all(home.join(".config/zcode"));
                    }
                    Some("kimi") => {
                        let _ = std::fs::create_dir_all(home.join(".kimi"));
                        let _ = std::fs::create_dir_all(home.join(".config/kimi"));
                    }
                    Some("grok") => {
                        let _ = std::fs::create_dir_all(home.join(".grok"));
                        let _ = std::fs::create_dir_all(home.join(".config/grok"));
                    }
                    Some("hermes") => {
                        let _ = std::fs::create_dir_all(home.join(".hermes"));
                        let _ = std::fs::create_dir_all(home.join(".config/hermes"));
                    }
                    Some("kilo") => {
                        let _ = std::fs::create_dir_all(home.join(".kilo"));
                        let _ = std::fs::create_dir_all(home.join(".config/kilo"));
                    }
                    Some("pi") => {
                        let _ = std::fs::create_dir_all(home.join(".pi"));
                        let _ = std::fs::create_dir_all(home.join(".config/pi"));
                    }
                    Some("command_code") => {
                        let _ = std::fs::create_dir_all(home.join(".command-code"));
                        let _ = std::fs::create_dir_all(home.join(".config/command-code"));
                    }
                    Some("freebuff") => {
                        let _ = std::fs::create_dir_all(home.join(".freebuff"));
                        let _ = std::fs::create_dir_all(home.join(".config/freebuff"));
                    }
                    Some("deepseek_harness") => {
                        let _ = std::fs::create_dir_all(home.join(".deepseek"));
                        let _ = std::fs::create_dir_all(home.join(".config/deepseek"));
                    }
                    Some("omnigent") => {
                        let _ = std::fs::create_dir_all(home.join(".omnigent"));
                        let _ = std::fs::create_dir_all(home.join(".config/omnigent"));
                    }
                    Some("crewai") => {
                        let _ = std::fs::create_dir_all(home.join(".crewai"));
                        let _ = std::fs::create_dir_all(home.join(".config/crewai"));
                    }
                    Some("autogen") => {
                        let _ = std::fs::create_dir_all(home.join(".autogen"));
                        let _ = std::fs::create_dir_all(home.join(".autogenstudio"));
                        let _ = std::fs::create_dir_all(home.join(".config/autogen"));
                    }
                    Some("aider") => {
                        let _ = std::fs::create_dir_all(home.join(".aider"));
                        let _ = std::fs::create_dir_all(home.join(".config/aider"));
                    }
                    _ => {}
                }
                let _ = std::fs::create_dir_all(home.join(".npm/_npx"));
                let _ = std::fs::create_dir_all(home.join(".cache/uv"));
                let _ = std::fs::create_dir_all(home.join(".local/share/uv"));
                let _ = std::fs::create_dir_all(home.join(".bun/install/cache"));
                let _ = std::fs::create_dir_all(home.join(".cache/ms-playwright"));
                let _ = std::fs::create_dir_all(home.join(".cache/puppeteer"));
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
            if defaults::canonical_agent_name(agent) == Some("opencode") {
                let dynamic_providers =
                    crate::policy::opencode::discover_opencode_providers_from_paths(
                        Some(home),
                        Some(project),
                    );
                for provider in dynamic_providers {
                    if !merged.network_allow.contains(&provider) {
                        merged.network_allow.push(provider);
                    }
                }
            }
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
                            if is_usable_file(&path)
                                && path.extension().is_some_and(|ext| ext == "toml")
                            {
                                fragment_files.push(path);
                            }
                        }
                    }
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

        resolve::build_policy(
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

pub fn is_usable_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

pub fn default_system_policy_path() -> Option<PathBuf> {
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

pub fn default_user_policy_path(home: &Path) -> Option<PathBuf> {
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

pub fn merge_layer(
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

pub fn validate_parent_name(parent: &str) -> Result<()> {
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

pub fn apply_overrides(merged: &mut MergedPolicy, overrides: &PolicyOverrides) -> Result<()> {
    if merged.is_immutable
        && (!overrides.allow_write.is_empty() || !overrides.allow_read.is_empty())
    {
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
    merged
        .deny_unix_sockets
        .extend(overrides.deny_unix_sockets.clone());
    deduplicate_strings(&mut merged.deny_unix_sockets);

    if let Some(true) = overrides.git_guard {
        merged.git_guard = true;
    }
    if let Some(true) = overrides.snapshot {
        merged.snapshot = true;
    }
    if let Some(true) = overrides.auto_deny_secrets {
        merged.auto_deny_secrets = true;
    }
    if let Some(true) = overrides.read_only_caches {
        merged.read_only_caches = true;
    }
    if let Some(true) = overrides.shadow {
        merged.shadow = true;
    }
    if let Some(tmpfs) = overrides.tmpfs_tmp {
        merged.tmpfs_tmp = Some(tmpfs);
    }

    for (domain, quota) in &overrides.net_quota {
        merged.net_quota.insert(domain.clone(), *quota);
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

pub fn deduplicate_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

pub fn same_file_path(left: &Path, right: &Path) -> Option<bool> {
    let left = std::fs::canonicalize(left).ok()?;
    let right = std::fs::canonicalize(right).ok()?;
    Some(left == right)
}
