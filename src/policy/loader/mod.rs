//! Policy loading: profile name/context -> resolved `Policy`.
//!
//! Loader rules:
//! 1. 7-Tier Precedence Hierarchy:
//!    Tier 1: System/Org Global Policy (/etc/vetto/policy.toml or %ProgramData%\vetto\policy.toml)
//!    Tier 2: User Global Policy (~/.config/vetto/policy.toml)
//!    Tier 3: Built-in Profile (default, strict, audit, permissive) + inherited profiles
//!    Tier 4: Agent Preset (codex, claude, cursor, aider, cline, opencode, copilot, amp, custom)
//!    Tier 5: Repository Policy (.vetto/policy.toml or vetto.toml) + Fragments (.vetto/policy.d/*.toml)
//!    Tier 6: Local Override Policy (.vetto.override.toml or .vetto/local.toml)
//!    Tier 7: Runtime CLI Flags (--policy, --allow-write, --deny-read, PolicyOverrides)
//! 2. Subtractive Rules: deny_read, deny_write, deny_env, deny_network subtract permissions.
//! 3. Enterprise Lockdown: When [security] immutable = true in Tier 1, lower layers cannot
//!    loosen security or override denied paths/limits without failing with PolicyLockdownViolation.
//! 4. FS-ONLY vs FULL tier masking semantics.

pub mod merge;
pub mod resolve;
pub mod schema;
#[cfg(test)]
mod tests;

use std::path::Path;

use anyhow::Result;

pub use merge::{
    apply_overrides, LayeredPolicyLoader, MergedPolicy, PolicyLoadOptions, PolicyOverrides,
};
pub use resolve::{
    agent_root, build_policy, resolve_package_cache_paths, FS_ONLY_ENUMERATION_BUDGET,
    PACKAGE_CACHE_PATHS,
};
pub use schema::{
    expand_net_preset, parse_layer, parse_quota_bytes, RawCgroup, RawDeny, RawEnvironment,
    RawFilesystem, RawIoRate, RawLayer, RawLimits, RawMetadata, RawNetPorts, RawNetwork,
    RawObservability, RawPlatform, RawSeccompNotify, RawSecrets, RawSecurity, RawStringList,
    RawUnixSockets, RawValueOrString,
};
pub use crate::policy::types::parse_byte_size as parse_bandwidth_str;
use crate::policy::types::{Policy, Tier};

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
