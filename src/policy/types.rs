//! Policy representation after load-time resolution.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Linux capability tier the policy was loaded for (affects masking strategy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Landlock + namespaces: secrets masked with mount overlays.
    Full,
    /// Landlock only (no userns): project secrets masked by explicit
    /// enumeration into the read allowlist; overlay masking unavailable.
    FsOnly,
}

impl Tier {
    pub fn label(&self) -> &'static str {
        match self {
            Tier::Full => "full",
            Tier::FsOnly => "fs-only",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DenyEntry {
    pub path: PathBuf,
    pub is_dir: bool,
}

/// User-facing metadata carried by a loaded policy.
///
/// The loader resolves inheritance before constructing `Policy`; `extends`
/// therefore records the built-in parents that were actually applied rather
/// than an untrusted path or arbitrary policy-language expression.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyMetadata {
    pub name: String,
    pub description: String,
    pub extends: Vec<String>,
}

/// Optional per-agent resource ceilings applied immediately before `execve`.
/// `None` means inherit the parent's existing limit; values are additive in
/// the policy loader but the effective value is always the strictest (lowest)
/// limit supplied by a layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    pub cpu_seconds: Option<u64>,
    pub address_space_bytes: Option<u64>,
    pub processes: Option<u64>,
    pub open_files: Option<u64>,
}

impl ResourceLimits {
    pub fn merge_strictest(&mut self, other: &Self) {
        self.cpu_seconds = strictest(self.cpu_seconds, other.cpu_seconds);
        self.address_space_bytes = strictest(self.address_space_bytes, other.address_space_bytes);
        self.processes = strictest(self.processes, other.processes);
        self.open_files = strictest(self.open_files, other.open_files);
    }
}

fn strictest(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// Environment variables explicitly allowed into the agent process.
///
/// Entries are exact names, except that a trailing `*` matches a name prefix
/// (for example, `LC_*`). This is an allowlist: an absent or unknown variable
/// is dropped before `execve`, and built-in defaults do not include credential
/// variables such as `GH_TOKEN`, `OPENAI_API_KEY`, `AWS_*`, or
/// `ANTHROPIC_API_KEY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentPolicy {
    pub pass_through: Vec<String>,
}

impl EnvironmentPolicy {
    pub fn allows(&self, key: &OsStr) -> bool {
        let key = key.to_string_lossy();
        self.pass_through.iter().any(|pattern| {
            pattern
                .strip_suffix('*')
                .map_or_else(|| pattern == key.as_ref(), |prefix| key.starts_with(prefix))
        })
    }
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
    /// Resolved display_only_deny paths that exist on this machine.
    pub deny_resolved: Vec<DenyEntry>,
    /// Environment allowlist applied immediately before agent execve.
    pub environment: EnvironmentPolicy,
    /// Non-fatal findings surfaced to doctor/statusline/reports.
    pub warnings: Vec<String>,
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
        self.allow_write.iter().any(|root| path.starts_with(root))
    }

    /// Is `path` covered by an allow rule at all?
    pub fn in_read_scope(&self, path: &Path) -> bool {
        let mut allowed = self.allow_read.iter().chain(self.allow_write.iter());
        allowed.any(|root| path.starts_with(root))
    }
}
