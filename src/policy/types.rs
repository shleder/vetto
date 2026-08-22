//! Policy representation after load-time resolution.

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

#[derive(Debug, Clone)]
pub struct Policy {
    pub name: String,
    /// Concrete read-write roots.
    pub allow_write: Vec<PathBuf>,
    /// Concrete read-only roots.
    pub allow_read: Vec<PathBuf>,
    /// Resolved display_only_deny paths that exist on this machine.
    pub deny_resolved: Vec<DenyEntry>,
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
