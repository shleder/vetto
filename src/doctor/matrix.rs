//! Uniform enforcement matrix for `vetto doctor`.
//!
//! Pure logic only (no I/O, no spawning): the four canonical enforcement rows
//! plus the platform default and its fail-closed reason. Shared surface for
//! the `feat/uniform-mac-vm` (`Backend::MacVm`) and `feat/uniform-win-wsl2`
//! (`Backend::Wsl2`) branches — this module names the rows, those branches
//! own the VM construction.

/// Canonical enforcement rows, in matrix order.
pub const MATRIX_ROWS: [&str; 4] = [
    "linux-tier-1 (direct kernel enforcement)",
    "mac-vm (tier-1 in VM)",
    "wsl2 (tier-1 in VM)",
    "legacy-process (explicit --backend process only, deprecated)",
];

/// Platform default enforcement row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultEnforcement {
    LinuxTier1,
    MacVm,
    Wsl2,
    LegacyProcess,
}

impl DefaultEnforcement {
    pub fn row_label(self) -> &'static str {
        match self {
            DefaultEnforcement::LinuxTier1 => MATRIX_ROWS[0],
            DefaultEnforcement::MacVm => MATRIX_ROWS[1],
            DefaultEnforcement::Wsl2 => MATRIX_ROWS[2],
            DefaultEnforcement::LegacyProcess => MATRIX_ROWS[3],
        }
    }
}

/// Platform default: Tier-1 direct or Tier-1 in a VM. Legacy process
/// backends never win by default — they require explicit `--backend process`.
pub fn default_enforcement() -> DefaultEnforcement {
    #[cfg(target_os = "linux")]
    {
        DefaultEnforcement::LinuxTier1
    }
    #[cfg(target_os = "macos")]
    {
        DefaultEnforcement::MacVm
    }
    #[cfg(target_os = "windows")]
    {
        DefaultEnforcement::Wsl2
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        DefaultEnforcement::LegacyProcess
    }
}

/// Fail-closed reason for the platform default (why this row was chosen).
pub fn default_reason() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "direct Tier-1 kernel enforcement (Landlock + seccomp + namespaces); default requires Tier-1 and fails closed"
    }
    #[cfg(target_os = "macos")]
    {
        "Tier-1 via mac-vm by default (VM provision → sync → exec → sync back); legacy Seatbelt process backend is deprecated, explicit --backend process only; missing VM fails closed"
    }
    #[cfg(target_os = "windows")]
    {
        "Tier-1 via wsl2 by default (VM provision → sync → exec → sync back); legacy AppContainer process backend is deprecated, explicit --backend process only; missing distro fails closed"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "unsupported platform: no Tier-1 path; fail-closed, explicit --backend process only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_has_four_canonical_rows() {
        assert_eq!(MATRIX_ROWS.len(), 4);
        assert!(MATRIX_ROWS[0].starts_with("linux-tier-1"));
        assert!(MATRIX_ROWS[1].starts_with("mac-vm"));
        assert!(MATRIX_ROWS[1].contains("tier-1 in VM"));
        assert!(MATRIX_ROWS[2].starts_with("wsl2"));
        assert!(MATRIX_ROWS[2].contains("tier-1 in VM"));
        assert!(MATRIX_ROWS[3].starts_with("legacy-process"));
    }

    #[test]
    fn default_is_tier1_or_vm_never_silent_legacy() {
        let def = default_enforcement();
        assert_eq!(def.row_label(), MATRIX_ROWS[match def {
            DefaultEnforcement::LinuxTier1 => 0,
            DefaultEnforcement::MacVm => 1,
            DefaultEnforcement::Wsl2 => 2,
            DefaultEnforcement::LegacyProcess => 3,
        }]);
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        assert_ne!(def, DefaultEnforcement::LegacyProcess);
    }

    #[test]
    fn default_reason_is_fail_closed() {
        let reason = default_reason();
        assert!(!reason.is_empty());
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        assert!(reason.contains("Tier-1"), "{reason}");
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        assert!(reason.contains("fails closed"), "{reason}");
    }
}
