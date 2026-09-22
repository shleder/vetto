//! Anonymous opt-in telemetry for sandbox violation causes.
//!
//! Excludes all paths, arguments, secrets, and identifiable project information.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousViolationReport {
    /// SHA256 hash of the agent slug (first 12 hex characters)
    pub agent_hash: String,
    /// High-level violation category (e.g., "fs_read", "fs_write", "net_denied", "seccomp_syscall")
    pub violation_category: String,
    /// Sandbox tier that enforced the violation ("full", "landlock", "seccomp", "macos", "windows")
    pub tier: String,
    /// Unix timestamp in seconds
    pub timestamp_epoch: u64,
}

/// Evaluates whether anonymous telemetry should be sent.
pub fn should_send_telemetry(opt_in: bool) -> bool {
    opt_in
}

/// Creates a safe, sanitized anonymous violation report.
pub fn create_anonymous_report(
    agent_slug: &str,
    category: &str,
    tier: &str,
) -> AnonymousViolationReport {
    let mut hasher = Sha256::new();
    hasher.update(agent_slug.as_bytes());
    let result = hasher.finalize();

    let mut agent_hash = String::with_capacity(12);
    for byte in result.iter().take(6) {
        use std::fmt::Write;
        write!(&mut agent_hash, "{:02x}", byte).unwrap();
    }

    let timestamp_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    AnonymousViolationReport {
        agent_hash,
        violation_category: category.to_string(),
        tier: tier.to_string(),
        timestamp_epoch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_send_telemetry() {
        assert!(should_send_telemetry(true));
        assert!(!should_send_telemetry(false));
    }

    #[test]
    fn test_create_anonymous_report_hashing() {
        let report1 = create_anonymous_report("claude", "fs_write", "landlock");
        let report2 = create_anonymous_report("claude", "fs_write", "landlock");
        let report3 = create_anonymous_report("opencode", "fs_write", "landlock");

        assert_eq!(report1.agent_hash.len(), 12);

        // Hashing is deterministic
        assert_eq!(report1.agent_hash, report2.agent_hash);

        // Different agents have different hashes
        assert_ne!(report1.agent_hash, report3.agent_hash);
    }

    #[test]
    fn test_absence_of_sensitive_data() {
        let sensitive_slug = "claude";
        let report = create_anonymous_report(sensitive_slug, "fs_write", "landlock");

        // The raw agent name must not be present in the report
        assert!(!report.agent_hash.contains(sensitive_slug));
        assert!(!report.violation_category.contains(sensitive_slug));
        assert!(!report.tier.contains(sensitive_slug));
    }
}
