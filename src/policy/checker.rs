//! Post-load sanity checks producing warnings (never hard failures unless
//! something makes enforcement impossible).

use std::path::PathBuf;

use super::types::Policy;

const SYSTEM_WRITE_ROOTS: [&str; 8] = [
    "/", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot",
];

pub fn check(policy: &mut Policy) {
    // Writing to system locations is almost always a misconfiguration.
    for w in &policy.allow_write {
        let canonical = std::fs::canonicalize(w).unwrap_or_else(|_| w.clone());
        if SYSTEM_WRITE_ROOTS.contains(&canonical.to_string_lossy().as_ref()) {
            policy.warnings.push(format!(
                "allow_write includes system path '{}' — this effectively disables filesystem isolation",
                w.display()
            ));
        }
    }

    // Reading $HOME wholesale exposes every secret by definition.
    if let Some(home) = home_dir() {
        if policy
            .allow_read
            .iter()
            .any(|p| std::fs::canonicalize(p).map(|c| c == home).unwrap_or(false))
        {
            policy.warnings.push(
                "allow_read includes $HOME itself — all user secrets are readable \
                 regardless of display_only_deny"
                    .to_string(),
            );
        }
    }

    // Non-existent write roots make enforcement impossible -> drop loudly.
    policy.allow_write.retain(|p| {
        let exists = p.exists();
        if !exists {
            policy.warnings.push(format!(
                "allow_write path '{}' does not exist; dropped",
                p.display()
            ));
        }
        exists
    });
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
