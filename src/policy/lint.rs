//! `vetto policy lint`: static checks over the resolved policy for
//! dangerous or useless configurations.
//!
//! Read-only tooling command: it loads the policy the same way a supervised
//! session does (network off, since linting must not depend on the relay)
//! and reports findings. Findings are advisory; `--strict` turns any finding
//! into exit code 1 so CI can fail on dangerous policies.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::NetMode;
use crate::sandbox::Backend;

use super::loader::{load_with_options, PolicyLoadOptions};
use super::types::{Policy, Tier};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Misconfiguration that materially weakens the sandbox boundary.
    High,
    /// Dead rule, missing hardening, or another non-urgent smell.
    Warn,
}

impl Severity {
    fn label(&self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Warn => "warn",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub rule: &'static str,
    pub message: String,
}

/// Load the effective policy (like a supervised session, network off), run
/// every rule and print findings. Exits 1 iff `strict` and any finding.
pub fn run_cli(strict: bool, profile: &str, policy_path: Option<&Path>) -> Result<()> {
    let tier = match Backend::detect(NetMode::Off, false) {
        Ok(b) => b.tier(),
        Err(_) => Some(Tier::FsOnly),
    };

    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("$HOME is not set; vetto needs it to resolve policy variables")?;

    let options = PolicyLoadOptions {
        agent: None,
        include_project_policy: true,
        ..PolicyLoadOptions::default()
    };
    let policy = load_with_options(
        profile,
        policy_path,
        &project,
        &home,
        tier.unwrap_or(Tier::Full),
        &options,
    )?;

    let findings = evaluate(&policy, &home);
    println!("vetto policy lint: {} finding(s)", findings.len());
    for finding in &findings {
        println!(
            "  [{}] {}: {}",
            finding.severity.label(),
            finding.rule,
            finding.message
        );
    }

    if strict && !findings.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

/// Run every rule against a resolved policy. `home` is passed explicitly
/// instead of read from the process environment so unit tests never mutate
/// process-global state.
pub fn evaluate(policy: &Policy, home: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(finding) = rule_home_write_root(policy, home) {
        findings.push(finding);
    }
    if let Some(finding) = rule_home_blanket_read(policy, home) {
        findings.push(finding);
    }
    if let Some(finding) = rule_useless_deny(policy) {
        findings.push(finding);
    }
    if let Some(finding) = rule_no_secrets_resolved(policy, home) {
        findings.push(finding);
    }
    if let Some(finding) = rule_no_limits(policy) {
        findings.push(finding);
    }
    findings
}

/// R1 (high): a write root is $HOME itself or an ancestor of $HOME, so the
/// agent can rewrite its own credential store and any config that vetto or
/// the toolchains trust.
fn rule_home_write_root(policy: &Policy, home: &Path) -> Option<Finding> {
    let message = |root: &Path| {
        format!(
            "write root '{}' is the user home directory ($HOME) or an ancestor of it: \
             the agent can rewrite its own credential store",
            root.display()
        )
    };
    for root in &policy.allow_write {
        // Lexical check first, then the canonical form so a symlinked root
        // cannot hide that it contains $HOME.
        if root == home || home.starts_with(root) {
            return Some(Finding {
                severity: Severity::High,
                rule: "home_write_root",
                message: message(root),
            });
        }
        if let (Ok(root_canonical), Ok(home_canonical)) =
            (std::fs::canonicalize(root), std::fs::canonicalize(home))
        {
            if root_canonical == home_canonical || home_canonical.starts_with(&root_canonical) {
                return Some(Finding {
                    severity: Severity::High,
                    rule: "home_write_root",
                    message: message(root),
                });
            }
        }
    }
    None
}

/// R2 (high): allow_read contains $HOME itself — every user secret is
/// readable regardless of deny rules.
fn rule_home_blanket_read(policy: &Policy, home: &Path) -> Option<Finding> {
    for root in &policy.allow_read {
        if root == home {
            return Some(Finding {
                severity: Severity::High,
                rule: "home_blanket_read",
                message: format!(
                    "read root '{}' is $HOME itself: every user secret is readable \
                     regardless of deny rules",
                    root.display()
                ),
            });
        }
    }
    None
}

/// R3 (warn): a resolved deny path is not under any allow_read/allow_write
/// root, so the sandbox never could have handed it out — the deny is a no-op
/// and only creates false confidence.
fn rule_useless_deny(policy: &Policy) -> Option<Finding> {
    for entry in &policy.deny_resolved {
        let covered = policy
            .allow_read
            .iter()
            .chain(policy.allow_write.iter())
            .any(|root| entry.path.starts_with(root));
        if !covered {
            return Some(Finding {
                severity: Severity::Warn,
                rule: "useless_deny",
                message: format!(
                    "denied path '{}' is not under any allow_read or allow_write root: \
                     the deny rule is a no-op",
                    entry.path.display()
                ),
            });
        }
    }
    None
}

/// R4 (warn): nothing is deny-resolved although well-known credential
/// directories exist on this host. Skipped when none of them exist, because
/// an empty deny list is fine on a machine without those directories.
fn rule_no_secrets_resolved(policy: &Policy, home: &Path) -> Option<Finding> {
    let credential_dirs: Vec<PathBuf> = [".ssh", ".codex", ".claude"]
        .iter()
        .map(|dir| home.join(dir))
        .filter(|dir| dir.exists())
        .collect();
    if credential_dirs.is_empty() || !policy.deny_resolved.is_empty() {
        return None;
    }
    let listed = credential_dirs
        .iter()
        .map(|dir| dir.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Some(Finding {
        severity: Severity::Warn,
        rule: "no_secrets_resolved",
        message: format!(
            "deny_resolved is empty although host credential directories exist ({listed}); \
             add display_only_deny paths so secrets stay masked"
        ),
    })
}

/// R5 (warn): every resource ceiling is unset — CPU, address space, process
/// count, open files and file size are all unlimited for the agent.
fn rule_no_limits(policy: &Policy) -> Option<Finding> {
    let limits = &policy.limits;
    let all_unset = limits.cpu_seconds.is_none()
        && limits.address_space_bytes.is_none()
        && limits.processes.is_none()
        && limits.open_files.is_none()
        && limits.file_size_bytes.is_none();
    if all_unset {
        Some(Finding {
            severity: Severity::Warn,
            rule: "no_limits",
            message: "no resource limits are set: cpu, address space, processes, \
                      open files and file size are all unlimited"
                .to_string(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::DenyEntry;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-lint-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    fn entry(path: &Path, is_dir: bool) -> DenyEntry {
        DenyEntry {
            path: path.to_path_buf(),
            is_dir,
        }
    }

    #[test]
    fn home_write_root_fires_on_home_and_ancestor_not_on_child() {
        let home = scratch("write-root-home");

        let policy = Policy {
            allow_write: vec![home.join("sub")],
            ..Policy::default()
        };
        assert!(
            rule_home_write_root(&policy, &home).is_none(),
            "child root is fine"
        );

        let policy = Policy {
            allow_write: vec![home.clone()],
            ..Policy::default()
        };
        let findings = evaluate(&policy, &home);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "home_write_root" && f.severity == Severity::High),
            "root == home must fire: {findings:?}"
        );

        let policy = Policy {
            allow_write: vec![home.parent().expect("scratch has a parent").to_path_buf()],
            ..Policy::default()
        };
        let findings = evaluate(&policy, &home);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "home_write_root" && f.severity == Severity::High),
            "ancestor of home must fire: {findings:?}"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn home_blanket_read_fires_only_on_home_itself() {
        let home = scratch("blanket-read-home");

        let policy = Policy {
            allow_read: vec![home.join(".cargo")],
            ..Policy::default()
        };
        assert!(
            rule_home_blanket_read(&policy, &home).is_none(),
            "narrow read is fine"
        );

        let policy = Policy {
            allow_read: vec![home.clone()],
            ..Policy::default()
        };
        let findings = evaluate(&policy, &home);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "home_blanket_read" && f.severity == Severity::High),
            "reading $HOME itself must fire: {findings:?}"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn useless_deny_fires_when_deny_path_is_outside_all_roots() {
        let root = scratch("useless-deny-root");
        let mut policy = Policy::default();

        // A home outside every root keeps R1/R2/R4 out of this test's way.
        let neutral_home = Path::new("/nonexistent-vetto-lint-home");

        policy.allow_read = vec![root.clone()];
        policy.deny_resolved = vec![entry(&root.join("secret.env"), false)];
        assert!(rule_useless_deny(&policy).is_none(), "covered deny is fine");

        let outside = scratch("useless-deny-outside");
        policy.deny_resolved = vec![entry(&outside.join("elsewhere.pem"), false)];
        let findings = evaluate(&policy, neutral_home);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "useless_deny" && f.severity == Severity::Warn),
            "deny outside every allow root is a no-op: {findings:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn no_secrets_resolved_requires_existing_credential_dirs() {
        let home = scratch("secrets-home");
        std::fs::create_dir_all(home.join(".ssh")).expect("create .ssh");
        let mut policy = Policy::default();

        let findings = evaluate(&policy, &home);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "no_secrets_resolved" && f.severity == Severity::Warn),
            "empty deny list with existing .ssh must fire: {findings:?}"
        );

        policy.deny_resolved = vec![entry(&home.join(".ssh"), true)];
        assert!(
            !evaluate(&policy, &home)
                .iter()
                .any(|f| f.rule == "no_secrets_resolved"),
            "resolved secrets satisfy the rule"
        );

        // No credential directory on this home: the rule must stay silent.
        let empty_home = scratch("secrets-empty-home");
        let policy = Policy::default();
        assert!(
            !evaluate(&policy, &empty_home)
                .iter()
                .any(|f| f.rule == "no_secrets_resolved"),
            "rule must skip when no credential dirs exist"
        );

        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&empty_home);
    }

    #[test]
    fn no_limits_fires_only_when_every_field_is_unset() {
        let mut policy = Policy::default();
        let findings = evaluate(&policy, Path::new("/nonexistent-home"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "no_limits" && f.severity == Severity::Warn),
            "all-unset limits must fire: {findings:?}"
        );

        policy.limits.cpu_seconds = Some(60);
        assert!(
            !evaluate(&policy, Path::new("/nonexistent-home"))
                .iter()
                .any(|f| f.rule == "no_limits"),
            "any set field satisfies the rule"
        );
    }
}
