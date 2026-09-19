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
/// every rule and print findings. Exits 1 if any High severity finding is
/// reported, or if `strict` is true and any finding is reported.
pub fn run_cli(strict: bool, profile: &str, policy_path: Option<&Path>) -> Result<()> {
    let backend = Backend::detect(NetMode::Off, false).ok();
    let tier = backend.as_ref().and_then(|b| b.tier());

    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context(
            "neither $HOME nor %USERPROFILE% is set; vetto needs it to resolve policy variables",
        )?;

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

    let findings = evaluate_with_project(&policy, &home, Some(&project));
    println!("vetto policy lint: {} finding(s)", findings.len());
    for finding in &findings {
        println!(
            "  [{}] {}: {}",
            finding.severity.label(),
            finding.rule,
            finding.message
        );
    }

    let has_high = findings.iter().any(|f| f.severity == Severity::High);
    if has_high || (strict && !findings.is_empty()) {
        std::process::exit(1);
    }
    Ok(())
}

/// Run every rule against a resolved policy. `home` is passed explicitly
/// instead of read from the process environment so unit tests never mutate
/// process-global state.
pub fn evaluate(policy: &Policy, home: &Path) -> Vec<Finding> {
    evaluate_with_project(policy, home, None)
}

/// Run every rule against a resolved policy, optionally validating that
/// the project root is covered by policy allow roots.
pub fn evaluate_with_project(policy: &Policy, home: &Path, project: Option<&Path>) -> Vec<Finding> {
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

    // Phase 5 diagnostic rules:
    findings.extend(rule_invalid_cgroup_spec(policy));
    if let Some(finding) = rule_memory_swap_inversion(policy) {
        findings.push(finding);
    }
    if let Some(finding) = rule_unsupported_platform_quota(policy) {
        findings.push(finding);
    }
    if let Some(finding) = rule_network_off_with_domains(policy) {
        findings.push(finding);
    }
    if let Some(finding) = rule_insecure_allowlist_wildcard(policy) {
        findings.push(finding);
    }
    findings.extend(rule_env_allow_deny_collision(policy));
    if let Some(project_path) = project {
        if let Some(finding) = rule_workspace_outside_roots(policy, project_path) {
            findings.push(finding);
        }
    }

    findings
}

fn is_valid_memory_spec(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.starts_with('-') {
        return false;
    }
    if t.eq_ignore_ascii_case("max") {
        return true;
    }
    crate::policy::types::parse_bytes_value(t)
        .map(|v| v > 0)
        .unwrap_or(false)
}

fn is_valid_pids_spec(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.starts_with('-') {
        return false;
    }
    if t.eq_ignore_ascii_case("max") {
        return true;
    }
    t.parse::<u64>().map(|v| v > 0).unwrap_or(false)
}

fn is_valid_cpu_spec(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.starts_with('-') {
        return false;
    }
    if t.eq_ignore_ascii_case("max") {
        return true;
    }
    if let Some(pct_str) = t.strip_suffix('%') {
        let pct_str = pct_str.trim();
        if pct_str.is_empty() || pct_str.starts_with('-') {
            return false;
        }
        return pct_str
            .parse::<f64>()
            .map(|p| p > 0.0 && !p.is_nan() && !p.is_infinite())
            .unwrap_or(false);
    }
    if t.contains(|c: char| c.is_whitespace()) {
        let mut parts = t.split_whitespace();
        let quota_s = match parts.next() {
            Some(q) => q,
            None => return false,
        };
        let period_s = match parts.next() {
            Some(p) => p,
            None => return false,
        };
        if parts.next().is_some() {
            return false;
        }
        if quota_s.starts_with('-') || period_s.starts_with('-') {
            return false;
        }
        let quota_ok = quota_s.eq_ignore_ascii_case("max")
            || quota_s.parse::<u64>().map(|q| q > 0).unwrap_or(false);
        let period_ok = period_s.parse::<u64>().map(|p| p > 0).unwrap_or(false);
        return quota_ok && period_ok;
    }
    if let Ok(quota) = t.parse::<u64>() {
        return quota > 0;
    }
    false
}

fn is_temp_root(p: &Path) -> bool {
    p == Path::new("/tmp")
        || p == Path::new("/var/tmp")
        || p == Path::new("/private/tmp")
        || p == std::env::temp_dir()
        || p.starts_with("/dev/")
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
        if root == home {
            return Some(Finding {
                severity: Severity::High,
                rule: "home_write_root",
                message: message(root),
            });
        }
        if !is_temp_root(root) && home.starts_with(root) {
            return Some(Finding {
                severity: Severity::High,
                rule: "home_write_root",
                message: message(root),
            });
        }
        if let (Ok(root_canonical), Ok(home_canonical)) =
            (std::fs::canonicalize(root), std::fs::canonicalize(home))
        {
            if root_canonical == home_canonical {
                return Some(Finding {
                    severity: Severity::High,
                    rule: "home_write_root",
                    message: message(root),
                });
            }
            if !is_temp_root(&root_canonical) && home_canonical.starts_with(&root_canonical) {
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

/// R6 (high): syntactically invalid, negative, or unparseable cgroup memory/CPU quota strings.
fn rule_invalid_cgroup_spec(policy: &Policy) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(cg) = &policy.cgroup {
        if let Some(mem) = &cg.memory_max {
            if !is_valid_memory_spec(mem) {
                findings.push(Finding {
                    severity: Severity::High,
                    rule: "invalid-cgroup-spec",
                    message: format!(
                        "invalid cgroup memory limit spec '{mem}': must be 'max' or positive byte quantity (e.g. '512M')"
                    ),
                });
            }
        }
        if let Some(swap) = &cg.swap_max {
            if !is_valid_memory_spec(swap) {
                findings.push(Finding {
                    severity: Severity::High,
                    rule: "invalid-cgroup-spec",
                    message: format!(
                        "invalid cgroup swap limit spec '{swap}': must be 'max' or positive byte quantity (e.g. '256M')"
                    ),
                });
            }
        }
        if let Some(pids) = &cg.pids_max {
            if !is_valid_pids_spec(pids) {
                findings.push(Finding {
                    severity: Severity::High,
                    rule: "invalid-cgroup-spec",
                    message: format!(
                        "invalid cgroup pids limit spec '{pids}': must be 'max' or positive integer"
                    ),
                });
            }
        }
        if let Some(cpu) = &cg.cpu_max {
            if !is_valid_cpu_spec(cpu) {
                findings.push(Finding {
                    severity: Severity::High,
                    rule: "invalid-cgroup-spec",
                    message: format!(
                        "invalid cgroup cpu limit spec '{cpu}': must be 'max', percentage (e.g. '50%'), or quota/period (e.g. '50000 100000')"
                    ),
                });
            }
        }
    }
    if let Some(cpu) = &policy.cpu_max {
        if !is_valid_cpu_spec(cpu) {
            findings.push(Finding {
                severity: Severity::High,
                rule: "invalid-cgroup-spec",
                message: format!(
                    "invalid policy cpu_max limit spec '{cpu}': must be 'max', percentage (e.g. '50%'), or quota/period"
                ),
            });
        }
    }
    findings
}

/// R7 (high): swap.max exceeds or conflicts with memory.max.
fn rule_memory_swap_inversion(policy: &Policy) -> Option<Finding> {
    let cg = policy.cgroup.as_ref()?;
    let swap_str = cg.swap_max.as_deref()?;
    let mem_str = cg.memory_max.as_deref()?;

    let swap_is_max = swap_str.trim().eq_ignore_ascii_case("max");
    let mem_is_max = mem_str.trim().eq_ignore_ascii_case("max");

    let swap_bytes = crate::policy::types::parse_bytes_value(swap_str);
    let mem_bytes = crate::policy::types::parse_bytes_value(mem_str);

    let inversion = match (swap_is_max, mem_is_max, swap_bytes, mem_bytes) {
        (true, false, _, Some(_)) => true, // swap unlimited while memory is limited
        (false, false, Some(sb), Some(mb)) => sb > mb,
        _ => false,
    };

    if inversion {
        Some(Finding {
            severity: Severity::High,
            rule: "memory-swap-inversion",
            message: format!(
                "cgroup swap.max ('{swap_str}') exceeds memory.max ('{mem_str}'): swap ceiling cannot be greater than memory ceiling"
            ),
        })
    } else {
        None
    }
}

/// R8 (warn): cgroup v2 quotas configured on platforms without cgroup support (macOS, Windows native).
fn rule_unsupported_platform_quota(policy: &Policy) -> Option<Finding> {
    let has_cgroup = policy.cgroup.as_ref().is_some_and(|cg| {
        cg.memory_max.is_some()
            || cg.swap_max.is_some()
            || cg.pids_max.is_some()
            || cg.cpu_max.is_some()
    }) || policy.cpu_max.is_some();

    if !has_cgroup {
        return None;
    }

    let os = std::env::var("VETTO_TARGET_OS").unwrap_or_else(|_| std::env::consts::OS.to_string());
    if os == "macos"
        || os == "windows"
        || (!cfg!(target_os = "linux") && std::env::var("VETTO_TARGET_OS").is_err())
    {
        Some(Finding {
            severity: Severity::Warn,
            rule: "unsupported-platform-quota",
            message: "cgroup v2 resource quotas configured in policy are not supported on macOS/Windows and will not be enforced".to_string(),
        })
    } else {
        None
    }
}

/// R9 (warn): network mode is 'off' but domain allowlist/strict rules are defined.
fn rule_network_off_with_domains(policy: &Policy) -> Option<Finding> {
    let net_off = policy
        .network_mode
        .as_deref()
        .map(|m| m.eq_ignore_ascii_case("off"))
        .unwrap_or(false)
        || policy.deny_network;
    let has_domains = !policy.network_allow.is_empty() || !policy.net_quota.is_empty();

    if net_off && has_domains {
        Some(Finding {
            severity: Severity::Warn,
            rule: "network-off-with-domains",
            message: format!(
                "network mode is 'off' but domain allowlist rules are defined ({} domain(s)); domain rules are dormant and will never be contacted",
                policy.network_allow.len()
            ),
        })
    } else {
        None
    }
}

/// R10 (high): wildcard rule '*' in network allowlist destroying domain isolation.
fn rule_insecure_allowlist_wildcard(policy: &Policy) -> Option<Finding> {
    for domain in &policy.network_allow {
        let trimmed = domain.trim();
        if trimmed == "*" || trimmed == "*.*" {
            return Some(Finding {
                severity: Severity::High,
                rule: "insecure-allowlist-wildcard",
                message: "wildcard '*' in network allowlist destroys domain isolation: every outbound destination is permitted".to_string(),
            });
        }
    }
    None
}

/// R11 (high): identical environment variable in both pass-through and deny lists.
fn rule_env_allow_deny_collision(policy: &Policy) -> Vec<Finding> {
    let mut findings = Vec::new();
    for pass in &policy.environment.pass_through {
        let is_denied = policy
            .environment
            .deny
            .iter()
            .any(|d| d.eq_ignore_ascii_case(pass));
        if is_denied {
            findings.push(Finding {
                severity: Severity::High,
                rule: "env-allow-deny-collision",
                message: format!(
                    "environment variable '{pass}' is present in both pass-through and deny lists: conflicting grant and revocation"
                ),
            });
        }
    }
    findings
}

/// R12 (high): workspace/project root is outside all allowed read/write roots.
fn rule_workspace_outside_roots(policy: &Policy, project: &Path) -> Option<Finding> {
    let covered_lexical = policy
        .allow_write
        .iter()
        .chain(policy.allow_read.iter())
        .any(|root| project == root || project.starts_with(root));

    if covered_lexical {
        return None;
    }

    if let Ok(project_canon) = std::fs::canonicalize(project) {
        let covered_canon = policy
            .allow_write
            .iter()
            .chain(policy.allow_read.iter())
            .any(|root| {
                if let Ok(root_canon) = std::fs::canonicalize(root) {
                    project_canon == root_canon || project_canon.starts_with(&root_canon)
                } else {
                    false
                }
            });
        if covered_canon {
            return None;
        }
    }

    Some(Finding {
        severity: Severity::High,
        rule: "workspace-outside-roots",
        message: format!(
            "workspace root '{}' is outside all allowed read/write roots: agent cannot access its own working directory",
            project.display()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::{CgroupConfig, DenyEntry};

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
        let base = scratch("write-root-base");
        let home = base.join("fake-home");
        std::fs::create_dir_all(&home).expect("create fake home");

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

        let _ = std::fs::remove_dir_all(&base);
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

    #[test]
    fn invalid_cgroup_spec_catches_negative_and_garbage() {
        let policy = Policy {
            cgroup: Some(CgroupConfig {
                memory_max: Some("-500M".into()),
                pids_max: Some("invalid".into()),
                swap_max: Some("".into()),
                cpu_max: Some("-10%".into()),
            }),
            cpu_max: Some("garbage".into()),
            ..Policy::default()
        };

        let findings = rule_invalid_cgroup_spec(&policy);
        assert_eq!(findings.len(), 5);
        for f in &findings {
            assert_eq!(f.rule, "invalid-cgroup-spec");
            assert_eq!(f.severity, Severity::High);
        }

        let valid_policy = Policy {
            cgroup: Some(CgroupConfig {
                memory_max: Some("512M".into()),
                swap_max: Some("max".into()),
                pids_max: Some("100".into()),
                cpu_max: Some("50000 100000".into()),
            }),
            cpu_max: Some("75%".into()),
            ..Policy::default()
        };
        assert!(rule_invalid_cgroup_spec(&valid_policy).is_empty());
    }

    #[test]
    fn is_valid_spec_helpers_test() {
        assert!(is_valid_memory_spec("max"));
        assert!(is_valid_memory_spec("MAX"));
        assert!(is_valid_memory_spec("512M"));
        assert!(is_valid_memory_spec("1G"));
        assert!(!is_valid_memory_spec(""));
        assert!(!is_valid_memory_spec("-100M"));
        assert!(!is_valid_memory_spec("0"));
        assert!(!is_valid_memory_spec("invalid"));

        assert!(is_valid_pids_spec("max"));
        assert!(is_valid_pids_spec("10"));
        assert!(!is_valid_pids_spec("0"));
        assert!(!is_valid_pids_spec("-5"));
        assert!(!is_valid_pids_spec(""));
        assert!(!is_valid_pids_spec("foo"));

        assert!(is_valid_cpu_spec("max"));
        assert!(is_valid_cpu_spec("max 100000"));
        assert!(is_valid_cpu_spec("50000 100000"));
        assert!(is_valid_cpu_spec("50%"));
        assert!(is_valid_cpu_spec("200000"));
        assert!(!is_valid_cpu_spec(""));
        assert!(!is_valid_cpu_spec("0"));
        assert!(!is_valid_cpu_spec("0%"));
        assert!(!is_valid_cpu_spec("-50%"));
        assert!(!is_valid_cpu_spec("max 0"));
        assert!(!is_valid_cpu_spec("50%foo"));
        assert!(!is_valid_cpu_spec("invalid"));
    }

    #[test]
    fn memory_swap_inversion_detects_swap_greater_than_mem() {
        let policy1 = Policy {
            cgroup: Some(CgroupConfig {
                memory_max: Some("512M".into()),
                swap_max: Some("1G".into()),
                pids_max: None,
                cpu_max: None,
            }),
            ..Policy::default()
        };
        let finding = rule_memory_swap_inversion(&policy1);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule, "memory-swap-inversion");
        assert_eq!(f.severity, Severity::High);

        let policy2 = Policy {
            cgroup: Some(CgroupConfig {
                memory_max: Some("512M".into()),
                swap_max: Some("max".into()),
                pids_max: None,
                cpu_max: None,
            }),
            ..Policy::default()
        };
        assert!(rule_memory_swap_inversion(&policy2).is_some());

        let policy3 = Policy {
            cgroup: Some(CgroupConfig {
                memory_max: Some("512M".into()),
                swap_max: Some("256M".into()),
                pids_max: None,
                cpu_max: None,
            }),
            ..Policy::default()
        };
        assert!(rule_memory_swap_inversion(&policy3).is_none());

        let policy4 = Policy {
            cgroup: Some(CgroupConfig {
                memory_max: Some("max".into()),
                swap_max: Some("max".into()),
                pids_max: None,
                cpu_max: None,
            }),
            ..Policy::default()
        };
        assert!(rule_memory_swap_inversion(&policy4).is_none());
    }

    #[test]
    fn unsupported_platform_quota_fires_on_macos_windows() {
        std::env::remove_var("VETTO_TARGET_OS");
        let policy = Policy {
            cpu_max: Some("50%".into()),
            ..Policy::default()
        };

        std::env::set_var("VETTO_TARGET_OS", "macos");
        let f_macos = rule_unsupported_platform_quota(&policy);
        assert!(f_macos.is_some());
        let f = f_macos.unwrap();
        assert_eq!(f.rule, "unsupported-platform-quota");
        assert_eq!(f.severity, Severity::Warn);

        std::env::set_var("VETTO_TARGET_OS", "windows");
        assert!(rule_unsupported_platform_quota(&policy).is_some());

        std::env::set_var("VETTO_TARGET_OS", "linux");
        assert!(rule_unsupported_platform_quota(&policy).is_none());

        std::env::remove_var("VETTO_TARGET_OS");
    }

    #[test]
    fn network_off_with_domains_detects_dormant_rules() {
        let policy1 = Policy {
            network_mode: Some("off".into()),
            network_allow: vec!["api.openai.com".into()],
            ..Policy::default()
        };
        let finding1 = rule_network_off_with_domains(&policy1);
        assert!(finding1.is_some());
        let f = finding1.unwrap();
        assert_eq!(f.rule, "network-off-with-domains");
        assert_eq!(f.severity, Severity::Warn);

        let mut policy2 = Policy {
            deny_network: true,
            ..Policy::default()
        };
        policy2.net_quota.insert("example.com".into(), 1024);
        assert!(rule_network_off_with_domains(&policy2).is_some());

        let policy3 = Policy {
            network_mode: Some("allowlist".into()),
            network_allow: vec!["api.openai.com".into()],
            ..Policy::default()
        };
        assert!(rule_network_off_with_domains(&policy3).is_none());

        let policy4 = Policy {
            network_mode: Some("off".into()),
            network_allow: Vec::new(),
            ..Policy::default()
        };
        assert!(rule_network_off_with_domains(&policy4).is_none());
    }

    #[test]
    fn insecure_allowlist_wildcard_detects_star() {
        let policy1 = Policy {
            network_allow: vec!["*".into()],
            ..Policy::default()
        };
        let finding1 = rule_insecure_allowlist_wildcard(&policy1);
        assert!(finding1.is_some());
        let f = finding1.unwrap();
        assert_eq!(f.rule, "insecure-allowlist-wildcard");
        assert_eq!(f.severity, Severity::High);

        let policy2 = Policy {
            network_allow: vec!["*.*".into()],
            ..Policy::default()
        };
        assert!(rule_insecure_allowlist_wildcard(&policy2).is_some());

        let policy3 = Policy {
            network_allow: vec!["*.openai.com".into()],
            ..Policy::default()
        };
        assert!(rule_insecure_allowlist_wildcard(&policy3).is_none());
    }

    #[test]
    fn env_allow_deny_collision_detects_overlap() {
        let mut policy = Policy::default();
        policy.environment.pass_through = vec!["OPENAI_API_KEY".into(), "PATH".into()];
        policy.environment.deny = vec!["openai_api_key".into()];

        let findings = rule_env_allow_deny_collision(&policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "env-allow-deny-collision");
        assert_eq!(findings[0].severity, Severity::High);

        let mut safe_policy = Policy::default();
        safe_policy.environment.pass_through = vec!["PATH".into()];
        safe_policy.environment.deny = vec!["SECRET_KEY".into()];
        assert!(rule_env_allow_deny_collision(&safe_policy).is_empty());
    }

    #[test]
    fn workspace_outside_roots_detects_uncovered_project() {
        let scratch_proj = scratch("workspace-proj");
        let scratch_other = scratch("workspace-other");

        let policy = Policy {
            allow_write: vec![scratch_other.clone()],
            ..Policy::default()
        };
        let finding = rule_workspace_outside_roots(&policy, &scratch_proj);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule, "workspace-outside-roots");
        assert_eq!(f.severity, Severity::High);

        let covered_policy = Policy {
            allow_write: vec![scratch_proj.clone()],
            ..Policy::default()
        };
        assert!(rule_workspace_outside_roots(&covered_policy, &scratch_proj).is_none());

        let _ = std::fs::remove_dir_all(&scratch_proj);
        let _ = std::fs::remove_dir_all(&scratch_other);
    }

    #[test]
    fn evaluate_with_project_aggregates_findings() {
        let scratch_proj = scratch("eval-proj");
        let neutral_home = Path::new("/nonexistent-vetto-lint-home");

        let mut policy = Policy {
            allow_write: vec![scratch_proj.clone()],
            network_allow: vec!["*".into()],
            ..Policy::default()
        };
        policy.limits.cpu_seconds = Some(10);

        let findings = evaluate_with_project(&policy, neutral_home, Some(&scratch_proj));
        assert!(findings
            .iter()
            .any(|f| f.rule == "insecure-allowlist-wildcard" && f.severity == Severity::High));

        let _ = std::fs::remove_dir_all(&scratch_proj);
    }

    #[test]
    fn strict_failure_invariant_decision_logic() {
        let high_findings = vec![Finding {
            severity: Severity::High,
            rule: "invalid-cgroup-spec",
            message: "msg".into(),
        }];
        let warn_findings = vec![Finding {
            severity: Severity::Warn,
            rule: "unsupported-platform-quota",
            message: "msg".into(),
        }];
        let empty_findings: Vec<Finding> = Vec::new();

        let should_fail = |findings: &[Finding], strict: bool| -> bool {
            let has_high = findings.iter().any(|f| f.severity == Severity::High);
            has_high || (strict && !findings.is_empty())
        };

        assert!(
            should_fail(&high_findings, false),
            "High fails even without strict"
        );
        assert!(should_fail(&high_findings, true), "High fails with strict");
        assert!(
            !should_fail(&warn_findings, false),
            "Warn succeeds without strict"
        );
        assert!(should_fail(&warn_findings, true), "Warn fails with strict");
        assert!(
            !should_fail(&empty_findings, false),
            "Empty succeeds without strict"
        );
        assert!(
            !should_fail(&empty_findings, true),
            "Empty succeeds with strict"
        );
    }
}
