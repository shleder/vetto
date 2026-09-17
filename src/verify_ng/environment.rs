//! Environment isolation verification battery (Master Task Section 5).
//!
//! Enforces that forbidden host environment values do not enter execution:
//! - Arbitrary host variables (never passed unless explicitly permitted by contract)
//! - Sensitive-looking variables (API keys, secrets, credentials, tokens)
//! - PATH manipulation (sanitization of empty components, '.', '~', and relative dirs)
//! - Inherited unscrubbed environment
//! - Internal Vetto variables (e.g. VETTO_SEATBELT_MODE, unconfigured flags)
//! - Explicitly denied variables (by contract.environment.redacted_patterns or policy.environment.deny)
//! - Post-start environment mutation immutability (host environment before == host environment after)
//!
//! The verifier distinguishes between variables "allowed by contract" and those
//! "present because host leaked", without making any blanket prefix assumptions.
//! All evidence collected is independent runtime evidence (`HOST_FACT`), captured
//! via the supervisor reading `/proc/<pid>/environ` and host process state.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::policy_ir::contract::SecurityContract;
use crate::sandbox::envfilter;
use crate::verify_ng::redact;

/// Violation categories defined by Master Task Section 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentViolation {
    /// An arbitrary variable from the host leaked into the child without contract authorization.
    ArbitraryHostVariableLeaked { key: String, value: String },
    /// A sensitive-looking variable (matching hard-denied prefixes or patterns) reached execution.
    SensitiveVariableLeaked { key: String, value: String },
    /// PATH was manipulated, unsanitized, or contains forbidden components ('.', empty, '~', relative).
    PathManipulation { path: String, reason: String },
    /// Host environment was inherited wholesale instead of being scrubbed clean-room.
    InheritedEnvironmentUnscrubbed { key: String },
    /// Internal Vetto variable leaked to the sandboxed execution.
    InternalVettoVariableLeaked { key: String },
    /// Variable explicitly denied by contract was present in execution.
    ExplicitlyDeniedVariablePresent { key: String },
    /// The host process environment was mutated across the execution run.
    HostEnvironmentMutated { diff: Vec<String> },
    /// Post-start mutation attempted by child violated contract confines.
    PostStartMutationDetected { detail: String },
}

impl EnvironmentViolation {
    pub fn key(&self) -> &str {
        match self {
            Self::ArbitraryHostVariableLeaked { key, .. } => key,
            Self::SensitiveVariableLeaked { key, .. } => key,
            Self::PathManipulation { .. } => "PATH",
            Self::InheritedEnvironmentUnscrubbed { key } => key,
            Self::InternalVettoVariableLeaked { key } => key,
            Self::ExplicitlyDeniedVariablePresent { key } => key,
            Self::HostEnvironmentMutated { .. } => "HOST_ENV",
            Self::PostStartMutationDetected { .. } => "MUTATION",
        }
    }

    pub fn reason(&self) -> String {
        match self {
            Self::ArbitraryHostVariableLeaked { key, .. } => {
                format!("arbitrary host variable '{key}' leaked into execution without contract authorization")
            }
            Self::SensitiveVariableLeaked { key, .. } => {
                format!("sensitive-looking variable '{key}' reached sandboxed execution")
            }
            Self::PathManipulation { path, reason } => {
                format!("PATH manipulation detected in '{path}': {reason}")
            }
            Self::InheritedEnvironmentUnscrubbed { key } => {
                format!("unallowed inherited variable '{key}' present in execution")
            }
            Self::InternalVettoVariableLeaked { key } => {
                format!("internal Vetto variable '{key}' leaked to execution")
            }
            Self::ExplicitlyDeniedVariablePresent { key } => {
                format!("variable '{key}' explicitly denied by contract was present in execution")
            }
            Self::HostEnvironmentMutated { diff } => {
                format!("host process environment was mutated: {}", diff.join(", "))
            }
            Self::PostStartMutationDetected { detail } => {
                format!("post-start mutation detected: {detail}")
            }
        }
    }
}

impl std::fmt::Display for EnvironmentViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason())
    }
}

/// Context for harness-managed environment variables necessary for verification transport.
#[derive(Debug, Clone)]
pub struct HarnessEnvContext {
    pub isolated_home: PathBuf,
    pub fixture_root: PathBuf,
    pub session_nonce: String,
    pub has_control_channel: bool,
    pub control_downlink_val: Option<String>,
    pub control_uplink_val: Option<String>,
}

/// Report produced by independent runtime environment verification.
#[derive(Debug, Clone)]
pub struct EnvironmentVerificationReport {
    pub clean: bool,
    pub allowed_by_contract: Vec<(String, String)>,
    pub violations: Vec<EnvironmentViolation>,
    pub host_facts: Vec<(String, String)>,
}

/// Read child process environment directly from `/proc/<pid>/environ` (Linux).
/// This provides independent runtime evidence from the OS kernel.
#[cfg(target_os = "linux")]
pub fn capture_proc_environ(pid: u32) -> Option<Vec<(String, String)>> {
    let bytes = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    parse_null_delimited_environ(&bytes)
}

#[cfg(not(target_os = "linux"))]
pub fn capture_proc_environ(_pid: u32) -> Option<Vec<(String, String)>> {
    None
}

/// Parse null-delimited environ bytes (`KEY=VAL\0KEY2=VAL2\0`).
pub fn parse_null_delimited_environ(bytes: &[u8]) -> Option<Vec<(String, String)>> {
    let mut vars = Vec::new();
    for entry in bytes.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        if let Some(pos) = entry.iter().position(|&b| b == b'=') {
            let key = String::from_utf8_lossy(&entry[..pos]).to_string();
            let val = String::from_utf8_lossy(&entry[pos + 1..]).to_string();
            vars.push((key, val));
        }
    }
    Some(vars)
}

/// Check if a variable is explicitly denied by the contract's redacted patterns or policy deny list.
pub fn is_denied_by_contract(contract: &SecurityContract, key: &str) -> bool {
    // 1. Check contract.environment.redacted_patterns
    if contract
        .environment
        .redacted_patterns
        .iter()
        .any(|pat| envfilter::matches_wildcard_pattern(pat, key))
    {
        return true;
    }
    // 2. Check production installation_policy.environment.deny
    if let Some(prod) = &contract.production {
        if prod
            .installation_policy
            .environment
            .deny
            .iter()
            .any(|pat| envfilter::matches_wildcard_pattern(pat, key))
        {
            return true;
        }
    }
    false
}

/// Check if a variable is explicitly allowed into the execution by the contract.
/// Strictly follows contract semantics; returns false for anything not defined.
pub fn is_allowed_by_contract(
    contract: &SecurityContract,
    key: &str,
    val: &str,
    harness: Option<&HarnessEnvContext>,
) -> Result<(), EnvironmentViolation> {
    // 1. Explicitly denied variables always fail
    if is_denied_by_contract(contract, key) {
        return Err(EnvironmentViolation::ExplicitlyDeniedVariablePresent {
            key: key.to_string(),
        });
    }

    // 2. Explicit contract vars
    if let Some(expected_val) = contract.environment.explicit_vars.get(key) {
        if expected_val == val {
            return Ok(());
        }
    }

    // 3. Injected session nonce
    if key == "VETTO_PROD_NONCE" {
        if contract.environment.inject_session_nonce && val == contract.session_nonce {
            return Ok(());
        } else {
            return Err(EnvironmentViolation::InternalVettoVariableLeaked {
                key: key.to_string(),
            });
        }
    }

    // 4. Harness transport variables
    if let Some(h) = harness {
        if key == "HOME" {
            if Path::new(val) == h.isolated_home {
                return Ok(());
            } else {
                return Err(EnvironmentViolation::InheritedEnvironmentUnscrubbed {
                    key: "HOME".to_string(),
                });
            }
        }
        if key == "USERPROFILE" {
            if Path::new(val) == h.isolated_home {
                return Ok(());
            }
        }
        if key == "VETTO_RUN_NONCE" && val == h.session_nonce {
            return Ok(());
        }
        if key == "VETTO_FIXTURE_ROOT" && Path::new(val) == h.fixture_root {
            return Ok(());
        }
        if key == "VETTO_VNG_CONTROL_DOWNLINK" && h.has_control_channel {
            if let Some(ref expected) = h.control_downlink_val {
                if val != expected {
                    return Err(EnvironmentViolation::InternalVettoVariableLeaked {
                        key: key.to_string(),
                    });
                }
            }
            return Ok(());
        }
        if key == "VETTO_VNG_CONTROL_UPLINK" && h.has_control_channel {
            if let Some(ref expected) = h.control_uplink_val {
                if val != expected {
                    return Err(EnvironmentViolation::InternalVettoVariableLeaked {
                        key: key.to_string(),
                    });
                }
            }
            return Ok(());
        }
    }

    // Any other VETTO_* variable not in the explicit harness set is an internal leak
    if key.starts_with("VETTO_") {
        return Err(EnvironmentViolation::InternalVettoVariableLeaked {
            key: key.to_string(),
        });
    }

    // 5. Hard-denied / sensitive credentials
    if envfilter::is_hard_denied(key) {
        return Err(EnvironmentViolation::SensitiveVariableLeaked {
            key: key.to_string(),
            value: redact::redact_text(val),
        });
    }

    // 6. PATH check
    if key.eq_ignore_ascii_case("PATH") {
        let components: Vec<&str> = val.split(':').collect();
        if components
            .iter()
            .any(|c| c.is_empty() || *c == "." || c.starts_with('~'))
        {
            return Err(EnvironmentViolation::PathManipulation {
                path: val.to_string(),
                reason: "contains '.', empty, or '~' relative component".to_string(),
            });
        }
        let sanitized = envfilter::sanitize_path(val);
        if val != sanitized {
            return Err(EnvironmentViolation::PathManipulation {
                path: val.to_string(),
                reason: format!("path '{val}' differs from sanitized '{sanitized}'"),
            });
        }
    }

    // 7. Contract pass_through_vars and policy.environment.allows
    let in_pass_through_vars = contract
        .environment
        .pass_through_vars
        .iter()
        .any(|pat| envfilter::matches_wildcard_pattern(pat, key));

    let in_policy_pass_through = contract
        .production
        .as_ref()
        .map(|prod| prod.installation_policy.environment.allows(OsStr::new(key)))
        .unwrap_or(false);

    if in_pass_through_vars || in_policy_pass_through {
        return Ok(());
    }

    Err(EnvironmentViolation::InheritedEnvironmentUnscrubbed {
        key: key.to_string(),
    })
}

/// Execute the environment isolation battery against an observed environment.
///
/// Consumes the SAME sealed [`SecurityContract`] used by production execution,
/// verifies that all observed variables are strictly allowed by the contract,
/// distinguishes allowed variables from host leaks, and checks that host process
/// environment remained immutable across the run.
pub fn verify_execution_environment(
    contract: &SecurityContract,
    observed_env: &[(String, String)],
    host_env_before: &BTreeMap<String, String>,
    host_env_after: &BTreeMap<String, String>,
    harness: Option<&HarnessEnvContext>,
) -> EnvironmentVerificationReport {
    let mut violations = Vec::new();
    let mut allowed_by_contract = Vec::new();
    let mut host_facts = Vec::new();

    // 1. Post-start host environment mutation check
    let mut mutated_keys = Vec::new();
    for (k, v) in host_env_before {
        if host_env_after.get(k) != Some(v) {
            mutated_keys.push(format!("mutated:{k}"));
        }
    }
    for (k, _) in host_env_after {
        if !host_env_before.contains_key(k) {
            mutated_keys.push(format!("added:{k}"));
        }
    }
    if !mutated_keys.is_empty() {
        violations.push(EnvironmentViolation::HostEnvironmentMutated {
            diff: mutated_keys.clone(),
        });
        host_facts.push((
            "env-violation".to_string(),
            format!("host_mutated:{}", mutated_keys.join(",")),
        ));
    }

    // 2. Per-variable analysis of observed execution environment
    for (key, val) in observed_env {
        match is_allowed_by_contract(contract, key, val, harness) {
            Ok(()) => {
                allowed_by_contract.push((key.clone(), val.clone()));
                host_facts.push(("env-item".to_string(), format!("allowed_by_contract:{key}")));
            }
            Err(mut v) => {
                // Refine error if this variable came from the host environment
                if let EnvironmentViolation::InheritedEnvironmentUnscrubbed { .. } = v {
                    if host_env_before.contains_key(key) {
                        v = EnvironmentViolation::ArbitraryHostVariableLeaked {
                            key: key.clone(),
                            value: val.clone(),
                        };
                    }
                }
                host_facts.push(("env-item".to_string(), format!("leaked_from_host:{key}")));
                host_facts.push((
                    "env-violation".to_string(),
                    format!("{}:{}", v.key(), v.reason()),
                ));
                violations.push(v);
            }
        }
    }

    // 3. Stamping vector evidence and clean-room summary
    if violations.is_empty() {
        host_facts.push((
            "env-isolated".to_string(),
            "clean:contract-conforming".to_string(),
        ));
        host_facts.push(("vector:env-scrub".to_string(), "clean:scrubbed".to_string()));
        host_facts.push((
            "vector:env-hygiene".to_string(),
            "clean:path-and-internal".to_string(),
        ));
    }

    EnvironmentVerificationReport {
        clean: violations.is_empty(),
        allowed_by_contract,
        violations,
        host_facts,
    }
}
