//! Attack scenario registry: static catalog of security properties.
//!
//! Each scenario carries a fixed [`ClaimStrength`](super::model::ClaimStrength)
//! per platform target, a quorum rule for multi-vector scenarios, and a
//! mandatory `known_limitation`. An empty limitation is a registry lint
//! error: every claim must state what it does not prove.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::model::{Category, ClaimStrength};

/// Platform/tier target a strength entry applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Target {
    LinuxFull,
    LinuxFsOnly,
    LinuxSeccomp,
    Macos,
    Windows,
    WindowsSandboxVm,
}

impl Target {
    pub fn label(self) -> &'static str {
        match self {
            Target::LinuxFull => "linux-full",
            Target::LinuxFsOnly => "linux-fsonly",
            Target::LinuxSeccomp => "linux-seccomp",
            Target::Macos => "macos",
            Target::Windows => "windows",
            Target::WindowsSandboxVm => "windows-sandbox-vm",
        }
    }
}

/// Severity if this scenario FAILs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Blocker,
    High,
    Medium,
    Low,
}

/// One registered attack scenario (mirrors `tests/verify_ng/scenarios/*.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    /// Capabilities the runner must prove present (else NOT_APPLICABLE).
    pub required_caps: Vec<String>,
    /// Static strength ceiling per target (FM-10/FM-11).
    pub strength: BTreeMap<String, ClaimStrength>,
    /// Minimum number of independent agreeing vectors for a verdict
    /// (FM-13). `1` only for single-vector scenarios.
    pub quorum: usize,
    /// What this scenario does NOT prove. Must be non-empty.
    pub known_limitation: String,
    /// Residual risk text for PARTIAL targets. Required when any target
    /// is PARTIAL.
    #[serde(default)]
    pub residual_risk: String,
}

impl Scenario {
    pub fn strength_for(&self, target: Target) -> ClaimStrength {
        self.strength
            .get(target.label())
            .copied()
            // Unknown target: claim nothing.
            .unwrap_or(ClaimStrength::Unsupported)
    }

    /// Registry lint: non-empty limitation; quorum >= 1; PARTIAL targets
    /// require residual_risk text.
    pub fn lint(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("scenario id is empty".to_string());
        }
        if self.quorum < 1 {
            return Err(format!("{}: quorum must be >= 1", self.id));
        }
        if self.known_limitation.trim().is_empty() {
            return Err(format!("{}: known_limitation must be non-empty", self.id));
        }
        if self
            .strength
            .values()
            .any(|s| *s == ClaimStrength::Partial)
            && self.residual_risk.trim().is_empty()
        {
            return Err(format!("{}: PARTIAL target requires residual_risk", self.id));
        }
        Ok(())
    }
}

/// Statically registered scenarios (the TOML files under
/// `tests/verify_ng/scenarios/` are the source of truth for documentation;
/// this table is the compiled enforcement of the same contracts).
pub fn registry() -> Vec<Scenario> {
    vec![
        Scenario {
            id: "ORACLE-DECEIT-001".to_string(),
            category: Category::Aux,
            severity: Severity::Blocker,
            required_caps: vec!["spawn".to_string()],
            strength: BTreeMap::from([(Target::LinuxFull.label().to_string(), ClaimStrength::Strong)]),
            quorum: 1,
            known_limitation: "Proves oracle soundness only; says nothing about any enforcement backend."
                .to_string(),
            residual_risk: String::new(),
        },
        Scenario {
            id: "CONTROL-SPLIT-001".to_string(),
            category: Category::Aux,
            severity: Severity::Blocker,
            required_caps: vec!["spawn".to_string()],
            strength: BTreeMap::from([(Target::LinuxFull.label().to_string(), ClaimStrength::Strong)]),
            quorum: 1,
            known_limitation: "Proves nonce binding of the control pair only."
                .to_string(),
            residual_risk: String::new(),
        },
        Scenario {
            id: "FIXTURE-MUTATE-001".to_string(),
            category: Category::Aux,
            severity: Severity::High,
            required_caps: vec!["spawn".to_string()],
            strength: BTreeMap::from([(Target::LinuxFull.label().to_string(), ClaimStrength::Strong)]),
            quorum: 1,
            known_limitation: "Proves payload integrity checking only."
                .to_string(),
            residual_risk: String::new(),
        },
        Scenario {
            id: "ENV-POISON-001".to_string(),
            category: Category::Spawn,
            severity: Severity::Blocker,
            required_caps: vec!["spawn".to_string()],
            strength: BTreeMap::from([
                (Target::LinuxFull.label().to_string(), ClaimStrength::Strong),
                (Target::Macos.label().to_string(), ClaimStrength::Strong),
            ]),
            quorum: 1,
            known_limitation: "Proves diagnostic-env detection only; not a substitute for env scrub verification."
                .to_string(),
            residual_risk: String::new(),
        },
        Scenario {
            id: "GATE-VACUUM-001".to_string(),
            category: Category::Aux,
            severity: Severity::High,
            required_caps: vec![],
            strength: BTreeMap::from([(Target::LinuxFull.label().to_string(), ClaimStrength::Strong)]),
            quorum: 1,
            known_limitation: "Meta-test of the gate quotas; proves the gate cannot pass on an empty suite."
                .to_string(),
            residual_risk: String::new(),
        },
        Scenario {
            id: "HANG-GRANDCHILD-001".to_string(),
            category: Category::Proc,
            severity: Severity::High,
            required_caps: vec!["spawn".to_string(), "tree-sweep".to_string()],
            strength: BTreeMap::from([
                (Target::LinuxFull.label().to_string(), ClaimStrength::Strong),
                (Target::Windows.label().to_string(), ClaimStrength::Strong),
                (Target::LinuxFsOnly.label().to_string(), ClaimStrength::Partial),
                (Target::Macos.label().to_string(), ClaimStrength::Partial),
            ]),
            quorum: 1,
            known_limitation: "Proves deadline-aware collection, not general liveness of arbitrary payloads."
                .to_string(),
            residual_risk: "On fs-only/macOS the grandchild may outlive the group kill until the sweep budget expires; verdict is FAIL/INCONCLUSIVE, never PASS.".to_string(),
        },
        Scenario {
            id: "VFS-TRAV-001".to_string(),
            category: Category::FsRead,
            severity: Severity::Blocker,
            required_caps: vec!["spawn".to_string(), "landlock".to_string()],
            strength: BTreeMap::from([
                (Target::LinuxFull.label().to_string(), ClaimStrength::Strong),
                (Target::LinuxFsOnly.label().to_string(), ClaimStrength::Strong),
                (Target::Macos.label().to_string(), ClaimStrength::Partial),
                (Target::Windows.label().to_string(), ClaimStrength::Partial),
            ]),
            quorum: 2,
            known_limitation: "Covers symlink/hardlink/dotdot/rename vectors present in the payload set; new kernel path aliases need new vectors."
                .to_string(),
            residual_risk: "macOS Shape-A broad reads and Windows ACL fallback may expose entries outside the tail-deny list; strength ceiling PARTIAL there.".to_string(),
        },
        Scenario {
            id: "NET-DNS-IPV6-001".to_string(),
            category: Category::Net,
            severity: Severity::Blocker,
            required_caps: vec!["spawn".to_string(), "netns".to_string()],
            strength: BTreeMap::from([
                (Target::LinuxFull.label().to_string(), ClaimStrength::Strong),
                (Target::LinuxFsOnly.label().to_string(), ClaimStrength::Partial),
                (Target::Macos.label().to_string(), ClaimStrength::Partial),
                (Target::Windows.label().to_string(), ClaimStrength::Partial),
            ]),
            quorum: 2,
            known_limitation: "Proves --net=off isolation only; allowlist relay modes need a separate broker suite."
                .to_string(),
            residual_risk: "Without a network namespace (fs-only/mac/win) only syscall/capability denial is proven, not absence of a route.".to_string(),
        },
        Scenario {
            id: "PROC-ESC-001".to_string(),
            category: Category::Proc,
            severity: Severity::Blocker,
            required_caps: vec!["spawn".to_string(), "tree-sweep".to_string()],
            strength: BTreeMap::from([
                (Target::LinuxFull.label().to_string(), ClaimStrength::Strong),
                (Target::Windows.label().to_string(), ClaimStrength::Strong),
                (Target::LinuxFsOnly.label().to_string(), ClaimStrength::Partial),
                (Target::Macos.label().to_string(), ClaimStrength::Partial),
            ]),
            quorum: 1,
            known_limitation: "Post-mortem sweep is host-side observation of absence; a hostile scheduler can delay reparenting past the sweep budget (INCONCLUSIVE, never PASS)."
                .to_string(),
            residual_risk: "fs-only setsid orphans and macOS watchdog races are known residuals; they FAIL/advisory, never PASS.".to_string(),
        },
        Scenario {
            id: "ENV-LEAK-001".to_string(),
            category: Category::Secrets,
            severity: Severity::Blocker,
            required_caps: vec!["spawn".to_string()],
            strength: BTreeMap::from([
                (Target::LinuxFull.label().to_string(), ClaimStrength::Strong),
                (Target::Macos.label().to_string(), ClaimStrength::Strong),
                (Target::Windows.label().to_string(), ClaimStrength::Strong),
            ]),
            quorum: 1,
            known_limitation: "Proves scrub of the canary key set; unknown exfil channels (covert timing, allowed-relay payloads) are out of scope."
                .to_string(),
            residual_risk: String::new(),
        },
        Scenario {
            id: "RACE-BINDING-001".to_string(),
            category: Category::Spawn,
            severity: Severity::Blocker,
            required_caps: vec!["spawn".to_string()],
            strength: BTreeMap::from([(Target::LinuxFull.label().to_string(), ClaimStrength::Strong)]),
            quorum: 1,
            known_limitation: "Proves spec/tier binding continuity in-process; a compromised host kernel is out of scope."
                .to_string(),
            residual_risk: String::new(),
        },
        Scenario {
            id: "CLEANUP-SIGKILL-001".to_string(),
            category: Category::Proc,
            severity: Severity::High,
            required_caps: vec!["spawn".to_string(), "tree-sweep".to_string()],
            strength: BTreeMap::from([
                (Target::LinuxFull.label().to_string(), ClaimStrength::Strong),
                (Target::Windows.label().to_string(), ClaimStrength::Strong),
                (Target::LinuxFsOnly.label().to_string(), ClaimStrength::Partial),
                (Target::Macos.label().to_string(), ClaimStrength::Partial),
            ]),
            quorum: 1,
            known_limitation: "Requires an external observer process/VM; cannot be self-proven from inside the harness under test."
                .to_string(),
            residual_risk: "fs-only/macOS orphans may survive a SIGKILLed harness; suite must run in a disposable VM there.".to_string(),
        },
        Scenario {
            id: "EVIDENCE-REDACT-001".to_string(),
            category: Category::Aux,
            severity: Severity::High,
            required_caps: vec![],
            strength: BTreeMap::from([(Target::LinuxFull.label().to_string(), ClaimStrength::Strong)]),
            quorum: 1,
            known_limitation: "Proves redaction of the known secret shapes; novel shapes need secretscan updates."
                .to_string(),
            residual_risk: String::new(),
        },
        Scenario {
            id: "MAC-SHAPE-001".to_string(),
            category: Category::FsRead,
            severity: Severity::High,
            required_caps: vec!["spawn".to_string(), "seatbelt".to_string()],
            strength: BTreeMap::from([(Target::Macos.label().to_string(), ClaimStrength::Partial)]),
            quorum: 1,
            known_limitation: "Proves the enforced profile is Shape-A + tail-deny byte-for-byte; read secrecy beyond tail-deny is UNPROVABLE on macOS native."
                .to_string(),
            residual_risk: "Any path outside the tail-deny list is readable by construction; use a Linux VM for strong read secrecy.".to_string(),
        },
        Scenario {
            id: "WIN-UNC-001".to_string(),
            category: Category::FsRead,
            severity: Severity::High,
            required_caps: vec!["spawn".to_string()],
            strength: BTreeMap::from([(Target::Windows.label().to_string(), ClaimStrength::Partial)]),
            quorum: 1,
            known_limitation: "Advisory until UNC/namespace-alias coverage is mapped; starts INCONCLUSIVE, never PASS on first implementation."
                .to_string(),
            residual_risk: "Alternate path aliases (UNC, \\?\, mapped drives) may bypass ACL-shaped checks.".to_string(),
        },
        Scenario {
            id: "WIN-WSL-001".to_string(),
            category: Category::FsRead,
            severity: Severity::High,
            required_caps: vec!["spawn".to_string()],
            strength: BTreeMap::from([(Target::Windows.label().to_string(), ClaimStrength::Unsupported)]),
            quorum: 1,
            known_limitation: "WSL-interop boundary is unmapped; INCONCLUSIVE baseline until researched. Any PASS is an oracle bug."
                .to_string(),
            residual_risk: String::new(),
        },
    ]
}

/// Lint the whole registry. Used by tests and the `verify-ng lint` path.
pub fn lint_all(scenarios: &[Scenario]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for s in scenarios {
        if !seen.insert(s.id.clone()) {
            errors.push(format!("duplicate scenario id {}", s.id));
        }
        if let Err(e) = s.lint() {
            errors.push(e);
        }
    }
    errors
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn registry_lints_clean() {
        let reg = registry();
        assert!(reg.len() >= 10);
        assert_eq!(lint_all(&reg), Vec::<String>::new());
    }

    #[test]
    fn empty_limitation_is_rejected() {
        let mut s = registry().remove(0);
        s.known_limitation.clear();
        assert!(s.lint().is_err());
    }

    #[test]
    fn partial_without_residual_is_rejected() {
        let mut s = registry().remove(0);
        s.strength = BTreeMap::from([("linux-full".to_string(), ClaimStrength::Partial)]);
        s.residual_risk.clear();
        assert!(s.lint().is_err());
    }
}
