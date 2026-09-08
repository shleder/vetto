//! Platform capability evidence: every NOT_APPLICABLE needs proof.
//!
//! A scenario may only be skipped as NOT_APPLICABLE when the harness holds
//! positive probe evidence that the required capability is absent (FM-12).
//! Missing evidence degrades to INCONCLUSIVE, never to PASS and never to a
//! silent skip.

use serde::{Deserialize, Serialize};

/// One probed capability with its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub present: bool,
    /// How presence/absence was determined (probe name + raw outcome).
    pub evidence: String,
}

impl Capability {
    pub fn present(name: impl Into<String>, evidence: impl Into<String>) -> Self {
        Self { name: name.into(), present: true, evidence: evidence.into() }
    }

    pub fn absent(name: impl Into<String>, evidence: impl Into<String>) -> Self {
        Self { name: name.into(), present: false, evidence: evidence.into() }
    }
}

/// Capability snapshot for one gate run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub capabilities: Vec<Capability>,
}

impl CapabilitySet {
    /// Check `required` against the snapshot. Returns the subset of missing
    /// capabilities with their absence evidence. An empty required list is
    /// always satisfied.
    pub fn missing<'a>(&self, required: &'a [String]) -> Vec<&'a String> {
        required
            .iter()
            .filter(|name| {
                self.capabilities
                    .iter()
                    .find(|c| &c.name == *name)
                    .map(|c| c.present)
                    .unwrap_or(false)
                    == false
            })
            .collect()
    }

    /// Absence evidence for the missing capabilities (FM-12: no silent N/A).
    pub fn absence_evidence(&self, missing: &[&String]) -> Vec<String> {
        missing
            .iter()
            .map(|name| {
                self.capabilities
                    .iter()
                    .find(|c| &c.name == name.as_str())
                    .map(|c| {
                        if c.present {
                            format!("{}: unexpectedly present", c.name)
                        } else {
                            format!("{}: absent ({})", c.name, c.evidence)
                        }
                    })
                    .unwrap_or_else(|| format!("{name}: never probed (no evidence)"))
            })
            .collect()
    }

    /// Collect host capabilities. Pure-Rust probe surface: kernel release,
    /// tier probe on Linux, seatbelt presence on macOS, process-model
    /// presence on Windows. Never shells out; never elevates.
    pub fn probe_host() -> Self {
        let mut capabilities = Vec::new();
        capabilities.push(Capability::present(
            "spawn",
            "harness process can fork/exec (self-evident by running)",
        ));
        #[cfg(target_os = "linux")]
        {
            let probe = crate::sandbox::linux::probe();
            capabilities.push(if probe.landlock_abi.is_some() {
                Capability::present(
                    "landlock",
                    format!("landlock ABI {:?}", probe.landlock_abi),
                )
            } else {
                Capability::absent("landlock", "no Landlock ABI reported")
            });
            capabilities.push(if probe.full_tier_available {
                Capability::present("netns", "full-tier probe: userns+net+pid available")
            } else {
                Capability::absent("netns", "full-tier probe failed")
            });
            capabilities.push(if probe.full_tier_available {
                Capability::present("tree-sweep", "pidns teardown available")
            } else if probe.seccomp_filter_available {
                Capability::absent(
                    "tree-sweep",
                    "pidns unavailable; bounded reparent-sweep only (partial)",
                )
            } else {
                Capability::absent("tree-sweep", "no containment teardown available")
            });
        }
        #[cfg(target_os = "macos")]
        {
            if crate::sandbox::macos::MacosSandbox::seatbelt_available() {
                capabilities.push(Capability::present(
                    "seatbelt",
                    "sandbox_init_with_parameters or sandbox-exec present",
                ));
            } else {
                capabilities.push(Capability::absent(
                    "seatbelt",
                    "no Seatbelt API and no sandbox-exec",
                ));
            }
            capabilities.push(Capability::absent(
                "netns",
                "Darwin has no unprivileged network namespaces",
            ));
            capabilities.push(Capability::absent(
                "tree-sweep",
                "no pid namespace; kqueue watchdog is best-effort only",
            ));
        }
        #[cfg(target_os = "windows")]
        {
            capabilities.push(Capability::absent(
                "netns",
                "Windows has no network namespaces for unprivileged processes",
            ));
            capabilities.push(Capability::present(
                "tree-sweep",
                "Job Object kill-on-close terminates the tree",
            ));
        }
        Self { capabilities }
    }
}

#[cfg(test)]
mod caps_tests {
    use super::*;

    #[test]
    fn missing_lists_absent_and_unprobed() {
        let set = CapabilitySet {
            capabilities: vec![Capability::absent("netns", "probe said no")],
        };
        let required = vec!["netns".to_string(), "landlock".to_string(), "spawn".to_string()];
        let missing = set.missing(&required);
        assert_eq!(missing.len(), 3);
        let ev = set.absence_evidence(&missing);
        assert!(ev.iter().any(|e| e.contains("probe said no")));
        assert!(ev.iter().any(|e| e.contains("never probed")));
    }

    #[test]
    fn empty_required_is_satisfied() {
        let set = CapabilitySet::default();
        assert!(set.missing(&[]).is_empty());
    }
}
