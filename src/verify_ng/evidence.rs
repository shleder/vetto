//! Three-tier evidence model (FM-01).
//!
//! - [`EvidenceTier::HostFact`]: observed by the trusted host after wait
//!   (post-mortem stat, wait status, sweep result, canary comparison).
//!   The only tier that can support a PASS.
//! - [`EvidenceTier::Constrained`]: narrow in-sandbox signal through a
//!   nonce-bound channel (errno class + nonce). Supports FAIL, never PASS
//!   alone.
//! - [`EvidenceTier::SelfReport`]: attacker-controlled stdout markers.
//!   Hints for triage only; never decide a verdict.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceTier {
    HostFact,
    Constrained,
    SelfReport,
}

/// One collected fact with its tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    pub tier: EvidenceTier,
    pub name: String,
    pub value: String,
}

/// Collected evidence for one scenario run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    pub facts: Vec<Fact>,
}

impl Evidence {
    pub fn push(&mut self, tier: EvidenceTier, name: &str, value: String) {
        self.facts.push(Fact {
            tier,
            name: name.to_string(),
            value,
        });
    }

    pub fn host_fact(&mut self, name: &str, value: String) {
        self.push(EvidenceTier::HostFact, name, value);
    }

    pub fn constrained(&mut self, name: &str, value: String) {
        self.push(EvidenceTier::Constrained, name, value);
    }

    pub fn self_report(&mut self, name: &str, value: String) {
        self.push(EvidenceTier::SelfReport, name, value);
    }

    /// PASS requires at least one host fact (FM-01 structural rule).
    pub fn has_host_fact(&self) -> bool {
        self.facts.iter().any(|f| f.tier == EvidenceTier::HostFact)
    }

    pub fn host_fact_value(&self, name: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|f| f.tier == EvidenceTier::HostFact && f.name == name)
            .map(|f| f.value.as_str())
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;

    #[test]
    fn pass_requires_host_fact() {
        let mut e = Evidence::default();
        e.self_report("marker", "PASS".to_string());
        e.constrained("errno", "EACCES".to_string());
        assert!(!e.has_host_fact());
        e.host_fact("postmortem", "absent".to_string());
        assert!(e.has_host_fact());
    }
}
