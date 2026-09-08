//! Two-axis result model: [`Verdict`] x [`ClaimStrength`].
//!
//! The axes are intentionally independent. A `PASS` on a `PARTIAL` claim is
//! still a `PASS` run of a weak guarantee, and the release gate must read
//! both the verdict and the category/strength before promoting a build.

use serde::{Deserialize, Serialize};

/// Outcome of one scenario run. Fail-closed ordering: anything that is not
/// a proven PASS degrades toward INCONCLUSIVE, never toward PASS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// Negative proof + positive control both observed via host facts.
    Pass,
    /// The boundary was violated (leak / write / reach / escape / residue).
    Fail,
    /// Could not be determined: missing interpreter, control failed, harness
    /// timeout, environment interference, contradictory evidence. Treated as
    /// FAIL by the release gate for blocker categories.
    Inconclusive,
    /// Required capability is absent on this platform/tier. Requires
    /// probe evidence of the absence (see [`crate::verify_ng::caps`]).
    NotApplicable,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Inconclusive => "INCONCLUSIVE",
            Verdict::NotApplicable => "NOT_APPLICABLE",
        }
    }

    /// Release-gate view: does this verdict alone block promotion?
    /// `NotApplicable` never blocks by itself; the gate additionally enforces
    /// quotas (canary PASS minimum, zero INCONCLUSIVE in blockers) in
    /// [`crate::verify_ng::exit`].
    pub fn blocks_release(self) -> bool {
        match self {
            Verdict::Pass | Verdict::NotApplicable => false,
            Verdict::Fail | Verdict::Inconclusive => true,
        }
    }
}

/// Maximum strength this (scenario, platform, tier) claim can ever reach.
/// Static registry property, never computed at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimStrength {
    /// Kernel-enforced, independently provable via host facts.
    Strong,
    /// Enforced with documented residual risk (see `residual_risk`).
    Partial,
    /// Cannot be proven with current primitives; advisory at best.
    Unsupported,
}

impl ClaimStrength {
    pub fn label(self) -> &'static str {
        match self {
            ClaimStrength::Strong => "STRONG",
            ClaimStrength::Partial => "PARTIAL",
            ClaimStrength::Unsupported => "UNSUPPORTED",
        }
    }
}

/// Blocker categories map to the security invariants I1..I6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// I1 fail-closed spawn.
    Spawn,
    /// I2 filesystem confidentiality.
    FsRead,
    /// I3 filesystem integrity.
    FsWrite,
    /// I4 network egress.
    Net,
    /// I5 process containment.
    Proc,
    /// I6 secret sealing.
    Secrets,
    /// Non-blocker auxiliary checks (resilience, diagnostics).
    Aux,
}

impl Category {
    /// Release-gate blocker categories (I1..I6).
    pub fn is_blocker(self) -> bool {
        !matches!(self, Category::Aux)
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::Spawn => "spawn",
            Category::FsRead => "fs-read",
            Category::FsWrite => "fs-write",
            Category::Net => "net",
            Category::Proc => "proc",
            Category::Secrets => "secrets",
            Category::Aux => "aux",
        }
    }
}

/// Final per-scenario result: verdict + static strength + category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioResult {
    pub id: String,
    pub category: Category,
    pub strength: ClaimStrength,
    pub verdict: Verdict,
    /// Stable evidence summary (already redacted, size-capped).
    pub detail: String,
}

impl ScenarioResult {
    pub fn blocks_release(&self) -> bool {
        self.category.is_blocker() && self.verdict.blocks_release()
    }
}

#[cfg(test)]
mod semantics_tests {
    use super::*;

    /// FM-10: gate matrix over Verdict x Category. Strength never flips the
    /// blocking decision; a PASS on a PARTIAL claim does not become a FAIL,
    /// and an INCONCLUSIVE on a blocker never becomes a PASS.
    #[test]
    fn gate_matrix_verdict_times_category() {
        for verdict in [
            Verdict::Pass,
            Verdict::Fail,
            Verdict::Inconclusive,
            Verdict::NotApplicable,
        ] {
            for category in [
                Category::Spawn,
                Category::FsRead,
                Category::FsWrite,
                Category::Net,
                Category::Proc,
                Category::Secrets,
                Category::Aux,
            ] {
                for strength in [
                    ClaimStrength::Strong,
                    ClaimStrength::Partial,
                    ClaimStrength::Unsupported,
                ] {
                    let r = ScenarioResult {
                        id: "SEMANTICS-001".to_string(),
                        category,
                        strength,
                        verdict,
                        detail: String::new(),
                    };
                    let expected = category.is_blocker() && verdict.blocks_release();
                    assert_eq!(
                        r.blocks_release(),
                        expected,
                        "verdict={:?} category={:?} strength={:?}",
                        verdict,
                        category,
                        strength
                    );
                }
            }
        }
    }

    #[test]
    fn partial_pass_is_still_a_pass_run_of_a_weak_claim() {
        let r = ScenarioResult {
            id: "x".to_string(),
            category: Category::FsRead,
            strength: ClaimStrength::Partial,
            verdict: Verdict::Pass,
            detail: String::new(),
        };
        assert!(!r.blocks_release());
        assert_eq!(r.strength, ClaimStrength::Partial);
    }

    #[test]
    fn inconclusive_on_blocker_blocks() {
        let r = ScenarioResult {
            id: "x".to_string(),
            category: Category::Net,
            strength: ClaimStrength::Strong,
            verdict: Verdict::Inconclusive,
            detail: String::new(),
        };
        assert!(r.blocks_release());
    }
}
