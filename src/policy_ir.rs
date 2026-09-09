//! Policy IR: requested → compile → validate → execute pipeline (P2 slice).
//!
//! The IR is a normalized, lint-checked form of a policy request. `compile`
//! normalizes and enforces fail-closed lint rules (root-read/root-write);
//! `validate` checks structural coherence (every write root must sit under a
//! read root). Enforcement itself stays in the sandbox backends — this module
//! only produces a checked plan, never executes it.

/// Security level of a requested policy. Orthogonal to enforcement tier:
/// the level describes how much the policy *asks for*, the tier describes
/// how strongly the platform can *confine* it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Least privilege: narrow reads, no writes outside reads.
    Strict,
    /// Default working set: project reads, scoped writes.
    Standard,
    /// Explicitly broad: may request filesystem-root reads. Never default.
    Permissive,
}

impl SecurityLevel {
    pub fn label(self) -> &'static str {
        match self {
            SecurityLevel::Strict => "STRICT",
            SecurityLevel::Standard => "STANDARD",
            SecurityLevel::Permissive => "PERMISSIVE",
        }
    }
}

/// Raw policy request, before normalization.
#[derive(Debug, Clone)]
pub struct RequestedPolicy {
    pub level: SecurityLevel,
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
}

/// Normalized, lint-checked policy plan. Invariants: lists are sorted,
/// deduplicated, free of empties; root-write is absent; root-read implies
/// [`SecurityLevel::Permissive`]; every write root is under a read root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub level: SecurityLevel,
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
}

/// Normalize + lint a request. Fails closed on root escalation:
/// `/` in `allow_write` is rejected at any level; `/` in `allow_read`
/// requires [`SecurityLevel::Permissive`].
pub fn compile(req: &RequestedPolicy) -> Result<CompiledPolicy, String> {
    let allow_read = normalize(&req.allow_read);
    let allow_write = normalize(&req.allow_write);
    if allow_write.iter().any(|p| p == "/") {
        return Err("policy_ir: allow_write contains filesystem root \"/\"".to_string());
    }
    if req.level != SecurityLevel::Permissive && allow_read.iter().any(|p| p == "/") {
        return Err(
            "policy_ir: allow_read contains filesystem root \"/\" without PERMISSIVE level"
                .to_string(),
        );
    }
    let compiled = CompiledPolicy {
        level: req.level,
        allow_read,
        allow_write,
    };
    validate(&compiled)?;
    Ok(compiled)
}

/// Structural check: every write root must sit under (or equal) a read root.
/// A request with writes but no reads can never validate.
pub fn validate(c: &CompiledPolicy) -> Result<(), String> {
    for w in &c.allow_write {
        let covered = c.allow_read.iter().any(|r| under(w, r));
        if !covered {
            return Err(format!(
                "policy_ir: allow_write '{w}' is not under any allow_read root"
            ));
        }
    }
    Ok(())
}

fn normalize(paths: &[String]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    for p in paths {
        let t = p.trim();
        if t.is_empty() {
            continue;
        }
        let t = t.trim_end_matches('/').to_string();
        let t = if t.is_empty() { "/".to_string() } else { t };
        seen.insert(t);
    }
    seen.into_iter().collect()
}

fn under(path: &str, root: &str) -> bool {
    if root == "/" {
        return path.starts_with('/');
    }
    path == root || path.starts_with(&format!("{root}/"))
}

#[cfg(test)]
mod policy_ir_tests {
    use super::*;

    fn req(level: SecurityLevel, r: &[&str], w: &[&str]) -> RequestedPolicy {
        RequestedPolicy {
            level,
            allow_read: r.iter().map(|s| s.to_string()).collect(),
            allow_write: w.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn happy_path_compiles_and_validates() {
        let c = compile(&req(
            SecurityLevel::Standard,
            &["/proj", "/tmp/"],
            &["/proj/out"],
        ))
        .unwrap();
        assert_eq!(c.level, SecurityLevel::Standard);
        assert_eq!(c.allow_read, vec!["/proj".to_string(), "/tmp".to_string()]);
        assert_eq!(c.allow_write, vec!["/proj/out".to_string()]);
        assert!(validate(&c).is_ok());
    }

    #[test]
    fn root_read_requires_permissive() {
        assert!(compile(&req(SecurityLevel::Standard, &["/"], &[])).is_err());
        assert!(compile(&req(SecurityLevel::Strict, &["/"], &[])).is_err());
        assert!(compile(&req(SecurityLevel::Permissive, &["/"], &[])).is_ok());
    }

    #[test]
    fn root_write_rejected_at_any_level() {
        assert!(compile(&req(SecurityLevel::Permissive, &["/"], &["/"])).is_err());
    }

    #[test]
    fn write_outside_read_fails_closed() {
        assert!(compile(&req(SecurityLevel::Standard, &["/proj"], &["/etc/x"])).is_err());
        // Prefix confusion is not coverage: /proj2 is not under /proj.
        assert!(compile(&req(SecurityLevel::Standard, &["/proj"], &["/proj2/o"])).is_err());
    }

    #[test]
    fn normalize_dedups_and_cleans() {
        let c = compile(&req(
            SecurityLevel::Standard,
            &["/b/", "/a", "/b", " "],
            &[],
        ))
        .unwrap();
        assert_eq!(c.allow_read, vec!["/a".to_string(), "/b".to_string()]);
    }
}
