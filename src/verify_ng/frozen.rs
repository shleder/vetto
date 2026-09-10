//! FrozenSpec: what was verified is what was launched (FM-03).
//!
//! Binding rules:
//! - Exactly one `Backend::detect` per scenario run; the detected tier is
//!   compared against the expected tier before spawn.
//! - The spec hash is computed once, in the same single-threaded section,
//!   from the same `&Policy` reference handed to `Backend::spawn`.
//! - Serialization is canonical: sorted paths, normalized strings, explicit
//!   tier/net/backend/argv/env/cwd. `Policy::deny_network` is intent-only;
//!   the effective [`crate::config::NetMode`] is hashed separately and
//!   explicitly.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical, hashable snapshot of everything that defines a scenario run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenSpec {
    pub scenario_id: String,
    pub registry_hash: String,
    pub tier: String,
    pub net_mode: String,
    pub backend: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub deny_read: Vec<String>,
    pub deny_write: Vec<String>,
    pub deny_resolved: Vec<String>,
    /// Session nonce binding the positive control to the negative proof.
    pub nonce: String,
    /// Canonical policy bytes: deterministic rendering of the full `Policy`
    /// (not just the decomposed path lists above). Same policy content
    /// always yields the same bytes regardless of in-memory ordering
    /// (`HashMap` iteration, unsorted vectors); any enforcement-relevant
    /// mutation changes them, and therefore the spec hash.
    pub policy_bytes: Vec<u8>,
}

impl FrozenSpec {
    /// Canonical bytes: JSON with sorted keys over normalized strings.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // BTreeMap + sorted Vecs + explicit fields make serde_json output
        // deterministic for a fixed struct layout.
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hex_encode(&hasher.finalize())
    }
}

/// Build the canonical spec from a resolved policy plus the effective
/// launch context. Callers must pass the same `policy` reference onward
/// to `Backend::spawn` (FM-03 continuity rule).
#[allow(clippy::too_many_arguments)]
pub fn freeze_spec(
    scenario_id: &str,
    registry_hash: &str,
    policy: &crate::policy::Policy,
    tier: &str,
    net_mode: &crate::config::NetMode,
    backend_describe: &str,
    argv: &[String],
    env: &BTreeMap<String, String>,
    cwd: &std::path::Path,
    nonce: &str,
) -> FrozenSpec {
    fn sorted(paths: &[PathBuf]) -> Vec<String> {
        let mut out: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        out.sort();
        out
    }
    let mut deny_resolved: Vec<String> = policy
        .deny_resolved
        .iter()
        .map(|e| e.path.display().to_string())
        .collect();
    deny_resolved.sort();
    FrozenSpec {
        scenario_id: scenario_id.to_string(),
        registry_hash: registry_hash.to_string(),
        tier: tier.to_string(),
        net_mode: net_mode.label(),
        backend: backend_describe.to_string(),
        argv: argv.to_vec(),
        env: env.clone(),
        cwd: cwd.to_path_buf(),
        allow_read: sorted(&policy.allow_read),
        allow_write: sorted(&policy.allow_write),
        deny_read: sorted(&policy.deny_read),
        deny_write: sorted(&policy.deny_write),
        deny_resolved,
        nonce: nonce.to_string(),
        policy_bytes: canonical_policy_bytes(policy),
    }
}

/// Canonical rendering of the full `Policy` into deterministic bytes.
///
/// `Policy` is not `Serialize` and holds order-unstable collections
/// (`net_quota: HashMap`, insertion-ordered vectors), so a plain debug dump
/// would hash-equal identical policies differently across runs. This builder
/// sorts every collection and emits fields in a fixed order with an explicit
/// version tag; any enforcement-relevant change flips the bytes (and the
/// [`FrozenSpec`] hash), any pure reordering does not.
pub fn canonical_policy_bytes(policy: &crate::policy::Policy) -> Vec<u8> {
    fn paths(ps: &[std::path::PathBuf]) -> String {
        let mut v: Vec<String> = ps.iter().map(|p| p.display().to_string()).collect();
        v.sort();
        format!("[{}]", v.join(","))
    }
    fn strs(ss: &[String]) -> String {
        let mut v = ss.to_vec();
        v.sort();
        format!("[{}]", v.join(","))
    }
    fn opt(o: &Option<String>) -> &str {
        o.as_deref().unwrap_or("-")
    }
    fn opt_u(o: &Option<u64>) -> String {
        o.map(|n| n.to_string()).unwrap_or_else(|| "-".to_string())
    }
    let mut quota: Vec<(&String, &u64)> = policy.net_quota.iter().collect();
    quota.sort();
    let quota_s = quota
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut ports_b = policy.net_bind_ports.clone();
    ports_b.sort_unstable();
    let mut ports_c = policy.net_connect_ports.clone();
    ports_c.sort_unstable();
    let num_list = |ps: &[u16]| {
        ps.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    let deny_resolved: Vec<String> = {
        let mut v: Vec<String> = policy
            .deny_resolved
            .iter()
            .map(|e| format!("{}:{}", e.path.display(), e.is_dir))
            .collect();
        v.sort();
        v
    };
    let lim = &policy.limits;
    let io_rate = lim
        .io_rate
        .as_ref()
        .map(|r| format!("iops={}bw={}", opt_u(&r.max_iops), opt_u(&r.max_bandwidth)));
    let sec_notify = policy.seccomp_notify.as_ref().map(|n| {
        format!(
            "enabled={}default={}allow=[{}]",
            n.enabled,
            opt(&n.default_action),
            {
                let mut v = n.allow_syscalls.clone();
                v.sort();
                v.join(",")
            }
        )
    });
    let cgroup = policy.cgroup.as_ref().map(|c| {
        format!(
            "mem={}pids={}swap={}cpu={}",
            opt(&c.memory_max),
            opt(&c.pids_max),
            opt(&c.swap_max),
            opt(&c.cpu_max)
        )
    });
    let meta = &policy.metadata;
    let mut extends = meta.extends.clone();
    extends.sort();
    let mut out = String::new();
    out.push_str("vng-policy-v1;");
    out.push_str(&format!("name={};", policy.name));
    out.push_str(&format!(
        "meta=name={}|desc={}|extends=[{}]|source={}|immutable={};",
        meta.name,
        meta.description,
        extends.join(","),
        meta.source_kind.map(|k| k.label()).unwrap_or("-"),
        meta.immutable
    ));
    out.push_str(&format!(
        "limits=cpu={}|as={}|procs={}|files={}|fsize={}|io={};",
        opt_u(&lim.cpu_seconds),
        opt_u(&lim.address_space_bytes),
        opt_u(&lim.processes),
        opt_u(&lim.open_files),
        opt_u(&lim.file_size_bytes),
        io_rate.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!(
        "fs=allow_w={}|allow_r={}|deny_w={}|deny_r={}|resolved=[{}];",
        paths(&policy.allow_write),
        paths(&policy.allow_read),
        paths(&policy.deny_write),
        paths(&policy.deny_read),
        deny_resolved.join(",")
    ));
    {
        let mut pass = policy.environment.pass_through.clone();
        pass.sort();
        let mut deny = policy.environment.deny.clone();
        deny.sort();
        out.push_str(&format!(
            "env=pass=[{}]|deny=[{}];",
            pass.join(","),
            deny.join(",")
        ));
    }
    out.push_str(&format!(
        "net=deny_net={}|cidr=[{}]|quota=[{}]|bind=[{}]|conn=[{}]|unix=[{}];",
        policy.deny_network,
        {
            let mut v = policy.allow_cidr.clone();
            v.sort();
            v.join(",")
        },
        quota_s,
        num_list(&ports_b),
        num_list(&ports_c),
        {
            let mut v = policy.allow_unix_sockets.clone();
            v.sort();
            v.join(",")
        }
    ));
    out.push_str(&format!(
        "harden=seccomp={}|notify={}|cgroup={}|cpu_max={}|io_prio={}|dev=[{}];",
        policy.seccomp_profile.label(),
        sec_notify.as_deref().unwrap_or("-"),
        cgroup.as_deref().unwrap_or("-"),
        opt(&policy.cpu_max),
        opt(&policy.io_priority),
        {
            let mut v = policy.dev_allow.clone().unwrap_or_default();
            v.sort();
            v.join(",")
        }
    ));
    out.push_str(&format!(
        "misc=oslog={}|lpac={}|immutable={}|syslog={}|autodeny={}|proxies=[{}]|ro=[{}]|git={}|snap={}|tmpfs={}|warn=[{}];",
        policy.oslog,
        policy.lpac,
        policy.is_immutable,
        policy.system_log,
        policy.auto_deny_secrets,
        strs(&policy.secret_proxies),
        paths(&policy.ro_mounts),
        policy.git_guard,
        policy.snapshot,
        policy.tmpfs_tmp,
        strs(&policy.warnings)
    ));
    out.into_bytes()
}

/// Minimal hex encoding (no new dependency; mirrors
/// `sandbox::linux::debug_guard`).
pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod frozen_tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_order_independent() {
        let mk = |writes: Vec<PathBuf>| FrozenSpec {
            scenario_id: "s".to_string(),
            registry_hash: "r".to_string(),
            tier: "full".to_string(),
            net_mode: "off".to_string(),
            backend: "b".to_string(),
            argv: vec!["a".to_string()],
            env: BTreeMap::new(),
            cwd: PathBuf::from("/tmp"),
            allow_read: vec![],
            allow_write: writes.iter().map(|p| p.display().to_string()).collect(),
            deny_read: vec![],
            deny_write: vec![],
            deny_resolved: vec![],
            nonce: "n".to_string(),
            policy_bytes: b"p".to_vec(),
        };
        let a = mk(vec![PathBuf::from("/b"), PathBuf::from("/a")]);
        let mut b = mk(vec![PathBuf::from("/a"), PathBuf::from("/b")]);
        b.allow_write.sort();
        // freeze_spec sorts; simulate by sorting both.
        let mut a_sorted = a.clone();
        a_sorted.allow_write.sort();
        assert_eq!(a_sorted.hash(), b.hash());
        let mut c = b.clone();
        c.nonce = "other".to_string();
        assert_ne!(b.hash(), c.hash());
    }

    #[test]
    fn net_mode_label_distinguishes_relay() {
        let off = crate::config::NetMode::Off.label();
        let allow = crate::config::NetMode::Allowlist(vec!["example.com".to_string()]).label();
        assert_ne!(off, allow);
    }

    #[test]
    fn policy_bytes_stable_under_reordering() {
        let mut a = crate::policy::Policy {
            allow_read: vec![PathBuf::from("/b"), PathBuf::from("/a")],
            ..Default::default()
        };
        a.net_quota.insert("x.example".to_string(), 10);
        a.net_quota.insert("a.example".to_string(), 5);
        let mut b = crate::policy::Policy {
            allow_read: vec![PathBuf::from("/a"), PathBuf::from("/b")],
            ..Default::default()
        };
        b.net_quota.insert("a.example".to_string(), 5);
        b.net_quota.insert("x.example".to_string(), 10);
        assert_eq!(canonical_policy_bytes(&a), canonical_policy_bytes(&b));
    }

    #[test]
    fn policy_bytes_flip_on_enforcement_change() {
        let a = crate::policy::Policy::default();
        let b = crate::policy::Policy {
            deny_network: true,
            ..Default::default()
        };
        assert_ne!(canonical_policy_bytes(&a), canonical_policy_bytes(&b));
        let c = crate::policy::Policy {
            allow_write: vec![PathBuf::from("/tmp/evil")],
            ..Default::default()
        };
        assert_ne!(canonical_policy_bytes(&a), canonical_policy_bytes(&c));
    }
}
