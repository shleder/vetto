//! Adversarial isolation probes: path traversal vs deny rules, secret-proxy
//! stripping, and snapshot-list honesty under concurrent mutation.
//!
//! Hermetic rules (copied from the existing suite): every test builds its own
//! `TempProject` dirs and passes explicit paths (`list_snapshots_in`, direct
//! `Policy` values). No process-global env (`HOME`/`PATH`) or cwd mutation,
//! no shared mutable store, so no `TEST_LOCK` is needed.

use crate::common::*;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn scope_policy(proj: &Path) -> vetto::policy::Policy {
    let secret = proj.join("secret");
    vetto::policy::Policy {
        allow_write: vec![proj.to_path_buf()],
        allow_read: vec![proj.to_path_buf()],
        deny_write: vec![secret.clone()],
        deny_read: vec![secret],
        ..Default::default()
    }
}

fn os_env(pairs: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
    pairs
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect()
}

fn has_key(env: &BTreeMap<OsString, OsString>, key: &str) -> bool {
    env.contains_key(&OsString::from(key))
}

fn write_snapshot_meta(root: &Path, session: &str) {
    let dir = root.join(session);
    std::fs::create_dir_all(&dir).expect("create session dir");
    let meta = vetto::rescue::snapshot::SnapshotMetadata {
        session_id: session.to_string(),
        created_at: "2026-09-06T00:00:00Z".to_string(),
        project_dir: root.to_path_buf(),
        archive_file: dir.join("snapshot.tar"),
        file_count: 1,
        total_size_bytes: 3,
    };
    let text = serde_json::to_string_pretty(&meta).expect("serialize meta");
    std::fs::write(dir.join("metadata.json"), text).expect("write meta");
}

#[test]
fn adv_dotdot_escape_of_allow_root_is_denied() {
    let proj = TempProject::new("adv-dotdot-escape");
    let policy = scope_policy(proj.path());
    // Lexically `/proj/../sibling` starts with `/proj`, but it resolves
    // outside the allow root and must be denied fail-closed.
    let escape = proj.path().join("..").join("adv-escape-sibling");
    assert!(
        !policy.in_write_scope(&escape),
        "dotdot escaped write scope: {}",
        escape.display()
    );
    assert!(
        !policy.in_read_scope(&escape),
        "dotdot escaped read scope: {}",
        escape.display()
    );
    assert!(policy.in_write_scope(&proj.path().join("child.txt")));
    assert!(policy.in_read_scope(&proj.path().join("child.txt")));
}

#[test]
fn adv_dotdot_evasion_of_deny_is_still_denied() {
    let proj = TempProject::new("adv-dotdot-deny");
    let policy = scope_policy(proj.path());
    // `/proj/a/../secret/x.txt` normalizes into the denied subtree; the
    // naive prefix check misses it, the normalized one must deny.
    let probe = proj
        .path()
        .join("a")
        .join("..")
        .join("secret")
        .join("x.txt");
    assert!(
        !policy.in_write_scope(&probe),
        "dotdot evaded write deny: {}",
        probe.display()
    );
    assert!(
        !policy.in_read_scope(&probe),
        "dotdot evaded read deny: {}",
        probe.display()
    );
    let plain = proj.path().join("secret").join("x.txt");
    assert!(!policy.in_write_scope(&plain));
    assert!(!policy.in_read_scope(&plain));
}

#[test]
fn adv_slash_confusables_stay_denied() {
    let proj = TempProject::new("adv-slash");
    let policy = scope_policy(proj.path());
    let secret = proj.path().join("secret");
    let trailing = PathBuf::from(format!("{}/", secret.display()));
    let doubled = PathBuf::from(format!("{}//secret//x.txt", proj.path().display()));
    let dotted = proj.path().join(".").join("secret").join("x.txt");
    for probe in [&trailing, &doubled, &dotted] {
        assert!(
            !policy.in_write_scope(probe),
            "slash confusable escaped write deny: {}",
            probe.display()
        );
        assert!(
            !policy.in_read_scope(probe),
            "slash confusable escaped read deny: {}",
            probe.display()
        );
    }
}

#[cfg(unix)]
#[test]
fn adv_symlink_parent_escape_is_denied() {
    let proj = TempProject::new("adv-symlink");
    let outside = TempProject::new("adv-symlink-outside");
    std::os::unix::fs::symlink(outside.path(), proj.path().join("link"))
        .expect("create escape symlink");
    let mut policy = scope_policy(proj.path());
    policy.deny_write.push(outside.path().to_path_buf());
    policy.deny_read.push(outside.path().to_path_buf());
    // `proj/link/x.txt` reads lexically inside the allow root but resolves
    // to the denied outside tree via the symlinked parent.
    let probe = proj.path().join("link").join("x.txt");
    assert!(
        !policy.in_write_scope(&probe),
        "symlink parent escaped write deny: {}",
        probe.display()
    );
    assert!(
        !policy.in_read_scope(&probe),
        "symlink parent escaped read deny: {}",
        probe.display()
    );
}

// Case-sensitivity of scope checks follows the filesystem: on case-sensitive
// filesystems (Linux) an uppercased variant is a different path and must not
// match; on case-insensitive ones (Windows, default macOS) canonicalization
// resolves it to the same directory, where in-scope is the secure answer.
#[cfg(target_os = "linux")]
#[test]
fn adv_case_variant_is_not_confused() {
    let proj = TempProject::new("adv-case");
    let policy = scope_policy(proj.path());
    let upper = PathBuf::from(proj.path().display().to_string().to_ascii_uppercase());
    if upper != proj.path().to_path_buf() {
        assert!(
            !policy.in_write_scope(&upper),
            "case variant wrongly in write scope: {}",
            upper.display()
        );
        assert!(
            !policy.in_read_scope(&upper),
            "case variant wrongly in read scope: {}",
            upper.display()
        );
    }
}

#[test]
fn adv_proxy_secrets_stripped_but_neighbors_kept() {
    let mut env = os_env(&[
        ("PATH", "/usr/bin"),
        ("PROXIED_ONE", "host-secret"),
        ("PROXIED_ONE_EXTRA", "must-keep"),
    ]);
    vetto::cred_broker::filter_proxy_secrets(&mut env, &["PROXIED_ONE".to_string()]);
    assert!(!has_key(&env, "PROXIED_ONE"), "proxied secret survived");
    assert!(has_key(&env, "PROXIED_ONE_EXTRA"), "neighbor over-stripped");
    assert!(has_key(&env, "PATH"), "unrelated var stripped");
}

#[test]
fn adv_proxy_beats_explicit_passthrough() {
    use std::ffi::OsStr;
    let policy_env = vetto::policy::EnvironmentPolicy {
        pass_through: vec!["SAFE_VAR".to_string(), "PROXIED_TWO".to_string()],
        deny: vec![],
    };
    assert!(policy_env.allows(OsStr::new("PROXIED_TWO")));
    let host = os_env(&[("PROXIED_TWO", "host-secret"), ("SAFE_VAR", "ok")]);
    let mut agent: BTreeMap<OsString, OsString> = host
        .into_iter()
        .filter(|(k, _)| policy_env.allows(k))
        .collect();
    vetto::cred_broker::filter_proxy_secrets(&mut agent, &["PROXIED_TWO".to_string()]);
    assert!(!has_key(&agent, "PROXIED_TWO"), "proxy lost to passthrough");
    assert_eq!(
        agent.get(&OsString::from("SAFE_VAR")),
        Some(&OsString::from("ok"))
    );
}

#[test]
fn adv_proxy_env_extra_merge_must_be_restripped() {
    // Production merges env_extra after the first strip; the second
    // fail-closed strip guarantees a colliding extra never reintroduces one.
    let proxies = vec!["PROXIED_THREE".to_string()];
    let mut env = os_env(&[("PATH", "/usr/bin")]);
    vetto::cred_broker::filter_proxy_secrets(&mut env, &proxies);
    env.insert(OsString::from("PROXIED_THREE"), OsString::from("x"));
    vetto::cred_broker::filter_proxy_secrets(&mut env, &proxies);
    assert!(
        !has_key(&env, "PROXIED_THREE"),
        "colliding extra reintroduced"
    );
    assert!(has_key(&env, "PATH"));
}

#[test]
fn adv_broker_domain_allowlist_fail_closed() {
    use vetto::cred_broker::is_domain_allowed;
    let allow = vec!["api.anthropic.com".to_string(), "openai.com".to_string()];
    assert!(!is_domain_allowed("api.anthropic.com", &[]));
    assert!(!is_domain_allowed("evil.example", &allow));
    assert!(is_domain_allowed("api.anthropic.com", &allow));
    assert!(is_domain_allowed("api.openai.com", &allow));
    assert!(is_domain_allowed("API.ANTHROPIC.COM", &allow));
    assert!(!is_domain_allowed("evilopenai.com", &allow));
    assert!(!is_domain_allowed("openai.com.evil.com", &allow));
}

#[test]
fn adv_snapshot_list_missing_root_is_empty_not_error() {
    let proj = TempProject::new("adv-snap-missing");
    let missing = proj.path().join("no-such-store");
    let listed = vetto::rescue::snapshot::list_snapshots_in(&missing)
        .expect("missing root must list as empty");
    assert!(listed.is_empty());
}

#[test]
fn adv_snapshot_list_skips_partial_and_corrupt() {
    let proj = TempProject::new("adv-snap-partial");
    let root = proj.path();
    write_snapshot_meta(root, "adv-complete");
    let partial = root.join("adv-partial");
    std::fs::create_dir_all(&partial).expect("create partial dir");
    std::fs::write(partial.join("snapshot.tar"), b"half-written").expect("write partial tar");
    let corrupt = root.join("adv-corrupt");
    std::fs::create_dir_all(&corrupt).expect("create corrupt dir");
    std::fs::write(corrupt.join("metadata.json"), "{not-json").expect("write corrupt meta");
    let listed = vetto::rescue::snapshot::list_snapshots_in(root)
        .expect("list must succeed despite partial entries");
    assert_eq!(
        listed.len(),
        1,
        "partial entries must not be listed: {listed:?}"
    );
    assert_eq!(listed[0].session_id, "adv-complete");
}

#[test]
fn adv_snapshot_list_concurrent_with_churn_never_lies() {
    let holder = TempProject::new("adv-snap-churn");
    let root = holder.path();
    write_snapshot_meta(root, "adv-stable-a");
    write_snapshot_meta(root, "adv-stable-b");
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            for i in 0..40u32 {
                let dir = root.join("adv-scratch");
                let _ = std::fs::create_dir_all(&dir);
                if i % 3 == 0 {
                    let _ = std::fs::remove_file(dir.join("metadata.json"));
                } else if i % 3 == 1 {
                    let _ = std::fs::write(dir.join("metadata.json"), "{corrupt");
                } else {
                    write_snapshot_meta(root, "adv-scratch");
                }
            }
        });
        let mut readers = Vec::new();
        for _ in 0..2 {
            readers.push(scope.spawn(|| {
                let mut seen = 0u32;
                for _ in 0..40u32 {
                    let listed = vetto::rescue::snapshot::list_snapshots_in(root)
                        .expect("list must fail loudly, never lie");
                    assert!(listed.iter().any(|m| m.session_id == "adv-stable-a"));
                    assert!(listed.iter().any(|m| m.session_id == "adv-stable-b"));
                    seen += 1;
                }
                seen
            }));
        }
        writer.join().expect("writer panicked");
        let mut total = 0u32;
        for reader in readers {
            total += reader.join().expect("reader panicked");
        }
        assert_eq!(total, 80);
    });
    let final_list = vetto::rescue::snapshot::list_snapshots_in(root).expect("final list");
    assert!(final_list.iter().any(|m| m.session_id == "adv-stable-a"));
    assert!(final_list.iter().any(|m| m.session_id == "adv-stable-b"));
}
