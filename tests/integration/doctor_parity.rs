//! Cross-platform doctor parity and scope honesty tests.
//!
//! Verifies:
//! - 3-tier platform contract output honesty in `vetto doctor`
//! - Linux: Landlock ABI status, user/mount/pid/net namespaces, cgroups v2 controllers, seccomp-bpf, Tier 1 status
//! - macOS: Seatbelt SBPL Shape D status, dyld shared cache restriction report (Issue #62), rlimits not claimed as Verified, Tier 2 status
//! - Windows: AppContainer/LPAC, Job Objects, WFP admin warning (Issue #63), WSL2 recommendation, Tier 3 status
//! - Overlap analysis for deny paths on Windows backend without blanket refusal

use crate::common::*;

#[test]
fn test_doctor_parity_and_tier_honesty() {
    let out = doctor_output();
    assert!(out.contains("vetto v"), "doctor output must include version: {out}");

    #[cfg(target_os = "linux")]
    {
        assert!(out.contains("kernel:"), "Linux doctor missing kernel info: {out}");
        assert!(out.contains("landlock:"), "Linux doctor missing Landlock status: {out}");
        assert!(out.contains("unprivileged userns:"), "Linux doctor missing userns: {out}");
        assert!(out.contains("full namespace stack:"), "Linux doctor missing full namespace stack: {out}");
        assert!(out.contains("namespaces (user/mount/pid/net):"), "Linux doctor missing namespaces breakdown: {out}");
        assert!(out.contains("cgroups v2 controllers:"), "Linux doctor missing cgroups v2 controllers: {out}");
        assert!(out.contains("seccomp filters:"), "Linux doctor missing seccomp filters: {out}");
        assert!(out.contains("chosen tier:"), "Linux doctor missing chosen tier: {out}");
        assert!(out.contains("Tier 1"), "Linux doctor missing Tier 1 platform status: {out}");
    }

    #[cfg(target_os = "macos")]
    {
        assert!(out.contains("sandbox-exec"), "macOS doctor missing seatbelt status: {out}");
        assert!(out.contains("sbpl-read-fragment:"), "macOS doctor missing sbpl-read-fragment status: {out}");
        assert!(out.contains("Shape D"), "macOS doctor missing Shape D AST status: {out}");
        assert!(out.contains("dyld shared cache:"), "macOS doctor missing dyld shared cache restriction notice (#62): {out}");
        assert!(out.contains("resource limits:"), "macOS doctor missing resource limits honesty notice: {out}");
        assert!(out.contains("Tier 2"), "macOS doctor missing Tier 2 platform status: {out}");
    }

    #[cfg(target_os = "windows")]
    {
        assert!(out.contains("windows capabilities:"), "Windows doctor missing capabilities summary: {out}");
        assert!(out.contains("job kill-on-close:"), "Windows doctor missing job kill-on-close: {out}");
        assert!(out.contains("AppContainer API:"), "Windows doctor missing AppContainer API: {out}");
        assert!(out.contains("LPAC API:"), "Windows doctor missing LPAC API: {out}");
        assert!(out.contains("network warning:"), "Windows doctor missing WFP network admin warning (#63): {out}");
        assert!(out.contains("WSL2"), "Windows doctor missing WSL2 recommendation: {out}");
        assert!(out.contains("Tier 3"), "Windows doctor missing Tier 3 platform status: {out}");
    }
}

#[test]
fn test_doctor_probe_parity_no_panic() {
    let proj = TempProject::new("doctor-probe-parity");
    write_file(&proj.path().join(".env"), "SECRET=parity\n");
    let out = run_vetto_in(proj.path(), &["doctor", "--probe"]);
    let text = stdout(&out);

    #[cfg(unix)]
    {
        if have_landlock() {
            assert!(
                text.contains("verified unreachable") || text.contains("no deny paths") || text.contains("probe:"),
                "unexpected doctor --probe unix output: {text}\nstderr: {}",
                stderr(&out)
            );
        }
    }

    #[cfg(target_os = "windows")]
    {
        assert!(
            text.contains("probe: analyzing deny-path overlap") || text.contains("no deny paths"),
            "Windows doctor --probe must perform overlap analysis: {text}\nstderr: {}",
            stderr(&out)
        );
        assert!(
            !text.contains("display-only deny verification is unavailable"),
            "Windows doctor --probe must not produce blanket refusal: {text}"
        );
    }
}

#[test]
fn test_deny_overlap_analysis_logic() {
    use std::path::PathBuf;
    use vetto::policy::{DenyEntry, Policy};

    let mut policy = Policy::default();
    policy.allow_read = vec![PathBuf::from("/workspace/src"), PathBuf::from("/tmp")];
    policy.allow_write = vec![PathBuf::from("/workspace/target")];
    policy.deny_resolved = vec![
        DenyEntry {
            path: PathBuf::from("/workspace/src/secret.key"),
            is_directory: false,
        },
        DenyEntry {
            path: PathBuf::from("/workspace/target/nested/leak.txt"),
            is_directory: false,
        },
        DenyEntry {
            path: PathBuf::from("/home/user/.ssh"),
            is_directory: true,
        },
    ];

    let overlaps = vetto::doctor::probe::analyze_deny_overlap(&policy);
    assert_eq!(overlaps.len(), 3);

    // /workspace/src/secret.key sits inside /workspace/src -> inside_grant = true
    let key_overlap = overlaps.iter().find(|o| o.denied_path.ends_with("secret.key")).unwrap();
    assert!(key_overlap.inside_grant);
    assert_eq!(key_overlap.conflicting_root.as_deref(), Some(std::path::Path::new("/workspace/src")));

    // /workspace/target/nested/leak.txt sits inside /workspace/target -> inside_grant = true
    let leak_overlap = overlaps.iter().find(|o| o.denied_path.ends_with("leak.txt")).unwrap();
    assert!(leak_overlap.inside_grant);
    assert_eq!(leak_overlap.conflicting_root.as_deref(), Some(std::path::Path::new("/workspace/target")));

    // /home/user/.ssh sits outside all grants -> inside_grant = false
    let ssh_overlap = overlaps.iter().find(|o| o.denied_path.ends_with(".ssh")).unwrap();
    assert!(!ssh_overlap.inside_grant);
    assert_eq!(ssh_overlap.conflicting_root, None);
}
