//! Integration tests for Vetto diagnostic preflight verification (`vetto doctor --preflight`).
//!
//! Validates:
//! - Human-readable text report (`vetto doctor --preflight`)
//! - Machine-readable JSON report (`vetto doctor --preflight --json` and `vetto doctor --json`)
//! - Presence and schema conformance of all 5 required keys:
//!   `landlock`, `namespaces`, `cgroups_v2`, `seccomp`, `runtime_paths`
//! - Stage 1 user namespace EPERM classification logic (sysctl vs AppArmor vs container Seccomp)
//! - Stage 2 tmpfs mount and executable path visibility probe
//! - Backward compatibility: default `vetto doctor` maintains legacy output and exit code 0

use std::process::Command;

use crate::common::*;

#[test]
fn test_doctor_preflight_text_output() {
    let output = Command::new(vetto_bin())
        .arg("doctor")
        .arg("--preflight")
        .output()
        .expect("execute vetto doctor --preflight");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout_str.contains("=== Vetto Diagnostic Preflight Report ==="),
        "preflight text output missing header: {stdout_str}\nstderr: {stderr_str}"
    );
    assert!(
        stdout_str.contains("[1/5] Landlock LSM:"),
        "preflight text output missing Landlock section: {stdout_str}"
    );
    assert!(
        stdout_str.contains("[2/5] Linux Namespaces:"),
        "preflight text output missing Namespaces section: {stdout_str}"
    );
    assert!(
        stdout_str.contains("[3/5] Cgroups v2:"),
        "preflight text output missing Cgroups section: {stdout_str}"
    );
    assert!(
        stdout_str.contains("[4/5] Seccomp:"),
        "preflight text output missing Seccomp section: {stdout_str}"
    );
    assert!(
        stdout_str.contains("[5/5] Runtime Paths & Secret Masking:"),
        "preflight text output missing Runtime Paths section: {stdout_str}"
    );
    assert!(
        stdout_str.contains("Verdict:"),
        "preflight text output missing Verdict: {stdout_str}"
    );

    // On standard Linux environments supporting isolation, exit code is 0
    #[cfg(target_os = "linux")]
    if have_landlock() {
        assert_eq!(
            output.status.code(),
            Some(0),
            "expected exit code 0 on supported Linux platform: {stdout_str}"
        );
    }
}

#[test]
fn test_doctor_preflight_json_output_and_all_keys_present() {
    let output = Command::new(vetto_bin())
        .arg("doctor")
        .arg("--preflight")
        .arg("--json")
        .output()
        .expect("execute vetto doctor --preflight --json");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    let v: serde_json::Value = serde_json::from_str(&stdout_str).unwrap_or_else(|e| {
        panic!("failed to parse preflight JSON: {e}\nstdout: {stdout_str}\nstderr: {stderr_str}")
    });

    // 1. Top-level keys: verdict, exit_code, and the 5 diagnostic components
    assert!(v.get("verdict").is_some(), "missing key: verdict");
    assert!(v.get("exit_code").is_some(), "missing key: exit_code");
    assert!(v.get("landlock").is_some(), "missing key: landlock");
    assert!(v.get("namespaces").is_some(), "missing key: namespaces");
    assert!(v.get("cgroups_v2").is_some(), "missing key: cgroups_v2");
    assert!(v.get("seccomp").is_some(), "missing key: seccomp");
    assert!(
        v.get("runtime_paths").is_some(),
        "missing key: runtime_paths"
    );

    // 2. landlock schema validation
    let landlock = v.get("landlock").unwrap();
    assert!(landlock.get("supported").unwrap().is_boolean());
    assert!(landlock.get("max_supported_abi").unwrap().is_number());
    assert!(landlock.get("status").unwrap().is_string());
    assert!(landlock.get("message").unwrap().is_string());
    assert!(landlock.get("feature_hints").unwrap().is_array());

    // 3. namespaces schema validation
    let namespaces = v.get("namespaces").unwrap();
    assert!(namespaces.get("overall_status").unwrap().is_string());

    let stage1 = namespaces.get("stage1_user_namespace").unwrap();
    assert!(stage1.get("supported").unwrap().is_boolean());
    assert!(stage1.get("status").unwrap().is_string());
    assert!(stage1.get("failure_cause").unwrap().is_string());
    assert!(stage1.get("message").unwrap().is_string());

    let stage2 = namespaces.get("stage2_tmpfs_mount").unwrap();
    assert!(stage2.get("supported").unwrap().is_boolean());
    assert!(stage2.get("status").unwrap().is_string());
    assert!(stage2.get("executable_visible").unwrap().is_boolean());
    assert!(stage2.get("message").unwrap().is_string());

    // 4. cgroups_v2 schema validation
    let cgroups = v.get("cgroups_v2").unwrap();
    assert!(cgroups.get("available").unwrap().is_boolean());
    assert!(cgroups.get("controllers").unwrap().is_array());
    assert!(cgroups.get("memory_controller").unwrap().is_boolean());
    assert!(cgroups.get("pids_controller").unwrap().is_boolean());
    assert!(cgroups.get("cgroup_kill").unwrap().is_boolean());
    assert!(cgroups.get("status").unwrap().is_string());
    assert!(cgroups.get("message").unwrap().is_string());

    // 5. seccomp schema validation
    let seccomp = v.get("seccomp").unwrap();
    assert!(seccomp.get("filter_available").unwrap().is_boolean());
    assert!(seccomp.get("notify_available").unwrap().is_boolean());
    assert!(seccomp.get("current_mode").unwrap().is_string());
    assert!(seccomp.get("container_restricted").unwrap().is_boolean());
    assert!(seccomp.get("status").unwrap().is_string());
    assert!(seccomp.get("message").unwrap().is_string());

    // 6. runtime_paths schema validation
    let rp = v.get("runtime_paths").unwrap();
    assert!(rp.get("exe_path").unwrap().is_string());
    assert!(rp.get("exe_parent_dir").unwrap().is_string());
    assert!(rp.get("parent_dir_in_allowances").unwrap().is_boolean());
    assert!(rp.get("is_bundled_runtime").unwrap().is_boolean());
    assert!(rp.get("shims_checked").unwrap().is_number());
    assert!(rp.get("shims_valid").unwrap().is_number());
    assert!(rp.get("secrets_masked").unwrap().is_boolean());
    assert!(rp.get("masked_paths").unwrap().is_array());
    assert!(rp.get("status").unwrap().is_string());
    assert!(rp.get("message").unwrap().is_string());

    let masked_paths: Vec<String> = rp
        .get("masked_paths")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p.as_str().map(String::from))
        .collect();
    assert!(
        masked_paths.iter().any(|p| p.contains(".ssh")),
        "masked_paths must include .ssh"
    );
    assert!(
        masked_paths.iter().any(|p| p.contains(".aws")),
        "masked_paths must include .aws"
    );
    assert!(
        masked_paths.iter().any(|p| p.contains(".env")),
        "masked_paths must include .env"
    );
}

#[test]
fn test_doctor_json_flag_alone_triggers_preflight_json() {
    let output = Command::new(vetto_bin())
        .arg("doctor")
        .arg("--json")
        .output()
        .expect("execute vetto doctor --json");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout_str)
        .unwrap_or_else(|e| panic!("failed to parse doctor --json: {e}\nstdout: {stdout_str}"));

    assert!(v.get("verdict").is_some());
    assert!(v.get("landlock").is_some());
    assert!(v.get("namespaces").is_some());
    assert!(v.get("cgroups_v2").is_some());
    assert!(v.get("seccomp").is_some());
    assert!(v.get("runtime_paths").is_some());
}

#[test]
fn test_stage1_eperm_disambiguation_logic() {
    use vetto::doctor::preflight::classify_userns_eperm;

    // 1. Success case: raw_errno == 0
    let (cause, status, msg) = classify_userns_eperm(0, None, None, None, None, false, "disabled");
    assert_eq!(cause, "none");
    assert_eq!(status, "available");
    assert!(msg.contains("supported"));

    // 2. Sysctl clone disabled: kernel.unprivileged_userns_clone == "0"
    let (cause, status, msg) =
        classify_userns_eperm(1, Some("0"), None, None, None, false, "disabled");
    assert_eq!(cause, "sysctl_disabled");
    assert_eq!(status, "sysctl_disabled");
    assert!(msg.contains("unprivileged_userns_clone=0"));

    // 3. Sysctl max userns disabled: user.max_user_namespaces == "0"
    let (cause, status, msg) =
        classify_userns_eperm(1, Some("1"), Some("0"), None, None, false, "disabled");
    assert_eq!(cause, "sysctl_disabled");
    assert_eq!(status, "sysctl_disabled");
    assert!(msg.contains("max_user_namespaces=0"));

    // 4. AppArmor knob restricted: kernel.apparmor_restrict_unprivileged_userns == "1"
    let (cause, status, msg) = classify_userns_eperm(
        1,
        Some("1"),
        Some("15000"),
        Some("1"),
        None,
        false,
        "disabled",
    );
    assert_eq!(cause, "apparmor_restricted");
    assert_eq!(status, "apparmor_restricted");
    assert!(msg.contains("apparmor_restrict_unprivileged_userns=1"));

    // 5. AppArmor confined profile: profile != "unconfined"
    let (cause, status, msg) = classify_userns_eperm(
        1,
        Some("1"),
        Some("15000"),
        Some("0"),
        Some("docker-default\n"),
        false,
        "disabled",
    );
    assert_eq!(cause, "apparmor_restricted");
    assert_eq!(status, "apparmor_restricted");
    assert!(msg.contains("docker-default"));

    // 6. Container Seccomp containment: is_container = true, seccomp = "filter"
    let (cause, status, msg) = classify_userns_eperm(
        1,
        Some("1"),
        Some("15000"),
        Some("0"),
        Some("unconfined"),
        true,
        "filter",
    );
    assert_eq!(cause, "container_seccomp");
    assert_eq!(status, "container_seccomp");
    assert!(msg.contains("container Seccomp"));

    // 7. Generic fallback EPERM
    let (cause, status, msg) = classify_userns_eperm(
        1,
        Some("1"),
        Some("15000"),
        Some("0"),
        Some("unconfined"),
        false,
        "disabled",
    );
    assert_eq!(cause, "other");
    assert_eq!(status, "permission_denied");
    assert!(msg.contains("returned EPERM (1)"));

    // 8. Non-EPERM errno (e.g. ENOSYS 38)
    let (cause, status, msg) = classify_userns_eperm(38, None, None, None, None, false, "disabled");
    assert_eq!(cause, "other");
    assert_eq!(status, "failed");
    assert!(msg.contains("errno 38"));
}

#[test]
#[cfg(target_os = "linux")]
fn test_stage2_tmpfs_mount_probe_skipped_when_stage1_fails() {
    let stage2 = vetto::doctor::preflight::probe_stage2_tmpfs_mount(false);
    assert!(!stage2.supported);
    assert_eq!(stage2.status, "skipped");
    assert!(!stage2.executable_visible);
    assert!(stage2.message.contains("prerequisite unavailable"));
}

#[test]
fn test_doctor_legacy_parity_retained() {
    let output = Command::new(vetto_bin())
        .arg("doctor")
        .output()
        .expect("execute vetto doctor");

    let stdout_str = String::from_utf8_lossy(&output.stdout);

    // Verify backward compatibility: legacy doctor output structure is preserved
    assert!(
        stdout_str.contains("vetto v"),
        "doctor output must include version: {stdout_str}"
    );
    assert!(
        !stdout_str.contains("=== Vetto Diagnostic Preflight Report ==="),
        "default doctor should not print preflight report header"
    );

    #[cfg(target_os = "linux")]
    {
        assert!(
            stdout_str.contains("kernel:"),
            "Linux doctor missing kernel info: {stdout_str}"
        );
        assert!(
            stdout_str.contains("landlock:"),
            "Linux doctor missing Landlock status: {stdout_str}"
        );
        assert!(
            stdout_str.contains("unprivileged userns:"),
            "Linux doctor missing userns: {stdout_str}"
        );
        assert!(
            stdout_str.contains("full namespace stack:"),
            "Linux doctor missing full namespace stack: {stdout_str}"
        );
        assert!(
            stdout_str.contains("cgroups v2 controllers:"),
            "Linux doctor missing cgroups v2: {stdout_str}"
        );
    }
}
