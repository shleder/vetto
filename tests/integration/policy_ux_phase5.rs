//! Integration tests for Phase 5 Policy UX: `policy explain` and `policy lint`.
//!
//! These tests drive the compiled `vetto` binary as a child process across
//! Linux, macOS, and Windows. They validate canonical sealed security contracts,
//! resource ceilings, platform capability diagnostic reporting, strictest-wins
//! CLI overrides, and strict non-zero exit code invariants.

use crate::common::*;

#[test]
fn test_policy_explain_displays_sealed_contract_and_resources() {
    let proj = TempProject::new("phase5-explain-basic");
    let out = run_vetto_in(proj.path(), &["policy", "explain"]);
    assert!(
        out.status.success(),
        "policy explain must succeed; exit={:?} stderr: {}",
        out.status.code(),
        stderr(&out)
    );
    let text = stdout(&out);

    // 1. Contract section and BLAKE3 digest verification
    assert!(
        text.contains("contract:"),
        "contract section missing: {text}"
    );
    assert!(
        text.contains("contract_digest_blake3:"),
        "contract_digest_blake3 missing: {text}"
    );
    let digest_line = text
        .lines()
        .find(|line| line.contains("contract_digest_blake3:"))
        .expect("contract_digest_blake3 line must be present");
    let digest = digest_line.split(':').nth(1).expect("digest value").trim();
    assert_eq!(
        digest.len(),
        64,
        "contract_digest_blake3 must be 64 hex characters: {digest}"
    );
    assert!(
        digest.chars().all(|c| c.is_ascii_hexdigit()),
        "contract_digest_blake3 must consist only of hex digits: {digest}"
    );

    // 2. Contract version and sealed execution state machine
    assert!(
        text.contains("contract_version:"),
        "contract_version missing: {text}"
    );
    assert!(
        text.contains("ContractSealed"),
        "ContractSealed FSM state missing: {text}"
    );

    // 3. Platform capability matrix
    assert!(text.contains("platform:"), "platform field missing: {text}");
    assert!(
        text.contains("Tier 1") || text.contains("Tier 2") || text.contains("Tier 3"),
        "platform capability matrix must report tier: {text}"
    );

    // 4. Resources section ceilings
    assert!(
        text.contains("Resources:"),
        "Resources section missing: {text}"
    );
    assert!(
        text.contains("CPU:"),
        "CPU resources section missing: {text}"
    );
    assert!(
        text.contains("Memory:"),
        "Memory resources section missing: {text}"
    );
    assert!(
        text.contains("Process:"),
        "Process resources section missing: {text}"
    );
    assert!(
        text.contains("File:"),
        "File resources section missing: {text}"
    );
}

#[test]
fn test_policy_explain_json_schema_contains_contract_and_limits() {
    let proj = TempProject::new("phase5-explain-json");
    let out = run_vetto_in(proj.path(), &["policy", "explain", "--json"]);
    assert!(
        out.status.success(),
        "policy explain --json must succeed; exit={:?} stderr: {}",
        out.status.code(),
        stderr(&out)
    );

    let val: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("policy explain --json must emit valid JSON");

    // 1. Contract object and top-level mirror keys
    let contract = val
        .get("contract")
        .expect("JSON must contain 'contract' object");
    let contract_digest = contract
        .get("contract_digest_blake3")
        .and_then(|v| v.as_str())
        .expect("'contract.contract_digest_blake3' must be a string");
    assert_eq!(
        contract_digest.len(),
        64,
        "contract digest must be 64 characters: {contract_digest}"
    );
    assert!(
        contract_digest.chars().all(|c| c.is_ascii_hexdigit()),
        "contract digest must be hex characters: {contract_digest}"
    );

    let contract_ver = contract
        .get("contract_version")
        .and_then(|v| v.as_u64())
        .expect("'contract.contract_version' must be an integer");
    assert!(contract_ver >= 1, "contract_version must be >= 1");

    let fsm_state = contract
        .get("fsm_state")
        .and_then(|v| v.as_str())
        .expect("'contract.fsm_state' must be a string");
    assert_eq!(fsm_state, "ContractSealed");

    let top_digest = val
        .get("contract_digest_blake3")
        .and_then(|v| v.as_str())
        .expect("top-level 'contract_digest_blake3' must be present");
    assert_eq!(top_digest.len(), 64);
    assert_eq!(top_digest, contract_digest);

    let top_fsm = val
        .get("fsm_state")
        .and_then(|v| v.as_str())
        .expect("top-level 'fsm_state' must be present");
    assert_eq!(top_fsm, "ContractSealed");

    // 2. Platform object
    let platform = val
        .get("platform")
        .expect("JSON must contain 'platform' object");
    assert!(
        platform.get("tier").and_then(|v| v.as_str()).is_some(),
        "platform.tier must be a string"
    );
    assert!(
        platform
            .get("diagnostic")
            .and_then(|v| v.as_str())
            .is_some(),
        "platform.diagnostic must be a string"
    );

    // 3. Resources object with categorized and flat keys
    let resources = val
        .get("resources")
        .expect("JSON must contain 'resources' object");
    assert!(
        resources.get("cpu").and_then(|v| v.as_object()).is_some(),
        "resources.cpu must be an object"
    );
    assert!(
        resources
            .get("memory")
            .and_then(|v| v.as_object())
            .is_some(),
        "resources.memory must be an object"
    );
    assert!(
        resources
            .get("process")
            .and_then(|v| v.as_object())
            .is_some(),
        "resources.process must be an object"
    );
    assert!(
        resources.get("file").and_then(|v| v.as_object()).is_some(),
        "resources.file must be an object"
    );

    assert!(
        resources.get("rlimit_cpu").is_some(),
        "rlimit_cpu must exist"
    );
    assert!(resources.get("cpu_max").is_some(), "cpu_max must exist");
    assert!(resources.get("rlimit_as").is_some(), "rlimit_as must exist");
    assert!(
        resources.get("memory_max").is_some(),
        "memory_max must exist"
    );
    assert!(resources.get("swap_max").is_some(), "swap_max must exist");
    assert!(
        resources.get("rlimit_nproc").is_some(),
        "rlimit_nproc must exist"
    );
    assert!(resources.get("pids_max").is_some(), "pids_max must exist");
    assert!(
        resources.get("open_files").is_some(),
        "open_files must exist"
    );
    assert!(
        resources.get("file_size_bytes").is_some(),
        "file_size_bytes must exist"
    );
}

#[test]
fn test_policy_explain_strictest_wins_cli_merging() {
    let proj = TempProject::new("phase5-explain-strictest");
    let layer_path = proj.path().join("layer.toml");
    write_file(
        &layer_path,
        r#"
[metadata]
name = "explain-strictest"

[limits]
cpu_seconds = 3600
address_space_bytes = 4294967296
processes = 100
"#,
    );

    let layer_str = layer_path.to_str().expect("valid utf8 layer path");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--policy",
            layer_str,
            "policy",
            "explain",
            "--limits",
            "cpu=30,as=2G,procs=10",
            "--json",
        ],
    );
    assert!(
        out.status.success(),
        "policy explain with --limits must succeed; exit={:?} stderr: {}",
        out.status.code(),
        stderr(&out)
    );

    let val: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("valid json output from explain");

    // Strictest wins: 30 < 3600, 2,000,000,000 < 4,294,967,296, 10 < 100
    let cpu_sec = val
        .get("limits")
        .and_then(|l| l.get("cpu_seconds"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            val.get("resources")
                .and_then(|r| r.get("rlimit_cpu"))
                .and_then(|v| v.as_u64())
        })
        .expect("cpu_seconds must be present");
    assert_eq!(cpu_sec, 30, "cpu_seconds must be tightened to 30");

    let as_bytes = val
        .get("limits")
        .and_then(|l| l.get("address_space_bytes"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            val.get("resources")
                .and_then(|r| r.get("rlimit_as"))
                .and_then(|v| v.as_u64())
        })
        .expect("address_space_bytes must be present");
    assert_eq!(
        as_bytes, 2_000_000_000,
        "address_space_bytes must be tightened to 2G decimal (2,000,000,000)"
    );

    let procs = val
        .get("limits")
        .and_then(|l| l.get("processes"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            val.get("resources")
                .and_then(|r| r.get("rlimit_nproc"))
                .and_then(|v| v.as_u64())
        })
        .expect("processes must be present");
    assert_eq!(procs, 10, "processes must be tightened to 10");

    // Verify that a looser CLI limit does NOT weaken a stricter policy limit:
    let strict_layer_path = proj.path().join("strict_layer.toml");
    write_file(
        &strict_layer_path,
        r#"
[metadata]
name = "strict-limit"

[limits]
cpu_seconds = 10
"#,
    );

    let strict_layer_str = strict_layer_path.to_str().expect("valid utf8 path");
    let out2 = run_vetto_in(
        proj.path(),
        &[
            "--policy",
            strict_layer_str,
            "policy",
            "explain",
            "--limits",
            "cpu=30",
            "--json",
        ],
    );
    assert!(
        out2.status.success(),
        "explain with looser CLI limit must succeed; exit={:?} stderr: {}",
        out2.status.code(),
        stderr(&out2)
    );
    let val2: serde_json::Value =
        serde_json::from_str(&stdout(&out2)).expect("valid json output from explain 2");
    let cpu_sec2 = val2
        .get("limits")
        .and_then(|l| l.get("cpu_seconds"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            val2.get("resources")
                .and_then(|r| r.get("rlimit_cpu"))
                .and_then(|v| v.as_u64())
        })
        .expect("cpu_seconds must be present");
    assert_eq!(
        cpu_sec2, 10,
        "stricter policy limit (10) must NOT be weakened by looser CLI limit (30)"
    );
}

#[test]
fn test_policy_lint_catches_invalid_cgroup_spec() {
    let proj = TempProject::new("phase5-lint-bad-cgroup");
    let layer_path = proj.path().join("bad_cgroup.toml");
    write_file(
        &layer_path,
        r#"
[metadata]
name = "bad-cgroup-policy"

[limits.cgroup]
memory_max = "-500M"
"#,
    );

    let layer_str = layer_path.to_str().expect("valid utf8 path");
    let out = run_vetto_in(proj.path(), &["--policy", layer_str, "policy", "lint"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "policy lint with High severity finding must exit 1 (fail-closed); stderr: {}",
        stderr(&out)
    );
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("[high] invalid-cgroup-spec"),
        "output must contain '[high] invalid-cgroup-spec': {text}"
    );
}

#[test]
fn test_policy_lint_catches_network_conflicts() {
    let proj = TempProject::new("phase5-lint-network");

    // Case A: policy with [network] mode = "allowlist", allow = ["*"]
    let layer_path_a = proj.path().join("layer_a.toml");
    write_file(
        &layer_path_a,
        r#"
[metadata]
name = "lint-net-wildcard"

[network]
mode = "allowlist"
allow = ["*"]
"#,
    );
    let layer_str_a = layer_path_a.to_str().expect("valid utf8 path");
    let out_a = run_vetto_in(proj.path(), &["--policy", layer_str_a, "policy", "lint"]);
    assert_eq!(
        out_a.status.code(),
        Some(1),
        "insecure wildcard allowlist must exit 1 (High finding); stderr: {}",
        stderr(&out_a)
    );
    let text_a = format!("{}{}", stdout(&out_a), stderr(&out_a));
    assert!(
        text_a.contains("[high] insecure-allowlist-wildcard"),
        "output must contain '[high] insecure-allowlist-wildcard': {text_a}"
    );

    // Case B: policy with [network] mode = "off", allow = ["example.com"]
    let layer_path_b = proj.path().join("layer_b.toml");
    write_file(
        &layer_path_b,
        r#"
[metadata]
name = "lint-net-off-with-domains"

[network]
mode = "off"
allow = ["example.com"]
"#,
    );
    let layer_str_b = layer_path_b.to_str().expect("valid utf8 path");
    let out_b = run_vetto_in(proj.path(), &["--policy", layer_str_b, "policy", "lint"]);
    assert!(
        out_b.status.success(),
        "warn-only finding without --strict must exit 0; exit={:?} stdout: {} stderr: {}",
        out_b.status.code(),
        stdout(&out_b),
        stderr(&out_b)
    );
    let text_b = format!("{}{}", stdout(&out_b), stderr(&out_b));
    assert!(
        text_b.contains("[warn] network-off-with-domains"),
        "output must contain '[warn] network-off-with-domains': {text_b}"
    );
}

#[test]
fn test_policy_lint_strict_exit_code() {
    let proj = TempProject::new("phase5-lint-strict");

    // Subtest 1: High finding without --strict -> exit code 1
    let layer_high = proj.path().join("layer_high.toml");
    write_file(
        &layer_high,
        r#"
[metadata]
name = "lint-subtest-high"

[network]
mode = "allowlist"
allow = ["*"]
"#,
    );
    let layer_high_str = layer_high.to_str().expect("valid utf8 path");
    let out1 = run_vetto_in(proj.path(), &["--policy", layer_high_str, "policy", "lint"]);
    assert_eq!(
        out1.status.code(),
        Some(1),
        "High finding without --strict must exit 1; stderr: {}",
        stderr(&out1)
    );

    // Subtest 2: Warn finding without --strict -> exit code 0
    let layer_warn = proj.path().join("layer_warn.toml");
    write_file(
        &layer_warn,
        r#"
[metadata]
name = "lint-subtest-warn"

[network]
mode = "off"
allow = ["api.example.com"]
"#,
    );
    let layer_warn_str = layer_warn.to_str().expect("valid utf8 path");
    let out2 = run_vetto_in(proj.path(), &["--policy", layer_warn_str, "policy", "lint"]);
    assert!(
        out2.status.success(),
        "Warn finding without --strict must exit 0; exit={:?} stdout: {} stderr: {}",
        out2.status.code(),
        stdout(&out2),
        stderr(&out2)
    );

    // Subtest 3: Warn finding WITH --strict -> exit code 1
    let out3 = run_vetto_in(
        proj.path(),
        &["--policy", layer_warn_str, "policy", "lint", "--strict"],
    );
    assert_eq!(
        out3.status.code(),
        Some(1),
        "Warn finding with --strict must exit 1; stderr: {}",
        stderr(&out3)
    );

    // Subtest 4: Clean policy WITH --strict -> exit code 0
    ensure_fake_ssh_key();
    let layer_clean = proj.path().join("layer_clean.toml");
    write_file(
        &layer_clean,
        r#"
[metadata]
name = "lint-subtest-clean"

[filesystem]
allow_read = ["$HOME/.ssh"]

[limits]
cpu_seconds = 3600
open_files = 512
processes = 100
"#,
    );
    let layer_clean_str = layer_clean.to_str().expect("valid utf8 path");
    let out4 = run_vetto_in(
        proj.path(),
        &["--policy", layer_clean_str, "policy", "lint", "--strict"],
    );
    assert!(
        out4.status.success(),
        "Clean policy with --strict must exit 0; exit={:?} stderr: {}\nstdout: {}",
        out4.status.code(),
        stderr(&out4),
        stdout(&out4)
    );
}
