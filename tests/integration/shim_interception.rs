//! Integration tests for fast native shim dispatcher and hook lifecycle (Step 14 & 15).

use super::common::*;
use std::process::Command;

#[test]
fn test_hook_install_and_status_and_uninstall() {
    let project = TempProject::new("shim-lifecycle");
    let proj_dir = project.path();

    // 1. Run vetto hook install --scope local
    let out = run_vetto_in(proj_dir, &["hook", "install", "--scope", "local", "--force"]);
    assert!(out.status.success(), "hook install failed: {}", stderr(&out));
    let stdout_str = stdout(&out);
    assert!(stdout_str.contains("vetto hook install: successfully configured environment"));
    assert!(proj_dir.join(".vetto").join("shims").exists());
    assert!(proj_dir.join(".vetto").join("shims").join("sh").exists());

    // 2. Run vetto hook status --scope local --json
    let out_status = run_vetto_in(proj_dir, &["hook", "status", "--scope", "local", "--json"]);
    assert!(out_status.status.success(), "hook status failed: {}", stderr(&out_status));
    let json_str = stdout(&out_status);
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("parse status json");
    assert_eq!(val["scope"], "local");
    assert!(val["shims_count"].as_u64().unwrap_or(0) > 0);

    // 3. Run vetto hook uninstall --scope local
    let out_un = run_vetto_in(proj_dir, &["hook", "uninstall", "--scope", "local"]);
    assert!(out_un.status.success(), "hook uninstall failed: {}", stderr(&out_un));
    assert!(stdout(&out_un).contains("vetto hook uninstall: successfully cleaned environment"));
}

#[test]
fn test_shim_dispatcher_and_recursion_barrier() {
    let project = TempProject::new("shim-dispatch");
    let proj_dir = project.path();

    // 1. Direct dispatch via vetto shim with recursion barrier active
    let out = Command::new(vetto_bin())
        .args(["shim", "sh", "--", "-c", "echo inside_barrier"])
        .current_dir(proj_dir)
        .env("VETTO_SANDBOXED", "1")
        .output()
        .expect("exec shim");

    assert!(out.status.success(), "shim failed: {}", stderr(&out));
    let out_text = stdout(&out);
    assert!(out_text.contains("inside_barrier"));
}
