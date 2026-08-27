//! Integration tests for Git auto-wrapping via core.hooksPath (Step 16).

use super::common::*;

#[test]
fn test_git_hook_install_and_status_and_uninstall() {
    let project = TempProject::new("git-hooks-lifecycle");
    let proj_dir = project.path();

    // 1. Install local git hooks
    let out = run_vetto_in(proj_dir, &["hook", "install", "--scope", "local", "--git", "--force"]);
    assert!(out.status.success(), "hook install --git failed: {}", stderr(&out));

    let git_hooks_dir = proj_dir.join(".vetto").join("git-hooks");
    assert!(git_hooks_dir.exists(), "git-hooks dir must exist");
    assert!(git_hooks_dir.join("pre-commit").exists(), "pre-commit hook must exist");

    // 2. Status inspection
    let out_status = run_vetto_in(proj_dir, &["hook", "status", "--scope", "local", "--json"]);
    assert!(out_status.status.success(), "hook status failed: {}", stderr(&out_status));
    let json_str = stdout(&out_status);
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("parse status json");
    assert!(val["git_hooks"]["hooks_dir"].as_str().is_some());

    // 3. Uninstall
    let out_un = run_vetto_in(proj_dir, &["hook", "uninstall", "--scope", "local", "--git"]);
    assert!(out_un.status.success(), "hook uninstall --git failed: {}", stderr(&out_un));
}
