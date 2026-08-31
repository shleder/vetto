//! Integration tests for `vetto enable` and `vetto disable` lifecycle.

use super::common::*;
use std::process::Command;

#[test]
fn test_enable_list_without_arguments() {
    let project = TempProject::new("enable-list");
    let out = run_vetto_in(project.path(), &["enable"]);
    assert!(
        out.status.success(),
        "vetto enable must succeed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("AI Coding Agents (vetto enable):"));
    assert!(text.contains("claude"));
    assert!(text.contains("codex"));
    assert!(text.contains("vetto enable <agent>"));
}

#[test]
fn test_enable_status_command() {
    let project = TempProject::new("enable-status");
    let out = run_vetto_in(project.path(), &["enable", "--status", "--scope", "local"]);
    assert!(
        out.status.success(),
        "vetto enable --status must succeed: {}",
        stderr(&out)
    );
}

#[test]
fn test_enable_and_disable_lifecycle() {
    let project = TempProject::new("enable-lifecycle");
    let proj_dir = project.path();

    // 1. Create a mock agent in a custom PATH directory
    let bin_dir = proj_dir.join("host_bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_agent = bin_dir.join("claude");
    write_file(&mock_agent, "#!/bin/sh\necho \"claude agent running\"\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_agent).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_agent, perms).unwrap();
    }

    // Set PATH to include bin_dir
    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    // 2. Run vetto enable claude --scope local
    let out = Command::new(vetto_bin())
        .args(["enable", "claude", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable");

    assert!(
        out.status.success(),
        "vetto enable claude failed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("successfully enabled sandbox wrapper for 'claude'"));

    let shim_path = proj_dir.join(".vetto").join("shims").join("claude");
    assert!(shim_path.exists(), "shim file must exist");
    let shim_content = std::fs::read_to_string(&shim_path).expect("read shim");
    assert!(shim_content.contains("VETTO_WRAPPED"));
    assert!(shim_content.contains("VETTO_SANDBOXED"));

    // 3. Status should show claude wrapped
    let out_st = Command::new(vetto_bin())
        .args(["enable", "--status", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable status");

    assert!(out_st.status.success());
    assert!(stdout(&out_st).contains("claude"));

    // 4. Run vetto disable claude --scope local
    let out_dis = Command::new(vetto_bin())
        .args(["disable", "claude", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec disable");

    assert!(
        out_dis.status.success(),
        "disable failed: {}",
        stderr(&out_dis)
    );
    assert!(stdout(&out_dis).contains("disabled sandbox wrapper for 'claude'"));
    assert!(!shim_path.exists(), "shim file must be removed");
    assert!(
        mock_agent.exists(),
        "real host binary must remain untouched"
    );
}

#[test]
fn test_enable_collision_protection() {
    let project = TempProject::new("enable-collision");
    let proj_dir = project.path();

    // 1. Create a mock agent in host_bin
    let bin_dir = proj_dir.join("host_bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_agent = bin_dir.join("codex");
    write_file(&mock_agent, "#!/bin/sh\necho \"codex host\"\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_agent).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_agent, perms).unwrap();
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    // 2. Pre-create a non-vetto file at the shim location
    let shims_dir = proj_dir.join(".vetto").join("shims");
    std::fs::create_dir_all(&shims_dir).expect("create shims dir");
    let collision_file = shims_dir.join("codex");
    write_file(&collision_file, "custom non-vetto binary content\n");

    // 3. Attempt enable without --force -> should fail
    let out_fail = Command::new(vetto_bin())
        .args(["enable", "codex", "--scope", "local"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable");

    assert!(
        !out_fail.status.success(),
        "enable without --force must fail on collision"
    );
    assert!(stderr(&out_fail).contains("not a Vetto shim"));

    // 4. Attempt enable with --force -> should succeed
    let out_force = Command::new(vetto_bin())
        .args(["enable", "codex", "--scope", "local", "--force"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", test_home())
        .output()
        .expect("exec enable force");

    assert!(
        out_force.status.success(),
        "enable with --force must succeed: {}",
        stderr(&out_force)
    );
    let content = std::fs::read_to_string(&collision_file).expect("read overwritten shim");
    assert!(content.contains("Vetto transparent binary shim"));
}
