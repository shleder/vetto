//! Integration tests for auto-enabling transparent shims on direct agent invocation (`vetto <agent>`).

use super::common::*;
use std::process::Command;

#[test]
fn test_direct_agent_invocation_auto_enables_shim() {
    #[cfg(target_os = "windows")]
    {
        let doc = doctor_output();
        if !doc.contains("experimental-process-sandbox=yes") {
            eprintln!("SKIP: Windows AppContainer/experimental sandbox backend is unavailable");
            return;
        }
    }

    let project = TempProject::new("cli-auto-enable");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    std::fs::create_dir_all(&home_dir).expect("create test home");

    let bin_dir = proj_dir.join("host_bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_agent = bin_dir.join("claude");
    write_file(
        &mock_agent,
        "#!/bin/sh\necho \"claude agent running under vetto\"\nexit 0\n",
    );
    #[cfg(windows)]
    {
        write_file(
            &bin_dir.join("claude.cmd"),
            "@echo off\r\necho claude agent running under vetto\r\n",
        );
    }
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

    let shim_path = home_dir.join(".vetto").join("shims").join("claude");
    assert!(
        !shim_path.exists(),
        "shim must not exist prior to invocation"
    );

    let out = Command::new(vetto_bin())
        .args(["--tui=none", "--net=off", "claude"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec direct claude");

    assert!(
        out.status.success(),
        "direct agent invocation must succeed: stdout: {} stderr: {}",
        stdout(&out),
        stderr(&out)
    );

    // 1. Verify that the shim was automatically created
    assert!(shim_path.exists(), "shim file must be auto-created");
    let shim_content = std::fs::read_to_string(&shim_path).expect("read shim");
    assert!(shim_content.contains("VETTO_WRAPPED"));

    // 2. Verify that the agent executed under the sandbox
    let text = stdout(&out);
    assert!(
        text.contains("claude agent running under vetto"),
        "agent must execute under sandbox: {}",
        text
    );

    // 3. Subsequent invocation uses already-enabled shim without error
    let out2 = Command::new(vetto_bin())
        .args(["--tui=none", "--net=off", "claude"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec direct claude second time");

    assert!(
        out2.status.success(),
        "subsequent agent invocation must succeed: stdout: {} stderr: {}",
        stdout(&out2),
        stderr(&out2)
    );
    assert!(
        stdout(&out2).contains("claude agent running under vetto"),
        "agent must execute on subsequent run: {}",
        stdout(&out2)
    );
}

#[test]
fn test_codex_policy_allows_auth_json_reading() {
    let project = TempProject::new("codex-auth");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    let codex_dir = home_dir.join(".codex");
    std::fs::create_dir_all(&codex_dir).expect("create .codex dir");

    let auth_json = codex_dir.join("auth.json");
    write_file(
        &auth_json,
        "{\"auth_mode\":\"chatgpt\",\"tokens\":{\"access_token\":\"mock-token-xyz\"}}\n",
    );

    let out = Command::new(vetto_bin())
        .args(["--dry-run", "--agent", "codex", "--", "/bin/true"])
        .current_dir(proj_dir)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto dry-run");

    assert!(out.status.success(), "vetto dry-run must succeed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("profile 'codex'"),
        "must resolve codex profile: {}",
        text
    );
    assert!(
        !text.contains("auth.json"),
        "auth.json must NOT be in deny paths: {}",
        text
    );

    #[cfg(unix)]
    if have_landlock() {
        let read_out = Command::new(vetto_bin())
            .args([
                "--tui=none",
                "--net=off",
                "--agent",
                "codex",
                "--",
                "cat",
                auth_json.to_str().unwrap(),
            ])
            .current_dir(proj_dir)
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .output()
            .expect("exec cat auth.json under vetto");

        assert!(
            read_out.status.success(),
            "cat auth.json must succeed under vetto sandbox: stdout: {} stderr: {}",
            stdout(&read_out),
            stderr(&read_out)
        );
        assert!(
            stdout(&read_out).contains("mock-token-xyz"),
            "auth.json contents must be readable inside vetto sandbox: {}",
            stdout(&read_out)
        );
    }
}
