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

    assert!(
        out.status.success(),
        "vetto dry-run must succeed: {}",
        stderr(&out)
    );
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

#[test]
fn test_claude_policy_allows_credentials_json_reading() {
    let project = TempProject::new("claude-auth");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    let claude_dir = home_dir.join(".claude");
    std::fs::create_dir_all(&claude_dir).expect("create .claude dir");

    let creds_json = claude_dir.join(".credentials.json");
    write_file(
        &creds_json,
        "{\"sessionToken\":\"mock-claude-token-abc\"}\n",
    );

    let claude_json = home_dir.join(".claude.json");
    write_file(&claude_json, "{\"autoUpdaterStatus\":\"disabled\"}\n");

    let out = Command::new(vetto_bin())
        .args(["--dry-run", "--agent", "claude", "--", "/bin/true"])
        .current_dir(proj_dir)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto dry-run");

    assert!(
        out.status.success(),
        "vetto dry-run must succeed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("profile 'claude'"),
        "must resolve claude profile: {}",
        text
    );
    assert!(
        !text.contains(".credentials.json"),
        ".credentials.json must NOT be in deny paths: {}",
        text
    );

    #[cfg(unix)]
    if have_landlock() {
        let read_out = Command::new(vetto_bin())
            .args([
                "--tui=none",
                "--net=off",
                "--agent",
                "claude",
                "--",
                "cat",
                creds_json.to_str().unwrap(),
            ])
            .current_dir(proj_dir)
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .output()
            .expect("exec cat .credentials.json under vetto");

        assert!(
            read_out.status.success(),
            "cat .credentials.json must succeed under vetto sandbox: stdout: {} stderr: {}",
            stdout(&read_out),
            stderr(&read_out)
        );
        assert!(
            stdout(&read_out).contains("mock-claude-token-abc"),
            ".credentials.json contents must be readable inside vetto sandbox: {}",
            stdout(&read_out)
        );
    }
}

#[test]
fn test_aider_policy_allows_conf_reading() {
    let project = TempProject::new("aider-conf");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    std::fs::create_dir_all(&home_dir).expect("create home dir");

    let aider_conf = home_dir.join(".aider.conf.yml");
    write_file(&aider_conf, "model: claude-3-5-sonnet-20241022\n");

    let out = Command::new(vetto_bin())
        .args(["--dry-run", "--agent", "aider", "--", "/bin/true"])
        .current_dir(proj_dir)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto dry-run");

    assert!(
        out.status.success(),
        "vetto dry-run must succeed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("profile 'aider'"),
        "must resolve aider profile: {}",
        text
    );
    assert!(
        !text.contains(".aider.conf.yml"),
        ".aider.conf.yml must NOT be in deny paths: {}",
        text
    );

    #[cfg(unix)]
    if have_landlock() {
        let read_out = Command::new(vetto_bin())
            .args([
                "--tui=none",
                "--net=off",
                "--agent",
                "aider",
                "--",
                "cat",
                aider_conf.to_str().unwrap(),
            ])
            .current_dir(proj_dir)
            .env("HOME", &home_dir)
            .env("USERPROFILE", &home_dir)
            .output()
            .expect("exec cat .aider.conf.yml under vetto");

        assert!(
            read_out.status.success(),
            "cat .aider.conf.yml must succeed under vetto sandbox: stdout: {} stderr: {}",
            stdout(&read_out),
            stderr(&read_out)
        );
        assert!(
            stdout(&read_out).contains("claude-3-5-sonnet-20241022"),
            ".aider.conf.yml contents must be readable inside vetto sandbox: {}",
            stdout(&read_out)
        );
    }
}

#[test]
fn test_doctor_and_enable_detects_path_shadowing() {
    let project = TempProject::new("path-shadow");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    let shims_dir = home_dir.join(".vetto").join("shims");
    std::fs::create_dir_all(&shims_dir).expect("create shims dir");

    let shadow_bin_dir = proj_dir.join("usr_bin");
    std::fs::create_dir_all(&shadow_bin_dir).expect("create usr_bin");
    let mock_claude = shadow_bin_dir.join("claude");
    write_file(&mock_claude, "#!/bin/sh\necho \"real host claude\"\n");
    #[cfg(windows)]
    {
        write_file(
            &shadow_bin_dir.join("claude.cmd"),
            "@echo off\r\necho real host claude\r\n",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_claude).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_claude, perms).unwrap();
    }

    let custom_path = std::env::join_paths([&shadow_bin_dir, &shims_dir]).unwrap();

    let doc_out = Command::new(vetto_bin())
        .args(["doctor", "--check-agent", "claude"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto doctor");

    assert!(
        doc_out.status.success(),
        "doctor must succeed: {}",
        stderr(&doc_out)
    );
    let doc_text = stdout(&doc_out);
    assert!(
        doc_text.contains("shadows the vetto shim at"),
        "doctor output must detect shadowing: {}",
        doc_text
    );
    assert!(
        doc_text.contains("Prepend '~/.vetto/shims' to your PATH"),
        "doctor output must include corrective guidance: {}",
        doc_text
    );

    let enable_out = Command::new(vetto_bin())
        .args(["enable", "claude"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto enable");

    assert!(
        enable_out.status.success(),
        "enable must succeed: {}",
        stderr(&enable_out)
    );
    let enable_text = stdout(&enable_out);
    assert!(
        enable_text.contains("shadows the vetto shim at"),
        "enable output must detect shadowing: {}",
        enable_text
    );
}
