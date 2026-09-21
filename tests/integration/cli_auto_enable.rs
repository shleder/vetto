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
    let deny_section = text.split("deny paths resolved:").nth(1).unwrap_or("");
    assert!(
        !deny_section.contains(".credentials.json"),
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
    let deny_section = text.split("deny paths resolved:").nth(1).unwrap_or("");
    assert!(
        !deny_section.contains(".aider.conf.yml"),
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

#[test]
fn test_shell_hook_relocated_to_eof_on_repair_eliminates_shadowing() {
    // R1 (v0.3.7): late PATH-mutating installers (nvm, conda, pyenv, asdf)
    // appended after the vetto block shadow `~/.vetto/shims`. Repair — the
    // engine `auto_repair_shell_hooks` (`vetto doctor --fix`) delegates to —
    // must excise the block and re-append it strictly at EOF so the hook runs
    // last and restores shims to PATH index 0.
    use vetto::cli::shell_env::{self, ShellKind, MARKER_END, MARKER_START};

    let project = TempProject::new("hook-eof-relocation");
    let home_dir = project.path().join("home");
    let shims_dir = home_dir.join(".vetto").join("shims");
    std::fs::create_dir_all(&shims_dir).expect("create shims dir");

    // 1. Install the hook, then simulate a late installer appending
    // PATH-mutating lines AFTER the vetto block.
    let bashrc = home_dir.join(".bashrc");
    shell_env::install_shell_hook(ShellKind::Bash, &shims_dir, &home_dir, false)
        .expect("install bash hook");
    let mut shadowed = std::fs::read_to_string(&bashrc).expect("read bashrc");
    assert!(shadowed.contains(MARKER_START));
    shadowed.push_str("export NVM_DIR=\"$HOME/.nvm\"\nexport PATH=\"/mock/nvm/bin:$PATH\"\n");
    write_file(&bashrc, &shadowed);
    // Keep a copy of the shadowed profile for the before/after sourcing check.
    let shadowed_copy = home_dir.join(".bashrc.shadowed");
    write_file(&shadowed_copy, &shadowed);

    // The hook block is now shadowed: installer lines trail the end marker.
    let before = std::fs::read_to_string(&bashrc).expect("read shadowed bashrc");
    let end_idx = before.find(MARKER_END).expect("end marker present");
    assert!(
        before[end_idx + MARKER_END.len()..].contains("/mock/nvm/bin"),
        "late installer lines must trail the hook block before repair"
    );

    // 2. Repair must relocate the block strictly to EOF, preserving content.
    let repaired =
        shell_env::repair_shell_profiles(&shims_dir, &home_dir).expect("repair profiles");
    assert!(
        repaired.contains(&bashrc),
        "repair must touch .bashrc: {repaired:?}"
    );
    let after = std::fs::read_to_string(&bashrc).expect("read repaired bashrc");
    assert!(
        after.contains("/mock/nvm/bin"),
        "late installer lines must be preserved: {after}"
    );
    assert!(
        after.contains("_vetto_clean_path"),
        "indestructible hook must survive repair: {after}"
    );
    assert_eq!(
        after.matches(MARKER_START).count(),
        1,
        "exactly one hook block must remain: {after}"
    );
    let end_idx = after.find(MARKER_END).expect("end marker present");
    assert!(
        after[end_idx + MARKER_END.len()..].trim().is_empty(),
        "hook block must be last (EOF), trailing: {:?}",
        &after[end_idx + MARKER_END.len()..]
    );

    // 3. Sourcing the repaired profile restores shims to PATH index 0,
    // while the shadowed profile leaves the late installer on top.
    #[cfg(unix)]
    {
        let shims_str = shims_dir.to_string_lossy().to_string();
        let dirty = format!("/usr/bin:/bin:{shims_str}");
        let eval_profile = |profile: &std::path::Path| {
            let script = format!(
                "PATH='{dirty}'; source '{}'; echo \"$PATH\"",
                profile.display()
            );
            let out = Command::new("bash")
                .args(["-c", &script])
                .output()
                .expect("run bash");
            assert!(
                out.status.success(),
                "bash source failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let shadowed_path = eval_profile(&shadowed_copy);
        assert!(
            shadowed_path.starts_with("/mock/nvm/bin:"),
            "shadowed profile must leave late installer on top: {shadowed_path}"
        );
        let repaired_path = eval_profile(&bashrc);
        assert!(
            repaired_path.starts_with(&shims_str),
            "repaired profile must restore shims to PATH index 0: {repaired_path}"
        );
    }
}

#[test]
fn test_vetto_run_subcommand_with_flags_and_trailing_args() {
    #[cfg(target_os = "windows")]
    {
        let doc = doctor_output();
        if !doc.contains("experimental-process-sandbox=yes") {
            eprintln!("SKIP: Windows AppContainer/experimental sandbox backend is unavailable");
            return;
        }
    }

    let project = TempProject::new("vetto-run-flags");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    std::fs::create_dir_all(&home_dir).expect("create test home");

    let bin_dir = proj_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_tool = bin_dir.join("myagent");
    write_file(&mock_tool, "#!/bin/sh\necho \"args: $@\"\nexit 0\n");
    #[cfg(windows)]
    {
        write_file(
            &bin_dir.join("myagent.cmd"),
            "@echo off\r\necho args: %*\r\n",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_tool).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_tool, perms).unwrap();
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    // 1. Verify `vetto run myagent -p "fix bug" --verbose --model sonnet` passes flags cleanly
    let out = Command::new(vetto_bin())
        .args([
            "--tui=none",
            "--net=off",
            "run",
            "myagent",
            "-p",
            "fix bug",
            "--verbose",
            "--model",
            "sonnet",
        ])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto run myagent");

    assert!(
        out.status.success(),
        "vetto run with flags must succeed: stdout: {} stderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("fix bug") && text.contains("--verbose") && text.contains("sonnet"),
        "flags and options must pass through to tool: {text}"
    );

    // 2. Verify `vetto run -- myagent -p "fix bug 2"` also works with double dash
    let out2 = Command::new(vetto_bin())
        .args([
            "--tui=none",
            "--net=off",
            "run",
            "--",
            "myagent",
            "-p",
            "fix bug 2",
        ])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto run with double dash");

    assert!(
        out2.status.success(),
        "vetto run with -- must succeed: stdout: {} stderr: {}",
        stdout(&out2),
        stderr(&out2)
    );
    let text2 = stdout(&out2);
    assert!(
        text2.contains("fix bug 2"),
        "arguments must pass through with double dash: {text2}"
    );
}

#[test]
fn test_vetto_run_subcommand_zero_arg_auto_detect() {
    #[cfg(target_os = "windows")]
    {
        let doc = doctor_output();
        if !doc.contains("experimental-process-sandbox=yes") {
            eprintln!("SKIP: Windows AppContainer/experimental sandbox backend is unavailable");
            return;
        }
    }

    let project = TempProject::new("vetto-run-autodetect");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    std::fs::create_dir_all(&home_dir).expect("create test home");

    // Create marker CLAUDE.md
    write_file(&proj_dir.join("CLAUDE.md"), "# Project Guide\n");

    let bin_dir = proj_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_claude = bin_dir.join("claude");
    write_file(
        &mock_claude,
        "#!/bin/sh\necho \"auto-detected claude ran successfully\"\nexit 0\n",
    );
    #[cfg(windows)]
    {
        write_file(
            &bin_dir.join("claude.cmd"),
            "@echo off\r\necho auto-detected claude ran successfully\r\n",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_claude).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_claude, perms).unwrap();
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    let out = Command::new(vetto_bin())
        .args(["--tui=none", "--net=off", "run"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto run zero-arg");

    assert!(
        out.status.success(),
        "vetto run zero-arg must succeed: stdout: {} stderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("auto-detected claude ran successfully"),
        "mock claude must have executed: {text}"
    );
}

#[test]
fn test_vetto_exec_subcommand_alias_with_flags() {
    #[cfg(target_os = "windows")]
    {
        let doc = doctor_output();
        if !doc.contains("experimental-process-sandbox=yes") {
            eprintln!("SKIP: Windows AppContainer/experimental sandbox backend is unavailable");
            return;
        }
    }

    let project = TempProject::new("vetto-exec-flags");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    std::fs::create_dir_all(&home_dir).expect("create test home");

    let bin_dir = proj_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_tool = bin_dir.join("myagent");
    write_file(&mock_tool, "#!/bin/sh\necho \"exec args: $@\"\nexit 0\n");
    #[cfg(windows)]
    {
        write_file(
            &bin_dir.join("myagent.cmd"),
            "@echo off\r\necho exec args: %*\r\n",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_tool).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_tool, perms).unwrap();
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    let out = Command::new(vetto_bin())
        .args([
            "--tui=none",
            "--net=off",
            "exec",
            "myagent",
            "-p",
            "test prompt",
            "--verbose",
        ])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto exec myagent");

    assert!(
        out.status.success(),
        "vetto exec with flags must succeed: stdout: {} stderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("test prompt") && text.contains("--verbose"),
        "flags and options must pass through via vetto exec: {text}"
    );
}

#[test]
fn test_vetto_headless_flag_alias_emits_ci_json() {
    #[cfg(target_os = "windows")]
    {
        let doc = doctor_output();
        if !doc.contains("experimental-process-sandbox=yes") {
            eprintln!("SKIP: Windows AppContainer/experimental sandbox backend is unavailable");
            return;
        }
    }

    let project = TempProject::new("vetto-headless-flags");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    std::fs::create_dir_all(&home_dir).expect("create test home");

    let bin_dir = proj_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_tool = bin_dir.join("myagent");
    write_file(&mock_tool, "#!/bin/sh\necho \"agent ran\"\nexit 0\n");
    #[cfg(windows)]
    {
        write_file(
            &bin_dir.join("myagent.cmd"),
            "@echo off\r\necho agent ran\r\n",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_tool).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_tool, perms).unwrap();
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    let out_headless = Command::new(vetto_bin())
        .args(["--headless", "--net=off", "exec", "myagent"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto --headless");

    assert!(
        out_headless.status.success(),
        "--headless run must succeed: stdout: {} stderr: {}",
        stdout(&out_headless),
        stderr(&out_headless)
    );
    let text_headless = stdout(&out_headless);
    assert!(
        text_headless.contains("\"vetto_ci\""),
        "--headless must emit JSON report on stdout: {text_headless}"
    );

    let out_non_interactive = Command::new(vetto_bin())
        .args(["--non-interactive", "--net=off", "exec", "myagent"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto --non-interactive");

    assert!(
        out_non_interactive.status.success(),
        "--non-interactive run must succeed: stdout: {} stderr: {}",
        stdout(&out_non_interactive),
        stderr(&out_non_interactive)
    );
    let text_non_interactive = stdout(&out_non_interactive);
    assert!(
        text_non_interactive.contains("\"vetto_ci\""),
        "--non-interactive must emit JSON report on stdout: {text_non_interactive}"
    );
}

#[test]
fn test_vetto_ci_env_defaults_to_no_tui() {
    #[cfg(target_os = "windows")]
    {
        let doc = doctor_output();
        if !doc.contains("experimental-process-sandbox=yes") {
            eprintln!("SKIP: Windows AppContainer/experimental sandbox backend is unavailable");
            return;
        }
    }

    let project = TempProject::new("vetto-ci-env");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    std::fs::create_dir_all(&home_dir).expect("create test home");

    let bin_dir = proj_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_tool = bin_dir.join("myagent");
    write_file(
        &mock_tool,
        "#!/bin/sh\necho \"running in automated CI\"\nexit 0\n",
    );
    #[cfg(windows)]
    {
        write_file(
            &bin_dir.join("myagent.cmd"),
            "@echo off\r\necho running in automated CI\r\n",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_tool).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_tool, perms).unwrap();
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    let out = Command::new(vetto_bin())
        .args(["--net=off", "exec", "myagent"])
        .current_dir(proj_dir)
        .env("CI", "true")
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto under CI=true");

    assert!(
        out.status.success(),
        "vetto run under CI=true must succeed: stdout: {} stderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("running in automated CI"),
        "command output must be present: {text}"
    );
}

#[test]
fn test_vetto_explicit_agent_flag_resolves_and_dry_runs() {
    let project = TempProject::new("vetto-explicit-agent");
    let proj_dir = project.path();

    let home_dir = proj_dir.join("home");
    std::fs::create_dir_all(&home_dir).expect("create test home");

    let bin_dir = proj_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let mock_codex = bin_dir.join("codex");
    write_file(
        &mock_codex,
        "#!/bin/sh\necho \"codex v1.0.0\"\nexit 0\n",
    );
    #[cfg(windows)]
    {
        write_file(
            &bin_dir.join("codex.cmd"),
            "@echo off\r\necho codex v1.0.0\r\n",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mock_codex).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_codex, perms).unwrap();
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = std::env::split_paths(&original_path).collect::<Vec<_>>();
    paths.insert(0, bin_dir.clone());
    let custom_path = std::env::join_paths(paths).unwrap();

    // 1. vetto --agent codex --dry-run
    let out = Command::new(vetto_bin())
        .args(["--dry-run", "--agent", "codex"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto --agent codex --dry-run");

    assert!(
        out.status.success(),
        "vetto --agent codex --dry-run must succeed: stdout: {} stderr: {}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("profile 'codex'"), "must resolve codex profile: {text}");

    // 2. vetto -a codex --dry-run (short flag)
    let out_short = Command::new(vetto_bin())
        .args(["--dry-run", "-a", "codex"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto -a codex --dry-run");

    assert!(
        out_short.status.success(),
        "vetto -a codex --dry-run must succeed: stdout: {} stderr: {}",
        stdout(&out_short),
        stderr(&out_short)
    );
    let text_short = stdout(&out_short);
    assert!(
        text_short.contains("profile 'codex'"),
        "must resolve codex profile via short flag: {text_short}"
    );

    // 3. vetto run -a codex --dry-run
    let out_run = Command::new(vetto_bin())
        .args(["run", "--dry-run", "-a", "codex"])
        .current_dir(proj_dir)
        .env("PATH", &custom_path)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .output()
        .expect("exec vetto run -a codex --dry-run");

    assert!(
        out_run.status.success(),
        "vetto run -a codex --dry-run must succeed: stdout: {} stderr: {}",
        stdout(&out_run),
        stderr(&out_run)
    );
}

#[test]
fn test_vetto_explicit_agent_not_found_returns_clean_guidance() {
    let project = TempProject::new("vetto-explicit-agent-missing");
    let proj_dir = project.path();

    // Empty PATH ensures the agent binary is not found
    let out = Command::new(vetto_bin())
        .args(["--agent", "codex"])
        .current_dir(proj_dir)
        .env("PATH", "")
        .output()
        .expect("exec vetto --agent codex with empty PATH");

    assert!(
        !out.status.success(),
        "vetto with missing agent binary must fail"
    );
    let err_text = stderr(&out);
    assert!(
        err_text.contains("agent binary for 'codex' was not found in PATH"),
        "must explain agent binary was not found: {err_text}"
    );
    assert!(
        err_text.contains("Supported agents:"),
        "must list supported agents: {err_text}"
    );
}

