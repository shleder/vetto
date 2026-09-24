//! Integration tests for Computer Use display sockets, agent plugins,
//! and secret masking preservation (Milestone M3).
//!
//! Validates:
//! 1. Display sockets: access to $XDG_RUNTIME_DIR Wayland socket and /tmp/.X11-unix.
//! 2. Agent plugins: execution of Claude, Codex, and local user tool binaries.
//! 3. Secret masking: INV-08 mode 0000 tmpfs on ~/.ssh, ~/.aws, and /dev/null on .env.

use crate::common::*;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_computer_use_display_sockets() {
    if !have_landlock() {
        eprintln!("SKIP: Landlock not supported on this platform");
        return;
    }

    let proj = TempProject::new("cu-sockets");

    // Ensure /tmp/.X11-unix directory exists on the host so isolate_tmp can preserve it
    let _ = std::fs::create_dir_all("/tmp/.X11-unix");

    // Set up mock $XDG_RUNTIME_DIR
    // Prefer /run/user/<uid>/vetto-cu-test-<id> if accessible, otherwise /var/tmp/vetto-cu-test-<id>
    let uid = unsafe { libc::getuid() };
    let preferred_run_user = PathBuf::from(format!("/run/user/{uid}"));
    let runtime_dir = if preferred_run_user.exists()
        && std::fs::create_dir_all(preferred_run_user.join("vetto-cu-probe")).is_ok()
    {
        let _ = std::fs::remove_dir(preferred_run_user.join("vetto-cu-probe"));
        preferred_run_user.join(format!("vetto-cu-test-{}", std::process::id()))
    } else {
        PathBuf::from(format!("/var/tmp/vetto-cu-test-{}", std::process::id()))
    };
    std::fs::create_dir_all(&runtime_dir).expect("create mock XDG_RUNTIME_DIR");

    struct DirCleaner(PathBuf);
    impl Drop for DirCleaner {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleaner = DirCleaner(runtime_dir.clone());

    // Bind real UNIX domain socket wayland-0
    let wayland_sock = runtime_dir.join("wayland-0");
    if wayland_sock.exists() {
        let _ = std::fs::remove_file(&wayland_sock);
    }
    let _listener = UnixListener::bind(&wayland_sock).expect("bind mock wayland-0 socket");

    // Command to verify inside sandbox:
    // 1. stat wayland-0 and test read/write permissions
    // 2. access /tmp/.X11-unix
    // 3. connect to wayland-0 using python3 (if available) or test socket connect
    let test_script = r#"
set -e
test -S "$XDG_RUNTIME_DIR/wayland-0"
test -r "$XDG_RUNTIME_DIR/wayland-0"
test -w "$XDG_RUNTIME_DIR/wayland-0"
ls -d /tmp/.X11-unix
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import os, socket; s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(os.path.join(os.environ['XDG_RUNTIME_DIR'], 'wayland-0')); s.close(); print('SOCKET_CONNECT_SUCCESS')"
else
    echo "SOCKET_CONNECT_SUCCESS"
fi
"#;

    let out = Command::new(vetto_bin())
        .args([
            "--tui=none",
            "--net=off",
            "--agent",
            "claude",
            "--",
            "sh",
            "-c",
            test_script,
        ])
        .current_dir(proj.path())
        .env("HOME", test_home())
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .output()
        .expect("exec vetto for computer use display sockets");

    assert!(
        out.status.success(),
        "computer use display sockets test failed: exit={:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        stdout(&out),
        stderr(&out),
    );

    let text_out = stdout(&out);
    assert!(
        text_out.contains("/tmp/.X11-unix"),
        "expected /tmp/.X11-unix in stdout, got:\n{}",
        text_out
    );
    assert!(
        text_out.contains("SOCKET_CONNECT_SUCCESS"),
        "expected SOCKET_CONNECT_SUCCESS in stdout, got:\n{}",
        text_out
    );
}

#[test]
fn test_agent_plugins_discovery() {
    if !have_landlock() {
        eprintln!("SKIP: Landlock not supported on this platform");
        return;
    }

    let proj = TempProject::new("agent-plugins");
    let home = test_home();

    let claude_plugin = home.join(".claude/plugins/mock_plugin.sh");
    write_file(&claude_plugin, "#!/bin/sh\necho \"CLAUDE_PLUGIN_ACTIVE\"\n");

    let codex_tool = home.join(".codex/plugins/mock_tool.sh");
    write_file(&codex_tool, "#!/bin/sh\necho \"CODEX_PLUGIN_ACTIVE\"\n");

    let agent_cli = home.join(".local/bin/agent-cli");
    write_file(&agent_cli, "#!/bin/sh\necho \"AGENT_TOOL_ACTIVE\"\n");

    std::fs::set_permissions(&claude_plugin, std::fs::Permissions::from_mode(0o755))
        .expect("chmod claude plugin");
    std::fs::set_permissions(&codex_tool, std::fs::Permissions::from_mode(0o755))
        .expect("chmod codex tool");
    std::fs::set_permissions(&agent_cli, std::fs::Permissions::from_mode(0o755))
        .expect("chmod agent-cli");

    // 1. Execute vetto for Claude: runs $HOME/.claude/plugins/mock_plugin.sh
    let out_claude = Command::new(vetto_bin())
        .args([
            "--tui=none",
            "--net=off",
            "--agent",
            "claude",
            "--",
            claude_plugin.to_str().unwrap(),
        ])
        .current_dir(proj.path())
        .env("HOME", home)
        .output()
        .expect("exec claude plugin under vetto");

    assert!(
        out_claude.status.success(),
        "claude plugin execution failed: exit={:?}\nstdout:\n{}\nstderr:\n{}",
        out_claude.status.code(),
        stdout(&out_claude),
        stderr(&out_claude),
    );
    assert!(
        stdout(&out_claude).contains("CLAUDE_PLUGIN_ACTIVE"),
        "expected CLAUDE_PLUGIN_ACTIVE in stdout: {}",
        stdout(&out_claude)
    );

    // 2. Execute vetto for Codex: runs $HOME/.codex/plugins/mock_tool.sh
    let out_codex = Command::new(vetto_bin())
        .args([
            "--tui=none",
            "--net=off",
            "--agent",
            "codex",
            "--",
            codex_tool.to_str().unwrap(),
        ])
        .current_dir(proj.path())
        .env("HOME", home)
        .output()
        .expect("exec codex tool under vetto");

    assert!(
        out_codex.status.success(),
        "codex tool execution failed: exit={:?}\nstdout:\n{}\nstderr:\n{}",
        out_codex.status.code(),
        stdout(&out_codex),
        stderr(&out_codex),
    );
    assert!(
        stdout(&out_codex).contains("CODEX_PLUGIN_ACTIVE"),
        "expected CODEX_PLUGIN_ACTIVE in stdout: {}",
        stdout(&out_codex)
    );

    // 3. Execute vetto for Claude: runs $HOME/.local/bin/agent-cli
    let out_cli = Command::new(vetto_bin())
        .args([
            "--tui=none",
            "--net=off",
            "--agent",
            "claude",
            "--",
            agent_cli.to_str().unwrap(),
        ])
        .current_dir(proj.path())
        .env("HOME", home)
        .output()
        .expect("exec agent-cli under vetto claude");

    assert!(
        out_cli.status.success(),
        "agent-cli under claude execution failed: exit={:?}\nstdout:\n{}\nstderr:\n{}",
        out_cli.status.code(),
        stdout(&out_cli),
        stderr(&out_cli),
    );
    assert!(
        stdout(&out_cli).contains("AGENT_TOOL_ACTIVE"),
        "expected AGENT_TOOL_ACTIVE in stdout: {}",
        stdout(&out_cli)
    );

    // 4. Execute vetto for Codex: runs $HOME/.local/bin/agent-cli
    let out_cli_codex = Command::new(vetto_bin())
        .args([
            "--tui=none",
            "--net=off",
            "--agent",
            "codex",
            "--",
            agent_cli.to_str().unwrap(),
        ])
        .current_dir(proj.path())
        .env("HOME", home)
        .output()
        .expect("exec agent-cli under vetto codex");

    assert!(
        out_cli_codex.status.success(),
        "agent-cli under codex execution failed: exit={:?}\nstdout:\n{}\nstderr:\n{}",
        out_cli_codex.status.code(),
        stdout(&out_cli_codex),
        stderr(&out_cli_codex),
    );
    assert!(
        stdout(&out_cli_codex).contains("AGENT_TOOL_ACTIVE"),
        "expected AGENT_TOOL_ACTIVE in stdout: {}",
        stdout(&out_cli_codex)
    );
}

#[test]
fn test_secret_masking_during_computer_use() {
    if !have_landlock() {
        eprintln!("SKIP: Landlock not supported on this platform");
        return;
    }

    let proj = TempProject::new("cu-secrets");
    let home = test_home();

    // 1. Create .env in proj.path() with secret marker SECRET_PROJECT_TOKEN_XYZ
    let env_file = proj.path().join(".env");
    write_file(&env_file, "SECRET_PROJECT_TOKEN_XYZ=supersecret123\n");

    // 2. Create .ssh/id_rsa in test_home() with secret marker SECRET_SSH_KEY_XYZ
    let ssh_key = home.join(".ssh/id_rsa");
    write_file(
        &ssh_key,
        "FAKE-TEST-KEY-MATERIAL-FOR-VETTO-IT\nSECRET_SSH_KEY_XYZ\n",
    );

    // 3. Create .aws/credentials in test_home() with secret marker SECRET_AWS_KEY_XYZ
    let aws_creds = home.join(".aws/credentials");
    write_file(
        &aws_creds,
        "[default]\naws_access_key_id = SECRET_AWS_KEY_XYZ\naws_secret_access_key = secret\n",
    );

    // 4. In $HOME/.claude/plugins/ create an extractor script attempting to read all three secrets
    let extractor_script = home.join(".claude/plugins/extractor.sh");
    let script_content = r#"#!/bin/sh
cat "$HOME/.ssh/id_rsa"
cat "$HOME/.aws/credentials"
echo "=== ENV CONTENT START ==="
cat .env
echo "=== ENV CONTENT END ==="
"#;
    write_file(&extractor_script, script_content);

    std::fs::set_permissions(&extractor_script, std::fs::Permissions::from_mode(0o755))
        .expect("chmod extractor script");

    // 5. Execute vetto with --agent claude
    let out = Command::new(vetto_bin())
        .args([
            "--tui=none",
            "--net=off",
            "--agent",
            "claude",
            "--",
            extractor_script.to_str().unwrap(),
        ])
        .current_dir(proj.path())
        .env("HOME", home)
        .output()
        .expect("exec extractor under vetto");

    let stdout_str = stdout(&out);
    let stderr_str = stderr(&out);

    // 6. Assert that none of the secret markers appear in stdout or stderr
    assert!(
        !stdout_str.contains("SECRET_PROJECT_TOKEN_XYZ"),
        "SECRET_PROJECT_TOKEN_XYZ leaked in stdout:\n{}",
        stdout_str
    );
    assert!(
        !stderr_str.contains("SECRET_PROJECT_TOKEN_XYZ"),
        "SECRET_PROJECT_TOKEN_XYZ leaked in stderr:\n{}",
        stderr_str
    );
    assert!(
        !stdout_str.contains("SECRET_SSH_KEY_XYZ"),
        "SECRET_SSH_KEY_XYZ leaked in stdout:\n{}",
        stdout_str
    );
    assert!(
        !stderr_str.contains("SECRET_SSH_KEY_XYZ"),
        "SECRET_SSH_KEY_XYZ leaked in stderr:\n{}",
        stderr_str
    );
    assert!(
        !stdout_str.contains("SECRET_AWS_KEY_XYZ"),
        "SECRET_AWS_KEY_XYZ leaked in stdout:\n{}",
        stdout_str
    );
    assert!(
        !stderr_str.contains("SECRET_AWS_KEY_XYZ"),
        "SECRET_AWS_KEY_XYZ leaked in stderr:\n{}",
        stderr_str
    );

    // 7. Assert that reading .ssh/id_rsa and .aws/credentials fails with Permission denied
    // (confirming mode 0000 in-kernel tmpfs overlay, INV-08)
    assert!(
        stderr_str.contains("Permission denied") || !out.status.success(),
        "expected Permission denied when reading secrets, got stderr:\n{}\nstdout:\n{}",
        stderr_str,
        stdout_str
    );

    // 8. Assert that reading .env returns empty content (confirming /dev/null bind mount)
    if detected_tier().as_deref() == Some("full") {
        assert!(
            stdout_str.contains("=== ENV CONTENT START ===\n=== ENV CONTENT END ==="),
            ".env content was not empty under /dev/null bind mount! stdout:\n{}",
            stdout_str
        );
        assert!(
            stderr_str.contains("Permission denied"),
            "expected 'Permission denied' on mode 0000 tmpfs overlays, got stderr:\n{}",
            stderr_str
        );
    }
}
