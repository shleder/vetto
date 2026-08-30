use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::json;

use super::common::vetto_bin;

#[test]
fn test_mcp_server_stdio_protocol() {
    let mut child = Command::new(vetto_bin())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn vetto mcp");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    // 1. Send initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    writeln!(stdin, "{}", init_req).expect("write init");
    stdin.flush().expect("flush");

    let mut line = String::new();
    reader.read_line(&mut line).expect("read init response");
    let resp: serde_json::Value = serde_json::from_str(&line).expect("parse init resp");
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["serverInfo"]["name"], "vetto");

    // 2. Send tools/list
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    writeln!(stdin, "{}", list_req).expect("write tools/list");
    stdin.flush().expect("flush");

    line.clear();
    reader.read_line(&mut line).expect("read tools/list resp");
    let resp: serde_json::Value = serde_json::from_str(&line).expect("parse tools resp");
    assert_eq!(resp["id"], 2);
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools[0]["name"], "run_sandboxed");

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_policy_signing_and_verification_cli() {
    let temp_dir = std::env::temp_dir().join(format!("vetto-cli-sign-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let policy_path = temp_dir.join("vetto.toml");
    let policy_content = r#"
[metadata]
name = "signed-cli-policy"

[filesystem]
allow_write = ["${PROJECT}"]
allow_read = ["/usr", "${PROJECT}"]
"#;
    std::fs::write(&policy_path, policy_content).unwrap();

    let key_path = temp_dir.join("custom.key");
    let (key, _) = vetto::policy::crypto::ensure_signing_keypair(&temp_dir).unwrap();
    let key_hex = vetto::policy::crypto::to_hex(&key.to_bytes());
    std::fs::write(&key_path, key_hex).unwrap();

    // 1. Sign policy
    let sign_status = Command::new(vetto_bin())
        .arg("policy")
        .arg("sign")
        .arg(&policy_path)
        .arg("--key")
        .arg(&key_path)
        .status()
        .expect("run vetto policy sign");
    assert!(sign_status.success(), "vetto policy sign must exit 0");

    let sig_path = temp_dir.join("vetto.toml.sig");
    assert!(sig_path.exists(), "signature file must be created");

    // 2. Verify valid signature
    let verify_status = Command::new(vetto_bin())
        .arg("policy")
        .arg("verify")
        .arg(&policy_path)
        .arg("--sig")
        .arg(&sig_path)
        .status()
        .expect("run vetto policy verify");
    assert!(verify_status.success(), "vetto policy verify must exit 0");

    // 3. Tamper with policy and verify failure
    std::fs::write(&policy_path, "tampered content").unwrap();
    let verify_tampered = Command::new(vetto_bin())
        .arg("policy")
        .arg("verify")
        .arg(&policy_path)
        .arg("--sig")
        .arg(&sig_path)
        .status()
        .expect("run vetto policy verify tampered");
    assert!(
        !verify_tampered.success(),
        "tampered policy verify must fail"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_policy_use_community_registry_cli() {
    let temp_dir = std::env::temp_dir().join(format!("vetto-cli-use-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let status = Command::new(vetto_bin())
        .current_dir(&temp_dir)
        .arg("policy")
        .arg("use")
        .arg("python-dev")
        .status()
        .expect("run vetto policy use python-dev");
    assert!(status.success());

    let installed_file = temp_dir.join("vetto.toml");
    assert!(installed_file.exists());
    let content = std::fs::read_to_string(&installed_file).unwrap();
    assert!(content.contains("name = \"python-dev\""));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_plugin_install_cli() {
    let temp_home = std::env::temp_dir().join(format!("vetto-plugin-home-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_home);
    std::fs::create_dir_all(&temp_home).unwrap();

    // Run plugin install claude-code with custom HOME
    let status = Command::new(vetto_bin())
        .env("HOME", &temp_home)
        .arg("plugin")
        .arg("install")
        .arg("claude-code")
        .status()
        .expect("run vetto plugin install claude-code");
    assert!(status.success());

    let settings = temp_home.join(".claude").join("settings.json");
    assert!(settings.exists());
    let content = std::fs::read_to_string(&settings).unwrap();
    assert!(content.contains("PreToolUse"));

    let _ = std::fs::remove_dir_all(&temp_home);
}
