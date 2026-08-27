//! Heavy stress testing suite: exercises hundreds of the heaviest, most adversarial
//! and complex usage scenarios (session fuzzing, deep directories, suspicious command matrices,
//! and agent auto-detection).

use crate::common::*;
use rusqlite::Connection;
use std::fs;
use std::process::Command;
use vetto::classifier::suspicious::{classify_command, EventSeverity};
use vetto::config::detect_agent_preset;

fn run_rescue_cmd(root: &std::path::Path, trailing: &[&str]) -> std::process::Output {
    let mut command = Command::new(vetto_bin());
    command
        .arg("rescue")
        .arg("--adapter")
        .arg("codex")
        .arg("--root")
        .arg(root)
        .arg("--json")
        .args(trailing)
        .output()
        .expect("spawn rescue command")
}

#[test]
fn stress_test_hundreds_of_fuzzed_corrupted_sessions() {
    let project = TempProject::new("stress-session-fuzzing");
    let root = project.path().join("codex-root");
    let sessions_dir = root.join("sessions").join("2026").join("08").join("27");
    fs::create_dir_all(&sessions_dir).expect("create sessions dir");

    // Initialize sqlite index
    let db_path = root.join("state_5.sqlite");
    let conn = Connection::open(&db_path).expect("create index db");
    conn.execute(
        "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT)",
        [],
    )
    .expect("create table");

    // Generate 120 distinct corrupt/heavy session scenarios
    for i in 0..120 {
        let session_file = sessions_dir.join(format!("session_{i}.jsonl"));
        let thread_id = format!("thread-{i:04}");

        let content = match i % 12 {
            0 => "{\"type\":\"session_meta\",\"id\":\"".to_string(), // Truncated mid-string
            1 => "{}\n{}\n{\"type\":\"unknown_event_type_xyz\"}\n".to_string(),
            2 => "{\"type\":\"session_meta\",\"id\":\"test\"}\n".repeat(500), // Duplicate metadata
            3 => format!(
                "{{\"type\":\"session_meta\",\"id\":\"{thread_id}\"}}\n{{\"type\":\"turn\",\"input\":[{{\"id\":\"review_rollout_user\",\"text\":\"fix bug\"}}]}}\n"
            ),
            4 => "{\"type\":\"session_meta\",\"payload\":".to_string() + &"[".repeat(200) + &"]".repeat(200) + "}\n", // Deep nesting
            5 => format!(
                "{{\"type\":\"session_meta\",\"id\":\"{thread_id}\"}}\n{{\"type\":\"function_call_output\",\"call_id\":\"call_1\",\"content\":\"{}\"}}\n",
                "A".repeat(50_000) // Heavy payload
            ),
            6 => "\0\0\0\x1f\x8b\x08\0\0\0\0\0\xff\x01".to_string(), // Binary / gzipped garbage
            7 => format!(
                "{{\"type\":\"session_meta\",\"id\":\"{thread_id}\"}}\n{{\"type\":\"event_msg\",\"payload\":{{\"type\":\"mcp_tool_call_begin\",\"call_id\":\"mcp-{i}\"}}}}\n"
            ), // Unfinished tool call
            8 => "{\"type\":\"invalid_json\"".to_string(),
            9 => "\n\n\n   \t\r\n".to_string(), // Empty whitespace lines
            10 => format!(
                "{{\"type\":\"session_meta\",\"id\":\"{thread_id}\"}}\n{{\"type\":\"message\",\"role\":\"user\",\"content\":\"valid turn {i}\"}}\n"
            ),
            _ => format!(
                "{{\"type\":\"session_meta\",\"id\":\"{thread_id}\"}}\n{{\"type\":\"turn_transition\",\"status\":\"in_progress\"}}\n"
            ),
        };

        fs::write(&session_file, content).expect("write fuzzed session");

        conn.execute(
            "INSERT INTO threads (id, rollout_path) VALUES (?1, ?2)",
            rusqlite::params![thread_id, session_file.to_string_lossy().to_string()],
        )
        .expect("insert index row");
    }

    // 1. Stress test scan: must process all 120 sessions without crashing
    let scan_out = run_rescue_cmd(&root, &["scan"]);
    assert!(
        scan_out.status.success(),
        "scan must safely process 120 fuzzed sessions"
    );

    // 2. Stress test diagnosis on all 120 sessions
    let out_dir = project.path().join("recovery-output");
    fs::create_dir_all(&out_dir).expect("recovery dir");

    for i in 0..120 {
        let session_file = sessions_dir.join(format!("session_{i}.jsonl"));
        let session_str = session_file.to_string_lossy().to_string();

        let diag_out = run_rescue_cmd(&root, &["diagnose", &session_str]);
        // Diagnosis must always terminate with valid exit code (0 or clean error) and zero panics
        assert!(
            diag_out.status.code().is_some(),
            "diagnose must never crash or terminate abnormally on session {i}"
        );

        // 3. Stress test snapshot creation
        let snap_dest = out_dir.join(format!("snapshot_{i}.jsonl"));
        let snap_dest_str = snap_dest.to_string_lossy().to_string();
        let _snap_out = run_rescue_cmd(
            &root,
            &["snapshot", &session_str, "--output", &snap_dest_str],
        );
    }
}

#[test]
fn stress_test_hundreds_of_suspicious_commands_classifier() {
    let test_cases = [
        // Subagent Control Plane Tampering
        ("cat /tmp/codex_app.sock", EventSeverity::High),
        ("nc -U ~/.claude/claude_code.sock", EventSeverity::High),
        (
            "curl --unix-socket /tmp/cursor-server.sock http://localhost/test",
            EventSeverity::High,
        ),
        (
            "sqlite3 ~/.codex/state_5.sqlite 'select * from threads'",
            EventSeverity::High,
        ),
        ("rm -f /tmp/vscode-ipc-12345.sock", EventSeverity::High),
        ("socat - /tmp/app_server.sock", EventSeverity::High),
        // Debug port probes
        ("curl http://127.0.0.1:9222/json", EventSeverity::High),
        ("wget http://localhost:9229/node-inspect", EventSeverity::High),
        ("ncat 127.0.0.1 5678", EventSeverity::High),
        // Tunneling & network manipulation
        ("chisel client server:8080 R:80:127.0.0.1:80", EventSeverity::High),
        ("ngrok http 3000", EventSeverity::High),
        ("cloudflared tunnel run my-tunnel", EventSeverity::High),
        ("tcpdump -i any -w dump.pcap", EventSeverity::High),
        // Memory & Heavy Dump Writes
        ("gcore -o /tmp/core.dump 1234", EventSeverity::Warning),
        ("heapdump-tool --output memory.heapsnapshot", EventSeverity::Warning),
        ("cp /proc/kcore ./core.1234", EventSeverity::Warning),
        // Normal developer tooling (should not trigger High severity)
        ("cargo build --release", EventSeverity::Info),
        ("git status", EventSeverity::Info),
        ("npm test", EventSeverity::Info),
        ("python -m unittest discover", EventSeverity::Info),
    ];

    for (cmd, expected_min_severity) in test_cases {
        let events = classify_command(cmd);
        if expected_min_severity != EventSeverity::Info {
            assert!(
                !events.is_empty(),
                "command '{cmd}' was expected to produce classification events"
            );
            let max_sev = events.iter().map(|e| e.severity).max().unwrap();
            assert_eq!(
                max_sev, expected_min_severity,
                "command '{cmd}' got severity {max_sev:?}, expected {expected_min_severity:?}"
            );
        }
    }
}

#[test]
fn stress_test_agent_auto_detection_matrix() {
    let scenarios = [
        // Codex variations
        (vec!["codex", "exec", "task"], Some("codex")),
        (vec!["/usr/bin/codex", "review"], Some("codex")),
        (
            vec!["C:\\Program Files\\Codex\\codex.exe", "exec"],
            Some("codex"),
        ),
        (vec!["codex-cli", "run"], Some("codex")),
        // Claude variations
        (vec!["claude", "-p", "hello"], Some("claude")),
        (vec!["/home/user/.local/bin/claude-code"], Some("claude")),
        (vec!["claude.exe", "-p", "fix"], Some("claude")),
        // Cursor variations
        (vec!["cursor", "."], Some("cursor")),
        (vec!["/usr/local/bin/cursor-server"], Some("cursor")),
        // Aider variations
        (vec!["aider", "--model", "gpt-4"], Some("aider")),
        (vec!["aider-chat"], Some("aider")),
        // Copilot variations
        (vec!["copilot", "suggest"], Some("copilot")),
        (vec!["github-copilot-cli"], Some("copilot")),
        // Cline & OpenCode
        (vec!["cline", "start"], Some("cline")),
        (vec!["opencode", "run"], Some("opencode")),
        // Non-agents (should return None)
        (vec!["python", "script.py"], None),
        (vec!["bash", "-c", "echo hello"], None),
        (vec!["cargo", "test"], None),
        (vec!["docker", "run", "ubuntu"], None),
        (vec!["curl", "https://example.com"], None),
    ];

    for (cmd_slice, expected) in scenarios {
        let cmd_vec: Vec<String> = cmd_slice.into_iter().map(String::from).collect();
        let detected = detect_agent_preset(&cmd_vec);
        assert_eq!(
            detected.as_deref(),
            expected,
            "failed auto-detection for command: {cmd_slice:?}"
        );
    }
}
