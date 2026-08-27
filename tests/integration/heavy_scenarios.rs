//! Heavy stress testing suite: exercises hundreds of the heaviest, most adversarial
//! and complex usage scenarios (session fuzzing, deep directories, suspicious command matrices,
//! and agent auto-detection).

use crate::common::*;
use chrono::Utc;
use rusqlite::Connection;
use std::fs;
use std::process::Command;
use vetto::classifier::suspicious::{classify_event, SuspicionSeverity};
use vetto::config::detect_agent_preset;
use vetto::events::{Event, FileAccess};

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
            2 => "{\"type\":\"session_meta\",\"id\":\"test\"}\n".repeat(200), // Duplicate metadata
            3 => format!(
                "{{\"type\":\"session_meta\",\"id\":\"{thread_id}\"}}\n{{\"type\":\"turn\",\"input\":[{{\"id\":\"review_rollout_user\",\"text\":\"fix bug\"}}]}}\n"
            ),
            4 => {
                "{\"type\":\"session_meta\",\"payload\":".to_string()
                    + &"[".repeat(100)
                    + &"]".repeat(100)
                    + "}\n"
            } // Deep nesting
            5 => format!(
                "{{\"type\":\"session_meta\",\"id\":\"{thread_id}\"}}\n{{\"type\":\"function_call_output\",\"call_id\":\"call_1\",\"content\":\"{}\"}}\n",
                "A".repeat(25_000) // Heavy payload
            ),
            6 => "{\"type\":\"raw_bytes\",\"data\":\"\\u0000\\u001f\\u007f\"}\n".to_string(), // Raw bytes representation
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
    // 1. Executed commands testing
    let exec_cases: &[(&[&str], Option<SuspicionSeverity>)] = &[
        (
            &["socat", "-", "/tmp/app_server.sock"],
            Some(SuspicionSeverity::High),
        ),
        (
            &["nc", "-l", "8080"],
            Some(SuspicionSeverity::High),
        ),
        (
            &["chisel", "client", "server:8080", "R:80:127.0.0.1:80"],
            Some(SuspicionSeverity::High),
        ),
        (&["ngrok", "http", "3000"], Some(SuspicionSeverity::High)),
        (
            &["cloudflared", "tunnel", "run", "my-tunnel"],
            Some(SuspicionSeverity::High),
        ),
        (
            &["tcpdump", "-i", "any", "-w", "dump.pcap"],
            Some(SuspicionSeverity::High),
        ),
        (&["sudo", "su"], Some(SuspicionSeverity::Advisory)),
        (&["gdb", "-p", "1234"], Some(SuspicionSeverity::Advisory)),
        (&["cargo", "build", "--release"], None),
        (&["git", "status"], None),
        (&["npm", "test"], None),
        (&["python", "-m", "unittest", "discover"], None),
    ];

    for (argv, expected_sev) in exec_cases {
        let argv_vec: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let event = Event::ExecObserved {
            ts: Utc::now(),
            pid: 42,
            argv: argv_vec,
        };
        let signal = classify_event(&event);

        match expected_sev {
            Some(expected) => {
                assert!(
                    signal.is_some(),
                    "expected suspicious signal for argv: {argv:?}"
                );
                assert_eq!(
                    signal.unwrap().severity,
                    *expected,
                    "severity mismatch for argv: {argv:?}"
                );
            }
            None => {
                assert!(
                    signal.is_none(),
                    "expected no suspicious signal for argv: {argv:?}"
                );
            }
        }
    }

    // 2. File and Socket access testing
    let file_cases: &[(&str, Option<SuspicionSeverity>)] = &[
        ("/tmp/codex_app.sock", Some(SuspicionSeverity::High)),
        (
            "/home/user/.claude/claude_code.sock",
            Some(SuspicionSeverity::High),
        ),
        (
            "/tmp/cursor-server.sock",
            Some(SuspicionSeverity::High),
        ),
        (
            "/home/user/.codex/state_5.sqlite",
            Some(SuspicionSeverity::High),
        ),
        (
            "/tmp/vscode-ipc-12345.sock",
            Some(SuspicionSeverity::High),
        ),
        ("/tmp/core.dump", Some(SuspicionSeverity::Warning)),
        (
            "memory.heapsnapshot",
            Some(SuspicionSeverity::Warning),
        ),
        ("/home/user/.ssh/id_rsa", Some(SuspicionSeverity::High)),
        ("/home/user/.aws/credentials", Some(SuspicionSeverity::High)),
        ("src/main.rs", None),
        ("package.json", None),
        ("Cargo.toml", None),
    ];

    for (path, expected_sev) in file_cases {
        let event = Event::FileObserved {
            ts: Utc::now(),
            pid: 42,
            path: path.to_string(),
            access: FileAccess::Read,
        };
        let signal = classify_event(&event);

        match expected_sev {
            Some(expected) => {
                assert!(
                    signal.is_some(),
                    "expected suspicious signal for path: {path}"
                );
                assert_eq!(
                    signal.unwrap().severity,
                    *expected,
                    "severity mismatch for path: {path}"
                );
            }
            None => {
                assert!(
                    signal.is_none(),
                    "expected no suspicious signal for path: {path}"
                );
            }
        }
    }

    // 3. Network debug port probes testing
    let net_cases: &[((&str, u16), Option<SuspicionSeverity>)] = &[
        (("127.0.0.1", 9222), Some(SuspicionSeverity::High)),
        (("localhost", 9229), Some(SuspicionSeverity::High)),
        (("127.0.0.1", 5678), Some(SuspicionSeverity::High)),
        (("api.github.com", 443), None),
        (("registry.npmjs.org", 443), None),
    ];

    for ((host, port), expected_sev) in net_cases {
        let event = Event::NetRequest {
            ts: Utc::now(),
            pid: 42,
            host: host.to_string(),
            port: *port,
            verdict: "allow".to_string(),
        };
        let signal = classify_event(&event);

        match expected_sev {
            Some(expected) => {
                assert!(
                    signal.is_some(),
                    "expected suspicious signal for net: {host}:{port}"
                );
                assert_eq!(
                    signal.unwrap().severity,
                    *expected,
                    "severity mismatch for net: {host}:{port}"
                );
            }
            None => {
                assert!(
                    signal.is_none(),
                    "expected no suspicious signal for net: {host}:{port}"
                );
            }
        }
    }
}

#[test]
fn stress_test_agent_auto_detection_matrix() {
    let scenarios: &[(&[&str], Option<&str>)] = &[
        // Codex variations
        (&["codex", "exec", "task"], Some("codex")),
        (&["/usr/bin/codex", "review"], Some("codex")),
        (
            &["C:\\Program Files\\Codex\\codex.exe", "exec"],
            Some("codex"),
        ),
        (&["codex-cli", "run"], Some("codex")),
        // Claude variations
        (&["claude", "-p", "hello"], Some("claude")),
        (&["/home/user/.local/bin/claude-code"], Some("claude")),
        (&["claude.exe", "-p", "fix"], Some("claude")),
        // Cursor variations
        (&["cursor", "."], Some("cursor")),
        (&["/usr/local/bin/cursor-server"], Some("cursor")),
        // Aider variations
        (&["aider", "--model", "gpt-4"], Some("aider")),
        (&["aider-chat"], Some("aider")),
        // Copilot variations
        (&["copilot", "suggest"], Some("copilot")),
        (&["github-copilot-cli"], Some("copilot")),
        // Cline & OpenCode
        (&["cline", "start"], Some("cline")),
        (&["opencode", "run"], Some("opencode")),
        // Non-agents (should return None)
        (&["python", "script.py"], None),
        (&["bash", "-c", "echo hello"], None),
        (&["cargo", "test"], None),
        (&["docker", "run", "ubuntu"], None),
        (&["curl", "https://example.com"], None),
    ];

    for (cmd_slice, expected) in scenarios {
        let cmd_vec: Vec<String> = cmd_slice.iter().map(|s| s.to_string()).collect();
        let detected = detect_agent_preset(&cmd_vec);
        assert_eq!(
            detected.as_deref(),
            *expected,
            "failed auto-detection for command: {cmd_slice:?}"
        );
    }
}
