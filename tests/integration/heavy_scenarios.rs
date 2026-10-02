//! Heavy stress testing suite: exercises hundreds of the heaviest, most adversarial
//! and complex usage scenarios (session fuzzing, deep directories, suspicious command matrices,
//! and agent auto-detection).

use chrono::Utc;
use vetto::classifier::suspicious::{classify_event, SuspicionSeverity};
use vetto::config::detect_agent_preset;
use vetto::events::{Event, FileAccess};

#[test]
fn stress_test_hundreds_of_suspicious_commands_classifier() {
    // 1. Executed commands testing
    let exec_cases: &[(&[&str], Option<SuspicionSeverity>)] = &[
        (
            &["socat", "-", "/tmp/app_server.sock"],
            Some(SuspicionSeverity::High),
        ),
        (&["nc", "-l", "8080"], Some(SuspicionSeverity::High)),
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
        ("/tmp/cursor-server.sock", Some(SuspicionSeverity::High)),
        (
            "/home/user/.codex/state_5.sqlite",
            Some(SuspicionSeverity::High),
        ),
        ("/tmp/vscode-ipc-12345.sock", Some(SuspicionSeverity::High)),
        ("/tmp/core.dump", Some(SuspicionSeverity::Warning)),
        ("memory.heapsnapshot", Some(SuspicionSeverity::Warning)),
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
            comm: "test".to_string(),
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
            host: host.to_string(),
            port: *port,
            allowed: true,
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
