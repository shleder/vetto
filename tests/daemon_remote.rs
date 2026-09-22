use clap::Parser;
use vetto::cli::{Cli, Command};

#[test]
fn test_cli_parse_daemon_commands() {
    let args = vec!["vetto", "daemon", "status"];
    let parsed = Cli::try_parse_from(args).expect("parse daemon status");
    assert!(matches!(
        parsed.command,
        Some(Command::Daemon {
            command: vetto::daemon::DaemonCommand::Status
        })
    ));
}

#[test]
fn test_cli_parse_serve_command() {
    let args = vec!["vetto", "serve", "--port", "54321"];
    let parsed = Cli::try_parse_from(args).expect("parse serve");
    assert!(matches!(
        parsed.command,
        Some(Command::Serve { port: 54321 })
    ));
}

#[test]
fn test_cli_parse_remote_flag() {
    let args = vec![
        "vetto",
        "--remote",
        "http://127.0.0.1:54321",
        "--",
        "echo",
        "hello",
    ];
    let parsed = Cli::try_parse_from(args).expect("parse remote args");
    assert_eq!(parsed.remote.as_deref(), Some("http://127.0.0.1:54321"));
    assert_eq!(parsed.agent, vec!["echo", "hello"]);
}
