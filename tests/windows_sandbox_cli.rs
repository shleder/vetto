use clap::Parser;
use vetto::cli::Cli;

#[test]
fn test_windows_sandbox_flag_parsed() {
    let args = vec!["vetto", "--windows-sandbox", "--", "echo", "hello"];
    let parsed = Cli::try_parse_from(args).expect("parse args");
    assert!(parsed.windows_sandbox);
    assert_eq!(parsed.agent, vec!["echo", "hello"]);
}

#[test]
fn test_windows_sandbox_default_false() {
    let args = vec!["vetto", "--", "echo", "hello"];
    let parsed = Cli::try_parse_from(args).expect("parse args");
    assert!(!parsed.windows_sandbox);
}
