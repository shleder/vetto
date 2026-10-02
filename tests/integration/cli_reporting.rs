//! CLI-only reporting/completion tests; these do not require a sandbox tier.

use crate::common::*;
use std::process::Command;

#[test]
fn completions_are_available_for_all_requested_shells() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let output = Command::new(vetto_bin())
            .args(["completions", shell])
            .output()
            .expect("spawn completion command");
        assert!(
            output.status.success(),
            "completion failed for {shell}: {}",
            stderr(&output)
        );
        assert!(
            !output.stdout.is_empty(),
            "completion output empty for {shell}"
        );
    }
}
