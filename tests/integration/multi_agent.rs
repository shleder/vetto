//! Multi-agent CLI safety checks. Runtime launch tests are intentionally
//! conditional on a usable sandbox tier; parser failures must be deterministic
//! on every platform and must never start an agent.

use crate::common::*;
use std::process::Command;

#[test]
fn ambiguous_separator_is_rejected_before_launch() {
    let project = TempProject::new("multi-ambiguous");
    let output = Command::new(vetto_bin())
        .current_dir(project.path())
        .args(["multi", "--", "echo", "--", "other"])
        .output()
        .expect("spawn vetto");
    assert!(!output.status.success());
    let text = stderr(&output);
    assert!(
        text.contains("ambiguous") || text.contains("manifest"),
        "stderr: {text}"
    );
}

#[test]
fn invalid_manifest_fails_closed_without_running_agent() {
    let project = TempProject::new("multi-invalid");
    let marker = project.path().join("should-not-exist");
    let manifest = project.path().join("agents.toml");
    write_file(
        &manifest,
        &format!(
            "[[agents]]\nname = \"bad\"\ncommand = [\"/bin/sh\", \"-c\", \"touch {}\"]\n[[agents]]\nname = \"bad\"\ncommand = [\"/bin/true\"]\n",
            marker.display()
        ),
    );
    let output = run_vetto_in(project.path(), &["multi", "--manifest", "agents.toml"]);
    assert!(!output.status.success());
    assert!(!marker.exists(), "invalid manifest launched a command");
}
