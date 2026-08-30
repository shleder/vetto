use std::path::Path;
use std::process::Command;

use crate::common;

#[test]
fn tour_non_interactive_completes_all_steps_successfully() {
    let mut cmd = Command::new(common::vetto_bin());
    cmd.arg("tour").arg("--non-interactive");

    let output = cmd.output().expect("invoke vetto tour --non-interactive");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "vetto tour failed: {output:?}");
    assert!(stdout.contains("Welcome to the vetto Tour"));
    assert!(stdout.contains("[Step 1/5]"));
    assert!(stdout.contains("[Step 2/5]"));
    assert!(stdout.contains("[Step 3/5]"));
    assert!(stdout.contains("[Step 4/5]"));
    assert!(stdout.contains("[Step 5/5]"));
    assert!(stdout.contains("Tour completed!"));
}

#[test]
fn upgrade_dry_run_and_check_flags_exit_zero() {
    let mut cmd = Command::new(common::vetto_bin());
    cmd.arg("upgrade").arg("--check");

    let output = cmd.output().expect("invoke vetto upgrade --check");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "vetto upgrade --check failed: {output:?}"
    );
    assert!(stdout.contains("vetto upgrade: checking updates"));

    let mut dry_cmd = Command::new(common::vetto_bin());
    dry_cmd.arg("upgrade").arg("--dry-run");

    let dry_output = dry_cmd.output().expect("invoke vetto upgrade --dry-run");
    assert!(dry_output.status.success());
}

#[test]
fn install_method_detection_logic() {
    use vetto::version::{detect_install_method, InstallMethod};

    assert_eq!(
        detect_install_method(Path::new("/home/dev/.cargo/bin/vetto")),
        InstallMethod::Cargo
    );
    assert_eq!(
        detect_install_method(Path::new(
            "/usr/local/lib/node_modules/@shledery/vetto/native/linux-x64/vetto"
        )),
        InstallMethod::Npm
    );
    assert_eq!(
        detect_install_method(Path::new("/opt/bin/vetto")),
        InstallMethod::Binary
    );
}

#[test]
fn registry_response_and_semver_parsing() {
    use vetto::version::{parse_registry_version, SemVer};

    let v_old = SemVer::parse("0.2.5").expect("parse 0.2.5");
    let v_new = SemVer::parse("0.2.6").expect("parse 0.2.6");
    assert!(v_new.is_newer_than(&v_old));
    assert!(!v_old.is_newer_than(&v_new));

    let pkg_json = r#"{
        "dist-tags": {
            "latest": "0.2.6",
            "alpha": "0.2.7-alpha.1"
        }
    }"#;
    assert_eq!(
        parse_registry_version(pkg_json, "stable").as_deref(),
        Some("0.2.6")
    );
    assert_eq!(
        parse_registry_version(pkg_json, "alpha").as_deref(),
        Some("0.2.7-alpha.1")
    );
}

#[test]
fn telemetry_zero_network_when_disabled() {
    use vetto::report::stats::SessionStats;
    use vetto::telemetry::send_session_telemetry;

    let stats = SessionStats::default();
    // Default config has telemetry = false, should return Ok without network calls
    let res = send_session_telemetry(&stats, "full");
    assert!(res.is_ok());
}
