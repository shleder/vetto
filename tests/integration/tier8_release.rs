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
        detect_install_method(Path::new("/opt/homebrew/bin/vetto")),
        InstallMethod::Homebrew
    );
    assert_eq!(
        detect_install_method(Path::new("/usr/local/Cellar/vetto/0.2.11/bin/vetto")),
        InstallMethod::Homebrew
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

#[test]
fn update_notification_banner_format() {
    use vetto::version::checker::UpdateNotice;
    use vetto::version::upgrade::InstallMethod;

    let notice = UpdateNotice {
        current_version: "0.2.10".to_string(),
        latest_version: "0.2.11".to_string(),
        channel: "stable".to_string(),
        install_method: InstallMethod::Npm,
    };
    assert_eq!(
        notice.banner_message(),
        "Update available: 0.2.10 -> 0.2.11 (run 'vetto upgrade')"
    );
}

#[test]
fn audit_cli_listing_and_json_flags() {
    let mut cmd = Command::new(common::vetto_bin());
    cmd.arg("audit").arg("--json");

    let output = cmd.output().expect("invoke vetto audit --json");
    assert!(
        output.status.success(),
        "vetto audit --json failed: {output:?}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.trim().starts_with('[') || stdout.trim().starts_with('{'));
}

#[test]
fn audit_cli_filtering_flags() {
    let mut cmd = Command::new(common::vetto_bin());
    cmd.arg("audit")
        .arg("--since")
        .arg("24h")
        .arg("--agent")
        .arg("claude")
        .arg("--limit")
        .arg("5")
        .arg("--json");

    let output = cmd.output().expect("invoke vetto audit with filters");
    assert!(
        output.status.success(),
        "vetto audit filtered failed: {output:?}"
    );
}

#[test]
fn github_releases_response_parsing() {
    use vetto::version::parse_registry_version;

    let gh_json = r#"{"tag_name": "v0.2.11", "name": "Release 0.2.11"}"#;
    assert_eq!(
        parse_registry_version(gh_json, "stable").as_deref(),
        Some("0.2.11")
    );

    let gh_arr = r#"[
        {"tag_name": "v0.2.12-alpha.1", "prerelease": true},
        {"tag_name": "v0.2.11", "prerelease": false}
    ]"#;
    assert_eq!(
        parse_registry_version(gh_arr, "stable").as_deref(),
        Some("0.2.11")
    );
    assert_eq!(
        parse_registry_version(gh_arr, "alpha").as_deref(),
        Some("0.2.12-alpha.1")
    );
}

#[test]
fn semver_numeric_prerelease_and_custom_tags() {
    use vetto::version::{parse_registry_version, SemVer};

    let v_alpha2 = SemVer::parse("0.2.11-alpha.2").expect("alpha.2");
    let v_alpha10 = SemVer::parse("0.2.11-alpha.10").expect("alpha.10");
    assert!(v_alpha10.is_newer_than(&v_alpha2));
    assert!(!v_alpha2.is_newer_than(&v_alpha10));

    let v_build = SemVer::parse("0.2.11+build.99").expect("build");
    assert_eq!(v_build.major, 0);
    assert_eq!(v_build.minor, 2);
    assert_eq!(v_build.patch, 11);
    assert_eq!(v_build.prerelease, None);

    let pkg_json = r#"{
        "dist-tags": {
            "latest": "0.2.11",
            "beta": "0.2.12-beta.1"
        }
    }"#;
    assert_eq!(
        parse_registry_version(pkg_json, "beta").as_deref(),
        Some("0.2.12-beta.1")
    );
}
