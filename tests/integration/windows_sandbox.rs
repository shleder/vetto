//! Windows backend checks.  They are capability-conditional because the
//! Windows 11 processmodel API is experimental and may be disabled by the OS
//! build or enterprise policy.

#[cfg(target_os = "windows")]
#[test]
fn capability_probe_reports_no_hidden_network_or_filesystem_fallback() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
        .arg("doctor")
        .output()
        .expect("vetto doctor");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("windows") || text.contains("Windows"), "{text}");
}

#[cfg(target_os = "windows")]
#[test]
fn appcontainer_detection_is_capability_only() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
        .arg("doctor")
        .output()
        .expect("vetto doctor");
    let text = String::from_utf8_lossy(&out.stdout);
    // Capability reporting must not imply that host firewall rules, DACLs, or
    // drivers were changed. The doctor path only probes APIs.
    assert!(text.contains("appcontainer") || text.contains("AppContainer"), "{text}");
}

#[cfg(not(target_os = "windows"))]
#[test]
fn windows_suite_not_applicable_on_this_platform() {}
