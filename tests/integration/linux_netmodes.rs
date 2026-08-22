//! Network modes: off (both tiers) and allowlist (FULL only, needs egress).
//! All tests conditional: python3/curl availability, tier, and network.

use crate::common::*;

const PY_PROBE: &str = "import socket\n\
try:\n\
    socket.create_connection(('1.1.1.1', 53), timeout=3)\n\
    print('NET-LEAK')\n\
except Exception:\n\
    print('net-blocked-ok')\n";

#[test]
fn net_off_full_blocks_socket() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs full tier");
        return;
    }
    if !tool_available("python3") {
        eprintln!("SKIP: python3 not installed");
        return;
    }
    let proj = TempProject::new("netoff");
    let out = run_vetto_in(
        proj.path(),
        &["--tui=none", "--", "python3", "-c", PY_PROBE],
    );
    assert!(
        !stdout(&out).contains("NET-LEAK"),
        "network reachable in off mode (full tier): {}",
        stdout(&out)
    );
}

#[test]
fn net_off_fs_only_blocks_socket() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs full-tier machine to force fs-only");
        return;
    }
    if !tool_available("python3") {
        eprintln!("SKIP: python3 not installed");
        return;
    }
    let proj = TempProject::new("netofffs");
    let out = run_vetto_env_in(
        proj.path(),
        &["--tui=none", "--", "python3", "-c", PY_PROBE],
        &[("VETTO_FORCE_TIER", "fs-only")],
    );
    assert!(
        !stdout(&out).contains("NET-LEAK"),
        "network reachable in off mode (fs-only/seccomp): {}",
        stdout(&out)
    );
}

#[test]
fn allowlist_permits_listed_domain_only() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: allowlist needs full tier");
        return;
    }
    if !tool_available("curl") {
        eprintln!("SKIP: curl not installed");
        return;
    }
    let proj = TempProject::new("allowlist");

    // Listed domain: CONNECT relay must carry it end-to-end.
    let ok = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--net=allowlist:example.com",
            "--",
            "curl",
            "-sS",
            "-m",
            "20",
            "https://example.com",
        ],
    );
    let ok_text = stdout(&ok);
    assert!(
        ok_text.contains("Example Domain") || ok_text.contains("example"),
        "listed domain unreachable via relay: {} / {}",
        ok_text,
        stderr(&ok)
    );

    // Not-listed domain: the broker must deny the CONNECT.
    let denied = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--net=allowlist:example.com",
            "--",
            "curl",
            "-sS",
            "-m",
            "20",
            "https://httpbin.org/status/200",
        ],
    );
    assert!(
        !denied.status.success(),
        "non-listed domain reachable through allowlist: {}",
        stdout(&denied)
    );
}
