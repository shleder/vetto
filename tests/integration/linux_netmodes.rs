//! Network modes: off (both tiers) and allowlist (FULL only, needs egress).
//! All tests conditional: python3/curl availability, tier, and network.

use crate::common::*;

const PY_PROBE: &str = "import socket\n\
try:\n\
    socket.create_connection(('1.1.1.1', 53), timeout=3)\n\
    print('NET-LEAK')\n\
except Exception:\n\
    print('net-blocked-ok')\n";

const PY_FAMILY_PROBE: &str = r#"import errno
import socket

# Linux address-family numbers: INET, INET6, NETLINK, PACKET, ALG, VSOCK, XDP.
for family in (2, 10, 16, 17, 38, 40, 44):
    try:
        sock = socket.socket(family, socket.SOCK_STREAM, 0)
    except OSError as error:
        if error.errno != errno.EAFNOSUPPORT:
            print(f"WRONG-ERRNO-{family}-{error.errno}")
            raise SystemExit(2)
    else:
        sock.close()
        print(f"FAMILY-LEAK-{family}")
        raise SystemExit(3)

left, right = socket.socketpair()
left.close()
right.close()
print("families-blocked-unix-ok")
"#;

const PY_ALLOWLIST_FAMILY_PROBE: &str = r#"import errno
import socket

# FULL/allowlist keeps ordinary IP sockets for the loopback proxy, but must
# deny host-facing, link-layer and kernel-control families.
for family in (1, 2, 10):  # UNIX, INET, INET6
    try:
        sock = socket.socket(family, socket.SOCK_STREAM, 0)
    except OSError as error:
        print(f"UNEXPECTED-IP-BLOCK-{family}-{error.errno}")
        raise SystemExit(2)
    else:
        sock.close()

for family in (0, 16, 17, 38, 40, 44):  # UNSPEC, NETLINK, PACKET, ALG, VSOCK, XDP
    try:
        sock = socket.socket(family, socket.SOCK_STREAM, 0)
    except OSError as error:
        if error.errno != errno.EAFNOSUPPORT:
            print(f"WRONG-ERRNO-{family}-{error.errno}")
            raise SystemExit(3)
    else:
        sock.close()
        print(f"FAMILY-LEAK-{family}")
        raise SystemExit(4)

left, right = socket.socketpair()
left.close()
right.close()
print("allowlist-family-policy-ok")
"#;

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
fn net_off_full_denies_every_non_unix_socket_family() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs full tier");
        return;
    }
    if !tool_available("python3") {
        eprintln!("SKIP: python3 not installed");
        return;
    }
    let proj = TempProject::new("netoff-full-families");
    let out = run_vetto_in(
        proj.path(),
        &["--tui=none", "--", "python3", "-c", PY_FAMILY_PROBE],
    );
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "stdout: {text}; stderr: {}",
        stderr(&out)
    );
    assert!(text.contains("families-blocked-unix-ok"), "stdout: {text}");
    assert!(!text.contains("LEAK"), "stdout: {text}");
    assert!(!text.contains("WRONG-ERRNO"), "stdout: {text}");
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
fn net_off_fs_only_denies_every_non_unix_socket_family() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs full-tier machine to force fs-only");
        return;
    }
    if !tool_available("python3") {
        eprintln!("SKIP: python3 not installed");
        return;
    }
    let proj = TempProject::new("netoff-families");
    let out = run_vetto_env_in(
        proj.path(),
        &["--tui=none", "--", "python3", "-c", PY_FAMILY_PROBE],
        &[("VETTO_FORCE_TIER", "fs-only")],
    );
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "stdout: {text}; stderr: {}",
        stderr(&out)
    );
    assert!(text.contains("families-blocked-unix-ok"), "stdout: {text}");
    assert!(!text.contains("LEAK"), "stdout: {text}");
    assert!(!text.contains("WRONG-ERRNO"), "stdout: {text}");
}

#[test]
fn allowlist_socket_policy_keeps_ip_and_blocks_host_families() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: allowlist needs full tier");
        return;
    }
    if !tool_available("python3") {
        eprintln!("SKIP: python3 not installed");
        return;
    }
    let proj = TempProject::new("allowlist-families");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--net=allowlist:example.com",
            "--",
            "python3",
            "-c",
            PY_ALLOWLIST_FAMILY_PROBE,
        ],
    );
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "stdout: {text}; stderr: {}",
        stderr(&out)
    );
    assert!(
        text.contains("allowlist-family-policy-ok"),
        "stdout: {text}"
    );
    assert!(!text.contains("LEAK"), "stdout: {text}");
    assert!(!text.contains("WRONG-ERRNO"), "stdout: {text}");
    assert!(!text.contains("UNEXPECTED-IP-BLOCK"), "stdout: {text}");
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
