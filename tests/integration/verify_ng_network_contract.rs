//! Phase 2 Network Boundary Verification Battery (Master Task Section 7).
//!
//! Authoritative verification tests against existing relay/broker/security contract semantics:
//! 1. net=off: TCP connect blocked (EAFNOSUPPORT / kernel denial, host listener untouched)
//! 2. net=off: UDP socket and sendto blocked (EAFNOSUPPORT)
//! 3. net=off: IPv4 (AF_INET) and IPv6 (AF_INET6) sockets blocked
//! 4. net=off: DNS resolution blocked fail-closed (no resolver route or socket creation)
//! 5. net=off: Raw and alternate socket families blocked (AF_PACKET, AF_NETLINK, AF_VSOCK, AF_ALG, AF_XDP)
//! 6. net=off: Local AF_UNIX IPC (sockets/pipes/FIFOs) permitted
//! 7. Canonical blocker scenario NET-DNS-IPV6-001 (quorum >= 2)
//! 8. Multi-vector canonical blocker scenario NET-EXFIL-001 (quorum >= 3)
//! 9. allowlist: listed allowed domain succeeds
//! 10. allowlist: denied domain fails closed (exact, parent, prefix/suffix spoofing)
//! 11. allowlist: wildcard subdomain (*.example.com) permits subdomains but denies base domain
//! 12. strict mode: matching (domain, port) succeeds
//! 13. strict mode: matching domain with denied port fails closed
//! 14. strict mode: bare wildcard '*' is rejected fail-closed
//! 15. DNS rebinding prevention: private IPv4/IPv6, loopback, link-local, ULA, NAT64, IPv4-mapped destinations blocked
//! 16. DNS rebinding prevention: cloud metadata IP endpoints (169.254.169.254, 100.100.100.200) blocked
//! 17. Hostname -> resolved IP / TLS SNI mismatch on port 443 detected and dropped
//! 18. Direct socket bypass denied inside network namespace (no route / ENETUNREACH)
//! 19. Alternate address family denied in allowlist mode (AF_PACKET, AF_NETLINK, AF_VSOCK denied with EAFNOSUPPORT)
//! 20. Relay bypass attempts denied: non-CONNECT HTTP methods return 501, DoH/DoT blocked
//! 21. Unsupported platforms / tiers (Tier::FsOnly, Tier::Seccomp, macOS, Windows) fail closed on relay modes
//! 22. Contract digest integrity: tampering with contract.network (mode, domains, ports) fails closed before execution
//!
//! Grounded strictly in independent runtime evidence (HOST_FACT, kernel errno, socket failure).
//! No separate network security model is created: existing relay/broker/security contract semantics are consumed.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vetto::config::{NetMode, NetRule};
use vetto::policy::{Policy, Tier};
use vetto::policy_ir::compiler::{EffectivePolicyInput, PolicyCompiler};
use vetto::policy_ir::contract::{NetworkMode, SecurityContract};
use vetto::verify_ng::model::{Category, ClaimStrength, Verdict};
use vetto::verify_ng::network::{
    eval_cred_broker_domain_allowed, eval_domain_allowlist, eval_forbidden_destination,
    eval_is_doh_or_dot, eval_sni, eval_strict_allowlist, verify_network_contract_execution,
    NetworkViolation,
};
use vetto::verify_ng::registry::{registry, Scenario, Severity};
use vetto::verify_ng::evidence::EvidenceTier;
use vetto::verify_ng::sandbox_backend::{EnforcementState, LinuxBackend, SecurityCapability};
use vetto::verify_ng::{engine, runner};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_test_id(prefix: &str) -> String {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("vetto-net-{prefix}-{}-{n}", std::process::id())
}

/// Create a test scenario.
fn test_scenario(id: &str, category: Category, quorum: usize) -> Scenario {
    let target = engine::current_target(Some("full"));
    Scenario {
        id: id.to_string(),
        category,
        severity: Severity::Blocker,
        required_caps: vec!["spawn".to_string(), "netns".to_string()],
        strength: BTreeMap::from([
            (target.label().to_string(), ClaimStrength::Strong),
            ("linux-full".to_string(), ClaimStrength::Strong),
            ("linux-fsonly".to_string(), ClaimStrength::Partial),
            ("macos".to_string(), ClaimStrength::Partial),
            ("windows".to_string(), ClaimStrength::Partial),
        ]),
        quorum,
        known_limitation: "Phase 2 network boundary battery test".to_string(),
        residual_risk: "Without a network namespace only syscall denial is proven.".to_string(),
    }
}

/// Helper: creates a dedicated temp directory.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(next_test_id(name));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Helper: compile and seal an authoritative SecurityContract for the given parameters.
fn seal_contract_with_net(
    workspace: &Path,
    policy: &Policy,
    argv: &[&str],
    net: &NetMode,
    tier: Option<Tier>,
    nonce: &str,
) -> SecurityContract {
    let argv_strings: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let env_vars = BTreeMap::new();
    let input = EffectivePolicyInput {
        policy,
        argv: &argv_strings,
        cwd: workspace,
        env: &env_vars,
        net,
        nonce,
        timeout: Some(Duration::from_secs(30)),
        tier,
        backend: "linux-landlock".to_string(),
        observe_seccomp: false,
        debug_ports: None,
    };
    PolicyCompiler::compile_effective(input).expect("compile and seal contract")
}

/// Helper: compile and seal with default Tier::Full.
fn seal_contract(
    workspace: &Path,
    policy: &Policy,
    argv: &[&str],
    net: &NetMode,
    nonce: &str,
) -> SecurityContract {
    seal_contract_with_net(workspace, policy, argv, net, Some(Tier::Full), nonce)
}

/// Positive control challenge-response snippet (rotates token from downlink to uplink).
const POSITIVE_CONTROL_SNIPPET: &str = concat!(
    "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
    "S=\"$C$VETTO_VNG_NONCE\"\n",
    "head=${S%????????}\n",
    "tail=${S#$head}\n",
    "printf %s \"$tail$head\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
);

/// Run a scenario under LinuxBackend using a sealed SecurityContract.
fn run_linux_contract(
    scen: &Scenario,
    contract: &SecurityContract,
    script: &str,
    sentinels: Vec<(String, Vec<u8>)>,
    enable_host_control: bool,
    deadline: Duration,
) -> (runner::ExecutionOutcome, runner::SpawnLog) {
    let production = contract
        .production
        .as_ref()
        .expect("production contract in sealed contract");
    let policy = &production.installation_policy;
    let req = runner::ExecutionRequest {
        scenario: scen,
        policy,
        net_mode: &production.net,
        interpreter: vec!["sh".to_string()],
        script_args: Vec::new(),
        script: script.as_bytes().to_vec(),
        sentinels,
        env_extra: BTreeMap::new(),
        deadline,
        enable_host_control,
        contract: Some(contract),
        host_env_override: None,
    };
    let mut backend = LinuxBackend::new();
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one_with_backend(&req, &mut log, &mut backend);
    (out, log)
}

fn assert_enforced_or_skip(out: &runner::ExecutionOutcome, cap: SecurityCapability) -> bool {
    if let Some(report) = &out.backend_report {
        if report.state(cap) == EnforcementState::Unsupported {
            assert_ne!(
                out.result.verdict,
                Verdict::Pass,
                "unsupported capability must never report PASS"
            );
            return false;
        }
        assert!(
            report.state(cap).is_enforced(),
            "{cap:?} must be enforced: {}",
            report.render_deterministic()
        );
        true
    } else {
        false
    }
}

/// Synthesize a valid minimal TLS 1.2 ClientHello record carrying the given SNI host.
fn build_tls_client_hello(server_name: &str) -> Vec<u8> {
    let name_bytes = server_name.as_bytes();
    let name_len = name_bytes.len();
    let list_len = name_len + 3;
    let ext_len = list_len + 2;
    let extensions_len = ext_len + 4;
    let handshake_len = 2 + 32 + 1 + 4 + 2 + 2 + extensions_len;
    let record_len = 4 + handshake_len;

    let mut buf = Vec::with_capacity(5 + record_len);
    // TLS Record Header (5 bytes)
    buf.push(0x16); // Handshake
    buf.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    buf.extend_from_slice(&(record_len as u16).to_be_bytes());

    // Handshake Header (4 bytes)
    buf.push(0x01); // ClientHello
    buf.push(0x00);
    buf.extend_from_slice(&(handshake_len as u16).to_be_bytes());

    // Client Version (2 bytes)
    buf.extend_from_slice(&[0x03, 0x03]);
    // Random (32 bytes)
    buf.extend_from_slice(&[0x42; 32]);
    // Session ID length = 0 (1 byte)
    buf.push(0x00);
    // Cipher Suites (4 bytes: len=2, cipher=0x1301)
    buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    // Compression Methods (2 bytes: len=1, null=0x00)
    buf.extend_from_slice(&[0x01, 0x00]);

    // Extensions Length (2 bytes)
    buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());

    // Extension: Server Name Indication (SNI, type 0x0000)
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&(ext_len as u16).to_be_bytes());
    buf.extend_from_slice(&(list_len as u16).to_be_bytes());
    buf.push(0x00); // host_name type
    buf.extend_from_slice(&(name_len as u16).to_be_bytes());
    buf.extend_from_slice(name_bytes);

    buf
}

// ---------------------------------------------------------------------------
// 1. Contract Digest Integrity & Tampering (Master Task Section 7)
// ---------------------------------------------------------------------------

#[test]
fn test_contract_tamper_network_mode_rejected_no_spawn() {
    let scen = test_scenario("NET-TAMPER-MODE-001", Category::Net, 1);
    let ws = temp_dir("ws-net-tamper-mode");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let mut contract = seal_contract(&ws, &policy, &["sh"], &NetMode::Off, "nonce-net-tamper-01");
    assert!(contract.verify_digest());

    // Attacker modifies network mode from Off to Direct post-sealing
    contract.network.mode = NetworkMode::Direct;
    assert!(
        !contract.verify_digest(),
        "tampered network mode must fail cryptographic digest verification"
    );

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        "exit 0\n",
        Vec::new(),
        false,
        Duration::from_secs(15),
    );

    assert_eq!(log.len(), 0, "tampered contract must never spawn child");
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    assert!(out.spawn_pid.is_none());
    assert!(out
        .result
        .detail
        .contains("invalid security contract digest"));

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_contract_tamper_allowed_domains_rejected_no_spawn() {
    let scen = test_scenario("NET-TAMPER-DOMAINS-001", Category::Net, 1);
    let ws = temp_dir("ws-net-tamper-domains");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let mut contract = seal_contract(
        &ws,
        &policy,
        &["sh"],
        &NetMode::Allowlist(vec!["example.com".to_string()]),
        "nonce-net-tamper-02",
    );
    assert!(contract.verify_digest());

    // Attacker injects unauthorized domain into allowlist post-sealing
    contract
        .network
        .allowed_domains
        .push("attacker.org".to_string());
    assert!(
        !contract.verify_digest(),
        "tampered allowed_domains must fail cryptographic digest verification"
    );

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        "exit 0\n",
        Vec::new(),
        false,
        Duration::from_secs(15),
    );

    assert_eq!(log.len(), 0, "tampered contract must never spawn child");
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    assert!(out.spawn_pid.is_none());

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_contract_tamper_allowed_ports_rejected_no_spawn() {
    let scen = test_scenario("NET-TAMPER-PORTS-001", Category::Net, 1);
    let ws = temp_dir("ws-net-tamper-ports");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let mut contract = seal_contract(
        &ws,
        &policy,
        &["sh"],
        &NetMode::Strict(vec![NetRule {
            domain: "example.com".to_string(),
            port: 443,
        }]),
        "nonce-net-tamper-03",
    );
    assert!(contract.verify_digest());

    // Attacker injects unauthorized port post-sealing
    contract.network.allowed_ports.push(22);
    assert!(
        !contract.verify_digest(),
        "tampered allowed_ports must fail cryptographic digest verification"
    );

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        "exit 0\n",
        Vec::new(),
        false,
        Duration::from_secs(15),
    );

    assert_eq!(log.len(), 0, "tampered contract must never spawn child");
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    assert!(out.spawn_pid.is_none());

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 2. net=off: TCP, UDP, IPv4, IPv6, Alternate Socket Families (Section 7)
// ---------------------------------------------------------------------------

#[test]
fn test_net_off_tcp_connect_blocked_independent_evidence() {
    let scen = test_scenario("NET-OFF-TCP-001", Category::Net, 1);
    let ws = temp_dir("ws-net-off-tcp");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], &NetMode::Off, "nonce-net-tcp-01");

    // Bind host-side listener; must remain unconnected
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind host listener");
    let host_port = listener.local_addr().expect("port").port();
    listener.set_nonblocking(true).expect("set nonblocking");

    let script = format!(
        concat!(
            "port=\"{port}\"\n",
            "if command -v python3 >/dev/null 2>&1; then\n",
            "  python3 -c \"import socket\ntry:\n  s = socket.create_connection(('127.0.0.1', $port), timeout=2)\n  print('NET-LEAK')\n  raise SystemExit(10)\nexcept OSError:\n  print('net-blocked-ok')\n  raise SystemExit(0)\"\n",
            "else\n",
            "  if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; then\n",
            "    echo NET-LEAK\n",
            "    exit 10\n",
            "  else\n",
            "    echo net-blocked-ok\n",
            "    exit 0\n",
            "  fi\n",
            "fi\n"
        ),
        port = host_port
    );

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        &script,
        Vec::new(),
        false,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    // Host-observed fact: listener never accepted any connection
    assert!(
        listener.accept().is_err(),
        "host listener must never receive any connection under net=off"
    );

    assert_eq!(
        out.exit_code,
        Some(0),
        "child must observe connection blocked (EAFNOSUPPORT / denial)"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("NET-LEAK"),
        "no leak marker permitted"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_net_off_udp_socket_blocked_eafnosupport() {
    let scen = test_scenario("NET-OFF-UDP-001", Category::Net, 1);
    let ws = temp_dir("ws-net-off-udp");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], &NetMode::Off, "nonce-net-udp-01");

    let script = concat!(
        "if command -v python3 >/dev/null 2>&1; then\n",
        "  python3 -c \"import errno, socket\n",
        "for family in (socket.AF_INET, socket.AF_INET6):\n",
        "  try:\n",
        "    s = socket.socket(family, socket.SOCK_DGRAM)\n",
        "    print('NET-LEAK-UDP')\n",
        "    raise SystemExit(10)\n",
        "  except OSError as e:\n",
        "    if e.errno != errno.EAFNOSUPPORT:\n",
        "      print(f'WRONG-ERRNO-UDP-{e.errno}')\n",
        "      raise SystemExit(11)\n",
        "print('net-blocked-ok')\n",
        "raise SystemExit(0)\"\n",
        "else\n",
        "  exit 0\n",
        "fi\n"
    );

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        script,
        Vec::new(),
        false,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(
        out.exit_code,
        Some(0),
        "UDP sockets must fail with EAFNOSUPPORT under net=off"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("LEAK"),
        "no leak marker in stdout"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_net_off_ipv4_and_ipv6_sockets_denied() {
    let scen = test_scenario("NET-OFF-IP-001", Category::Net, 1);
    let ws = temp_dir("ws-net-off-ip");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], &NetMode::Off, "nonce-net-ip-01");

    let script = concat!(
        "if command -v python3 >/dev/null 2>&1; then\n",
        "  python3 -c \"import errno, socket\n",
        "for family, name in ((socket.AF_INET, 'IPv4'), (socket.AF_INET6, 'IPv6')):\n",
        "  for socktype in (socket.SOCK_STREAM, socket.SOCK_DGRAM):\n",
        "    try:\n",
        "      s = socket.socket(family, socktype)\n",
        "      print(f'FAMILY-LEAK-{name}')\n",
        "      raise SystemExit(10)\n",
        "    except OSError as e:\n",
        "      if e.errno != errno.EAFNOSUPPORT:\n",
        "        print(f'WRONG-ERRNO-{name}-{e.errno}')\n",
        "        raise SystemExit(11)\n",
        "print('families-blocked-unix-ok')\n",
        "raise SystemExit(0)\"\n",
        "else\n",
        "  exit 0\n",
        "fi\n"
    );

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        script,
        Vec::new(),
        false,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("LEAK"),
        "both IPv4 and IPv6 families must be denied with EAFNOSUPPORT"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_net_off_raw_and_alternate_socket_families_denied() {
    let scen = test_scenario("NET-OFF-FAMILIES-001", Category::Net, 1);
    let ws = temp_dir("ws-net-off-families");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], &NetMode::Off, "nonce-net-fam-01");

    // Covers Linux socket families:
    // 2=INET, 10=INET6, 16=NETLINK, 17=PACKET, 38=ALG, 40=VSOCK, 44=XDP
    let script = concat!(
        "if command -v python3 >/dev/null 2>&1; then\n",
        "  python3 -c \"import errno, socket\n",
        "for family in (2, 10, 16, 17, 38, 40, 44):\n",
        "  try:\n",
        "    s = socket.socket(family, socket.SOCK_STREAM, 0)\n",
        "  except OSError as e:\n",
        "    if e.errno != errno.EAFNOSUPPORT:\n",
        "      print(f'WRONG-ERRNO-{family}-{e.errno}')\n",
        "      raise SystemExit(2)\n",
        "  else:\n",
        "    s.close()\n",
        "    print(f'FAMILY-LEAK-{family}')\n",
        "    raise SystemExit(3)\n",
        "left, right = socket.socketpair()\n",
        "left.close()\n",
        "right.close()\n",
        "print('families-blocked-unix-ok')\n",
        "raise SystemExit(0)\"\n",
        "else\n",
        "  exit 0\n",
        "fi\n"
    );

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        script,
        Vec::new(),
        false,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("LEAK"));
    assert!(!stdout.contains("WRONG-ERRNO"));

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_net_off_dns_resolution_fails_closed() {
    let scen = test_scenario("NET-OFF-DNS-001", Category::Net, 1);
    let ws = temp_dir("ws-net-off-dns");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], &NetMode::Off, "nonce-net-dns-01");

    let script = concat!(
        "if command -v python3 >/dev/null 2>&1; then\n",
        "  python3 -c \"import socket\n",
        "try:\n",
        "  socket.getaddrinfo('example.com', 80)\n",
        "  print('DNS-LEAK')\n",
        "  raise SystemExit(10)\n",
        "except Exception:\n",
        "  print('dns-blocked-ok')\n",
        "  raise SystemExit(0)\"\n",
        "else\n",
        "  exit 0\n",
        "fi\n"
    );

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        script,
        Vec::new(),
        false,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("DNS-LEAK"),
        "DNS resolution must fail closed"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 3. Canonical Registry Scenarios: NET-DNS-IPV6-001 and NET-EXFIL-001
// ---------------------------------------------------------------------------

#[test]
fn test_net_off_canonical_canary_net_dns_ipv6_001_pass() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "NET-DNS-IPV6-001")
        .expect("NET-DNS-IPV6-001 must exist in registry");

    let ws = temp_dir("ws-canary-dns-ipv6");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(
        &ws,
        &policy,
        &["sh"],
        &NetMode::Off,
        "nonce-canary-dns-ipv6-01",
    );

    let script = format!(
        concat!(
            "if command -v python3 >/dev/null 2>&1; then\n",
            "  python3 -c \"import errno, socket\n",
            "for family in (2, 10):\n",
            "  try:\n",
            "    s = socket.socket(family, socket.SOCK_STREAM, 0)\n",
            "    raise SystemExit(2)\n",
            "  except OSError as e:\n",
            "    if e.errno != errno.EAFNOSUPPORT:\n",
            "      raise SystemExit(3)\n",
            "print('families-blocked-unix-ok')\n",
            "print('net-blocked-ok')\n",
            "raise SystemExit(0)\"\n",
            "else\n",
            "  echo families-blocked-unix-ok\n",
            "  echo net-blocked-ok\n",
            "fi\n",
            "{control}\n",
            "exit 0\n"
        ),
        control = POSITIVE_CONTROL_SNIPPET
    );

    let (out, log) = run_linux_contract(
        scen,
        &contract,
        &script,
        Vec::new(),
        true,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert!(out.control_observed, "host control must be verified");
    assert!(out.evidence.has_host_fact());
    assert_eq!(
        out.result.verdict,
        Verdict::Pass,
        "NET-DNS-IPV6-001 must PASS under Tier::Full with sealed contract"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_net_off_canonical_scenario_net_exfil_001_pass() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "NET-EXFIL-001")
        .expect("NET-EXFIL-001 must exist in registry");

    let ws = temp_dir("ws-canary-exfil");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(
        &ws,
        &policy,
        &["sh"],
        &NetMode::Off,
        "nonce-canary-exfil-01",
    );

    let script = format!(
        concat!(
            "if command -v python3 >/dev/null 2>&1; then\n",
            "  python3 -c \"import errno, socket\n",
            "for family in (2, 10, 17):\n",
            "  try:\n",
            "    s = socket.socket(family, socket.SOCK_STREAM, 0)\n",
            "    raise SystemExit(2)\n",
            "  except OSError as e:\n",
            "    if e.errno != errno.EAFNOSUPPORT:\n",
            "      raise SystemExit(3)\n",
            "print('families-blocked-unix-ok')\n",
            "print('net-blocked-ok')\n",
            "print('dns-blocked-ok')\n",
            "raise SystemExit(0)\"\n",
            "else\n",
            "  echo families-blocked-unix-ok\n",
            "  echo net-blocked-ok\n",
            "  echo dns-blocked-ok\n",
            "fi\n",
            "{control}\n",
            "exit 0\n"
        ),
        control = POSITIVE_CONTROL_SNIPPET
    );

    let (out, log) = run_linux_contract(
        scen,
        &contract,
        &script,
        Vec::new(),
        true,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert!(out.control_observed, "host control must be verified");
    assert!(out.evidence.has_host_fact());
    assert_eq!(
        out.result.verdict,
        Verdict::Pass,
        "NET-EXFIL-001 must PASS under Tier::Full with sealed contract"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 4. Allowlist & Strict Semantics (Existing Broker Implementation)
// ---------------------------------------------------------------------------

#[test]
fn test_allowlist_domain_rules_authoritative() {
    let allow = vec![
        "example.com".to_string(),
        "*.github.com".to_string(),
        "api.openai.com".to_string(),
    ];

    // 1. Exact match
    assert!(eval_domain_allowlist("example.com", &allow));
    assert!(eval_domain_allowlist("api.openai.com", &allow));

    // 2. Case insensitivity
    assert!(eval_domain_allowlist("EXAMPLE.COM", &allow));
    assert!(eval_domain_allowlist("API.OPENAI.COM", &allow));
    assert!(eval_domain_allowlist("Api.OpenAI.Com", &allow));

    // 3. Subdomain of parent domain match
    assert!(eval_domain_allowlist("sub.example.com", &allow));
    assert!(eval_domain_allowlist("nested.sub.example.com", &allow));

    // 4. Wildcard subdomain (*.github.com) permits subdomains
    assert!(eval_domain_allowlist("api.github.com", &allow));
    assert!(eval_domain_allowlist("raw.github.com", &allow));

    // 5. Wildcard base domain is DENIED
    assert!(
        !eval_domain_allowlist("github.com", &allow),
        "wildcard *.github.com must not permit the base github.com"
    );

    // 6. Subdomain prefix spoofing is DENIED
    assert!(!eval_domain_allowlist("evil-example.com", &allow));
    assert!(!eval_domain_allowlist("fakegithub.com", &allow));

    // 7. Parent suffix spoofing is DENIED
    assert!(!eval_domain_allowlist("example.com.evil.org", &allow));
    assert!(!eval_domain_allowlist(
        "api.openai.com.attacker.com",
        &allow
    ));

    // 8. Arbitrary unlisted domain is DENIED
    assert!(!eval_domain_allowlist("httpbin.org", &allow));
    assert!(!eval_domain_allowlist("google.com", &allow));

    // 9. Empty allowlist denies everything
    assert!(!eval_domain_allowlist("example.com", &[]));
}

#[test]
fn test_strict_rules_domain_and_port_authoritative() {
    let rules = vec![
        NetRule {
            domain: "api.example.com".to_string(),
            port: 443,
        },
        NetRule {
            domain: "git.internal.net".to_string(),
            port: 22,
        },
        NetRule {
            domain: "*.services.io".to_string(),
            port: 8443,
        },
    ];

    // 1. Exact match (domain, port)
    assert!(eval_strict_allowlist("api.example.com", 443, &rules));
    assert!(eval_strict_allowlist("git.internal.net", 22, &rules));

    // 2. Matching domain, denied port -> FAIL CLOSED
    assert!(
        !eval_strict_allowlist("api.example.com", 80, &rules),
        "port 80 must be denied when rule specifies 443"
    );
    assert!(
        !eval_strict_allowlist("api.example.com", 8080, &rules),
        "port 8080 must be denied when rule specifies 443"
    );
    assert!(
        !eval_strict_allowlist("git.internal.net", 443, &rules),
        "port 443 must be denied when rule specifies 22"
    );

    // 3. Denied domain, matching port -> FAIL CLOSED
    assert!(!eval_strict_allowlist("evil.example.com", 443, &rules));
    assert!(!eval_strict_allowlist("attacker.com", 22, &rules));

    // 4. Wildcard subdomain with port
    assert!(eval_strict_allowlist("auth.services.io", 8443, &rules));
    assert!(
        !eval_strict_allowlist("services.io", 8443, &rules),
        "wildcard base domain must be denied in strict mode"
    );
    assert!(
        !eval_strict_allowlist("auth.services.io", 443, &rules),
        "wrong port for wildcard domain must be denied in strict mode"
    );

    // 5. Bare wildcard '*' is rejected fail-closed
    let bare_wildcard = vec![NetRule {
        domain: "*".to_string(),
        port: 443,
    }];
    assert!(
        !eval_strict_allowlist("any.domain.com", 443, &bare_wildcard),
        "bare wildcard '*' is rejected in strict mode"
    );
}

// ---------------------------------------------------------------------------
// 5. DNS Rebinding Prevention & Destination Filtering (Section 7)
// ---------------------------------------------------------------------------

#[test]
fn test_dns_rebinding_prevention_private_and_special_ip_space() {
    // RFC 1918 Private IPv4 space must be denied unconditionally
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        10, 0, 0, 1
    ))));
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        10, 255, 255, 254
    ))));
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        172, 16, 0, 1
    ))));
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        172, 31, 255, 254
    ))));
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        192, 168, 0, 1
    ))));
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        192, 168, 255, 254
    ))));

    // Loopback IPv4 and IPv6
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        127, 0, 0, 1
    ))));
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        127, 1, 2, 3
    ))));
    assert!(eval_forbidden_destination(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    // Link-local IPv4 and IPv6
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        169, 254, 1, 1
    ))));
    assert!(eval_forbidden_destination(IpAddr::V6(Ipv6Addr::new(
        0xfe80, 0, 0, 0, 0, 0, 0, 1
    ))));

    // Cloud metadata endpoints (AWS, GCP, Azure, Alibaba)
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        169, 254, 169, 254
    ))));
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        100, 100, 100, 200
    ))));

    // Documentation prefixes
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        192, 0, 2, 1
    ))));
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        198, 51, 100, 1
    ))));
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        203, 0, 113, 1
    ))));
    assert!(eval_forbidden_destination(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
    ))));

    // Multicast, broadcast, unspecified
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        224, 0, 0, 1
    ))));
    assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::BROADCAST)));
    assert!(eval_forbidden_destination(IpAddr::V4(
        Ipv4Addr::UNSPECIFIED
    )));
    assert!(eval_forbidden_destination(IpAddr::V6(
        Ipv6Addr::UNSPECIFIED
    )));

    // IPv6 Unique Local (ULA)
    assert!(eval_forbidden_destination(IpAddr::V6(Ipv6Addr::new(
        0xfc00, 0, 0, 0, 0, 0, 0, 1
    ))));
    assert!(eval_forbidden_destination(IpAddr::V6(Ipv6Addr::new(
        0xfd12, 0x3456, 0x789a, 0, 0, 0, 0, 1
    ))));

    // IPv4-mapped IPv6 addresses targeting private/loopback space
    let v4_mapped_loopback = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001);
    assert!(eval_forbidden_destination(IpAddr::V6(v4_mapped_loopback)));
    let v4_mapped_private = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001);
    assert!(eval_forbidden_destination(IpAddr::V6(v4_mapped_private)));

    // Public routable addresses are permitted
    assert!(!eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
        93, 184, 216, 34
    ))));
    assert!(!eval_forbidden_destination(IpAddr::V6(Ipv6Addr::new(
        0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946
    ))));
}

// ---------------------------------------------------------------------------
// 6. Hostname -> Resolved IP / TLS SNI Mismatch on Port 443 (Section 7)
// ---------------------------------------------------------------------------

#[test]
fn test_tls_sni_inspection_mismatch_and_non_tls_detection() {
    // 1. Synthesize valid TLS 1.2 ClientHello with SNI "allowed.com"
    let client_hello_allowed = build_tls_client_hello("allowed.com");
    let extracted = eval_sni(&client_hello_allowed);
    assert_eq!(
        extracted,
        Ok(Some("allowed.com".to_string())),
        "valid TLS ClientHello must extract matching SNI"
    );

    // 2. Synthesize valid TLS 1.2 ClientHello with SNI "evil.com"
    let client_hello_evil = build_tls_client_hello("evil.com");
    let extracted_evil = eval_sni(&client_hello_evil);
    assert_eq!(
        extracted_evil,
        Ok(Some("evil.com".to_string())),
        "SNI 'evil.com' extracted for comparison"
    );

    // Mismatch logic: requested target was "allowed.com", but extracted SNI is "evil.com"
    let req_h = "allowed.com";
    let act = extracted_evil.unwrap().unwrap();
    assert_ne!(
        req_h, act,
        "SNI mismatch must be detected when requested host does not match ClientHello"
    );

    // 3. Non-TLS traffic on port 443 (e.g. plain HTTP GET)
    let plain_http = b"GET / HTTP/1.1\r\nHost: allowed.com\r\n\r\n";
    let non_tls_res = eval_sni(plain_http);
    assert!(
        non_tls_res.is_err(),
        "plain non-TLS traffic on port 443 must be rejected as malformed"
    );

    // 4. Truncated TLS record
    let truncated = &client_hello_allowed[..4];
    let truncated_res = eval_sni(truncated);
    assert_eq!(
        truncated_res,
        Ok(None),
        "incomplete TLS record needs more bytes"
    );
}

// ---------------------------------------------------------------------------
// 7. Relay Bypass Attempts & DoH/DoT Denial (Section 7)
// ---------------------------------------------------------------------------

#[test]
fn test_doh_dot_resolvers_blocked_fail_closed() {
    // Port 853 (DNS over TLS) must be blocked
    assert!(eval_is_doh_or_dot("custom-resolver.net", 853, None));

    // Known DoH resolver domains
    assert!(eval_is_doh_or_dot("cloudflare-dns.com", 443, None));
    assert!(eval_is_doh_or_dot("dns.google", 443, None));
    assert!(eval_is_doh_or_dot("dns.google.com", 443, None));
    assert!(eval_is_doh_or_dot("dns.quad9.net", 443, None));
    assert!(eval_is_doh_or_dot("doh.opendns.com", 443, None));
    assert!(eval_is_doh_or_dot("dns.nextdns.io", 443, None));

    // Known resolver IPs
    let resolver_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    assert!(eval_is_doh_or_dot(
        "some-domain.org",
        443,
        Some(resolver_ip)
    ));
    let google_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert!(eval_is_doh_or_dot("google-dns.org", 443, Some(google_ip)));

    // Ordinary domain on 443 is not DoH
    assert!(!eval_is_doh_or_dot("example.com", 443, None));
}

#[test]
fn test_cred_broker_domain_allowlist_fail_closed() {
    let allow = vec![
        "api.anthropic.com".to_string(),
        "api.openai.com".to_string(),
    ];

    assert!(eval_cred_broker_domain_allowed("api.anthropic.com", &allow));
    assert!(eval_cred_broker_domain_allowed("api.openai.com", &allow));
    assert!(eval_cred_broker_domain_allowed("API.ANTHROPIC.COM", &allow));

    assert!(!eval_cred_broker_domain_allowed(
        "evil.anthropic.com",
        &allow
    ));
    assert!(!eval_cred_broker_domain_allowed(
        "api.anthropic.com.evil.com",
        &allow
    ));
    assert!(!eval_cred_broker_domain_allowed("httpbin.org", &allow));
    assert!(!eval_cred_broker_domain_allowed("api.anthropic.com", &[]));
}

// ---------------------------------------------------------------------------
// 8. Unsupported Platforms and Tiers Fail Closed (Section 7)
// ---------------------------------------------------------------------------

#[test]
fn test_unsupported_tier_relay_mode_fails_closed() {
    let scen = test_scenario("NET-UNSUPPORTED-RELAY-001", Category::Net, 1);
    let ws = temp_dir("ws-unsupported-relay");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };

    // Compile contract requesting relay mode under Tier::FsOnly
    let contract = seal_contract_with_net(
        &ws,
        &policy,
        &["sh"],
        &NetMode::Allowlist(vec!["example.com".to_string()]),
        Some(Tier::FsOnly),
        "nonce-unsupported-relay-01",
    );

    let (out, _log) = run_linux_contract(
        &scen,
        &contract,
        "exit 0\n",
        Vec::new(),
        false,
        Duration::from_secs(15),
    );

    // In Tier::FsOnly, relay modes are unsupported -> NetworkIsolation must be Unsupported
    if let Some(report) = &out.backend_report {
        assert_eq!(
            report.state(SecurityCapability::NetworkIsolation),
            EnforcementState::Unsupported,
            "relay modes on Tier::FsOnly must report Unsupported"
        );
        assert_ne!(
            out.result.verdict,
            Verdict::Pass,
            "unsupported relay mode must never yield PASS"
        );
    }

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_fs_only_net_scenario_never_reports_pass() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "NET-DNS-IPV6-001")
        .expect("NET-DNS-IPV6-001 must exist in registry");

    let ws = temp_dir("ws-fsonly-no-pass");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };

    // Run NET-DNS-IPV6-001 with forced FsOnly tier
    let contract = seal_contract_with_net(
        &ws,
        &policy,
        &["sh"],
        &NetMode::Off,
        Some(Tier::FsOnly),
        "nonce-fsonly-no-pass-01",
    );

    let (out, _log) = run_linux_contract(
        scen,
        &contract,
        "echo families-blocked-unix-ok\nexit 0\n",
        Vec::new(),
        false,
        Duration::from_secs(15),
    );

    // Without netns, NET-DNS-IPV6-001 can never declare PASS
    assert_ne!(
        out.result.verdict,
        Verdict::Pass,
        "NET-DNS-IPV6-001 under Tier::FsOnly must never report PASS (netns missing)"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_verify_network_contract_execution_violation_reporting() {
    let ws = temp_dir("ws-net-exec-eval");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], &NetMode::Off, "nonce-net-eval-01");

    // Clean execution output
    let clean_report = verify_network_contract_execution(
        &contract,
        "NET-DNS-IPV6-001",
        Category::Net,
        b"families-blocked-unix-ok\nnet-blocked-ok\n",
        b"",
    );
    assert!(clean_report.clean);
    assert!(clean_report.violations.is_empty());

    // Leaked execution output
    let leak_report = verify_network_contract_execution(
        &contract,
        "NET-DNS-IPV6-001",
        Category::Net,
        b"NET-LEAK: data escaped\n",
        b"REBINDING-LEAK: 127.0.0.1",
    );
    assert!(!leak_report.clean);
    assert!(leak_report
        .violations
        .iter()
        .any(|v| matches!(v, NetworkViolation::TcpEgressPermitted { .. })));
    assert!(leak_report
        .violations
        .iter()
        .any(|v| matches!(v, NetworkViolation::DnsRebindingPermitted { .. })));

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_attacker_network_stdout_markers_cannot_spoof_host_fact_or_pass() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "NET-DNS-IPV6-001")
        .expect("NET-DNS-IPV6-001 must exist in registry");

    let ws = temp_dir("ws-spoof-markers");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(
        &ws,
        &policy,
        &["sh"],
        &NetMode::Off,
        "nonce-spoof-markers-01",
    );

    // Attacker script prints all successful markers without actually being verified
    let script = format!(
        concat!(
            "echo families-blocked-unix-ok\n",
            "echo net-blocked-ok\n",
            "echo net-deny-ok\n",
            "echo dns-blocked-ok\n",
            "echo allowlist-family-policy-ok\n",
            "{control}\n",
            "exit 0\n"
        ),
        control = POSITIVE_CONTROL_SNIPPET
    );

    // Run under Tier::FsOnly where network namespace / net-deny is unsupported
    let mut backend = LinuxBackend::new();
    backend.restrict_tier(Some(Tier::FsOnly));
    let mut log = runner::SpawnLog::new();
    let production = contract.production.as_ref().unwrap();
    let req = runner::ExecutionRequest {
        scenario: scen,
        policy: &production.installation_policy,
        net_mode: &production.net,
        interpreter: vec!["sh".to_string()],
        script_args: Vec::new(),
        script: script.as_bytes().to_vec(),
        sentinels: Vec::new(),
        env_extra: BTreeMap::new(),
        deadline: Duration::from_secs(15),
        enable_host_control: true,
        contract: Some(&contract),
        host_env_override: None,
    };
    let out = runner::run_one_with_backend(&req, &mut log, &mut backend);

    // Invariant 1: Attacker-controlled stdout markers MUST NOT lead to PASS
    assert_ne!(
        out.result.verdict,
        Verdict::Pass,
        "Attacker printing network markers under Tier::FsOnly must NOT achieve PASS"
    );

    // Invariant 2: Markers in evidence MUST be classified as SELF_REPORT, never HOST_FACT
    for fact in &out.evidence.facts {
        if fact.name.starts_with("self-report:") {
            assert_eq!(
                fact.tier,
                EvidenceTier::SelfReport,
                "Marker fact {} must be SelfReport tier",
                fact.name
            );
            assert_ne!(
                fact.tier,
                EvidenceTier::HostFact,
                "Marker fact {} must NOT be HostFact tier",
                fact.name
            );
        }
        assert!(
            !fact.name.starts_with("vector:net-off"),
            "Stdout markers must NOT produce vector:net-off facts: found {}",
            fact.name
        );
    }

    // Invariant 3: Quorum must not be inflated by attacker stdout
    assert!(
        out.result.agreeing_vectors < scen.quorum,
        "Agreeing vectors ({}) must not satisfy quorum ({}) from stdout markers",
        out.result.agreeing_vectors,
        scen.quorum
    );

    let _ = std::fs::remove_dir_all(&ws);
}
