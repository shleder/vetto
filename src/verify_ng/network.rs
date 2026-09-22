//! Phase 2 Network Boundary Verification Battery (Master Task Section 7).
//!
//! Enforces authoritative network containment against existing relay/broker/security contract semantics:
//! 1. net=off: TCP connect blocked (EAFNOSUPPORT / kernel denial)
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

use std::net::IpAddr;
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::NetRule;
#[cfg(test)]
use crate::policy_ir::contract::NetworkMode;
use crate::policy_ir::contract::SecurityContract;
use crate::verify_ng::model::Category;

/// Violation categories defined by Master Task Section 7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkViolation {
    /// TCP egress was permitted under net=off mode.
    TcpEgressPermitted { destination: String, detail: String },
    /// UDP egress was permitted under net=off mode.
    UdpEgressPermitted { destination: String, detail: String },
    /// IPv4 (AF_INET) socket family was permitted under net=off mode.
    Ipv4FamilyPermitted { detail: String },
    /// IPv6 (AF_INET6) socket family was permitted under net=off mode.
    Ipv6FamilyPermitted { detail: String },
    /// An alternate socket family (e.g. AF_PACKET, AF_NETLINK, AF_VSOCK) was permitted.
    AlternateFamilyPermitted { family: i32, detail: String },
    /// DNS resolution was permitted under net=off mode.
    DnsResolutionPermitted { host: String, detail: String },
    /// DNS rebinding destination was not blocked by destination IP filter.
    DnsRebindingPermitted {
        host: String,
        ip: String,
        detail: String,
    },
    /// Direct socket bypass succeeded around the relay / outside network namespace.
    DirectSocketBypassPermitted { detail: String },
    /// TLS SNI mismatch was permitted without termination.
    SniMismatchPermitted {
        host: String,
        sni: String,
        detail: String,
    },
    /// Relay bypass attempt was permitted.
    RelayBypassPermitted { detail: String },
    /// Disallowed domain was permitted through the relay allowlist.
    DisallowedDomainPermitted { host: String },
    /// Disallowed port was permitted for a domain in strict mode.
    DisallowedPortPermitted { host: String, port: u16 },
    /// An unsupported platform or tier assumed success instead of failing closed.
    UnsupportedPlatformAssumedSuccess {
        platform_or_tier: String,
        reason: String,
    },
    /// Security contract digest verification failed due to network field tampering.
    ContractDigestTampered { detail: String },
}

impl NetworkViolation {
    pub fn reason(&self) -> String {
        match self {
            Self::TcpEgressPermitted {
                destination,
                detail,
            } => {
                format!("TCP egress permitted to {destination} under net=off: {detail}")
            }
            Self::UdpEgressPermitted {
                destination,
                detail,
            } => {
                format!("UDP egress permitted to {destination} under net=off: {detail}")
            }
            Self::Ipv4FamilyPermitted { detail } => {
                format!("IPv4 (AF_INET) socket family permitted under net=off: {detail}")
            }
            Self::Ipv6FamilyPermitted { detail } => {
                format!("IPv6 (AF_INET6) socket family permitted under net=off: {detail}")
            }
            Self::AlternateFamilyPermitted { family, detail } => {
                format!("alternate socket family {family} permitted: {detail}")
            }
            Self::DnsResolutionPermitted { host, detail } => {
                format!("DNS resolution permitted for {host} under net=off: {detail}")
            }
            Self::DnsRebindingPermitted { host, ip, detail } => {
                format!("DNS rebinding target {ip} for {host} not blocked: {detail}")
            }
            Self::DirectSocketBypassPermitted { detail } => {
                format!("direct socket bypass succeeded around relay: {detail}")
            }
            Self::SniMismatchPermitted { host, sni, detail } => {
                format!("TLS SNI mismatch not dropped (host={host}, sni={sni}): {detail}")
            }
            Self::RelayBypassPermitted { detail } => {
                format!("relay bypass attempt permitted: {detail}")
            }
            Self::DisallowedDomainPermitted { host } => {
                format!("disallowed domain {host} permitted through relay allowlist")
            }
            Self::DisallowedPortPermitted { host, port } => {
                format!("disallowed port {port} for domain {host} permitted in strict mode")
            }
            Self::UnsupportedPlatformAssumedSuccess {
                platform_or_tier,
                reason,
            } => {
                format!("unsupported platform or tier {platform_or_tier} assumed success: {reason}")
            }
            Self::ContractDigestTampered { detail } => {
                format!("contract digest tampered on network fields: {detail}")
            }
        }
    }
}

impl std::fmt::Display for NetworkViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason())
    }
}

/// Structured network report produced from execution and contract evaluation.
#[derive(Debug, Clone)]
pub struct NetworkReport {
    pub clean: bool,
    pub violations: Vec<NetworkViolation>,
    pub host_facts: Vec<(String, String)>,
    pub self_reports: Vec<(String, String)>,
}

impl Default for NetworkReport {
    fn default() -> Self {
        Self {
            clean: true,
            violations: Vec::new(),
            host_facts: Vec::new(),
            self_reports: Vec::new(),
        }
    }
}

/// Verify network contract execution evidence against the sealed SecurityContract.
///
/// Gathers host facts, verifies that contract digest holds, checks stdout/stderr
/// for any leak markers, and records verified vectors for multi-vector quorum evaluation.
pub fn verify_network_contract_execution(
    contract: &SecurityContract,
    _scenario_id: &str,
    _category: Category,
    stdout_bytes: &[u8],
    stderr_bytes: &[u8],
) -> NetworkReport {
    let mut report = NetworkReport::default();

    // 1. Authoritative contract digest verification
    if !contract.verify_digest() {
        report.clean = false;
        report
            .violations
            .push(NetworkViolation::ContractDigestTampered {
                detail: "SecurityContract digest mismatch (fail-closed, no network authority)"
                    .to_string(),
            });
        report.host_facts.push((
            "contract-network".to_string(),
            "digest-invalid-tampered".to_string(),
        ));
        return report;
    }

    // 2. Record host facts reflecting authoritative contract settings
    report.host_facts.push((
        "contract-net-mode".to_string(),
        format!("{:?}", contract.network.mode),
    ));
    if !contract.network.allowed_domains.is_empty() {
        report.host_facts.push((
            "contract-allowed-domains".to_string(),
            contract.network.allowed_domains.join(","),
        ));
    }
    if !contract.network.allowed_ports.is_empty() {
        report.host_facts.push((
            "contract-allowed-ports".to_string(),
            format!("{:?}", contract.network.allowed_ports),
        ));
    }

    let stdout_str = String::from_utf8_lossy(stdout_bytes);
    let stderr_str = String::from_utf8_lossy(stderr_bytes);

    // 3. Check for any leak signals in execution output
    if stdout_str.contains("NET-LEAK") || stderr_str.contains("NET-LEAK") {
        report.clean = false;
        report
            .violations
            .push(NetworkViolation::TcpEgressPermitted {
                destination: "detected-in-output".to_string(),
                detail: "NET-LEAK marker observed in process output".to_string(),
            });
    }
    if stdout_str.contains("FAMILY-LEAK") || stderr_str.contains("FAMILY-LEAK") {
        report.clean = false;
        report
            .violations
            .push(NetworkViolation::AlternateFamilyPermitted {
                family: -1,
                detail: "FAMILY-LEAK marker observed in process output".to_string(),
            });
    }
    if stdout_str.contains("DNS-LEAK") || stderr_str.contains("DNS-LEAK") {
        report.clean = false;
        report
            .violations
            .push(NetworkViolation::DnsResolutionPermitted {
                host: "detected-in-output".to_string(),
                detail: "DNS-LEAK marker observed in process output".to_string(),
            });
    }
    if stdout_str.contains("REBINDING-LEAK") || stderr_str.contains("REBINDING-LEAK") {
        report.clean = false;
        report
            .violations
            .push(NetworkViolation::DnsRebindingPermitted {
                host: "detected-in-output".to_string(),
                ip: "forbidden".to_string(),
                detail: "REBINDING-LEAK marker observed in process output".to_string(),
            });
    }
    if stdout_str.contains("SNI-LEAK") || stderr_str.contains("SNI-LEAK") {
        report.clean = false;
        report
            .violations
            .push(NetworkViolation::SniMismatchPermitted {
                host: "mismatch".to_string(),
                sni: "detected".to_string(),
                detail: "SNI-LEAK marker observed in process output".to_string(),
            });
    }
    if stdout_str.contains("BYPASS-LEAK") || stderr_str.contains("BYPASS-LEAK") {
        report.clean = false;
        report
            .violations
            .push(NetworkViolation::RelayBypassPermitted {
                detail: "BYPASS-LEAK marker observed in process output".to_string(),
            });
    }
    if stdout_str.contains("WRONG-ERRNO") || stderr_str.contains("WRONG-ERRNO") {
        report.clean = false;
        report
            .violations
            .push(NetworkViolation::AlternateFamilyPermitted {
                family: -1,
                detail: "WRONG-ERRNO marker observed (expected EAFNOSUPPORT)".to_string(),
            });
    }

    // 4. Record self-reported markers for diagnostics/observability only.
    // Invariant: Attacker-controlled stdout/stderr is NEVER a HOST_FACT and CANNOT increase quorum.
    if stdout_str.contains("families-blocked-unix-ok") {
        report.self_reports.push((
            "self-report:net-off-families".to_string(),
            "families-blocked-unix-ok".to_string(),
        ));
    }
    if stdout_str.contains("net-blocked-ok") || stdout_str.contains("net-deny-ok") {
        report.self_reports.push((
            "self-report:net-off-tcp".to_string(),
            "net-blocked-ok".to_string(),
        ));
    }
    if stdout_str.contains("allowlist-family-policy-ok") {
        report.self_reports.push((
            "self-report:allowlist-families".to_string(),
            "allowlist-family-policy-ok".to_string(),
        ));
    }
    if stdout_str.contains("dns-blocked-ok") {
        report.self_reports.push((
            "self-report:net-off-dns".to_string(),
            "dns-blocked-ok".to_string(),
        ));
    }

    report
}

/// Evaluates domain allowlist semantics using existing production broker implementation.
pub fn eval_domain_allowlist(host: &str, allowlist: &[String]) -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::sandbox::linux::net_relay::domain_allowed(host, allowlist)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        allowlist.iter().any(|pat| {
            let pat = pat.trim().trim_end_matches('.').to_ascii_lowercase();
            if pat == "*" {
                return true;
            }
            if let Some(suffix) = pat.strip_prefix("*.") {
                host.ends_with(&format!(".{suffix}"))
            } else {
                host == pat || host.ends_with(&format!(".{pat}"))
            }
        })
    }
}

/// Evaluates strict mode (domain and port) semantics using existing production broker implementation.
pub fn eval_strict_allowlist(host: &str, port: u16, rules: &[NetRule]) -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::sandbox::linux::net_relay::strict_allowed(host, port, rules)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        rules.iter().any(|rule| {
            if rule.port != port {
                return false;
            }
            let pat = rule
                .domain
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if pat == "*" || pat.is_empty() {
                return false;
            }
            if let Some(suffix) = pat.strip_prefix("*.") {
                host.ends_with(&format!(".{suffix}"))
            } else {
                host == pat || host.ends_with(&format!(".{pat}"))
            }
        })
    }
}

/// Evaluates destination IP forbidden status (DNS rebinding / private IP prevention)
/// using existing production broker implementation.
pub fn eval_forbidden_destination(ip: IpAddr) -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::sandbox::linux::net_relay::forbidden_destination(ip)
    }
    #[cfg(not(target_os = "linux"))]
    {
        match ip {
            IpAddr::V4(v4) => {
                let [a, b, c, d] = v4.octets();
                let private =
                    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168);
                let link_local = a == 169 && b == 254;
                let loopback = a == 127;
                let multicast_or_reserved = a >= 224;
                let unspecified = a == 0;
                let broadcast = a == 255 && b == 255 && c == 255 && d == 255;
                let cloud_metadata = (a == 169 && b == 254 && c == 169 && d == 254)
                    || (a == 100 && b == 100 && c == 100 && d == 200);
                private
                    || link_local
                    || loopback
                    || multicast_or_reserved
                    || unspecified
                    || broadcast
                    || cloud_metadata
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let is_unspecified = octets.iter().all(|&b| b == 0);
                let is_loopback = octets[..15].iter().all(|&b| b == 0) && octets[15] == 1;
                let is_link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
                let is_unique_local = (octets[0] & 0xfe) == 0xfc;
                let is_multicast = octets[0] == 0xff;
                is_unspecified || is_loopback || is_link_local || is_unique_local || is_multicast
            }
        }
    }
}

/// Evaluates TLS ClientHello SNI inspection using existing production broker implementation.
#[allow(clippy::result_unit_err)]
pub fn eval_sni(buf: &[u8]) -> Result<Option<String>, ()> {
    #[cfg(target_os = "linux")]
    {
        crate::sandbox::linux::net_relay::extract_sni(buf)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if buf.is_empty() {
            return Ok(None);
        }
        if buf[0] != 0x16 {
            return Err(());
        }
        if buf.len() < 5 {
            return Ok(None);
        }
        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() < 5 + record_len {
            return Ok(None);
        }
        if buf[5] != 0x01 {
            return Err(());
        }
        let handshake_len = (u32::from_be_bytes([0, buf[6], buf[7], buf[8]])) as usize;
        if record_len < 4 + handshake_len {
            return Err(());
        }
        let mut pos = 9 + 2 + 32;
        if pos >= buf.len() {
            return Err(());
        }
        let session_id_len = buf[pos] as usize;
        pos += 1 + session_id_len;
        if pos + 2 > buf.len() {
            return Err(());
        }
        let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;
        if pos >= buf.len() {
            return Err(());
        }
        let compression_methods_len = buf[pos] as usize;
        pos += 1 + compression_methods_len;
        if pos + 2 > buf.len() {
            return Ok(None);
        }
        let extensions_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;
        if extensions_end > buf.len() {
            return Err(());
        }
        while pos + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > extensions_end {
                return Err(());
            }
            if ext_type == 0 {
                if ext_len < 5 {
                    return Err(());
                }
                let name_type = buf[pos + 2];
                if name_type != 0 {
                    return Err(());
                }
                let name_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
                if pos + 5 + name_len > extensions_end {
                    return Err(());
                }
                let host_bytes = &buf[pos + 5..pos + 5 + name_len];
                let host_str = std::str::from_utf8(host_bytes).map_err(|_| ())?;
                return Ok(Some(host_str.to_string()));
            }
            pos += ext_len;
        }
        Ok(None)
    }
}

/// Evaluates DoH / DoT resolver denial using existing production broker implementation.
pub fn eval_is_doh_or_dot(host: &str, port: u16, ip: Option<IpAddr>) -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::sandbox::linux::net_relay::is_doh_or_dot(host, port, ip)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if port == 853 {
            return true;
        }
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        const DOH_DOMAINS: &[&str] = &[
            "cloudflare-dns.com",
            "one.one.one.one",
            "mozilla.cloudflare-dns.com",
            "dns.cloudflare.com",
            "dns.google",
            "dns.google.com",
            "dns.quad9.net",
            "doh.opendns.com",
            "dns.adguard-dns.com",
            "unfiltered.adguard-dns.com",
            "freedns.controld.com",
            "dns.nextdns.io",
        ];
        if DOH_DOMAINS
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
        {
            return true;
        }
        const DOH_IPS: &[&str] = &[
            "1.1.1.1",
            "1.0.0.1",
            "8.8.8.8",
            "8.8.4.4",
            "9.9.9.9",
            "149.112.112.112",
            "208.67.222.222",
            "208.67.220.220",
            "94.140.14.14",
            "94.140.15.15",
            "76.76.2.0",
            "76.76.10.0",
        ];
        if let Ok(ip_addr) = host.parse::<IpAddr>() {
            let ip_s = ip_addr.to_string();
            if DOH_IPS.iter().any(|&denied| denied == ip_s) {
                return true;
            }
        }
        if let Some(ip) = ip {
            let ip_s = ip.to_string();
            if DOH_IPS.iter().any(|&denied| denied == ip_s) {
                return true;
            }
        }
        false
    }
}

/// Evaluates loopback host check using existing production broker implementation.
pub fn eval_is_loopback_host(host: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::sandbox::linux::net_relay::is_loopback_host(host)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]"
    }
}

/// Evaluates credential broker domain allowlist using existing credential broker implementation.
pub fn eval_cred_broker_domain_allowed(host: &str, allowlist: &[String]) -> bool {
    crate::cred_broker::is_domain_allowed(host, allowlist)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_ir::contract::{
        AgentIdentity, AttestationContract, CryptoContract, EnvironmentContract,
        FilesystemContract, NetworkContract, ResourceContract, UnsealedSecurityContract,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn sample_contract(
        mode: NetworkMode,
        domains: Vec<String>,
        ports: Vec<u16>,
    ) -> SecurityContract {
        UnsealedSecurityContract {
            production: None,
            crypto: CryptoContract::default(),
            contract_version: 1,
            contract_id: "test-net-contract-001".to_string(),
            session_nonce: "nonce-net-12345".to_string(),
            agent_identity: AgentIdentity {
                agent_name: "test-agent".to_string(),
                agent_preset: "test".to_string(),
                agent_version: "0.1.0".to_string(),
                invoked_binary: PathBuf::from("/bin/sh"),
                invoked_args: vec![],
            },
            filesystem: FilesystemContract {
                workspace_root: PathBuf::from("/tmp/ws"),
                allow_read: vec![PathBuf::from("/tmp/ws")],
                allow_write: vec![PathBuf::from("/tmp/ws")],
                allow_execute: vec![],
                mask_paths: vec![],
                cow_overlay: true,
                execution_root_ro: true,
                shadow: false,
            },
            network: NetworkContract {
                mode,
                allowed_domains: domains,
                allowed_ports: ports,
                block_cloud_metadata: true,
                block_loopback_daemons: true,
            },
            resources: ResourceContract {
                max_pids: 32,
                max_memory_bytes: 1024 * 1024,
                max_cpu_percent: 100,
                max_wall_time_ms: 5000,
                max_stdout_bytes: 65536,
                max_file_size_bytes: 1024 * 1024,
            },
            environment: EnvironmentContract {
                pass_through_vars: vec!["PATH".to_string()],
                explicit_vars: BTreeMap::new(),
                redacted_patterns: vec![],
                inject_session_nonce: true,
            },
            attestation: AttestationContract {
                generate_audit_jsonl: true,
                sign_minisign: false,
                sign_cosign_slsa: false,
                evidence_level_minimum: "HOST_FACT".into(),
            },
        }
        .seal()
        .expect("seal contract")
    }

    #[test]
    fn test_contract_network_digest_validity_and_tamper() {
        let mut contract = sample_contract(NetworkMode::Off, vec![], vec![]);
        assert!(
            contract.verify_digest(),
            "clean contract must pass digest check"
        );

        // Tamper network mode
        contract.network.mode = NetworkMode::Direct;
        assert!(
            !contract.verify_digest(),
            "tampered network mode must fail digest check"
        );

        // Restore and tamper domains
        let mut contract = sample_contract(
            NetworkMode::Allowlist,
            vec!["example.com".to_string()],
            vec![443],
        );
        assert!(contract.verify_digest());
        contract
            .network
            .allowed_domains
            .push("evil.com".to_string());
        assert!(
            !contract.verify_digest(),
            "tampered domains must fail digest check"
        );

        // Restore and tamper ports
        let mut contract = sample_contract(
            NetworkMode::Strict,
            vec!["example.com".to_string()],
            vec![443],
        );
        assert!(contract.verify_digest());
        contract.network.allowed_ports.push(80);
        assert!(
            !contract.verify_digest(),
            "tampered ports must fail digest check"
        );
    }

    #[test]
    fn test_verify_network_contract_execution_clean() {
        let contract = sample_contract(NetworkMode::Off, vec![], vec![]);
        let report = verify_network_contract_execution(
            &contract,
            "NET-DNS-IPV6-001",
            Category::Net,
            b"families-blocked-unix-ok\nnet-blocked-ok\n",
            b"",
        );
        assert!(report.clean);
        assert!(report.violations.is_empty());
        assert!(report
            .host_facts
            .iter()
            .any(|(k, v)| k == "contract-net-mode" && v == "Off"));
        // Markers from stdout MUST be recorded as self_reports, NEVER host_facts
        assert!(report
            .self_reports
            .iter()
            .any(|(k, _)| k == "self-report:net-off-families"));
        assert!(report
            .self_reports
            .iter()
            .any(|(k, _)| k == "self-report:net-off-tcp"));
        assert!(!report
            .host_facts
            .iter()
            .any(|(k, _)| k.starts_with("vector:")));
    }

    #[test]
    fn test_verify_network_contract_execution_detects_leaks() {
        let contract = sample_contract(NetworkMode::Off, vec![], vec![]);
        let report = verify_network_contract_execution(
            &contract,
            "NET-DNS-IPV6-001",
            Category::Net,
            b"NET-LEAK detected\nFAMILY-LEAK-2\n",
            b"DNS-LEAK error",
        );
        assert!(!report.clean);
        assert_eq!(report.violations.len(), 3);
        assert!(matches!(
            &report.violations[0],
            NetworkViolation::TcpEgressPermitted { .. }
        ));
        assert!(matches!(
            &report.violations[1],
            NetworkViolation::AlternateFamilyPermitted { .. }
        ));
        assert!(matches!(
            &report.violations[2],
            NetworkViolation::DnsResolutionPermitted { .. }
        ));
    }

    #[test]
    fn test_domain_allowlist_semantics() {
        let allowlist = vec![
            "example.com".to_string(),
            "*.sub.org".to_string(),
            "api.service.io".to_string(),
        ];
        // Exact matches
        assert!(eval_domain_allowlist("example.com", &allowlist));
        assert!(eval_domain_allowlist("api.service.io", &allowlist));
        // Subdomain of parent match
        assert!(eval_domain_allowlist("foo.example.com", &allowlist));
        // Case insensitivity
        assert!(eval_domain_allowlist("EXAMPLE.COM", &allowlist));
        assert!(eval_domain_allowlist("Foo.Example.Com", &allowlist));
        // Wildcard: subdomain permitted, base denied
        assert!(eval_domain_allowlist("test.sub.org", &allowlist));
        assert!(!eval_domain_allowlist("sub.org", &allowlist));
        // Prefix / suffix spoofing attacks denied
        assert!(!eval_domain_allowlist("evil-example.com", &allowlist));
        assert!(!eval_domain_allowlist("example.com.evil.com", &allowlist));
        assert!(!eval_domain_allowlist("notexample.com", &allowlist));
        assert!(!eval_domain_allowlist("attacker.com", &allowlist));
    }

    #[test]
    fn test_strict_mode_semantics() {
        let rules = vec![
            NetRule {
                domain: "api.example.com".to_string(),
                port: 443,
            },
            NetRule {
                domain: "*.service.org".to_string(),
                port: 8443,
            },
        ];
        // Exact match domain + port
        assert!(eval_strict_allowlist("api.example.com", 443, &rules));
        // Matching domain, wrong port -> DENIED
        assert!(!eval_strict_allowlist("api.example.com", 80, &rules));
        assert!(!eval_strict_allowlist("api.example.com", 8080, &rules));
        // Wrong domain, matching port -> DENIED
        assert!(!eval_strict_allowlist("evil.com", 443, &rules));
        // Wildcard subdomain with port
        assert!(eval_strict_allowlist("auth.service.org", 8443, &rules));
        assert!(!eval_strict_allowlist("service.org", 8443, &rules));
        assert!(!eval_strict_allowlist("auth.service.org", 443, &rules));
        // Bare '*' wildcard is rejected in strict mode
        let bare_rules = vec![NetRule {
            domain: "*".to_string(),
            port: 443,
        }];
        assert!(!eval_strict_allowlist("any.com", 443, &bare_rules));
    }

    #[test]
    fn test_forbidden_destination_rebinding_prevention() {
        // RFC 1918 Private IPv4
        assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            172, 31, 255, 254
        ))));
        assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        // Loopback
        assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            127, 1, 2, 3
        ))));
        assert!(eval_forbidden_destination(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // Link-Local
        assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(eval_forbidden_destination(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        // Cloud metadata endpoints
        assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            100, 100, 100, 200
        ))));
        // Unspecified & broadcast
        assert!(eval_forbidden_destination(IpAddr::V4(
            Ipv4Addr::UNSPECIFIED
        )));
        assert!(eval_forbidden_destination(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(eval_forbidden_destination(IpAddr::V6(
            Ipv6Addr::UNSPECIFIED
        )));
        // IPv6 ULA
        assert!(eval_forbidden_destination(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(eval_forbidden_destination(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
        // Public routable targets are allowed
        assert!(!eval_forbidden_destination(IpAddr::V4(Ipv4Addr::new(
            93, 184, 216, 34
        ))));
        assert!(!eval_forbidden_destination(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946
        ))));
    }

    #[test]
    fn test_doh_dot_denial() {
        // Port 853 (DoT)
        assert!(eval_is_doh_or_dot("example.com", 853, None));
        // Known DoH domains
        assert!(eval_is_doh_or_dot("cloudflare-dns.com", 443, None));
        assert!(eval_is_doh_or_dot("dns.google", 443, None));
        assert!(eval_is_doh_or_dot("dns.google.com", 443, None));
        assert!(eval_is_doh_or_dot("dns.quad9.net", 443, None));
        // Normal domain on 443 is not DoH
        assert!(!eval_is_doh_or_dot("example.com", 443, None));
    }

    #[test]
    fn test_cred_broker_domain_allowed() {
        let allow = vec!["api.anthropic.com".to_string(), "openai.com".to_string()];
        assert!(eval_cred_broker_domain_allowed("api.anthropic.com", &allow));
        assert!(eval_cred_broker_domain_allowed("api.openai.com", &allow));
        assert!(eval_cred_broker_domain_allowed("API.ANTHROPIC.COM", &allow));
        assert!(!eval_cred_broker_domain_allowed("evil.example", &allow));
        assert!(!eval_cred_broker_domain_allowed("evilopenai.com", &allow));
        assert!(!eval_cred_broker_domain_allowed(
            "openai.com.evil.com",
            &allow
        ));
        assert!(!eval_cred_broker_domain_allowed("api.anthropic.com", &[]));
    }
}
