//! Tunneling & Exfiltration Detector, TLS SNI & JA4 Pinning, and eBPF Socket Flow Table.
//!
//! Covers:
//! - **R2.3**: Background tunneling & exfiltration detector (`TunnelMonitorEngine`, `TunnelingToolKind`, `TunnelDetectionRule`, `TunnelDetectionAlert`, `TunnelKillAction`)
//! - **R2.6**: TLS SNI verification and JA4 certificate pinning (`TlsPinningEngine`, `Ja4Fingerprint`, `TlsPinningPolicy`, `TlsHandshakeSecurityVerdict`)
//! - **R2.10**: eBPF socket-to-PID correlation table & streaming telemetry (`EbpfFlowTable`, `SocketTelemetryRingBuffer`, `SocketPidMapping`, `LiveFlowRecord`, `FlowState`)

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ============================================================================
// R2.3: Background Tunneling & Exfiltration Detector
// ============================================================================

/// Recognized background tunneling tools and protocols.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TunnelingToolKind {
    Ngrok,
    Cloudflared,
    Localtunnel,
    Bore,
    Pinggy,
    Frp,
    Tailscale,
    Pagekite,
    SshReverseTunnel,
    Chisel,
    Rathole,
    UnknownTunneler(String),
}

/// Action to execute when a tunneling tool is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelKillAction {
    /// Terminate the spawned process immediately with SIGKILL.
    ProcessTerminatedWithSigKill,
    /// Drop the network connection without killing process.
    ConnectionDropped,
    /// Record the event in security audit log only.
    AuditLoggedOnly,
    /// Suspend the entire sandbox session.
    SandboxSuspended,
}

/// Alert emitted upon detection of unauthorized tunneling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelDetectionAlert {
    pub pid: u32,
    pub binary_path: PathBuf,
    pub detected_tool: TunnelingToolKind,
    pub trigger_reason: String,
    pub remote_address: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub action_taken: TunnelKillAction,
}

/// Detection rule specification for a tunneling utility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelDetectionRule {
    pub tool: TunnelingToolKind,
    pub binary_names: Vec<String>,
    pub cli_signatures: Vec<String>,
    pub outbound_domains: Vec<String>,
    pub default_action: TunnelKillAction,
}

/// Background Tunnel Monitor Engine.
pub struct TunnelMonitorEngine {
    rules: Vec<TunnelDetectionRule>,
    domain_to_tool: HashMap<String, (TunnelingToolKind, TunnelKillAction)>,
}

impl Default for TunnelMonitorEngine {
    fn default() -> Self {
        let rules = vec![
            TunnelDetectionRule {
                tool: TunnelingToolKind::Ngrok,
                binary_names: vec!["ngrok".to_string(), "ngrok.exe".to_string()],
                cli_signatures: vec!["http".to_string(), "tcp".to_string(), "start".to_string(), "tunnel".to_string()],
                outbound_domains: vec![
                    "ngrok.io".to_string(),
                    "ngrok-free.app".to_string(),
                    "ngrok.com".to_string(),
                    "tunnel.ngrok.com".to_string(),
                ],
                default_action: TunnelKillAction::ProcessTerminatedWithSigKill,
            },
            TunnelDetectionRule {
                tool: TunnelingToolKind::Cloudflared,
                binary_names: vec!["cloudflared".to_string(), "cloudflared.exe".to_string()],
                cli_signatures: vec!["tunnel".to_string(), "run".to_string(), "--url".to_string()],
                outbound_domains: vec![
                    "trycloudflare.com".to_string(),
                    "argotunnel.com".to_string(),
                    "cftunnel.com".to_string(),
                ],
                default_action: TunnelKillAction::ProcessTerminatedWithSigKill,
            },
            TunnelDetectionRule {
                tool: TunnelingToolKind::Localtunnel,
                binary_names: vec!["lt".to_string(), "localtunnel".to_string()],
                cli_signatures: vec!["--port".to_string(), "-p".to_string(), "--subdomain".to_string()],
                outbound_domains: vec!["localtunnel.me".to_string()],
                default_action: TunnelKillAction::ProcessTerminatedWithSigKill,
            },
            TunnelDetectionRule {
                tool: TunnelingToolKind::Bore,
                binary_names: vec!["bore".to_string(), "bore.exe".to_string()],
                cli_signatures: vec!["local".to_string(), "--to".to_string()],
                outbound_domains: vec!["bore.pub".to_string()],
                default_action: TunnelKillAction::ProcessTerminatedWithSigKill,
            },
            TunnelDetectionRule {
                tool: TunnelingToolKind::Pinggy,
                binary_names: vec!["pinggy".to_string()],
                cli_signatures: vec!["-R".to_string(), "a.pinggy.io".to_string()],
                outbound_domains: vec!["pinggy.io".to_string(), "a.pinggy.io".to_string()],
                default_action: TunnelKillAction::ProcessTerminatedWithSigKill,
            },
            TunnelDetectionRule {
                tool: TunnelingToolKind::SshReverseTunnel,
                binary_names: vec!["ssh".to_string()],
                cli_signatures: vec!["-R".to_string(), "-N".to_string(), "-f".to_string()],
                outbound_domains: vec![],
                default_action: TunnelKillAction::ProcessTerminatedWithSigKill,
            },
            TunnelDetectionRule {
                tool: TunnelingToolKind::Chisel,
                binary_names: vec!["chisel".to_string(), "chisel.exe".to_string()],
                cli_signatures: vec!["client".to_string(), "server".to_string(), "R:".to_string()],
                outbound_domains: vec![],
                default_action: TunnelKillAction::ProcessTerminatedWithSigKill,
            },
            TunnelDetectionRule {
                tool: TunnelingToolKind::Frp,
                binary_names: vec!["frpc".to_string(), "frpc.exe".to_string()],
                cli_signatures: vec!["-c".to_string(), "frpc.ini".to_string()],
                outbound_domains: vec![],
                default_action: TunnelKillAction::ProcessTerminatedWithSigKill,
            },
        ];

        let mut domain_to_tool = HashMap::new();
        for r in &rules {
            for d in &r.outbound_domains {
                domain_to_tool.insert(d.to_lowercase(), (r.tool.clone(), r.default_action));
            }
        }

        Self { rules, domain_to_tool }
    }
}

impl TunnelMonitorEngine {
    /// Create new custom tunnel monitor engine.
    pub fn new(rules: Vec<TunnelDetectionRule>) -> Self {
        let mut domain_to_tool = HashMap::new();
        for r in &rules {
            for d in &r.outbound_domains {
                domain_to_tool.insert(d.to_lowercase(), (r.tool.clone(), r.default_action));
            }
        }
        Self { rules, domain_to_tool }
    }

    /// Inspect process spawn command line and binary executable path.
    pub fn inspect_process_spawn(&self, pid: u32, exe_path: &Path, argv: &[String]) -> Option<TunnelDetectionAlert> {
        let file_name = exe_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("")
            .to_lowercase();

        let joined_args = argv.join(" ").to_lowercase();

        for rule in &self.rules {
            // Check binary name matching
            let bin_matched = rule.binary_names.iter().any(|b| b.eq_ignore_ascii_case(&file_name));

            // Check CLI signature heuristics
            let sig_matched = if rule.cli_signatures.is_empty() {
                false
            } else {
                rule.cli_signatures.iter().any(|sig| joined_args.contains(&sig.to_lowercase()))
            };

            // SSH reverse port forward check (-R flag)
            if rule.tool == TunnelingToolKind::SshReverseTunnel && bin_matched {
                if argv.iter().any(|arg| arg.starts_with("-R") || arg == "-R") {
                    return Some(TunnelDetectionAlert {
                        pid,
                        binary_path: exe_path.to_path_buf(),
                        detected_tool: TunnelingToolKind::SshReverseTunnel,
                        trigger_reason: format!("Detected SSH reverse tunnel invocation: '{}'", joined_args),
                        remote_address: None,
                        timestamp: Utc::now(),
                        action_taken: rule.default_action,
                    });
                }
            }

            if bin_matched && (sig_matched || rule.tool == TunnelingToolKind::Ngrok || rule.tool == TunnelingToolKind::Cloudflared) {
                return Some(TunnelDetectionAlert {
                    pid,
                    binary_path: exe_path.to_path_buf(),
                    detected_tool: rule.tool.clone(),
                    trigger_reason: format!(
                        "Matched tunneling binary '{}' with arguments '{}'",
                        file_name, joined_args
                    ),
                    remote_address: None,
                    timestamp: Utc::now(),
                    action_taken: rule.default_action,
                });
            }
        }

        None
    }

    /// Inspect outbound TLS SNI or DNS target hostname.
    pub fn inspect_outbound_sni(&self, pid: u32, hostname: &str) -> Option<TunnelDetectionAlert> {
        let clean = hostname.split(':').next().unwrap_or(hostname).to_lowercase();

        for (domain, (tool, action)) in &self.domain_to_tool {
            if clean == *domain || clean.ends_with(&format!(".{}", domain)) {
                return Some(TunnelDetectionAlert {
                    pid,
                    binary_path: PathBuf::new(),
                    detected_tool: tool.clone(),
                    trigger_reason: format!("Outbound connection to known tunneling relay domain: '{}'", clean),
                    remote_address: Some(clean),
                    timestamp: Utc::now(),
                    action_taken: *action,
                });
            }
        }

        None
    }
}

// ============================================================================
// R2.6: TLS SNI Verification & JA4 Certificate Pinning
// ============================================================================

/// JA4 Client Fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4Fingerprint {
    pub raw_fingerprint: String,
    pub protocol: String,
    pub cipher_hash: String,
    pub extension_hash: String,
    pub alpn: String,
}

/// Security verdict for TLS Handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsHandshakeSecurityVerdict {
    AllowHandshake,
    SniHostMismatch { sni: String, host: String },
    SpkiPinMismatch { domain: String, actual_spki_sha256: [u8; 32] },
    ForbiddenJa4 { fingerprint: String, reason: String },
    MalformedClientHello(String),
}

/// TLS Policy for Pinning and Fingerprint Enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsPinningPolicy {
    pub domain_spki_pins: HashMap<String, Vec<[u8; 32]>>,
    pub allowed_ja4_fingerprints: Vec<String>,
    pub blocked_ja4_fingerprints: Vec<String>,
    pub enforce_sni_host_equality: bool,
}

impl Default for TlsPinningPolicy {
    fn default() -> Self {
        Self {
            domain_spki_pins: HashMap::new(),
            allowed_ja4_fingerprints: Vec::new(),
            blocked_ja4_fingerprints: Vec::new(),
            enforce_sni_host_equality: true,
        }
    }
}

/// Errors raised during TLS auditing.
#[derive(Debug, Error)]
pub enum TlsAuditError {
    #[error("Malformed TLS ClientHello packet: {0}")]
    MalformedClientHello(String),
    #[error("SNI Spoofing detected: SNI '{sni}' does not match HTTP Host '{host}'")]
    SniHostMismatch { sni: String, host: String },
    #[error("SPKI pinning failure for domain '{0}': certificate public key hash not pinned")]
    SpkiPinMismatch(String),
    #[error("Forbidden client JA4 fingerprint: {0}")]
    ForbiddenJa4(String),
}

/// TLS Security and Pinning Engine.
pub struct TlsPinningEngine {
    policy: RwLock<TlsPinningPolicy>,
}

impl TlsPinningEngine {
    /// Create new TLS Pinning Engine.
    pub fn new(policy: TlsPinningPolicy) -> Self {
        Self {
            policy: RwLock::new(policy),
        }
    }

    /// Parse TLS ClientHello wire bytes to extract SNI and compute JA4 fingerprint.
    pub fn parse_client_hello(&self, raw: &[u8]) -> Result<(Option<String>, Ja4Fingerprint), TlsAuditError> {
        // TLS record format: 5 bytes header [ContentType(0x16), VersionMajor(3), VersionMinor(1..3), Length(u16)]
        if raw.len() < 5 || raw[0] != 0x16 {
            return Err(TlsAuditError::MalformedClientHello("Not a TLS Handshake record".to_string()));
        }

        let record_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
        if raw.len() < 5 + record_len {
            return Err(TlsAuditError::MalformedClientHello("Truncated TLS Handshake record".to_string()));
        }

        let handshake_data = &raw[5..5 + record_len];
        if handshake_data.is_empty() || handshake_data[0] != 0x01 {
            // Handshake type 0x01 = ClientHello
            return Err(TlsAuditError::MalformedClientHello("Handshake message is not ClientHello".to_string()));
        }

        let mut offset = 4; // Skip type (1) + length (3)
        if handshake_data.len() < offset + 34 {
            return Err(TlsAuditError::MalformedClientHello("ClientHello too short".to_string()));
        }

        // Client version (2) + Random (32)
        offset += 34;

        // Session ID
        if handshake_data.len() <= offset {
            return Err(TlsAuditError::MalformedClientHello("Invalid Session ID length".to_string()));
        }
        let session_id_len = handshake_data[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher Suites
        if handshake_data.len() < offset + 2 {
            return Err(TlsAuditError::MalformedClientHello("Invalid Cipher Suites length".to_string()));
        }
        let cipher_len = u16::from_be_bytes([handshake_data[offset], handshake_data[offset + 1]]) as usize;
        offset += 2;

        if handshake_data.len() < offset + cipher_len {
            return Err(TlsAuditError::MalformedClientHello("Truncated Cipher Suites".to_string()));
        }

        let mut cipher_suites: Vec<u16> = Vec::new();
        for chunk in handshake_data[offset..offset + cipher_len].chunks_exact(2) {
            let cs = u16::from_be_bytes([chunk[0], chunk[1]]);
            // Ignore GREASE ciphers (0x?a?a)
            if (cs & 0x0f0f) != 0x0a0a {
                cipher_suites.push(cs);
            }
        }
        offset += cipher_len;

        // Compression Methods
        if handshake_data.len() <= offset {
            return Err(TlsAuditError::MalformedClientHello("Missing compression methods".to_string()));
        }
        let comp_len = handshake_data[offset] as usize;
        offset += 1 + comp_len;

        // Extensions
        let mut extensions: Vec<u16> = Vec::new();
        let mut sni_hostname: Option<String> = None;
        let mut alpn_first: Option<String> = None;

        if handshake_data.len() >= offset + 2 {
            let ext_total_len = u16::from_be_bytes([handshake_data[offset], handshake_data[offset + 1]]) as usize;
            offset += 2;

            let ext_end = offset + ext_total_len;
            let mut ext_ptr = offset;

            while ext_ptr + 4 <= ext_end && ext_ptr + 4 <= handshake_data.len() {
                let ext_type = u16::from_be_bytes([handshake_data[ext_ptr], handshake_data[ext_ptr + 1]]);
                let ext_len = u16::from_be_bytes([handshake_data[ext_ptr + 2], handshake_data[ext_ptr + 3]]) as usize;
                ext_ptr += 4;

                if (ext_type & 0x0f0f) != 0x0a0a {
                    extensions.push(ext_type);
                }

                if ext_ptr + ext_len <= handshake_data.len() {
                    let ext_body = &handshake_data[ext_ptr..ext_ptr + ext_len];

                    // Extension 0x0000 = Server Name Indication (SNI)
                    if ext_type == 0x0000 && ext_body.len() >= 5 {
                        let list_len = u16::from_be_bytes([ext_body[0], ext_body[1]]) as usize;
                        if list_len + 2 <= ext_body.len() && ext_body[2] == 0x00 {
                            // NameType 0 = host_name
                            let name_len = u16::from_be_bytes([ext_body[3], ext_body[4]]) as usize;
                            if 5 + name_len <= ext_body.len() {
                                if let Ok(s) = std::str::from_utf8(&ext_body[5..5 + name_len]) {
                                    sni_hostname = Some(s.to_string());
                                }
                            }
                        }
                    }

                    // Extension 0x0010 = ALPN
                    if ext_type == 0x0010 && ext_body.len() >= 3 {
                        let alpn_str_len = ext_body[2] as usize;
                        if 3 + alpn_str_len <= ext_body.len() {
                            if let Ok(s) = std::str::from_utf8(&ext_body[3..3 + alpn_str_len]) {
                                alpn_first = Some(s.to_string());
                            }
                        }
                    }
                }
                ext_ptr += ext_len;
            }
        }

        // Build JA4 Fingerprint components
        // JA4 format: Protocol (t for TCP, q for QUIC) + Version (13 for TLS 1.3) + SNI (d/i) + NumCiphers + NumExts + ALPN (first & last chars)
        let proto = "t".to_string();
        let sni_ind = if sni_hostname.is_some() { "d" } else { "i" };
        let num_ciphers = format!("{:02}", cipher_suites.len().min(99));
        let num_exts = format!("{:02}", extensions.len().min(99));
        let alpn_code = match &alpn_first {
            Some(a) if a.len() >= 2 => format!("{}{}", &a[0..1], &a[a.len() - 1..]),
            Some(a) if a.len() == 1 => format!("{}0", a),
            _ => "00".to_string(),
        };

        let ja4_a = format!("{}{}{}{}{}{}", proto, "13", sni_ind, num_ciphers, num_exts, alpn_code);

        // JA4_b: SHA256 of sorted ciphers (first 12 chars hex)
        let mut cipher_strings: Vec<String> = cipher_suites.iter().map(|c| format!("{:04x}", c)).collect();
        cipher_strings.sort();
        let cipher_joined = cipher_strings.join(",");
        let cipher_hash: String = hex_encode(&Sha256::digest(cipher_joined.as_bytes()))[..12].to_string();

        // JA4_c: SHA256 of sorted extensions (first 12 chars hex)
        let mut ext_strings: Vec<String> = extensions.iter().map(|e| format!("{:04x}", e)).collect();
        ext_strings.sort();
        let ext_joined = ext_strings.join(",");
        let ext_hash: String = hex_encode(&Sha256::digest(ext_joined.as_bytes()))[..12].to_string();

        let raw_fingerprint = format!("{}_{}_{}", ja4_a, cipher_hash, ext_hash);

        let ja4 = Ja4Fingerprint {
            raw_fingerprint,
            protocol: proto,
            cipher_hash,
            extension_hash: ext_hash,
            alpn: alpn_code,
        };

        Ok((sni_hostname, ja4))
    }

    /// Audit TLS Handshake against policy.
    pub fn audit_handshake(&self, sni: Option<&str>, host_header: Option<&str>, ja4: &Ja4Fingerprint) -> TlsHandshakeSecurityVerdict {
        let policy = match self.policy.read() {
            Ok(p) => p,
            Err(_) => return TlsHandshakeSecurityVerdict::MalformedClientHello("Policy lock poisoned".to_string()),
        };

        // Enforce SNI == Host
        if policy.enforce_sni_host_equality {
            if let (Some(s), Some(h)) = (sni, host_header) {
                let s_clean = s.split(':').next().unwrap_or(s);
                let h_clean = h.split(':').next().unwrap_or(h);
                if !s_clean.eq_ignore_ascii_case(h_clean) {
                    return TlsHandshakeSecurityVerdict::SniHostMismatch {
                        sni: s.to_string(),
                        host: h.to_string(),
                    };
                }
            }
        }

        // Blocked JA4 list check
        if policy.blocked_ja4_fingerprints.iter().any(|b| b == &ja4.raw_fingerprint) {
            return TlsHandshakeSecurityVerdict::ForbiddenJa4 {
                fingerprint: ja4.raw_fingerprint.clone(),
                reason: "Fingerprint in blocked list".to_string(),
            };
        }

        // Allowed JA4 list check (if configured)
        if !policy.allowed_ja4_fingerprints.is_empty()
            && !policy.allowed_ja4_fingerprints.iter().any(|a| a == &ja4.raw_fingerprint)
        {
            return TlsHandshakeSecurityVerdict::ForbiddenJa4 {
                fingerprint: ja4.raw_fingerprint.clone(),
                reason: "Fingerprint not in allowlist".to_string(),
            };
        }

        TlsHandshakeSecurityVerdict::AllowHandshake
    }

    /// Verify server certificate SPKI SHA-256 pin for domain.
    pub fn verify_spki_pin(&self, domain: &str, actual_spki_sha256: &[u8; 32]) -> Result<(), TlsAuditError> {
        let policy = self
            .policy
            .read()
            .map_err(|_| TlsAuditError::MalformedClientHello("Lock poisoned".to_string()))?;

        if let Some(pins) = policy.domain_spki_pins.get(domain) {
            if !pins.iter().any(|pin| pin == actual_spki_sha256) {
                return Err(TlsAuditError::SpkiPinMismatch(domain.to_string()));
            }
        }
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ============================================================================
// R2.10: eBPF Socket-to-PID Correlation Table & Streaming Telemetry
// ============================================================================

/// Connection flow state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    SynSent,
    Established,
    FinWait,
    CloseWait,
    Closed,
    TimeWait,
    Listening,
    Unknown,
}

/// Raw eBPF socket event structure (matches Linux kernel sockops tracepoint C struct).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfSocketEventRaw {
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub src_ip: [u32; 4],
    pub dst_ip: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub family: u8,
    pub protocol: u8,
    pub timestamp_ns: u64,
    pub exe_comm: [u8; 16],
}

/// Live correlation record for active and transient network flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveFlowRecord {
    pub pid: u32,
    pub process_name: String,
    pub cgroup_id: u64,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub protocol: String,
    pub state: FlowState,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub timestamp: DateTime<Utc>,
}

/// Socket to PID mapping metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketPidMapping {
    pub socket_inode: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub process_name: String,
    pub cmdline: String,
    pub created_at: DateTime<Utc>,
}

/// Ring buffer for streaming socket telemetry.
pub struct SocketTelemetryRingBuffer {
    buffer: Mutex<VecDeque<LiveFlowRecord>>,
    max_capacity: usize,
    dropped_count: Mutex<u64>,
}

impl SocketTelemetryRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(capacity)),
            max_capacity: capacity.max(16),
            dropped_count: Mutex::new(0),
        }
    }

    pub fn push_event(&self, record: LiveFlowRecord) {
        if let Ok(mut buf) = self.buffer.lock() {
            if buf.len() >= self.max_capacity {
                buf.pop_front();
                if let Ok(mut dropped) = self.dropped_count.lock() {
                    *dropped += 1;
                }
            }
            buf.push_back(record);
        }
    }

    pub fn drain_events(&self) -> Vec<LiveFlowRecord> {
        if let Ok(mut buf) = self.buffer.lock() {
            buf.drain(..).collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_dropped_count(&self) -> u64 {
        self.dropped_count.lock().map(|g| *g).unwrap_or(0)
    }
}

/// eBPF Socket-to-PID Flow Table.
pub struct EbpfFlowTable {
    active_flows: RwLock<HashMap<(SocketAddr, SocketAddr), LiveFlowRecord>>,
    inode_map: RwLock<HashMap<u64, SocketPidMapping>>,
    ring_buffer: Arc<SocketTelemetryRingBuffer>,
}

impl EbpfFlowTable {
    /// Create new eBPF Flow Table.
    pub fn new(ring_buffer_capacity: usize) -> Self {
        Self {
            active_flows: RwLock::new(HashMap::new()),
            inode_map: RwLock::new(HashMap::new()),
            ring_buffer: Arc::new(SocketTelemetryRingBuffer::new(ring_buffer_capacity)),
        }
    }

    /// Record a new or updated network socket flow.
    pub fn record_flow_event(&self, flow: LiveFlowRecord) {
        let key = (flow.src_addr, flow.dst_addr);

        if let Ok(mut map) = self.active_flows.write() {
            map.insert(key, flow.clone());
        }

        self.ring_buffer.push_event(flow);
    }

    /// Associate a socket inode with process metadata.
    pub fn register_socket_inode(&self, mapping: SocketPidMapping) {
        if let Ok(mut inodes) = self.inode_map.write() {
            inodes.insert(mapping.socket_inode, mapping);
        }
    }

    /// Find the process PID owning an active flow.
    pub fn lookup_pid_for_flow(&self, src: SocketAddr, dst: SocketAddr) -> Option<u32> {
        let map = self.active_flows.read().ok()?;
        map.get(&(src, dst)).map(|f| f.pid)
    }

    /// Drain recent streaming flow telemetry records.
    pub fn poll_telemetry_batch(&self) -> Vec<LiveFlowRecord> {
        self.ring_buffer.drain_events()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_monitor_spawn_detection() {
        let engine = TunnelMonitorEngine::default();

        // 1. Spawning ngrok -> detected and killed
        let ngrok_exe = Path::new("/usr/local/bin/ngrok");
        let ngrok_argv = vec!["ngrok".into(), "http".into(), "3000".into()];
        let alert1 = engine.inspect_process_spawn(1001, ngrok_exe, &ngrok_argv);
        assert!(alert1.is_some());
        let a1 = alert1.unwrap();
        assert_eq!(a1.detected_tool, TunnelingToolKind::Ngrok);
        assert_eq!(a1.action_taken, TunnelKillAction::ProcessTerminatedWithSigKill);

        // 2. Spawning cloudflared -> detected
        let cf_exe = Path::new("/usr/bin/cloudflared");
        let cf_argv = vec!["cloudflared".into(), "tunnel".into(), "--url".into(), "http://localhost:8080".into()];
        let alert2 = engine.inspect_process_spawn(1002, cf_exe, &cf_argv);
        assert!(alert2.is_some());
        assert_eq!(alert2.unwrap().detected_tool, TunnelingToolKind::Cloudflared);

        // 3. Spawning standard compiler -> ignored
        let cargo_exe = Path::new("/home/user/.cargo/bin/cargo");
        let cargo_argv = vec!["cargo".into(), "check".into()];
        let alert3 = engine.inspect_process_spawn(1003, cargo_exe, &cargo_argv);
        assert!(alert3.is_none());
    }

    #[test]
    fn test_tunnel_monitor_sni_detection() {
        let engine = TunnelMonitorEngine::default();

        let alert1 = engine.inspect_outbound_sni(2001, "my-app.ngrok-free.app");
        assert!(alert1.is_some());
        assert_eq!(alert1.unwrap().detected_tool, TunnelingToolKind::Ngrok);

        let alert2 = engine.inspect_outbound_sni(2002, "quick-tunnel.trycloudflare.com");
        assert!(alert2.is_some());
        assert_eq!(alert2.unwrap().detected_tool, TunnelingToolKind::Cloudflared);

        let clean_res = engine.inspect_outbound_sni(2003, "api.github.com");
        assert!(clean_res.is_none());
    }

    #[test]
    fn test_ja4_fingerprint_and_tls_auditing() {
        let policy = TlsPinningPolicy::default();
        let engine = TlsPinningEngine::new(policy);

        let dummy_ja4 = Ja4Fingerprint {
            raw_fingerprint: "t13d1516h2_8daaf6152771_e562703ab892".to_string(),
            protocol: "t".to_string(),
            cipher_hash: "8daaf6152771".to_string(),
            extension_hash: "e562703ab892".to_string(),
            alpn: "h2".to_string(),
        };

        // Matching SNI and Host -> Allow
        let v1 = engine.audit_handshake(Some("api.github.com"), Some("api.github.com"), &dummy_ja4);
        assert_eq!(v1, TlsHandshakeSecurityVerdict::AllowHandshake);

        // SNI spoofing mismatch -> SniHostMismatch
        let v2 = engine.audit_handshake(Some("api.github.com"), Some("evil-site.com"), &dummy_ja4);
        assert!(matches!(v2, TlsHandshakeSecurityVerdict::SniHostMismatch { .. }));
    }

    #[test]
    fn test_ebpf_flow_table_and_ring_buffer() {
        let table = EbpfFlowTable::new(100);

        let src: SocketAddr = "127.0.0.1:45123".parse().unwrap();
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let flow = LiveFlowRecord {
            pid: 4096,
            process_name: "curl".to_string(),
            cgroup_id: 100,
            src_addr: src,
            dst_addr: dst,
            protocol: "TCP".to_string(),
            state: FlowState::Established,
            rx_bytes: 1024,
            tx_bytes: 512,
            timestamp: Utc::now(),
        };

        table.record_flow_event(flow);

        assert_eq!(table.lookup_pid_for_flow(src, dst), Some(4096));

        let batch = table.poll_telemetry_batch();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].pid, 4096);
    }
}
