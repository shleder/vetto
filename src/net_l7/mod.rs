//! Vetto Deep L7 Network Inspection and Dev Server Protection Subsystem (Milestone R2).
//!
//! Provides granular protocol inspection, rate limiting, and zero-trust security controls:
//! - **R2.1**: L7 HTTP/HTTPS method and endpoint REST filtering (`acl::L7HttpFilterEngine`)
//! - **R2.2**: Dev server port armor for 3000, 5173, 8000, 8080 (`dev_server::DevServerPortArmor`)
//! - **R2.3**: Background tunneling & exfiltration detector (`tunnel::TunnelMonitorEngine`)
//! - **R2.4**: Outbound API token scope verifier (`token::TokenScopeInspector`)
//! - **R2.5**: DNS rebinding & private network defense (`acl::DnsRebindingArmor`)
//! - **R2.6**: TLS SNI verification and JA4 certificate pinning (`tunnel::TlsPinningEngine`)
//! - **R2.7**: WebSocket frame inspector and scrubbing (`dev_server::WsFrameInspector`)
//! - **R2.8**: AF_UNIX local socket firewall & FD passing inspector (`acl::UnixSocketFirewall`)
//! - **R2.9**: HTTP request smuggling & framing anomaly detector (`acl::RequestSmugglingDetector`)
//! - **R2.10**: eBPF socket-to-PID correlation table & streaming telemetry (`tunnel::EbpfFlowTable`)
//! - **R2.11**: Ephemeral in-memory root CA & dynamic TLS interception (`token::MitmCertManager`)
//! - **R2.12**: Webhook gateway with constant-time HMAC validation & payload scrubbing (`dev_server::WebhookArmorEngine`)

pub mod acl;
pub mod dev_server;
pub mod token;
pub mod tunnel;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

// Direct re-exports for ergonomic usage
pub use acl::{
    AfUnixError, AncillaryDataReport, DnsRebindingArmor, DnsResolutionRecord, DnsSecurityError, FdPassingRule,
    FdType, FramingValidationResult, HttpFramingAnomaly, HttpMethod, IpClassification, L7AclAction, L7AclRule,
    L7CompileError, L7HttpFilterEngine, L7InspectionVerdict, L7PathPattern, PrivateNetworkPolicy,
    RequestSmugglingDetector, SmugglingRiskLevel, SocketVerdict, UnixSocketAcl, UnixSocketFirewall,
};

pub use dev_server::{
    constant_time_eq, constant_time_eq_hex, hmac_sha256, hmac_sha512, DevPortArmorConfig, DevServerPortArmor,
    DevServerSecurityVerdict, ProtectedPortRule, WebhookArmorEngine, WebhookProviderKind, WebhookSanitizeError,
    WebhookSecurityPolicy, WebhookVerificationResult, WsFrameAction, WsFrameHeader, WsFrameInspector, WsFrameKind,
    WsFrameMutation, WsInspectionError, WsInspectionPolicy,
};

pub use tunnel::{
    BpfSocketEventRaw, EbpfFlowTable, FlowState, Ja4Fingerprint, LiveFlowRecord, SocketPidMapping,
    SocketTelemetryRingBuffer, SniValidationRule, TlsAuditError, TlsHandshakeSecurityVerdict, TlsPinningEngine,
    TlsPinningPolicy, TunnelDetectionAlert, TunnelDetectionRule, TunnelKillAction, TunnelMonitorEngine,
    TunnelingToolKind,
};

pub use token::{
    base64_encode, CaMintError, EphemeralCaConfig, EphemeralCaEngine, GeneratedCertificate,
    IntrospectedScopeResult, KeyAlgorithm, MitmCertManager, TokenIntrospectionError, TokenProviderKind,
    TokenScopeInspector, TokenScopeRule,
};

// ============================================================================
// Unified L7 Configuration & Security Gateway Facade
// ============================================================================

/// Comprehensive configuration for all L7 inspection and network protection features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetL7Config {
    pub enabled: bool,
    pub http_acl_rules: Vec<L7AclRule>,
    pub default_http_action: L7AclAction,
    pub dev_server_armor: DevPortArmorConfig,
    pub tunnel_rules: Vec<TunnelDetectionRule>,
    pub token_scope_rules: Vec<TokenScopeRule>,
    pub private_network_policy: PrivateNetworkPolicy,
    pub tls_pinning_policy: TlsPinningPolicy,
    pub ws_inspection_policy: WsInspectionPolicy,
    pub unix_socket_acls: Vec<UnixSocketAcl>,
    pub unix_socket_default_deny: bool,
    pub webhook_policies: Vec<WebhookSecurityPolicy>,
    pub ephemeral_ca_config: EphemeralCaConfig,
    pub ebpf_ring_buffer_capacity: usize,
}

impl Default for NetL7Config {
    fn default() -> Self {
        Self {
            enabled: true,
            http_acl_rules: Vec::new(),
            default_http_action: L7AclAction::Allow,
            dev_server_armor: DevPortArmorConfig::default(),
            tunnel_rules: Vec::new(),
            token_scope_rules: vec![
                TokenScopeRule::default_github_hardened(),
                TokenScopeRule::default_gitlab_hardened(),
            ],
            private_network_policy: PrivateNetworkPolicy::BlockAllPrivate,
            tls_pinning_policy: TlsPinningPolicy::default(),
            ws_inspection_policy: WsInspectionPolicy::default(),
            unix_socket_acls: Vec::new(),
            unix_socket_default_deny: false,
            webhook_policies: Vec::new(),
            ephemeral_ca_config: EphemeralCaConfig::default(),
            ebpf_ring_buffer_capacity: 1024,
        }
    }
}

/// Unified High-Level L7 Security Gateway orchestrating all 12 R2 sub-engines.
pub struct UnifiedL7SecurityGateway {
    pub config: NetL7Config,
    pub http_filter: Arc<L7HttpFilterEngine>,
    pub dev_port_armor: Arc<DevServerPortArmor>,
    pub tunnel_monitor: Arc<TunnelMonitorEngine>,
    pub token_inspector: Arc<TokenScopeInspector>,
    pub dns_armor: Arc<DnsRebindingArmor>,
    pub tls_pinning: Arc<TlsPinningEngine>,
    pub ws_inspector: Arc<WsFrameInspector>,
    pub unix_firewall: Arc<UnixSocketFirewall>,
    pub smuggle_detector: Arc<RequestSmugglingDetector>,
    pub ebpf_flow_table: Arc<EbpfFlowTable>,
    pub mitm_ca_manager: Arc<MitmCertManager>,
    pub webhook_armor: Arc<WebhookArmorEngine>,
}

impl UnifiedL7SecurityGateway {
    /// Initialize unified gateway with configuration and session token.
    pub fn new(config: NetL7Config, session_auth_token: String) -> Result<Self, anyhow::Error> {
        let http_filter = Arc::new(L7HttpFilterEngine::from_rules(
            config.http_acl_rules.clone(),
            config.default_http_action.clone(),
        )?);

        let dev_port_armor = Arc::new(DevServerPortArmor::new(
            config.dev_server_armor.clone(),
            session_auth_token,
        ));

        let tunnel_monitor = if config.tunnel_rules.is_empty() {
            Arc::new(TunnelMonitorEngine::default())
        } else {
            Arc::new(TunnelMonitorEngine::new(config.tunnel_rules.clone()))
        };

        let token_inspector = Arc::new(TokenScopeInspector::new(config.token_scope_rules.clone()));

        let dns_armor = Arc::new(DnsRebindingArmor::new(config.private_network_policy.clone()));

        let tls_pinning = Arc::new(TlsPinningEngine::new(config.tls_pinning_policy.clone()));

        let ws_inspector = Arc::new(WsFrameInspector::new(config.ws_inspection_policy.clone()));

        let unix_firewall = Arc::new(UnixSocketFirewall::new(config.unix_socket_default_deny));
        for acl in &config.unix_socket_acls {
            unix_firewall.register_socket_acl(acl.clone());
        }

        let smuggle_detector = Arc::new(RequestSmugglingDetector::new());

        let ebpf_flow_table = Arc::new(EbpfFlowTable::new(config.ebpf_ring_buffer_capacity));

        let ephemeral_ca = EphemeralCaEngine::generate_ephemeral(config.ephemeral_ca_config.clone())
            .map_err(|e| anyhow::anyhow!("Failed to initialize ephemeral CA: {}", e))?;
        let mitm_ca_manager = Arc::new(MitmCertManager::new(ephemeral_ca));

        let webhook_armor = Arc::new(WebhookArmorEngine::new(config.webhook_policies.clone()));

        Ok(Self {
            config,
            http_filter,
            dev_port_armor,
            tunnel_monitor,
            token_inspector,
            dns_armor,
            tls_pinning,
            ws_inspector,
            unix_firewall,
            smuggle_detector,
            ebpf_flow_table,
            mitm_ca_manager,
            webhook_armor,
        })
    }

    /// Complete inspection pipeline for an incoming HTTP request (framing, smuggling, and L7 REST rules).
    pub fn inspect_http_request(
        &self,
        method: &HttpMethod,
        host: &str,
        path_and_query: &str,
        raw_header_lines: &[String],
    ) -> (FramingValidationResult, L7InspectionVerdict) {
        // 1. Smuggling check
        let framing_res = self.smuggle_detector.validate_headers(raw_header_lines);

        // If smuggling threat is CriticalDrop, immediately block
        if framing_res.risk_level == SmugglingRiskLevel::CriticalDrop {
            let verdict = L7InspectionVerdict {
                action: L7AclAction::DropConnection,
                matched_rule_id: None,
                reason: format!("HTTP Smuggling Threat Detected: {:?}", framing_res.anomalies),
                timestamp: chrono::Utc::now(),
            };
            return (framing_res, verdict);
        }

        // 2. L7 REST Rule evaluation
        let l7_verdict = self.http_filter.evaluate_request(method, host, path_and_query);

        (framing_res, l7_verdict)
    }

    /// Inspect local development server access.
    pub fn inspect_dev_server(
        &self,
        port: u16,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> DevServerSecurityVerdict {
        self.dev_port_armor.inspect_dev_request(port, path, headers)
    }

    /// Audit process spawn against background tunneling signatures.
    pub fn inspect_process_spawn(
        &self,
        pid: u32,
        exe_path: &Path,
        argv: &[String],
    ) -> Option<TunnelDetectionAlert> {
        self.tunnel_monitor.inspect_process_spawn(pid, exe_path, argv)
    }

    /// Verify token scopes for outbound API request.
    pub fn verify_token(
        &self,
        token: &str,
        scopes: &[String],
        user: Option<String>,
    ) -> Result<IntrospectedScopeResult, TokenIntrospectionError> {
        self.token_inspector.verify_token_scopes(token, scopes, user)
    }

    /// Verify DNS resolution against rebinding and bogons.
    pub fn verify_dns_resolution(
        &self,
        hostname: &str,
        fresh_ips: &[IpAddr],
        ttl_seconds: u64,
    ) -> Result<IpAddr, DnsSecurityError> {
        self.dns_armor.record_and_verify_resolution(hostname, fresh_ips, ttl_seconds)
    }

    /// Inspect WebSocket frame payload.
    pub fn inspect_ws_frame(
        &self,
        kind: WsFrameKind,
        payload: &[u8],
    ) -> Result<WsFrameAction, WsInspectionError> {
        self.ws_inspector.inspect_payload(kind, payload)
    }

    /// Verify webhook HMAC signature and sanitize payload.
    pub fn verify_webhook(
        &self,
        provider: WebhookProviderKind,
        raw_body: &[u8],
        signature_header: &str,
    ) -> WebhookVerificationResult {
        self.webhook_armor.verify_and_sanitize_incoming(provider, raw_body, signature_header)
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_l7_gateway_orchestration() {
        let config = NetL7Config::default();
        let gateway = UnifiedL7SecurityGateway::new(config, "test-session-secret".to_string()).unwrap();

        // 1. Clean HTTP Request
        let headers = vec![
            "Host: api.github.com\r\n".to_string(),
            "Content-Length: 0\r\n".to_string(),
        ];
        let (framing, verdict) = gateway.inspect_http_request(
            &HttpMethod::Get,
            "api.github.com",
            "/repos/shleder/vetto",
            &headers,
        );
        assert!(framing.is_valid);
        assert_eq!(verdict.action, L7AclAction::Allow);

        // 2. Dev server port check (port 3000)
        let mut dev_headers = HashMap::new();
        dev_headers.insert("host".to_string(), "localhost:3000".to_string());
        let dev_verdict = gateway.inspect_dev_server(3000, "/api/status", &dev_headers);
        assert_eq!(dev_verdict, DevServerSecurityVerdict::AllowTraffic);

        // 3. Background tunneling detection
        let alert = gateway.inspect_process_spawn(
            999,
            Path::new("/usr/bin/ngrok"),
            &["ngrok".into(), "http".into(), "3000".into()],
        );
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().detected_tool, TunnelingToolKind::Ngrok);

        // 4. Token Scope Inspection
        let res = gateway.verify_token("ghp_test_token_123", &["repo".into(), "read:org".into()], None);
        assert!(res.is_ok());

        // 5. MITM Leaf Cert generation
        let leaf = gateway.mitm_ca_manager.get_or_mint_leaf("api.openai.com").unwrap();
        assert_eq!(leaf.domain, "api.openai.com");
    }
}
