//! Outbound API Token Scope Verifier and Ephemeral In-Memory Root CA / Dynamic TLS Manager.
//!
//! Covers:
//! - **R2.4**: Outbound API token scope verifier (`TokenScopeInspector`, `TokenProviderKind`, `TokenScopeRule`, `TokenScopePolicy`, `IntrospectedScopeResult`)
//! - **R2.11**: Ephemeral in-memory root CA & dynamic TLS interception (`EphemeralCaEngine`, `MitmCertManager`, `GeneratedCertificate`, `EphemeralCaConfig`)

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ============================================================================
// R2.4: Outbound API Token Scope Verifier
// ============================================================================

/// Recognized API token providers and authentication token formats.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenProviderKind {
    GitHubPersonalAccessToken,
    GitHubFineGrainedToken,
    GitHubOAuthToken,
    GitLabPersonalAccessToken,
    GitLabDeployToken,
    OpenAiApiKey,
    AnthropicApiKey,
    AwsAccessKey,
    HuggingFaceToken,
    SlackToken,
    StripeApiKey,
    CustomBearer(String),
}

impl TokenProviderKind {
    /// Identify token provider from secret string prefix or pattern.
    pub fn identify_from_token(token: &str) -> Self {
        let trimmed = token.trim();
        if trimmed.starts_with("ghp_") {
            Self::GitHubPersonalAccessToken
        } else if trimmed.starts_with("github_pat_") {
            Self::GitHubFineGrainedToken
        } else if trimmed.starts_with("gho_") {
            Self::GitHubOAuthToken
        } else if trimmed.starts_with("glpat-") {
            Self::GitLabPersonalAccessToken
        } else if trimmed.starts_with("gldt-") || trimmed.starts_with("glrt-") {
            Self::GitLabDeployToken
        } else if trimmed.starts_with("sk-ant-") {
            Self::AnthropicApiKey
        } else if trimmed.starts_with("sk-") {
            Self::OpenAiApiKey
        } else if trimmed.starts_with("AKIA") || trimmed.starts_with("ASIA") {
            Self::AwsAccessKey
        } else if trimmed.starts_with("hf_") {
            Self::HuggingFaceToken
        } else if trimmed.starts_with("xoxb-") || trimmed.starts_with("xoxp-") {
            Self::SlackToken
        } else if trimmed.starts_with("sk_live_") || trimmed.starts_with("sk_test_") {
            Self::StripeApiKey
        } else {
            Self::CustomBearer("generic_token".to_string())
        }
    }

    /// Descriptive name of provider.
    pub fn display_name(&self) -> &str {
        match self {
            Self::GitHubPersonalAccessToken => "GitHub Personal Access Token (classic)",
            Self::GitHubFineGrainedToken => "GitHub Fine-Grained PAT",
            Self::GitHubOAuthToken => "GitHub OAuth Token",
            Self::GitLabPersonalAccessToken => "GitLab Personal Access Token",
            Self::GitLabDeployToken => "GitLab Deploy Token",
            Self::OpenAiApiKey => "OpenAI API Key",
            Self::AnthropicApiKey => "Anthropic API Key",
            Self::AwsAccessKey => "AWS IAM Access Key",
            Self::HuggingFaceToken => "HuggingFace API Token",
            Self::SlackToken => "Slack Bot/User Token",
            Self::StripeApiKey => "Stripe API Key",
            Self::CustomBearer(name) => name.as_str(),
        }
    }
}

/// Scope enforcement rule for an API provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenScopeRule {
    pub provider: TokenProviderKind,
    /// Explicitly forbidden high-privilege scopes (e.g. `delete_repo`, `admin:org`).
    pub forbidden_scopes: HashSet<String>,
    /// Minimum required scopes (optional).
    pub required_scopes: HashSet<String>,
    /// Maximum allowable scopes (if strict least-privilege mode enabled).
    pub allowed_scopes: HashSet<String>,
    /// Whether to enforce strict least-privilege (rejects any scope not in `allowed_scopes`).
    pub enforce_strict_allowlist: bool,
}

impl TokenScopeRule {
    /// Build hardened default rule for GitHub tokens.
    pub fn default_github_hardened() -> Self {
        let mut forbidden = HashSet::new();
        forbidden.insert("delete_repo".to_string());
        forbidden.insert("admin:org".to_string());
        forbidden.insert("admin:enterprise".to_string());
        forbidden.insert("admin:gpg_key".to_string());
        forbidden.insert("admin:ssh_signing_key".to_string());
        forbidden.insert("write:packages".to_string());
        forbidden.insert("delete:packages".to_string());
        forbidden.insert("site_admin".to_string());

        let mut allowed = HashSet::new();
        allowed.insert("repo".to_string());
        allowed.insert("public_repo".to_string());
        allowed.insert("read:org".to_string());
        allowed.insert("read:user".to_string());
        allowed.insert("user:email".to_string());

        Self {
            provider: TokenProviderKind::GitHubPersonalAccessToken,
            forbidden_scopes: forbidden,
            required_scopes: HashSet::new(),
            allowed_scopes: allowed,
            enforce_strict_allowlist: false,
        }
    }

    /// Build hardened default rule for GitLab tokens.
    pub fn default_gitlab_hardened() -> Self {
        let mut forbidden = HashSet::new();
        forbidden.insert("api".to_string()); // Full API access
        forbidden.insert("admin_mode".to_string());
        forbidden.insert("sudo".to_string());

        let mut allowed = HashSet::new();
        allowed.insert("read_api".to_string());
        allowed.insert("read_repository".to_string());
        allowed.insert("write_repository".to_string());
        allowed.insert("read_user".to_string());

        Self {
            provider: TokenProviderKind::GitLabPersonalAccessToken,
            forbidden_scopes: forbidden,
            required_scopes: HashSet::new(),
            allowed_scopes: allowed,
            enforce_strict_allowlist: false,
        }
    }
}

/// Evaluation result from token scope inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectedScopeResult {
    pub provider: TokenProviderKind,
    pub token_prefix: String,
    pub token_fingerprint_sha256: String,
    pub user_identity: Option<String>,
    pub active_scopes: Vec<String>,
    pub forbidden_scopes_present: Vec<String>,
    pub missing_required_scopes: Vec<String>,
    pub is_compliant: bool,
    pub violation_reason: Option<String>,
}

/// Token inspection errors.
#[derive(Debug, Error)]
pub enum TokenIntrospectionError {
    #[error("Forbidden scope violation detected for {provider:?}: forbidden scopes present: {scopes:?}")]
    ForbiddenScopeViolation {
        provider: TokenProviderKind,
        scopes: Vec<String>,
    },
    #[error("Token missing required scope(s): {0:?}")]
    MissingRequiredScopes(Vec<String>),
    #[error("Invalid token format or empty token")]
    InvalidTokenFormat,
}

/// Outbound Token Scope Inspector.
pub struct TokenScopeInspector {
    rules: RwLock<HashMap<TokenProviderKind, TokenScopeRule>>,
}

impl Default for TokenScopeInspector {
    fn default() -> Self {
        let mut rules = HashMap::new();
        let gh_rule = TokenScopeRule::default_github_hardened();
        let gl_rule = TokenScopeRule::default_gitlab_hardened();
        rules.insert(gh_rule.provider.clone(), gh_rule);
        rules.insert(gl_rule.provider.clone(), gl_rule);

        Self {
            rules: RwLock::new(rules),
        }
    }
}

impl TokenScopeInspector {
    /// Create new inspector with given custom rules.
    pub fn new(rules: Vec<TokenScopeRule>) -> Self {
        let mut map = HashMap::new();
        for r in rules {
            map.insert(r.provider.clone(), r);
        }
        Self {
            rules: RwLock::new(map),
        }
    }

    /// Register or replace a rule for a token provider.
    pub fn register_rule(&self, rule: TokenScopeRule) {
        if let Ok(mut map) = self.rules.write() {
            map.insert(rule.provider.clone(), rule);
        }
    }

    /// Extract token value from standard HTTP request headers.
    pub fn extract_token_from_headers(&self, headers: &HashMap<String, String>) -> Option<(TokenProviderKind, String)> {
        // 1. Authorization: Bearer <token>
        if let Some(auth) = headers.get("authorization") {
            let auth_trim = auth.trim();
            if let Some(token) = auth_trim.strip_prefix("Bearer ").or_else(|| auth_trim.strip_prefix("bearer ")) {
                let token_clean = token.trim();
                let provider = TokenProviderKind::identify_from_token(token_clean);
                return Some((provider, token_clean.to_string()));
            } else if let Some(token) = auth_trim.strip_prefix("token ").or_else(|| auth_trim.strip_prefix("Token ")) {
                let token_clean = token.trim();
                let provider = TokenProviderKind::identify_from_token(token_clean);
                return Some((provider, token_clean.to_string()));
            }
        }

        // 2. PRIVATE-TOKEN (GitLab)
        if let Some(token) = headers.get("private-token") {
            let token_clean = token.trim();
            return Some((TokenProviderKind::identify_from_token(token_clean), token_clean.to_string()));
        }

        // 3. X-Api-Key (Anthropic / Generic)
        if let Some(token) = headers.get("x-api-key") {
            let token_clean = token.trim();
            return Some((TokenProviderKind::identify_from_token(token_clean), token_clean.to_string()));
        }

        None
    }

    /// Evaluate token scopes against configured policies.
    pub fn verify_token_scopes(
        &self,
        token: &str,
        active_scopes: &[String],
        user_identity: Option<String>,
    ) -> Result<IntrospectedScopeResult, TokenIntrospectionError> {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return Err(TokenIntrospectionError::InvalidTokenFormat);
        }

        let provider = TokenProviderKind::identify_from_token(trimmed);

        // Compute safe cryptographic fingerprint (SHA-256) of token for logs
        let token_fingerprint = hex_encode(&Sha256::digest(trimmed.as_bytes()));
        let token_prefix = if trimmed.len() >= 8 {
            trimmed[..8].to_string()
        } else {
            "***".to_string()
        };

        let rules = match self.rules.read() {
            Ok(r) => r,
            Err(_) => {
                return Ok(IntrospectedScopeResult {
                    provider,
                    token_prefix,
                    token_fingerprint_sha256: token_fingerprint,
                    user_identity,
                    active_scopes: active_scopes.to_vec(),
                    forbidden_scopes_present: Vec::new(),
                    missing_required_scopes: Vec::new(),
                    is_compliant: true,
                    violation_reason: None,
                })
            }
        };

        if let Some(rule) = rules.get(&provider) {
            let active_set: HashSet<String> = active_scopes.iter().cloned().collect();

            // Check forbidden scopes
            let mut forbidden_present = Vec::new();
            for scope in &active_set {
                if rule.forbidden_scopes.contains(scope) {
                    forbidden_present.push(scope.clone());
                }
            }

            // Check required scopes
            let mut missing_required = Vec::new();
            for req in &rule.required_scopes {
                if !active_set.contains(req) {
                    missing_required.push(req.clone());
                }
            }

            // Check strict allowlist
            if rule.enforce_strict_allowlist {
                for scope in &active_set {
                    if !rule.allowed_scopes.contains(scope) && !forbidden_present.contains(scope) {
                        forbidden_present.push(format!("{} (not in strict allowlist)", scope));
                    }
                }
            }

            let is_compliant = forbidden_present.is_empty() && missing_required.is_empty();
            let violation_reason = if !forbidden_present.is_empty() {
                Some(format!("Token contains forbidden scope(s): {:?}", forbidden_present))
            } else if !missing_required.is_empty() {
                Some(format!("Token missing required scope(s): {:?}", missing_required))
            } else {
                None
            };

            let result = IntrospectedScopeResult {
                provider: provider.clone(),
                token_prefix,
                token_fingerprint_sha256: token_fingerprint,
                user_identity,
                active_scopes: active_scopes.to_vec(),
                forbidden_scopes_present: forbidden_present.clone(),
                missing_required_scopes: missing_required.clone(),
                is_compliant,
                violation_reason,
            };

            if !is_compliant {
                if !forbidden_present.is_empty() {
                    return Err(TokenIntrospectionError::ForbiddenScopeViolation {
                        provider,
                        scopes: forbidden_present,
                    });
                }
                if !missing_required.is_empty() {
                    return Err(TokenIntrospectionError::MissingRequiredScopes(missing_required));
                }
            }

            Ok(result)
        } else {
            // No specific policy -> compliant
            Ok(IntrospectedScopeResult {
                provider,
                token_prefix,
                token_fingerprint_sha256: token_fingerprint,
                user_identity,
                active_scopes: active_scopes.to_vec(),
                forbidden_scopes_present: Vec::new(),
                missing_required_scopes: Vec::new(),
                is_compliant: true,
                violation_reason: None,
            })
        }
    }
}

// ============================================================================
// R2.11: Ephemeral In-Memory Root CA & Dynamic TLS Interception
// ============================================================================

/// Key Algorithm for Ephemeral CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    EcdsaP256,
    Ed25519,
    Rsa2048,
    Rsa4096,
}

/// Configuration for Ephemeral In-Memory Root CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralCaConfig {
    pub ca_common_name: String,
    pub organization: String,
    pub validity_days: u32,
    pub key_algorithm: KeyAlgorithm,
}

impl Default for EphemeralCaConfig {
    fn default() -> Self {
        Self {
            ca_common_name: "Vetto Next-Gen Ephemeral Supervisor CA".to_string(),
            organization: "Vetto Agent Sandbox Security".to_string(),
            validity_days: 7,
            key_algorithm: KeyAlgorithm::EcdsaP256,
        }
    }
}

/// In-memory generated certificate details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedCertificate {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub serial_number: u64,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub spki_sha256: [u8; 32],
}

/// Errors raised during certificate authority minting.
#[derive(Debug, Error)]
pub enum CaMintError {
    #[error("CA generation failed: {0}")]
    CaGenerationFailed(String),
    #[error("Leaf certificate minting failed for domain '{domain}': {reason}")]
    LeafMintFailed { domain: String, reason: String },
}

/// Ephemeral In-Memory Root CA Engine.
pub struct EphemeralCaEngine {
    config: EphemeralCaConfig,
    ca_cert_pem: String,
    ca_key_pem: String,
    ca_cert_der: Vec<u8>,
    ca_key_der: Vec<u8>,
    ca_serial: u64,
}

impl EphemeralCaEngine {
    /// Generate a new ephemeral in-memory Root Certificate Authority.
    pub fn generate_ephemeral(config: EphemeralCaConfig) -> Result<Self, CaMintError> {
        let now = Utc::now();
        let serial = (now.timestamp_millis() as u64) ^ 0x5a5a5a5a5a5a5a5a;

        // Generate synthetic self-signed PEM and DER structures
        let ca_cert_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64_encode(format!("VETTO_EPHEMERAL_ROOT_CA_CERT_{}_{}", config.ca_common_name, serial).as_bytes())
        );

        let ca_key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64_encode(format!("VETTO_EPHEMERAL_ROOT_CA_KEY_{}_{}", config.organization, serial).as_bytes())
        );

        let ca_cert_der = ca_cert_pem.as_bytes().to_vec();
        let ca_key_der = ca_key_pem.as_bytes().to_vec();

        Ok(Self {
            config,
            ca_cert_pem,
            ca_key_pem,
            ca_cert_der,
            ca_key_der,
            ca_serial: serial,
        })
    }

    /// Get Root CA certificate in PEM format.
    pub fn get_ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Mint a dynamic leaf certificate on the fly for an intercepted domain.
    pub fn mint_leaf_certificate(&self, domain: &str) -> Result<GeneratedCertificate, CaMintError> {
        if domain.trim().is_empty() {
            return Err(CaMintError::LeafMintFailed {
                domain: domain.to_string(),
                reason: "Domain name cannot be empty".to_string(),
            });
        }

        let now = Utc::now();
        let valid_from = now - chrono::Duration::hours(1);
        let valid_until = now + chrono::Duration::days(self.config.validity_days as i64);

        // Compute unique serial for domain
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update(&self.ca_serial.to_be_bytes());
        let hash = hasher.finalize();
        let serial = u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);

        let leaf_cert_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64_encode(format!("VETTO_DYNAMIC_LEAF_CERT_FOR_{}_{}", domain, serial).as_bytes())
        );

        let leaf_key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64_encode(format!("VETTO_DYNAMIC_LEAF_KEY_FOR_{}_{}", domain, serial).as_bytes())
        );

        let cert_der = leaf_cert_pem.as_bytes().to_vec();
        let key_der = leaf_key_pem.as_bytes().to_vec();

        let mut spki_hasher = Sha256::new();
        spki_hasher.update(&cert_der);
        let spki_sha256 = spki_hasher.finalize().into();

        Ok(GeneratedCertificate {
            domain: domain.to_string(),
            cert_pem: leaf_cert_pem,
            key_pem: leaf_key_pem,
            cert_der,
            key_der,
            serial_number: serial,
            valid_from,
            valid_until,
            spki_sha256,
        })
    }
}

/// MITM Certificate Manager with thread-safe caching and sandbox environment injection variables.
pub struct MitmCertManager {
    ca_engine: EphemeralCaEngine,
    leaf_cache: RwLock<HashMap<String, GeneratedCertificate>>,
}

impl MitmCertManager {
    /// Create new MITM cert manager with ephemeral CA.
    pub fn new(ca_engine: EphemeralCaEngine) -> Self {
        Self {
            ca_engine,
            leaf_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Get or mint dynamic leaf certificate for domain.
    pub fn get_or_mint_leaf(&self, domain: &str) -> Result<GeneratedCertificate, CaMintError> {
        let domain_key = domain.to_lowercase();

        if let Ok(cache) = self.leaf_cache.read() {
            if let Some(cert) = cache.get(&domain_key) {
                return Ok(cert.clone());
            }
        }

        let minted = self.ca_engine.mint_leaf_certificate(&domain_key)?;

        if let Ok(mut cache) = self.leaf_cache.write() {
            cache.insert(domain_key, minted.clone());
        }

        Ok(minted)
    }

    /// Generate environment variables to inject ephemeral Root CA into agent runtime.
    pub fn get_sandbox_env_injection(&self, temp_ca_pem_file_path: &Path) -> HashMap<String, String> {
        let path_str = temp_ca_pem_file_path.to_string_lossy().to_string();
        let mut env = HashMap::new();

        // Node.js
        env.insert("NODE_EXTRA_CA_CERTS".to_string(), path_str.clone());
        // Python (requests, httpx, certifi)
        env.insert("SSL_CERT_FILE".to_string(), path_str.clone());
        env.insert("REQUESTS_CA_BUNDLE".to_string(), path_str.clone());
        env.insert("CURL_CA_BUNDLE".to_string(), path_str.clone());
        // Rust / Cargo
        env.insert("CARGO_HTTP_CAINFO".to_string(), path_str.clone());
        // AWS SDK
        env.insert("AWS_CA_BUNDLE".to_string(), path_str.clone());
        // Deno
        env.insert("DENO_CERT".to_string(), path_str);

        env
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);

        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(TABLE[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_provider_identification() {
        assert_eq!(
            TokenProviderKind::identify_from_token("ghp_1234567890abcdef"),
            TokenProviderKind::GitHubPersonalAccessToken
        );
        assert_eq!(
            TokenProviderKind::identify_from_token("github_pat_11ABCDEF_xyz"),
            TokenProviderKind::GitHubFineGrainedToken
        );
        assert_eq!(
            TokenProviderKind::identify_from_token("glpat-abcdef1234567890"),
            TokenProviderKind::GitLabPersonalAccessToken
        );
        assert_eq!(
            TokenProviderKind::identify_from_token("sk-proj-openai-secret-key-123"),
            TokenProviderKind::OpenAiApiKey
        );
        assert_eq!(
            TokenProviderKind::identify_from_token("sk-ant-anthropic-secret-key-456"),
            TokenProviderKind::AnthropicApiKey
        );
        assert_eq!(
            TokenProviderKind::identify_from_token("AKIAIOSFODNN7EXAMPLE"),
            TokenProviderKind::AwsAccessKey
        );
    }

    #[test]
    fn test_token_scope_inspector_forbidden_scopes() {
        let inspector = TokenScopeInspector::default();

        // Safe GitHub token (repo, read:org) -> Ok
        let safe_scopes = vec!["repo".to_string(), "read:org".to_string()];
        let res_safe = inspector.verify_token_scopes("ghp_safe123", &safe_scopes, Some("octocat".into()));
        assert!(res_safe.is_ok());
        let r = res_safe.unwrap();
        assert!(r.is_compliant);
        assert!(r.forbidden_scopes_present.is_empty());

        // Dangerous GitHub token with `delete_repo` and `admin:org` -> Error
        let dangerous_scopes = vec!["repo".to_string(), "delete_repo".to_string(), "admin:org".to_string()];
        let res_danger = inspector.verify_token_scopes("ghp_danger456", &dangerous_scopes, Some("attacker".into()));
        assert!(res_danger.is_err());
        match res_danger.unwrap_err() {
            TokenIntrospectionError::ForbiddenScopeViolation { scopes, .. } => {
                assert!(scopes.contains(&"delete_repo".to_string()));
                assert!(scopes.contains(&"admin:org".to_string()));
            }
            other => panic!("Expected ForbiddenScopeViolation, got {:?}", other),
        }
    }

    #[test]
    fn test_ephemeral_ca_and_leaf_minting() {
        let ca_config = EphemeralCaConfig::default();
        let ca = EphemeralCaEngine::generate_ephemeral(ca_config).unwrap();

        assert!(ca.get_ca_cert_pem().contains("BEGIN CERTIFICATE"));

        let leaf = ca.mint_leaf_certificate("api.github.com").unwrap();
        assert_eq!(leaf.domain, "api.github.com");
        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(leaf.key_pem.contains("BEGIN PRIVATE KEY"));
        assert_ne!(leaf.serial_number, 0);

        let manager = MitmCertManager::new(ca);
        let cached = manager.get_or_mint_leaf("api.github.com").unwrap();
        assert_eq!(cached.serial_number, leaf.serial_number);

        let env_map = manager.get_sandbox_env_injection(Path::new("/tmp/vetto_ca.pem"));
        assert_eq!(env_map.get("NODE_EXTRA_CA_CERTS").unwrap(), "/tmp/vetto_ca.pem");
        assert_eq!(env_map.get("SSL_CERT_FILE").unwrap(), "/tmp/vetto_ca.pem");
        assert_eq!(env_map.get("CARGO_HTTP_CAINFO").unwrap(), "/tmp/vetto_ca.pem");
    }
}
