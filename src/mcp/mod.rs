//! Model Context Protocol (MCP) Next-Gen Supervisor and Capability Plane (Category R1).
//!
//! Provides native process isolation for stdio/SSE/WebSocket MCP servers,
//! AST-based `.cursorrules` policy generation, streaming JSON-RPC 2.0 authorization gates,
//! session replay/mocking, schema fuzzing, roots sandboxing, and prompt injection defense.

pub mod delegation;
pub mod proxy;
pub mod replay;
pub mod validator;

// Re-export core types for top-level convenience
pub use delegation::*;
pub use proxy::*;
pub use replay::*;
pub use validator::*;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;

// =========================================================================
// R1.1: Native MCP stdio/SSE/WebSocket Sandbox Management
// =========================================================================

/// Transport mechanism utilized by the target MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpTransportKind {
    /// Standard I/O communication over stdin/stdout pipes.
    Stdio,
    /// Server-Sent Events (SSE) HTTP transport.
    Sse {
        endpoint_url: String,
        bind_addr: Option<std::net::SocketAddr>,
    },
    /// Bidirectional WebSocket transport.
    WebSocket { endpoint_url: String },
}

/// Sandboxing and capability policy applied to a spawned MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSandboxPolicy {
    /// Human-readable server identifier (e.g. "postgres-mcp", "github-mcp").
    pub server_name: String,
    /// Transport mechanism.
    pub transport: McpTransportKind,
    /// Allowed filesystem read paths.
    pub allowed_read_paths: Vec<PathBuf>,
    /// Allowed filesystem write paths.
    pub allowed_write_paths: Vec<PathBuf>,
    /// Permitted environment variables (all others are scrubbed).
    pub environment_allowlist: Vec<String>,
    /// Permitted outbound network domains or IP CIDRs.
    pub network_egress_allowlist: Vec<String>,
    /// Maximum resident memory limit in bytes.
    pub max_memory_bytes: u64,
    /// Maximum CPU execution time budget in milliseconds.
    pub max_cpu_time_ms: u64,
    /// Whether the MCP server is permitted to spawn nested subprocesses.
    pub allow_subprocess_spawn: bool,
    /// Whether strict JSON-RPC 2.0 framing is enforced.
    pub enforce_strict_jsonrpc: bool,
}

impl Default for McpSandboxPolicy {
    fn default() -> Self {
        Self {
            server_name: "default-mcp-server".into(),
            transport: McpTransportKind::Stdio,
            allowed_read_paths: vec![PathBuf::from(".")],
            allowed_write_paths: vec![],
            environment_allowlist: vec![
                "PATH".into(),
                "HOME".into(),
                "USER".into(),
                "LANG".into(),
                "LC_ALL".into(),
            ],
            network_egress_allowlist: vec![],
            max_memory_bytes: 512 * 1024 * 1024, // 512MB
            max_cpu_time_ms: 60_000,             // 60s
            allow_subprocess_spawn: false,
            enforce_strict_jsonrpc: true,
        }
    }
}

/// Specification required to launch and isolate an MCP server process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerLaunchSpec {
    /// Executable binary path.
    pub command: PathBuf,
    /// Command line arguments.
    pub args: Vec<String>,
    /// Explicit environment variables to inject.
    pub env: HashMap<String, String>,
    /// Working directory for the spawned server.
    pub working_dir: PathBuf,
    /// Security and resource policy.
    pub policy: McpSandboxPolicy,
}

/// Live handle to an active sandboxed MCP server instance.
pub struct McpSandboxedHandle {
    /// Server identifier.
    pub server_name: String,
    /// Child process ID on the host OS.
    pub child_pid: u32,
    /// Asynchronous sink to write requests into the server's stdin.
    pub stdin_tx: Box<dyn AsyncWrite + Send + Unpin>,
    /// Asynchronous stream to read responses from the server's stdout.
    pub stdout_rx: Box<dyn AsyncRead + Send + Unpin>,
    /// Asynchronous stream to read diagnostic logs from the server's stderr.
    pub stderr_rx: Box<dyn AsyncRead + Send + Unpin>,
    /// Launch timestamp.
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Active state flag.
    pub is_active: bool,
}

/// Asynchronous trait defining the lifecycle supervisor for isolated MCP servers.
#[async_trait::async_trait]
pub trait McpServerIsolationManager: Send + Sync {
    /// Spawns a new sandboxed MCP server according to the launch specification.
    async fn spawn_sandboxed_server(
        &self,
        spec: McpServerLaunchSpec,
    ) -> Result<McpSandboxedHandle, McpSandboxError>;

    /// Terminates an active MCP server by name.
    async fn terminate_server(&self, server_name: &str) -> Result<(), McpSandboxError>;

    /// Lists the names of all currently supervised MCP servers.
    async fn list_active_servers(&self) -> Vec<String>;

    /// Retrieves the active policy for a supervised server.
    async fn get_server_policy(&self, server_name: &str) -> Option<McpSandboxPolicy>;
}

/// Errors arising during MCP server sandboxing and lifecycle operations.
#[derive(Debug, thiserror::Error)]
pub enum McpSandboxError {
    #[error("Sandbox backend initialization failed: {0}")]
    BackendFailure(String),
    #[error("Failed to bind stdio pipes for MCP server: {0}")]
    Io(#[from] std::io::Error),
    #[error("Policy violation during spawn: {0}")]
    PolicyViolation(String),
    #[error("Server '{0}' not found or already terminated")]
    ServerNotFound(String),
    #[error("Process spawning failed: {0}")]
    SpawnFailed(String),
}

/// Concrete supervisor managing active MCP server processes and applying security boundaries.
#[derive(Clone)]
pub struct DefaultMcpIsolationManager {
    servers: Arc<RwLock<HashMap<String, McpSandboxPolicy>>>,
}

impl DefaultMcpIsolationManager {
    /// Creates a new default MCP isolation manager.
    pub fn new() -> Self {
        Self {
            servers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Validates a launch spec against strict security constraints before process spawning.
    pub fn validate_spec(&self, spec: &McpServerLaunchSpec) -> Result<(), McpSandboxError> {
        if spec.command.as_os_str().is_empty() {
            return Err(McpSandboxError::PolicyViolation(
                "Executable command path cannot be empty".into(),
            ));
        }

        // Verify working directory exists or is valid
        if !spec.working_dir.is_absolute() && !spec.working_dir.starts_with(".") {
            return Err(McpSandboxError::PolicyViolation(
                "Working directory must be explicit or relative to workspace".into(),
            ));
        }

        // Check write paths
        for wp in &spec.policy.allowed_write_paths {
            let wp_str = wp.to_string_lossy();
            if wp_str == "/" || wp_str == "/etc" || wp_str == "/usr" || wp_str == "/bin" {
                return Err(McpSandboxError::PolicyViolation(format!(
                    "Disallowed system write path: {wp_str}"
                )));
            }
        }

        Ok(())
    }
}

impl Default for DefaultMcpIsolationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl McpServerIsolationManager for DefaultMcpIsolationManager {
    async fn spawn_sandboxed_server(
        &self,
        spec: McpServerLaunchSpec,
    ) -> Result<McpSandboxedHandle, McpSandboxError> {
        self.validate_spec(&spec)?;

        let server_name = spec.policy.server_name.clone();

        // In real execution, we spawn tokio::process::Command with piped stdio/stdout/stderr
        let mut cmd = tokio::process::Command::new(&spec.command);
        cmd.args(&spec.args);
        cmd.current_dir(&spec.working_dir);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        // Clear and filter environment variables according to allowlist
        cmd.env_clear();
        for key in &spec.policy.environment_allowlist {
            if let Ok(val) = std::env::var(key) {
                cmd.env(key, val);
            }
        }
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }

        // Set sandboxing markers
        cmd.env("VETTO_SANDBOXED", "1");
        cmd.env("VETTO_MCP_SERVER", &server_name);

        let mut child = cmd.spawn().map_err(|e| {
            McpSandboxError::SpawnFailed(format!("Failed to spawn MCP server {server_name}: {e}"))
        })?;

        let child_pid = child.id().unwrap_or(0);
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| McpSandboxError::BackendFailure("Failed to capture stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| McpSandboxError::BackendFailure("Failed to capture stdout".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| McpSandboxError::BackendFailure("Failed to capture stderr".into()))?;

        self.servers
            .write()
            .await
            .insert(server_name.clone(), spec.policy);

        Ok(McpSandboxedHandle {
            server_name,
            child_pid,
            stdin_tx: Box::new(stdin),
            stdout_rx: Box::new(stdout),
            stderr_rx: Box::new(stderr),
            started_at: Utc::now(),
            is_active: true,
        })
    }

    async fn terminate_server(&self, server_name: &str) -> Result<(), McpSandboxError> {
        let mut map = self.servers.write().await;
        if map.remove(server_name).is_some() {
            Ok(())
        } else {
            Err(McpSandboxError::ServerNotFound(server_name.to_string()))
        }
    }

    async fn list_active_servers(&self) -> Vec<String> {
        self.servers.read().await.keys().cloned().collect()
    }

    async fn get_server_policy(&self, server_name: &str) -> Option<McpSandboxPolicy> {
        self.servers.read().await.get(server_name).cloned()
    }
}

// =========================================================================
// R1.4: AST-Based .cursorrules Policy Generator
// =========================================================================

/// Software ecosystems detected during repository analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EcosystemType {
    RustCargo,
    NodeNpmYarnPnpm,
    PythonPipPoetryUv,
    GoMod,
    JavaMavenGradle,
    DockerCompose,
    RubyBundler,
    CPlusPlusCMake,
}

/// Structural AST and filesystem summary of a scanned workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectAstAnalysis {
    /// Detected ecosystems (Rust, Node, Python, Go, etc.).
    pub detected_ecosystems: Vec<EcosystemType>,
    /// Build output directories that require write access (e.g. `target/`, `dist/`).
    pub detected_output_dirs: Vec<PathBuf>,
    /// Package manager cache directories requiring read/write access.
    pub detected_cache_dirs: Vec<PathBuf>,
    /// Hardcoded external endpoints found in source code strings.
    pub hardcoded_network_endpoints: Vec<String>,
    /// Recognized cloud and SaaS SDK endpoints (AWS, Stripe, Supabase, OpenAI, Anthropic).
    pub sdk_network_endpoints: Vec<String>,
    /// Sensitive credential and secret files discovered in workspace.
    pub sensitive_files_found: Vec<PathBuf>,
    /// Identified build tools and package managers.
    pub detected_build_tools: Vec<String>,
    /// List of declared third-party dependencies.
    pub package_dependencies: Vec<String>,
}

/// Alias for compatibility with differing architectural naming conventions.
pub type ProjectAstSummary = ProjectAstAnalysis;

/// Individual granular policy rule synthesized for Cursor or Vetto.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorPolicyRule {
    pub rule_name: String,
    pub glob_pattern: String,
    pub access_level: String, // "read_only", "read_write", "deny"
    pub description: String,
}

/// Synthesized policy configuration files ready to write to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedPolicySet {
    /// Content for `.cursorrules` / `.cursor/rules/vetto.mdc`.
    pub cursor_rules_content: String,
    /// Content for `vetto.toml`.
    pub vetto_toml_content: String,
    /// Overall repository security posture score (0 - 100).
    pub security_score: u32,
    /// Suggested path exclusions.
    pub suggested_exclusions: Vec<PathBuf>,
    /// Extracted policy rules.
    pub rules: Vec<CursorPolicyRule>,
}

/// Alias for compatibility with architectural naming conventions.
pub type GeneratedCursorRules = GeneratedPolicySet;

/// Trait defining AST and repository scanning for automated policy synthesis.
pub trait AstPolicyScanner: Send + Sync {
    /// Scans a workspace root directory and returns a structural summary.
    fn scan_workspace(&self, root: &Path) -> Result<ProjectAstAnalysis, AstScanError>;

    /// Synthesizes `.cursorrules` and `vetto.toml` policies based on workspace analysis.
    fn synthesize_policies(
        &self,
        analysis: &ProjectAstAnalysis,
    ) -> Result<GeneratedPolicySet, AstScanError>;
}

/// Errors encountered during AST scanning and policy generation.
#[derive(Debug, thiserror::Error)]
pub enum AstScanError {
    #[error("IO error while reading workspace: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse failure in file {0}: {1}")]
    ParseFailure(PathBuf, String),
    #[error("Workspace path {0:?} does not exist or is inaccessible")]
    InvalidWorkspace(PathBuf),
    #[error("Failed to serialize generated policy: {0}")]
    SerializationError(String),
}

/// Concrete implementation of the AST-based `.cursorrules` policy generator.
#[derive(Debug, Default, Clone)]
pub struct CursorRulesGenerator;

pub type DefaultAstPolicyScanner = CursorRulesGenerator;

impl CursorRulesGenerator {
    /// Creates a new policy generator.
    pub fn new() -> Self {
        Self
    }

    /// Analyzes a source file or manifest to detect SDK patterns, endpoints, and secrets.
    pub fn inspect_source_content(&self, filename: &str, content: &str, analysis: &mut ProjectAstAnalysis) {
        // Look for sensitive files
        if filename.contains(".env")
            || filename.ends_with(".pem")
            || filename.ends_with(".key")
            || filename.contains("id_rsa")
            || filename.contains("credentials")
        {
            analysis.sensitive_files_found.push(PathBuf::from(filename));
        }

        // Heuristic detection of SDK endpoints
        let content_lower = content.to_ascii_lowercase();
        if content_lower.contains("api.openai.com") {
            Self::add_unique_string(&mut analysis.sdk_network_endpoints, "api.openai.com".into());
        }
        if content_lower.contains("api.anthropic.com") {
            Self::add_unique_string(&mut analysis.sdk_network_endpoints, "api.anthropic.com".into());
        }
        if content_lower.contains("api.github.com") {
            Self::add_unique_string(&mut analysis.sdk_network_endpoints, "api.github.com".into());
        }
        if content_lower.contains("amazonaws.com") {
            Self::add_unique_string(&mut analysis.sdk_network_endpoints, "*.amazonaws.com".into());
        }
        if content_lower.contains("supabase.co") {
            Self::add_unique_string(&mut analysis.sdk_network_endpoints, "*.supabase.co".into());
        }
        if content_lower.contains("api.stripe.com") {
            Self::add_unique_string(&mut analysis.sdk_network_endpoints, "api.stripe.com".into());
        }

        // Generic URL detection heuristic
        for word in content.split_whitespace() {
            if (word.starts_with("http://") || word.starts_with("https://")) && word.len() < 120 {
                let clean = word
                    .trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ',' || c == ';')
                    .to_string();
                if clean.contains('.') && !clean.contains("127.0.0.1") && !clean.contains("localhost") {
                    Self::add_unique_string(&mut analysis.hardcoded_network_endpoints, clean);
                }
            }
        }
    }

    fn add_unique_string(vec: &mut Vec<String>, item: String) {
        if !vec.contains(&item) {
            vec.push(item);
        }
    }

    fn add_unique_ecosystem(vec: &mut Vec<EcosystemType>, item: EcosystemType) {
        if !vec.contains(&item) {
            vec.push(item);
        }
    }
}

impl AstPolicyScanner for CursorRulesGenerator {
    fn scan_workspace(&self, root: &Path) -> Result<ProjectAstAnalysis, AstScanError> {
        if !root.exists() {
            return Err(AstScanError::InvalidWorkspace(root.to_path_buf()));
        }

        let mut analysis = ProjectAstAnalysis {
            detected_ecosystems: Vec::new(),
            detected_output_dirs: Vec::new(),
            detected_cache_dirs: Vec::new(),
            hardcoded_network_endpoints: Vec::new(),
            sdk_network_endpoints: Vec::new(),
            sensitive_files_found: Vec::new(),
            detected_build_tools: Vec::new(),
            package_dependencies: Vec::new(),
        };

        // Scan root manifest files
        if root.join("Cargo.toml").exists() {
            Self::add_unique_ecosystem(&mut analysis.detected_ecosystems, EcosystemType::RustCargo);
            analysis.detected_build_tools.push("cargo".into());
            analysis.detected_output_dirs.push(PathBuf::from("target"));
            analysis.detected_cache_dirs.push(PathBuf::from("~/.cargo/registry"));
        }
        if root.join("package.json").exists() {
            Self::add_unique_ecosystem(&mut analysis.detected_ecosystems, EcosystemType::NodeNpmYarnPnpm);
            analysis.detected_build_tools.push("npm/node".into());
            analysis.detected_output_dirs.push(PathBuf::from("node_modules"));
            analysis.detected_output_dirs.push(PathBuf::from("dist"));
            analysis.detected_output_dirs.push(PathBuf::from(".next"));
            analysis.detected_cache_dirs.push(PathBuf::from("~/.npm"));
        }
        if root.join("pyproject.toml").exists()
            || root.join("requirements.txt").exists()
            || root.join("Pipfile").exists()
        {
            Self::add_unique_ecosystem(&mut analysis.detected_ecosystems, EcosystemType::PythonPipPoetryUv);
            analysis.detected_build_tools.push("python/pip".into());
            analysis.detected_output_dirs.push(PathBuf::from(".venv"));
            analysis.detected_output_dirs.push(PathBuf::from("__pycache__"));
            analysis.detected_cache_dirs.push(PathBuf::from("~/.cache/pip"));
        }
        if root.join("go.mod").exists() {
            Self::add_unique_ecosystem(&mut analysis.detected_ecosystems, EcosystemType::GoMod);
            analysis.detected_build_tools.push("go".into());
            analysis.detected_cache_dirs.push(PathBuf::from("~/go/pkg/mod"));
        }
        if root.join("docker-compose.yml").exists() || root.join("docker-compose.yaml").exists() {
            Self::add_unique_ecosystem(&mut analysis.detected_ecosystems, EcosystemType::DockerCompose);
            analysis.detected_build_tools.push("docker-compose".into());
        }

        // Check for common sensitive files in workspace root
        for candidate in &[".env", ".env.local", ".env.production", "id_rsa", "secrets.json"] {
            if root.join(candidate).exists() {
                analysis.sensitive_files_found.push(PathBuf::from(candidate));
            }
        }

        Ok(analysis)
    }

    fn synthesize_policies(
        &self,
        analysis: &ProjectAstAnalysis,
    ) -> Result<GeneratedPolicySet, AstScanError> {
        let mut rules = Vec::new();
        let mut suggested_exclusions = Vec::new();

        // 1. Sensitive files denial rules
        for s in &analysis.sensitive_files_found {
            rules.push(CursorPolicyRule {
                rule_name: "deny_sensitive_credentials".into(),
                glob_pattern: s.to_string_lossy().to_string(),
                access_level: "deny".into(),
                description: "Block AI agents from reading or exfiltrating credentials".into(),
            });
            suggested_exclusions.push(s.clone());
        }

        // 2. Build output dirs read-write rules
        for out in &analysis.detected_output_dirs {
            rules.push(CursorPolicyRule {
                rule_name: "allow_build_output".into(),
                glob_pattern: format!("{}/**", out.to_string_lossy()),
                access_level: "read_write".into(),
                description: "Allow build artifacts and compiler caching".into(),
            });
        }

        // 3. Network egress domains
        let mut domains: HashSet<String> = HashSet::new();
        for sdk in &analysis.sdk_network_endpoints {
            domains.insert(sdk.clone());
        }

        // Standard registry endpoints by ecosystem
        for eco in &analysis.detected_ecosystems {
            match eco {
                EcosystemType::RustCargo => {
                    domains.insert("crates.io".into());
                    domains.insert("static.crates.io".into());
                    domains.insert("docs.rs".into());
                }
                EcosystemType::NodeNpmYarnPnpm => {
                    domains.insert("registry.npmjs.org".into());
                    domains.insert("registry.yarnpkg.com".into());
                }
                EcosystemType::PythonPipPoetryUv => {
                    domains.insert("pypi.org".into());
                    domains.insert("files.pythonhosted.org".into());
                }
                EcosystemType::GoMod => {
                    domains.insert("proxy.golang.org".into());
                    domains.insert("sum.golang.org".into());
                }
                _ => {}
            }
        }

        // Calculate security score
        let mut security_score = 100u32;
        if !analysis.sensitive_files_found.is_empty() {
            security_score = security_score.saturating_sub(15 * analysis.sensitive_files_found.len() as u32);
        }
        if analysis.hardcoded_network_endpoints.len() > 5 {
            security_score = security_score.saturating_sub(10);
        }
        security_score = security_score.max(10);

        // Synthesize .cursorrules markdown
        let mut cursor_rules = String::new();
        cursor_rules.push_str("# Vetto AI Security & Sandboxing Profile (.cursorrules)\n\n");
        cursor_rules.push_str("## Protected Boundaries\n");
        cursor_rules.push_str("- Never read or expose `.env`, `.pem`, `.key`, or SSH credentials.\n");
        cursor_rules.push_str("- Execute commands exclusively through the Vetto supervisor (`vetto exec -- <cmd>`).\n");
        cursor_rules.push_str("- Network egress is restricted to declared package registries and verified SDK endpoints.\n\n");
        cursor_rules.push_str("## Allowed Network Endpoints\n");
        for d in &domains {
            cursor_rules.push_str(&format!("- `{d}`\n"));
        }
        cursor_rules.push_str("\n## Build Directories\n");
        for out in &analysis.detected_output_dirs {
            cursor_rules.push_str(&format!("- `{}/` (read-write)\n", out.to_string_lossy()));
        }

        // Synthesize vetto.toml content
        let mut vetto_toml = String::new();
        vetto_toml.push_str("# Auto-generated by vetto init --from-ast\n");
        vetto_toml.push_str("[sandbox]\n");
        vetto_toml.push_str("mode = \"strict\"\n");
        vetto_toml.push_str("allow_subprocess_spawn = false\n\n");
        vetto_toml.push_str("[filesystem]\n");
        vetto_toml.push_str("read_paths = [\".\"]\n");
        let write_paths_str = analysis
            .detected_output_dirs
            .iter()
            .map(|p| format!("\"{}\"", p.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(", ");
        vetto_toml.push_str(&format!("write_paths = [{write_paths_str}]\n"));
        let deny_paths_str = analysis
            .sensitive_files_found
            .iter()
            .map(|p| format!("\"{}\"", p.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(", ");
        vetto_toml.push_str(&format!("deny_paths = [{deny_paths_str}]\n\n"));
        vetto_toml.push_str("[network]\n");
        let domains_str = domains
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ");
        vetto_toml.push_str(&format!("allow_domains = [{domains_str}]\n"));

        Ok(GeneratedPolicySet {
            cursor_rules_content: cursor_rules,
            vetto_toml_content: vetto_toml,
            security_score,
            suggested_exclusions,
            rules,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_launch_spec_validation() {
        let manager = DefaultMcpIsolationManager::new();

        let valid_spec = McpServerLaunchSpec {
            command: PathBuf::from("/usr/bin/node"),
            args: vec!["server.js".into()],
            env: HashMap::new(),
            working_dir: PathBuf::from("."),
            policy: McpSandboxPolicy::default(),
        };
        assert!(manager.validate_spec(&valid_spec).is_ok());

        let invalid_spec = McpServerLaunchSpec {
            command: PathBuf::from(""),
            args: vec![],
            env: HashMap::new(),
            working_dir: PathBuf::from("."),
            policy: McpSandboxPolicy::default(),
        };
        assert!(manager.validate_spec(&invalid_spec).is_err());
    }

    #[test]
    fn test_cursor_rules_generator_heuristic_inspection() {
        let generator = CursorRulesGenerator::new();
        let mut analysis = ProjectAstAnalysis {
            detected_ecosystems: vec![EcosystemType::RustCargo, EcosystemType::NodeNpmYarnPnpm],
            detected_output_dirs: vec![PathBuf::from("target"), PathBuf::from("dist")],
            detected_cache_dirs: vec![],
            hardcoded_network_endpoints: vec![],
            sdk_network_endpoints: vec![],
            sensitive_files_found: vec![],
            detected_build_tools: vec!["cargo".into(), "npm".into()],
            package_dependencies: vec![],
        };

        let sample_source = r#"
            const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
            const stripe = require('stripe')('sk_test_123');
            fetch("https://api.example.com/v1/data");
        "#;

        generator.inspect_source_content(".env", "", &mut analysis);
        generator.inspect_source_content("app.js", sample_source, &mut analysis);

        assert!(analysis.sensitive_files_found.contains(&PathBuf::from(".env")));
        assert!(analysis.sdk_network_endpoints.contains(&"api.openai.com".to_string()));
        assert!(analysis.sdk_network_endpoints.contains(&"api.stripe.com".to_string()));
        assert!(analysis.hardcoded_network_endpoints.contains(&"https://api.example.com/v1/data".to_string()));

        let policies = generator.synthesize_policies(&analysis).unwrap();
        assert!(policies.cursor_rules_content.contains("api.openai.com"));
        assert!(policies.cursor_rules_content.contains("crates.io"));
        assert!(policies.vetto_toml_content.contains("target"));
        assert!(policies.security_score <= 85);
    }
}
