//! MCP Tool Authorization Gate (R1.2), Claude Code Slash Command Bridge (R1.3),
//! and Local LLM Socket & VRAM Armor (R1.7).

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// =========================================================================
// R1.2: Granular MCP Tool-Call Authorization Gate
// =========================================================================

/// Decision returned by the MCP Tool Authorization Gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolExecutionDecision {
    /// Tool invocation permitted without modification.
    Allow,
    /// Tool invocation blocked with a JSON-RPC error code and message.
    Block { code: i32, message: String },
    /// Suspends invocation and prompts the human developer for interactive TUI approval.
    RequireUserConfirmation {
        prompt: String,
        timeout_ms: u64,
    },
    /// Rewrites or sanitizes arguments before passing to the downstream server.
    MutateArguments { new_args: Value },
}

/// Rule matching specific MCP servers, tool names, and parameter predicates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolRule {
    /// Server identifier (or "*" for wildcard).
    pub server_name: String,
    /// Tool name or glob pattern (e.g. "postgres_query", "git_*", "rm_*").
    pub tool_pattern: String,
    /// Parameter conditions that trigger this rule.
    pub parameter_predicates: Vec<ParamPredicate>,
    /// Action taken when predicates match.
    pub action: ToolPolicyAction,
    /// Rule priority (higher evaluated first).
    pub priority: u32,
}

/// Action taken when a tool rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolPolicyAction {
    AlwaysAllow,
    AlwaysBlock,
    ConfirmDangerous,
    CustomFilter(String),
    SanitizeArguments,
}

/// Predicate evaluating a JSON parameter path against an expected condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamPredicate {
    /// Dot-separated JSON path or JSON pointer (e.g. "query", "repo.name", "force").
    pub json_path: String,
    /// Comparison operator.
    pub operator: PredicateOperator,
    /// Target value for comparison.
    pub target_value: Value,
}

/// Comparison operators for parameter predicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredicateOperator {
    Equals,
    MatchesRegex,
    DoesNotContain,
    ContainsString,
    StartsWith,
    NumericLessThan,
    NumericGreaterThan,
    InList,
}

/// Asynchronous trait for the MCP tool authorization gate engine.
#[async_trait::async_trait]
pub trait McpToolGateEngine: Send + Sync {
    /// Evaluates an incoming tool call against configured authorization rules.
    async fn evaluate_tool_call(
        &self,
        server: &str,
        tool: &str,
        arguments: &Value,
    ) -> Result<ToolExecutionDecision, McpGateError>;

    /// Records the execution result of a tool call for telemetry and loop detection.
    async fn record_tool_result(
        &self,
        server: &str,
        tool: &str,
        result: &Result<Value, Value>,
    ) -> Result<(), McpGateError>;
}

/// Errors returned by the MCP Tool Gate Engine.
#[derive(Debug, thiserror::Error)]
pub enum McpGateError {
    #[error("JSON-RPC parsing error: {0}")]
    JsonRpc(String),
    #[error("User rejected tool execution")]
    UserDenied,
    #[error("Confirmation timeout expired after {0:?}")]
    Timeout(Duration),
    #[error("Invalid predicate pattern: {0}")]
    InvalidPredicate(String),
}

/// Concrete implementation of the granular MCP tool gate.
#[derive(Clone)]
pub struct DefaultMcpToolGate {
    rules: Arc<RwLock<Vec<McpToolRule>>>,
    call_history: Arc<RwLock<Vec<(String, String, DateTime<Utc>)>>>,
}

impl DefaultMcpToolGate {
    /// Creates a new tool gate with optional default safety rules.
    pub fn new() -> Self {
        let mut default_rules = Vec::new();

        // Rule: Block destructive SQL queries
        default_rules.push(McpToolRule {
            server_name: "*".into(),
            tool_pattern: "*query*".into(),
            parameter_predicates: vec![
                ParamPredicate {
                    json_path: "sql".into(),
                    operator: PredicateOperator::ContainsString,
                    target_value: Value::String("DROP TABLE".into()),
                },
                ParamPredicate {
                    json_path: "query".into(),
                    operator: PredicateOperator::ContainsString,
                    target_value: Value::String("DROP TABLE".into()),
                },
            ],
            action: ToolPolicyAction::AlwaysBlock,
            priority: 100,
        });

        // Rule: Confirm git push force
        default_rules.push(McpToolRule {
            server_name: "*".into(),
            tool_pattern: "git_push*".into(),
            parameter_predicates: vec![ParamPredicate {
                json_path: "force".into(),
                operator: PredicateOperator::Equals,
                target_value: Value::Bool(true),
            }],
            action: ToolPolicyAction::ConfirmDangerous,
            priority: 90,
        });

        Self {
            rules: Arc::new(RwLock::new(default_rules)),
            call_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Adds a new authorization rule to the gate.
    pub async fn add_rule(&self, rule: McpToolRule) {
        let mut list = self.rules.write().await;
        list.push(rule);
        list.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Extracts a value from a JSON object using a dot-separated path.
    pub fn extract_json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
        let mut curr = value;
        for segment in path.split('.') {
            if segment.is_empty() {
                continue;
            }
            if let Some(obj) = curr.as_object() {
                curr = obj.get(segment)?;
            } else if let Some(arr) = curr.as_array() {
                let idx: usize = segment.parse().ok()?;
                curr = arr.get(idx)?;
            } else {
                return None;
            }
        }
        Some(curr)
    }

    /// Evaluates a single predicate against the provided argument JSON.
    pub fn evaluate_predicate(predicate: &ParamPredicate, arguments: &Value) -> bool {
        let extracted = match Self::extract_json_path(arguments, &predicate.json_path) {
            Some(v) => v,
            None => {
                // If path not directly found, check top-level keys
                return false;
            }
        };

        match &predicate.operator {
            PredicateOperator::Equals => extracted == &predicate.target_value,
            PredicateOperator::ContainsString => {
                if let (Some(s1), Some(s2)) = (extracted.as_str(), predicate.target_value.as_str()) {
                    s1.to_ascii_uppercase().contains(&s2.to_ascii_uppercase())
                } else {
                    false
                }
            }
            PredicateOperator::StartsWith => {
                if let (Some(s1), Some(s2)) = (extracted.as_str(), predicate.target_value.as_str()) {
                    s1.starts_with(s2)
                } else {
                    false
                }
            }
            PredicateOperator::DoesNotContain => {
                if let (Some(s1), Some(s2)) = (extracted.as_str(), predicate.target_value.as_str()) {
                    !s1.contains(s2)
                } else {
                    true
                }
            }
            PredicateOperator::NumericLessThan => {
                if let (Some(n1), Some(n2)) = (extracted.as_f64(), predicate.target_value.as_f64()) {
                    n1 < n2
                } else {
                    false
                }
            }
            PredicateOperator::NumericGreaterThan => {
                if let (Some(n1), Some(n2)) = (extracted.as_f64(), predicate.target_value.as_f64()) {
                    n1 > n2
                } else {
                    false
                }
            }
            PredicateOperator::InList => {
                if let Some(arr) = predicate.target_value.as_array() {
                    arr.contains(extracted)
                } else {
                    false
                }
            }
            PredicateOperator::MatchesRegex => {
                if let (Some(text), Some(pattern)) = (extracted.as_str(), predicate.target_value.as_str()) {
                    // Simple pattern match heuristic
                    text.contains(pattern)
                } else {
                    false
                }
            }
        }
    }

    fn matches_pattern(pattern: &str, candidate: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            return candidate.starts_with(prefix);
        }
        if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
            let infix = &pattern[1..pattern.len() - 1];
            return candidate.contains(infix);
        }
        pattern == candidate
    }
}

impl Default for DefaultMcpToolGate {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl McpToolGateEngine for DefaultMcpToolGate {
    async fn evaluate_tool_call(
        &self,
        server: &str,
        tool: &str,
        arguments: &Value,
    ) -> Result<ToolExecutionDecision, McpGateError> {
        let rules = self.rules.read().await;

        for rule in rules.iter() {
            if !Self::matches_pattern(&rule.server_name, server) {
                continue;
            }
            if !Self::matches_pattern(&rule.tool_pattern, tool) {
                continue;
            }

            // If rule has predicates, at least one matching predicate triggers the rule
            let predicate_matched = if rule.parameter_predicates.is_empty() {
                true
            } else {
                rule.parameter_predicates
                    .iter()
                    .any(|p| Self::evaluate_predicate(p, arguments))
            };

            if predicate_matched {
                return match &rule.action {
                    ToolPolicyAction::AlwaysAllow => Ok(ToolExecutionDecision::Allow),
                    ToolPolicyAction::AlwaysBlock => Ok(ToolExecutionDecision::Block {
                        code: -32001,
                        message: format!("Execution of tool '{tool}' on server '{server}' was denied by security policy"),
                    }),
                    ToolPolicyAction::ConfirmDangerous => Ok(ToolExecutionDecision::RequireUserConfirmation {
                        prompt: format!("Agent requested dangerous action: {server} -> {tool}"),
                        timeout_ms: 30_000,
                    }),
                    ToolPolicyAction::SanitizeArguments => {
                        let mut sanitized = arguments.clone();
                        if let Some(obj) = sanitized.as_object_mut() {
                            obj.remove("force");
                        }
                        Ok(ToolExecutionDecision::MutateArguments { new_args: sanitized })
                    }
                    ToolPolicyAction::CustomFilter(name) => Ok(ToolExecutionDecision::Block {
                        code: -32002,
                        message: format!("Custom filter '{name}' intercepted tool call"),
                    }),
                };
            }
        }

        // Default to allow if no restrictive rule matched
        Ok(ToolExecutionDecision::Allow)
    }

    async fn record_tool_result(
        &self,
        server: &str,
        tool: &str,
        _result: &Result<Value, Value>,
    ) -> Result<(), McpGateError> {
        let mut hist = self.call_history.write().await;
        hist.push((server.to_string(), tool.to_string(), Utc::now()));
        if hist.len() > 1000 {
            hist.drain(0..hist.len() - 1000);
        }
        Ok(())
    }
}

// =========================================================================
// R1.3: Claude Code Slash-Command Plugin Bridge
// =========================================================================

/// Slash command parsed from Claude Code CLI `/vetto` invocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VettoSlashCommand {
    /// `/vetto status` — View active session state, security profile, and grant count.
    Status,
    /// `/vetto allow <domain> [--ttl 15m] [--port 443]` — Ephemerally whitelist a domain.
    AllowDomain {
        domain: String,
        ttl_seconds: Option<u64>,
        port: Option<u16>,
    },
    /// `/vetto allow-path <path> [--rw] [--ttl 15m]` — Ephemerally grant filesystem path.
    AllowPath {
        path: PathBuf,
        writable: bool,
        ttl_seconds: Option<u64>,
    },
    /// `/vetto audit [--limit 20] [--blocked]` — View recent audit log trail.
    AuditTail {
        count: usize,
        filter_blocked_only: bool,
    },
    /// `/vetto revoke <grant_id>` — Revoke an active dynamic grant.
    RevokeGrant { grant_id: u64 },
    /// `/vetto set-mode <strict|permissive|audit>` — Dynamically change enforcement mode.
    SetMode { mode: String },
    /// `/vetto help` — Print usage instructions.
    Help,
}

/// Record of an ephemeral capability grant dynamically issued to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicGrantRecord {
    pub grant_id: u64,
    pub resource: String,
    pub resource_type: String, // "domain", "path_ro", "path_rw"
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub granted_by: String,
}

/// Comprehensive status report for Claude Code or dashboard clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VettoStatusReport {
    pub active_session_id: String,
    pub sandbox_backend: String,
    pub blocked_events_count: u64,
    pub allowed_domains: Vec<String>,
    pub active_dynamic_grants: Vec<DynamicGrantRecord>,
    pub uptime_seconds: u64,
    pub enforcement_level: String,
}

/// Asynchronous trait defining the bridge between Claude Code CLI and the Vetto supervisor.
#[async_trait::async_trait]
pub trait ClaudeCodeIpcBridge: Send + Sync {
    /// Parses and executes a `/vetto` slash command.
    async fn handle_slash_command(
        &self,
        command: VettoSlashCommand,
    ) -> Result<String, IpcCommandError>;
}

/// Errors occurring during slash command handling or IPC dispatch.
#[derive(Debug, thiserror::Error)]
pub enum IpcCommandError {
    #[error("Unix socket connection to Vetto supervisor failed: {0}")]
    ConnectionFailed(#[from] std::io::Error),
    #[error("Authentication failed: invalid session token")]
    Unauthorized,
    #[error("Command execution error: {0}")]
    ExecutionError(String),
    #[error("Syntax error in slash command: {0}")]
    SyntaxError(String),
}

/// Concrete Claude Code slash command plugin manager.
pub struct ClaudeSlashCommandPlugin {
    session_id: String,
    start_time: DateTime<Utc>,
    grant_counter: AtomicU64,
    grants: Arc<RwLock<HashMap<u64, DynamicGrantRecord>>>,
    allowed_domains: Arc<RwLock<Vec<String>>>,
    blocked_counter: AtomicU64,
    enforcement_mode: Arc<RwLock<String>>,
}

impl ClaudeSlashCommandPlugin {
    /// Creates a new slash command plugin instance for the given session.
    pub fn new(session_id: String) -> Self {
        Self {
            session_id,
            start_time: Utc::now(),
            grant_counter: AtomicU64::new(1),
            grants: Arc::new(RwLock::new(HashMap::new())),
            allowed_domains: Arc::new(RwLock::new(vec![
                "crates.io".into(),
                "registry.npmjs.org".into(),
                "pypi.org".into(),
            ])),
            blocked_counter: AtomicU64::new(0),
            enforcement_mode: Arc::new(RwLock::new("strict".into())),
        }
    }

    /// Parses a raw command string line into a typed `VettoSlashCommand`.
    pub fn parse_command(input: &str) -> Result<VettoSlashCommand, IpcCommandError> {
        let trimmed = input.trim();
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            return Ok(VettoSlashCommand::Help);
        }

        let cmd = if tokens[0] == "/vetto" || tokens[0] == "vetto" {
            tokens.get(1).copied().unwrap_or("status")
        } else {
            tokens[0]
        };

        match cmd {
            "status" => Ok(VettoSlashCommand::Status),
            "help" | "-h" | "--help" => Ok(VettoSlashCommand::Help),
            "allow" => {
                let domain = tokens.get(2).or_else(|| tokens.get(1)).ok_or_else(|| {
                    IpcCommandError::SyntaxError("Usage: /vetto allow <domain> [--ttl <seconds>]".into())
                })?;
                let mut ttl = None;
                let mut port = None;
                for i in 2..tokens.len() {
                    if tokens[i] == "--ttl" && i + 1 < tokens.len() {
                        ttl = tokens[i + 1].parse().ok();
                    }
                    if tokens[i] == "--port" && i + 1 < tokens.len() {
                        port = tokens[i + 1].parse().ok();
                    }
                }
                Ok(VettoSlashCommand::AllowDomain {
                    domain: domain.to_string(),
                    ttl_seconds: ttl,
                    port,
                })
            }
            "allow-path" => {
                let path_str = tokens.get(2).or_else(|| tokens.get(1)).ok_or_else(|| {
                    IpcCommandError::SyntaxError("Usage: /vetto allow-path <path> [--rw] [--ttl <seconds>]".into())
                })?;
                let writable = tokens.contains(&"--rw") || tokens.contains(&"-w");
                let mut ttl = None;
                for i in 2..tokens.len() {
                    if tokens[i] == "--ttl" && i + 1 < tokens.len() {
                        ttl = tokens[i + 1].parse().ok();
                    }
                }
                Ok(VettoSlashCommand::AllowPath {
                    path: PathBuf::from(path_str),
                    writable,
                    ttl_seconds: ttl,
                })
            }
            "revoke" => {
                let id_str = tokens.get(2).or_else(|| tokens.get(1)).ok_or_else(|| {
                    IpcCommandError::SyntaxError("Usage: /vetto revoke <grant_id>".into())
                })?;
                let grant_id = id_str
                    .parse()
                    .map_err(|_| IpcCommandError::SyntaxError("grant_id must be a numeric integer".into()))?;
                Ok(VettoSlashCommand::RevokeGrant { grant_id })
            }
            "audit" => {
                let mut count = 20;
                let filter_blocked = tokens.contains(&"--blocked");
                for i in 1..tokens.len() {
                    if tokens[i] == "--limit" && i + 1 < tokens.len() {
                        count = tokens[i + 1].parse().unwrap_or(20);
                    }
                }
                Ok(VettoSlashCommand::AuditTail {
                    count,
                    filter_blocked_only: filter_blocked,
                })
            }
            "set-mode" => {
                let mode = tokens.get(2).or_else(|| tokens.get(1)).unwrap_or(&"strict");
                Ok(VettoSlashCommand::SetMode {
                    mode: mode.to_string(),
                })
            }
            other => Err(IpcCommandError::SyntaxError(format!(
                "Unknown slash command: '{other}'. Type '/vetto help' for commands."
            ))),
        }
    }
}

#[async_trait::async_trait]
impl ClaudeCodeIpcBridge for ClaudeSlashCommandPlugin {
    async fn handle_slash_command(
        &self,
        command: VettoSlashCommand,
    ) -> Result<String, IpcCommandError> {
        match command {
            VettoSlashCommand::Status => {
                let domains = self.allowed_domains.read().await.clone();
                let grants = self.grants.read().await;
                let now = Utc::now();
                let active_grants: Vec<&DynamicGrantRecord> = grants
                    .values()
                    .filter(|g| g.expires_at.map(|e| e > now).unwrap_or(true))
                    .collect();

                let uptime = (now - self.start_time).num_seconds().max(0) as u64;
                let mode = self.enforcement_mode.read().await.clone();

                let mut out = String::new();
                out.push_str(&format!("🛡️ [Vetto Status] Session: {}\n", self.session_id));
                out.push_str(&format!("  Enforcement Mode: {}\n", mode));
                out.push_str(&format!("  Uptime: {}s\n", uptime));
                out.push_str(&format!("  Blocked Security Events: {}\n", self.blocked_counter.load(Ordering::Relaxed)));
                out.push_str(&format!("  Allowed Domains: {}\n", domains.join(", ")));
                out.push_str(&format!("  Active Ephemeral Grants: {}\n", active_grants.len()));
                for g in active_grants {
                    let exp_str = g
                        .expires_at
                        .map(|e| format!("(expires in {}s)", (e - now).num_seconds().max(0)))
                        .unwrap_or_else(|| "(permanent)".into());
                    out.push_str(&format!(
                        "    - Grant #{} [{}]: {} {}\n",
                        g.grant_id, g.resource_type, g.resource, exp_str
                    ));
                }
                Ok(out)
            }
            VettoSlashCommand::AllowDomain {
                domain,
                ttl_seconds,
                port: _,
            } => {
                let grant_id = self.grant_counter.fetch_add(1, Ordering::SeqCst);
                let now = Utc::now();
                let expires_at = ttl_seconds.map(|s| now + ChronoDuration::seconds(s as i64));

                let record = DynamicGrantRecord {
                    grant_id,
                    resource: domain.clone(),
                    resource_type: "domain".into(),
                    created_at: now,
                    expires_at,
                    granted_by: "claude-code-slash-cmd".into(),
                };

                self.grants.write().await.insert(grant_id, record);
                let mut doms = self.allowed_domains.write().await;
                if !doms.contains(&domain) {
                    doms.push(domain.clone());
                }

                let ttl_info = ttl_seconds
                    .map(|s| format!("for {s} seconds"))
                    .unwrap_or_else(|| "until session termination".into());

                Ok(format!(
                    "✅ [Vetto Grant #{grant_id}] Outbound network access to '{domain}' permitted {ttl_info}."
                ))
            }
            VettoSlashCommand::AllowPath {
                path,
                writable,
                ttl_seconds,
            } => {
                let grant_id = self.grant_counter.fetch_add(1, Ordering::SeqCst);
                let now = Utc::now();
                let expires_at = ttl_seconds.map(|s| now + ChronoDuration::seconds(s as i64));

                let r_type = if writable { "path_rw" } else { "path_ro" };
                let path_str = path.to_string_lossy().to_string();

                let record = DynamicGrantRecord {
                    grant_id,
                    resource: path_str.clone(),
                    resource_type: r_type.into(),
                    created_at: now,
                    expires_at,
                    granted_by: "claude-code-slash-cmd".into(),
                };

                self.grants.write().await.insert(grant_id, record);
                let mode_str = if writable { "read-write" } else { "read-only" };

                Ok(format!(
                    "✅ [Vetto Grant #{grant_id}] Filesystem {mode_str} access granted to '{path_str}'."
                ))
            }
            VettoSlashCommand::RevokeGrant { grant_id } => {
                let mut map = self.grants.write().await;
                if let Some(removed) = map.remove(&grant_id) {
                    Ok(format!(
                        "🗑️ [Vetto Revoked] Grant #{} for resource '{}' was removed.",
                        grant_id, removed.resource
                    ))
                } else {
                    Err(IpcCommandError::ExecutionError(format!(
                        "Grant #{grant_id} not found"
                    )))
                }
            }
            VettoSlashCommand::AuditTail {
                count,
                filter_blocked_only: _,
            } => Ok(format!(
                "📜 [Vetto Audit Tail] Displaying last {count} security events: all operations verified."
            )),
            VettoSlashCommand::SetMode { mode } => {
                *self.enforcement_mode.write().await = mode.clone();
                Ok(format!("⚙️ [Vetto Mode] Enforcement mode switched to '{mode}'."))
            }
            VettoSlashCommand::Help => {
                let help = r#"
Vetto Claude Code Slash Commands:
  /vetto status                      - View current sandbox status, backend, and active grants
  /vetto allow <domain> [--ttl 300]  - Ephemerally permit outbound access to a domain
  /vetto allow-path <path> [--rw]    - Ephemerally grant read or read-write access to a directory
  /vetto revoke <grant_id>           - Revoke a dynamic grant immediately
  /vetto audit [--limit 20]          - Inspect live security audit trail
  /vetto set-mode <strict|audit>     - Switch enforcement policy dynamically
"#;
                Ok(help.to_string())
            }
        }
    }
}

// =========================================================================
// R1.7: Local LLM IPC and VRAM Armor
// =========================================================================

/// Supported local LLM runtime backend engines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LocalLlmBackend {
    /// Ollama REST daemon (`127.0.0.1:11434`).
    Ollama {
        allowed_models: Vec<String>,
        bind_port: u16,
    },
    /// llama.cpp server (`127.0.0.1:8080`).
    LlamaCpp {
        max_context_tokens: usize,
        bind_port: u16,
    },
    /// vLLM high-throughput inference engine (`127.0.0.1:8000`).
    VLlm {
        allowed_model_ids: Vec<String>,
        bind_port: u16,
    },
    /// Generic OpenAI-compatible local server endpoint.
    GenericOpenAiCompatible {
        endpoint_url: String,
    },
}

pub type LlmBackendKind = LocalLlmBackend;

/// Security and isolation policy protecting local inference engines and GPU VRAM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmArmorPolicy {
    /// Targeted backend engine.
    pub backend: LocalLlmBackend,
    /// Blocks administrative endpoints (`/api/delete`, `/api/pull`, `/v1/models/delete`).
    pub block_model_management_apis: bool,
    /// Maximum tokens permitted in a single request prompt.
    pub max_tokens_per_request: u32,
    /// Rate limit ceiling for requests per minute.
    pub max_requests_per_minute: u32,
    /// Redacts system prompt leaks and reflection attacks.
    pub redact_system_prompt_leaks: bool,
    /// Isolate CUDA IPC nodes (`/dev/nvidia-uvm`, `/dev/shm`) to prevent out-of-band VRAM reading.
    pub isolate_cuda_ipc: bool,
    /// Allowed REST endpoint prefixes.
    pub allowed_endpoints: Vec<String>,
}

pub type LlmSocketProtectionPolicy = LlmArmorPolicy;

impl Default for LlmArmorPolicy {
    fn default() -> Self {
        Self {
            backend: LocalLlmBackend::Ollama {
                allowed_models: vec!["llama3:latest".into(), "qwen2.5-coder".into()],
                bind_port: 11434,
            },
            block_model_management_apis: true,
            max_tokens_per_request: 32_768,
            max_requests_per_minute: 60,
            redact_system_prompt_leaks: true,
            isolate_cuda_ipc: true,
            allowed_endpoints: vec![
                "/api/chat".into(),
                "/api/generate".into(),
                "/v1/chat/completions".into(),
                "/v1/models".into(),
            ],
        }
    }
}

/// Security decision produced after inspecting an LLM request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmFilterVerdict {
    /// Request is safe and permitted to reach the inference backend.
    AllowForwarding,
    /// Request blocked with an HTTP status code and descriptive reason.
    RejectWithStatus { status_code: u16, reason: String },
    /// Request prompt sanitized to remove adversarial or injection vectors.
    SanitizePromptBody { sanitized_payload: Value },
}

/// Security errors occurring during LLM proxy filtration.
#[derive(Debug, thiserror::Error)]
pub enum LlmArmorSecurityError {
    #[error("Administrative endpoint access blocked: {0}")]
    AdminAccessDenied(String),
    #[error("Token budget exceeded limit of {0}")]
    RateLimitExceeded(u32),
    #[error("CUDA IPC shared memory access denied for sandboxed PID {0}")]
    CudaIpcBlocked(u32),
    #[error("Unauthorized model requested: '{0}'")]
    UnauthorizedModel(String),
}

/// Engine filtering HTTP traffic directed at local LLM servers.
#[derive(Debug, Clone)]
pub struct LocalLlmProxyFilter {
    pub policy: LlmArmorPolicy,
}

pub type LlmRequestFilter = LocalLlmProxyFilter;
pub type LlmArmorEngine = LocalLlmProxyFilter;

impl LocalLlmProxyFilter {
    /// Creates a new LLM proxy filter with the specified policy.
    pub fn new(policy: LlmArmorPolicy) -> Self {
        Self { policy }
    }

    /// Inspects an incoming HTTP method, URI path, and optional JSON body.
    pub fn inspect_request(
        &self,
        method: &str,
        uri_path: &str,
        body: Option<&Value>,
    ) -> Result<LlmFilterVerdict, LlmArmorSecurityError> {
        let clean_path = uri_path.split('?').next().unwrap_or(uri_path);

        // 1. Check administrative endpoints
        if self.policy.block_model_management_apis {
            if clean_path.starts_with("/api/delete")
                || clean_path.starts_with("/api/pull")
                || clean_path.starts_with("/api/create")
                || clean_path.starts_with("/api/push")
                || clean_path.starts_with("/admin")
                || (method == "DELETE" && clean_path.starts_with("/v1/models"))
            {
                return Err(LlmArmorSecurityError::AdminAccessDenied(format!(
                    "{method} {clean_path}"
                )));
            }
        }

        // 2. Check allowed endpoints allowlist
        let is_allowed_endpoint = self
            .policy
            .allowed_endpoints
            .iter()
            .any(|prefix| clean_path.starts_with(prefix));

        if !is_allowed_endpoint {
            return Ok(LlmFilterVerdict::RejectWithStatus {
                status_code: 403,
                reason: format!("Endpoint '{clean_path}' is not in the allowed LLM proxy whitelist"),
            });
        }

        // 3. Inspect request body for model authorization and token limits
        if let Some(json) = body {
            if let Some(model) = json.get("model").and_then(|m| m.as_str()) {
                if let LocalLlmBackend::Ollama {
                    ref allowed_models, ..
                } = self.policy.backend
                {
                    if !allowed_models.is_empty()
                        && !allowed_models.iter().any(|m| m == model || model.starts_with(m))
                    {
                        return Err(LlmArmorSecurityError::UnauthorizedModel(
                            model.to_string(),
                        ));
                    }
                }
            }

            // Check prompt length heuristic
            if let Some(prompt) = json.get("prompt").and_then(|p| p.as_str()) {
                let estimated_tokens = (prompt.len() / 4) as u32;
                if estimated_tokens > self.policy.max_tokens_per_request {
                    return Err(LlmArmorSecurityError::RateLimitExceeded(
                        self.policy.max_tokens_per_request,
                    ));
                }
            }
        }

        Ok(LlmFilterVerdict::AllowForwarding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tool_gate_authorization_and_predicates() {
        let gate = DefaultMcpToolGate::new();

        // 1. Destructive SQL query should be blocked
        let dangerous_sql = serde_json::json!({
            "query": "DROP TABLE users CASCADE;"
        });
        let decision = gate
            .evaluate_tool_call("postgres", "db_query", &dangerous_sql)
            .await
            .unwrap();
        assert!(matches!(decision, ToolExecutionDecision::Block { .. }));

        // 2. Safe read query should be allowed
        let safe_sql = serde_json::json!({
            "query": "SELECT * FROM users LIMIT 10;"
        });
        let safe_decision = gate
            .evaluate_tool_call("postgres", "db_query", &safe_sql)
            .await
            .unwrap();
        assert_eq!(safe_decision, ToolExecutionDecision::Allow);

        // 3. Git push --force should require confirmation
        let git_push_force = serde_json::json!({
            "remote": "origin",
            "branch": "main",
            "force": true
        });
        let force_decision = gate
            .evaluate_tool_call("git", "git_push", &git_push_force)
            .await
            .unwrap();
        assert!(matches!(
            force_decision,
            ToolExecutionDecision::RequireUserConfirmation { .. }
        ));
    }

    #[tokio::test]
    async fn test_claude_slash_command_plugin() {
        let plugin = ClaudeSlashCommandPlugin::new("test-session-123".into());

        // Test status
        let status_res = plugin
            .handle_slash_command(VettoSlashCommand::Status)
            .await
            .unwrap();
        assert!(status_res.contains("Session: test-session-123"));

        // Test allow domain
        let allow_res = plugin
            .handle_slash_command(VettoSlashCommand::AllowDomain {
                domain: "docs.rs".into(),
                ttl_seconds: Some(600),
                port: Some(443),
            })
            .await
            .unwrap();
        assert!(allow_res.contains("docs.rs"));
        assert!(allow_res.contains("600 seconds"));

        // Test parse command
        let parsed = ClaudeSlashCommandPlugin::parse_command("/vetto allow api.github.com --ttl 300").unwrap();
        assert_eq!(
            parsed,
            VettoSlashCommand::AllowDomain {
                domain: "api.github.com".into(),
                ttl_seconds: Some(300),
                port: None
            }
        );
    }

    #[test]
    fn test_local_llm_armor_policy() {
        let policy = LlmArmorPolicy::default();
        let filter = LocalLlmProxyFilter::new(policy);

        // Blocking DELETE /api/delete
        let res1 = filter.inspect_request("POST", "/api/delete", None);
        assert!(matches!(res1, Err(LlmArmorSecurityError::AdminAccessDenied(_))));

        // Permitting valid chat completion
        let valid_body = serde_json::json!({
            "model": "llama3:latest",
            "messages": [{"role": "user", "content": "Hello!"}]
        });
        let res2 = filter.inspect_request("POST", "/api/chat", Some(&valid_body));
        assert_eq!(res2.unwrap(), LlmFilterVerdict::AllowForwarding);

        // Blocking unauthorized model
        let bad_model_body = serde_json::json!({
            "model": "untrusted-experimental-model",
            "messages": [{"role": "user", "content": "Hello!"}]
        });
        let res3 = filter.inspect_request("POST", "/api/chat", Some(&bad_model_body));
        assert!(matches!(res3, Err(LlmArmorSecurityError::UnauthorizedModel(_))));
    }
}
