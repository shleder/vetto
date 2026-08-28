//! Deterministic JSON-RPC 2.0 Session Replay (R1.10)
//! and Streaming SIMD stdio/PTY Buffer Scrubbing (R1.12).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

// =========================================================================
// R1.10: Deterministic JSON-RPC 2.0 Session Replay & Mock Engine
// =========================================================================

/// Direction of an intercepted JSON-RPC 2.0 frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcDirection {
    /// Request sent from client (AI Agent) to MCP Server.
    ClientToServer,
    /// Response sent from MCP Server to client.
    ServerToClient,
}

/// Recorded JSON-RPC 2.0 event frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTraceFrame {
    /// Monotonically increasing sequence number.
    pub sequence_id: u64,
    /// Relative timestamp offset in nanoseconds from session start.
    pub relative_timestamp_ns: u64,
    /// Message direction.
    pub direction: RpcDirection,
    /// Target MCP server name.
    pub server_name: String,
    /// JSON-RPC method name (e.g. "tools/call", "resources/read", "roots/list").
    pub method: String,
    /// Optional invocation parameters payload.
    pub params: Option<Value>,
    /// Optional success result payload.
    pub result: Option<Value>,
    /// Optional error payload.
    pub error: Option<Value>,
    /// JSON-RPC call ID.
    pub call_id: Option<Value>,
}

pub type RecordedRpcEntry = RpcTraceFrame;

/// Manifest header describing a recorded `.vetto-trace` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTraceManifest {
    pub trace_version: u32,
    pub recorded_at: DateTime<Utc>,
    pub agent_name: String,
    pub frames_count: usize,
    pub checksum_sha256: String,
    pub metadata: HashMap<String, String>,
}

/// Matching strategy used during offline session replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayMatchStrategy {
    /// Strict sequential matching of calls in identical recorded order.
    StrictSequence,
    /// Content hash matching (hash of server + method + canonical args).
    MethodAndArgsHash,
    /// Fuzzy heuristic matching allowing partial argument variations.
    FuzzyMatch,
}

/// Active session recorder capturing JSON-RPC 2.0 frames in real-time.
#[derive(Debug, Clone)]
pub struct JsonRpcRecordingSession {
    agent_name: String,
    start_instant: Instant,
    recorded_at: DateTime<Utc>,
    frames: Vec<RpcTraceFrame>,
    metadata: HashMap<String, String>,
}

impl JsonRpcRecordingSession {
    /// Initializes a new recording session for the specified agent.
    pub fn new(agent_name: String) -> Self {
        Self {
            agent_name,
            start_instant: Instant::now(),
            recorded_at: Utc::now(),
            frames: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Records a new RPC frame into the in-memory trace.
    pub fn record_frame(
        &mut self,
        direction: RpcDirection,
        server_name: &str,
        method: &str,
        params: Option<Value>,
        result: Option<Value>,
        error: Option<Value>,
        call_id: Option<Value>,
    ) {
        let sequence_id = self.frames.len() as u64 + 1;
        let relative_timestamp_ns = self.start_instant.elapsed().as_nanos() as u64;

        self.frames.push(RpcTraceFrame {
            sequence_id,
            relative_timestamp_ns,
            direction,
            server_name: server_name.to_string(),
            method: method.to_string(),
            params,
            result,
            error,
            call_id,
        });
    }

    /// Serializes the recorded session into JSON with an integrity checksum.
    pub fn export_trace_json(&self) -> Result<String, ReplayLoadError> {
        let frames_json = serde_json::to_string(&self.frames)
            .map_err(|e| ReplayLoadError::CorruptTrace(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(frames_json.as_bytes());
        let checksum = format!("{:x}", hasher.finalize());

        let manifest = McpTraceManifest {
            trace_version: 1,
            recorded_at: self.recorded_at,
            agent_name: self.agent_name.clone(),
            frames_count: self.frames.len(),
            checksum_sha256: checksum,
            metadata: self.metadata.clone(),
        };

        let bundle = serde_json::json!({
            "manifest": manifest,
            "frames": self.frames,
        });

        serde_json::to_string_pretty(&bundle)
            .map_err(|e| ReplayLoadError::CorruptTrace(e.to_string()))
    }
}

/// Errors occurring during session replay and mock execution.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("No matching recorded response found for method '{0}' on server '{1}'")]
    UnmatchedCall(String, String),
    #[error("Replay trace exhausted at frame index {0}")]
    TraceExhausted(usize),
    #[error("Checksum verification failed for trace")]
    IntegrityViolation,
}

/// Errors occurring during trace loading and deserialization.
#[derive(Debug, thiserror::Error)]
pub enum ReplayLoadError {
    #[error("Failed to read trace file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Decompression / deserialization error: {0}")]
    CorruptTrace(String),
}

/// Replay and mock engine serving deterministic responses to agents from recorded traces.
#[derive(Debug, Clone)]
pub struct McpReplayEngine {
    pub manifest: McpTraceManifest,
    pub recorded_frames: Vec<RpcTraceFrame>,
    pub current_cursor: usize,
    pub match_strategy: ReplayMatchStrategy,
}

pub type MockRpcEngine = McpReplayEngine;

impl McpReplayEngine {
    /// Loads a recorded trace from a JSON string payload.
    pub fn load_from_trace_json(json_data: &str) -> Result<Self, ReplayLoadError> {
        let parsed: Value = serde_json::from_str(json_data)
            .map_err(|e| ReplayLoadError::CorruptTrace(e.to_string()))?;

        let manifest: McpTraceManifest = serde_json::from_value(
            parsed
                .get("manifest")
                .cloned()
                .ok_or_else(|| ReplayLoadError::CorruptTrace("Missing manifest".into()))?,
        )
        .map_err(|e| ReplayLoadError::CorruptTrace(e.to_string()))?;

        let frames: Vec<RpcTraceFrame> = serde_json::from_value(
            parsed
                .get("frames")
                .cloned()
                .ok_or_else(|| ReplayLoadError::CorruptTrace("Missing frames".into()))?,
        )
        .map_err(|e| ReplayLoadError::CorruptTrace(e.to_string()))?;

        Ok(Self {
            manifest,
            recorded_frames: frames,
            current_cursor: 0,
            match_strategy: ReplayMatchStrategy::MethodAndArgsHash,
        })
    }

    /// Verifies the cryptographic SHA-256 integrity of the loaded trace.
    pub fn verify_integrity(&self) -> bool {
        if let Ok(frames_json) = serde_json::to_string(&self.recorded_frames) {
            let mut hasher = Sha256::new();
            hasher.update(frames_json.as_bytes());
            let computed = format!("{:x}", hasher.finalize());
            computed == self.manifest.checksum_sha256
        } else {
            false
        }
    }

    /// Computes a deterministic canonical hash of an RPC call.
    pub fn compute_call_hash(server: &str, method: &str, params: &Option<Value>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(server.as_bytes());
        hasher.update(b":");
        hasher.update(method.as_bytes());
        hasher.update(b":");
        if let Some(p) = params {
            let s = p.to_string();
            hasher.update(s.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Fetches a mocked response corresponding to the requested tool call or method.
    pub fn get_mocked_response(
        &mut self,
        server: &str,
        method: &str,
        params: &Option<Value>,
    ) -> Result<Value, ReplayError> {
        match self.match_strategy {
            ReplayMatchStrategy::StrictSequence => {
                while self.current_cursor < self.recorded_frames.len() {
                    let frame = &self.recorded_frames[self.current_cursor];
                    self.current_cursor += 1;
                    if frame.server_name == server && frame.method == method {
                        if let Some(ref res) = frame.result {
                            return Ok(res.clone());
                        }
                        if let Some(ref err) = frame.error {
                            return Ok(serde_json::json!({ "error": err }));
                        }
                    }
                }
                Err(ReplayError::TraceExhausted(self.current_cursor))
            }
            ReplayMatchStrategy::MethodAndArgsHash => {
                let target_hash = Self::compute_call_hash(server, method, params);
                for frame in &self.recorded_frames {
                    let h = Self::compute_call_hash(&frame.server_name, &frame.method, &frame.params);
                    if h == target_hash {
                        if let Some(ref res) = frame.result {
                            return Ok(res.clone());
                        }
                        if let Some(ref err) = frame.error {
                            return Ok(serde_json::json!({ "error": err }));
                        }
                    }
                }
                // Fallback: match by server and method if args differ slightly
                for frame in &self.recorded_frames {
                    if frame.server_name == server && frame.method == method {
                        if let Some(ref res) = frame.result {
                            return Ok(res.clone());
                        }
                    }
                }
                Err(ReplayError::UnmatchedCall(method.to_string(), server.to_string()))
            }
            ReplayMatchStrategy::FuzzyMatch => {
                for frame in &self.recorded_frames {
                    if frame.server_name == server && frame.method == method {
                        if let Some(ref res) = frame.result {
                            return Ok(res.clone());
                        }
                    }
                }
                Err(ReplayError::UnmatchedCall(method.to_string(), server.to_string()))
            }
        }
    }
}

// =========================================================================
// R1.12: Streaming SIMD stdio/PTY Buffer Scrubbing
// =========================================================================

/// Match occurrence produced during stream scrubbing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubbingMatch {
    pub pattern_name: String,
    pub start_idx: usize,
    pub end_idx: usize,
    pub confidence: f32,
}

/// Real-time statistics tracked during stream redaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScrubStatistics {
    pub total_bytes_processed: u64,
    pub secrets_redacted_count: u64,
    pub ansi_control_sequences_stripped: u64,
    pub entropy_violations_found: u64,
}

/// Trait for PTY and stdio stream redacting filters.
pub trait PtyStreamSanitizer: Send + Sync {
    fn sanitize_stream(&self, raw_input: &[u8]) -> Vec<u8>;
}

/// High-throughput streaming buffer scrubber removing ANSI escapes, secrets, and high-entropy tokens.
#[derive(Debug, Clone)]
pub struct SimdTokenScrubber {
    known_secret_prefixes: Vec<(&'static str, &'static str)>,
    entropy_threshold: f64,
    replacement_token: &'static [u8],
}

pub type SimdPatternMatcher = SimdTokenScrubber;
pub type StreamScrubEngine = SimdTokenScrubber;

impl SimdTokenScrubber {
    /// Creates a new scrubber with standard credential token signatures.
    pub fn new(entropy_threshold: f64) -> Self {
        let prefixes = vec![
            ("AKIA", "AWS_ACCESS_KEY"),
            ("ASIA", "AWS_TEMP_KEY"),
            ("ghp_", "GITHUB_PAT"),
            ("gho_", "GITHUB_OAUTH"),
            ("xoxb-", "SLACK_BOT_TOKEN"),
            ("xoxp-", "SLACK_USER_TOKEN"),
            ("sk-proj-", "OPENAI_API_KEY"),
            ("sk-ant-", "ANTHROPIC_API_KEY"),
            ("Bearer eyJ", "JWT_BEARER_TOKEN"),
        ];

        Self {
            known_secret_prefixes: prefixes,
            entropy_threshold,
            replacement_token: b"[VETTO_REDACTED_SECRET]",
        }
    }

    /// Computes Shannon entropy (bits per byte) of a byte slice.
    pub fn compute_shannon_entropy(slice: &[u8]) -> f64 {
        if slice.is_empty() {
            return 0.0;
        }

        let mut counts = [0usize; 256];
        for &b in slice {
            counts[b as usize] += 1;
        }

        let len_f = slice.len() as f64;
        let mut entropy = 0.0;

        for &c in &counts {
            if c > 0 {
                let p = c as f64 / len_f;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Strips ANSI terminal escape sequences (CSI sequences `\x1b[...]` and OSC `\x1b]...`) from stream.
    pub fn strip_ansi_escapes(input: &[u8], stats: &mut ScrubStatistics) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        let mut idx = 0;
        let len = input.len();

        while idx < len {
            if input[idx] == 0x1b && idx + 1 < len {
                stats.ansi_control_sequences_stripped += 1;
                let next = input[idx + 1];
                if next == b'[' {
                    // CSI sequence: parse until terminating byte (0x40..=0x7e)
                    idx += 2;
                    while idx < len && (input[idx] < 0x40 || input[idx] > 0x7e) {
                        idx += 1;
                    }
                    if idx < len {
                        idx += 1; // skip terminator
                    }
                    continue;
                } else if next == b']' {
                    // OSC sequence: parse until BEL (0x07) or ST (0x1b 0x5c)
                    idx += 2;
                    while idx < len && input[idx] != 0x07 && !(input[idx] == 0x1b && idx + 1 < len && input[idx + 1] == 0x5c) {
                        idx += 1;
                    }
                    if idx < len && input[idx] == 0x07 {
                        idx += 1;
                    } else if idx + 1 < len && input[idx] == 0x1b {
                        idx += 2;
                    }
                    continue;
                } else {
                    idx += 2;
                    continue;
                }
            } else {
                output.push(input[idx]);
                idx += 1;
            }
        }

        output
    }

    /// Scrubs secrets and high-entropy substrings in-place or copies to a sanitized buffer.
    pub fn scrub_buffer(&self, raw_input: &[u8], stats: &mut ScrubStatistics) -> Vec<u8> {
        stats.total_bytes_processed += raw_input.len() as u64;

        // 1. Strip ANSI escape sequences
        let cleaned = Self::strip_ansi_escapes(raw_input, stats);

        // 2. Scan and redact known secret tokens
        let mut output = Vec::with_capacity(cleaned.len());
        let mut idx = 0;
        let len = cleaned.len();

        while idx < len {
            let mut matched = false;

            // Check known secret prefixes
            for &(prefix, _) in &self.known_secret_prefixes {
                let p_bytes = prefix.as_bytes();
                if idx + p_bytes.len() <= len && &cleaned[idx..idx + p_bytes.len()] == p_bytes {
                    // Secret detected! Scan until next whitespace or delimiter
                    let mut end = idx + p_bytes.len();
                    while end < len
                        && cleaned[end] != b' '
                        && cleaned[end] != b'\n'
                        && cleaned[end] != b'\r'
                        && cleaned[end] != b'\t'
                        && cleaned[end] != b'"'
                        && cleaned[end] != b'\''
                    {
                        end += 1;
                    }

                    stats.secrets_redacted_count += 1;
                    output.extend_from_slice(self.replacement_token);
                    idx = end;
                    matched = true;
                    break;
                }
            }

            if !matched {
                output.push(cleaned[idx]);
                idx += 1;
            }
        }

        // 3. Scan words for Shannon entropy threshold anomalies (only tokens >= 24 chars)
        let text = String::from_utf8_lossy(&output);
        let mut final_output = String::with_capacity(text.len());

        for word in text.split(' ') {
            if word.len() >= 24 && !word.contains("[VETTO_REDACTED") {
                let ent = Self::compute_shannon_entropy(word.as_bytes());
                if ent >= self.entropy_threshold {
                    stats.entropy_violations_found += 1;
                    stats.secrets_redacted_count += 1;
                    final_output.push_str("[VETTO_REDACTED_HIGH_ENTROPY] ");
                    continue;
                }
            }
            final_output.push_str(word);
            final_output.push(' ');
        }

        if final_output.ends_with(' ') {
            final_output.pop();
        }

        final_output.into_bytes()
    }
}

impl Default for SimdTokenScrubber {
    fn default() -> Self {
        Self::new(4.5)
    }
}

impl PtyStreamSanitizer for SimdTokenScrubber {
    fn sanitize_stream(&self, raw_input: &[u8]) -> Vec<u8> {
        let mut stats = ScrubStatistics::default();
        self.scrub_buffer(raw_input, &mut stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_recording_and_replay_engine() {
        let mut session = JsonRpcRecordingSession::new("test-agent".into());

        // Record tools/call request and response
        let params = serde_json::json!({ "name": "read_file", "path": "/src/main.rs" });
        let result = serde_json::json!({ "content": "fn main() {}" });

        session.record_frame(
            RpcDirection::ClientToServer,
            "filesystem-mcp",
            "tools/call",
            Some(params.clone()),
            Some(result.clone()),
            None,
            Some(Value::from(1)),
        );

        let exported = session.export_trace_json().unwrap();
        assert!(exported.contains("filesystem-mcp"));

        let mut replay = McpReplayEngine::load_from_trace_json(&exported).unwrap();
        assert!(replay.verify_integrity());

        let mocked = replay
            .get_mocked_response("filesystem-mcp", "tools/call", &Some(params))
            .unwrap();
        assert_eq!(mocked, result);
    }

    #[test]
    fn test_simd_scrubber_redaction_and_ansi_stripping() {
        let scrubber = SimdTokenScrubber::default();
        let mut stats = ScrubStatistics::default();

        let terminal_output = b"\x1b[32mSUCCESS:\x1b[0m AWS Key is AKIA1234567890EXAMPLE and token ghp_secretpat1234567890 \x1b[1mDone\x1b[0m";

        let scrubbed = scrubber.scrub_buffer(terminal_output, &mut stats);
        let scrubbed_str = String::from_utf8_lossy(&scrubbed);

        assert!(!scrubbed_str.contains("AKIA1234567890EXAMPLE"));
        assert!(!scrubbed_str.contains("ghp_secretpat"));
        assert!(scrubbed_str.contains("[VETTO_REDACTED_SECRET]"));
        assert!(!scrubbed_str.contains("\x1b[32m"));
        assert!(stats.secrets_redacted_count >= 2);
        assert!(stats.ansi_control_sequences_stripped >= 2);
    }

    #[test]
    fn test_shannon_entropy() {
        let low_ent = b"AAAAAAAAAAAAAAAAAAAA";
        assert!(SimdTokenScrubber::compute_shannon_entropy(low_ent) < 0.1);

        let high_ent = b"a8F9z!q2L#mP0x$V7r@K9wB4";
        assert!(SimdTokenScrubber::compute_shannon_entropy(high_ent) > 4.0);
    }
}
