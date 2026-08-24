use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::report;

use super::adapter::RescueAdapter;
use super::codex_inventory;
use super::types::{
    AdapterStatus, Availability, RescueContext, SessionHealth, SessionRef, SessionView,
    SnapshotReceipt,
};

pub struct CodexAdapter;

// Semantic inspection is intentionally separate from replay.  These limits
// keep attacker-controlled IDs and future schemas from turning diagnosis into
// an unbounded allocation while still covering ordinary long-lived rollouts.
const MAX_SEMANTIC_FINDINGS: usize = 128;
const MAX_CORRELATION_STATES: usize = 1024;
const MAX_CALL_OCCURRENCES: usize = 2;
const MAX_RETIRED_CALL_IDS: usize = 1024;
const MAX_SEMANTIC_ID_BYTES: usize = 4096;

const CALL_FAMILIES: [&str; 3] = ["function_call", "custom_tool_call", "tool_search_call"];

fn output_family(kind: &str) -> Option<&'static str> {
    match kind {
        "function_call_output" => Some("function_call"),
        "custom_tool_call_output" => Some("custom_tool_call"),
        "tool_search_output" => Some("tool_search_call"),
        _ => None,
    }
}

fn response_item_id_prefix(kind: &str) -> Option<&'static str> {
    // Keep this table aligned with Codex's ResponseItem::id_prefix().  A
    // missing prefix is not rejected: upstream deliberately accepts legacy
    // unprefixed IDs and clears them before replay.
    match kind {
        "additional_tools" => Some("at"),
        "message" => Some("msg"),
        "agent_message" => Some("amsg"),
        "reasoning" => Some("rs"),
        "local_shell_call" => Some("lsh"),
        "function_call" => Some("fc"),
        "tool_search_call" => Some("tsc"),
        "function_call_output" => Some("fco"),
        "custom_tool_call" => Some("ctc"),
        "custom_tool_call_output" => Some("ctco"),
        "tool_search_output" => Some("tso"),
        "web_search_call" => Some("ws"),
        "image_generation_call" => Some("ig"),
        "compaction" | "context_compaction" => Some("cmp"),
        _ => None,
    }
}

fn is_known_response_item_type(kind: &str) -> bool {
    response_item_id_prefix(kind).is_some()
}

fn is_known_event_msg_type(kind: &str) -> bool {
    // These current operational events used to be mistaken for future
    // schemas.  They carry a call identity but are not response-item call /
    // output pairs, so they are recognized without inventing correlation.
    matches!(
        kind,
        "mcp_tool_call_begin"
            | "mcp_tool_call_end"
            | "view_image_tool_call"
            | "dynamic_tool_call_request"
            | "dynamic_tool_call_response"
    )
}

fn is_call_family(kind: &str) -> bool {
    CALL_FAMILIES.contains(&kind)
}

#[derive(Default)]
struct CallState {
    families: Vec<String>,
}

#[derive(Default)]
struct SemanticDiagnostics {
    findings: Vec<String>,
    calls: HashMap<String, CallState>,
    outputs: HashMap<String, CallState>,
    retired_ids: HashSet<String>,
    retired_order: VecDeque<String>,
    correlation_overflow: bool,
}

impl SemanticDiagnostics {
    fn push_finding(&mut self, finding: &'static str) {
        if self.findings.len() < MAX_SEMANTIC_FINDINGS
            && !self.findings.iter().any(|item| item == finding)
        {
            self.findings.push(finding.to_string());
        }
    }

    fn check_persisted_id(&mut self, payload: &serde_json::Map<String, serde_json::Value>, kind: &str) {
        let Some(expected) = response_item_id_prefix(kind) else {
            return;
        };
        let Some(value) = payload.get("id") else {
            return;
        };
        // Optional IDs are valid when explicitly null as well as when absent.
        if value.is_null() {
            return;
        }
        let Some(raw_id) = value.as_str() else {
            self.push_finding("INVALID_PERSISTED_ITEM_ID");
            return;
        };
        if raw_id.is_empty() {
            self.push_finding("INVALID_PERSISTED_ITEM_ID");
            return;
        }
        let Some((prefix, suffix)) = raw_id.split_once('_') else {
            // Legacy persisted IDs are intentionally compatible.
            return;
        };
        if prefix != expected || suffix.is_empty() {
            self.push_finding("INVALID_PERSISTED_ITEM_ID");
        }
    }

    fn operational_schema_issue(
        &self,
        payload: &serde_json::Map<String, serde_json::Value>,
        outer_type: Option<&str>,
    ) -> bool {
        let Some(outer_type) = outer_type else {
            return false;
        };
        if outer_type != "response_item" && outer_type != "event_msg" {
            return false;
        }
        let Some(kind) = payload.get("type").and_then(serde_json::Value::as_str) else {
            return true;
        };

        let identity_present = payload
            .get("call_id")
            .or_else(|| (outer_type == "response_item").then(|| payload.get("id")).flatten())
            .is_some_and(|value| !value.is_null() && value.as_str().is_some_and(|s| !s.is_empty()));
        let lower = kind.to_ascii_lowercase();
        let looks_operational = is_known_event_msg_type(kind)
            || output_family(kind).is_some()
            || is_call_family(kind)
            || kind.ends_with("_call")
            || kind.ends_with("_output")
            || lower.contains("tool")
            || (identity_present
                && (lower.contains("event")
                    || lower.starts_with("future_")
                    || lower.starts_with("unknown_")));
        if !looks_operational {
            return false;
        }

        let known = if outer_type == "response_item" {
            is_known_response_item_type(kind)
        } else {
            is_known_event_msg_type(kind)
        };
        if !known {
            return true;
        }

        let requires_identity = is_call_family(kind)
            || output_family(kind).is_some()
            || (outer_type == "event_msg" && is_known_event_msg_type(kind))
            || matches!(kind, "web_search_call" | "image_generation_call");
        if requires_identity {
            let call_id = payload
                .get("call_id")
                .or_else(|| payload.get("id"))
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty());
            if call_id.is_none() {
                return true;
            }
            if is_call_family(kind)
                && payload
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_none()
            {
                return true;
            }
        }
        false
    }

    fn add_correlation(&mut self, kind: &str, payload: &serde_json::Map<String, serde_json::Value>) {
        let call_kind = is_call_family(kind);
        let output_kind = output_family(kind);
        if !call_kind && output_kind.is_none() {
            return;
        }

        let Some(call_id) = payload
            .get("call_id")
            .or_else(|| payload.get("id"))
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        if call_id.len() > MAX_SEMANTIC_ID_BYTES {
            self.correlation_overflow = true;
            self.push_finding("UNKNOWN_OPERATIONAL_SCHEMA");
            return;
        }

        if call_kind {
            if !self.calls.contains_key(call_id)
                && !self.outputs.contains_key(call_id)
                && self.calls.len().saturating_add(self.outputs.len()) >= MAX_CORRELATION_STATES
            {
                self.correlation_overflow = true;
                self.push_finding("UNKNOWN_OPERATIONAL_SCHEMA");
                return;
            }
            let occurrences_overflow = {
                let state = self.calls.entry(call_id.to_string()).or_default();
                if state.families.len() < MAX_CALL_OCCURRENCES {
                    state.families.push(kind.to_string());
                    false
                } else {
                    true
                }
            };
            if occurrences_overflow {
                self.correlation_overflow = true;
                self.push_finding("UNKNOWN_OPERATIONAL_SCHEMA");
            }
            if self.retired_ids.contains(call_id) {
                self.push_finding("UNKNOWN_OPERATIONAL_SCHEMA");
            }
        } else if let Some(output_family) = output_kind {
            if !self.outputs.contains_key(call_id)
                && !self.calls.contains_key(call_id)
                && self.calls.len().saturating_add(self.outputs.len()) >= MAX_CORRELATION_STATES
            {
                self.correlation_overflow = true;
                self.push_finding("UNKNOWN_OPERATIONAL_SCHEMA");
                return;
            }
            let occurrences_overflow = {
                let state = self.outputs.entry(call_id.to_string()).or_default();
                if state.families.len() < MAX_CALL_OCCURRENCES {
                    state.families.push(output_family.to_string());
                    false
                } else {
                    true
                }
            };
            if occurrences_overflow {
                self.correlation_overflow = true;
                self.push_finding("UNKNOWN_OPERATIONAL_SCHEMA");
            }
        }

        self.retire_completed(call_id);
    }

    fn retire_completed(&mut self, call_id: &str) {
        let completed = self
            .calls
            .get(call_id)
            .zip(self.outputs.get(call_id))
            .is_some_and(|(call_state, output_state)| {
                call_state.families.len() == 1
                    && output_state.families.len() == 1
                    && call_state.families[0] == output_state.families[0]
            });
        if !completed {
            return;
        }
        self.calls.remove(call_id);
        self.outputs.remove(call_id);
        if self.retired_order.len() == MAX_RETIRED_CALL_IDS {
            if let Some(oldest) = self.retired_order.pop_front() {
                self.retired_ids.remove(&oldest);
            }
        }
        let owned = call_id.to_string();
        self.retired_order.push_back(owned.clone());
        self.retired_ids.insert(owned);
    }

    fn inspect(&mut self, value: &serde_json::Value) {
        let Some(record) = value.as_object() else {
            return;
        };
        let outer_type = record.get("type").and_then(serde_json::Value::as_str);
        let Some(payload) = record.get("payload").and_then(serde_json::Value::as_object) else {
            return;
        };
        let Some(kind) = payload.get("type").and_then(serde_json::Value::as_str) else {
            if outer_type == Some("response_item") || outer_type == Some("event_msg") {
                self.push_finding("UNKNOWN_OPERATIONAL_SCHEMA");
            }
            return;
        };
        if outer_type == Some("response_item") {
            self.check_persisted_id(payload, kind);
        }
        if self.operational_schema_issue(payload, outer_type) {
            self.push_finding("UNKNOWN_OPERATIONAL_SCHEMA");
        }
        self.add_correlation(kind, payload);
    }

    fn finish(mut self) -> Vec<String> {
        let mut unfinished = false;
        let mut ambiguous = false;
        for (call_id, call_state) in &self.calls {
            let Some(output_state) = self.outputs.get(call_id) else {
                unfinished = true;
                continue;
            };
            let one_to_one = call_state.families.len() == 1
                && output_state.families.len() == 1
                && call_state.families[0] == output_state.families[0];
            if !one_to_one {
                ambiguous = true;
                unfinished = true;
            }
        }
        if self
            .outputs
            .keys()
            .any(|call_id| !self.calls.contains_key(call_id))
        {
            ambiguous = true;
        }
        if ambiguous || self.correlation_overflow {
            self.push_finding("UNKNOWN_OPERATIONAL_SCHEMA");
        }
        if unfinished {
            self.push_finding("UNFINISHED_TOOL_CALL");
        }
        self.findings
    }
}

impl CodexAdapter {
    fn session_roots(context: &RescueContext) -> [PathBuf; 2] {
        [
            context.root.join("sessions"),
            context.root.join("archived_sessions"),
        ]
    }

    fn validate_root(context: &RescueContext) -> Result<PathBuf> {
        let metadata = fs::symlink_metadata(&context.root)
            .with_context(|| format!("inspect rescue root {}", context.root.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "rescue root must be a real directory, not a symlink: {}",
                context.root.display()
            );
        }
        fs::canonicalize(&context.root)
            .with_context(|| format!("canonicalize rescue root {}", context.root.display()))
    }

    fn canonical_session_roots(context: &RescueContext) -> Result<Vec<PathBuf>> {
        let canonical_root = Self::validate_root(context)?;
        let mut roots = Vec::new();
        for root in Self::session_roots(context) {
            let metadata = match fs::symlink_metadata(&root) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                continue;
            }
            let canonical = fs::canonicalize(&root)
                .with_context(|| format!("canonicalize session root {}", root.display()))?;
            if canonical.starts_with(&canonical_root) {
                roots.push(canonical);
            }
        }
        Ok(roots)
    }

    fn validate_session_path(context: &RescueContext, path: &Path) -> Result<PathBuf> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect session {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("session must be a regular non-symlink file");
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            bail!("session hardlinks are not accepted");
        }
        if metadata.len() > context.max_session_bytes {
            bail!(
                "session exceeds the {} byte inspection budget",
                context.max_session_bytes
            );
        }
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("canonicalize session {}", path.display()))?;
        let roots = Self::canonical_session_roots(context)?;
        if !roots.iter().any(|root| canonical.starts_with(root)) {
            bail!("session is outside the configured Codex session roots");
        }
        Ok(canonical)
    }

    fn normalized_relative(context: &RescueContext, path: &Path) -> Result<String> {
        let relative = path
            .strip_prefix(&context.root)
            .with_context(|| format!("session {} is outside rescue root", path.display()))?;
        Ok(relative.to_string_lossy().replace('\\', "/"))
    }

    fn sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn read_stable(context: &RescueContext, path: &Path) -> Result<Vec<u8>> {
        Self::read_stable_with(context, path, Self::read_bounded)
    }

    fn read_stable_with<F>(context: &RescueContext, path: &Path, mut read: F) -> Result<Vec<u8>>
    where
        F: FnMut(&Path, u64) -> Result<Vec<u8>>,
    {
        let canonical = Self::validate_session_path(context, path)?;
        let first = read(&canonical, context.max_session_bytes)
            .with_context(|| format!("read session {}", canonical.display()))?;
        let second = read(&canonical, context.max_session_bytes)
            .with_context(|| format!("re-read session {}", canonical.display()))?;
        if Self::sha256(&first) != Self::sha256(&second) {
            bail!("session changed while being read; retry after the writer stops");
        }
        Ok(first)
    }

    fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
        let file = File::open(path)?;
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            bail!("session grew beyond the inspection budget while reading");
        }
        Ok(bytes)
    }

    fn scan_directory(
        context: &RescueContext,
        root: &Path,
        sessions: &mut Vec<SessionRef>,
        total_bytes: &mut u64,
        entries_seen: &mut usize,
    ) -> Result<()> {
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            let mut entries = fs::read_dir(&directory)
                .with_context(|| format!("scan session directory {}", directory.display()))?
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(|entry| entry.path());
            for entry in entries {
                *entries_seen = entries_seen
                    .checked_add(1)
                    .context("session entry counter overflow")?;
                if *entries_seen > context.max_files {
                    bail!(
                        "session discovery exceeded the {} entry budget",
                        context.max_files
                    );
                }
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    continue;
                }
                if metadata.is_dir() {
                    let canonical = match fs::canonicalize(&path) {
                        Ok(canonical) if canonical.starts_with(root) => canonical,
                        _ => continue,
                    };
                    pending.push(canonical);
                    continue;
                }
                if !metadata.is_file()
                    || path.extension().and_then(|ext| ext.to_str()) != Some("jsonl")
                {
                    continue;
                }
                #[cfg(unix)]
                if metadata.nlink() != 1 {
                    continue;
                }
                if metadata.len() > context.max_session_bytes {
                    bail!(
                        "session discovery found a file over the {} byte inspection budget",
                        context.max_session_bytes
                    );
                }
                let canonical = match fs::canonicalize(&path) {
                    Ok(canonical) if canonical.starts_with(root) => canonical,
                    _ => continue,
                };
                *total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .context("session byte counter overflow")?;
                if *total_bytes > context.max_total_bytes {
                    bail!(
                        "session discovery exceeded the {} byte budget",
                        context.max_total_bytes
                    );
                }
                let relative_path = Self::normalized_relative(context, &canonical)?;
                let modified_unix_secs = metadata
                    .modified()
                    .ok()
                    .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs());
                sessions.push(SessionRef {
                    adapter: "codex".to_string(),
                    key: relative_path.clone(),
                    relative_path,
                    bytes: metadata.len(),
                    modified_unix_secs,
                    source_path: canonical,
                });
            }
        }
        Ok(())
    }
}

impl RescueAdapter for CodexAdapter {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn detect(&self, context: &RescueContext) -> Result<AdapterStatus> {
        match Self::validate_root(context) {
            Ok(_) => Ok(AdapterStatus {
                adapter: self.id().to_string(),
                availability: Availability::Available,
                support_level: "rescue-only".to_string(),
                reason: None,
            }),
            Err(error) => Ok(AdapterStatus {
                adapter: self.id().to_string(),
                availability: Availability::Unavailable,
                support_level: "unsupported".to_string(),
                reason: Some(error.to_string()),
            }),
        }
    }

    fn discover_sessions(&self, context: &RescueContext) -> Result<Vec<SessionRef>> {
        Self::validate_root(context)?;
        let mut sessions = Vec::new();
        let mut total_bytes = 0u64;
        let mut entries_seen = 0usize;
        for root in Self::canonical_session_roots(context)? {
            Self::scan_directory(
                context,
                &root,
                &mut sessions,
                &mut total_bytes,
                &mut entries_seen,
            )?;
        }
        sessions.sort_by(|left, right| {
            right
                .modified_unix_secs
                .cmp(&left.modified_unix_secs)
                .then_with(|| left.key.cmp(&right.key))
        });
        Ok(sessions)
    }

    fn diagnose(&self, context: &RescueContext, session: &SessionRef) -> Result<SessionView> {
        let bytes = Self::read_stable(context, &session.source_path)?;
        let terminated_with_newline = bytes.is_empty() || bytes.ends_with(b"\n");
        let mut records = 0usize;
        let mut malformed_records = 0usize;
        let mut oversized_records = 0usize;
        let mut semantic = SemanticDiagnostics::default();

        for raw_record in bytes.split_inclusive(|byte| *byte == b'\n') {
            let mut record = raw_record;
            if record.ends_with(b"\n") {
                record = &record[..record.len() - 1];
            }
            if record.ends_with(b"\r") {
                record = &record[..record.len() - 1];
            }
            if record.is_empty() {
                continue;
            }
            if record.len() > context.max_record_bytes {
                oversized_records += 1;
                continue;
            }
            match serde_json::from_slice::<serde_json::Value>(record) {
                Ok(value) => {
                    records += 1;
                    semantic.inspect(&value);
                }
                Err(_) => malformed_records += 1,
            }
        }

        let mut notices = Vec::new();
        if !terminated_with_newline {
            notices.push("session tail is not newline-terminated".to_string());
        }
        if malformed_records > 0 {
            notices.push(format!("{malformed_records} malformed JSONL record(s)"));
        }
        if oversized_records > 0 {
            notices.push(format!(
                "{oversized_records} record(s) exceeded the {} byte budget",
                context.max_record_bytes
            ));
        }
        let mut findings = semantic.finish();
        let inventory = codex_inventory::inspect_session(
            context,
            Some(&session.source_path),
            Some(&bytes),
            None,
        )?;
        for finding in inventory.findings {
            if !findings.iter().any(|existing| existing == &finding) {
                findings.push(finding);
            }
        }
        notices.extend(inventory.notices);
        for finding in &findings {
            notices.push(format!("diagnostic finding: {finding}"));
        }
        let health = if malformed_records > 0 || oversized_records > 0 {
            SessionHealth::Corrupt
        } else if records == 0 {
            SessionHealth::Unknown
        } else if !findings.is_empty() || !terminated_with_newline {
            SessionHealth::Warning
        } else {
            SessionHealth::Healthy
        };

        Ok(SessionView {
            adapter: self.id().to_string(),
            key: session.key.clone(),
            relative_path: session.relative_path.clone(),
            bytes: bytes.len() as u64,
            sha256: Self::sha256(&bytes),
            health,
            records,
            malformed_records,
            oversized_records,
            terminated_with_newline,
            findings,
            notices,
        })
    }

    fn snapshot(
        &self,
        context: &RescueContext,
        session: &SessionRef,
        destination: &Path,
    ) -> Result<SnapshotReceipt> {
        let bytes = Self::read_stable(context, &session.source_path)?;
        let source_hash = Self::sha256(&bytes);
        let destination = if destination.is_absolute() {
            destination.to_path_buf()
        } else {
            std::env::current_dir()?.join(destination)
        };
        let parent = destination
            .parent()
            .context("snapshot destination must have a parent directory")?;
        let file_name = destination
            .file_name()
            .context("snapshot destination must have a file name")?;
        let canonical_parent = fs::canonicalize(parent)
            .with_context(|| format!("canonicalize snapshot parent {}", parent.display()))?;
        let canonical_root = Self::validate_root(context)?;
        if canonical_parent.starts_with(&canonical_root) {
            bail!("snapshot destination may not be inside the original agent state root");
        }
        // macOS exposes system aliases such as /var -> /private/var. Resolve
        // the already-verified parent and then create only the caller's final
        // filename through the existing no-follow/exclusive writer.
        let destination = canonical_parent.join(file_name);
        report::write_new_bytes(&destination, &bytes)
            .with_context(|| format!("create snapshot {}", destination.display()))?;
        let written = fs::read(&destination)
            .with_context(|| format!("verify snapshot {}", destination.display()))?;
        let written_hash = Self::sha256(&written);
        if written_hash != source_hash {
            bail!("snapshot verification hash mismatch");
        }

        Ok(SnapshotReceipt {
            adapter: self.id().to_string(),
            source_key: session.key.clone(),
            destination: destination.to_string_lossy().to_string(),
            bytes: written.len() as u64,
            sha256: written_hash,
            source_preserved: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue::types::DEFAULT_MAX_TOTAL_BYTES;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nonce = NEXT_TEMP_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vetto-rescue-contract-{tag}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create rescue test root");
            Self(path)
        }

        fn codex_home(&self) -> PathBuf {
            self.0.join("codex-home")
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn session(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join("sessions").join(name);
        fs::create_dir_all(path.parent().expect("session parent")).expect("session parent");
        fs::write(&path, bytes).expect("session fixture");
        path
    }

    #[test]
    fn discovery_enforces_entry_aggregate_and_session_budgets() {
        let temp = TempRoot::new("budgets");
        let root = temp.codex_home();
        session(&root, "one.jsonl", b"one\n");
        session(&root, "two.jsonl", b"two\n");

        let adapter = CodexAdapter;
        let mut context = RescueContext::new(root.clone());
        context.max_files = 1;
        let error = adapter
            .discover_sessions(&context)
            .expect_err("entry budget must fail closed");
        assert!(error.to_string().contains("entry budget"), "{error:#}");

        context.max_files = 10;
        context.max_total_bytes = 1;
        let error = adapter
            .discover_sessions(&context)
            .expect_err("aggregate byte budget must fail closed");
        assert!(error.to_string().contains("byte budget"), "{error:#}");

        context.max_total_bytes = DEFAULT_MAX_TOTAL_BYTES;
        context.max_session_bytes = 1;
        let error = adapter
            .discover_sessions(&context)
            .expect_err("per-session budget must fail closed");
        assert!(error.to_string().contains("inspection budget"), "{error:#}");
    }

    #[test]
    fn diagnose_marks_records_over_the_record_budget_corrupt() {
        let temp = TempRoot::new("record-budget");
        let root = temp.codex_home();
        let path = session(
            &root,
            "oversized.jsonl",
            br#"{"type":"turn"}
"#,
        );
        let adapter = CodexAdapter;
        let context = RescueContext {
            max_record_bytes: 3,
            ..RescueContext::new(root)
        };
        let sessions = adapter
            .discover_sessions(&context)
            .expect("discover session");
        let view = adapter
            .diagnose(&context, &sessions[0])
            .expect("diagnose session");
        assert_eq!(view.health, SessionHealth::Corrupt);
        assert_eq!(view.oversized_records, 1);
        assert!(path.exists(), "diagnosis must not mutate the source");
    }

    #[test]
    fn stable_read_rejects_a_source_changed_between_reads() {
        let temp = TempRoot::new("source-change");
        let root = temp.codex_home();
        let path = session(&root, "changing.jsonl", b"{\"version\":1}\n");
        let context = RescueContext::new(root);
        let mut reads = 0;
        let error = CodexAdapter::read_stable_with(&context, &path, |path, limit| {
            let bytes = CodexAdapter::read_bounded(path, limit)?;
            reads += 1;
            if reads == 1 {
                fs::write(path, b"{\"version\":2}\n")?;
            }
            Ok(bytes)
        })
        .expect_err("changing source must fail closed");
        assert!(
            error.to_string().contains("changed while being read"),
            "{error:#}"
        );
        assert_eq!(reads, 2, "the stable-read contract requires two reads");
    }

    fn diagnose_records(tag: &str, records: &[serde_json::Value]) -> SessionView {
        let temp = TempRoot::new(tag);
        let root = temp.codex_home();
        let bytes = records
            .iter()
            .map(|record| serde_json::to_vec(record).expect("serialize fixture"))
            .fold(Vec::new(), |mut output, mut record| {
                output.append(&mut record);
                output.push(b'\n');
                output
            });
        session(&root, "semantic.jsonl", &bytes);
        let adapter = CodexAdapter;
        let context = RescueContext::new(root);
        let sessions = adapter
            .discover_sessions(&context)
            .expect("discover semantic fixture");
        // Keep the temporary directory alive until the diagnosis has read it.
        let view = adapter
            .diagnose(&context, &sessions[0])
            .expect("diagnose semantic fixture");
        drop(temp);
        view
    }

    #[test]
    fn semantic_check_accepts_current_and_legacy_item_ids() {
        let view = diagnose_records(
            "semantic-valid-ids",
            &[
                serde_json::json!({"type":"session_meta","payload":{"id":"fixture"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"message","id":"msg_123","role":"assistant","content":[]}}),
                serde_json::json!({"type":"response_item","payload":{"type":"reasoning","id":"rs_123","summary":[]}}),
                serde_json::json!({"type":"response_item","payload":{"type":"function_call","id":"legacy-id","call_id":"c1","name":"echo","arguments":"{}"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"ok"}}),
            ],
        );
        assert!(!view.findings.contains(&"INVALID_PERSISTED_ITEM_ID".to_string()));
        assert!(!view.findings.contains(&"UNFINISHED_TOOL_CALL".to_string()));
    }

    #[test]
    fn semantic_check_rejects_type_incompatible_prefixed_ids() {
        let view = diagnose_records(
            "semantic-invalid-id",
            &[
                serde_json::json!({"type":"session_meta","payload":{"id":"fixture"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"reasoning","id":"item_wrong","summary":[]}}),
            ],
        );
        assert!(view.findings.contains(&"INVALID_PERSISTED_ITEM_ID".to_string()));
        assert_eq!(view.health, SessionHealth::Warning);
    }

    #[test]
    fn semantic_check_recognizes_current_operational_types() {
        let view = diagnose_records(
            "semantic-known-types",
            &[
                serde_json::json!({"type":"session_meta","payload":{"id":"fixture"}}),
                serde_json::json!({"type":"event_msg","payload":{"type":"mcp_tool_call_begin","call_id":"mcp-1","invocation":{"server":"s","tool":"t"}}}),
                serde_json::json!({"type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"mcp-1","result":{"ok":true}}}),
                serde_json::json!({"type":"event_msg","payload":{"type":"dynamic_tool_call_request","call_id":"dyn-1"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"tool_search_call","id":"tsc_1","call_id":"search-1","name":"search","arguments":{}}}),
                serde_json::json!({"type":"response_item","payload":{"type":"tool_search_output","call_id":"search-1","output":[]}}),
                serde_json::json!({"type":"response_item","payload":{"type":"web_search_call","id":"ws_1","status":"completed"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"image_generation_call","id":"ig_1","status":"completed","result":""}}),
            ],
        );
        assert!(!view.findings.contains(&"UNKNOWN_OPERATIONAL_SCHEMA".to_string()));
        assert!(!view.findings.contains(&"UNFINISHED_TOOL_CALL".to_string()));
    }

    #[test]
    fn semantic_check_accepts_message_and_reasoning_without_optional_ids() {
        let view = diagnose_records(
            "semantic-missing-optional-ids",
            &[
                serde_json::json!({"type":"session_meta","payload":{"id":"fixture"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[]}}),
                serde_json::json!({"type":"response_item","payload":{"type":"reasoning","summary":[]}}),
            ],
        );
        assert!(view.findings.is_empty(), "unexpected findings: {:?}", view.findings);
    }

    #[test]
    fn semantic_check_fails_closed_for_future_operational_type() {
        let view = diagnose_records(
            "semantic-future-type",
            &[
                serde_json::json!({"type":"session_meta","payload":{"id":"fixture"}}),
                serde_json::json!({"type":"event_msg","payload":{"type":"future_event_v99","call_id":"future-1"}}),
            ],
        );
        assert!(view.findings.contains(&"UNKNOWN_OPERATIONAL_SCHEMA".to_string()));
    }

    #[test]
    fn semantic_check_correlates_tool_calls_without_replaying_them() {
        let complete = diagnose_records(
            "semantic-complete-call",
            &[
                serde_json::json!({"type":"session_meta","payload":{"id":"fixture"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"function_call","call_id":"c1","name":"echo","arguments":"{}"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"ok"}}),
            ],
        );
        assert!(!complete.findings.contains(&"UNFINISHED_TOOL_CALL".to_string()));

        let unfinished = diagnose_records(
            "semantic-unfinished-call",
            &[
                serde_json::json!({"type":"session_meta","payload":{"id":"fixture"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"function_call","call_id":"c2","name":"echo","arguments":"{}"}}),
            ],
        );
        assert!(unfinished.findings.contains(&"UNFINISHED_TOOL_CALL".to_string()));
    }

    #[test]
    fn semantic_check_marks_orphan_and_duplicate_correlations_unknown() {
        let orphan = diagnose_records(
            "semantic-orphan-output",
            &[
                serde_json::json!({"type":"session_meta","payload":{"id":"fixture"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"orphan","output":"ok"}}),
            ],
        );
        assert!(orphan.findings.contains(&"UNKNOWN_OPERATIONAL_SCHEMA".to_string()));

        let duplicate_call = diagnose_records(
            "semantic-duplicate-call",
            &[
                serde_json::json!({"type":"session_meta","payload":{"id":"fixture"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"function_call","call_id":"dup","name":"echo","arguments":"{}"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"function_call","call_id":"dup","name":"echo","arguments":"{}"}}),
                serde_json::json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"dup","output":"ok"}}),
            ],
        );
        assert!(duplicate_call.findings.contains(&"UNKNOWN_OPERATIONAL_SCHEMA".to_string()));
        assert!(duplicate_call.findings.contains(&"UNFINISHED_TOOL_CALL".to_string()));
    }
}
