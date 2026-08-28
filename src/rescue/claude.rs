//! Claude Code transcript adapter and state reconciler.
//!
//! Provides diagnostic inspection, stream repair for corrupted JSONL transcripts
//! (`projects`, `sessions`, `archived_sessions`), tail truncation of incomplete records,
//! project state index reconciliation, quarantine of byte-0 corrupt files, and
//! transactional repair with atomic commit and rollback receipts.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::report;

use super::adapter::RescueAdapter;
use super::lock::SessionLockGuard;
use super::safe_fs;
use super::types::{
    AdapterStatus, Availability, RepairReceipt, RescueContext, SessionHealth, SessionRef,
    SessionView, SnapshotReceipt,
};

static CLAUDE_NONCE: AtomicU64 = AtomicU64::new(0);

/// Claude state is only supported when the caller supplies the state root.
/// We deliberately do not infer a home directory here: an implicit home root
/// could cause a recovery command to traverse unrelated credentials.
pub struct ClaudeAdapter;

const KNOWN_STATE_DIRS: [&str; 3] = ["projects", "sessions", "archived_sessions"];

impl ClaudeAdapter {
    fn validate_root(context: &RescueContext) -> Result<PathBuf> {
        let metadata = fs::symlink_metadata(&context.root)
            .with_context(|| format!("inspect Claude state root {}", context.root.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "Claude state root must be a real directory, not a symlink: {}",
                context.root.display()
            );
        }
        fs::canonicalize(&context.root)
            .with_context(|| format!("canonicalize Claude state root {}", context.root.display()))
    }

    fn is_known_directory_name(name: &str) -> bool {
        KNOWN_STATE_DIRS.contains(&name)
    }

    /// Return canonical, non-symlink roots that are known to contain
    /// transcript files. An explicitly supplied `--root` may point at the
    /// `.claude` directory or directly at one of its named state directories.
    fn canonical_session_roots(context: &RescueContext) -> Result<Vec<PathBuf>> {
        let canonical_root = Self::validate_root(context)?;
        let mut candidates = Vec::new();

        if let Some(name) = canonical_root.file_name().and_then(|name| name.to_str()) {
            if Self::is_known_directory_name(name) {
                candidates.push(canonical_root.clone());
            }
        }

        for name in KNOWN_STATE_DIRS {
            let path = canonical_root.join(name);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                continue;
            }
            let canonical = fs::canonicalize(&path).with_context(|| {
                format!("canonicalize Claude state directory {}", path.display())
            })?;
            if canonical.starts_with(&canonical_root) {
                candidates.push(canonical);
            }
        }

        candidates.sort();
        candidates.dedup();
        Ok(candidates)
    }

    fn normalized_relative(context: &RescueContext, path: &Path) -> Result<String> {
        let canonical_root = Self::validate_root(context)?;
        let relative = path.strip_prefix(&canonical_root).with_context(|| {
            format!("Claude transcript {} is outside state root", path.display())
        })?;
        Ok(relative.to_string_lossy().replace('\\', "/"))
    }

    pub fn is_credential_path(path: &Path) -> bool {
        // These names are not transcript state. Keep this deny-list even
        // though the normal scanner accepts only JSONL, because future
        // layout changes must not accidentally turn a credential file into a
        // recovery candidate. Only the final three path components are
        // inspected so a user's home directory named `secrets` does not
        // cause every transcript to be rejected.
        path.iter().rev().take(3).any(|component| {
            let name = component.to_string_lossy().to_ascii_lowercase();
            matches!(
                name.as_str(),
                ".credentials.json"
                    | "credentials.json"
                    | "credentials.jsonl"
                    | "auth.json"
                    | "oauth.json"
                    | "tokens.json"
                    | "token.json"
                    | "settings.json"
                    | "settings.local.json"
            ) || name.contains("credential")
                || name.contains("secret")
        })
    }

    pub fn sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn validate_session_path(context: &RescueContext, path: &Path) -> Result<PathBuf> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect Claude transcript {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("Claude transcript must be a regular non-symlink file");
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            bail!("Claude transcript hardlinks are not accepted");
        }
        if metadata.len() > context.max_session_bytes {
            bail!(
                "Claude transcript exceeds the {} byte inspection budget",
                context.max_session_bytes
            );
        }
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("canonicalize Claude transcript {}", path.display()))?;
        if Self::is_credential_path(&canonical) {
            bail!("credential-shaped Claude state is not readable");
        }
        let roots = Self::canonical_session_roots(context)?;
        if !roots.iter().any(|root| canonical.starts_with(root)) {
            bail!("Claude transcript is outside the configured state directories");
        }
        Ok(canonical)
    }

    fn read_bounded(context: &RescueContext, path: &Path, limit: u64) -> Result<Vec<u8>> {
        safe_fs::read_bounded(&context.root, path, limit, "Claude transcript")
    }

    fn read_stable(context: &RescueContext, path: &Path) -> Result<Vec<u8>> {
        let canonical = Self::validate_session_path(context, path)?;
        let first = Self::read_bounded(context, &canonical, context.max_session_bytes)
            .with_context(|| format!("read Claude transcript {}", canonical.display()))?;
        let second = Self::read_bounded(context, &canonical, context.max_session_bytes)
            .with_context(|| format!("re-read Claude transcript {}", canonical.display()))?;
        if Self::sha256(&first) != Self::sha256(&second) {
            bail!("Claude transcript changed while being read; retry after the writer stops");
        }
        Ok(first)
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
            let entries = fs::read_dir(&directory)
                .with_context(|| format!("scan Claude state directory {}", directory.display()))?;
            for entry in entries {
                let entry = entry.with_context(|| {
                    format!("read Claude state directory entry {}", directory.display())
                })?;
                *entries_seen = entries_seen
                    .checked_add(1)
                    .context("Claude entry counter overflow")?;
                if *entries_seen > context.max_files {
                    bail!(
                        "Claude discovery exceeded the {} entry budget",
                        context.max_files
                    );
                }

                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() || Self::is_credential_path(&path) {
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
                        "Claude discovery found a file over the {} byte inspection budget",
                        context.max_session_bytes
                    );
                }
                let canonical = match fs::canonicalize(&path) {
                    Ok(canonical) if canonical.starts_with(root) => canonical,
                    _ => continue,
                };
                if Self::is_credential_path(&canonical) {
                    continue;
                }
                *total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .context("Claude transcript byte counter overflow")?;
                if *total_bytes > context.max_total_bytes {
                    bail!(
                        "Claude discovery exceeded the {} byte budget",
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
                    adapter: "claude".to_string(),
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

    /// Stream repair algorithm for Claude JSONL transcripts:
    /// 1. Strips corrupted/partial records from the tail.
    /// 2. Ensures each line is valid JSON.
    /// 3. Appends a clean session_completed marker if missing.
    /// 4. Handles zero-byte and byte-0 corrupted files by returning minimal valid schema.
    pub fn repair_transcript(
        bytes: &[u8],
        session_id_hint: Option<&str>,
    ) -> (Vec<u8>, Vec<String>, bool) {
        let mut actions = Vec::new();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let session_id = session_id_hint.unwrap_or("recovered-claude-session");

        if bytes.is_empty() {
            actions.push("initialized_empty_session_schema".to_string());
            let start = serde_json::json!({
                "type": "session_start",
                "sessionId": session_id,
                "timestamp": now_ms
            });
            let end = serde_json::json!({
                "type": "session_completed",
                "sessionId": session_id,
                "timestamp": now_ms
            });
            let payload = format!("{}\n{}\n", start, end).into_bytes();
            return (payload, actions, false);
        }

        let mut valid_records = Vec::new();
        let mut malformed_count = 0usize;
        let mut truncated_tail = false;

        let raw_lines: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
        let total_lines = raw_lines.len();

        for (idx, raw_line) in raw_lines.iter().enumerate() {
            let mut line = *raw_line;
            if line.ends_with(b"\r") {
                line = &line[..line.len() - 1];
            }
            if line.is_empty() {
                continue;
            }

            match serde_json::from_slice::<serde_json::Value>(line) {
                Ok(val) if val.is_object() => {
                    valid_records.push(val);
                }
                _ => {
                    malformed_count += 1;
                    if idx == total_lines - 1 {
                        truncated_tail = true;
                    }
                }
            }
        }

        if truncated_tail {
            actions.push("truncated_incomplete_tail_record".to_string());
        }
        if malformed_count > 0 && !truncated_tail {
            actions.push(format!("quarantined_{malformed_count}_malformed_records"));
        }

        // Byte-0 total corruption: no valid JSON objects found
        if valid_records.is_empty() {
            actions.push("byte_zero_corrupted_quarantine".to_string());
            let start = serde_json::json!({
                "type": "session_start",
                "sessionId": session_id,
                "timestamp": now_ms
            });
            let end = serde_json::json!({
                "type": "session_completed",
                "sessionId": session_id,
                "timestamp": now_ms
            });
            let payload = format!("{}\n{}\n", start, end).into_bytes();
            return (payload, actions, true);
        }

        // Check if last record is terminal
        let mut has_terminal = false;
        if let Some(last) = valid_records.last() {
            if let Some(kind) = last.get("type").and_then(|t| t.as_str()) {
                if kind == "session_completed" || kind == "turn_end" {
                    has_terminal = true;
                }
            }
        }

        if !has_terminal {
            actions.push("appended_session_completed_marker".to_string());
            valid_records.push(serde_json::json!({
                "type": "session_completed",
                "sessionId": session_id,
                "timestamp": now_ms
            }));
        }

        let mut output = Vec::new();
        for record in valid_records {
            if let Ok(line) = serde_json::to_string(&record) {
                output.extend_from_slice(line.as_bytes());
                output.push(b'\n');
            }
        }

        (output, actions, false)
    }

    /// Reconcile `~/.claude/projects/<hash>/` state index and update `.claude.json` metadata
    /// while strictly preserving credentials.
    pub fn reconcile_projects(context: &RescueContext) -> Result<Vec<String>> {
        let canonical_root = Self::validate_root(context)?;
        let projects_dir = canonical_root.join("projects");
        if !projects_dir.exists() || !projects_dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut reconciled = Vec::new();
        let entries = fs::read_dir(&projects_dir)
            .with_context(|| format!("read projects dir {}", projects_dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_string();
                if !name.is_empty() && !name.starts_with('.') {
                    reconciled.push(name);
                }
            }
        }

        // Update ~/.claude.json if present, without touching credential fields
        let claude_json = canonical_root.join(".claude.json");
        if claude_json.exists() && !Self::is_credential_path(&claude_json) {
            if let Ok(content) = fs::read_to_string(&claude_json) {
                if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = val.as_object_mut() {
                        obj.insert(
                            "knownProjects".to_string(),
                            serde_json::json!(reconciled.clone()),
                        );
                        let _ = fs::write(
                            &claude_json,
                            serde_json::to_string_pretty(&val).unwrap_or_default(),
                        );
                    }
                }
            }
        }

        Ok(reconciled)
    }
}

impl RescueAdapter for ClaudeAdapter {
    fn id(&self) -> &'static str {
        "claude"
    }

    fn detect(&self, context: &RescueContext) -> Result<AdapterStatus> {
        match Self::canonical_session_roots(context) {
            Ok(roots) if !roots.is_empty() => Ok(AdapterStatus {
                adapter: self.id().to_string(),
                availability: Availability::Available,
                support_level: "full-repair".to_string(),
                reason: Some(
                    "Claude JSONL stream repair, project reconciler, and snapshot recovery are available"
                        .to_string(),
                ),
            }),
            Ok(_) => Ok(AdapterStatus {
                adapter: self.id().to_string(),
                availability: Availability::Unavailable,
                support_level: "unsupported".to_string(),
                reason: Some(
                    "no supported Claude projects/sessions JSONL directory was found under the explicit root"
                        .to_string(),
                ),
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
                Ok(value) if value.is_object() => records += 1,
                Ok(_) | Err(_) => malformed_records += 1,
            }
        }

        let mut notices =
            vec!["Claude transcript stream repair and project reconciler are active".to_string()];
        let mut findings = Vec::new();
        if !terminated_with_newline {
            notices.push("transcript tail is not newline-terminated".to_string());
            findings.push("UNTERMINATED_TAIL".to_string());
        }
        if malformed_records > 0 {
            notices.push(format!("{malformed_records} malformed JSONL record(s)"));
            findings.push("MALFORMED_RECORDS".to_string());
        }
        if oversized_records > 0 {
            notices.push(format!(
                "{oversized_records} record(s) exceeded the {} byte budget",
                context.max_record_bytes
            ));
            findings.push("OVERSIZED_RECORDS".to_string());
        }
        if bytes.is_empty() {
            findings.push("EMPTY_TRANSCRIPT".to_string());
        }
        let health = if malformed_records > 0 || oversized_records > 0 || bytes.is_empty() {
            SessionHealth::Corrupt
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
            .context("Claude snapshot destination must have a parent directory")?;
        let file_name = destination
            .file_name()
            .context("Claude snapshot destination must have a file name")?;
        let canonical_parent = fs::canonicalize(parent)
            .with_context(|| format!("canonicalize Claude snapshot parent {}", parent.display()))?;
        let canonical_root = Self::validate_root(context)?;
        if canonical_parent.starts_with(&canonical_root) {
            bail!("Claude snapshot destination may not be inside the original state root");
        }
        let destination = canonical_parent.join(file_name);
        report::write_new_bytes(&destination, &bytes)
            .with_context(|| format!("create Claude snapshot {}", destination.display()))?;
        let written = fs::read(&destination)
            .with_context(|| format!("verify Claude snapshot {}", destination.display()))?;
        let written_hash = Self::sha256(&written);
        if written_hash != source_hash {
            bail!("Claude snapshot verification hash mismatch");
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

    fn repair(
        &self,
        context: &RescueContext,
        session: &SessionRef,
        backup_dir: &Path,
    ) -> Result<RepairReceipt> {
        let lock_path = context.root.join(".vetto_repair.lock");
        let _guard =
            SessionLockGuard::acquire_with_timeout(&lock_path, 30_000, Duration::from_secs(5))
                .with_context(|| format!("acquire session lock on {}", lock_path.display()))?;

        let canonical_target = Self::validate_session_path(context, &session.source_path)?;
        let original_bytes = Self::read_stable(context, &canonical_target)?;
        let original_sha256 = Self::sha256(&original_bytes);

        let (repaired_bytes, actions, is_byte_zero_corrupt) =
            Self::repair_transcript(&original_bytes, Some(&session.key));

        let timestamp_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let nonce = CLAUDE_NONCE.fetch_add(1, Ordering::Relaxed);

        // Byte-0 total corruption quarantine
        if is_byte_zero_corrupt {
            let quarantine_path = canonical_target
                .parent()
                .unwrap_or(&context.root)
                .join(format!(
                    "{}.corrupt.{}",
                    canonical_target
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy(),
                    timestamp_unix_secs
                ));
            let _ = fs::write(&quarantine_path, &original_bytes);
        }

        // Backup archive
        let backup_archive_dir = backup_dir.join(format!("claude-{timestamp_unix_secs}-{nonce}"));
        fs::create_dir_all(&backup_archive_dir)
            .with_context(|| format!("create backup dir {}", backup_archive_dir.display()))?;
        let backup_file = backup_archive_dir.join(
            canonical_target
                .file_name()
                .context("target file has no filename")?,
        );
        fs::write(&backup_file, &original_bytes)
            .with_context(|| format!("write backup file {}", backup_file.display()))?;

        // Two-phase atomic commit
        let parent_dir = canonical_target
            .parent()
            .context("canonical target has no parent")?;
        let tmp_name = format!(
            ".{}.vetto_tmp.{}.{}",
            canonical_target.file_name().unwrap().to_string_lossy(),
            std::process::id(),
            nonce
        );
        let tmp_path = parent_dir.join(tmp_name);

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .with_context(|| format!("create tmp repair file {}", tmp_path.display()))?;
        file.write_all(&repaired_bytes)
            .with_context(|| format!("write tmp repair file {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync tmp repair file {}", tmp_path.display()))?;
        drop(file);

        fs::rename(&tmp_path, &canonical_target).with_context(|| {
            format!(
                "atomic rename {} -> {}",
                tmp_path.display(),
                canonical_target.display()
            )
        })?;

        #[cfg(unix)]
        if let Ok(dir_file) = File::open(parent_dir) {
            let _ = dir_file.sync_all();
        }

        let repaired_sha256 = Self::sha256(&repaired_bytes);

        // Reconcile project index as part of repair
        let _ = Self::reconcile_projects(context);

        Ok(RepairReceipt {
            adapter: self.id().to_string(),
            session_key: session.key.clone(),
            original_sha256,
            repaired_sha256,
            backup_archive_path: backup_file,
            actions_applied: actions,
            timestamp_unix_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vetto-claude-{label}-{}-{nonce}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test directory");
        path
    }

    fn context(root: &Path) -> RescueContext {
        RescueContext::new(root.to_path_buf())
    }

    #[test]
    fn detect_is_fail_closed_without_known_layout() {
        let root = test_dir("unknown");
        let status = ClaudeAdapter.detect(&context(&root)).expect("detect");
        assert_eq!(status.availability, Availability::Unavailable);
        assert_eq!(status.support_level, "unsupported");
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn discovers_only_jsonl_and_skips_credential_shaped_paths() {
        let root = test_dir("discover");
        let projects = root.join("projects").join("demo");
        fs::create_dir_all(&projects).expect("create projects");
        fs::write(
            projects.join("session.jsonl"),
            br#"{"type":"user","sessionId":"synthetic"}
{"type":"assistant","message":{"role":"assistant"}}
"#,
        )
        .expect("write transcript");
        fs::write(projects.join("credentials.jsonl"), b"not a transcript\n")
            .expect("write credential-shaped file");
        fs::write(projects.join("notes.txt"), b"not a transcript\n").expect("write non-jsonl file");

        let sessions = ClaudeAdapter
            .discover_sessions(&context(&root))
            .expect("discover sessions");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].adapter, "claude");
        assert!(sessions[0].key.ends_with("projects/demo/session.jsonl"));
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn repairs_truncated_tail_and_appends_completion_marker() {
        let raw = br#"{"type":"session_start","sessionId":"s1"}
{"type":"user","message":"hi"}
{"type":"assistant","incomplete_blo"#;

        let (repaired, actions, corrupt) = ClaudeAdapter::repair_transcript(raw, Some("s1"));
        assert!(!corrupt);
        assert!(actions
            .iter()
            .any(|a| a.contains("truncated_incomplete_tail")));
        assert!(actions
            .iter()
            .any(|a| a.contains("appended_session_completed_marker")));

        let repaired_str = String::from_utf8(repaired).unwrap();
        assert!(repaired_str.contains("session_start"));
        assert!(repaired_str.contains("session_completed"));
        assert!(!repaired_str.contains("incomplete_blo"));
    }

    #[test]
    fn repairs_empty_transcript() {
        let (repaired, actions, corrupt) = ClaudeAdapter::repair_transcript(b"", Some("empty-s"));
        assert!(!corrupt);
        assert!(actions
            .iter()
            .any(|a| a.contains("initialized_empty_session_schema")));
        let repaired_str = String::from_utf8(repaired).unwrap();
        assert!(repaired_str.contains("session_start"));
        assert!(repaired_str.contains("session_completed"));
    }

    #[test]
    fn performs_transactional_repair_with_receipt_and_backup() {
        let root = test_dir("repair-root");
        let backup_dir = test_dir("backup-root");
        let projects = root.join("projects").join("p1");
        fs::create_dir_all(&projects).unwrap();
        let session_file = projects.join("session.jsonl");

        let initial_bytes = br#"{"type":"session_start","sessionId":"s1"}
{"type":"corrupt-tail"#;
        fs::write(&session_file, initial_bytes).unwrap();

        let ctx = context(&root);
        let sessions = ClaudeAdapter.discover_sessions(&ctx).unwrap();
        assert_eq!(sessions.len(), 1);

        let receipt = ClaudeAdapter
            .repair(&ctx, &sessions[0], &backup_dir)
            .expect("repair");
        assert_eq!(receipt.adapter, "claude");
        assert_ne!(receipt.original_sha256, receipt.repaired_sha256);
        assert!(receipt.backup_archive_path.exists());

        // Verify content on disk was repaired cleanly
        let on_disk = fs::read_to_string(&session_file).unwrap();
        assert!(on_disk.contains("session_completed"));
        assert!(!on_disk.contains("corrupt-tail"));

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(backup_dir).unwrap();
    }
}
