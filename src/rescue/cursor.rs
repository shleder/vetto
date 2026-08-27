//! Cursor Agent State Database (`state.vscdb`) and Composer session repair adapter.
//!
//! Inspects and repairs Cursor's SQLite workspace state databases (`state.vscdb`)
//! and associated `chatEditingSessions/*.jsonl` transcripts.
//!
//! Target storage layout:
//! - Linux: `~/.config/Cursor/User/workspaceStorage/<workspace_id>/state.vscdb`
//! - macOS: `~/Library/Application Support/Cursor/User/workspaceStorage/<workspace_id>/state.vscdb`
//! - Windows: `%APPDATA%\Cursor\User\workspaceStorage\<workspace_id>\state.vscdb`

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use anyhow::{bail, Context, Result};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::report;

use super::adapter::RescueAdapter;
use super::lock::SessionLockGuard;
use super::safe_fs;
use super::types::{
    AdapterStatus, Availability, RepairReceipt, RescueContext, SessionHealth, SessionRef,
    SessionView, SnapshotReceipt,
};
use super::wal::SqliteWalManager;

static CURSOR_NONCE: AtomicU64 = AtomicU64::new(0);

const CURSOR_INTERESTING_KEYS: [&str; 4] = [
    "composer.composerData",
    "workbench.panel.chatSidebar",
    "interactive.sessions",
    "chat.workspaceTransfer",
];

pub struct CursorAdapter;

impl CursorAdapter {
    pub fn default_user_dir() -> Option<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                return Some(PathBuf::from(home).join(".config/Cursor/User"));
            }
        }
        #[cfg(target_os = "macos")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                return Some(
                    PathBuf::from(home).join("Library/Application Support/Cursor/User"),
                );
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(appdata) = std::env::var_os("APPDATA") {
                return Some(PathBuf::from(appdata).join("Cursor/User"));
            }
        }
        None
    }

    fn validate_root(context: &RescueContext) -> Result<PathBuf> {
        let metadata = fs::symlink_metadata(&context.root)
            .with_context(|| format!("inspect Cursor root {}", context.root.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "Cursor state root must be a real directory, not a symlink: {}",
                context.root.display()
            );
        }
        fs::canonicalize(&context.root)
            .with_context(|| format!("canonicalize Cursor state root {}", context.root.display()))
    }

    pub fn is_credential_key(key: &str) -> bool {
        let lower = key.to_ascii_lowercase();
        lower.contains("token")
            || lower.contains("auth")
            || lower.contains("secret")
            || lower.contains("credential")
            || lower.contains("apikey")
            || lower.contains("password")
    }

    pub fn sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn normalized_relative(context: &RescueContext, path: &Path) -> Result<String> {
        let canonical_root = Self::validate_root(context)?;
        let relative = path.strip_prefix(&canonical_root).with_context(|| {
            format!("Cursor path {} is outside state root", path.display())
        })?;
        Ok(relative.to_string_lossy().replace('\\', "/"))
    }

    fn validate_session_path(context: &RescueContext, path: &Path) -> Result<PathBuf> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect Cursor session {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("Cursor session must be a regular non-symlink file");
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            bail!("Cursor session hardlinks are not accepted");
        }
        if metadata.len() > context.max_session_bytes {
            bail!(
                "Cursor session exceeds the {} byte inspection budget",
                context.max_session_bytes
            );
        }
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("canonicalize Cursor session {}", path.display()))?;
        let canonical_root = Self::validate_root(context)?;
        if !canonical.starts_with(&canonical_root) {
            bail!("Cursor session is outside the configured state root");
        }
        Ok(canonical)
    }

    /// Attempts to repair a corrupted/truncated JSON string.
    pub fn repair_json_string(raw: &str) -> (String, bool) {
        if serde_json::from_str::<serde_json::Value>(raw).is_ok() {
            return (raw.to_string(), false);
        }

        let mut candidate = raw.trim().to_string();
        if candidate.is_empty() {
            return ("{}".to_string(), true);
        }

        // Close unclosed quotes
        let quote_count = candidate.chars().filter(|c| *c == '"').count();
        if quote_count % 2 != 0 {
            candidate.push('"');
        }

        // Balance brackets and braces
        let mut open_braces = 0i32;
        let mut open_brackets = 0i32;
        let mut in_quote = false;
        let mut escape = false;

        for ch in candidate.chars() {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == '"' {
                in_quote = !in_quote;
                continue;
            }
            if !in_quote {
                match ch {
                    '{' => open_braces += 1,
                    '}' => open_braces = (open_braces - 1).max(0),
                    '[' => open_brackets += 1,
                    ']' => open_brackets = (open_brackets - 1).max(0),
                    _ => {}
                }
            }
        }

        for _ in 0..open_brackets {
            candidate.push(']');
        }
        for _ in 0..open_braces {
            candidate.push('}');
        }

        if serde_json::from_str::<serde_json::Value>(&candidate).is_ok() {
            return (candidate, true);
        }

        // Fallback to valid minimal container
        if raw.trim_start().starts_with('[') {
            ("[]".to_string(), true)
        } else {
            ("{}".to_string(), true)
        }
    }

    /// Repair corrupted `ItemTable` JSON values and checkpoint WAL in `state.vscdb`.
    pub fn repair_database_in_place(db_path: &Path) -> Result<Vec<String>> {
        let mut actions = Vec::new();
        let mut conn = Connection::open(db_path)
            .with_context(|| format!("open Cursor database {}", db_path.display()))?;

        let has_item_table: bool = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='ItemTable'",
                [],
                |row| row.get::<_, i64>(0).map(|c| c > 0),
            )
            .unwrap_or(false);

        if has_item_table {
            let mut stmt = conn.prepare("SELECT key, value FROM ItemTable")?;
            let rows = stmt.query_map([], |row| {
                let key: String = row.get(0)?;
                let val: Option<String> = row.get(1)?;
                Ok((key, val))
            })?;

            let mut updates = Vec::new();
            for item in rows {
                let (key, val) = item?;
                if Self::is_credential_key(&key) {
                    continue;
                }
                if let Some(raw_val) = val {
                    let (repaired, modified) = Self::repair_json_string(&raw_val);
                    if modified {
                        updates.push((key, repaired));
                    }
                }
            }
            drop(stmt);

            for (key, repaired) in updates {
                conn.execute(
                    "UPDATE ItemTable SET value = ?1 WHERE key = ?2",
                    rusqlite::params![repaired, key],
                )?;
                actions.push(format!("repaired_item_table_key_{key}"));
            }
        }

        // Checkpoint and verify integrity
        SqliteWalManager::checkpoint_and_recover(&mut conn)?;
        actions.push("checkpointed_and_verified_sqlite_wal".to_string());
        drop(conn);

        Ok(actions)
    }
}

impl RescueAdapter for CursorAdapter {
    fn id(&self) -> &'static str {
        "cursor"
    }

    fn detect(&self, context: &RescueContext) -> Result<AdapterStatus> {
        match Self::validate_root(context) {
            Ok(root) => {
                let ws_dir = root.join("workspaceStorage");
                let gs_db = root.join("globalStorage/state.vscdb");
                if ws_dir.exists() || gs_db.exists() {
                    Ok(AdapterStatus {
                        adapter: self.id().to_string(),
                        availability: Availability::Available,
                        support_level: "full-repair".to_string(),
                        reason: Some(
                            "Cursor workspaceStorage / globalStorage state database repair available"
                                .to_string(),
                        ),
                    })
                } else {
                    Ok(AdapterStatus {
                        adapter: self.id().to_string(),
                        availability: Availability::Unavailable,
                        support_level: "unsupported".to_string(),
                        reason: Some(
                            "Cursor state root found, but no workspaceStorage or state.vscdb was present"
                                .to_string(),
                        ),
                    })
                }
            }
            Err(error) => Ok(AdapterStatus {
                adapter: self.id().to_string(),
                availability: Availability::Unavailable,
                support_level: "unsupported".to_string(),
                reason: Some(error.to_string()),
            }),
        }
    }

    fn discover_sessions(&self, context: &RescueContext) -> Result<Vec<SessionRef>> {
        let root = Self::validate_root(context)?;
        let mut sessions = Vec::new();
        let mut pending = vec![root.clone()];
        let mut entries_seen = 0usize;

        while let Some(dir) = pending.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            for entry in entries {
                let entry = entry?;
                entries_seen += 1;
                if entries_seen > context.max_files {
                    bail!("Cursor discovery exceeded max file budget");
                }

                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    continue;
                }

                if metadata.is_dir() {
                    let canonical = match fs::canonicalize(&path) {
                        Ok(c) if c.starts_with(&root) => c,
                        _ => continue,
                    };
                    pending.push(canonical);
                    continue;
                }

                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                let is_vscdb = file_name == "state.vscdb";
                let is_jsonl = path.extension().and_then(|e| e.to_str()) == Some("jsonl");

                if (is_vscdb || is_jsonl) && metadata.is_file() {
                    #[cfg(unix)]
                    if metadata.nlink() != 1 {
                        continue;
                    }

                    let canonical = match fs::canonicalize(&path) {
                        Ok(c) if c.starts_with(&root) => c,
                        _ => continue,
                    };

                    let rel = Self::normalized_relative(context, &canonical)?;
                    let modified_unix_secs = metadata
                        .modified()
                        .ok()
                        .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs());

                    sessions.push(SessionRef {
                        adapter: "cursor".to_string(),
                        key: rel.clone(),
                        relative_path: rel,
                        bytes: metadata.len(),
                        modified_unix_secs,
                        source_path: canonical,
                    });
                }
            }
        }

        sessions.sort_by(|a, b| {
            b.modified_unix_secs
                .cmp(&a.modified_unix_secs)
                .then_with(|| a.key.cmp(&b.key))
        });
        Ok(sessions)
    }

    fn diagnose(&self, context: &RescueContext, session: &SessionRef) -> Result<SessionView> {
        let canonical_path = Self::validate_session_path(context, &session.source_path)?;
        let file_name = canonical_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        let mut findings = Vec::new();
        let mut notices = Vec::new();
        let mut records = 0usize;
        let mut malformed_records = 0usize;
        let mut oversized_records = 0usize;

        if file_name.ends_with(".vscdb") || file_name.ends_with(".sqlite") {
            let conn = safe_fs::open_sqlite_read_only(&context.root, &canonical_path, "state.vscdb")?;
            let has_item_table: bool = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='ItemTable'",
                    [],
                    |r| r.get::<_, i64>(0).map(|c| c > 0),
                )
                .unwrap_or(false);

            if has_item_table {
                let mut stmt = conn.prepare("SELECT key, value FROM ItemTable")?;
                let rows = stmt.query_map([], |row| {
                    let k: String = row.get(0)?;
                    let v: Option<String> = row.get(1)?;
                    Ok((k, v))
                })?;

                for row in rows {
                    let (key, val) = row?;
                    records += 1;
                    if let Some(raw) = val {
                        if CURSOR_INTERESTING_KEYS.contains(&key.as_str()) {
                            if serde_json::from_str::<serde_json::Value>(&raw).is_err() {
                                malformed_records += 1;
                                findings.push(format!("TRUNCATED_JSON_PAYLOAD_{key}"));
                            }
                        }
                    }
                }
            }
        } else {
            // JSONL chat session
            let bytes = safe_fs::read_bounded(&context.root, &canonical_path, context.max_session_bytes, "chat jsonl")?;
            for line in bytes.split(|b| *b == b'\n') {
                let mut l = line;
                if l.ends_with(b"\r") {
                    l = &l[..l.len() - 1];
                }
                if l.is_empty() {
                    continue;
                }
                if l.len() > context.max_record_bytes {
                    oversized_records += 1;
                    continue;
                }
                if serde_json::from_slice::<serde_json::Value>(l).is_ok() {
                    records += 1;
                } else {
                    malformed_records += 1;
                }
            }
        }

        let raw_bytes = fs::read(&canonical_path).unwrap_or_default();
        let sha256 = Self::sha256(&raw_bytes);
        let health = if malformed_records > 0 || oversized_records > 0 {
            SessionHealth::Warning
        } else {
            SessionHealth::Healthy
        };

        if malformed_records > 0 {
            notices.push(format!("{malformed_records} malformed record(s) detected in Cursor state"));
        }

        Ok(SessionView {
            adapter: self.id().to_string(),
            key: session.key.clone(),
            relative_path: session.relative_path.clone(),
            bytes: raw_bytes.len() as u64,
            sha256,
            health,
            records,
            malformed_records,
            oversized_records,
            terminated_with_newline: true,
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
        let canonical_src = Self::validate_session_path(context, &session.source_path)?;
        let destination = if destination.is_absolute() {
            destination.to_path_buf()
        } else {
            std::env::current_dir()?.join(destination)
        };

        let parent = destination
            .parent()
            .context("Cursor snapshot destination must have a parent")?;
        let file_name = destination
            .file_name()
            .context("Cursor snapshot destination must have a filename")?;
        let canonical_parent = fs::canonicalize(parent)?;
        let canonical_root = Self::validate_root(context)?;
        if canonical_parent.starts_with(&canonical_root) {
            bail!("Cursor snapshot destination may not be inside state root");
        }

        let final_dest = canonical_parent.join(file_name);
        SqliteWalManager::copy_sqlite_set(&canonical_src, &final_dest)?;

        let bytes = fs::read(&final_dest)?;
        let sha256 = Self::sha256(&bytes);

        Ok(SnapshotReceipt {
            adapter: self.id().to_string(),
            source_key: session.key.clone(),
            destination: final_dest.to_string_lossy().to_string(),
            bytes: bytes.len() as u64,
            sha256,
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
        let _guard = SessionLockGuard::acquire_with_timeout(&lock_path, 30_000, Duration::from_secs(5))
            .with_context(|| format!("acquire session lock on {}", lock_path.display()))?;

        let canonical_target = Self::validate_session_path(context, &session.source_path)?;
        let original_bytes = fs::read(&canonical_target)
            .with_context(|| format!("read original Cursor file {}", canonical_target.display()))?;
        let original_sha256 = Self::sha256(&original_bytes);

        let timestamp_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let nonce = CURSOR_NONCE.fetch_add(1, Ordering::Relaxed);

        // Backup archive
        let backup_archive_dir = backup_dir.join(format!("cursor-{timestamp_unix_secs}-{nonce}"));
        fs::create_dir_all(&backup_archive_dir)?;
        let backup_file = backup_archive_dir.join(
            canonical_target
                .file_name()
                .context("target file has no filename")?,
        );
        SqliteWalManager::copy_sqlite_set(&canonical_target, &backup_file)?;

        // Two-phase atomic commit via private temporary staging
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

        SqliteWalManager::copy_sqlite_set(&canonical_target, &tmp_path)?;
        let actions = Self::repair_database_in_place(&tmp_path)?;

        fs::rename(&tmp_path, &canonical_target)
            .with_context(|| format!("atomic rename {} -> {}", tmp_path.display(), canonical_target.display()))?;

        #[cfg(unix)]
        if let Ok(dir_file) = File::open(parent_dir) {
            let _ = dir_file.sync_all();
        }

        let repaired_bytes = fs::read(&canonical_target)?;
        let repaired_sha256 = Self::sha256(&repaired_bytes);

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

    fn test_dir(tag: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vetto-cursor-{tag}-{}-{nonce}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn repairs_truncated_json_string() {
        let truncated = r#"{"composerData":{"text":"hello world"#;
        let (repaired, modified) = CursorAdapter::repair_json_string(truncated);
        assert!(modified);
        let val: serde_json::Value = serde_json::from_str(&repaired).expect("valid json after repair");
        assert!(val.is_object());
    }

    #[test]
    fn discovers_and_repairs_cursor_database() {
        let root = test_dir("cursor-storage");
        let ws_dir = root.join("workspaceStorage").join("ws_123");
        fs::create_dir_all(&ws_dir).unwrap();
        let db_path = ws_dir.join("state.vscdb");
        let backup_dir = root.join("backups");

        // Create initial vscdb with corrupted item
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO ItemTable VALUES ('composer.composerData', '{\"text\":\"incomp');",
            )
            .unwrap();
        }

        let ctx = RescueContext::new(root.clone());
        let sessions = CursorAdapter.discover_sessions(&ctx).unwrap();
        assert_eq!(sessions.len(), 1);

        let view = CursorAdapter.diagnose(&ctx, &sessions[0]).unwrap();
        assert_eq!(view.health, SessionHealth::Warning);
        assert!(view.findings.iter().any(|f| f.contains("composer.composerData")));

        let receipt = CursorAdapter.repair(&ctx, &sessions[0], &backup_dir).unwrap();
        assert_eq!(receipt.adapter, "cursor");
        assert!(receipt.backup_archive_path.exists());

        // Check repaired DB
        let conn = Connection::open(&db_path).unwrap();
        let val: String = conn
            .query_row(
                "SELECT value FROM ItemTable WHERE key = 'composer.composerData'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&val).is_ok());

        let _ = fs::remove_dir_all(root);
    }
}
