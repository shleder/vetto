use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::report;

use super::adapter::RescueAdapter;
use super::types::{
    AdapterStatus, Availability, RescueContext, SessionHealth, SessionRef, SessionView,
    SnapshotReceipt,
};

pub struct CodexAdapter;

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
        let canonical = Self::validate_session_path(context, path)?;
        let first = fs::read(&canonical)
            .with_context(|| format!("read session {}", canonical.display()))?;
        if first.len() as u64 > context.max_session_bytes {
            bail!("session grew beyond the inspection budget while reading");
        }
        let second = fs::read(&canonical)
            .with_context(|| format!("re-read session {}", canonical.display()))?;
        if Self::sha256(&first) != Self::sha256(&second) {
            bail!("session changed while being read; retry after the writer stops");
        }
        Ok(first)
    }

    fn scan_directory(
        context: &RescueContext,
        root: &Path,
        sessions: &mut Vec<SessionRef>,
        total_bytes: &mut u64,
    ) -> Result<()> {
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            let mut entries = fs::read_dir(&directory)
                .with_context(|| format!("scan session directory {}", directory.display()))?
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(|entry| entry.path());
            for entry in entries {
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
                if !metadata.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("jsonl")
                {
                    continue;
                }
                let canonical = match fs::canonicalize(&path) {
                    Ok(canonical) if canonical.starts_with(root) => canonical,
                    _ => continue,
                };
                if sessions.len() >= context.max_files {
                    bail!("session discovery exceeded the {} file budget", context.max_files);
                }
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
                support_level: "unavailable".to_string(),
                reason: Some(error.to_string()),
            }),
        }
    }

    fn discover_sessions(&self, context: &RescueContext) -> Result<Vec<SessionRef>> {
        Self::validate_root(context)?;
        let mut sessions = Vec::new();
        let mut total_bytes = 0u64;
        for root in Self::canonical_session_roots(context)? {
            Self::scan_directory(context, &root, &mut sessions, &mut total_bytes)?;
        }
        sessions.sort_by(|left, right| {
            right
                .modified_unix_secs
                .cmp(&left.modified_unix_secs)
                .then_with(|| left.key.cmp(&right.key))
        });
        Ok(sessions)
    }

    fn diagnose(
        &self,
        context: &RescueContext,
        session: &SessionRef,
    ) -> Result<SessionView> {
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
                Ok(_) => records += 1,
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
        let health = if malformed_records > 0 || oversized_records > 0 {
            SessionHealth::Corrupt
        } else if records == 0 {
            SessionHealth::Unknown
        } else if !terminated_with_newline {
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
        let canonical_parent = fs::canonicalize(parent)
            .with_context(|| format!("canonicalize snapshot parent {}", parent.display()))?;
        let canonical_root = Self::validate_root(context)?;
        if canonical_parent.starts_with(&canonical_root) {
            bail!("snapshot destination may not be inside the original agent state root");
        }
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

