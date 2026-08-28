use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::adapter::RescueAdapter;
use super::safe_fs;
use super::types::{
    AdapterStatus, Availability, IntegrityStatus, RepairReceipt, RescueContext, SessionRef,
    SessionView, SnapshotReceipt,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct AntigravityAdapter;

impl AntigravityAdapter {
    pub fn default_root() -> Option<PathBuf> {
        if let Some(dir) = std::env::var_os("ANTIGRAVITY_HOME") {
            return Some(PathBuf::from(dir));
        }
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)?;
        Some(home.join(".gemini/antigravity"))
    }
}

impl RescueAdapter for AntigravityAdapter {
    fn id(&self) -> &'static str {
        "antigravity"
    }

    fn detect(&self, context: &RescueContext) -> Result<AdapterStatus> {
        let root = &context.root;
        if !root.exists() {
            return Ok(AdapterStatus {
                adapter: self.id().to_string(),
                root: root.clone(),
                availability: Availability::Absent,
                reason: Some("Antigravity data root does not exist".to_string()),
            });
        }

        let brain_dir = root.join("brain");
        if brain_dir.is_dir() {
            Ok(AdapterStatus {
                adapter: self.id().to_string(),
                root: root.clone(),
                availability: Availability::Ready,
                reason: None,
            })
        } else {
            Ok(AdapterStatus {
                adapter: self.id().to_string(),
                root: root.clone(),
                availability: Availability::Degraded,
                reason: Some("Antigravity root exists but brain/ directory was not found".to_string()),
            })
        }
    }

    fn discover_sessions(&self, context: &RescueContext) -> Result<Vec<SessionRef>> {
        let root = &context.root;
        let brain_dir = root.join("brain");
        let mut sessions = Vec::new();

        if !brain_dir.is_dir() {
            return Ok(sessions);
        }

        if let Ok(entries) = fs::read_dir(brain_dir) {
            for entry in entries.flatten() {
                let conv_dir = entry.path();
                if conv_dir.is_dir() {
                    let conv_id = conv_dir
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    let log_file = conv_dir.join(".system_generated/logs/transcript.jsonl");
                    if log_file.is_file() {
                        if let Ok(meta) = fs::metadata(&log_file) {
                            sessions.push(SessionRef {
                                id: format!("conv:{conv_id}"),
                                path: log_file,
                                size_bytes: meta.len(),
                                modified_at: meta.modified().ok(),
                            });
                        }
                    }
                }
            }
        }

        Ok(sessions)
    }

    fn diagnose(&self, context: &RescueContext, session: &SessionRef) -> Result<SessionView> {
        let _ = context;
        let path = &session.path;
        if !path.exists() {
            bail!("session target does not exist: {}", path.display());
        }

        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut total_lines = 0;
        let mut corrupted_lines = 0;

        for line_res in reader.lines() {
            match line_res {
                Ok(line) => {
                    total_lines += 1;
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        if serde_json::from_str::<serde_json::Value>(trimmed).is_err() {
                            corrupted_lines += 1;
                        }
                    }
                }
                Err(_) => {
                    corrupted_lines += 1;
                }
            }
        }

        let status = if corrupted_lines > 0 {
            IntegrityStatus::Degraded
        } else {
            IntegrityStatus::Healthy
        };

        Ok(SessionView {
            id: session.id.clone(),
            path: session.path.clone(),
            status,
            details: format!(
                "Antigravity Transcript: {} total lines, {} corrupted lines (size: {} bytes)",
                total_lines, corrupted_lines, session.size_bytes
            ),
        })
    }

    fn snapshot(
        &self,
        context: &RescueContext,
        session: &SessionRef,
        destination: &Path,
    ) -> Result<SnapshotReceipt> {
        let _ = context;
        if !session.path.exists() {
            bail!("session target does not exist: {}", session.path.display());
        }

        safe_fs::atomic_copy(&session.path, destination)?;
        let meta = fs::metadata(destination)?;

        Ok(SnapshotReceipt {
            source_path: session.path.clone(),
            destination_path: destination.to_path_buf(),
            bytes_written: meta.len(),
            created_at: std::time::SystemTime::now(),
        })
    }

    fn repair(
        &self,
        context: &RescueContext,
        session: &SessionRef,
        backup_dir: &Path,
    ) -> Result<RepairReceipt> {
        let _ = context;
        let log_path = &session.path;
        if !log_path.exists() {
            bail!("session target does not exist: {}", log_path.display());
        }

        fs::create_dir_all(backup_dir)?;
        let backup_file = backup_dir.join(
            log_path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("transcript.jsonl.bak")),
        );
        safe_fs::atomic_copy(log_path, &backup_file)?;

        // Repair unclosed or invalid JSON lines by parsing line by line
        let file = fs::File::open(log_path)?;
        let reader = BufReader::new(file);
        let mut clean_lines = Vec::new();
        let mut dropped = 0;

        for line_res in reader.lines() {
            if let Ok(line) = line_res {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
                        clean_lines.push(line);
                    } else {
                        dropped += 1;
                    }
                }
            }
        }

        let repaired_content = clean_lines.join("\n") + "\n";
        safe_fs::atomic_write_file(log_path, repaired_content.as_bytes())?;

        Ok(RepairReceipt {
            session_id: session.id.clone(),
            target_path: log_path.clone(),
            backup_path: backup_file,
            summary: format!(
                "Repaired Antigravity transcript: retained {} valid JSON lines, purged {} corrupted tail chunks",
                clean_lines.len(), dropped
            ),
        })
    }
}
