use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use super::adapter::RescueAdapter;
use super::safe_fs;
use super::types::{
    AdapterStatus, Availability, IntegrityStatus, RepairReceipt, RescueContext, SessionRef,
    SessionView, SnapshotReceipt,
};
use super::wal;

#[derive(Debug, Default, Clone, Copy)]
pub struct OpenCodeAdapter;

impl OpenCodeAdapter {
    pub fn default_root() -> Option<PathBuf> {
        if let Some(dir) = std::env::var_os("OPENCODE_HOME") {
            return Some(PathBuf::from(dir));
        }
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)?;
        Some(home.join(".local/share/opencode"))
    }
}

impl RescueAdapter for OpenCodeAdapter {
    fn id(&self) -> &'static str {
        "opencode"
    }

    fn detect(&self, context: &RescueContext) -> Result<AdapterStatus> {
        let root = &context.root;
        if !root.exists() {
            return Ok(AdapterStatus {
                adapter: self.id().to_string(),
                root: root.clone(),
                availability: Availability::Absent,
                reason: Some("OpenCode data directory does not exist".to_string()),
            });
        }

        let db_path = root.join("opencode.db");
        if db_path.exists() {
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
                reason: Some("OpenCode data root exists but opencode.db was not found".to_string()),
            })
        }
    }

    fn discover_sessions(&self, context: &RescueContext) -> Result<Vec<SessionRef>> {
        let root = &context.root;
        let mut sessions = Vec::new();

        let db_path = root.join("opencode.db");
        if db_path.exists() {
            let metadata = fs::metadata(&db_path)?;
            sessions.push(SessionRef {
                id: "opencode-main-db".to_string(),
                path: db_path,
                size_bytes: metadata.len(),
                modified_at: metadata.modified().ok(),
            });
        }

        let storage_dir = root.join("storage");
        if storage_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(storage_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(meta) = entry.metadata() {
                            let stem = path
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("unknown")
                                .to_string();
                            sessions.push(SessionRef {
                                id: format!("storage:{stem}"),
                                path,
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

        let is_sqlite = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.ends_with(".db") || s.ends_with(".sqlite"))
            .unwrap_or(false);

        if is_sqlite {
            let wal_file = path.with_extension("db-wal");
            let shm_file = path.with_extension("db-shm");
            let has_wal = wal_file.exists();
            let has_shm = shm_file.exists();

            let wal_size = if has_wal {
                fs::metadata(&wal_file).map(|m| m.len()).unwrap_or(0)
            } else {
                0
            };

            let status = if has_wal && wal_size > 10 * 1024 * 1024 {
                IntegrityStatus::Degraded
            } else {
                IntegrityStatus::Healthy
            };

            Ok(SessionView {
                id: session.id.clone(),
                path: session.path.clone(),
                status,
                details: format!(
                    "OpenCode SQLite DB (size: {} bytes, WAL: {}, WAL size: {} bytes, SHM: {})",
                    session.size_bytes, has_wal, wal_size, has_shm
                ),
            })
        } else {
            let meta = fs::metadata(path)?;
            Ok(SessionView {
                id: session.id.clone(),
                path: session.path.clone(),
                status: IntegrityStatus::Healthy,
                details: format!("OpenCode Session Storage file (size: {} bytes)", meta.len()),
            })
        }
    }

    fn snapshot(
        &self,
        context: &RescueContext,
        session: &SessionRef,
        destination: &Path,
    ) -> Result<SnapshotReceipt> {
        let _ = context;
        if !session.path.exists() {
            bail!("session path does not exist: {}", session.path.display());
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
        let db_path = &session.path;
        if !db_path.exists() {
            bail!("session target does not exist: {}", db_path.display());
        }

        let is_sqlite = db_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.ends_with(".db") || s.ends_with(".sqlite"))
            .unwrap_or(false);

        if !is_sqlite {
            bail!("repair is only supported on OpenCode SQLite databases (*.db)");
        }

        fs::create_dir_all(backup_dir)?;
        let backup_file = backup_dir.join(
            db_path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("opencode.db.bak")),
        );
        safe_fs::atomic_copy(db_path, &backup_file)?;

        let checkpoint_result = wal::checkpoint_sqlite_db(db_path)?;

        Ok(RepairReceipt {
            session_id: session.id.clone(),
            target_path: db_path.clone(),
            backup_path: backup_file,
            summary: format!(
                "Successfully executed SQLite WAL checkpoint on OpenCode DB: {}",
                checkpoint_result
            ),
        })
    }
}
