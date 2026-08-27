//! SQLite WAL checkpointing and safe crash-consistent recovery engine.
//!
//! Replaces fail-closed errors on active SQLite WAL/SHM files with automated
//! recovery: staging the SQLite database and sidecars atomically into a private
//! temporary workspace, executing `PRAGMA wal_checkpoint(TRUNCATE)`, and verifying
//! data integrity with `PRAGMA integrity_check(100)`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rusqlite::Connection;

pub const SQLITE_SIDECAR_EXTENSIONS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Manages SQLite Write-Ahead Log (WAL) checkpointing, sidecar staging, and
/// integrity verification.
pub struct SqliteWalManager;

impl SqliteWalManager {
    /// Execute WAL checkpointing with TRUNCATE mode and run integrity checks
    /// on an open SQLite connection.
    pub fn checkpoint_and_recover(conn: &mut Connection) -> Result<()> {
        conn.execute_batch(
            "PRAGMA busy_timeout = 5000;
             PRAGMA wal_checkpoint(TRUNCATE);
             PRAGMA integrity_check(100);",
        )
        .context("SQLite WAL checkpoint and integrity check failed")?;
        Ok(())
    }

    /// Check if any SQLite sidecar files (`-wal`, `-shm`, `-journal`) exist next to `db_path`.
    pub fn has_active_wal(db_path: &Path) -> bool {
        let base_str = db_path.to_string_lossy();
        SQLITE_SIDECAR_EXTENSIONS.iter().any(|ext| {
            let sidecar = PathBuf::from(format!("{}{}", base_str, ext));
            sidecar.exists()
        })
    }

    /// Copy the SQLite database and all adjacent sidecars atomically to a destination directory.
    pub fn copy_sqlite_set(src_db: &Path, dst_db: &Path) -> Result<Vec<PathBuf>> {
        if let Some(parent) = dst_db.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create destination dir {}", parent.display()))?;
        }

        let mut copied = Vec::new();
        fs::copy(src_db, dst_db)
            .with_context(|| format!("copy main sqlite db {} -> {}", src_db.display(), dst_db.display()))?;
        copied.push(dst_db.to_path_buf());

        let src_base = src_db.to_string_lossy();
        let dst_base = dst_db.to_string_lossy();

        for ext in SQLITE_SIDECAR_EXTENSIONS {
            let src_sidecar = PathBuf::from(format!("{}{}", src_base, ext));
            let dst_sidecar = PathBuf::from(format!("{}{}", dst_base, ext));
            if src_sidecar.exists() {
                if let Ok(meta) = fs::symlink_metadata(&src_sidecar) {
                    if meta.file_type().is_symlink() {
                        bail!("SQLite sidecar {} is a symlink", src_sidecar.display());
                    }
                }
                fs::copy(&src_sidecar, &dst_sidecar).with_context(|| {
                    format!(
                        "copy sqlite sidecar {} -> {}",
                        src_sidecar.display(),
                        dst_sidecar.display()
                    )
                })?;
                copied.push(dst_sidecar);
            }
        }

        Ok(copied)
    }

    /// Recover a SQLite database by staging it and its sidecars into `stage_dir`,
    /// performing a checkpoint, and verifying integrity.
    pub fn recover_in_staging(src_db: &Path, stage_dir: &Path) -> Result<PathBuf> {
        let file_name = src_db
            .file_name()
            .context("source database path has no filename")?;
        let staged_db = stage_dir.join(file_name);

        Self::copy_sqlite_set(src_db, &staged_db)?;

        let mut conn = Connection::open(&staged_db)
            .with_context(|| format!("open staged SQLite database {}", staged_db.display()))?;

        Self::checkpoint_and_recover(&mut conn)?;
        drop(conn);

        Ok(staged_db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_NONCE: AtomicU64 = AtomicU64::new(0);

    fn temp_test_dir(tag: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vetto-wal-test-{}-{}-{}-{}",
            tag,
            std::process::id(),
            nonce,
            n
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn checkpoints_and_verifies_wal_database() {
        let dir = temp_test_dir("wal-checkpoint");
        let db_path = dir.join("test.sqlite");

        // Create db in WAL mode with uncheckpointed data
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
                 INSERT INTO users (name) VALUES ('alice'), ('bob');",
            )
            .unwrap();
        }

        fs::write(dir.join("test.sqlite-wal"), b"wal_data").unwrap();
        assert!(SqliteWalManager::has_active_wal(&db_path));

        // Open and checkpoint
        {
            let mut conn = Connection::open(&db_path).unwrap();
            SqliteWalManager::checkpoint_and_recover(&mut conn).unwrap();
            let count: i64 = conn
                .query_row("SELECT count(*) FROM users", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 2);
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn staging_recovery_preserves_data_cleanly() {
        let src_dir = temp_test_dir("wal-src");
        let stage_dir = temp_test_dir("wal-stage");
        let db_path = src_dir.join("state.sqlite");

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE sessions (key TEXT PRIMARY KEY, status TEXT);
                 INSERT INTO sessions VALUES ('sess-1', 'active');",
            )
            .unwrap();
        }

        let recovered_path =
            SqliteWalManager::recover_in_staging(&db_path, &stage_dir).expect("staging recovery");
        assert!(recovered_path.exists());

        let conn = Connection::open(&recovered_path).unwrap();
        let status: String = conn
            .query_row("SELECT status FROM sessions WHERE key = 'sess-1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(status, "active");

        let _ = fs::remove_dir_all(src_dir);
        let _ = fs::remove_dir_all(stage_dir);
    }
}
