//! Transactional repair receipts and atomic rollback subsystem.
//!
//! Enforces two-phase atomic commits for all rescue state repairs:
//! 1. Writes repaired content to a temporary sibling file `.<file>.vetto_tmp.<pid>.<nonce>`.
//! 2. Flushes data to disk with `File::sync_all()`.
//! 3. Performs an atomic swap via `std::fs::rename()` over the target file.
//! 4. Synchronizes the parent directory.
//!
//! Provides `rollback_repair` to cryptographically verify pre-repair backup
//! archives against the `RepairReceipt` and atomically restore the exact
//! pre-repair bytes.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use super::types::{RepairReceipt, RollbackReceipt};

static ROLLBACK_NONCE: AtomicU64 = AtomicU64::new(0);

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Atomically writes `bytes` to `target_path` via a temporary sibling file
/// and `std::fs::rename`.
pub fn atomic_commit_bytes(target_path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = target_path
        .parent()
        .context("target path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create parent dir {}", parent.display()))?;

    let file_name = target_path
        .file_name()
        .context("target path has no filename")?
        .to_string_lossy();

    let nonce = ROLLBACK_NONCE.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{}.vetto_tmp.{}.{}", file_name, std::process::id(), nonce);
    let tmp_path = parent.join(tmp_name);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .with_context(|| format!("create atomic tmp file {}", tmp_path.display()))?;

    file.write_all(bytes)
        .with_context(|| format!("write to atomic tmp file {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync atomic tmp file {}", tmp_path.display()))?;
    drop(file);

    fs::rename(&tmp_path, target_path).with_context(|| {
        format!(
            "atomic swap {} -> {}",
            tmp_path.display(),
            target_path.display()
        )
    })?;

    #[cfg(unix)]
    if let Ok(dir_file) = File::open(parent) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

/// Rollback a previous repair by verifying receipt hashes and restoring
/// the pre-repair backup archive atomically.
pub fn rollback_repair(
    receipt_path: &Path,
    target_override: Option<&Path>,
) -> Result<RollbackReceipt> {
    let receipt_bytes = fs::read(receipt_path)
        .with_context(|| format!("read repair receipt {}", receipt_path.display()))?;
    let receipt: RepairReceipt = serde_json::from_slice(&receipt_bytes)
        .with_context(|| format!("parse repair receipt {}", receipt_path.display()))?;

    let backup_path = &receipt.backup_archive_path;
    if !backup_path.exists() {
        bail!(
            "backup archive {} specified in receipt does not exist",
            backup_path.display()
        );
    }

    let backup_bytes = fs::read(backup_path)
        .with_context(|| format!("read backup archive {}", backup_path.display()))?;
    let actual_backup_sha256 = sha256_bytes(&backup_bytes);

    if actual_backup_sha256 != receipt.original_sha256 {
        bail!(
            "backup archive cryptographic hash mismatch: expected {}, found {}",
            receipt.original_sha256,
            actual_backup_sha256
        );
    }

    let target_path: PathBuf = match target_override {
        Some(t) => t.to_path_buf(),
        None => {
            // Attempt to resolve target from receipt session_key
            let candidate = PathBuf::from(&receipt.session_key);
            if candidate.exists() {
                candidate
            } else {
                bail!(
                    "target file for session {} could not be automatically determined; pass --target explicitly",
                    receipt.session_key
                );
            }
        }
    };

    // If backup is a SQLite database with sidecars in the backup folder, restore sidecars too
    if let Some(_backup_parent) = backup_path.parent() {
        let backup_base = backup_path.to_string_lossy();
        for ext in ["-wal", "-shm", "-journal"] {
            let src_sc = PathBuf::from(format!("{}{}", backup_base, ext));
            if src_sc.exists() {
                let target_sc = PathBuf::from(format!("{}{}", target_path.display(), ext));
                if let Ok(sc_bytes) = fs::read(&src_sc) {
                    let _ = atomic_commit_bytes(&target_sc, &sc_bytes);
                }
            }
        }
    }

    atomic_commit_bytes(&target_path, &backup_bytes)?;

    // Verify restored file hash
    let restored_bytes = fs::read(&target_path)
        .with_context(|| format!("read restored target {}", target_path.display()))?;
    let restored_sha256 = sha256_bytes(&restored_bytes);

    if restored_sha256 != receipt.original_sha256 {
        bail!("rollback verification hash mismatch after restore");
    }

    let timestamp_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(RollbackReceipt {
        adapter: receipt.adapter,
        session_key: receipt.session_key,
        target_path: target_path.to_string_lossy().to_string(),
        restored_sha256,
        timestamp_unix_secs,
    })
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
            "vetto-rollback-{tag}-{}-{nonce}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn atomic_commit_writes_file_cleanly() {
        let dir = test_dir("commit");
        let target = dir.join("session.jsonl");
        atomic_commit_bytes(&target, b"line 1\nline 2\n").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"line 1\nline 2\n");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rollback_restores_exact_pre_repair_bytes_from_receipt() {
        let dir = test_dir("rb-test");
        let target = dir.join("session.jsonl");
        let original_data = b"original pre-repair content\n";
        let repaired_data = b"repaired content\n";

        fs::write(&target, repaired_data).unwrap();

        let backup_file = dir.join("backup_session.jsonl");
        fs::write(&backup_file, original_data).unwrap();

        let receipt = RepairReceipt {
            adapter: "test".to_string(),
            session_key: "session.jsonl".to_string(),
            original_sha256: sha256_bytes(original_data),
            repaired_sha256: sha256_bytes(repaired_data),
            backup_archive_path: backup_file.clone(),
            actions_applied: vec!["test_repair".to_string()],
            timestamp_unix_secs: 1234567,
        };

        let receipt_path = dir.join("receipt.json");
        fs::write(
            &receipt_path,
            serde_json::to_string_pretty(&receipt).unwrap(),
        )
        .unwrap();

        let rb_receipt = rollback_repair(&receipt_path, Some(&target)).expect("rollback");
        assert_eq!(rb_receipt.restored_sha256, receipt.original_sha256);
        assert_eq!(fs::read(&target).unwrap(), original_data);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rollback_rejects_tampered_backup() {
        let dir = test_dir("tamper-test");
        let target = dir.join("session.jsonl");
        let original_data = b"original content";
        let backup_file = dir.join("backup.jsonl");
        fs::write(&backup_file, b"tampered content").unwrap();

        let receipt = RepairReceipt {
            adapter: "test".to_string(),
            session_key: "session.jsonl".to_string(),
            original_sha256: sha256_bytes(original_data),
            repaired_sha256: sha256_bytes(b"repaired"),
            backup_archive_path: backup_file,
            actions_applied: vec![],
            timestamp_unix_secs: 100,
        };

        let receipt_path = dir.join("receipt.json");
        fs::write(&receipt_path, serde_json::to_string(&receipt).unwrap()).unwrap();

        let res = rollback_repair(&receipt_path, Some(&target));
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("hash mismatch"));

        let _ = fs::remove_dir_all(dir);
    }
}
