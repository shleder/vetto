//! Project Snapshot & Rollback Engine (Feature 32).
//!
//! Creates a lightweight TAR archive of project files in `~/.vetto/snapshots/<session>/`
//! with a strict size limit, and provides rollback functionality to restore files.

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Maximum size permitted for a single project snapshot (50 MB).
pub const DEFAULT_MAX_SNAPSHOT_SIZE: u64 = 50 * 1024 * 1024;

/// Metadata stored alongside the snapshot archive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SnapshotMetadata {
    pub session_id: String,
    pub created_at: String,
    pub project_dir: PathBuf,
    pub archive_file: PathBuf,
    pub file_count: usize,
    pub total_size_bytes: u64,
}

/// Result of a rollback operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RollbackResult {
    pub session_id: String,
    pub target_dir: PathBuf,
    pub files_restored: usize,
    pub bytes_restored: u64,
}

/// Resolves the snapshots root directory (`~/.vetto/snapshots`).
pub fn snapshots_root_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("neither HOME nor USERPROFILE is set")?;
    Ok(home.join(".vetto").join("snapshots"))
}

/// Lists all available project snapshots across all sessions, ordered newest first.
pub fn list_snapshots() -> Result<Vec<SnapshotMetadata>> {
    let root = match snapshots_root_dir() {
        Ok(dir) => dir,
        Err(_) => return Ok(Vec::new()),
    };
    list_snapshots_in(&root)
}

/// Same as [`list_snapshots`], but rooted at an explicit directory.
/// Production passes the real store root; tests pass a fresh temp dir so
/// they stay hermetic against the shared per-user store ($HOME/.vetto).
pub fn list_snapshots_in(root: &Path) -> Result<Vec<SnapshotMetadata>> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    // Transient IO failures (Windows Defender locks on fresh dirs, loaded
    // CI runners) must not masquerade as "no snapshots": retry briefly,
    // then fail loudly instead of returning a lying empty list.
    let mut last_err = String::new();
    for _ in 0..3 {
        match std::fs::read_dir(root) {
            Ok(entries) => {
                let mut snapshots = Vec::new();
                for entry in entries.flatten() {
                    let meta_file = entry.path().join("metadata.json");
                    if meta_file.is_file() {
                        if let Ok(text) = std::fs::read_to_string(&meta_file) {
                            if let Ok(meta) = serde_json::from_str::<SnapshotMetadata>(&text) {
                                snapshots.push(meta);
                            }
                        }
                    }
                }

                snapshots.sort_by(|a, b| {
                    b.created_at
                        .cmp(&a.created_at)
                        .then_with(|| b.session_id.cmp(&a.session_id))
                });
                return Ok(snapshots);
            }
            Err(e) => {
                last_err = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    bail!("cannot list snapshots in {}: {last_err}", root.display())
}

/// Inspect entries in a snapshot archive, returning relative paths and byte sizes.
pub fn inspect_snapshot_archive(session: &str) -> Result<Vec<(String, u64)>> {
    let session_path = Path::new(session);
    let archive_path = if session_path.is_file() {
        session_path.to_path_buf()
    } else {
        let root = snapshots_root_dir()?;
        let dir = root.join(session);
        if !dir.exists() {
            bail!(
                "snapshot for session '{session}' was not found in {}",
                root.display()
            );
        }
        let archive = dir.join("snapshot.tar");
        if !archive.exists() {
            bail!("snapshot archive '{}' not found", archive.display());
        }
        archive
    };

    let mut archive_file = File::open(&archive_path)
        .with_context(|| format!("failed to open snapshot archive {}", archive_path.display()))?;

    let mut entries = Vec::new();
    loop {
        let mut header = [0u8; 512];
        let n = archive_file.read(&mut header)?;
        if n < 512 || header.iter().all(|&b| b == 0) {
            break;
        }

        let (name, size) = parse_tar_header(&header)?;
        if name.is_empty() {
            break;
        }

        let clean_path = Path::new(&name);
        if !clean_path.is_absolute()
            && !clean_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            entries.push((name, size));
        }

        let padding = (512 - (size % 512)) % 512;
        let to_skip = size + padding;
        archive_file.seek(std::io::SeekFrom::Current(to_skip as i64))?;
    }

    Ok(entries)
}

/// Create a project snapshot for the given session.
pub fn create_snapshot(
    project_dir: &Path,
    session_id: &str,
    max_bytes: u64,
) -> Result<SnapshotMetadata> {
    let snapshots_dir = snapshots_root_dir()?.join(session_id);
    std::fs::create_dir_all(&snapshots_dir)
        .with_context(|| format!("create snapshot dir {}", snapshots_dir.display()))?;

    let archive_path = snapshots_dir.join("snapshot.tar");
    let mut file = File::create(&archive_path)
        .with_context(|| format!("create archive {}", archive_path.display()))?;

    let mut file_count = 0;
    let mut total_size = 0u64;

    let mut queue = vec![project_dir.to_path_buf()];
    while let Some(dir) = queue.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() {
                if !crate::policy::secretscan::is_ignored_directory(&name) {
                    queue.push(path);
                }
            } else if path.is_file() {
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                let file_len = meta.len();
                if total_size + file_len > max_bytes {
                    // Clean up and fail closed
                    drop(file);
                    let _ = std::fs::remove_file(&archive_path);
                    bail!(
                        "project size (exceeds {} MB) exceeds maximum snapshot limit; snapshot aborted",
                        max_bytes / (1024 * 1024)
                    );
                }

                if let Ok(rel) = path.strip_prefix(project_dir) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    let mut data = Vec::with_capacity(file_len as usize);
                    let Ok(mut f) = File::open(&path) else {
                        continue;
                    };
                    if f.read_to_end(&mut data).is_ok() {
                        write_tar_entry(
                            &mut file,
                            &rel_str,
                            &data,
                            meta.modified().unwrap_or(SystemTime::now()),
                        )?;
                        file_count += 1;
                        total_size += file_len;
                    }
                }
            }
        }
    }

    // Write two 512-byte zero blocks to terminate TAR
    file.write_all(&[0u8; 1024])?;
    file.flush()?;

    let metadata = SnapshotMetadata {
        session_id: session_id.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        project_dir: project_dir.to_path_buf(),
        archive_file: archive_path,
        file_count,
        total_size_bytes: total_size,
    };

    let meta_path = snapshots_dir.join("metadata.json");
    let json_text = serde_json::to_string_pretty(&metadata)?;
    std::fs::write(&meta_path, json_text)?;

    Ok(metadata)
}

/// Rollback / restore a project snapshot.
pub fn rollback_snapshot(
    session: &str,
    target_dir_override: Option<&Path>,
) -> Result<RollbackResult> {
    let session_path = Path::new(session);
    let (archive_path, project_dir) = if session_path.is_file() {
        // Direct path to tar archive
        let parent = session_path.parent().unwrap_or(Path::new("."));
        let meta_file = parent.join("metadata.json");
        let proj = if meta_file.exists() {
            let text = std::fs::read_to_string(&meta_file).unwrap_or_default();
            let meta: Option<SnapshotMetadata> = serde_json::from_str(&text).ok();
            meta.map(|m| m.project_dir)
                .unwrap_or_else(|| PathBuf::from("."))
        } else {
            PathBuf::from(".")
        };
        (session_path.to_path_buf(), proj)
    } else {
        let root = snapshots_root_dir()?;
        let dir = root.join(session);
        if !dir.exists() {
            bail!(
                "snapshot for session '{session}' was not found in {}",
                root.display()
            );
        }
        let archive = dir.join("snapshot.tar");
        if !archive.exists() {
            bail!("snapshot archive '{}' not found", archive.display());
        }
        let meta_file = dir.join("metadata.json");
        let proj = if meta_file.exists() {
            let text = std::fs::read_to_string(&meta_file).unwrap_or_default();
            let meta: Option<SnapshotMetadata> = serde_json::from_str(&text).ok();
            meta.map(|m| m.project_dir)
                .unwrap_or_else(|| PathBuf::from("."))
        } else {
            PathBuf::from(".")
        };
        (archive, proj)
    };

    let dest = target_dir_override.unwrap_or(&project_dir);
    std::fs::create_dir_all(dest)
        .with_context(|| format!("failed to create restore directory {}", dest.display()))?;

    let mut archive_file = File::open(&archive_path)
        .with_context(|| format!("failed to open snapshot archive {}", archive_path.display()))?;

    let mut files_restored = 0;
    let mut bytes_restored = 0u64;

    loop {
        let mut header = [0u8; 512];
        let n = archive_file.read(&mut header)?;
        if n < 512 || header.iter().all(|&b| b == 0) {
            break;
        }

        let (name, size) = parse_tar_header(&header)?;
        if name.is_empty() {
            break;
        }

        // Read file data
        let mut data = vec![0u8; size as usize];
        archive_file.read_exact(&mut data)?;

        // Skip padding
        let padding = (512 - (size % 512)) % 512;
        if padding > 0 {
            let mut pad_buf = vec![0u8; padding as usize];
            archive_file.read_exact(&mut pad_buf)?;
        }

        // Prevent path traversal
        let clean_path = Path::new(&name);
        if clean_path.is_absolute()
            || clean_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            continue;
        }

        let out_path = dest.join(clean_path);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&out_path, &data)?;
        files_restored += 1;
        bytes_restored += size;
    }

    Ok(RollbackResult {
        session_id: session.to_string(),
        target_dir: dest.to_path_buf(),
        files_restored,
        bytes_restored,
    })
}

pub fn write_tar_entry<W: Write>(
    writer: &mut W,
    path: &str,
    data: &[u8],
    mtime: SystemTime,
) -> Result<()> {
    let mut header = [0u8; 512];

    // Name (100 bytes)
    let path_bytes = path.as_bytes();
    let name_len = path_bytes.len().min(100);
    header[..name_len].copy_from_slice(&path_bytes[..name_len]);

    // Mode (8 bytes): 0000644\0
    header[100..108].copy_from_slice(b"0000644\0");
    // UID / GID: 0000000\0
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");

    // Size (12 bytes octal)
    let size_oct = format!("{:011o}\0", data.len());
    header[124..136].copy_from_slice(size_oct.as_bytes());

    // Mtime (12 bytes octal)
    let mtime_secs = mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mtime_oct = format!("{:011o}\0", mtime_secs);
    header[136..148].copy_from_slice(mtime_oct.as_bytes());

    // Typeflag: '0' (regular file)
    header[156] = b'0';

    // Magic & version: "ustar\0" "00"
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    // Checksum placeholder (8 spaces)
    header[148..156].copy_from_slice(b"        ");
    let chksum: u32 = header.iter().map(|&b| b as u32).sum();
    let chksum_oct = format!("{:06o}\0 ", chksum);
    header[148..156].copy_from_slice(chksum_oct.as_bytes());

    writer.write_all(&header)?;
    writer.write_all(data)?;

    let padding = (512 - (data.len() % 512)) % 512;
    if padding > 0 {
        writer.write_all(&vec![0u8; padding])?;
    }

    Ok(())
}

pub fn parse_tar_header(header: &[u8; 512]) -> Result<(String, u64)> {
    let name_bytes: Vec<u8> = header[..100]
        .iter()
        .take_while(|&&b| b != 0)
        .copied()
        .collect();
    let name = String::from_utf8_lossy(&name_bytes).to_string();

    let size_str = String::from_utf8_lossy(&header[124..136])
        .trim()
        .trim_matches('\0')
        .to_string();
    let size = u64::from_str_radix(&size_str, 8).unwrap_or(0);

    Ok((name, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-snap-{tag}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn snapshot_and_rollback_restores_cleanly() {
        let src_dir = temp_test_dir("src");
        let restore_dir = temp_test_dir("restore");

        fs::write(src_dir.join("a.txt"), "hello file a\n").unwrap();
        fs::write(src_dir.join("sub").join("b.txt"), "hello file b\n").unwrap_or_else(|_| {
            fs::create_dir_all(src_dir.join("sub")).unwrap();
            fs::write(src_dir.join("sub").join("b.txt"), "hello file b\n").unwrap();
        });

        let session_id = format!("test-session-{}", std::process::id());
        let meta = create_snapshot(&src_dir, &session_id, DEFAULT_MAX_SNAPSHOT_SIZE).unwrap();
        assert_eq!(meta.file_count, 2);
        assert!(meta.total_size_bytes > 0);

        let res = rollback_snapshot(&session_id, Some(&restore_dir)).unwrap();
        assert_eq!(res.files_restored, 2);
        assert_eq!(
            fs::read_to_string(restore_dir.join("a.txt")).unwrap(),
            "hello file a\n"
        );
        assert_eq!(
            fs::read_to_string(restore_dir.join("sub").join("b.txt")).unwrap(),
            "hello file b\n"
        );

        let _ = fs::remove_dir_all(&src_dir);
        let _ = fs::remove_dir_all(&restore_dir);
    }
}
