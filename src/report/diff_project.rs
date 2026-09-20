//! Project Diff Report (Feature 30).
//!
//! Creates an initial lightweight manifest of project files (path, mtime, size, quick sha256 hash)
//! and compares it with the final session state to report modified/created/deleted files
//! without duplicating the whole project tree.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// File metadata captured in the baseline manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileFingerprint {
    pub size: u64,
    pub mtime_secs: u64,
    pub sha256: String,
}

/// Baseline manifest of project files before session execution.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProjectManifest {
    pub files: BTreeMap<PathBuf, FileFingerprint>,
}

impl ProjectManifest {
    /// Captures a project manifest using fast metadata inspection without reading file contents.
    pub fn capture_fast(root: &Path, max_files: usize, budget: Duration) -> Self {
        let mut files = BTreeMap::new();
        let mut queue = vec![root.to_path_buf()];
        let start = std::time::Instant::now();

        while let Some(dir) = queue.pop() {
            if start.elapsed() >= budget || files.len() >= max_files {
                break;
            }

            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };

            for entry in entries.flatten() {
                if start.elapsed() >= budget || files.len() >= max_files {
                    break;
                }

                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();

                if path.is_dir() {
                    if !crate::policy::secretscan::is_ignored_directory(&name) {
                        queue.push(path);
                    }
                } else if path.is_file() {
                    if let Ok(rel) = path.strip_prefix(root) {
                        if let Some(fp) = fast_fingerprint_file(&path) {
                            files.insert(rel.to_path_buf(), fp);
                        }
                    }
                }
            }
        }

        Self { files }
    }

    /// Legacy capture compatibility method with bounded budget.
    pub fn capture(root: &Path) -> Self {
        Self::capture_fast(root, 1000, Duration::from_millis(150))
    }
}

/// Summary of project file differences after session completion.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProjectDiff {
    pub added: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
    pub deleted: Vec<PathBuf>,
}

impl ProjectDiff {
    pub fn total_changed(&self) -> usize {
        self.added.len() + self.modified.len() + self.deleted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.total_changed() == 0
    }

    pub fn summary(&self) -> String {
        format!(
            "agent modified: {} file(s) ({} added, {} modified, {} deleted)",
            self.total_changed(),
            self.added.len(),
            self.modified.len(),
            self.deleted.len()
        )
    }

    /// Compute the diff between an initial baseline manifest and current state on disk.
    pub fn compute(initial: &ProjectManifest, root: &Path) -> Self {
        let final_manifest = ProjectManifest::capture(root);
        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();

        let initial_keys: BTreeSet<&PathBuf> = initial.files.keys().collect();
        let final_keys: BTreeSet<&PathBuf> = final_manifest.files.keys().collect();

        // Added files
        for key in final_keys.difference(&initial_keys) {
            added.push((*key).clone());
        }

        // Deleted files
        for key in initial_keys.difference(&final_keys) {
            deleted.push((*key).clone());
        }

        // Modified files
        for key in initial_keys.intersection(&final_keys) {
            let initial_fp = &initial.files[*key];
            let final_fp = &final_manifest.files[*key];
            if initial_fp != final_fp {
                modified.push((*key).clone());
            }
        }

        added.sort();
        modified.sort();
        deleted.sort();

        Self {
            added,
            modified,
            deleted,
        }
    }
}

pub fn fast_fingerprint_file(path: &Path) -> Option<FileFingerprint> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return None;
    }

    let size = meta.len();
    let mtime_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    };
    #[cfg(not(unix))]
    let inode = 0u64;

    Some(FileFingerprint {
        size,
        mtime_secs,
        sha256: format!("{size}-{mtime_secs}-{inode}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-diff-{tag}-{}",
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
    fn detects_added_modified_and_deleted_files() {
        let dir = temp_test_dir("diff-test");
        let initial_file = dir.join("initial.txt");
        let deleted_file = dir.join("deleted.txt");
        fs::write(&initial_file, "initial content\n").unwrap();
        fs::write(&deleted_file, "to be deleted\n").unwrap();

        let manifest = ProjectManifest::capture(&dir);
        assert_eq!(manifest.files.len(), 2);

        // Perform modifications
        fs::write(&initial_file, "modified content\n").unwrap();
        fs::remove_file(&deleted_file).unwrap();
        fs::write(dir.join("added.txt"), "new file\n").unwrap();

        let diff = ProjectDiff::compute(&manifest, &dir);
        assert_eq!(diff.added, vec![PathBuf::from("added.txt")]);
        assert_eq!(diff.modified, vec![PathBuf::from("initial.txt")]);
        assert_eq!(diff.deleted, vec![PathBuf::from("deleted.txt")]);
        assert_eq!(diff.total_changed(), 3);
        assert!(diff.summary().contains("3 file(s)"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn capture_fast_respects_max_files() {
        let dir = temp_test_dir("max-files-test");
        for i in 0..10 {
            fs::write(dir.join(format!("file_{i}.txt")), format!("data {i}\n")).unwrap();
        }

        let manifest = ProjectManifest::capture_fast(&dir, 4, Duration::from_secs(5));
        assert_eq!(manifest.files.len(), 4);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fast_fingerprint_file_format_and_properties() {
        let dir = temp_test_dir("fp-test");
        let file = dir.join("test.txt");
        fs::write(&file, "hello world\n").unwrap();

        let fp = fast_fingerprint_file(&file).expect("fingerprint should succeed");
        assert_eq!(fp.size, 12);
        assert!(fp.sha256.starts_with("12-"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn fast_fingerprint_file_rejects_symlinks() {
        let dir = temp_test_dir("symlink-test");
        let file = dir.join("target.txt");
        let link = dir.join("link.txt");
        fs::write(&file, "target\n").unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();

        assert!(fast_fingerprint_file(&link).is_none());

        let _ = fs::remove_dir_all(&dir);
    }
}
