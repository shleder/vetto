//! Safe report storage with bounded cleanup enabled by default.
//!
//! A report directory is an explicit trust boundary. Writers refuse symlinked
//! path components and existing destinations; cleanup can be explicitly
//! disabled, is limited to generated report names, and is anchored to an open directory fd on
//! Unix so a replaced parent path cannot redirect deletion elsewhere.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

use super::{write_new_report, ReportOptions};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub struct ReportStorage {
    root: PathBuf,
    auto_cleanup: bool,
    retention: Option<usize>,
    max_age: Option<Duration>,
}

impl ReportStorage {
    pub fn new(options: &ReportOptions) -> Result<Self> {
        let requested = options
            .report_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(".vetto/reports"));
        let root = if requested.is_absolute() {
            requested
        } else {
            std::env::current_dir()?.join(requested)
        };
        ensure_directory(&root)
            .with_context(|| format!("prepare report directory {}", root.display()))?;
        Ok(Self {
            root,
            auto_cleanup: options.auto_cleanup,
            retention: options.retention,
            max_age: options.max_age_secs.map(Duration::from_secs),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn write(&self, extension: &str, content: &str) -> Result<PathBuf> {
        let extension = extension.trim_start_matches('.');
        if extension.is_empty()
            || !extension
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            anyhow::bail!("invalid report extension");
        }
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        for _ in 0..128 {
            let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let name = format!(
                "vetto-report-{stamp}-{}-{id}.{extension}",
                std::process::id()
            );
            let path = self.root.join(&name);
            match write_new_report(&path, content) {
                Ok(()) => {
                    if self.auto_cleanup {
                        self.cleanup().ok();
                    }
                    return Ok(path);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("write report {}", path.display()))
                }
            }
        }
        anyhow::bail!(
            "could not allocate a unique report name in {}",
            self.root.display()
        )
    }

    /// Remove only generated report files directly inside this exact root.
    /// Errors are returned to callers that explicitly requested cleanup; the
    /// caller may choose to treat cleanup as best-effort after a successful
    /// report write.
    pub fn cleanup(&self) -> Result<usize> {
        if !self.auto_cleanup {
            return Ok(0);
        }
        let now = SystemTime::now();
        let mut candidates = Vec::new();
        for entry in fs::read_dir(&self.root)
            .with_context(|| format!("scan report directory {}", self.root.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.parent() != Some(self.root.as_path()) {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !is_generated_report(name) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                continue;
            }
            #[cfg(unix)]
            if metadata.nlink() != 1 {
                // A hardlink may point at a user-owned file. Cleanup only
                // removes files whose ownership is unambiguous.
                continue;
            }
            let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let expired = self
                .max_age
                .map(|age| now.duration_since(modified).unwrap_or_default() > age)
                .unwrap_or(false);
            candidates.push((path, modified, expired));
        }

        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.1));
        let mut remove = Vec::new();
        for (index, (path, _, expired)) in candidates.iter().enumerate() {
            let over_retention = self.retention.map(|n| index >= n).unwrap_or(false);
            if *expired || over_retention {
                remove.push(path.clone());
            }
        }

        let mut removed = 0;
        #[cfg(unix)]
        {
            let directory = super::open_parent_dir(&self.root.join(".vetto-cleanup"))
                .map_err(|e| anyhow::anyhow!("open report directory for cleanup: {e}"))?
                .0;
            for path in remove {
                let Some(name) = path.file_name() else {
                    continue;
                };
                let name = super::component_cstring(name)
                    .map_err(|e| anyhow::anyhow!("invalid report filename: {e}"))?;
                // SAFETY: directory is an O_DIRECTORY|O_NOFOLLOW fd and name
                // is one direct child selected from read_dir above.
                let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
                if result == 0 {
                    removed += 1;
                } else if std::io::Error::last_os_error().kind() != io::ErrorKind::NotFound {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
        }
        #[cfg(not(unix))]
        for path in remove {
            if fs::remove_file(path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn is_generated_report(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("vetto-report-") else {
        return false;
    };
    let Some((stem, extension)) = rest.rsplit_once('.') else {
        return false;
    };
    if !matches!(extension, "html" | "md" | "json" | "sarif") {
        return false;
    }
    let mut parts = stem.split('-');
    let Some(date) = parts.next() else {
        return false;
    };
    let Some(time) = parts.next() else {
        return false;
    };
    let Some(pid) = parts.next() else {
        return false;
    };
    let Some(id) = parts.next() else { return false };
    parts.next().is_none()
        && date.len() == 8
        && time.len() == 6
        && date.bytes().all(|byte| byte.is_ascii_digit())
        && time.bytes().all(|byte| byte.is_ascii_digit())
        && !pid.is_empty()
        && !id.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && id.bytes().all(|byte| byte.is_ascii_digit())
}

fn ensure_directory(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty report directory",
        ));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = if absolute.has_root() {
        PathBuf::from(
            absolute
                .components()
                .next()
                .expect("root component")
                .as_os_str(),
        )
    } else {
        PathBuf::new()
    };
    for component in absolute.components() {
        use std::path::Component;
        match component {
            Component::Prefix(prefix) => current = PathBuf::from(prefix.as_os_str()),
            Component::RootDir => {
                if current.as_os_str().is_empty() {
                    current.push(std::path::MAIN_SEPARATOR.to_string());
                }
            }
            Component::CurDir => {}
            Component::ParentDir => current.push(".."),
            Component::Normal(name) => {
                current.push(name);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                format!(
                                    "report directory component is a symlink: {}",
                                    current.display()
                                ),
                            ));
                        }
                        if !metadata.is_dir() {
                            return Err(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                format!(
                                    "report directory component is not a directory: {}",
                                    current.display()
                                ),
                            ));
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        fs::create_dir(&current)?;
                        let metadata = fs::symlink_metadata(&current)?;
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "new report directory is not a real directory",
                            ));
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
use std::os::fd::AsRawFd;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::report::ReportOptions;
    use std::os::unix::fs::symlink;

    fn temp_dir(label: &str) -> PathBuf {
        let temp = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        let dir = temp.join(format!(
            "vetto-storage-{label}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&dir).expect("create temp directory");
        dir
    }

    #[test]
    fn rejects_symlink_report_directory() {
        let real = temp_dir("real");
        let link = real.with_file_name(format!(
            "{}-link",
            real.file_name().unwrap().to_string_lossy()
        ));
        symlink(&real, &link).expect("create symlink");
        let options = ReportOptions {
            report_dir: Some(link.clone()),
            ..ReportOptions::default()
        };
        assert!(ReportStorage::new(&options).is_err());
        fs::remove_file(link).expect("remove symlink");
        fs::remove_dir(real).expect("remove directory");
    }

    #[test]
    fn cleanup_only_removes_generated_reports_in_root() {
        let root = temp_dir("cleanup");
        let outside = root.with_file_name(format!(
            "{}-outside",
            root.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir(&outside).expect("create outside");
        fs::write(outside.join("vetto-report-old.json"), b"sentinel").expect("write outside");
        let options = ReportOptions {
            report_dir: Some(root.clone()),
            auto_cleanup: true,
            retention: Some(0),
            ..ReportOptions::default()
        };
        let storage = ReportStorage::new(&options).expect("storage");
        storage.write("json", "{}\n").expect("write report");
        let generated = fs::read_dir(&root)
            .expect("read root")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("vetto-report-")
            })
            .count();
        assert_eq!(generated, 0);
        assert!(outside.join("vetto-report-old.json").exists());
        fs::remove_dir_all(root).expect("remove root");
        fs::remove_dir_all(outside).expect("remove outside");
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_skips_hardlinked_generated_reports() {
        let root = temp_dir("hardlink");
        let options = ReportOptions {
            report_dir: Some(root.clone()),
            auto_cleanup: false,
            retention: Some(0),
            ..ReportOptions::default()
        };
        let mut storage = ReportStorage::new(&options).expect("storage");
        let path = storage.write("json", "{}\n").expect("write report");
        let hardlink = root.join("vetto-report-20990101-000000-123-999.json");
        fs::hard_link(&path, &hardlink).expect("create hardlink");
        storage.auto_cleanup = true;

        assert_eq!(storage.cleanup().expect("cleanup"), 0);
        assert!(path.exists());
        assert!(hardlink.exists());
        fs::remove_dir_all(root).expect("remove root");
    }
}
