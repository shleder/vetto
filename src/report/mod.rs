//! Post-session audit reports (HTML / Markdown / JSON / SARIF).

pub mod diff_project;
pub mod json;
pub mod markdown;
pub mod sarif;
pub mod stats;
pub mod storage;

pub use diff_project::{ProjectDiff, ProjectManifest};

use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};

#[cfg(unix)]
use std::ffi::{CString, OsStr};
#[cfg(not(unix))]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use crate::config::ReportFormat;
use crate::logger::sanitizer;

#[derive(Debug, Clone)]
pub struct ReportOptions {
    pub report_dir: Option<PathBuf>,
    pub auto_cleanup: bool,
    pub retention: Option<usize>,
    pub max_age_secs: Option<u64>,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            report_dir: Some(PathBuf::from(".vetto/reports")),
            auto_cleanup: true,
            retention: Some(50),
            max_age_secs: None,
        }
    }
}

#[cfg(test)]
fn new_records(
    left: &serde_json::Value,
    right: &serde_json::Value,
    array_key: &str,
    identity_fields: &[&str],
) -> Vec<serde_json::Value> {
    fn identity(record: &serde_json::Value, fields: &[&str]) -> String {
        fields
            .iter()
            .map(|field| {
                serde_json::to_string(record.get(*field).unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_else(|_| "null".to_string())
            })
            .collect::<Vec<_>>()
            .join("\u{1f}")
    }

    let known: std::collections::BTreeSet<String> = left
        .get(array_key)
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .map(|record| identity(record, identity_fields))
        .collect();
    right
        .get(array_key)
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|record| !known.contains(&identity(record, identity_fields)))
        .cloned()
        .collect()
}

pub(crate) fn sanitize_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = clean(text),
        serde_json::Value::Array(items) => {
            for item in items {
                sanitize_json_strings(item);
            }
        }
        serde_json::Value::Object(fields) => {
            let entries = std::mem::take(fields);
            for (key, mut value) in entries {
                let key = clean(&key);
                sanitize_json_strings(&mut value);
                fields.insert(key, value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// Write a uniquely named `vetto-report-<timestamp>-<pid>-<id>.<ext>` for
/// every requested format in `.vetto/reports`.
/// Values pass through the BEST-EFFORT sanitizer before rendering.
pub fn write_reports(
    stats: &stats::SessionStats,
    formats: &[ReportFormat],
) -> Result<Vec<PathBuf>> {
    write_reports_with_options(stats, formats, &ReportOptions::default())
}

/// Write reports using an explicitly bounded storage policy.
pub fn write_reports_with_options(
    stats: &stats::SessionStats,
    formats: &[ReportFormat],
    options: &ReportOptions,
) -> Result<Vec<PathBuf>> {
    let storage = storage::ReportStorage::new(options)?;
    let mut written = Vec::new();
    for fmt in formats {
        let (content, ext): (String, &str) = match fmt {
            ReportFormat::Markdown => (markdown::render(stats), "md"),
            ReportFormat::Json => (json::render(stats), "json"),
            ReportFormat::Sarif => (sarif::render(stats), "sarif"),
        };
        let path = storage.write(ext, &content)?;
        written.push(path);
    }
    Ok(written)
}

/// Create a report without following or replacing an existing final path.
///
/// Reports are new artifacts, so refusing an existing path is preferable to
/// truncating it.  On Unix, every parent component is opened relative to a
/// directory fd with `O_DIRECTORY|O_NOFOLLOW`; the final `O_CREAT|O_EXCL`
/// descriptor is also checked with `fstat` before any bytes are written.
pub(crate) fn write_new_report(path: &std::path::Path, content: &str) -> io::Result<()> {
    write_new_bytes(path, content.as_bytes())
}

/// Create a private regular file without following parent or final symlinks.
///
/// Rescue snapshots reuse the same final-path security boundary as reports,
/// but preserve arbitrary source bytes instead of converting them to text.
pub(crate) fn write_new_bytes(path: &std::path::Path, content: &[u8]) -> io::Result<()> {
    let mut file = open_new_report(path)?;
    file.write_all(content)
}

#[cfg(unix)]
fn open_new_report(path: &std::path::Path) -> io::Result<File> {
    let (parent, name) = open_parent_dir(path)?;
    let flags = libc::O_WRONLY
        | libc::O_CREAT
        | libc::O_EXCL
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        // Avoid blocking forever if an attacker points the path at a FIFO.
        | libc::O_NONBLOCK;
    // SAFETY: parent is a live directory fd and name is a NUL-terminated path
    // component created from the caller's Path.
    // Reports can contain paths, commands, and policy observations; keep the
    // artifact private to the invoking account by default.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was returned by a successful openat and is now owned by File.
    let file = unsafe { File::from_raw_fd(fd) };
    ensure_regular(&file)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_new_report(path: &std::path::Path) -> io::Result<File> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    ensure_regular(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn open_parent_dir(path: &std::path::Path) -> io::Result<(File, CString)> {
    let mut components: Vec<_> = path.components().collect();
    let final_component = components.pop().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "report path has no final component",
        )
    })?;
    let mut parent = open_base_dir(path.is_absolute())?;
    for component in components {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => parent = open_child_dir(&parent, name)?,
            std::path::Component::ParentDir => {
                parent = open_child_dir(&parent, OsStr::new(".."))?;
            }
            std::path::Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path prefix is not supported on Unix",
                ));
            }
        }
    }
    let name = match final_component {
        std::path::Component::Normal(name) => component_cstring(name)?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "report path final component is not a file name",
            ));
        }
    };
    Ok((parent, name))
}

#[cfg(unix)]
fn open_base_dir(absolute: bool) -> io::Result<File> {
    let base = if absolute { "/" } else { "." };
    let base = CString::new(base).expect("static path has no NUL");
    // SAFETY: static NUL-terminated base path and scalar flags.
    let fd = unsafe {
        libc::open(
            base.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was returned by a successful open and is now owned by File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_child_dir(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = component_cstring(name)?;
    // SAFETY: parent is a live directory fd and name is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was returned by a successful openat and is now owned by File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn component_cstring(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "path component contains an embedded NUL",
        )
    })
}

#[cfg(unix)]
fn ensure_regular(file: &File) -> io::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: file is an open descriptor and stat points to writable storage.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat initialized stat on success.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report target is not a regular file",
        ));
    }
    if stat.st_nlink != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report target has multiple hard links",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_regular(file: &File) -> io::Result<()> {
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report target is not a regular file",
        ));
    }
    Ok(())
}

/// BEST-EFFORT redaction applied to every user-derived string in reports.
pub fn clean(s: &str) -> String {
    sanitizer::sanitize_line(s)
}

#[cfg(test)]
mod compare_tests {
    use super::*;

    #[test]
    fn compare_diff_includes_new_suspicious_records_and_sanitizes_keys() {
        let left = serde_json::json!({
            "suspicious_signals": [{
                "category": "credential_path_access",
                "severity": "high",
                "subject": "/tmp/old.env",
                "reason": "old",
                "count": 1
            }]
        });
        let secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        let mut right = serde_json::json!({
            "suspicious_signals": [{
                "category": "credential_path_access",
                "severity": "high",
                "subject": format!("/tmp/{secret}"),
                "reason": "new",
                "count": 1
            }]
        });
        right
            .as_object_mut()
            .expect("object")
            .insert(format!("secret-{secret}"), serde_json::json!(secret));

        let records = new_records(
            &left,
            &right,
            "suspicious_signals",
            &["category", "severity", "subject", "reason"],
        );
        assert_eq!(records.len(), 1);

        let mut sanitized = right;
        sanitize_json_strings(&mut sanitized);
        let serialized = serde_json::to_string(&sanitized).expect("JSON");
        assert!(!serialized.contains(secret), "secret leaked: {serialized}");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "vetto-report-symlink-{}-{nonce}-{n}",
            std::process::id()
        ));
        fs::create_dir(&dir).expect("create test directory");
        dir
    }

    #[test]
    fn report_refuses_final_symlink() {
        let dir = test_dir();
        let victim = dir.join("victim");
        let link = dir.join("vetto-report.html");
        fs::write(&victim, b"sentinel\n").expect("write victim");
        symlink(&victim, &link).expect("create symlink");

        assert!(write_new_report(&link, "new content\n").is_err());
        assert_eq!(fs::read(&victim).expect("read victim"), b"sentinel\n");
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn report_refuses_symlink_parent() {
        let dir = test_dir();
        let real_parent = dir.join("real");
        let link_parent = dir.join("parent");
        fs::create_dir(&real_parent).expect("create real parent");
        symlink(&real_parent, &link_parent).expect("create parent symlink");

        let path = link_parent.join("vetto-report.html");
        assert!(write_new_report(&path, "new content\n").is_err());
        assert!(!real_parent.join("vetto-report.html").exists());
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn report_refuses_non_regular_target() {
        let dir = test_dir();
        let fifo = dir.join("vetto-report.html");
        let c_fifo = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path has no NUL");
        // SAFETY: c_fifo is a valid NUL-terminated path and mode is scalar.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);

        assert!(write_new_report(&fifo, "new content\n").is_err());
        fs::remove_dir_all(dir).expect("remove test directory");
    }
}
