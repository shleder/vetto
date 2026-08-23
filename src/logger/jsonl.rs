//! JSONL session log: one sanitized JSON object per line, appended by a
//! dedicated thread subscribed to the event bus.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::{CString, OsStr};
#[cfg(not(unix))]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use tokio::sync::broadcast;

use crate::events::{Event, EventBus};
use crate::logger::sanitizer;

pub struct JsonlSink;

impl JsonlSink {
    /// Spawn the sink thread. Events already emitted before the subscription
    /// are not captured; subscribe early.
    pub fn spawn(bus: &EventBus, path: PathBuf) -> std::thread::JoinHandle<()> {
        let rx = bus.subscribe();
        std::thread::Builder::new()
            .name("vetto-jsonl".into())
            .spawn(move || sink_loop(rx, path))
            .expect("spawn jsonl sink")
    }
}

fn sink_loop(mut rx: broadcast::Receiver<Event>, path: PathBuf) {
    let Ok(file) = open_append_nofollow(&path) else {
        eprintln!(
            "vetto: cannot open --jsonl file {}: skipping sink",
            path.display()
        );
        return;
    };
    let mut out = std::io::BufWriter::new(file);
    let _ = writeln!(
        out,
        "{}",
        serde_json::json!({
            "_vetto": "jsonl-sink",
            "note": "secret sanitizer is BEST-EFFORT; false positives and misses are possible",
        })
    );
    let _ = out.flush();
    loop {
        match rx.blocking_recv() {
            Ok(ev) => {
                let line = serde_json::to_string(&ev).unwrap_or_default();
                let _ = writeln!(out, "{}", sanitizer::sanitize_line(&line));
                let _ = out.flush();
            }
            Err(broadcast::error::RecvError::Lagged(missed)) => {
                let _ = writeln!(
                    out,
                    "{}",
                    serde_json::json!({"_vetto": "sink-lagged", "missed": missed})
                );
                let _ = out.flush();
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Open an existing JSONL sink for append without following a final symlink.
///
/// The first Unix open uses `O_CREAT|O_EXCL`; only an `EEXIST` result falls
/// through to a no-create append open.  On Unix, every parent component is
/// opened relative to a directory fd with `O_DIRECTORY|O_NOFOLLOW`, and the
/// final descriptor is checked with `fstat` before any bytes are written.
#[cfg(unix)]
fn open_append_nofollow(path: &Path) -> io::Result<File> {
    let (parent, name) = open_parent_dir(path)?;
    let common_flags = libc::O_WRONLY
        | libc::O_APPEND
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        // Avoid blocking forever if an attacker points the path at a FIFO.
        | libc::O_NONBLOCK;
    // First create exclusively.  This avoids ever opening an attacker-created
    // object as the result of a create race; an existing sink is handled by a
    // separate no-create append open below.
    let create_flags = common_flags | libc::O_CREAT | libc::O_EXCL;
    // SAFETY: parent is a live directory fd and name is a NUL-terminated path
    // component created from the caller's Path.
    let mut fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), create_flags, 0o666) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error);
        }
        // Existing files are opened only after the exclusive-create attempt,
        // with no O_CREAT, and are revalidated by fstat below.
        // SAFETY: same live directory fd and NUL-terminated final component.
        fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), common_flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: fd was returned by a successful openat and is now owned by File.
    let file = unsafe { File::from_raw_fd(fd) };
    ensure_regular(&file)?;
    Ok(file)
}

/// Portable fallback for targets without Unix `openat(2)`.  The supported
/// sandbox backends are Unix; this keeps the logger buildable elsewhere while
/// still refusing a non-regular opened target where the platform exposes it.
#[cfg(not(unix))]
fn open_append_nofollow(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    ensure_regular(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn open_parent_dir(path: &Path) -> io::Result<(File, CString)> {
    let mut components: Vec<_> = path.components().collect();
    let final_component = components.pop().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "JSONL path has no final component",
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
                "JSONL path final component is not a file name",
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
            "JSONL target is not a regular file",
        ));
    }
    if stat.st_nlink != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "JSONL target has multiple hard links",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_regular(file: &File) -> io::Result<()> {
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "JSONL target is not a regular file",
        ));
    }
    Ok(())
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
            "vetto-jsonl-symlink-{}-{nonce}-{n}",
            std::process::id()
        ));
        fs::create_dir(&dir).expect("create test directory");
        dir
    }

    #[test]
    fn append_refuses_final_symlink() {
        let dir = test_dir();
        let victim = dir.join("victim");
        let link = dir.join("session.jsonl");
        fs::write(&victim, b"sentinel\n").expect("write victim");
        symlink(&victim, &link).expect("create symlink");

        assert!(open_append_nofollow(&link).is_err());
        assert_eq!(fs::read(&victim).expect("read victim"), b"sentinel\n");
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn append_preserves_existing_regular_file() {
        let dir = test_dir();
        let path = dir.join("session.jsonl");
        fs::write(&path, b"old\n").expect("write existing sink");

        let mut file = open_append_nofollow(&path).expect("open existing sink");
        file.write_all(b"new\n").expect("append to sink");
        drop(file);

        assert_eq!(fs::read(&path).expect("read sink"), b"old\nnew\n");
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn append_refuses_symlink_parent() {
        let dir = test_dir();
        let real_parent = dir.join("real");
        let link_parent = dir.join("parent");
        fs::create_dir(&real_parent).expect("create real parent");
        symlink(&real_parent, &link_parent).expect("create parent symlink");

        let path = link_parent.join("session.jsonl");
        assert!(open_append_nofollow(&path).is_err());
        assert!(!real_parent.join("session.jsonl").exists());
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn append_refuses_non_regular_target() {
        let dir = test_dir();
        let fifo = dir.join("session.jsonl");
        let c_fifo = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path has no NUL");
        // SAFETY: c_fifo is a valid NUL-terminated path and mode is scalar.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);

        assert!(open_append_nofollow(&fifo).is_err());
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn append_refuses_hardlink_target() {
        let dir = test_dir();
        let victim = dir.join("victim");
        let link = dir.join("session.jsonl");
        fs::write(&victim, b"sentinel\n").expect("write victim");
        fs::hard_link(&victim, &link).expect("create hardlink");

        assert!(open_append_nofollow(&link).is_err());
        assert_eq!(fs::read(&victim).expect("read victim"), b"sentinel\n");
        fs::remove_dir_all(dir).expect("remove test directory");
    }
}
