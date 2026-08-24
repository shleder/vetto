//! Bounded, read-only filesystem primitives for rescue diagnostics.
//!
//! Rescue consumes provider-owned files.  A provider path is untrusted input,
//! even when it was discovered below the configured state root: the path can
//! be replaced by a symlink, junction, or another file between validation and
//! the eventual open.  This module centralises the checks used by the rescue
//! adapters so that every byte read follows the same boundary.
//!
//! The checks are deliberately conservative.  Unix uses `O_NOFOLLOW` for the
//! final component and compares device/inode identity from the path with the
//! acquired handle.  Windows has no stable, safe-std API for obtaining the
//! file-index and hard-link count on the minimum supported toolchain.  We
//! reject observable reparse points and perform a post-open path/handle
//! identity check using the stable metadata available there.  A replacement
//! observed by those checks is an error; an undetectable Windows hard-link
//! race remains an explicit limitation rather than a claimed guarantee.  This
//! helper never mutates a source file.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OpenFlags};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

#[cfg(test)]
use std::io::{Seek, SeekFrom};

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// An identity which is stable for the lifetime of an opened source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    // `MetadataExt::{volume_serial_number,file_index,number_of_links}` are
    // still unstable on the minimum supported Rust toolchain.  The stable
    // metadata fingerprint is therefore intentionally conservative: any
    // observed mismatch fails closed, while the API does not claim that it
    // closes an undetectable Windows hard-link race.
    Windows {
        length: u64,
        modified: u64,
        created: u64,
        attributes: u32,
    },
    #[cfg(not(any(unix, windows)))]
    Portable {
        length: u64,
        modified_nanos: Option<u128>,
    },
}

/// A file opened after root and identity validation.
///
/// The underlying handle remains open while the caller consumes it.  Call
/// [`VerifiedFile::ensure_unchanged`] after reading to detect replacement,
/// truncation, or a path race observed by the platform metadata APIs.
pub(crate) struct VerifiedFile {
    file: File,
    canonical_path: PathBuf,
    identity: FileIdentity,
    length: u64,
}

impl std::fmt::Debug for VerifiedFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedFile")
            .field("canonical_path", &self.canonical_path)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

impl VerifiedFile {
    pub(crate) fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub(crate) fn len(&self) -> u64 {
        self.length
    }

    pub(crate) fn metadata(&self) -> Result<Metadata> {
        self.file.metadata().context("stat verified file handle")
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Verify that both the open handle and the pathname still identify the
    /// same regular file.  This is intentionally required after every read.
    pub(crate) fn ensure_unchanged(&self, label: &str) -> Result<()> {
        let handle_metadata = self
            .file
            .metadata()
            .with_context(|| format!("stat {label} handle"))?;
        validate_regular_metadata(&handle_metadata, label)?;
        let handle_identity = identity(&handle_metadata, label)?;
        if handle_identity != self.identity || handle_metadata.len() != self.length {
            bail!("{label} changed while being inspected");
        }

        let path_metadata = fs::symlink_metadata(&self.canonical_path)
            .with_context(|| format!("recheck {label}"))?;
        validate_regular_metadata(&path_metadata, label)?;
        let path_identity = identity(&path_metadata, label)?;
        if path_identity != self.identity || path_metadata.len() != self.length {
            bail!("{label} path changed while being inspected");
        }
        let canonical = fs::canonicalize(&self.canonical_path)
            .with_context(|| format!("re-canonicalize {label}"))?;
        if canonical != self.canonical_path {
            bail!("{label} path changed while being inspected");
        }
        Ok(())
    }
}

/// Canonicalize and validate a configured rescue root.
pub(crate) fn canonical_root(root: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect rescue root {}", root.display()))?;
    validate_directory_metadata(&metadata, "rescue root")?;
    let canonical = fs::canonicalize(root)
        .with_context(|| format!("canonicalize rescue root {}", root.display()))?;
    let canonical_metadata = fs::symlink_metadata(&canonical)
        .with_context(|| format!("recheck rescue root {}", root.display()))?;
    validate_directory_metadata(&canonical_metadata, "rescue root")?;
    Ok(canonical)
}

/// Return a canonical regular file path after validating every component.
///
/// This is useful for preflight and path-only diagnostics.  Callers which
/// consume bytes should use [`open_regular`] instead so the acquired handle
/// and the path are checked together.
pub(crate) fn canonical_regular_path(root: &Path, path: &Path, label: &str) -> Result<PathBuf> {
    let root = canonical_root(root)?;
    let candidate = candidate_under_root(&root, path, label)?;
    walk_without_links(&root, &candidate, label)?;
    let canonical =
        fs::canonicalize(&candidate).with_context(|| format!("canonicalize {label}"))?;
    if !canonical.starts_with(&root) {
        bail!("{label} is outside the configured rescue root");
    }
    let metadata = fs::symlink_metadata(&canonical).with_context(|| format!("inspect {label}"))?;
    validate_regular_metadata(&metadata, label)?;
    Ok(canonical)
}

/// Open a regular file read-only after root-bound and no-follow checks.
pub(crate) fn open_regular(root: &Path, path: &Path, label: &str) -> Result<VerifiedFile> {
    let root = canonical_root(root)?;
    let candidate = candidate_under_root(&root, path, label)?;
    walk_without_links(&root, &candidate, label)?;

    let canonical_before =
        fs::canonicalize(&candidate).with_context(|| format!("canonicalize {label}"))?;
    if !canonical_before.starts_with(&root) {
        bail!("{label} is outside the configured rescue root");
    }
    let path_metadata =
        fs::symlink_metadata(&candidate).with_context(|| format!("inspect {label}"))?;
    validate_regular_metadata(&path_metadata, label)?;
    let expected_identity = identity(&path_metadata, label)?;
    let expected_length = path_metadata.len();

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    #[cfg(windows)]
    {
        // FILE_FLAG_OPEN_REPARSE_POINT makes the final component observable
        // as a reparse point instead of silently following it.  Parent
        // components are independently checked by walk_without_links.
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let probe = options
        .open(&candidate)
        .with_context(|| format!("open {label}"))?;
    let opened_metadata = probe
        .metadata()
        .with_context(|| format!("stat {label} handle"))?;
    validate_regular_metadata(&opened_metadata, label)?;
    let opened_identity = identity(&opened_metadata, label)?;
    if opened_identity != expected_identity || opened_metadata.len() != expected_length {
        bail!("{label} changed while being opened");
    }

    // A canonical-path recheck catches parent-directory replacement on all
    // platforms.  It cannot make a race atomic with stable std APIs; if the
    // replacement is observed, the operation fails closed.
    let canonical_after =
        fs::canonicalize(&candidate).with_context(|| format!("recheck {label}"))?;
    if canonical_after != canonical_before || !canonical_after.starts_with(&root) {
        bail!("{label} changed while being opened");
    }

    Ok(VerifiedFile {
        file: probe,
        canonical_path: canonical_before,
        identity: opened_identity,
        length: opened_metadata.len(),
    })
}

/// Read a bounded snapshot while keeping the validated handle open.
pub(crate) fn read_bounded(root: &Path, path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut verified = open_regular(root, path, label)?;
    read_bounded_from_opened(&mut verified, limit, label)
}

/// Read a bounded snapshot from a path which was already root-validated by a
/// caller.  This is used by the Codex adapter's two-pass stability check; the
/// final component is still opened with the platform-specific no-follow
/// policy and handle/path identity checks.
pub(crate) fn read_bounded_existing(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    validate_regular_metadata(&path_metadata, label)?;
    let expected_identity = identity(&path_metadata, label)?;
    let expected_length = path_metadata.len();
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    #[cfg(windows)]
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .with_context(|| format!("open {label}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat {label} handle"))?;
    validate_regular_metadata(&metadata, label)?;
    let opened_identity = identity(&metadata, label)?;
    if opened_identity != expected_identity || metadata.len() != expected_length {
        bail!("{label} changed while being opened");
    }
    let canonical = fs::canonicalize(path).with_context(|| format!("canonicalize {label}"))?;
    let canonical_metadata =
        fs::symlink_metadata(&canonical).with_context(|| format!("recheck {label}"))?;
    validate_regular_metadata(&canonical_metadata, label)?;
    if identity(&canonical_metadata, label)? != expected_identity
        || canonical_metadata.len() != expected_length
    {
        bail!("{label} changed while being opened");
    }
    let mut verified = VerifiedFile {
        file,
        canonical_path: canonical,
        identity: opened_identity,
        length: metadata.len(),
    };
    read_bounded_from_opened(&mut verified, limit, label)
}

fn read_bounded_from_opened(
    verified: &mut VerifiedFile,
    limit: u64,
    label: &str,
) -> Result<Vec<u8>> {
    if verified.len() > limit {
        bail!("{label} exceeds the inspection budget");
    }
    let mut bytes = Vec::new();
    verified
        .file_mut()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    if bytes.len() as u64 > limit {
        bail!("{label} exceeds the inspection budget");
    }
    verified.ensure_unchanged(label)?;
    Ok(bytes)
}

/// Open a SQLite database with `READ_ONLY` and `NO_CREATE` semantics after
/// the same file/path checks used for JSONL sources.
pub(crate) fn open_sqlite_read_only(root: &Path, path: &Path, label: &str) -> Result<Connection> {
    let verified = open_regular(root, path, label)?;
    let canonical = verified.path().to_path_buf();
    let connection = Connection::open_with_flags(
        &canonical,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| anyhow::anyhow!("{label} could not be opened read-only"))?;
    // SQLite's flags prevent creation.  query_only protects against accidental
    // writes in future diagnostic queries; identity is checked before the
    // connection is returned so a path swap cannot be silently accepted.
    connection
        .execute_batch("PRAGMA query_only=ON; PRAGMA busy_timeout=250;")
        .map_err(|_| anyhow::anyhow!("{label} could not be configured read-only"))?;
    verified.ensure_unchanged(label)?;
    Ok(connection)
}

fn candidate_under_root(root: &Path, path: &Path, label: &str) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("{label} path is empty");
    }
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        bail!("{label} contains an unsafe path component");
    }
    if !candidate.starts_with(root) {
        bail!("{label} is outside the configured rescue root");
    }
    Ok(candidate)
}

fn walk_without_links(root: &Path, candidate: &Path, label: &str) -> Result<()> {
    let relative = candidate
        .strip_prefix(root)
        .with_context(|| format!("{label} is outside the configured rescue root"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!("{label} contains an unsafe path component");
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect {label} path component"))?;
        validate_not_reparse(&metadata, label)?;
        if current != candidate && !metadata.is_dir() {
            bail!("{label} has a non-directory parent");
        }
    }
    Ok(())
}

fn validate_directory_metadata(metadata: &Metadata, label: &str) -> Result<()> {
    validate_not_reparse(metadata, label)?;
    if !metadata.is_dir() {
        bail!("{label} must be a real directory");
    }
    Ok(())
}

fn validate_regular_metadata(metadata: &Metadata, label: &str) -> Result<()> {
    validate_not_reparse(metadata, label)?;
    if !metadata.is_file() {
        bail!("{label} must be a regular file");
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        bail!("{label} must not be hardlinked");
    }
    Ok(())
}

fn validate_not_reparse(metadata: &Metadata, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() {
        bail!("{label} must not be a symlink or reparse point");
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("{label} must not be a symlink or reparse point");
    }
    Ok(())
}

fn identity(metadata: &Metadata, label: &str) -> Result<FileIdentity> {
    let _ = label;
    #[cfg(unix)]
    {
        return Ok(FileIdentity::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        });
    }
    #[cfg(windows)]
    {
        // These fields are all stable on the supported Windows toolchains.
        // The Windows file-index/link-count accessors are nightly-only, so we
        // intentionally do not claim hard-link identity here.
        return Ok(FileIdentity::Windows {
            length: metadata.len(),
            modified: metadata.last_write_time(),
            created: metadata.creation_time(),
            attributes: metadata.file_attributes(),
        });
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(FileIdentity::Portable {
            length: metadata.len(),
            modified_nanos: metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|value| value.as_nanos()),
        })
    }
    #[allow(unreachable_code)]
    {
        let _ = label;
        bail!("file identity is unavailable on this platform");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nonce = NEXT_TEMP_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vetto-safe-fs-{tag}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("temp root");
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn opens_only_regular_files_under_root_and_preserves_bytes() {
        let temp = TempRoot::new("regular");
        let root = &temp.0;
        let path = root.join("sessions/session.jsonl");
        fs::create_dir_all(path.parent().expect("parent")).expect("parent");
        fs::write(&path, b"hello\n").expect("source");

        let bytes = read_bounded(root, &path, 1024, "session").expect("read");
        assert_eq!(bytes, b"hello\n");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_final_symlink_and_intermediate_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempRoot::new("symlink");
        let root = &temp.0;
        let outside = temp.0.join("outside.jsonl");
        fs::write(&outside, b"outside\n").expect("outside");
        let final_link = root.join("final.jsonl");
        symlink(&outside, &final_link).expect("final symlink");
        assert!(open_regular(root, &final_link, "final").is_err());

        let outside_dir = temp.0.join("outside-dir");
        fs::create_dir_all(&outside_dir).expect("outside dir");
        fs::write(outside_dir.join("nested.jsonl"), b"outside\n").expect("nested");
        let linked_dir = root.join("linked");
        symlink(&outside_dir, &linked_dir).expect("directory symlink");
        let nested = linked_dir.join("nested.jsonl");
        assert!(open_regular(root, &nested, "nested").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_hardlink_identity_aliases() {
        let temp = TempRoot::new("hardlink");
        let root = &temp.0;
        let source = root.join("source.jsonl");
        let alias = root.join("alias.jsonl");
        fs::write(&source, b"source\n").expect("source");
        fs::hard_link(&source, &alias).expect("hardlink");
        let error = open_regular(root, &alias, "alias").expect_err("hardlink rejected");
        assert!(error.to_string().contains("hardlinked"), "{error:#}");
    }

    #[test]
    fn rejects_root_escape_and_path_replacement_on_revalidation() {
        let temp = TempRoot::new("race");
        let root = &temp.0;
        let path = root.join("session.jsonl");
        fs::write(&path, b"before\n").expect("source");
        let verified = open_regular(root, &path, "session").expect("open");
        let outside = temp.0.join("outside");
        fs::write(&outside, b"outside\n").expect("outside");
        assert!(canonical_regular_path(root, Path::new("../outside"), "escape").is_err());

        fs::remove_file(&path).expect("remove source");
        fs::write(&path, b"replacement\n").expect("replacement");
        assert!(verified.ensure_unchanged("session").is_err());
    }

    #[test]
    fn bounded_reader_rejects_growth() {
        let temp = TempRoot::new("limit");
        let root = &temp.0;
        let path = root.join("session.jsonl");
        fs::write(&path, b"12345").expect("source");
        let error = read_bounded(root, &path, 4, "session").expect_err("limit");
        assert!(error.to_string().contains("budget"), "{error:#}");
    }

    #[test]
    fn verified_file_can_be_consumed_without_mutating_source() {
        let temp = TempRoot::new("readonly");
        let root = &temp.0;
        let path = root.join("session.jsonl");
        fs::write(&path, b"read-only\n").expect("source");
        let mut file = open_regular(root, &path, "session").expect("open");
        file.file_mut()
            .seek(SeekFrom::Start(0))
            .expect("seek source");
        let mut bytes = Vec::new();
        file.file_mut().read_to_end(&mut bytes).expect("read source");
        file.ensure_unchanged("session").expect("unchanged");
        assert_eq!(bytes, b"read-only\n");
        assert_eq!(fs::read(&path).expect("source bytes"), b"read-only\n");
    }

    #[test]
    fn sqlite_open_is_read_only_and_never_creates_a_missing_source() {
        let temp = TempRoot::new("sqlite");
        let root = &temp.0;
        let path = root.join("state.sqlite");
        let connection = Connection::open(&path).expect("fixture database");
        connection
            .execute("CREATE TABLE threads (id TEXT PRIMARY KEY)", [])
            .expect("fixture schema");
        drop(connection);

        let connection = open_sqlite_read_only(root, &path, "SQLite database").expect("open");
        assert!(connection
            .execute("CREATE TABLE should_not_exist (id TEXT)", [])
            .is_err());

        let missing = root.join("missing.sqlite");
        assert!(open_sqlite_read_only(root, &missing, "SQLite database").is_err());
        assert!(!missing.exists(), "read-only open must not create a file");
    }
}
