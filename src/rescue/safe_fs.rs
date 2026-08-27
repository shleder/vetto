//! Bounded, read-only filesystem primitives for rescue diagnostics.
//!
//! Rescue consumes provider-owned files.  A provider path is untrusted input,
//! even when it was discovered below the configured state root: the path can
//! be replaced by a symlink, junction, or another file between validation and
//! the eventual open.  This module centralises the checks used by the rescue
//! adapters so that every byte read follows the same boundary.
//! SQLite sources are copied into a private, bounded snapshot before opening;
//! the provider-owned pathname is never reopened for queries.
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
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OpenFlags};

use super::wal::SqliteWalManager;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

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

/// The largest SQLite main-file snapshot accepted by the generic opener.
/// Adapters should pass their tighter context budget through
/// [`open_sqlite_read_only_bounded`].
const DEFAULT_SQLITE_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;
const SQLITE_SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];
const SNAPSHOT_DIRECTORY_ATTEMPTS: usize = 32;

static NEXT_SNAPSHOT_ID: AtomicU64 = AtomicU64::new(0);

/// A private, owned copy of a SQLite main database.
///
/// SQLite is deliberately opened against this path, never against the
/// provider-owned pathname.  The directory is private and the guard removes
/// it when the connection wrapper is dropped.  Keeping the guard alongside
/// the connection is important on Windows, where an open file cannot be
/// unlinked like it can on Unix.
struct PrivateSqliteSnapshot {
    directory: PathBuf,
    path: PathBuf,
}

impl Drop for PrivateSqliteSnapshot {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Ok(metadata) = fs::metadata(&self.path) {
            // Windows refuses to unlink a read-only file. This path is our
            // own private, bounded snapshot inside a private directory that
            // is removed immediately afterwards, so clearing the bit first
            // is safe and intentional.
            #[allow(clippy::permissions_set_readonly_false)]
            {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(false);
                let _ = fs::set_permissions(&self.path, permissions);
            }
        }
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.directory);
    }
}

/// SQLite connection backed by a verified immutable snapshot.
///
/// The `Deref` implementation preserves the existing internal call sites'
/// `&Connection` API while retaining ownership of the snapshot until SQLite
/// has finished all reads.
pub(crate) struct VerifiedSqliteConnection {
    connection: Connection,
    _snapshot: PrivateSqliteSnapshot,
}

impl Deref for VerifiedSqliteConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl DerefMut for VerifiedSqliteConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

#[cfg(test)]
impl VerifiedSqliteConnection {
    fn snapshot_path_for_test(&self) -> &Path {
        &self._snapshot.path
    }
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
    let canonical_root = canonical_root(root)?;
    let lexical_root = lexical_root(root)?;
    let boundary_root = path
        .is_absolute()
        .then_some(&canonical_root)
        .filter(|candidate_root| path.starts_with(*candidate_root))
        .unwrap_or(&lexical_root);
    let candidate = candidate_under_root(boundary_root, path, label)?;
    walk_without_links(boundary_root, &candidate, label)?;
    let canonical =
        fs::canonicalize(&candidate).with_context(|| format!("canonicalize {label}"))?;
    if !canonical.starts_with(&canonical_root) {
        bail!("{label} is outside the configured rescue root");
    }
    let metadata = fs::symlink_metadata(&canonical).with_context(|| format!("inspect {label}"))?;
    validate_regular_metadata(&metadata, label)?;
    Ok(canonical)
}

/// Open a regular file read-only after root-bound and no-follow checks.
pub(crate) fn open_regular(root: &Path, path: &Path, label: &str) -> Result<VerifiedFile> {
    let canonical_root = canonical_root(root)?;
    let lexical_root = lexical_root(root)?;
    let boundary_root = path
        .is_absolute()
        .then_some(&canonical_root)
        .filter(|candidate_root| path.starts_with(*candidate_root))
        .unwrap_or(&lexical_root);
    let candidate = candidate_under_root(boundary_root, path, label)?;
    walk_without_links(boundary_root, &candidate, label)?;

    let canonical_before =
        fs::canonicalize(&candidate).with_context(|| format!("canonicalize {label}"))?;
    if !canonical_before.starts_with(&canonical_root) {
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
    if canonical_after != canonical_before || !canonical_after.starts_with(&canonical_root) {
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
#[allow(dead_code)]
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
pub(crate) fn open_sqlite_read_only(
    root: &Path,
    path: &Path,
    label: &str,
) -> Result<VerifiedSqliteConnection> {
    open_sqlite_read_only_bounded(root, path, DEFAULT_SQLITE_SNAPSHOT_BYTES, label)
}

pub(crate) fn open_sqlite_read_only_bounded(
    root: &Path,
    path: &Path,
    limit: u64,
    label: &str,
) -> Result<VerifiedSqliteConnection> {
    let mut verified = open_regular(root, path, label)?;
    if verified.len() > limit {
        bail!("{label} exceeds the inspection budget");
    }

    let snapshot = create_private_sqlite_snapshot_with_recovery(&mut verified, limit, label)?;
    verified.ensure_unchanged(label)?;

    let connection = Connection::open_with_flags(
        &snapshot.path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| anyhow::anyhow!("{label} snapshot could not be opened read-only"))?;
    // SQLite's flags prevent creation. query_only protects against accidental
    // writes in future diagnostic queries. The connection points only to the
    // private snapshot, so provider-path replacement after this point cannot
    // change the evidence being queried.
    connection
        .execute_batch("PRAGMA query_only=ON; PRAGMA busy_timeout=250;")
        .map_err(|_| anyhow::anyhow!("{label} snapshot could not be configured read-only"))?;
    // SQLite opens lazily: a non-SQLite payload would only fail at first
    // read. Probe the schema header eagerly so malformed input fails closed
    // at open time instead of surfacing later as confusing query errors.
    let _schema_probe: i64 = connection
        .query_row("PRAGMA schema_version", [], |row| row.get(0))
        .map_err(|_| anyhow::anyhow!("{label} snapshot is not a readable SQLite database"))?;
    Ok(VerifiedSqliteConnection {
        connection,
        _snapshot: snapshot,
    })
}

/// Read the same verified source twice. A size/inode check alone does not
/// detect an in-place database rewrite of equal length, while comparing the
/// two bounded byte reads does. The source handle stays open for both passes
/// and ensure_unchanged also rechecks the pathname identity.
fn read_stable_bounded_from_opened(
    verified: &mut VerifiedFile,
    limit: u64,
    label: &str,
) -> Result<Vec<u8>> {
    let first = read_bounded_from_opened(verified, limit, label)?;
    verified
        .file_mut()
        .seek(SeekFrom::Start(0))
        .with_context(|| format!("rewind {label}"))?;
    let second = read_bounded_from_opened(verified, limit, label)?;
    if first != second {
        bail!("{label} bytes changed while being inspected");
    }
    Ok(first)
}

/// Return whether any SQLite sidecar exists next to path.
fn sqlite_sidecar_state(path: &Path, label: &str) -> Result<bool> {
    let mut present = false;
    for suffix in SQLITE_SIDECARS {
        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
        match fs::symlink_metadata(&sidecar) {
            Ok(metadata) => {
                validate_not_reparse(&metadata, label)?;
                if !metadata.is_file() {
                    bail!("{label} has an unsupported SQLite sidecar");
                }
                present = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {label} SQLite sidecar"));
            }
        }
    }
    Ok(present)
}

fn create_private_sqlite_snapshot_with_recovery(
    verified: &mut VerifiedFile,
    limit: u64,
    label: &str,
) -> Result<PrivateSqliteSnapshot> {
    let base = fs::canonicalize(std::env::temp_dir())
        .with_context(|| format!("resolve private {label} snapshot directory"))?;
    let base_metadata = fs::symlink_metadata(&base)
        .with_context(|| format!("inspect private {label} snapshot directory"))?;
    validate_directory_metadata(&base_metadata, "private snapshot directory")?;
    let process = std::process::id();
    let nonce = NEXT_SNAPSHOT_ID.fetch_add(1, Ordering::Relaxed);

    for attempt in 0..SNAPSHOT_DIRECTORY_ATTEMPTS {
        let directory = base.join(format!("vetto-sqlite-snapshot-{process}-{nonce}-{attempt}"));
        match create_private_directory(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("create private {label} snapshot"));
            }
        }
        let db_path = directory.join("database.sqlite");
        let result = (|| {
            // Read main db bytes from opened verified handle
            verified.file_mut().seek(SeekFrom::Start(0))?;
            let mut db_bytes = Vec::new();
            verified
                .file_mut()
                .take(limit.saturating_add(1))
                .read_to_end(&mut db_bytes)?;
            if db_bytes.len() as u64 > limit {
                bail!("{label} exceeds the inspection budget");
            }
            verified.ensure_unchanged(label)?;

            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            #[cfg(windows)]
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            let mut file = options
                .open(&db_path)
                .with_context(|| format!("create private {label} snapshot file"))?;
            file.write_all(&db_bytes)
                .with_context(|| format!("write private {label} snapshot"))?;
            file.sync_all()
                .with_context(|| format!("flush private {label} snapshot"))?;
            drop(file);

            // Stage sidecars if present
            let src_base = verified.path().display().to_string();
            let mut has_sidecars = false;
            for suffix in SQLITE_SIDECARS {
                let src_sidecar = PathBuf::from(format!("{}{}", src_base, suffix));
                let dst_sidecar = directory.join(format!("database.sqlite{}", suffix));
                match fs::symlink_metadata(&src_sidecar) {
                    Ok(meta) => {
                        validate_regular_metadata(&meta, label)?;
                        let mut sc_file = OpenOptions::new();
                        sc_file.read(true);
                        #[cfg(unix)]
                        sc_file.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
                        #[cfg(windows)]
                        sc_file.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
                        let mut sc_handle = sc_file.open(&src_sidecar)?;
                        let mut sc_bytes = Vec::new();
                        sc_handle.read_to_end(&mut sc_bytes)?;
                        fs::write(&dst_sidecar, sc_bytes)?;
                        has_sidecars = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).with_context(|| format!("inspect {label} SQLite sidecar")),
                }
            }

            verified.ensure_unchanged(label)?;

            if has_sidecars {
                // Open in read-write mode inside our private sandbox directory to checkpoint and recover WAL
                let mut conn = Connection::open(&db_path)?;
                SqliteWalManager::checkpoint_and_recover(&mut conn)?;
                drop(conn);

                // Remove temporary sidecar files in the staging directory
                for suffix in SQLITE_SIDECARS {
                    let dst_sidecar = directory.join(format!("database.sqlite{}", suffix));
                    let _ = fs::remove_file(&dst_sidecar);
                }
            }

            make_snapshot_read_only(&db_path)
                .with_context(|| format!("protect private {label} snapshot"))?;
            Ok::<(), anyhow::Error>(())
        })();

        match result {
            Ok(()) => return Ok(PrivateSqliteSnapshot { directory, path: db_path }),
            Err(error) => {
                let _ = fs::remove_file(&db_path);
                let _ = fs::remove_dir_all(&directory);
                return Err(error);
            }
        }
    }
    bail!("could not allocate a private {label} snapshot directory")
}

#[allow(dead_code)]
fn create_private_sqlite_snapshot(bytes: &[u8], label: &str) -> Result<PrivateSqliteSnapshot> {
    let base = fs::canonicalize(std::env::temp_dir())
        .with_context(|| format!("resolve private {label} snapshot directory"))?;
    let base_metadata = fs::symlink_metadata(&base)
        .with_context(|| format!("inspect private {label} snapshot directory"))?;
    validate_directory_metadata(&base_metadata, "private snapshot directory")?;
    let process = std::process::id();
    let nonce = NEXT_SNAPSHOT_ID.fetch_add(1, Ordering::Relaxed);
    for attempt in 0..SNAPSHOT_DIRECTORY_ATTEMPTS {
        let directory = base.join(format!("vetto-sqlite-snapshot-{process}-{nonce}-{attempt}"));
        match create_private_directory(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("create private {label} snapshot"));
            }
        }
        let path = directory.join("database.sqlite");
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            #[cfg(windows)]
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            let mut file = options
                .open(&path)
                .with_context(|| format!("create private {label} snapshot file"))?;
            file.write_all(bytes)
                .with_context(|| format!("write private {label} snapshot"))?;
            file.sync_all()
                .with_context(|| format!("flush private {label} snapshot"))?;
            drop(file);
            make_snapshot_read_only(&path)
                .with_context(|| format!("protect private {label} snapshot"))?;
            Ok::<(), anyhow::Error>(())
        })();
        match result {
            Ok(()) => return Ok(PrivateSqliteSnapshot { directory, path }),
            Err(error) => {
                let _ = fs::remove_file(&path);
                let _ = fs::remove_dir(&directory);
                return Err(error);
            }
        }
    }
    bail!("could not allocate a private {label} snapshot directory")
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn make_snapshot_read_only(path: &Path) -> std::io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o400);
    }
    #[cfg(windows)]
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
}

fn candidate_under_root(root: &Path, path: &Path, label: &str) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("{label} path is empty");
    }
    // Scope the component check to the derived part of the path. The operator
    // chooses the rescue root (`CODEX_HOME=./codex-home` is legitimate); the
    // threat model targets non-canonical provider-derived paths, not the root.
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        bail!("{label} contains an unsafe path component");
    }
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    if !candidate.starts_with(root) {
        bail!("{label} is outside the configured rescue root");
    }
    Ok(candidate)
}

fn lexical_root(root: &Path) -> Result<PathBuf> {
    if root.is_absolute() {
        return Ok(root.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("resolve rescue root")?
        .join(root))
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

    #[test]
    fn candidate_under_root_accepts_operator_root_with_dot_component() {
        // CODEX_HOME=./codex-home is a legitimate operator choice; only
        // provider-derived path parts are hostile.
        let root = Path::new("./rel-root");
        let candidate =
            candidate_under_root(root, Path::new("sessions/2026/rollout.jsonl"), "session")
                .expect("relative path under a dotted operator root");
        assert_eq!(
            candidate,
            Path::new("./rel-root/sessions/2026/rollout.jsonl")
        );
    }

    #[test]
    fn candidate_under_root_still_rejects_parent_dir_in_derived_paths() {
        let error = candidate_under_root(
            Path::new("/state"),
            Path::new("sessions/../../etc/passwd"),
            "session",
        )
        .expect_err("derived parent-dir escape must fail closed");
        assert!(error.to_string().contains("unsafe path component"));
    }

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
        file.file_mut()
            .read_to_end(&mut bytes)
            .expect("read source");
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

    #[test]
    fn sqlite_uses_private_snapshot_and_survives_source_path_replacement() {
        let temp = TempRoot::new("sqlite-snapshot");
        let root = &temp.0;
        let path = root.join("state.sqlite");
        let source = Connection::open(&path).expect("fixture database");
        source
            .execute("CREATE TABLE threads (id TEXT PRIMARY KEY)", [])
            .expect("fixture schema");
        source
            .execute("INSERT INTO threads VALUES ('original')", [])
            .expect("fixture row");
        drop(source);

        let connection =
            open_sqlite_read_only(root, &path, "SQLite database").expect("open snapshot");
        let snapshot_path = connection.snapshot_path_for_test().to_path_buf();
        assert!(
            snapshot_path.exists(),
            "snapshot must stay alive with connection"
        );

        fs::remove_file(&path).expect("remove source");
        fs::write(&path, b"this replacement is not sqlite").expect("replacement");

        let value: String = connection
            .query_row("SELECT id FROM threads", [], |row| row.get(0))
            .expect("query original snapshot");
        assert_eq!(value, "original");

        drop(connection);
        assert!(
            !snapshot_path.exists(),
            "private snapshot must be removed after connection drop"
        );
    }

    #[test]
    fn sqlite_rejects_oversized_and_malformed_snapshots() {
        let temp = TempRoot::new("sqlite-invalid");
        let root = &temp.0;
        let oversized = root.join("oversized.sqlite");
        fs::write(&oversized, [0u8; 64]).expect("oversized fixture");
        assert!(open_sqlite_read_only_bounded(root, &oversized, 8, "SQLite database").is_err());

        let malformed = root.join("malformed.sqlite");
        fs::write(&malformed, b"not a sqlite database").expect("malformed fixture");
        assert!(open_sqlite_read_only(root, &malformed, "SQLite database").is_err());
    }

    #[test]
    fn sqlite_recovers_wal_state() {
        let temp = TempRoot::new("sqlite-wal");
        let root = &temp.0;
        let path = root.join("state.sqlite");
        let source = Connection::open(&path).expect("fixture database");
        source
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE threads (id TEXT PRIMARY KEY);
                 INSERT INTO threads VALUES ('wal_entry');",
            )
            .expect("fixture schema and row");
        drop(source);

        let connection = open_sqlite_read_only(root, &path, "SQLite database")
            .expect("open sqlite with wal recovery");
        let value: String = connection
            .query_row("SELECT id FROM threads", [], |row| row.get(0))
            .expect("query recovered db");
        assert_eq!(value, "wal_entry");
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_rejects_symlinked_wal_state() {
        use std::os::unix::fs::symlink;

        let temp = TempRoot::new("sqlite-wal-symlink");
        let root = &temp.0;
        let path = root.join("state.sqlite");
        let source = Connection::open(&path).expect("fixture database");
        source
            .execute("CREATE TABLE threads (id TEXT PRIMARY KEY)", [])
            .expect("fixture schema");
        drop(source);
        let outside = temp.0.join("outside-wal");
        fs::write(&outside, b"outside").expect("outside marker");
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        symlink(&outside, &wal).expect("symlink wal");
        assert!(open_sqlite_read_only(root, &path, "SQLite database").is_err());
    }
}
