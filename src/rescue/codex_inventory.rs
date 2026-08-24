//! Read-only Codex SQLite inventory and projection diagnostics.
//!
//! This module deliberately does not share the legacy mutating planner.  It
//! treats the JSONL rollout as the source of truth and SQLite as derived
//! metadata.  Databases are opened with SQLite's read-only/no-create flag and
//! every diagnostic is bounded by the caller's [`RescueContext`].  The public
//! report contains only classifications and numeric cursor evidence; provider
//! paths read from SQLite are never serialized or included in errors.
//!
//! The shared [`super::safe_fs`] opener keeps source/handle identity checks in
//! one place.  It is intentionally fail-closed when a path or acquired handle
//! changes; on Windows the stable std API cannot expose file-index/hard-link
//! identity, so the helper documents that remaining limitation instead of
//! claiming an atomic guarantee it cannot provide.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use rusqlite::{types::ValueRef, Connection};
use serde::Serialize;

use super::{safe_fs, types::RescueContext};

pub const INDEX_DIVERGENCE: &str = "INDEX_DIVERGENCE";
pub const ROLLOUT_MISSING: &str = "ROLLOUT_MISSING";
pub const SIDEBAR_METADATA_EMPTY: &str = "SIDEBAR_METADATA_EMPTY";
pub const WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE: &str =
    "WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE";
pub const WEDGED_PROJECTION: &str = "WEDGED_PROJECTION";
pub const PROJECTION_STATE_UNKNOWN: &str = "PROJECTION_STATE_UNKNOWN";

const THREAD_TABLE: &str = "threads";
const PROJECTION_TABLE: &str = "thread_history_projection_state";
const MAX_SQLITE_CANDIDATES: usize = 32;
const MAX_SQLITE_ROWS: usize = 100_000;
const MAX_SQLITE_CELL_BYTES: usize = 64 * 1024;
const MAX_SQLITE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SESSION_ID_BYTES: usize = 256;

/// Optional identity/path metadata supplied by a caller that already parsed
/// the session.  The values are used only for matching; they are not exposed
/// in [`CodexInventoryReport`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionMetadata {
    pub session_id: Option<String>,
    pub rollout_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    Consistent,
    Findings,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ThreadStoreEvidence {
    pub status: String,
    pub path_relation: String,
    pub row_present: Option<bool>,
    pub rollout_present: Option<bool>,
    pub windows_namespace_divergence: bool,
}

impl Default for ThreadStoreEvidence {
    fn default() -> Self {
        Self {
            status: "not_applicable".to_string(),
            path_relation: "not_applicable".to_string(),
            row_present: None,
            rollout_present: None,
            windows_namespace_divergence: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProjectionEvidence {
    pub status: String,
    pub next_rollout_byte_offset: Option<u64>,
    pub next_rollout_ordinal: Option<u64>,
    pub canonical_size: Option<u64>,
    pub boundary_ordinal: Option<u64>,
    pub next_boundary_ordinal: Option<u64>,
    pub confidence: String,
}

impl Default for ProjectionEvidence {
    fn default() -> Self {
        Self {
            status: "not_applicable".to_string(),
            next_rollout_byte_offset: None,
            next_rollout_ordinal: None,
            canonical_size: None,
            boundary_ordinal: None,
            next_boundary_ordinal: None,
            confidence: "not_applicable".to_string(),
        }
    }
}

/// Privacy-preserving result of the inventory pass.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CodexInventoryReport {
    pub status: InventoryStatus,
    pub findings: Vec<String>,
    pub notices: Vec<String>,
    pub thread_store: ThreadStoreEvidence,
    pub projection: ProjectionEvidence,
}

/// Inspect a rollout path, bounded bytes, or metadata-only identity.
///
/// `session_path` and `session_bytes` are both optional so callers can use a
/// stable byte snapshot obtained by the adapter.  If both are supplied, bytes
/// are the canonical evidence and the path is used only for path identity.
/// Metadata-only calls can classify a matching SQLite row, but cannot make a
/// projection claim without rollout bytes.
pub fn inspect_session(
    context: &RescueContext,
    session_path: Option<&Path>,
    session_bytes: Option<&[u8]>,
    metadata: Option<&SessionMetadata>,
) -> Result<CodexInventoryReport> {
    let configured_root = context.root.clone();
    let root = canonical_root(&context.root)?;
    let metadata = metadata.cloned().unwrap_or_default();
    let requested_path = session_path
        .map(Path::to_path_buf)
        .or_else(|| metadata.rollout_path.clone());
    let requested_path = requested_path.as_deref();

    let bytes = match session_bytes {
        Some(bytes) => {
            if bytes.len() as u64 > context.max_session_bytes {
                bail!("session evidence exceeds the inspection budget");
            }
            Some(bytes.to_vec())
        }
        None => requested_path
            .map(|path| read_stable_session(&configured_root, path, context.max_session_bytes))
            .transpose()?,
    };

    let canonical_session_path = requested_path
        .map(|path| validate_session_path(&configured_root, path))
        .transpose()?;
    let session_id = metadata
        .session_id
        .as_deref()
        .and_then(validate_session_id)
        .or_else(|| bytes.as_deref().and_then(parse_session_id))
        .or_else(|| {
            canonical_session_path
                .as_deref()
                .and_then(session_id_from_path)
        });

    let mut report = CodexInventoryReport {
        status: InventoryStatus::NotApplicable,
        findings: Vec::new(),
        notices: Vec::new(),
        thread_store: ThreadStoreEvidence::default(),
        projection: ProjectionEvidence::default(),
    };

    let thread_result = inspect_thread_store(
        &root,
        canonical_session_path.as_deref(),
        session_id.as_deref(),
        context.max_files,
        context.max_total_bytes.min(MAX_SQLITE_BYTES),
    );
    report.thread_store = thread_result.evidence;
    extend_unique(&mut report.findings, thread_result.findings);
    extend_unique(&mut report.notices, thread_result.notices);

    let projection_result = inspect_projection(
        &root,
        bytes.as_deref(),
        session_id.as_deref(),
        context.max_files,
        context.max_record_bytes,
        context.max_total_bytes.min(MAX_SQLITE_BYTES),
    );
    report.projection = projection_result.evidence;
    extend_unique(&mut report.findings, projection_result.findings);
    extend_unique(&mut report.notices, projection_result.notices);

    report.status =
        if report.projection.status == "unknown" || report.thread_store.status == "unknown" {
            InventoryStatus::Unknown
        } else if !report.findings.is_empty() {
            InventoryStatus::Findings
        } else if report.thread_store.status == "not_applicable"
            && report.projection.status == "not_applicable"
        {
            InventoryStatus::NotApplicable
        } else {
            InventoryStatus::Consistent
        };
    Ok(report)
}

#[derive(Debug, Default)]
struct ThreadStoreResult {
    evidence: ThreadStoreEvidence,
    findings: Vec<String>,
    notices: Vec<String>,
}

#[derive(Debug, Default)]
struct ProjectionResult {
    evidence: ProjectionEvidence,
    findings: Vec<String>,
    notices: Vec<String>,
}

fn canonical_root(root: &Path) -> Result<PathBuf> {
    safe_fs::canonical_root(root)
        .map_err(|_| anyhow::anyhow!("rescue root cannot be canonicalized"))
}

fn validate_session_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let verified = safe_fs::open_regular(root, path, "session evidence")
        .map_err(|_| anyhow::anyhow!("session evidence cannot be opened safely"))?;
    verified
        .ensure_unchanged("session evidence")
        .map_err(|_| anyhow::anyhow!("session evidence changed while being inspected"))?;
    Ok(verified.path().to_path_buf())
}

fn read_stable_session(root: &Path, path: &Path, limit: u64) -> Result<Vec<u8>> {
    let first = safe_fs::read_bounded(root, path, limit, "session evidence")?;
    let second = safe_fs::read_bounded(root, path, limit, "session evidence")?;
    if first != second {
        bail!("session changed while being read; retry after the writer stops");
    }
    Ok(first)
}

fn parse_session_id(bytes: &[u8]) -> Option<String> {
    for raw in bytes.split(|byte| *byte == b'\n').take(4_096) {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("type").and_then(serde_json::Value::as_str) != Some("session_meta") {
            continue;
        }
        if let Some(payload) = value.get("payload") {
            if let Some(id) =
                value_string(payload, "session_id").or_else(|| value_string(payload, "id"))
            {
                return Some(id);
            }
        }
    }
    None
}

fn validate_session_id(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > MAX_SESSION_ID_BYTES || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_owned())
}

fn value_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|value| value.as_str())
        .and_then(validate_session_id)
}

fn session_id_from_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    if stem.len() < 36 {
        return None;
    }
    let candidate = &stem[stem.len() - 36..];
    let valid = candidate.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    });
    if valid {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn extend_unique(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

#[derive(Debug, Default)]
struct DatabaseCandidates {
    paths: Vec<PathBuf>,
    rejected: bool,
}

fn database_candidates(
    root: &Path,
    max_files: usize,
    max_database_bytes: u64,
) -> DatabaseCandidates {
    let limit = max_files.min(MAX_SQLITE_CANDIDATES);
    if limit == 0 {
        return DatabaseCandidates {
            paths: Vec::new(),
            rejected: true,
        };
    }
    // Only real directory entries belong in the candidate list.  Seeding
    // missing defaults would consume a small caller budget before reaching a
    // real provider database such as `a.sqlite`.
    let mut names = Vec::new();
    let mut rejected = false;
    match fs::read_dir(root) {
        Ok(entries) => {
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        rejected = true;
                        break;
                    }
                };
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                let lower = name.to_ascii_lowercase();
                if (lower.ends_with(".sqlite")
                    || lower.ends_with(".sqlite3")
                    || lower.ends_with(".db"))
                    && !names.iter().any(|known| known == name)
                {
                    if names.len() >= limit {
                        rejected = true;
                        break;
                    }
                    names.push(name.to_string());
                }
            }
        }
        Err(_) => rejected = true,
    }
    names.sort_by_key(|name| {
        if name == "state_5.sqlite" {
            0
        } else if name == "state.sqlite" {
            1
        } else if name == "state.db" {
            2
        } else {
            3
        }
    });
    let mut paths = Vec::new();
    let mut total_bytes = 0u64;
    for name in names.into_iter().take(limit) {
        let path = root.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                rejected = true;
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            rejected = true;
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                rejected = true;
                continue;
            }
        }
        let size = metadata.len();
        if size > max_database_bytes {
            rejected = true;
            continue;
        }
        let Some(next_total) = total_bytes.checked_add(size) else {
            return DatabaseCandidates {
                paths: Vec::new(),
                rejected: true,
            };
        };
        if next_total > max_database_bytes {
            // No earlier path may be opened after aggregate preflight fails.
            return DatabaseCandidates {
                paths: Vec::new(),
                rejected: true,
            };
        }
        total_bytes = next_total;
        let canonical = match safe_fs::canonical_regular_path(root, &path, "SQLite database") {
            Ok(canonical) if canonical.starts_with(root) => canonical,
            Ok(_) | Err(_) => {
                rejected = true;
                continue;
            }
        };
        paths.push(canonical);
    }
    if rejected {
        return DatabaseCandidates {
            paths: Vec::new(),
            rejected: true,
        };
    }
    DatabaseCandidates {
        paths,
        rejected: false,
    }
}

fn table_names(connection: &Connection) -> Result<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .map_err(|_| anyhow::anyhow!("SQLite schema could not be read"))?;
    let rows = statement
        .query_map([], |row| {
            let value = row.get_ref(0)?;
            Ok(bounded_text_value(value))
        })
        .map_err(|_| anyhow::anyhow!("SQLite schema could not be read"))?;
    let mut names = Vec::new();
    let mut rows_seen = 0usize;
    for row in rows {
        rows_seen = rows_seen
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("SQLite schema row counter overflow"))?;
        if rows_seen > MAX_SQLITE_ROWS {
            return Err(anyhow::anyhow!(
                "SQLite schema exceeded the configured row budget"
            ));
        }
        if let Some(name) = row.map_err(|_| anyhow::anyhow!("SQLite schema could not be read"))? {
            names.push(name);
        }
    }
    Ok(names)
}

fn table_columns(connection: &Connection, table: &str) -> Result<HashSet<String>> {
    let sql = format!("PRAGMA table_info({})", quote_identifier(table));
    let mut statement = connection
        .prepare(&sql)
        .map_err(|_| anyhow::anyhow!("SQLite table schema could not be read"))?;
    let rows = statement
        .query_map([], |row| {
            let value = row.get_ref(1)?;
            Ok(bounded_text_value(value))
        })
        .map_err(|_| anyhow::anyhow!("SQLite table schema could not be read"))?;
    let mut columns = HashSet::new();
    let mut rows_seen = 0usize;
    for row in rows {
        rows_seen = rows_seen
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("SQLite table schema row counter overflow"))?;
        if rows_seen > MAX_SQLITE_ROWS {
            return Err(anyhow::anyhow!(
                "SQLite table schema exceeded the configured row budget"
            ));
        }
        if let Some(column) =
            row.map_err(|_| anyhow::anyhow!("SQLite table schema could not be read"))?
        {
            columns.insert(column);
        }
    }
    Ok(columns)
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn first_column(columns: &HashSet<String>, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find(|name| columns.contains(**name))
        .map(|name| (*name).to_string())
}

fn value_text(value: ValueRef<'_>) -> Option<String> {
    match value {
        ValueRef::Text(value) if value.len() <= MAX_SQLITE_CELL_BYTES => {
            std::str::from_utf8(value).ok().map(ToOwned::to_owned)
        }
        ValueRef::Text(_) => None,
        ValueRef::Integer(value) => Some(value.to_string()),
        ValueRef::Real(value) => Some(value.to_string()),
        ValueRef::Null | ValueRef::Blob(_) => None,
    }
}

fn bounded_text_value(value: ValueRef<'_>) -> Option<String> {
    match value {
        ValueRef::Text(value) if value.len() <= MAX_SQLITE_CELL_BYTES => {
            std::str::from_utf8(value).ok().map(ToOwned::to_owned)
        }
        ValueRef::Text(_) | ValueRef::Null | ValueRef::Blob(_) => None,
        ValueRef::Integer(value) => Some(value.to_string()),
        ValueRef::Real(value) => Some(value.to_string()),
    }
}

fn value_i64(value: ValueRef<'_>) -> Option<i64> {
    match value {
        ValueRef::Integer(value) => Some(value),
        ValueRef::Text(value) => std::str::from_utf8(value).ok()?.parse().ok(),
        ValueRef::Real(_) | ValueRef::Null | ValueRef::Blob(_) => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathRelation {
    Exact,
    Equivalent { namespace_divergence: bool },
    Different,
    Unknown,
}

fn path_relation(stored: &str, discovered: &Path) -> PathRelation {
    let discovered = discovered_logical_path(&discovered.to_string_lossy());
    if stored == discovered {
        return PathRelation::Exact;
    }
    let Some((stored_normalized, stored_extended)) = normalize_path(stored) else {
        return PathRelation::Unknown;
    };
    let Some((discovered_normalized, discovered_extended)) = normalize_path(&discovered) else {
        return PathRelation::Unknown;
    };
    if stored_normalized == discovered_normalized {
        PathRelation::Equivalent {
            namespace_divergence: stored_extended != discovered_extended,
        }
    } else {
        PathRelation::Different
    }
}

fn discovered_logical_path(raw: &str) -> String {
    if cfg!(windows) {
        let replaced = raw.replace('\\', "/");
        if replaced
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("//?/UNC/"))
        {
            return format!("//{}", &replaced[8..]);
        }
        if let Some(stripped) = replaced.strip_prefix("//?/") {
            return stripped.to_string();
        }
    }
    raw.to_string()
}

fn normalize_path(raw: &str) -> Option<(String, bool)> {
    if raw.is_empty() || raw.contains('\0') {
        return None;
    }
    let mut value = raw.replace('\\', "/");
    let extended = value.starts_with("//?/");
    if extended {
        if value.len() >= 8 && value[4..].to_ascii_uppercase().starts_with("UNC/") {
            value = format!("//{}", &value[8..]);
        } else if value.len() >= 7
            && value.as_bytes().get(4).is_some_and(u8::is_ascii_alphabetic)
            && value.as_bytes().get(5) == Some(&b':')
        {
            value = value[4..].to_string();
        } else {
            return None;
        }
    }
    if value.len() >= 3 && value.as_bytes()[1] == b':' {
        if !value.as_bytes()[0].is_ascii_alphabetic() {
            return None;
        }
        value = value[0..1].to_ascii_uppercase() + &value[1..];
        value = value.to_ascii_lowercase();
    } else if value.starts_with("//") {
        value = value.to_ascii_lowercase();
    } else if value.starts_with("/mnt/") && value.len() >= 7 {
        let drive = value.as_bytes()[5];
        if drive.is_ascii_alphabetic() && value.as_bytes()[6] == b'/' {
            value = format!("{}:/{}", (drive as char).to_ascii_uppercase(), &value[7..]);
            value = value.to_ascii_lowercase();
        }
    }
    while value.contains("//") && !value.starts_with("//") {
        value = value.replace("//", "/");
    }
    if value.split('/').any(|part| part == "." || part == "..") {
        return None;
    }
    if value.len() > 1 {
        value = value.trim_end_matches('/').to_string();
    }
    Some((value, extended))
}

/// Check a stored rollout path only when every component is lexically inside
/// the already-canonicalized rescue root.  SQLite is provider-derived input;
/// its path column must never turn diagnosis into an arbitrary filesystem or
/// UNC/network metadata probe.
fn stored_path_exists_within_root(root: &Path, stored: &str) -> Option<bool> {
    if stored.is_empty() || stored.contains('\0') {
        return None;
    }
    if cfg!(not(windows)) && looks_windows_path(stored) {
        return None;
    }
    let raw = Path::new(stored);
    if raw
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return None;
    }
    if !raw.is_absolute()
        && raw.components().any(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Prefix(_)
            )
        })
    {
        return None;
    }
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        root.join(raw)
    };
    if !candidate.starts_with(root) {
        return None;
    }

    let relative = candidate.strip_prefix(root).ok()?;
    let components = relative.components().collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = *component else {
            return None;
        };
        current.push(name);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(false),
            Err(_) => return None,
        };
        if metadata.file_type().is_symlink() {
            return None;
        }
        if index + 1 < components.len() && !metadata.is_dir() {
            return Some(false);
        }
        #[cfg(unix)]
        if index + 1 == components.len() {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return None;
            }
        }
    }
    let metadata = fs::symlink_metadata(&candidate).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Some(false);
    }
    // Re-run the shared final-component/reparse policy before treating a
    // provider-supplied alternate path as present.  Any unestablished
    // identity is deliberately reported as unknown rather than true.
    safe_fs::canonical_regular_path(root, &candidate, "stored rollout").ok()?;
    Some(true)
}

fn looks_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() >= 3 && bytes[1] == b':') || value.starts_with("\\\\") || value.starts_with("//")
}

fn inspect_thread_store(
    root: &Path,
    session_path: Option<&Path>,
    session_id: Option<&str>,
    max_files: usize,
    max_database_bytes: u64,
) -> ThreadStoreResult {
    let mut result = ThreadStoreResult::default();
    let candidate_set = database_candidates(root, max_files, max_database_bytes);
    if candidate_set.paths.is_empty() {
        if candidate_set.rejected {
            result.evidence.status = "unknown".to_string();
            result
                .notices
                .push("a SQLite candidate exceeded the safe inspection boundary".to_string());
            return result;
        }
        result
            .notices
            .push("no compatible Codex SQLite store was found".to_string());
        return result;
    }
    let candidates = candidate_set.paths;
    let mut compatible_store = false;
    let mut read_error = false;
    let mut schema_unknown = false;
    for db_path in candidates {
        let Ok(connection) = safe_fs::open_sqlite_read_only_bounded(
            root,
            &db_path,
            max_database_bytes,
            "SQLite database",
        )
        else {
            read_error = true;
            continue;
        };
        let Ok(tables) = table_names(&connection) else {
            read_error = true;
            continue;
        };
        if !tables.iter().any(|table| table == THREAD_TABLE) {
            continue;
        }
        let Ok(columns) = table_columns(&connection, THREAD_TABLE) else {
            read_error = true;
            continue;
        };
        let Some(path_column) = first_column(&columns, &["rollout_path", "session_path", "path"])
        else {
            continue;
        };
        compatible_store = true;
        let id_column = first_column(&columns, &["id", "thread_id", "session_id"]);
        if id_column.is_none() && session_id.is_some() {
            schema_unknown = true;
            continue;
        }
        let preview_column = first_column(&columns, &["preview"]);
        let first_user_column = first_column(&columns, &["first_user_message"]);
        let sql = format!(
            "SELECT {}, {}, {}, {} FROM {}{} LIMIT {}",
            id_column
                .as_deref()
                .map(quote_identifier)
                .unwrap_or_else(|| "NULL".to_string()),
            quote_identifier(&path_column),
            preview_column
                .as_deref()
                .map(quote_identifier)
                .unwrap_or_else(|| "NULL".to_string()),
            first_user_column
                .as_deref()
                .map(quote_identifier)
                .unwrap_or_else(|| "NULL".to_string()),
            quote_identifier(THREAD_TABLE),
            if let (Some(id_column), Some(_)) = (id_column.as_deref(), session_id) {
                format!(
                    " WHERE {} = {}",
                    quote_identifier(id_column),
                    quote_literal_placeholder()
                )
            } else {
                String::new()
            },
            MAX_SQLITE_ROWS
        );
        let mut statement = match connection.prepare(&sql) {
            Ok(statement) => statement,
            Err(_) => {
                read_error = true;
                continue;
            }
        };
        let matched_by_id = id_column.is_some() && session_id.is_some();
        let rows_result = if matched_by_id {
            statement.query([session_id.unwrap()])
        } else {
            statement.query([])
        };
        let Ok(mut rows) = rows_result else {
            read_error = true;
            continue;
        };
        let mut matched = false;
        loop {
            let row = match rows.next() {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(_) => {
                    read_error = true;
                    break;
                }
            };
            let stored = match row.get_ref(1) {
                Ok(value) => value_text(value),
                Err(_) => {
                    read_error = true;
                    break;
                }
            };
            let preview = match row.get_ref(2) {
                Ok(value) => value_text(value),
                Err(_) => {
                    read_error = true;
                    break;
                }
            };
            let first_user = match row.get_ref(3) {
                Ok(value) => value_text(value),
                Err(_) => {
                    read_error = true;
                    break;
                }
            };
            let relation = match (&stored, session_path) {
                (Some(stored), Some(session_path)) => path_relation(stored, session_path),
                _ => PathRelation::Unknown,
            };
            let by_id = matched_by_id;
            let by_path = session_id.is_none()
                && !matches!(relation, PathRelation::Different | PathRelation::Unknown);
            if !by_id && !by_path {
                continue;
            }
            matched = true;
            result.evidence.row_present = Some(true);
            if preview_column.is_some()
                && first_user_column.is_some()
                && preview.as_deref().unwrap_or("").trim().is_empty()
                && first_user.as_deref().unwrap_or("").trim().is_empty()
            {
                result.findings.push(SIDEBAR_METADATA_EMPTY.to_string());
                result.notices.push(
                    "thread row exists but both sidebar discovery fields are empty".to_string(),
                );
            }
            match stored {
                None => {
                    result.evidence.status = "unknown".to_string();
                    result.evidence.path_relation = "unknown".to_string();
                    result.notices.push(
                        "thread row has no usable rollout path; divergence was not inferred"
                            .to_string(),
                    );
                }
                Some(stored) => {
                    match relation {
                        PathRelation::Exact => {
                            result.evidence.status = "consistent".to_string();
                            result.evidence.path_relation = "exact".to_string();
                            result.evidence.rollout_present = Some(true);
                        }
                        PathRelation::Equivalent {
                            namespace_divergence,
                        } => {
                            result.evidence.status = if namespace_divergence {
                                "diverged"
                            } else {
                                "consistent"
                            }
                            .to_string();
                            result.evidence.path_relation = "equivalent".to_string();
                            result.evidence.windows_namespace_divergence = namespace_divergence;
                            result.evidence.rollout_present = Some(true);
                            if namespace_divergence {
                                result
                                    .findings
                                    .push(WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE.to_string());
                                result.notices.push("thread index and rollout use different Windows path namespaces".to_string());
                            }
                        }
                        PathRelation::Different => {
                            result.evidence.status = "diverged".to_string();
                            result.evidence.path_relation = "different".to_string();
                            match stored_path_exists_within_root(root, &stored) {
                                Some(true) => {
                                    result.evidence.rollout_present = Some(true);
                                    result.findings.push(INDEX_DIVERGENCE.to_string());
                                    result.notices.push(
                                        "thread index points to a different rollout reference"
                                            .to_string(),
                                    );
                                }
                                Some(false) => {
                                    result.evidence.rollout_present = Some(false);
                                    result.findings.push(ROLLOUT_MISSING.to_string());
                                    result.notices.push(
                                        "thread index references a rollout that is not present"
                                            .to_string(),
                                    );
                                }
                                None => {
                                    result.evidence.rollout_present = None;
                                    result.findings.push(INDEX_DIVERGENCE.to_string());
                                    result.notices.push("thread index and discovered rollout identity differ; exact filesystem cause is unknown".to_string());
                                }
                            }
                        }
                        PathRelation::Unknown => {
                            result.evidence.status = "unknown".to_string();
                            result.evidence.path_relation = "unknown".to_string();
                            result.notices.push(
                                "thread index path identity could not be established safely"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
            if by_id {
                break;
            }
        }
        if matched {
            break;
        }
    }
    if candidate_set.rejected || read_error || schema_unknown {
        result.evidence.status = "unknown".to_string();
        result.evidence.path_relation = "unknown".to_string();
        result.evidence.row_present = None;
        result.evidence.rollout_present = None;
        result.evidence.windows_namespace_divergence = false;
        result.findings.clear();
        result.notices.push(
            "SQLite inventory evidence was incomplete or could not be correlated safely"
                .to_string(),
        );
        return result;
    }
    if !matched_or_row(&result.evidence) {
        if compatible_store && session_path.is_some() {
            result.evidence.status = "diverged".to_string();
            result.evidence.path_relation = "not_indexed".to_string();
            result.evidence.row_present = Some(false);
            result.findings.push(INDEX_DIVERGENCE.to_string());
            result.notices.push(
                "rollout exists on disk but no matching thread index row was found".to_string(),
            );
        } else if compatible_store {
            result.evidence.status = "not_recorded".to_string();
            result.evidence.row_present = Some(false);
            result.notices.push("no matching thread index row was found; absence is not treated as rollout deletion".to_string());
        } else {
            result.evidence.status = "unknown".to_string();
            result.notices.push(
                "SQLite exists but no compatible threads rollout schema was found".to_string(),
            );
        }
    }
    result
}

fn matched_or_row(evidence: &ThreadStoreEvidence) -> bool {
    evidence.row_present == Some(true)
}

fn quote_literal_placeholder() -> &'static str {
    "?"
}

#[derive(Debug, Clone, Copy)]
struct RecordBoundary {
    ordinal: Option<u64>,
    end: usize,
}

struct RecordBoundaryIter<'a> {
    bytes: &'a [u8],
    start: usize,
    max_record_bytes: usize,
}

impl<'a> RecordBoundaryIter<'a> {
    fn new(bytes: &'a [u8], max_record_bytes: usize) -> Self {
        Self {
            bytes,
            start: 0,
            max_record_bytes,
        }
    }
}

impl Iterator for RecordBoundaryIter<'_> {
    type Item = RecordBoundary;

    fn next(&mut self) -> Option<Self::Item> {
        while self.start < self.bytes.len() {
            let start = self.start;
            let bytes = self.bytes;
            let relative_end = bytes[start..].iter().position(|byte| *byte == b'\n');
            let (index, end) = match relative_end {
                Some(relative_end) => {
                    let index = start + relative_end;
                    (index, index + 1)
                }
                None => (bytes.len(), bytes.len()),
            };
            let raw = bytes[start..index]
                .strip_suffix(b"\r")
                .unwrap_or(&bytes[start..index]);
            self.start = end;
            if raw.iter().all(|byte| byte.is_ascii_whitespace()) {
                continue;
            }
            let ordinal = if raw.len() <= self.max_record_bytes {
                serde_json::from_slice::<serde_json::Value>(raw)
                    .ok()
                    .and_then(|value| value.get("ordinal").and_then(|value| value.as_u64()))
            } else {
                None
            };
            return Some(RecordBoundary { ordinal, end });
        }
        None
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct BoundarySummary {
    last_ordinal: Option<u64>,
    invalid_record: bool,
}

fn boundary_summary(bytes: &[u8], max_record_bytes: usize) -> BoundarySummary {
    let mut summary = BoundarySummary::default();
    for boundary in RecordBoundaryIter::new(bytes, max_record_bytes) {
        match boundary.ordinal {
            Some(ordinal) => summary.last_ordinal = Some(ordinal),
            None => summary.invalid_record = true,
        }
    }
    summary
}

fn boundary_at(
    bytes: &[u8],
    offset: usize,
    max_record_bytes: usize,
) -> Option<(RecordBoundary, Option<RecordBoundary>)> {
    if offset >= bytes.len() || (offset > 0 && bytes[offset - 1] != b'\n') {
        return None;
    }
    let mut current_start = 0usize;
    let mut boundaries = RecordBoundaryIter::new(bytes, max_record_bytes);
    while let Some(boundary) = boundaries.next() {
        if boundary.end <= offset {
            current_start = boundary.end;
            continue;
        }
        if current_start != offset {
            return None;
        }
        return Some((boundary, boundaries.next()));
    }
    None
}

fn inspect_projection(
    root: &Path,
    bytes: Option<&[u8]>,
    session_id: Option<&str>,
    max_files: usize,
    max_record_bytes: usize,
    max_database_bytes: u64,
) -> ProjectionResult {
    let mut result = ProjectionResult::default();
    let Some(session_id) = session_id else {
        result
            .notices
            .push("projection inspection requires a stable session identity".to_string());
        return result;
    };
    let candidate_set = database_candidates(root, max_files, max_database_bytes);
    let candidates = candidate_set.paths;
    let mut states = Vec::new();
    let mut relevant_error = candidate_set.rejected;
    for db_path in candidates {
        let Ok(connection) = safe_fs::open_sqlite_read_only_bounded(
            root,
            &db_path,
            max_database_bytes,
            "SQLite database",
        )
        else {
            relevant_error = true;
            continue;
        };
        let Ok(tables) = table_names(&connection) else {
            relevant_error = true;
            continue;
        };
        let mut projection_tables = tables
            .into_iter()
            .filter(|table| {
                table == PROJECTION_TABLE || table.to_ascii_lowercase().contains("projection")
            })
            .collect::<Vec<_>>();
        projection_tables.sort_by_key(|table| if table == PROJECTION_TABLE { 0 } else { 1 });
        for table in projection_tables {
            let Ok(columns) = table_columns(&connection, &table) else {
                relevant_error = true;
                continue;
            };
            let Some(id_column) = first_column(&columns, &["thread_id", "session_id"]) else {
                continue;
            };
            let Some(offset_column) = first_column(
                &columns,
                &[
                    "next_rollout_byte_offset",
                    "next_byte_offset",
                    "rollout_byte_offset",
                ],
            ) else {
                continue;
            };
            let Some(ordinal_column) =
                first_column(&columns, &["next_rollout_ordinal", "next_ordinal"])
            else {
                continue;
            };
            let sql = format!(
                "SELECT {}, {} FROM {} WHERE {} = ? LIMIT 2",
                quote_identifier(&offset_column),
                quote_identifier(&ordinal_column),
                quote_identifier(&table),
                quote_identifier(&id_column)
            );
            let mut statement = match connection.prepare(&sql) {
                Ok(statement) => statement,
                Err(_) => {
                    relevant_error = true;
                    continue;
                }
            };
            let mut rows = match statement.query([session_id]) {
                Ok(rows) => rows,
                Err(_) => {
                    relevant_error = true;
                    continue;
                }
            };
            loop {
                let row = match rows.next() {
                    Ok(Some(row)) => row,
                    Ok(None) => break,
                    Err(_) => {
                        relevant_error = true;
                        break;
                    }
                };
                let offset = match row.get_ref(0) {
                    Ok(value) => value_i64(value),
                    Err(_) => {
                        relevant_error = true;
                        break;
                    }
                };
                let ordinal = match row.get_ref(1) {
                    Ok(value) => value_i64(value),
                    Err(_) => {
                        relevant_error = true;
                        break;
                    }
                };
                let (Some(offset), Some(ordinal)) = (offset, ordinal) else {
                    relevant_error = true;
                    break;
                };
                if offset < 0 || ordinal < 0 {
                    relevant_error = true;
                    break;
                }
                states.push((offset as u64, ordinal as u64));
            }
        }
    }
    if relevant_error {
        result.evidence.status = "unknown".to_string();
        result.evidence.confidence = "unknown".to_string();
        result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
        result
            .notices
            .push("projection database/schema could not be read safely".to_string());
        return result;
    }
    if states.is_empty() {
        result
            .notices
            .push("no readable projection row was found for this session".to_string());
        return result;
    }
    if states.windows(2).any(|window| window[0] != window[1]) {
        result.evidence.status = "unknown".to_string();
        result.evidence.confidence = "unknown".to_string();
        result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
        result
            .notices
            .push("readable projection stores disagree on the cursor".to_string());
        return result;
    }
    let (next_offset, next_ordinal) = states[0];
    result.evidence.next_rollout_byte_offset = Some(next_offset);
    result.evidence.next_rollout_ordinal = Some(next_ordinal);
    let Some(bytes) = bytes else {
        result.evidence.status = "unknown".to_string();
        result.evidence.confidence = "unknown".to_string();
        result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
        result
            .notices
            .push("projection row exists but rollout bytes were not supplied".to_string());
        return result;
    };
    result.evidence.canonical_size = Some(bytes.len() as u64);
    let summary = boundary_summary(bytes, max_record_bytes);
    if summary.invalid_record {
        result.evidence.status = "unknown".to_string();
        result.evidence.confidence = "unknown".to_string();
        result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
        result.notices.push(
            "rollout contains a malformed or ordinal-less record; projection parity is unknown"
                .to_string(),
        );
        return result;
    }
    if next_offset > bytes.len() as u64 {
        result.evidence.status = "unknown".to_string();
        result.evidence.confidence = "unknown".to_string();
        result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
        result
            .notices
            .push("projection byte cursor is beyond the rollout".to_string());
        return result;
    }
    let final_ordinal = summary.last_ordinal;
    if next_offset == bytes.len() as u64 {
        if let Some(final_ordinal) = final_ordinal {
            if next_ordinal == final_ordinal.saturating_add(1) {
                result.evidence.status = "exact".to_string();
                result.evidence.confidence = "strong".to_string();
                result.notices.push(
                    "projection byte and ordinal cursors match the exact rollout EOF".to_string(),
                );
            } else {
                result.evidence.status = "unknown".to_string();
                result.evidence.confidence = "unknown".to_string();
                result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
                result.notices.push(format!("projection is at EOF but next ordinal {next_ordinal} does not equal final ordinal plus one ({})", final_ordinal.saturating_add(1)));
            }
        } else {
            result.evidence.status = "unknown".to_string();
            result.evidence.confidence = "unknown".to_string();
            result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
            result
                .notices
                .push("rollout EOF has no usable paginated ordinal".to_string());
        }
        return result;
    }
    let Some((boundary, next_boundary)) =
        boundary_at(bytes, next_offset as usize, max_record_bytes)
    else {
        result.evidence.status = "unknown".to_string();
        result.evidence.confidence = "unknown".to_string();
        result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
        result
            .notices
            .push("projection byte cursor is not aligned to a rollout record boundary".to_string());
        return result;
    };
    result.evidence.boundary_ordinal = boundary.ordinal;
    result.evidence.next_boundary_ordinal = next_boundary.and_then(|boundary| boundary.ordinal);
    let Some(first_ordinal) = boundary.ordinal else {
        result.evidence.status = "unknown".to_string();
        result.evidence.confidence = "unknown".to_string();
        result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
        result
            .notices
            .push("rollout suffix at the projection cursor has no usable ordinal".to_string());
        return result;
    };
    let replayed = next_ordinal > 0
        && first_ordinal == next_ordinal - 1
        && next_boundary.and_then(|boundary| boundary.ordinal) == Some(next_ordinal);
    if first_ordinal == next_ordinal || replayed {
        result.evidence.status = "wedged".to_string();
        result.evidence.confidence = "strong".to_string();
        result.findings.push(WEDGED_PROJECTION.to_string());
        if replayed {
            result.notices.push(format!("stable projection boundary replays ordinal {first_ordinal} before expected ordinal {next_ordinal}"));
        } else {
            result.notices.push(format!(
                "stable rollout suffix begins at persisted next ordinal {next_ordinal}"
            ));
        }
    } else {
        result.evidence.status = "unknown".to_string();
        result.evidence.confidence = "unknown".to_string();
        result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
        result.notices.push(format!("projection ordinal {next_ordinal} disagrees with rollout boundary ordinal {first_ordinal}"));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue::types::DEFAULT_MAX_RECORD_BYTES;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vetto-inventory-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp root");
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn rollout(root: &Path, id: &str) -> (PathBuf, Vec<u8>) {
        let path = root.join("sessions").join(format!("rollout-{id}.jsonl"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = format!(
            "{{\"type\":\"session_meta\",\"ordinal\":0,\"payload\":{{\"id\":\"{id}\"}}}}\n{{\"type\":\"event_msg\",\"ordinal\":1}}\n"
        )
        .into_bytes();
        fs::write(&path, &bytes).unwrap();
        (path, bytes)
    }

    #[cfg(windows)]
    fn create_threads_db(root: &Path, id: &str, stored_path: &str) -> PathBuf {
        let path = root.join("state_5.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT)",
                [],
            )
            .unwrap();
        connection
            .execute("INSERT INTO threads VALUES (?1, ?2)", (id, stored_path))
            .unwrap();
        drop(connection);
        path
    }

    fn create_empty_sidebar_db(root: &Path, id: &str, stored_path: &str) -> PathBuf {
        let path = root.join("state_5.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, preview TEXT, first_user_message TEXT)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO threads VALUES (?1, ?2, '', '')",
                (id, stored_path),
            )
            .unwrap();
        drop(connection);
        path
    }

    fn create_threads_db_without_id(root: &Path, stored_path: &str) -> PathBuf {
        let path = root.join("state_5.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute("CREATE TABLE threads (rollout_path TEXT)", [])
            .unwrap();
        connection
            .execute("INSERT INTO threads VALUES (?1)", [stored_path])
            .unwrap();
        drop(connection);
        path
    }

    fn create_projection_db(root: &Path, id: &str, offset: u64, ordinal: u64) -> PathBuf {
        let path = root.join("thread_history_1.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection.execute(
            "CREATE TABLE thread_history_projection_state (thread_id TEXT PRIMARY KEY, next_rollout_byte_offset INTEGER, next_rollout_ordinal INTEGER)",
            [],
        ).unwrap();
        connection
            .execute(
                "INSERT INTO thread_history_projection_state VALUES (?1, ?2, ?3)",
                (id, offset, ordinal),
            )
            .unwrap();
        drop(connection);
        path
    }

    fn sha(path: &Path) -> String {
        let mut hasher = Sha256::new();
        hasher.update(fs::read(path).unwrap());
        format!("{:x}", hasher.finalize())
    }

    #[cfg(windows)]
    #[test]
    fn windows_namespace_difference_is_index_divergence_without_path_leak() {
        let temp = TempRoot::new("windows");
        let id = "019fffff-1111-7111-8111-111111111111";
        let (path, bytes) = rollout(&temp.0, id);
        let canonical = fs::canonicalize(&path).unwrap();
        let normal = discovered_logical_path(&canonical.to_string_lossy()).replace('/', "\\");
        let extended = format!("\\\\?\\{normal}");
        create_threads_db(&temp.0, id, &extended);
        let report = inspect_session(
            &RescueContext::new(temp.0.clone()),
            Some(&path),
            Some(&bytes),
            None,
        )
        .unwrap();
        assert!(report
            .findings
            .contains(&WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE.to_string()));
        assert!(report.thread_store.windows_namespace_divergence);
        assert!(report
            .notices
            .iter()
            .all(|notice| !notice.contains(&normal)));
        assert!(report
            .notices
            .iter()
            .all(|notice| !notice.contains(&extended)));
    }

    #[test]
    fn windows_namespace_relation_is_detected_lexically() {
        assert_eq!(
            path_relation(
                r"\\?\C:\Users\Alice\.codex\sessions\rollout.jsonl",
                Path::new(r"C:\Users\Alice\.codex\sessions\rollout.jsonl"),
            ),
            PathRelation::Equivalent {
                namespace_divergence: true,
            }
        );
    }

    #[test]
    fn empty_sidebar_metadata_is_reported_without_exposing_content() {
        let temp = TempRoot::new("sidebar-empty");
        let id = "019fffff-1212-7121-8121-121212121212";
        let (path, bytes) = rollout(&temp.0, id);
        create_empty_sidebar_db(&temp.0, id, &path.to_string_lossy());
        let report = inspect_session(
            &RescueContext::new(temp.0.clone()),
            Some(&path),
            Some(&bytes),
            None,
        )
        .unwrap();
        assert!(report
            .findings
            .contains(&SIDEBAR_METADATA_EMPTY.to_string()));
        assert!(report.notices.iter().all(|notice| !notice.contains(id)));
    }

    #[test]
    fn external_sqlite_path_is_not_probed() {
        let temp = TempRoot::new("external-path");
        let root = fs::canonicalize(&temp.0).unwrap();
        let external = if cfg!(windows) {
            r"\\127.0.0.1\vetto\outside.jsonl"
        } else {
            "/etc/passwd"
        };
        assert_eq!(stored_path_exists_within_root(&root, external), None);
    }

    #[test]
    fn schema_without_id_is_unknown_when_session_id_is_present() {
        let temp = TempRoot::new("schema-without-id");
        let id = "019fffff-5555-7555-8555-555555555555";
        let (path, bytes) = rollout(&temp.0, id);
        create_threads_db_without_id(&temp.0, &path.to_string_lossy());
        let report = inspect_session(
            &RescueContext::new(temp.0.clone()),
            Some(&path),
            Some(&bytes),
            None,
        )
        .unwrap();
        assert_eq!(report.thread_store.status, "unknown");
        assert!(!report.findings.contains(&INDEX_DIVERGENCE.to_string()));
    }

    #[test]
    fn malformed_projection_tail_is_unknown_at_eof() {
        let temp = TempRoot::new("malformed-tail");
        let id = "019fffff-6666-7666-8666-666666666666";
        let (path, _) = rollout(&temp.0, id);
        let bytes = format!(
            "{{\"type\":\"session_meta\",\"ordinal\":0,\"payload\":{{\"id\":\"{id}\"}}}}\nnot-json\n"
        )
        .into_bytes();
        fs::write(&path, &bytes).unwrap();
        create_projection_db(&temp.0, id, bytes.len() as u64, 1);
        let report = inspect_session(
            &RescueContext::new(temp.0.clone()),
            Some(&path),
            Some(&bytes),
            None,
        )
        .unwrap();
        assert_eq!(report.projection.status, "unknown");
        assert!(report
            .findings
            .contains(&PROJECTION_STATE_UNKNOWN.to_string()));
    }

    #[test]
    fn boundary_summary_is_stream_like_for_many_short_records() {
        let mut bytes = Vec::with_capacity(100_000 * 3);
        for _ in 0..100_000 {
            bytes.extend_from_slice(b"{}\n");
        }
        let summary = boundary_summary(&bytes, DEFAULT_MAX_RECORD_BYTES);
        assert!(summary.invalid_record);
        assert_eq!(summary.last_ordinal, None);
    }

    #[test]
    fn oversized_sqlite_is_unknown_not_index_divergence() {
        let temp = TempRoot::new("oversized-db");
        let id = "019fffff-7777-7777-8777-777777777777";
        let (path, bytes) = rollout(&temp.0, id);
        create_empty_sidebar_db(&temp.0, id, &path.to_string_lossy());
        let context = RescueContext {
            max_total_bytes: 1,
            ..RescueContext::new(temp.0.clone())
        };
        let report = inspect_session(&context, Some(&path), Some(&bytes), None).unwrap();
        assert_eq!(report.status, InventoryStatus::Unknown);
        assert!(!report.findings.contains(&INDEX_DIVERGENCE.to_string()));
        assert!(report
            .findings
            .contains(&PROJECTION_STATE_UNKNOWN.to_string()));
    }

    #[test]
    fn malformed_sqlite_is_unknown_not_index_divergence() {
        let temp = TempRoot::new("malformed-db");
        let id = "019fffff-8888-7888-8888-888888888888";
        let (path, bytes) = rollout(&temp.0, id);
        fs::write(temp.0.join("state_5.sqlite"), b"not a sqlite database").unwrap();
        let report = inspect_session(
            &RescueContext::new(temp.0.clone()),
            Some(&path),
            Some(&bytes),
            None,
        )
        .unwrap();
        assert_eq!(report.thread_store.status, "unknown");
        assert!(!report.findings.contains(&INDEX_DIVERGENCE.to_string()));
    }

    #[test]
    fn wal_or_shm_presence_is_unknown_not_a_false_inventory_finding() {
        let temp = TempRoot::new("wal-uncertain");
        let id = "019fffff-9999-7999-8999-999999999999";
        let (path, bytes) = rollout(&temp.0, id);
        create_empty_sidebar_db(&temp.0, id, &path.to_string_lossy());
        let wal = PathBuf::from(format!("{}-wal", temp.0.join("state_5.sqlite").display()));
        fs::write(wal, b"unproven wal bytes").unwrap();

        let report = inspect_session(
            &RescueContext::new(temp.0.clone()),
            Some(&path),
            Some(&bytes),
            None,
        )
        .unwrap();
        assert_eq!(report.status, InventoryStatus::Unknown);
        assert_eq!(report.thread_store.status, "unknown");
        assert!(!report.findings.contains(&INDEX_DIVERGENCE.to_string()));
        assert!(report
            .findings
            .contains(&PROJECTION_STATE_UNKNOWN.to_string()));
    }

    #[test]
    fn sqlite_candidate_enumeration_is_bounded() {
        let temp = TempRoot::new("candidate-bound");
        for index in 0..(MAX_SQLITE_CANDIDATES + 8) {
            fs::write(temp.0.join(format!("candidate-{index}.sqlite")), b"").unwrap();
        }
        let candidates = database_candidates(&temp.0, 10_000, MAX_SQLITE_BYTES);
        assert!(candidates.paths.is_empty());
        assert!(candidates.rejected);
    }

    #[test]
    fn cumulative_sqlite_size_is_preflighted_before_open() {
        let temp = TempRoot::new("candidate-total-size");
        fs::write(temp.0.join("a.sqlite"), [0u8; 16]).unwrap();
        fs::write(temp.0.join("b.sqlite"), [0u8; 16]).unwrap();
        let candidates = database_candidates(&temp.0, 10_000, 24);
        assert!(candidates.paths.is_empty());
        assert!(candidates.rejected);
    }

    #[test]
    fn one_file_budget_selects_existing_non_default_database() {
        let temp = TempRoot::new("candidate-single-budget");
        let path = temp.0.join("a.sqlite");
        fs::write(&path, b"sqlite-placeholder").unwrap();
        let canonical_root = fs::canonicalize(&temp.0).unwrap();
        let candidates = database_candidates(&canonical_root, 1, MAX_SQLITE_BYTES);
        assert!(!candidates.rejected);
        assert_eq!(candidates.paths, vec![fs::canonicalize(path).unwrap()]);
    }

    #[test]
    fn filename_identity_uses_the_complete_uuid_suffix() {
        let path = Path::new(
            "sessions/2026/08/19/rollout-2026-08-19T00-00-00-019fffff-1111-7111-8111-111111111111.jsonl",
        );
        assert_eq!(
            session_id_from_path(path).as_deref(),
            Some("019fffff-1111-7111-8111-111111111111")
        );
    }

    #[test]
    fn unrelated_record_id_is_not_used_as_session_identity() {
        let bytes = b"{\"type\":\"response_item\",\"payload\":{\"type\":\"reasoning\",\"id\":\"rs_not_a_session\"}}\n";
        assert_eq!(parse_session_id(bytes), None);
    }

    #[test]
    fn session_identity_is_bounded_and_rejects_control_bytes() {
        let oversized = "x".repeat(MAX_SESSION_ID_BYTES + 1);
        assert_eq!(validate_session_id(&oversized), None);
        assert_eq!(validate_session_id("session\n1"), None);
        let bytes =
            format!("{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{oversized}\"}}}}\n")
                .into_bytes();
        assert_eq!(parse_session_id(&bytes), None);
    }

    #[test]
    fn exact_projection_eof_is_healthy_and_db_hash_is_unchanged() {
        let temp = TempRoot::new("exact");
        let id = "019fffff-2222-7222-8222-222222222222";
        let (path, bytes) = rollout(&temp.0, id);
        let db_path = create_projection_db(&temp.0, id, bytes.len() as u64, 2);
        let before = sha(&db_path);
        let report = inspect_session(
            &RescueContext::new(temp.0.clone()),
            Some(&path),
            Some(&bytes),
            None,
        )
        .unwrap();
        let after = sha(&db_path);
        assert_eq!(before, after);
        assert_eq!(report.projection.status, "exact");
        assert!(!report.findings.contains(&WEDGED_PROJECTION.to_string()));
    }

    #[test]
    fn projection_cursor_at_expected_boundary_is_wedged() {
        let temp = TempRoot::new("wedged");
        let id = "019fffff-3333-7333-8333-333333333333";
        let (path, bytes) = rollout(&temp.0, id);
        let first_end = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        create_projection_db(&temp.0, id, first_end as u64, 1);
        let report = inspect_session(
            &RescueContext::new(temp.0.clone()),
            Some(&path),
            Some(&bytes),
            None,
        )
        .unwrap();
        assert_eq!(report.projection.status, "wedged");
        assert!(report.findings.contains(&WEDGED_PROJECTION.to_string()));
        assert_eq!(report.projection.boundary_ordinal, Some(1));
    }

    #[test]
    fn malformed_cursor_is_unknown_not_wedged() {
        let temp = TempRoot::new("unknown");
        let id = "019fffff-4444-7444-8444-444444444444";
        let (path, bytes) = rollout(&temp.0, id);
        create_projection_db(&temp.0, id, 1, 1);
        let report = inspect_session(
            &RescueContext::new(temp.0.clone()),
            Some(&path),
            Some(&bytes),
            None,
        )
        .unwrap();
        assert_eq!(report.projection.status, "unknown");
        assert!(report
            .findings
            .contains(&PROJECTION_STATE_UNKNOWN.to_string()));
        assert!(!report.findings.contains(&WEDGED_PROJECTION.to_string()));
    }
}
