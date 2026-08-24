//! Read-only Codex SQLite inventory and projection diagnostics.
//!
//! This module deliberately does not share the legacy mutating planner.  It
//! treats the JSONL rollout as the source of truth and SQLite as derived
//! metadata.  Databases are opened with SQLite's read-only/no-create flag and
//! every diagnostic is bounded by the caller's [`RescueContext`].  The public
//! report contains only classifications and numeric cursor evidence; provider
//! paths read from SQLite are never serialized or included in errors.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde::Serialize;

use super::types::RescueContext;

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
            .map(|path| read_stable_session(&root, path, context.max_session_bytes))
            .transpose()?,
    };

    let canonical_session_path = requested_path
        .map(|path| validate_session_path(&root, path))
        .transpose()?;
    let session_id = metadata
        .session_id
        .clone()
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
    );
    report.projection = projection_result.evidence;
    extend_unique(&mut report.findings, projection_result.findings);
    extend_unique(&mut report.notices, projection_result.notices);

    report.status = if !report.findings.is_empty() {
        InventoryStatus::Findings
    } else if report.projection.status == "unknown" || report.thread_store.status == "unknown" {
        InventoryStatus::Unknown
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
    let metadata =
        fs::symlink_metadata(root).map_err(|_| anyhow::anyhow!("rescue root is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("rescue root must be a real directory");
    }
    fs::canonicalize(root).map_err(|_| anyhow::anyhow!("rescue root cannot be canonicalized"))
}

fn validate_session_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| anyhow::anyhow!("session evidence is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("session evidence must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            bail!("session hardlinks are not accepted");
        }
    }
    let canonical = fs::canonicalize(path)
        .map_err(|_| anyhow::anyhow!("session evidence cannot be canonicalized"))?;
    if !canonical.starts_with(root) {
        bail!("session evidence is outside the configured rescue root");
    }
    Ok(canonical)
}

fn read_stable_session(root: &Path, path: &Path, limit: u64) -> Result<Vec<u8>> {
    let canonical = validate_session_path(root, path)?;
    let first = read_bounded(&canonical, limit)?;
    let second = read_bounded(&canonical, limit)?;
    if first != second {
        bail!("session changed while being read; retry after the writer stops");
    }
    Ok(first)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).map_err(|_| anyhow::anyhow!("session evidence cannot be opened"))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("session evidence cannot be read"))?;
    if bytes.len() as u64 > limit {
        bail!("session evidence exceeds the inspection budget");
    }
    Ok(bytes)
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

fn value_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
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

fn database_candidates(root: &Path, max_files: usize) -> Vec<PathBuf> {
    let limit = max_files.clamp(1, MAX_SQLITE_CANDIDATES);
    let mut names = vec![
        "state_5.sqlite".to_string(),
        "state.sqlite".to_string(),
        "state.db".to_string(),
    ];
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let lower = name.to_ascii_lowercase();
            if (lower.ends_with(".sqlite") || lower.ends_with(".sqlite3") || lower.ends_with(".db"))
                && !names.iter().any(|known| known == name)
            {
                names.push(name.to_string());
            }
        }
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
    names
        .into_iter()
        .take(limit)
        .filter_map(|name| {
            let path = root.join(name);
            let metadata = fs::symlink_metadata(&path).ok()?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return None;
                }
            }
            fs::canonicalize(path).ok()
        })
        .collect()
}

fn open_read_only(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| anyhow::anyhow!("SQLite database could not be opened read-only"))?;
    connection
        .execute_batch("PRAGMA query_only=ON; PRAGMA busy_timeout=250;")
        .map_err(|_| anyhow::anyhow!("SQLite database could not be configured read-only"))?;
    Ok(connection)
}

fn table_names(connection: &Connection) -> Result<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .map_err(|_| anyhow::anyhow!("SQLite schema could not be read"))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| anyhow::anyhow!("SQLite schema could not be read"))?;
    let mut names = Vec::new();
    for row in rows.take(MAX_SQLITE_ROWS) {
        names.push(row.map_err(|_| anyhow::anyhow!("SQLite schema could not be read"))?);
    }
    Ok(names)
}

fn table_columns(connection: &Connection, table: &str) -> Result<HashSet<String>> {
    let sql = format!("PRAGMA table_info({})", quote_identifier(table));
    let mut statement = connection
        .prepare(&sql)
        .map_err(|_| anyhow::anyhow!("SQLite table schema could not be read"))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| anyhow::anyhow!("SQLite table schema could not be read"))?;
    let mut columns = HashSet::new();
    for row in rows {
        columns.insert(row.map_err(|_| anyhow::anyhow!("SQLite table schema could not be read"))?);
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
        ValueRef::Text(value) => std::str::from_utf8(value).ok().map(ToOwned::to_owned),
        ValueRef::Integer(value) => Some(value.to_string()),
        ValueRef::Real(value) => Some(value.to_string()),
        ValueRef::Null | ValueRef::Blob(_) => None,
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

fn stored_path_exists(stored: &str) -> Option<bool> {
    if cfg!(not(windows)) && looks_windows_path(stored) {
        return None;
    }
    let metadata = fs::symlink_metadata(stored).ok()?;
    Some(metadata.is_file() && !metadata.file_type().is_symlink())
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
) -> ThreadStoreResult {
    let mut result = ThreadStoreResult::default();
    let candidates = database_candidates(root, max_files);
    if candidates.is_empty() {
        result
            .notices
            .push("no compatible Codex SQLite store was found".to_string());
        return result;
    }
    let mut compatible_store = false;
    let mut read_error = false;
    for db_path in candidates {
        let Ok(connection) = open_read_only(&db_path) else {
            if db_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.to_ascii_lowercase().contains("state"))
            {
                read_error = true;
            }
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
        while let Ok(Some(row)) = rows.next() {
            let stored = value_text(row.get_ref(1).unwrap_or(ValueRef::Null));
            let preview = value_text(row.get_ref(2).unwrap_or(ValueRef::Null));
            let first_user = value_text(row.get_ref(3).unwrap_or(ValueRef::Null));
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
                            result.findings.push(
                                WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE.to_string(),
                            );
                            result.notices.push("thread index and rollout use different Windows path namespaces".to_string());
                            }
                        }
                        PathRelation::Different => {
                            result.evidence.status = "diverged".to_string();
                            result.evidence.path_relation = "different".to_string();
                            match stored_path_exists(&stored) {
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
    if !matched_or_row(&result.evidence) {
        if compatible_store && session_path.is_some() {
            result.evidence.status = "diverged".to_string();
            result.evidence.path_relation = "not_indexed".to_string();
            result.evidence.row_present = Some(false);
            result.findings.push(INDEX_DIVERGENCE.to_string());
            result.notices.push(
                "rollout exists on disk but no matching thread index row was found".to_string(),
            );
        } else if read_error {
            result.evidence.status = "unknown".to_string();
            result
                .notices
                .push("a state SQLite store could not be inspected read-only".to_string());
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

fn record_boundaries(bytes: &[u8], max_record_bytes: usize) -> Vec<RecordBoundary> {
    let mut result = Vec::new();
    let mut start = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        let end = index + 1;
        let raw = &bytes[start..index];
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        let ordinal = if raw.len() <= max_record_bytes {
            serde_json::from_slice::<serde_json::Value>(raw)
                .ok()
                .and_then(|value| value.get("ordinal").and_then(|value| value.as_u64()))
        } else {
            None
        };
        if !raw.iter().all(|byte| byte.is_ascii_whitespace()) {
            result.push(RecordBoundary { ordinal, end });
        }
        start = end;
    }
    if start < bytes.len() {
        let raw = &bytes[start..];
        let ordinal = if raw.len() <= max_record_bytes {
            serde_json::from_slice::<serde_json::Value>(raw)
                .ok()
                .and_then(|value| value.get("ordinal").and_then(|value| value.as_u64()))
        } else {
            None
        };
        if !raw.iter().all(|byte| byte.is_ascii_whitespace()) {
            result.push(RecordBoundary {
                ordinal,
                end: bytes.len(),
            });
        }
    }
    result
}

fn boundary_at(
    bytes: &[u8],
    offset: usize,
    max_record_bytes: usize,
) -> Option<(RecordBoundary, Option<RecordBoundary>)> {
    if offset >= bytes.len() || (offset > 0 && bytes[offset - 1] != b'\n') {
        return None;
    }
    let boundaries = record_boundaries(bytes, max_record_bytes);
    let index = boundaries
        .iter()
        .position(|boundary| boundary.end > offset && boundary.end - offset > 0)?;
    let current_start = boundaries
        .get(index.wrapping_sub(1))
        .map(|boundary| boundary.end)
        .unwrap_or(0);
    if current_start != offset {
        return None;
    }
    Some((boundaries[index], boundaries.get(index + 1).copied()))
}

fn last_ordinal(bytes: &[u8], max_record_bytes: usize) -> Option<u64> {
    record_boundaries(bytes, max_record_bytes)
        .into_iter()
        .rev()
        .find_map(|boundary| boundary.ordinal)
}

fn inspect_projection(
    root: &Path,
    bytes: Option<&[u8]>,
    session_id: Option<&str>,
    max_files: usize,
    max_record_bytes: usize,
) -> ProjectionResult {
    let mut result = ProjectionResult::default();
    let Some(session_id) = session_id else {
        result
            .notices
            .push("projection inspection requires a stable session identity".to_string());
        return result;
    };
    let candidates = database_candidates(root, max_files);
    let mut states = Vec::new();
    let mut relevant_error = false;
    for db_path in candidates {
        let Ok(connection) = open_read_only(&db_path) else {
            if db_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.to_ascii_lowercase().contains("thread"))
            {
                relevant_error = true;
            }
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
            while let Ok(Some(row)) = rows.next() {
                let offset = value_i64(row.get_ref(0).unwrap_or(ValueRef::Null));
                let ordinal = value_i64(row.get_ref(1).unwrap_or(ValueRef::Null));
                let (Some(offset), Some(ordinal)) = (offset, ordinal) else {
                    relevant_error = true;
                    continue;
                };
                if offset < 0 || ordinal < 0 {
                    relevant_error = true;
                    continue;
                }
                states.push((offset as u64, ordinal as u64));
            }
        }
    }
    if states.is_empty() {
        if relevant_error {
            result.evidence.status = "unknown".to_string();
            result.evidence.confidence = "unknown".to_string();
            result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
            result
                .notices
                .push("projection database/schema could not be read safely".to_string());
        } else {
            result
                .notices
                .push("no readable projection row was found for this session".to_string());
        }
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
    if next_offset > bytes.len() as u64 {
        result.evidence.status = "unknown".to_string();
        result.evidence.confidence = "unknown".to_string();
        result.findings.push(PROJECTION_STATE_UNKNOWN.to_string());
        result
            .notices
            .push("projection byte cursor is beyond the rollout".to_string());
        return result;
    }
    let final_ordinal = last_ordinal(bytes, max_record_bytes);
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
