//! Read-only, index-first discovery for Codex rollout files.
//!
//! The normal filesystem walk is intentionally kept as an explicit escape
//! hatch (`vetto rescue scan --all`).  Large Codex homes can contain many
//! thousands of rollout files, while the provider's SQLite state store (or a
//! small `session_index.jsonl` file supplied by a future provider version)
//! already identifies the sessions a user is likely trying to recover.  This
//! module consumes those indexes without opening them for writing, verifies
//! every path before returning it, and fails closed when the index cannot be
//! trusted.  It never falls back to a partial directory walk.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rusqlite::{types::ValueRef, Connection};
use serde_json::Value;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use super::{
    safe_fs,
    types::{RescueContext, SessionRef},
};

const MAX_INDEX_ROWS: usize = 100_000;
const MAX_SQLITE_CELL_BYTES: usize = 64 * 1024;
const MAX_SQLITE_DATABASES: usize = 64;
const SQLITE_NAMES: [&str; 3] = ["state_5.sqlite", "state.sqlite", "state.db"];
const SESSION_INDEX_NAME: &str = "session_index.jsonl";
const PATH_COLUMNS: [&str; 3] = ["rollout_path", "session_path", "path"];

/// Result of a verified index-first discovery pass.
#[derive(Debug)]
pub struct IndexDiscovery {
    pub sessions: Vec<SessionRef>,
    /// Number of unique index records verified before applying `--limit`.
    pub candidate_count: usize,
    pub truncated: bool,
    /// Stable source label; this intentionally contains no user paths.
    pub source: String,
}

#[derive(Debug, Clone)]
struct IndexPath {
    raw: String,
}

/// Discover sessions from provider indexes, with an optional caller limit.
///
/// A missing or unreadable index is an error.  In particular, this function
/// does not silently switch to the recursive filesystem walker: a successful
/// limited scan must mean that the requested result came from a verified
/// index.  The caller can request the bounded filesystem walk explicitly with
/// `--all`.
pub fn discover(context: &RescueContext, limit: usize) -> Result<IndexDiscovery> {
    if limit == 0 {
        bail!("rescue scan --limit must be greater than zero");
    }

    let configured_root = context.root.clone();
    let root = canonical_root(&configured_root)?;
    let max_index_rows = context.max_files.min(MAX_INDEX_ROWS);
    if max_index_rows == 0 {
        bail!("limited rescue scan requires a positive max_files budget");
    }
    let mut paths = Vec::new();
    let mut sources = Vec::new();

    if let Some(index_paths) = read_session_index(&root, context, max_index_rows)? {
        sources.push("session-index");
        paths.extend(index_paths);
    }

    if let Some(sqlite_paths) = read_sqlite_indexes(context, &root, max_index_rows)? {
        sources.push("sqlite");
        paths.extend(sqlite_paths);
    }

    if sources.is_empty() {
        bail!(
            "limited rescue scan requires a readable Codex index (state SQLite or session_index.jsonl); use `vetto rescue scan --all` for an explicit filesystem walk"
        );
    }
    if paths.is_empty() {
        bail!(
            "Codex index was found but contained no rollout paths; refusing to return a misleading empty limited scan"
        );
    }
    if paths.len() > max_index_rows {
        bail!(
            "Codex index exceeded the configured {} entry budget",
            context.max_files
        );
    }

    let roots = session_roots(&root)?;
    let mut seen = HashSet::new();
    let mut sessions = Vec::with_capacity(paths.len());
    for index_path in paths {
        let session = verify_index_path(context, &configured_root, &root, &roots, &index_path.raw)?;
        if seen.insert(session.source_path.clone()) {
            sessions.push(session);
        }
    }

    sessions.sort_by(|left, right| {
        right
            .modified_unix_secs
            .cmp(&left.modified_unix_secs)
            .then_with(|| left.key.cmp(&right.key))
    });
    let candidate_count = sessions.len();
    let truncated = candidate_count > limit;
    let total_bytes = sessions.iter().try_fold(0u64, |total, session| {
        total
            .checked_add(session.bytes)
            .context("indexed session byte counter overflow")
    })?;
    if total_bytes > context.max_total_bytes {
        bail!(
            "limited rescue scan exceeded the {} byte budget",
            context.max_total_bytes
        );
    }
    sessions.truncate(limit);

    Ok(IndexDiscovery {
        sessions,
        candidate_count,
        truncated,
        source: sources.join("+"),
    })
}

fn canonical_root(root: &Path) -> Result<PathBuf> {
    safe_fs::canonical_root(root)
        .with_context(|| "Codex rescue root is unavailable; pass --root to a real Codex home")
}

fn session_roots(root: &Path) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    for name in ["sessions", "archived_sessions"] {
        let path = root.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect Codex session root"),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let canonical = fs::canonicalize(path).context("canonicalize Codex session root")?;
        if canonical.starts_with(root) {
            roots.push(canonical);
        }
    }
    if roots.is_empty() {
        bail!("Codex index is present but no real sessions directory exists");
    }
    Ok(roots)
}

fn verify_index_path(
    context: &RescueContext,
    configured_root: &Path,
    canonical_root: &Path,
    roots: &[PathBuf],
    raw: &str,
) -> Result<SessionRef> {
    if raw.is_empty() || raw.contains('\0') {
        bail!("Codex index contains an invalid rollout path");
    }
    let candidate = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        configured_root.join(raw)
    };
    let verified = safe_fs::open_regular(configured_root, &candidate, "indexed rollout")
        .context("Codex index references an unavailable rollout")?;
    let canonical = verified.path().to_path_buf();
    if canonical.extension().and_then(|value| value.to_str()) != Some("jsonl") {
        bail!("Codex index references a non-JSONL rollout file");
    }
    if !roots
        .iter()
        .any(|session_root| canonical.starts_with(session_root))
    {
        bail!("Codex index references a rollout outside the session roots");
    }
    let canonical_metadata = verified.metadata().context("stat indexed rollout")?;
    if canonical_metadata.len() > context.max_session_bytes {
        bail!(
            "Codex index references a rollout over the {} byte inspection budget",
            context.max_session_bytes
        );
    }
    verified.ensure_unchanged("indexed rollout")?;
    let relative = canonical
        .strip_prefix(canonical_root)
        .context("indexed rollout is outside the Codex root")?
        .to_string_lossy()
        .replace('\\', "/");
    let modified_unix_secs = canonical_metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs());
    Ok(SessionRef {
        adapter: "codex".to_string(),
        key: relative.clone(),
        relative_path: relative,
        bytes: canonical_metadata.len(),
        modified_unix_secs,
        source_path: canonical,
    })
}

fn read_session_index(
    root: &Path,
    context: &RescueContext,
    max_index_rows: usize,
) -> Result<Option<Vec<IndexPath>>> {
    let path = root.join(SESSION_INDEX_NAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect Codex session index"),
    }
    let first = safe_fs::read_bounded(
        root,
        &path,
        context.max_session_bytes,
        "Codex session index",
    )?;
    let second = safe_fs::read_bounded(
        root,
        &path,
        context.max_session_bytes,
        "Codex session index",
    )?;
    if first != second {
        bail!("Codex session index changed while being read; retry after the writer stops");
    }
    let mut paths = Vec::new();
    for (line_number, raw) in first.split(|byte| *byte == b'\n').enumerate() {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        if raw.is_empty() {
            continue;
        }
        if raw.len() > context.max_record_bytes {
            bail!(
                "Codex session index record {} exceeds the record budget",
                line_number + 1
            );
        }
        let value: Value = serde_json::from_slice(raw).with_context(|| {
            format!(
                "Codex session index record {} is not valid JSON",
                line_number + 1
            )
        })?;
        for path in extract_paths(&value, 0) {
            paths.push(IndexPath { raw: path });
        }
        if paths.len() > max_index_rows {
            bail!(
                "Codex session index exceeded the configured {} entry budget",
                context.max_files
            );
        }
    }
    Ok(Some(paths))
}

fn extract_paths(value: &Value, depth: usize) -> Vec<String> {
    if depth > 2 {
        return Vec::new();
    }
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    for key in PATH_COLUMNS {
        if let Some(path) = object
            .get(key)
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty())
        {
            paths.push(path.to_string());
        }
    }
    for key in ["thread", "session", "rollout"] {
        if let Some(nested) = object.get(key) {
            paths.extend(extract_paths(nested, depth + 1));
        }
    }
    paths
}

fn read_sqlite_indexes(
    context: &RescueContext,
    root: &Path,
    max_index_rows: usize,
) -> Result<Option<Vec<IndexPath>>> {
    let max_database_candidates = max_index_rows.min(MAX_SQLITE_DATABASES);
    if max_database_candidates == 0 {
        bail!("limited rescue scan requires a positive SQLite candidate budget");
    }
    let mut candidates = Vec::new();
    for name in SQLITE_NAMES.iter().copied() {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                if candidates.len() >= max_database_candidates {
                    bail!(
                        "Codex SQLite index fanout exceeded the configured {} entry budget",
                        context.max_files
                    );
                }
                candidates.push(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect Codex root for SQLite indexes"),
        }
    }

    // Keep support for provider schema revisions that use a different state
    // filename, but inspect only direct children and only database suffixes.
    // This stays streaming and bounded: a hostile Codex root cannot make us
    // collect an unbounded list of arbitrary database filenames.
    let mut known_names = SQLITE_NAMES
        .iter()
        .map(|name| (*name).to_string())
        .collect::<HashSet<_>>();
    for entry in fs::read_dir(root).context("inspect Codex root for SQLite indexes")? {
        let entry = entry.context("inspect Codex root for SQLite indexes")?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if (lower.ends_with(".sqlite") || lower.ends_with(".sqlite3") || lower.ends_with(".db"))
            && known_names.insert(name.to_string())
        {
            if candidates.len() >= max_database_candidates {
                bail!(
                    "Codex SQLite index fanout exceeded the configured {} entry budget",
                    context.max_files
                );
            }
            candidates.push(path);
        }
    }

    // Preflight every bounded candidate before opening any SQLite connection.
    // This makes the aggregate byte budget meaningful even when several state
    // databases are present: one large file cannot consume the full budget
    // and leave later candidates unchecked.
    let mut verified_candidates = Vec::with_capacity(candidates.len());
    let mut sqlite_total_bytes = 0u64;
    for path in candidates {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect Codex SQLite index"),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("Codex SQLite index is not a regular file");
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            bail!("Codex SQLite index must not be hardlinked");
        }
        sqlite_total_bytes = sqlite_total_bytes
            .checked_add(metadata.len())
            .context("Codex SQLite index byte counter overflow")?;
        if sqlite_total_bytes > context.max_total_bytes {
            bail!(
                "Codex SQLite indexes exceed the aggregate {} byte budget",
                context.max_total_bytes
            );
        }
        let canonical = safe_fs::canonical_regular_path(root, &path, "Codex SQLite index")?;
        verified_candidates.push(canonical);
    }

    let mut found = false;
    let mut paths = Vec::new();
    for path in verified_candidates {
        found = true;
        let connection = safe_fs::open_sqlite_read_only(root, &path, "Codex SQLite index")?;
        let tables = table_names(&connection)?;
        if !tables.iter().any(|table| table == "threads") {
            continue;
        }
        let columns = table_columns(&connection, "threads")?;
        let Some(path_column) = PATH_COLUMNS.iter().find(|name| columns.contains(**name)) else {
            continue;
        };
        let sql = format!(
            "SELECT {} FROM \"threads\" LIMIT {}",
            quote_identifier(path_column),
            max_index_rows + 1
        );
        let mut statement = connection
            .prepare(&sql)
            .context("read Codex SQLite rollout index")?;
        let rows = statement
            .query_map([], |row| row.get_ref(0).map(value_text))
            .context("read Codex SQLite rollout index")?;
        let mut local_count = 0usize;
        for row in rows {
            local_count = local_count
                .checked_add(1)
                .context("Codex SQLite index row counter overflow")?;
            if local_count > max_index_rows {
                bail!(
                    "Codex SQLite index exceeded the configured {} entry budget",
                    context.max_files
                );
            }
            if let Some(path) = row
                .context("read Codex SQLite rollout path")?
                .filter(|path| !path.is_empty())
            {
                paths.push(IndexPath { raw: path });
                if paths.len() > max_index_rows {
                    bail!(
                        "Codex SQLite index exceeded the configured {} entry budget",
                        context.max_files
                    );
                }
            }
        }
    }
    if found {
        Ok(Some(paths))
    } else {
        Ok(None)
    }
}

fn table_names(connection: &Connection) -> Result<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table'")
        .context("read Codex SQLite schema")?;
    let rows = statement
        .query_map([], |row| {
            let value = row.get_ref(0)?;
            Ok(bounded_text_value(value))
        })
        .context("read Codex SQLite schema")?;
    let mut names = Vec::new();
    let mut rows_seen = 0usize;
    for row in rows {
        rows_seen = rows_seen
            .checked_add(1)
            .context("Codex SQLite schema row counter overflow")?;
        if rows_seen > MAX_INDEX_ROWS {
            bail!("Codex SQLite schema exceeded the configured row budget");
        }
        if let Some(value) = row.context("read Codex SQLite schema")? {
            names.push(value);
        }
    }
    Ok(names)
}

fn table_columns(connection: &Connection, table: &str) -> Result<HashSet<String>> {
    let sql = format!("PRAGMA table_info({})", quote_identifier(table));
    let mut statement = connection
        .prepare(&sql)
        .context("read Codex SQLite table schema")?;
    let rows = statement
        .query_map([], |row| {
            let value = row.get_ref(1)?;
            Ok(bounded_text_value(value))
        })
        .context("read Codex SQLite table schema")?;
    let mut columns = HashSet::new();
    let mut rows_seen = 0usize;
    for row in rows {
        rows_seen = rows_seen
            .checked_add(1)
            .context("Codex SQLite table schema row counter overflow")?;
        if rows_seen > MAX_INDEX_ROWS {
            bail!("Codex SQLite table schema exceeded the configured row budget");
        }
        if let Some(value) = row.context("read Codex SQLite table schema")? {
            columns.insert(value);
        }
    }
    Ok(columns)
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
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
    let ValueRef::Text(value) = value else {
        return None;
    };
    if value.len() > MAX_SQLITE_CELL_BYTES {
        return None;
    }
    std::str::from_utf8(value).ok().map(ToOwned::to_owned)
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
                "vetto-index-test-{tag}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp root");
            Self(path)
        }

        fn codex_home(&self) -> PathBuf {
            self.0.join("codex-home")
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn rollout(root: &Path, name: &str) -> PathBuf {
        let path = root.join("sessions").join(name);
        fs::create_dir_all(path.parent().expect("rollout parent")).expect("rollout parent");
        fs::write(&path, b"{\"type\":\"turn\"}\n").expect("rollout");
        path
    }

    fn sqlite_index(root: &Path, paths: &[&Path]) {
        let path = root.join("state_5.sqlite");
        let connection = Connection::open(&path).expect("create SQLite fixture");
        connection
            .execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT)",
                [],
            )
            .expect("create threads table");
        for (index, rollout) in paths.iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO threads (id, rollout_path) VALUES (?1, ?2)",
                    rusqlite::params![index.to_string(), rollout.to_string_lossy().to_string()],
                )
                .expect("insert index row");
        }
    }

    #[test]
    fn sqlite_index_verifies_candidates_without_walking_unindexed_files() {
        let temp = TempRoot::new("sqlite");
        let root = temp.codex_home();
        let indexed = rollout(&root, "indexed.jsonl");
        let unindexed = rollout(&root, "unindexed.jsonl");
        sqlite_index(&root, &[&indexed]);

        let result = discover(&RescueContext::new(root), 10).expect("index discovery");
        assert_eq!(result.source, "sqlite");
        assert_eq!(result.candidate_count, 1);
        assert!(!result.truncated);
        assert_eq!(
            result.sessions[0].source_path,
            fs::canonicalize(indexed).unwrap()
        );
        assert_ne!(
            result.sessions[0].source_path,
            fs::canonicalize(unindexed).unwrap()
        );
    }

    #[test]
    fn explicit_limit_is_reported_as_truncation() {
        let temp = TempRoot::new("limit");
        let root = temp.codex_home();
        let first = rollout(&root, "first.jsonl");
        let second = rollout(&root, "second.jsonl");
        sqlite_index(&root, &[&first, &second]);

        let result = discover(&RescueContext::new(root), 1).expect("limited discovery");
        assert_eq!(result.candidate_count, 2);
        assert_eq!(result.sessions.len(), 1);
        assert!(result.truncated);
    }

    #[test]
    fn index_rows_respect_the_context_file_budget() {
        let temp = TempRoot::new("max-files");
        let root = temp.codex_home();
        let first = rollout(&root, "first.jsonl");
        let second = rollout(&root, "second.jsonl");
        sqlite_index(&root, &[&first, &second]);
        let mut context = RescueContext::new(root);
        context.max_files = 1;

        let error = discover(&context, 10).expect_err("index row budget");
        assert!(error.to_string().contains("entry budget"), "{error:#}");
    }

    #[test]
    fn sqlite_size_is_rejected_before_the_read_only_open() {
        let temp = TempRoot::new("sqlite-size");
        let root = temp.codex_home();
        let indexed = rollout(&root, "indexed.jsonl");
        sqlite_index(&root, &[&indexed]);
        let mut context = RescueContext::new(root);
        context.max_total_bytes = 1;

        let error = discover(&context, 10).expect_err("oversized SQLite index");
        assert!(
            error.to_string().contains("SQLite") && error.to_string().contains("byte budget"),
            "{error:#}"
        );
    }

    #[test]
    fn aggregate_sqlite_size_is_checked_across_candidates_before_opening() {
        let temp = TempRoot::new("sqlite-aggregate-size");
        let root = temp.codex_home();
        let indexed = rollout(&root, "indexed.jsonl");
        sqlite_index(&root, &[&indexed]);
        let first_db = root.join("state_5.sqlite");
        let second_db = root.join("state.sqlite");
        fs::copy(&first_db, &second_db).expect("copy second SQLite index");
        let first_size = fs::metadata(&first_db)
            .expect("first SQLite metadata")
            .len();
        let second_size = fs::metadata(&second_db)
            .expect("second SQLite metadata")
            .len();
        let mut context = RescueContext::new(root);
        context.max_total_bytes = first_size
            .checked_add(second_size)
            .expect("fixture byte sum")
            .saturating_sub(1);

        let error = discover(&context, 10).expect_err("aggregate SQLite size");
        assert!(
            error.to_string().contains("aggregate") && error.to_string().contains("SQLite indexes"),
            "{error:#}"
        );
    }

    #[test]
    fn sqlite_database_fanout_is_bounded_before_opening_each_candidate() {
        let temp = TempRoot::new("sqlite-fanout");
        let root = temp.codex_home();
        fs::create_dir_all(&root).expect("Codex root");
        fs::write(root.join("a.sqlite"), b"").expect("first database candidate");
        fs::write(root.join("b.sqlite"), b"").expect("second database candidate");
        let mut context = RescueContext::new(root);
        context.max_files = 1;

        let error = discover(&context, 10).expect_err("SQLite fanout budget");
        assert!(
            error.to_string().contains("fanout") || error.to_string().contains("SQLite index"),
            "{error:#}"
        );
    }

    #[test]
    fn stale_index_fails_closed() {
        let temp = TempRoot::new("stale");
        let root = temp.codex_home();
        fs::create_dir_all(root.join("sessions")).expect("sessions");
        sqlite_index(&root, &[&root.join("sessions/missing.jsonl")]);

        let error = discover(&RescueContext::new(root), 10).expect_err("stale index");
        assert!(
            error.to_string().contains("unavailable") || error.to_string().contains("rollout"),
            "{error:#}"
        );
    }

    #[test]
    fn limited_scan_does_not_fallback_to_the_filesystem() {
        let temp = TempRoot::new("no-index");
        let root = temp.codex_home();
        let _session = rollout(&root, "filesystem-only.jsonl");

        let error = discover(&RescueContext::new(root), 10).expect_err("missing index");
        assert!(error
            .to_string()
            .contains("requires a readable Codex index"));
    }

    #[test]
    fn session_index_is_supported_and_is_read_twice() {
        let temp = TempRoot::new("jsonl");
        let root = temp.codex_home();
        let indexed = rollout(&root, "indexed.jsonl");
        fs::create_dir_all(&root).expect("codex root");
        fs::write(
            root.join(SESSION_INDEX_NAME),
            format!(
                "{}\n",
                serde_json::json!({ "rollout_path": indexed.to_string_lossy() })
            ),
        )
        .expect("session index");

        let result = discover(&RescueContext::new(root), 10).expect("session index discovery");
        assert_eq!(result.source, "session-index");
        assert_eq!(result.sessions.len(), 1);
    }

    #[test]
    fn session_index_rows_respect_the_context_file_budget() {
        let temp = TempRoot::new("session-index-max-files");
        let root = temp.codex_home();
        let first = rollout(&root, "first.jsonl");
        let second = rollout(&root, "second.jsonl");
        fs::write(
            root.join(SESSION_INDEX_NAME),
            format!(
                "{}\n{}\n",
                serde_json::json!({ "rollout_path": first.to_string_lossy() }),
                serde_json::json!({ "rollout_path": second.to_string_lossy() })
            ),
        )
        .expect("session index");
        let mut context = RescueContext::new(root);
        context.max_files = 1;

        let error = discover(&context, 10).expect_err("session index row budget");
        assert!(error.to_string().contains("entry budget"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_session_index_is_rejected() {
        let temp = TempRoot::new("session-index-hardlink");
        let root = temp.codex_home();
        let indexed = rollout(&root, "indexed.jsonl");
        let index = root.join(SESSION_INDEX_NAME);
        fs::write(
            &index,
            format!("{{\"rollout_path\":\"{}\"}}\n", indexed.to_string_lossy()),
        )
        .expect("session index");
        fs::hard_link(&index, root.join("session-index-alias.jsonl")).expect("hardlink index");

        let error = discover(&RescueContext::new(root), 10).expect_err("hardlinked index");
        assert!(error.to_string().contains("hardlinked"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_sqlite_index_is_rejected() {
        let temp = TempRoot::new("sqlite-hardlink");
        let root = temp.codex_home();
        let indexed = rollout(&root, "indexed.jsonl");
        sqlite_index(&root, &[&indexed]);
        fs::hard_link(root.join("state_5.sqlite"), root.join("state-alias.sqlite"))
            .expect("hardlink SQLite index");

        let error = discover(&RescueContext::new(root), 10).expect_err("hardlinked SQLite");
        assert!(error.to_string().contains("hardlinked"), "{error:#}");
    }
}
