mod adapter;
mod claude;
mod codex;
mod codex_index;
mod codex_inventory;
mod safe_fs;
pub mod types;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::cli::RescueCommand;
use crate::report;

use adapter::RescueAdapter;
use claude::ClaudeAdapter;
use codex::CodexAdapter;
use types::{Availability, RescueContext, SessionRef};

const DEFAULT_INDEX_SCAN_LIMIT: usize = 50;

fn adapter_by_id(id: &str) -> Result<Box<dyn RescueAdapter>> {
    match id {
        "codex" => Ok(Box::new(CodexAdapter)),
        "claude" => Ok(Box::new(ClaudeAdapter)),
        other => bail!(
            "unsupported rescue adapter {other:?} in {}; available: codex, claude",
            env!("CARGO_PKG_VERSION")
        ),
    }
}

fn default_root(adapter: &str, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        return Ok(candidate);
    }
    if adapter != "codex" {
        bail!("adapter {adapter:?} requires an explicit --root");
    }
    if let Some(path) = std::env::var_os("CODEX_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("neither CODEX_HOME, HOME nor USERPROFILE is set; pass --root")?;
    Ok(home.join(".codex"))
}

fn select_session(
    adapter: &dyn RescueAdapter,
    context: &RescueContext,
    selector: &str,
) -> Result<SessionRef> {
    // Codex keys are stable root-relative paths emitted by scan. Resolve them
    // directly so diagnose/snapshot/fork never performs a complete discovery
    // pass. Basename matching is intentionally not used for Codex: nested
    // rollouts may legitimately share one filename.
    if adapter.id() == "codex" {
        return codex::CodexAdapter::resolve_exact(&context.root, selector);
    }

    let selector = selector.replace('\\', "/");
    let sessions = adapter.discover_sessions(context)?;
    if let Some(session) = sessions.iter().find(|session| session.key == selector) {
        return Ok(session.clone());
    }
    let mut matches = sessions
        .into_iter()
        .filter(|session| {
            let path = Path::new(&session.relative_path);
            path.file_name().and_then(|name| name.to_str()) == Some(selector.as_str())
                || path.file_stem().and_then(|name| name.to_str()) == Some(selector.as_str())
        })
        .collect::<Vec<_>>();
    match matches.len() {
        0 => bail!("session {selector:?} was not found; run `vetto rescue scan`"),
        1 => Ok(matches.remove(0)),
        count => bail!(
            "session selector {selector:?} is ambiguous ({count} matches); use the exact key from `vetto rescue scan`"
        ),
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let mut value = serde_json::to_value(value)?;
    report::sanitize_json_strings(&mut value);
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

#[derive(Debug, Serialize)]
struct ScanDiscovery {
    /// `filesystem-all` is the bounded recursive walker. `index-first` means
    /// every returned candidate came from a verified provider index.
    mode: &'static str,
    /// The evidence set whose completeness is described by `complete`.
    /// Index completeness never proves that the provider indexed every file
    /// in the state root.
    scope: &'static str,
    source: String,
    complete: bool,
    limit: Option<usize>,
    candidate_count: usize,
    returned_count: usize,
}

pub fn run_cli(
    adapter_id: &str,
    root: Option<&Path>,
    json: bool,
    command: &RescueCommand,
) -> Result<()> {
    let adapter = adapter_by_id(adapter_id)?;
    let context = RescueContext::new(default_root(adapter_id, root)?);
    match command {
        RescueCommand::Scan { limit, all } => {
            if *limit == Some(0) {
                bail!("rescue scan --limit must be greater than zero");
            }
            if limit.is_some() && adapter_id != "codex" {
                bail!("`rescue scan --limit` is supported only by the Codex index-first adapter");
            }

            let status = adapter.detect(&context)?;
            let use_index = adapter_id == "codex" && !*all;
            let effective_limit = use_index.then_some((*limit).unwrap_or(DEFAULT_INDEX_SCAN_LIMIT));
            let filesystem_mode = if *all { "filesystem-all" } else { "filesystem" };
            let (sessions, discovery) = if status.availability == Availability::Available {
                if let Some(limit) = effective_limit {
                    let indexed = codex_index::discover(&context, limit)?;
                    let returned_count = indexed.sessions.len();
                    let complete = !indexed.truncated;
                    (
                        indexed.sessions,
                        ScanDiscovery {
                            mode: "index-first",
                            scope: "provider-index",
                            source: indexed.source,
                            complete,
                            limit: Some(limit),
                            candidate_count: indexed.candidate_count,
                            returned_count,
                        },
                    )
                } else {
                    let sessions = adapter.discover_sessions(&context)?;
                    let returned_count = sessions.len();
                    (
                        sessions,
                        ScanDiscovery {
                            mode: filesystem_mode,
                            scope: "session-roots",
                            source: "session-roots".to_string(),
                            complete: true,
                            limit: None,
                            candidate_count: returned_count,
                            returned_count,
                        },
                    )
                }
            } else {
                (
                    Vec::new(),
                    ScanDiscovery {
                        mode: if use_index {
                            "index-first"
                        } else {
                            filesystem_mode
                        },
                        scope: if use_index {
                            "provider-index"
                        } else {
                            "session-roots"
                        },
                        source: "unavailable".to_string(),
                        complete: false,
                        limit: effective_limit,
                        candidate_count: 0,
                        returned_count: 0,
                    },
                )
            };
            if json {
                print_json(&serde_json::json!({
                    "status": status,
                    "sessions": sessions,
                    "discovery": discovery,
                }))
            } else {
                println!("adapter: {} ({})", adapter.id(), status.support_level);
                if let Some(reason) = status.reason {
                    println!("status: unavailable ({})", report::clean(&reason));
                } else {
                    println!("status: available");
                }
                println!(
                    "discovery: {} ({}, {} candidate(s), {} returned)",
                    discovery.mode,
                    discovery.source,
                    discovery.candidate_count,
                    discovery.returned_count
                );
                if let Some(limit) = discovery.limit {
                    if !discovery.complete {
                        println!(
                            "notice: result is limited to {limit}; use a larger --limit or `--all` for the bounded filesystem walk"
                        );
                    }
                }
                println!("sessions: {}", sessions.len());
                for session in sessions {
                    println!("{}  {} bytes", report::clean(&session.key), session.bytes);
                }
                Ok(())
            }
        }
        RescueCommand::Diagnose { session } => {
            let session = select_session(adapter.as_ref(), &context, session)?;
            let view = adapter.diagnose(&context, &session)?;
            if json {
                print_json(&view)
            } else {
                println!("session: {}", report::clean(&view.key));
                println!("health: {:?}", view.health);
                println!("records: {}", view.records);
                println!("malformed records: {}", view.malformed_records);
                println!("oversized records: {}", view.oversized_records);
                println!("sha256: {}", view.sha256);
                for notice in view.notices {
                    println!("notice: {}", report::clean(&notice));
                }
                Ok(())
            }
        }
        RescueCommand::Snapshot { session, output } | RescueCommand::Fork { session, output } => {
            let session = select_session(adapter.as_ref(), &context, session)?;
            let receipt = adapter.snapshot(&context, &session, output)?;
            if json {
                print_json(&receipt)
            } else {
                println!("snapshot: {}", report::clean(&receipt.destination));
                println!("bytes: {}", receipt.bytes);
                println!("sha256: {}", receipt.sha256);
                println!("source preserved: {}", receipt.source_preserved);
                Ok(())
            }
        }
    }
}
