mod adapter;
mod codex;
pub mod types;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::cli::RescueCommand;
use crate::report;

use adapter::RescueAdapter;
use codex::CodexAdapter;
use types::{Availability, RescueContext, SessionRef};

fn adapter_by_id(id: &str) -> Result<Box<dyn RescueAdapter>> {
    match id {
        "codex" => Ok(Box::new(CodexAdapter)),
        other => bail!(
            "rescue adapter {other:?} is not available in {}; available: codex",
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
        return Ok(fs_canonical_or_original(candidate));
    }
    if adapter != "codex" {
        bail!("adapter {adapter:?} requires an explicit --root");
    }
    if let Some(path) = std::env::var_os("CODEX_HOME") {
        return Ok(fs_canonical_or_original(PathBuf::from(path)));
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("neither CODEX_HOME, HOME nor USERPROFILE is set; pass --root")?;
    Ok(fs_canonical_or_original(home.join(".codex")))
}

fn fs_canonical_or_original(path: PathBuf) -> PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

fn select_session(
    adapter: &dyn RescueAdapter,
    context: &RescueContext,
    selector: &str,
) -> Result<SessionRef> {
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

pub fn run_cli(
    adapter_id: &str,
    root: Option<&Path>,
    json: bool,
    command: &RescueCommand,
) -> Result<()> {
    let adapter = adapter_by_id(adapter_id)?;
    let context = RescueContext::new(default_root(adapter_id, root)?);
    match command {
        RescueCommand::Scan => {
            let status = adapter.detect(&context)?;
            let sessions = if status.availability == Availability::Available {
                adapter.discover_sessions(&context)?
            } else {
                Vec::new()
            };
            if json {
                print_json(&serde_json::json!({
                    "status": status,
                    "sessions": sessions,
                }))
            } else {
                println!("adapter: {} ({})", adapter.id(), status.support_level);
                if let Some(reason) = status.reason {
                    println!("status: unavailable ({})", report::clean(&reason));
                } else {
                    println!("status: available");
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
