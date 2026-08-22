//! Session reporting.

use anyhow::Result;

use crate::events::types::ShieldEvent;

/// Emit the session event log as pretty JSON (used by --ci).
pub fn emit_json(events: &[ShieldEvent]) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(events)?);
    Ok(())
}
