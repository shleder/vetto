//! Post-session audit reports (HTML / Markdown / JSON).

pub mod html;
pub mod json;
pub mod markdown;
pub mod stats;

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::config::ReportFormat;
use crate::logger::sanitizer;

/// Write `./vetto-report-<timestamp>.<ext>` for every requested format.
/// Values pass through the BEST-EFFORT sanitizer before rendering.
pub fn write_reports(stats: &stats::SessionStats, formats: &[ReportFormat]) -> Result<Vec<PathBuf>> {
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let mut written = Vec::new();
    for fmt in formats {
        let (content, ext): (String, &str) = match fmt {
            ReportFormat::Html => (html::render(stats), "html"),
            ReportFormat::Markdown => (markdown::render(stats), "md"),
            ReportFormat::Json => (json::render(stats), "json"),
        };
        let path = PathBuf::from(format!("vetto-report-{ts}.{ext}"));
        std::fs::write(&path, content)
            .with_context(|| format!("write report {}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

/// BEST-EFFORT redaction applied to every user-derived string in reports.
pub fn clean(s: &str) -> String {
    sanitizer::sanitize_line(s)
}
