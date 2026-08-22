//! Logging: tracing diagnostics on STDERR (stdout belongs to the sandboxed
//! agent's pass-through and must never carry vetto output) + the JSONL event
//! sink with BEST-EFFORT secret redaction.

pub mod jsonl;
pub mod sanitizer;

use tracing_subscriber::filter::LevelFilter;

/// Initialize tracing. Verbose mode enables DEBUG; the default is WARN so a
/// normal session stays silent on stderr.
pub fn init(verbose: bool) {
    let level = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::WARN
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}
