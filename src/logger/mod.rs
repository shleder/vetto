//! Logging: tracing diagnostics on STDERR (stdout belongs to the sandboxed
//! agent's pass-through and must never carry vetto output) + the JSONL event
//! sink with BEST-EFFORT secret redaction.

pub mod jsonl;
pub mod oslog;
pub mod sanitizer;
pub mod system_log;

pub use oslog::OsLogSink;
use std::sync::atomic::{AtomicU8, Ordering};
use tracing_subscriber::filter::LevelFilter;

/// Global verbosity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Verbosity {
    /// Only errors and session lifecycle events.
    Quiet = 0,
    /// Default output.
    Normal = 1,
    /// Detailed diagnostic output including policy resolution.
    Verbose = 2,
}

static CURRENT_VERBOSITY: AtomicU8 = AtomicU8::new(Verbosity::Normal as u8);

/// Return the globally configured verbosity level.
pub fn verbosity() -> Verbosity {
    match CURRENT_VERBOSITY.load(Ordering::Relaxed) {
        0 => Verbosity::Quiet,
        2 => Verbosity::Verbose,
        _ => Verbosity::Normal,
    }
}

/// Check if quiet mode is active.
pub fn is_quiet() -> bool {
    verbosity() == Verbosity::Quiet
}

/// Check if verbose mode is active.
pub fn is_verbose() -> bool {
    verbosity() == Verbosity::Verbose
}

/// Initialize tracing with boolean verbose flag (backwards compatibility).
pub fn init(verbose: bool) {
    init_verbosity(if verbose {
        Verbosity::Verbose
    } else {
        Verbosity::Normal
    });
}

/// Initialize tracing with explicit quiet/verbose flags.
pub fn init_flags(quiet: bool, verbose: bool) {
    let verbosity = if quiet {
        Verbosity::Quiet
    } else if verbose {
        Verbosity::Verbose
    } else {
        Verbosity::Normal
    };
    init_verbosity(verbosity);
}

/// Initialize tracing with a specific verbosity level.
pub fn init_verbosity(verbosity: Verbosity) {
    CURRENT_VERBOSITY.store(verbosity as u8, Ordering::Relaxed);
    let level = match verbosity {
        Verbosity::Quiet => LevelFilter::ERROR,
        Verbosity::Normal => LevelFilter::WARN,
        Verbosity::Verbose => LevelFilter::DEBUG,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbosity_levels_roundtrip() {
        init_verbosity(Verbosity::Quiet);
        assert_eq!(verbosity(), Verbosity::Quiet);
        assert!(is_quiet());
        assert!(!is_verbose());

        init_verbosity(Verbosity::Verbose);
        assert_eq!(verbosity(), Verbosity::Verbose);
        assert!(!is_quiet());
        assert!(is_verbose());

        init_verbosity(Verbosity::Normal);
        assert_eq!(verbosity(), Verbosity::Normal);
        assert!(!is_quiet());
        assert!(!is_verbose());
    }
}
