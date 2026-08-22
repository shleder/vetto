//! Tracing bootstrap.

use tracing_subscriber::filter::LevelFilter;

/// Initialize tracing to stdout. Debug level when --verbose is passed.
pub fn init(verbose: bool) {
    let level = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();
}
