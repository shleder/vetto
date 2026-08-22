//! JSON report (pretty-printed serde output of SessionStats).

use super::stats::SessionStats;

pub fn render(stats: &SessionStats) -> String {
    serde_json::to_string_pretty(stats).unwrap_or_else(|_| "{}\n".to_string())
}
