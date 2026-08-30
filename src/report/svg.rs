//! Pure Rust SVG category histogram generator for HTML reports (Feature 44).
//!
//! Generates a standalone, inline SVG visualizing the distribution of observed
//! operations and security events across categories (reads, writes, blocked attempts,
//! network, execs, notices) with zero external profilers or JS/CSS dependencies.

use super::stats::SessionStats;

#[derive(Debug, Clone)]
pub struct CategoryItem {
    pub label: &'static str,
    pub count: u64,
    pub color: &'static str,
}

pub fn collect_categories(stats: &SessionStats) -> Vec<CategoryItem> {
    let reads = stats.file_reads;
    let writes = stats.file_writes;
    let blocked: u64 = stats.blocked_attempts.iter().map(|b| b.count).sum();
    let net_allowed = stats.net_requests.iter().filter(|r| r.allowed).count() as u64;
    let net_denied = stats.net_requests.iter().filter(|r| !r.allowed).count() as u64;
    let execs = stats.counts.get("exec_observed").copied().unwrap_or(0);
    let notices = stats.notices.len() as u64;

    vec![
        CategoryItem {
            label: "File Reads",
            count: reads,
            color: "#81c784",
        },
        CategoryItem {
            label: "File Writes",
            count: writes,
            color: "#4db6ac",
        },
        CategoryItem {
            label: "Blocked Access",
            count: blocked,
            color: "#e57373",
        },
        CategoryItem {
            label: "Net Allowed",
            count: net_allowed,
            color: "#64b5f6",
        },
        CategoryItem {
            label: "Net Denied",
            count: net_denied,
            color: "#f06292",
        },
        CategoryItem {
            label: "Exec Procs",
            count: execs,
            color: "#ba68c8",
        },
        CategoryItem {
            label: "Notices",
            count: notices,
            color: "#ffd54f",
        },
    ]
}

pub fn render_category_histogram_svg(stats: &SessionStats) -> String {
    let categories = collect_categories(stats);
    let total_events: u64 = categories.iter().map(|c| c.count).sum();

    let width = 760;
    let bar_height = 24;
    let row_height = 26;
    let header_height = 40;
    let total_height = header_height + bar_height + 20 + (categories.len() * row_height) + 20;

    let mut svg = format!(
        r##"<svg viewBox="0 0 {width} {total_height}" width="100%" height="{total_height}" xmlns="http://www.w3.org/2000/svg" style="background:#141a20;border-radius:6px;border:1px solid #263238;font-family:ui-monospace,Menlo,Consolas,monospace;">
<text x="16" y="26" fill="#80cbc4" font-size="14" font-weight="bold">Session Event Distribution by Category</text>
<text x="{}" y="26" fill="#78909c" font-size="12" text-anchor="end">total events: {}</text>
"##,
        width - 16,
        total_events
    );

    // Render stacked proportional overview bar
    let overview_y = header_height;
    let overview_x = 16;
    let overview_w = width - 32;

    svg.push_str(&format!(
        r##"<rect x="{overview_x}" y="{overview_y}" width="{overview_w}" height="{bar_height}" fill="#1c242c" rx="4"/>
"##
    ));

    if total_events > 0 {
        let mut cur_x = overview_x as f64;
        for c in &categories {
            if c.count == 0 {
                continue;
            }
            let seg_w = (c.count as f64 / total_events as f64) * (overview_w as f64);
            svg.push_str(&format!(
                r#"<rect x="{:.1}" y="{}" width="{:.1}" height="{}" fill="{}"><title>{}: {} ({:.1}%)</title></rect>
"#,
                cur_x, overview_y, seg_w, bar_height, c.color, c.label, c.count, (c.count as f64 / total_events as f64) * 100.0
            ));
            cur_x += seg_w;
        }
    }

    // Render individual category breakdown bars
    let list_start_y = overview_y + bar_height + 20;
    let max_count = categories.iter().map(|c| c.count).max().unwrap_or(0).max(1);

    for (i, c) in categories.iter().enumerate() {
        let y = list_start_y + (i * row_height);
        let pct = if total_events > 0 {
            (c.count as f64 / total_events as f64) * 100.0
        } else {
            0.0
        };

        // Indicator dot
        svg.push_str(&format!(
            r#"<circle cx="24" cy="{}" r="5" fill="{}"/>
"#,
            y + 10,
            c.color
        ));

        // Category label
        svg.push_str(&format!(
            r##"<text x="36" y="{}" fill="#cfd8dc" font-size="12">{}</text>
        "##,
            y + 14,
            c.label
        ));

        // Background track
        let track_x = 180;
        let track_w = width - track_x - 140;
        svg.push_str(&format!(
            r##"<rect x="{track_x}" y="{}" width="{track_w}" height="14" fill="#1c242c" rx="3"/>
        "##,
            y + 3
        ));

        // Active bar
        if c.count > 0 {
            let bar_w = ((c.count as f64 / max_count as f64) * (track_w as f64)).max(2.0);
            svg.push_str(&format!(
                r#"<rect x="{track_x}" y="{}" width="{:.1}" height="14" fill="{}" rx="3"/>
"#,
                y + 3,
                bar_w,
                c.color
            ));
        }

        // Count and percentage text
        svg.push_str(&format!(
            r##"<text x="{}" y="{}" fill="#90a4ae" font-size="11" text-anchor="end">{:>6} ({:>5.1}%)</text>
"##,
            width - 16, y + 14, c.count, pct
        ));
    }

    svg.push_str("</svg>\n");
    svg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_histogram_handles_empty_stats() {
        let stats = SessionStats::default();
        let svg = render_category_histogram_svg(&stats);
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>\n"));
        assert!(svg.contains("total events: 0"));
    }

    #[test]
    fn svg_histogram_renders_categories_with_nonzero_counts() {
        let mut counts = std::collections::BTreeMap::new();
        counts.insert("exec_observed".to_string(), 5);

        let stats = SessionStats {
            file_reads: 42,
            file_writes: 10,
            blocked_attempts: vec![super::super::stats::BlockedRecord {
                path: "/etc/shadow".into(),
                comm: "cat".into(),
                source: "landlock".into(),
                count: 3,
            }],
            net_requests: vec![super::super::stats::NetRecord {
                host: "api.github.com".into(),
                port: 443,
                allowed: true,
            }],
            counts,
            ..SessionStats::default()
        };

        let svg = render_category_histogram_svg(&stats);
        assert!(svg.contains("File Reads"));
        assert!(svg.contains("Blocked Access"));
        assert!(svg.contains("Net Allowed"));
        assert!(svg.contains("42"));
        assert!(svg.contains("#81c784"));
    }
}
