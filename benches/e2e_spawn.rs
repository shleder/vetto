//! Black-box end-to-end benchmark: how long one vetto sandbox session takes.
//!
//! Constraints:
//! - The measured unit is a full process life cycle: spawn
//!   `vetto --tui=none -- /bin/true`, wait for exit, require a success
//!   status. A session that exits non-zero panics so a silently broken
//!   sandbox can never be recorded as a benchmark sample.
//! - The bench must not fail on incapable hosts: when no vetto binary can be
//!   resolved, or `vetto doctor` reports no usable tier (`NONE`, the
//!   fail-closed outcome), the bench prints a reason and exits 0 without
//!   recording anything.
//! - No invented numbers: the committed baseline stays empty until the CI
//!   `perf` job fills it from a real run. Nothing in this file hardcodes a
//!   latency expectation.

#![allow(clippy::all)]
#![allow(warnings)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion};

/// Arguments for one throw-away sandbox session.
const SESSION_ARGS: [&str; 3] = ["--tui=none", "--", "/bin/true"];
/// Samples for the independent wall-clock summary (median + p95).
const SUMMARY_SAMPLES: usize = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tier {
    Full,
    FsOnly,
}

impl Tier {
    /// Value accepted by the `VETTO_FORCE_TIER` testing override, so every
    /// measured sample provably runs the tier its label claims.
    fn force_value(self) -> &'static str {
        match self {
            Tier::Full => "full",
            Tier::FsOnly => "fs-only",
        }
    }
}

/// Resolve the vetto binary to spawn.
///
/// Search order: the `VETTO_BIN` environment variable (explicit override),
/// the path cargo injects at compile time for binaries of this package, then
/// the release and debug build outputs relative to the manifest directory.
/// `None` means the host cannot run this benchmark at all.
fn resolve_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("VETTO_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
        eprintln!("e2e_spawn: VETTO_BIN={path:?} is not a file; continuing search");
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_vetto") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let manifest = env!("CARGO_MANIFEST_DIR");
    for profile in ["release", "debug"] {
        let path = PathBuf::from(manifest)
            .join("target")
            .join(profile)
            .join("vetto");
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

/// Ask `vetto doctor` for the tier this host would pick.
///
/// Returns `None` when doctor cannot be executed, does not print the
/// `chosen tier:` line, or reports `NONE` (fail-closed). In every one of
/// those cases there is no working sandbox to measure.
fn detect_tier(binary: &Path) -> Option<Tier> {
    let output = Command::new(binary).arg("doctor").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("chosen tier:") else {
            continue;
        };
        let rest = rest.trim();
        if rest.starts_with("NONE") {
            return None;
        }
        if rest.contains("fs-only") {
            return Some(Tier::FsOnly);
        }
        if rest.contains("full") {
            return Some(Tier::Full);
        }
    }
    None
}

/// Run one sandbox session to completion and panic unless it succeeds.
fn run_session(binary: &Path, tier: Tier) {
    let status = Command::new(binary)
        .args(SESSION_ARGS)
        .env("VETTO_FORCE_TIER", tier.force_value())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to spawn the vetto binary");
    assert!(
        status.success(),
        "vetto sandbox session did not exit cleanly: {status:?}"
    );
}

/// Criterion group: full session spawn per supported tier.
fn bench_e2e_spawn(c: &mut Criterion, binary: &Path, tiers: &[Tier]) {
    let mut group = c.benchmark_group("e2e-spawn-exit");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(2));
    for tier in tiers {
        group.bench_function(BenchmarkId::from_parameter(tier.force_value()), |b| {
            b.iter(|| run_session(binary, *tier))
        });
    }
    group.finish();
}

/// Independent wall-clock summary, outside criterion.
///
/// Runs `SUMMARY_SAMPLES` sessions per tier, then writes
/// `{"variants":{"<tier>":{"median_ms":...,"p95_ms":...}}}` to the path in
/// `VETTO_PERF_OUT` (fallback: `<temp dir>/vetto-perf-latest.json`) and
/// prints the same JSON to stdout. The CI `perf` job gates on this file; the
/// median uses the usual even/odd middle average and p95 uses the
/// nearest-rank method.
fn write_summary(binary: &Path, tiers: &[Tier]) {
    let mut variants = serde_json::Map::new();
    for tier in tiers {
        let mut durations = Vec::with_capacity(SUMMARY_SAMPLES);
        for _ in 0..SUMMARY_SAMPLES {
            let start = Instant::now();
            run_session(binary, *tier);
            durations.push(start.elapsed());
        }
        let mut millis: Vec<f64> = durations.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
        millis.sort_by(|a, b| a.partial_cmp(b).expect("durations are never NaN"));
        let median = if millis.len() % 2 == 1 {
            millis[millis.len() / 2]
        } else {
            (millis[millis.len() / 2 - 1] + millis[millis.len() / 2]) / 2.0
        };
        let rank = ((0.95 * millis.len() as f64).ceil() as usize).clamp(1, millis.len());
        let p95 = millis[rank - 1];
        let round3 = |value: f64| (value * 1000.0).round() / 1000.0;
        variants.insert(
            tier.force_value().to_string(),
            serde_json::json!({
                "median_ms": round3(median),
                "p95_ms": round3(p95),
            }),
        );
    }
    let summary = serde_json::json!({ "variants": variants });
    let text = serde_json::to_string_pretty(&summary).expect("summary is valid JSON");
    let out_path = std::env::var("VETTO_PERF_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("vetto-perf-latest.json"));
    if let Some(parent) = out_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&out_path, &text) {
        Ok(()) => eprintln!("e2e_spawn: perf summary written to {}", out_path.display()),
        Err(e) => eprintln!(
            "e2e_spawn: failed to write perf summary to {}: {e}",
            out_path.display()
        ),
    }
    println!("{text}");
}

fn main() {
    let Some(binary) = resolve_binary() else {
        eprintln!(
            "e2e_spawn: no vetto binary found (set VETTO_BIN to point at one); \
             skipping benchmark on this host"
        );
        std::process::exit(0);
    };

    // Tier gate: measure exactly what this host can actually run. A full-tier
    // host measures both variants (fs-only forced via VETTO_FORCE_TIER); an
    // fs-only host measures fs-only only; a fail-closed host records nothing.
    let tiers: Vec<Tier> = match detect_tier(&binary) {
        Some(Tier::Full) => vec![Tier::Full, Tier::FsOnly],
        Some(Tier::FsOnly) => vec![Tier::FsOnly],
        None => {
            eprintln!(
                "e2e_spawn: vetto doctor reports no usable tier (fail-closed); \
                 skipping benchmark on this host"
            );
            std::process::exit(0);
        }
    };

    let mut criterion = Criterion::default();
    bench_e2e_spawn(&mut criterion, &binary, &tiers);

    write_summary(&binary, &tiers);
}
