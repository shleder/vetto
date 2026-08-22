//! JSONL session log: one sanitized JSON object per line, appended by a
//! dedicated thread subscribed to the event bus.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use tokio::sync::broadcast;

use crate::events::{Event, EventBus};
use crate::logger::sanitizer;

pub struct JsonlSink;

impl JsonlSink {
    /// Spawn the sink thread. Events already emitted before the subscription
    /// are not captured; subscribe early.
    pub fn spawn(bus: &EventBus, path: PathBuf) -> std::thread::JoinHandle<()> {
        let rx = bus.subscribe();
        std::thread::Builder::new()
            .name("vetto-jsonl".into())
            .spawn(move || sink_loop(rx, path))
            .expect("spawn jsonl sink")
    }
}

fn sink_loop(mut rx: broadcast::Receiver<Event>, path: PathBuf) {
    let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) else {
        eprintln!("vetto: cannot open --jsonl file {}: skipping sink", path.display());
        return;
    };
    let mut out = std::io::BufWriter::new(file);
    let _ = writeln!(
        out,
        "{}",
        serde_json::json!({
            "_vetto": "jsonl-sink",
            "note": "secret sanitizer is BEST-EFFORT; false positives and misses are possible",
        })
    );
    let _ = out.flush();
    loop {
        match rx.blocking_recv() {
            Ok(ev) => {
                let line = serde_json::to_string(&ev).unwrap_or_default();
                let _ = writeln!(out, "{}", sanitizer::sanitize_line(&line));
                let _ = out.flush();
            }
            Err(broadcast::error::RecvError::Lagged(missed)) => {
                let _ = writeln!(
                    out,
                    "{}",
                    serde_json::json!({"_vetto": "sink-lagged", "missed": missed})
                );
                let _ = out.flush();
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}
