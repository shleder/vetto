//! OpenTelemetry integration for vetto sandboxed sessions.
//!
//! Feature `telemetry` (default off):
//! When enabled and an `otel_endpoint` is configured, one sandbox session = root span
//! (`vetto.session`), and each security/observation event is emitted as a span-event.
//! When disabled or unconfigured, this module provides zero-overhead no-op handles.

use crate::events::Event;
use anyhow::Result;

#[cfg(feature = "telemetry")]
mod inner {
    use super::*;
    use opentelemetry::trace::{Span, Status, Tracer, TracerProvider};
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    pub struct OtelSessionInner {
        provider: SdkTracerProvider,
        span: Arc<Mutex<opentelemetry_sdk::trace::Span>>,
    }

    pub struct TelemetrySession {
        inner: Option<OtelSessionInner>,
    }

    impl TelemetrySession {
        pub fn start(
            endpoint: Option<&str>,
            session_id: &str,
            tier: &str,
            net: &str,
            profile: &str,
        ) -> Result<Self> {
            let endpoint = match endpoint {
                Some(ep) if !ep.trim().is_empty() => ep.trim().to_string(),
                _ => match std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
                    Ok(ep) if !ep.trim().is_empty() => ep.trim().to_string(),
                    _ => return Ok(Self { inner: None }),
                },
            };

            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build OTLP span exporter: {e}"))?;

            let resource = opentelemetry_sdk::Resource::new(vec![
                KeyValue::new("service.name", "vetto"),
                KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                KeyValue::new("session.id", session_id.to_string()),
                KeyValue::new("sandbox.tier", tier.to_string()),
                KeyValue::new("sandbox.net", net.to_string()),
                KeyValue::new("policy.profile", profile.to_string()),
            ]);

            let provider = SdkTracerProvider::builder()
                .with_simple_exporter(exporter)
                .with_resource(resource)
                .build();

            let tracer = provider.tracer("vetto");
            let span = tracer.start("vetto.session");

            Ok(Self {
                inner: Some(OtelSessionInner {
                    provider,
                    span: Arc::new(Mutex::new(span)),
                }),
            })
        }

        pub fn record_event(&self, event: &Event) {
            let Some(inner) = &self.inner else { return };
            let Ok(mut span) = inner.span.lock() else {
                return;
            };
            let ts = SystemTime::from(event.ts());

            match event {
                Event::SessionStarted {
                    pid,
                    tier,
                    net_mode,
                    profile,
                    ..
                } => {
                    span.add_event_with_timestamp(
                        "session_started",
                        ts,
                        vec![
                            KeyValue::new("pid", *pid as i64),
                            KeyValue::new("tier", tier.clone()),
                            KeyValue::new("net_mode", net_mode.clone()),
                            KeyValue::new("profile", profile.clone()),
                        ],
                    );
                }
                Event::FileObserved {
                    pid,
                    comm,
                    path,
                    access,
                    ..
                } => {
                    let access_str = match access {
                        crate::events::FileAccess::Read => "read",
                        crate::events::FileAccess::Write => "write",
                        crate::events::FileAccess::Unknown => "unknown",
                    };
                    span.add_event_with_timestamp(
                        "file_observed",
                        ts,
                        vec![
                            KeyValue::new("pid", *pid as i64),
                            KeyValue::new("comm", comm.clone()),
                            KeyValue::new("path", path.clone()),
                            KeyValue::new("access", access_str),
                        ],
                    );
                }
                Event::ExecObserved { pid, argv, .. } => {
                    span.add_event_with_timestamp(
                        "exec_observed",
                        ts,
                        vec![
                            KeyValue::new("pid", *pid as i64),
                            KeyValue::new("argv", argv.join(" ")),
                        ],
                    );
                }
                Event::BlockedAttempt {
                    pid,
                    comm,
                    path,
                    source,
                    ..
                } => {
                    span.add_event_with_timestamp(
                        "blocked_attempt",
                        ts,
                        vec![
                            KeyValue::new("pid", *pid as i64),
                            KeyValue::new("comm", comm.clone()),
                            KeyValue::new("path", path.clone()),
                            KeyValue::new("source", source.clone()),
                        ],
                    );
                }
                Event::NetRequest {
                    host,
                    port,
                    allowed,
                    ..
                } => {
                    span.add_event_with_timestamp(
                        "net_request",
                        ts,
                        vec![
                            KeyValue::new("host", host.clone()),
                            KeyValue::new("port", *port as i64),
                            KeyValue::new("allowed", *allowed),
                        ],
                    );
                }
                Event::SecretMasked { path, .. } => {
                    span.add_event_with_timestamp(
                        "secret_masked",
                        ts,
                        vec![KeyValue::new("path", path.clone())],
                    );
                }
                Event::Notice { message, .. } => {
                    span.add_event_with_timestamp(
                        "notice",
                        ts,
                        vec![KeyValue::new("message", message.clone())],
                    );
                }
                Event::SessionTimeout { .. } => {
                    span.add_event_with_timestamp(
                        "session_timeout",
                        ts,
                        vec![KeyValue::new("timeout", true)],
                    );
                }
                Event::SessionEnded {
                    exit_code,
                    duration_secs,
                    ..
                } => {
                    span.add_event_with_timestamp(
                        "session_ended",
                        ts,
                        vec![
                            KeyValue::new("exit_code", *exit_code as i64),
                            KeyValue::new("duration_secs", *duration_secs as i64),
                        ],
                    );
                }
            }
        }

        pub fn finish(&self, exit_code: i32) {
            if let Some(inner) = &self.inner {
                if let Ok(mut span) = inner.span.lock() {
                    span.set_attribute(KeyValue::new("exit_code", exit_code as i64));
                    if exit_code == 0 {
                        span.set_status(Status::Ok);
                    } else {
                        span.set_status(Status::error(format!(
                            "agent exited with code {exit_code}"
                        )));
                    }
                    span.end();
                }
                let _ = inner.provider.force_flush();
                let _ = inner.provider.shutdown();
            }
        }
    }
}

#[cfg(not(feature = "telemetry"))]
mod inner {
    use super::*;

    pub struct TelemetrySession;

    impl TelemetrySession {
        pub fn start(
            _endpoint: Option<&str>,
            _session_id: &str,
            _tier: &str,
            _net: &str,
            _profile: &str,
        ) -> Result<Self> {
            Ok(Self)
        }

        pub fn record_event(&self, _event: &Event) {}

        pub fn finish(&self, _exit_code: i32) {}
    }
}

pub use inner::TelemetrySession;

/// Spawn a background subscriber to mirror EventBus events to the TelemetrySession.
pub fn spawn_telemetry_subscriber(
    bus: &crate::events::EventBus,
    session: std::sync::Arc<TelemetrySession>,
) -> std::thread::JoinHandle<()> {
    let mut rx = bus.subscribe();
    std::thread::Builder::new()
        .name("vetto-telemetry".into())
        .spawn(move || loop {
            match rx.blocking_recv() {
                Ok(event) => {
                    session.record_event(&event);
                    if matches!(event, Event::SessionEnded { .. }) {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        })
        .expect("spawn telemetry subscriber")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::now;

    #[test]
    fn telemetry_session_handles_events_without_panicking() {
        let session = TelemetrySession::start(None, "test-session", "full", "off", "default")
            .expect("create telemetry session");
        session.record_event(&Event::SessionStarted {
            ts: now(),
            pid: 100,
            tier: "full".into(),
            net_mode: "off".into(),
            profile: "default".into(),
        });
        session.record_event(&Event::BlockedAttempt {
            ts: now(),
            pid: 100,
            comm: "cat".into(),
            path: "/etc/shadow".into(),
            source: "landlock".into(),
        });
        session.finish(0);
    }
}
