//! OpenTelemetry distributed tracing initialization.
//!
//! Builds the global `tracing` subscriber, optionally layering an OTLP span
//! exporter when `observability.otlp` is configured. When the section is
//! absent the existing logging-only subscriber is installed with no OTel
//! overhead.
//!
//! # Lifecycle
//!
//! Call [`init`] once at startup and hold the returned [`TracingGuard`] for
//! the entire process lifetime. Dropping the guard flushes the batch exporter
//! and shuts down the OTel pipeline cleanly.

use std::io::IsTerminal as _;

use thiserror::Error;

use opentelemetry::KeyValue;
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::trace::{BatchSpanProcessor, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::config::{ObservabilityConfig, OtlpConfig, OtlpProtocol};

/// Error returned when the OTLP telemetry pipeline cannot be configured.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TelemetryError {
    /// The OTLP span exporter builder failed (bad endpoint, invalid header, etc.).
    #[error("failed to build OTLP span exporter: {0}")]
    OtlpBuild(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Holds the live OTel tracer provider. Dropping this guard flushes all
/// pending spans and shuts down the export pipeline.
pub struct TracingGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

/// Initialize the global `tracing` subscriber.
///
/// When `config.otlp` is `Some`, a `BatchSpanProcessor` is wired in and
/// spans flow to the configured OTLP collector via gRPC or HTTP. If the OTLP
/// exporter cannot be built (bad endpoint URL, invalid header value, etc.),
/// the function falls back to logging-only mode and emits a `warn`-level
/// tracing event describing the failure — the server continues to start
/// normally.
///
/// When `config.otlp` is `None`, or when OTLP setup fails, only the fmt
/// layer is installed (identical to the previous setup).
///
/// When `config.dev_mode` is true or stdout is a TTY, a compact pretty
/// formatter is used: `HH:MM:SS` timestamps, ANSI-colored levels (TTY only),
/// and abbreviated target paths (last two `::` segments).
///
/// # Panics
///
/// Panics if the global subscriber has already been set (called twice).
pub fn init(config: &ObservabilityConfig) -> TracingGuard {
    // RUST_LOG takes priority. When absent, bake per-crate warn overrides for
    // known noisy dependencies so they don't pollute default output.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "{},globset=warn,h2=warn,hyper=warn,tower=warn",
            config.log_level
        ))
    });

    let json = config.log_format == "json";
    let is_tty = std::io::stdout().is_terminal();
    // Use the pretty dev formatter when explicitly in dev mode OR when writing
    // to an interactive terminal.
    let use_pretty = !json && (config.dev_mode || is_tty);
    let ansi = is_tty;

    // Try to build the OTLP provider. On failure, capture the error and fall
    // back to logging-only mode; we emit a warn! after the subscriber is up.
    let (provider, otlp_error) = match config.otlp.as_ref() {
        Some(cfg) => match build_provider(cfg) {
            Ok(p) => (Some(p), None),
            Err(e) => (None, Some(e)),
        },
        None => (None, None),
    };

    if let Some(ref p) = provider {
        let tracer = {
            use opentelemetry::trace::TracerProvider as _;
            p.tracer("hearth")
        };
        opentelemetry::global::set_tracer_provider(p.clone());
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        if json {
            tracing_subscriber::registry()
                .with(filter)
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        } else if use_pretty {
            tracing_subscriber::registry()
                .with(filter)
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer().event_format(DevFormatter { ansi }))
                .init();
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    } else if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else if use_pretty {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().event_format(DevFormatter { ansi }))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    // Subscriber is now installed; safe to use tracing macros.
    if let Some(ref e) = otlp_error {
        tracing::warn!(error = %e, "OTLP exporter unavailable; traces disabled");
    }

    TracingGuard { provider }
}

// ── private helpers ──────────────────────────────────────────────────────────

/// Dev-mode event formatter: `HH:MM:SS LEVEL target: message key=val`.
///
/// Activated when `dev_mode = true` or stdout is a TTY. Produces one physical
/// line per event (equivalent to `.compact()`).
struct DevFormatter {
    /// Whether to emit ANSI color escape codes.
    ansi: bool,
}

impl<S, N> FormatEvent<S, N> for DevFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let meta = event.metadata();

        // HH:MM:SS UTC timestamp.
        let now = time::OffsetDateTime::now_utc();
        write!(
            writer,
            "{:02}:{:02}:{:02} ",
            now.hour(),
            now.minute(),
            now.second()
        )?;

        // Level — right-aligned in 5 chars, optionally colored.
        if self.ansi {
            let colored = match *meta.level() {
                Level::ERROR => "\x1b[31mERROR\x1b[0m",
                Level::WARN => "\x1b[33m WARN\x1b[0m",
                Level::INFO => "\x1b[32m INFO\x1b[0m",
                Level::DEBUG => "\x1b[34mDEBUG\x1b[0m",
                Level::TRACE => "\x1b[35mTRACE\x1b[0m",
            };
            write!(writer, "{colored} ")?;
        } else {
            write!(writer, "{:>5} ", meta.level())?;
        }

        // Short target: last two `::` segments only.
        write!(writer, "{}: ", short_target(meta.target()))?;

        // Message and structured fields.
        ctx.format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

/// Returns the last two `::`-delimited segments of `target`.
///
/// `"hearth::identity::engine"` → `"identity::engine"`.
/// Targets with fewer than three segments are returned unchanged.
fn short_target(target: &str) -> String {
    let mut rev = target.rsplit("::");
    let last = rev.next().unwrap_or(target);
    match rev.next() {
        Some(second_last) => format!("{second_last}::{last}"),
        None => target.to_string(),
    }
}

fn build_provider(cfg: &OtlpConfig) -> Result<SdkTracerProvider, TelemetryError> {
    let resource = Resource::builder()
        .with_attribute(KeyValue::new(SERVICE_NAME, cfg.service_name.clone()))
        .build();
    let exporter = build_exporter(cfg)?;
    let processor = BatchSpanProcessor::builder(exporter).build();
    Ok(SdkTracerProvider::builder()
        .with_span_processor(processor)
        .with_resource(resource)
        .build())
}

fn build_exporter(cfg: &OtlpConfig) -> Result<opentelemetry_otlp::SpanExporter, TelemetryError> {
    let endpoint = cfg.effective_endpoint();

    match cfg.protocol {
        OtlpProtocol::Grpc => {
            let mut builder = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint);

            if !cfg.headers.is_empty() {
                let metadata = tonic_metadata_from_headers(&cfg.headers);
                builder = builder.with_metadata(metadata);
            }

            builder
                .build()
                .map_err(|e| TelemetryError::OtlpBuild(Box::new(e)))
        }
        OtlpProtocol::Http => {
            let mut builder = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(endpoint);

            if !cfg.headers.is_empty() {
                builder = builder.with_headers(cfg.headers.clone());
            }

            builder
                .build()
                .map_err(|e| TelemetryError::OtlpBuild(Box::new(e)))
        }
    }
}

fn tonic_metadata_from_headers(
    headers: &std::collections::HashMap<String, String>,
) -> tonic::metadata::MetadataMap {
    let mut map = tonic::metadata::MetadataMap::new();
    for (k, v) in headers {
        if let (Ok(key), Ok(val)) = (
            tonic::metadata::MetadataKey::from_bytes(k.as_bytes()),
            tonic::metadata::AsciiMetadataValue::try_from(v.as_str()),
        ) {
            map.insert(key, val);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::{build_exporter, short_target};
    use crate::config::{OtlpConfig, OtlpProtocol};

    fn bad_endpoint_cfg(protocol: OtlpProtocol) -> OtlpConfig {
        OtlpConfig {
            endpoint: Some("not a valid uri at all".to_string()),
            protocol,
            headers: std::collections::HashMap::new(),
            service_name: "test".to_string(),
        }
    }

    #[test]
    fn build_exporter_grpc_returns_err_on_invalid_endpoint() {
        let result = build_exporter(&bad_endpoint_cfg(OtlpProtocol::Grpc));
        assert!(
            result.is_err(),
            "expected Err for invalid gRPC endpoint, got Ok"
        );
    }

    #[test]
    fn build_exporter_http_returns_err_on_invalid_endpoint() {
        let result = build_exporter(&bad_endpoint_cfg(OtlpProtocol::Http));
        assert!(
            result.is_err(),
            "expected Err for invalid HTTP endpoint, got Ok"
        );
    }

    #[test]
    fn short_target_three_segments() {
        assert_eq!(short_target("hearth::identity::engine"), "identity::engine");
    }

    #[test]
    fn short_target_four_segments() {
        assert_eq!(
            short_target("hearth::identity::engine::reconcile"),
            "engine::reconcile"
        );
    }

    #[test]
    fn short_target_two_segments_unchanged() {
        assert_eq!(short_target("identity::engine"), "identity::engine");
    }

    #[test]
    fn short_target_one_segment_unchanged() {
        assert_eq!(short_target("hearth"), "hearth");
    }

    #[test]
    fn short_target_empty_unchanged() {
        assert_eq!(short_target(""), "");
    }
}
