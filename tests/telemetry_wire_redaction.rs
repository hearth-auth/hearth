//! HEA §4.14#3 — `observability.log_level: trace` must not dump outbound
//! request heads.
//!
//! Every outbound egress path in the tree (federation, email, SMS, webhook
//! dispatch, pre-token webhook) is built on `ureq`. `ureq_proto` hex-dumps the
//! serialized request head — `Authorization: Bearer <provider api key>`
//! included — through `log::trace!` from `ureq_proto::util::log_data`, and
//! `tracing-subscriber` bridges `log` records into the global subscriber. At
//! `log_level: trace` that leaked every federation client secret, SMS provider
//! auth token and email provider API key into the operator log in cleartext.
//!
//! The project rule is absolute: never log passwords, tokens, keys or PII, at
//! any level. These tests pin the two halves of the fix — an unconditional cap
//! on the wire-dump targets that `RUST_LOG` cannot lift, and a redaction helper
//! the transports use when they log their own request head.

use std::sync::{Arc, Mutex};

use hearth::telemetry::redact::{is_sensitive_header, redact_header_value, redacted_headers};
use tracing_subscriber::layer::SubscriberExt;

/// A canary standing in for a provider API key.
const SECRET: &str = "sk-live-CANARY-do-not-log-0123456789abcdef";

#[derive(Clone, Default)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl CaptureWriter {
    fn contents(&self) -> String {
        #[allow(clippy::expect_used)]
        let bytes = self.0.lock().expect("capture mutex").clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        #[allow(clippy::expect_used)]
        self.0.lock().expect("capture mutex").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for CaptureWriter {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// Runs `f` under a subscriber wired with the *production* filter for
/// `log_level`, capturing everything the filter lets through.
fn capture_under_production_filter(log_level: &str, f: impl FnOnce()) -> String {
    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::registry()
        .with(hearth::telemetry::build_env_filter(log_level))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false),
        );
    tracing::subscriber::with_default(subscriber, f);
    writer.contents()
}

/// One row of the hex+ASCII dump `ureq_proto::util::log_data` emits, carrying
/// the tail of an `Authorization` header.
fn wire_dump_row() -> String {
    format!("41 75 74 68  Authorization: Bearer {SECRET}")
}

#[test]
fn trace_level_does_not_dump_the_outbound_request_head() {
    let out = capture_under_production_filter("trace", || {
        tracing::trace!(target: "ureq_proto::util", "{}", wire_dump_row());
    });

    assert!(
        !out.contains(SECRET),
        "log_level: trace leaked an outbound provider credential: {out}"
    );
}

#[test]
fn rust_log_cannot_re_enable_the_request_head_dump() {
    // An operator reaching for maximum verbosity must still not be handed
    // other people's API keys.
    std::env::set_var("RUST_LOG", "trace,ureq_proto::util=trace,ureq_proto=trace");
    let out = capture_under_production_filter("info", || {
        tracing::trace!(target: "ureq_proto::util", "{}", wire_dump_row());
    });
    std::env::remove_var("RUST_LOG");

    assert!(
        !out.contains(SECRET),
        "RUST_LOG re-enabled the wire dump: {out}"
    );
}

#[test]
fn h1_and_h2_header_frame_traces_are_capped_too() {
    let out = capture_under_production_filter("trace", || {
        tracing::trace!(target: "h2::codec::framed_write", "authorization: Bearer {SECRET}");
        tracing::trace!(target: "hyper::proto::h1::role", "authorization: Bearer {SECRET}");
        tracing::trace!(target: "hyper_util::client::legacy::pool", "authorization: Bearer {SECRET}");
    });

    assert!(
        !out.contains(SECRET),
        "an HTTP framing trace leaked a credential: {out}"
    );
}

#[test]
fn ordinary_hearth_targets_still_log_at_trace() {
    // The cap must be surgical: it may not turn `log_level: trace` into a
    // no-op for the server's own diagnostics.
    let out = capture_under_production_filter("trace", || {
        tracing::trace!(target: "hearth::identity::federation", "upstream fetch started");
    });

    assert!(
        out.contains("upstream fetch started"),
        "the wire-dump cap silenced ordinary trace logging: {out}"
    );
}

#[test]
fn sensitive_outbound_headers_are_redacted_at_the_point_of_logging() {
    for name in [
        "Authorization",
        "authorization",
        "Proxy-Authorization",
        "Cookie",
        "X-Api-Key",
        "api-key",
        "X-Auth-Token",
        "X-Amz-Security-Token",
        "X-Goog-Api-Key",
        "X-Postmark-Server-Token",
        "X-Hearth-Signature-256",
        "DPoP",
    ] {
        assert!(
            is_sensitive_header(name),
            "{name} must be treated sensitive"
        );
        assert_eq!(
            redact_header_value(name, SECRET),
            "[redacted]",
            "{name} value must never reach the log"
        );
    }

    assert_eq!(
        redact_header_value("Content-Type", "application/json"),
        "application/json",
        "a benign header must survive redaction"
    );
}

#[test]
fn redacted_headers_keeps_names_and_drops_values() {
    let headers = vec![
        ("Authorization".to_string(), format!("Bearer {SECRET}")),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];

    let rendered = redacted_headers(&headers);

    assert!(
        !rendered.contains(SECRET),
        "redacted header rendering leaked the credential: {rendered}"
    );
    assert!(
        rendered.contains("Authorization"),
        "the header name is useful and must be kept: {rendered}"
    );
    assert!(
        rendered.contains("application/json"),
        "a benign header value must be kept: {rendered}"
    );
}
