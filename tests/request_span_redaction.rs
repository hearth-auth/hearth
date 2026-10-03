//! GA audit 2026-09-28 M16 — one-time tokens in request URLs were recorded in
//! the per-request tracing span.
//!
//! `protocol/http.rs` installed tower-http's `DefaultMakeSpan`, which records
//! `uri = %request.uri()` — query string included. Setup, password-reset,
//! magic-link, invitation and email-verification links all carry their
//! credential in `?token=`, and the federation callback carries `code` and
//! `state`. The default fmt layers print span fields on every event inside the
//! request, and the OTLP exporter ships every span with its attributes.
//!
//! The span must keep the path and the parameter *names* (both useful when
//! debugging) and never the values.

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;

/// A canary standing in for a one-time credential.
const CANARY: &str = "CANARY-one-time-token-0123456789abcdef";

#[derive(Clone, Default)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl CaptureWriter {
    fn contents(&self) -> String {
        let bytes = self.0.lock().expect("capture mutex").clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
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

/// Sends `uri` through the real API router under a subscriber that prints
/// every span's fields when the span opens, and returns everything logged.
fn logged_for(uri: &str) -> String {
    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_span_events(FmtSpan::NEW),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let h = common::TestHarness::in_process().await.expect("harness");
            let app = router(Arc::new(AppState::new(
                h.identity_arc(),
                h.rbac_arc(),
                h.audit_arc(),
            )));
            let request = Request::builder()
                .uri(uri)
                .header("host", "localhost")
                .body(Body::empty())
                .expect("request");
            let _ = app.oneshot(request).await.expect("response");
        });
    });
    writer.contents()
}

#[test]
fn the_request_span_never_records_query_values() {
    let logged = logged_for(&format!(
        "/ui/realms/acme/magic-link?token={CANARY}&next=%2Fhome"
    ));
    assert!(
        logged.contains("/ui/realms/acme/magic-link"),
        "the span must still record the path; logged:\n{logged}"
    );
    assert!(
        !logged.contains(CANARY),
        "a one-time token from the query string reached the log:\n{logged}"
    );
    assert!(
        logged.contains("token="),
        "parameter names are kept for debugging; logged:\n{logged}"
    );
}

/// A value with no name (`?<token>`), or a token used as the name, is still a
/// value: neither may be recorded.
#[test]
fn bare_and_oversized_query_entries_are_not_recorded() {
    let logged = logged_for(&format!("/ui/setup?{CANARY}&{CANARY}=1&ok=2"));
    assert!(
        !logged.contains(CANARY),
        "a bare query entry reached the log:\n{logged}"
    );
    assert!(
        logged.contains("ok="),
        "short names are kept; logged:\n{logged}"
    );
}

#[test]
fn federation_callback_code_and_state_are_not_recorded() {
    let logged = logged_for(&format!(
        "/ui/realms/acme/federation/callback?code={CANARY}&state=S-{CANARY}"
    ));
    assert!(
        !logged.contains(CANARY),
        "an authorization code or state value reached the log:\n{logged}"
    );
}
