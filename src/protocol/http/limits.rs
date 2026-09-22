//! Operational and HTTP/2 limits applied to both listeners.
//!
//! # What was wrong
//!
//! `operational.request_timeout_secs`, `operational.max_connections` and
//! `operational.queue_depth` parsed into
//! [`OperationalConfig`](crate::config::OperationalConfig), were validated at
//! startup, were documented in `docs/specs/CONFIGURATION.md` — and were then
//! read by nothing. A 38-second socket transcript ran to completion against a
//! configured 5-second timeout (audit 2026-08-28 §4.4#3). `security.http2.*`
//! had the same shape: the rapid-reset caps came from compiled-in constants,
//! and they were applied only on the TLS accept loop, so the plaintext
//! listener advertised no `MAX_CONCURRENT_STREAMS` at all (§4.12#20).
//!
//! # The mechanism
//!
//! [`ServerLimits`] is installed once at startup by `main.rs` and read by both
//! [`serve_router`](super::serve_router) and
//! [`serve_tls_router`](super::serve_tls_router), so a setting cannot land on
//! one listener and miss the other. Three things hang off it:
//!
//! 1. **Request timeout** — [`apply_request_timeout`] wraps the router so a
//!    handler that has not produced response *headers* within
//!    `request_timeout_secs` is cut off with `504 Gateway Timeout`. Streaming
//!    response bodies are unaffected: the timeout covers response generation,
//!    not transmission.
//! 2. **Connection admission** — [`ConnectionGate`] caps concurrently served
//!    connections at `max_connections` and allows at most `queue_depth`
//!    connections to wait for a permit; beyond that the connection is closed
//!    immediately rather than queued without bound.
//! 3. **HTTP/2 caps** — [`ServerLimits::http2_max_concurrent_streams`] and
//!    [`ServerLimits::http2_max_pending_reset_streams`] are handed to the
//!    hyper connection builder on *both* listeners.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Default request timeout, matching `OperationalConfig::default_request_timeout_secs`.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default connection cap, matching `OperationalConfig::default_max_connections`.
const DEFAULT_MAX_CONNECTIONS: u32 = 1024;

/// Default admission backlog, matching `OperationalConfig::default_queue_depth`.
const DEFAULT_QUEUE_DEPTH: u32 = 4096;

/// Route prefixes exempt from [`ServerLimits::request_timeout`].
///
/// Backup export and restore stream multi-gigabyte archives inside the handler
/// (`BACKUP_RESTORE_BODY_LIMIT` is 4 GiB), so they legitimately outlive any
/// sane request deadline. Every other route is subject to the deadline.
const TIMEOUT_EXEMPT_PREFIXES: &[&str] = &["/admin/backup"];

/// Operational and HTTP/2 limits, resolved from `hearth.yaml` at startup.
#[derive(Debug, Clone, Copy)]
pub struct ServerLimits {
    /// Wall-clock budget for a handler to produce response headers.
    pub request_timeout: Duration,
    /// Maximum connections served concurrently on one listener.
    pub max_connections: u32,
    /// Maximum connections allowed to wait for an admission permit.
    pub queue_depth: u32,
    /// HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` advertised per connection.
    pub http2_max_concurrent_streams: u32,
    /// HTTP/2 pending-`RST_STREAM` budget per connection (CVE-2023-44487).
    pub http2_max_pending_reset_streams: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            queue_depth: DEFAULT_QUEUE_DEPTH,
            http2_max_concurrent_streams: super::HTTP2_MAX_CONCURRENT_STREAMS,
            http2_max_pending_reset_streams: super::HTTP2_MAX_PENDING_RESET_STREAMS,
        }
    }
}

/// The installed limits plus the admission gate derived from them.
struct Installed {
    limits: ServerLimits,
    gate: Arc<ConnectionGate>,
}

static INSTALLED: OnceLock<Installed> = OnceLock::new();

/// Installs the process-wide server limits.
///
/// Returns `false` when limits were already installed — the first caller wins,
/// matching the "config is immutable after startup" rule. `main.rs` calls this
/// before binding either listener; a caller that serves without installing gets
/// [`ServerLimits::default`], which reproduces the pre-fix compiled-in caps.
pub fn init_server_limits(limits: ServerLimits) -> bool {
    let gate = Arc::new(ConnectionGate::new(
        limits.max_connections,
        limits.queue_depth,
    ));
    INSTALLED.set(Installed { limits, gate }).is_ok()
}

fn installed() -> &'static Installed {
    INSTALLED.get_or_init(|| {
        let limits = ServerLimits::default();
        let gate = Arc::new(ConnectionGate::new(
            limits.max_connections,
            limits.queue_depth,
        ));
        Installed { limits, gate }
    })
}

/// Returns the installed limits, or the defaults when none were installed.
pub(crate) fn server_limits() -> ServerLimits {
    installed().limits
}

/// Returns the shared connection-admission gate.
pub(crate) fn connection_gate() -> Arc<ConnectionGate> {
    Arc::clone(&installed().gate)
}

/// Bounded connection admission.
///
/// `max_connections` permits are served concurrently. A connection that finds
/// no permit waits, but only while fewer than `queue_depth` connections are
/// already waiting; past that the gate refuses rather than growing an unbounded
/// backlog of parked tasks.
pub(crate) struct ConnectionGate {
    permits: Arc<Semaphore>,
    waiting: AtomicUsize,
    queue_depth: usize,
}

impl ConnectionGate {
    fn new(max_connections: u32, queue_depth: u32) -> Self {
        // `validate.rs` rejects zero for both, but a zero here would deadlock
        // every connection rather than fail loudly, so clamp defensively.
        let max = usize::try_from(max_connections)
            .unwrap_or(usize::MAX)
            .max(1);
        Self {
            permits: Arc::new(Semaphore::new(max)),
            waiting: AtomicUsize::new(0),
            queue_depth: usize::try_from(queue_depth).unwrap_or(usize::MAX),
        }
    }

    /// Admits one connection, or returns `None` when the backlog is full.
    ///
    /// The permit is held for the connection's lifetime; dropping it readmits
    /// one waiter.
    pub(crate) async fn admit(&self) -> Option<OwnedSemaphorePermit> {
        if let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() {
            return Some(permit);
        }

        if self.waiting.fetch_add(1, Ordering::AcqRel) >= self.queue_depth {
            self.waiting.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        let acquired = Arc::clone(&self.permits).acquire_owned().await;
        self.waiting.fetch_sub(1, Ordering::AcqRel);
        acquired.ok()
    }
}

/// Wraps `app` so every non-exempt handler is cut off at the configured
/// request timeout with `504 Gateway Timeout`.
///
/// Applied inside both serve functions rather than at router assembly so a new
/// listener cannot be added without it.
pub(crate) fn apply_request_timeout(app: Router) -> Router {
    let timeout = server_limits().request_timeout;
    app.layer(axum::middleware::from_fn(
        move |req: Request, next: Next| async move {
            let path = req.uri().path().to_owned();
            if TIMEOUT_EXEMPT_PREFIXES
                .iter()
                .any(|prefix| path.starts_with(prefix))
            {
                return next.run(req).await;
            }
            match tokio::time::timeout(timeout, next.run(req)).await {
                Ok(response) => response,
                Err(_elapsed) => {
                    tracing::warn!(
                        path = %path,
                        timeout_secs = timeout.as_secs(),
                        "request exceeded operational.request_timeout_secs"
                    );
                    timeout_response()
                }
            }
        },
    ))
}

/// The response returned when a handler outruns its deadline.
fn timeout_response() -> Response {
    (
        StatusCode::GATEWAY_TIMEOUT,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        r#"{"error":"server_error","error_description":"request timed out"}"#,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_reproduce_the_pre_fix_compiled_in_caps() {
        let limits = ServerLimits::default();
        assert_eq!(limits.http2_max_concurrent_streams, 100);
        assert_eq!(limits.http2_max_pending_reset_streams, 10);
        assert_eq!(limits.request_timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn the_gate_refuses_once_the_backlog_is_full() {
        // One permit, no queue: the second caller must be refused outright
        // rather than parked, which is the unbounded growth this closes.
        let gate = ConnectionGate::new(1, 0);
        let held = gate.admit().await.expect("first connection is admitted");
        assert!(
            gate.admit().await.is_none(),
            "a connection past max_connections + queue_depth must be refused"
        );
        drop(held);
        assert!(
            gate.admit().await.is_some(),
            "releasing a permit must readmit"
        );
    }
}
