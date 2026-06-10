//! HTTP/HTTPS server startup and shutdown helpers.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::response::Redirect;
use axum::Router;
use tokio::net::TcpListener;
use tracing::info;

use super::state::AppState;


/// Starts the HTTP server on the given address.
///
/// Binds to the specified address and serves requests until the provided
/// shutdown signal resolves. Returns an error if binding or serving fails.
pub async fn serve(
    addr: SocketAddr,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    serve_router(addr, router(state), shutdown).await
}

/// Starts the HTTP server on the given address with a pre-built router.
///
/// Variant of [`serve`] that accepts an already-assembled axum [`Router`]
/// so callers can merge in additional routers (e.g. the web UI adapter
/// under `/ui/*`) before handing the final tree to axum.
///
/// # Errors
///
/// Returns the same errors as [`serve`].
pub async fn serve_router(
    addr: SocketAddr,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;

    info!(%local_addr, "HTTP server listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;

    Ok(())
}

/// Starts the HTTPS server on a pre-bound listener with TLS termination.
///
/// Accepts TCP connections, performs TLS handshakes using the provided
/// `TlsAcceptor`, then serves HTTP/1.1 and HTTP/2 requests via the axum
/// router. Each connection is spawned independently — a failed handshake
/// does not block other connections.
pub async fn serve_tls(
    listener: TcpListener,
    state: Arc<AppState>,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    shutdown: tokio::sync::watch::Receiver<()>,
) -> Result<(), std::io::Error> {
    serve_tls_router(listener, router(state), tls_acceptor, shutdown).await
}

/// Starts the HTTPS server with a pre-built router.
///
/// Variant of [`serve_tls`] that accepts an already-assembled axum
/// [`Router`] so callers can merge in additional routers (e.g. the web
/// UI adapter under `/ui/*`) before handing the final tree to axum.
///
/// # Errors
///
/// Returns the same errors as [`serve_tls`].
pub async fn serve_tls_router(
    listener: TcpListener,
    app: Router,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    shutdown: tokio::sync::watch::Receiver<()>,
) -> Result<(), std::io::Error> {
    let local_addr = listener.local_addr()?;

    info!(%local_addr, "HTTPS server listening");

    let mut shutdown_rx = shutdown;
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!(error = %e, "failed to accept TCP connection");
                        continue;
                    }
                };

                let acceptor = tls_acceptor.clone();
                let app = app.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                            return;
                        }
                    };

                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(
                        app.into_service(),
                    );

                    // A-39: HTTP/2 rapid-reset defense (CVE-2023-44487).
                    // Cap concurrent streams and RST_STREAM budget to limit
                    // the amplification factor of rapid-reset attacks.
                    let mut builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    builder
                        .http2()
                        .max_concurrent_streams(HTTP2_MAX_CONCURRENT_STREAMS)
                        .max_pending_accept_reset_streams(Some(
                            HTTP2_MAX_PENDING_RESET_STREAMS,
                        ));

                    if let Err(e) = builder.serve_connection(io, service).await {
                        debug!(peer = %peer_addr, error = %e, "connection error");
                    }
                });
            }
            _ = shutdown_rx.changed() => {
                info!("HTTPS server shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// Starts an HTTP server that redirects all requests to HTTPS via 301.
///
/// Accepts connections on the given pre-bound `listener` and responds to every
/// request with a `301 Moved Permanently` redirect to the HTTPS equivalent URL
/// on the given `https_port`.
///
/// The caller is responsible for binding the listener; this function does not
/// call `bind()` internally so callers can detect the assigned port before
/// invoking this function.
pub async fn serve_redirect(
    listener: TcpListener,
    https_port: u16,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    let app = Router::new().fallback(move |req: axum::extract::Request| async move {
        let host = req
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");

        // Strip port from host if present
        let hostname = host.split(':').next().unwrap_or(host);
        let path = req.uri().path();
        let query = req
            .uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();

        let location = if https_port == 443 {
            format!("https://{hostname}{path}{query}")
        } else {
            format!("https://{hostname}:{https_port}{path}{query}")
        };

        (
            StatusCode::MOVED_PERMANENTLY,
            [(axum::http::header::LOCATION, location)],
        )
    });

    let local_addr = listener.local_addr()?;
    info!(%local_addr, "HTTP→HTTPS redirect server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}

// === JSON helpers ===

/// Serializes a proto type to a `serde_json::Value` with int64 fields
/// emitted as JSON numbers instead of strings.
///
/// pbjson follows the proto3 JSON mapping spec which encodes int64/uint64
/// as strings to avoid IEEE 754 precision loss. REST APIs conventionally
/// use numeric JSON values, so this helper post-processes the serialized
/// JSON to convert string-encoded integers back to numbers.
fn proto_to_rest_json<T: Serialize>(value: &T) -> serde_json::Value {
    match serde_json::to_value(value) {
        Ok(v) => coerce_string_ints(v),
        Err(e) => {
            tracing::error!(error = %e, "proto serialization failed");
            serde_json::Value::Null
        }
    }
}

/// Recursively converts string values that represent integers to JSON numbers.
fn coerce_string_ints(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(ref s) => {
            if let Ok(n) = s.parse::<i64>() {
                serde_json::Value::Number(n.into())
            } else {
                v
            }
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, coerce_string_ints(v)))
                .collect(),
        ),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(coerce_string_ints).collect())
        }
        other => other,
    }
}

// === Observability middleware ===

/// Tower middleware that records HTTP request latency into the Prometheus
/// `hearth_http_request_duration_seconds` histogram.
///
/// Must be applied via [`Router::route_layer`] so that [`MatchedPath`] is
/// already populated by the router before this middleware runs. Routes without
/// a matched pattern (e.g. 404s) fall back to the raw URI path.
pub(crate) async fn track_metrics(request: Request, next: Next) -> Response {
