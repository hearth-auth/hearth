//! HTTP/HTTPS server startup and shutdown helpers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::Router;
use tokio::net::TcpListener;
use tracing::info;
use tracing::{debug, error, warn};

use super::limits::{apply_request_timeout, connection_gate, server_limits};
use super::state::AppState;

pub async fn serve(
    addr: SocketAddr,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    serve_router(addr, super::router(state), shutdown).await
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
    serve_router_on(listener, app, shutdown).await
}

/// Starts the HTTP server on a pre-bound listener.
///
/// Variant of [`serve_router`] for callers that need to know the assigned port
/// before serving (and for tests, which bind `127.0.0.1:0`). Binding outside
/// this function also removes the bind/connect TOCTOU that a
/// "bind, read port, drop, re-bind" dance would introduce.
///
/// # Operational limits
///
/// This loop applies the same limits as
/// [`serve_tls_router`] — the request deadline from
/// `operational.request_timeout_secs`, the admission cap from
/// `operational.max_connections` / `operational.queue_depth`, and the HTTP/2
/// rapid-reset caps from `security.http2.*`. It used to call `axum::serve`,
/// which applies no HTTP/2 configuration at all, so the caps existed on the TLS
/// listener only (audit 2026-08-28 §4.12#20).
///
/// # Shutdown
///
/// Draining is preserved: every accepted connection is watched by a
/// [`hyper_util::server::graceful::GracefulShutdown`], the accept loop stops on
/// the shutdown future, and this function then waits for in-flight exchanges to
/// finish. The caller (`main.rs`) still owns the drain deadline.
///
/// # Errors
///
/// Returns the same errors as [`serve_router`].
pub async fn serve_router_on(
    listener: TcpListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    let local_addr = listener.local_addr()?;
    let limits = server_limits();

    info!(
        %local_addr,
        request_timeout_secs = limits.request_timeout.as_secs(),
        max_connections = limits.max_connections,
        "HTTP server listening"
    );

    let app = apply_request_timeout(app);
    let gate = connection_gate();
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);

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

                let app = app.clone();
                let gate = Arc::clone(&gate);
                let watcher = graceful.watcher();

                tokio::spawn(async move {
                    // Admission happens inside the task so a saturated server
                    // still drains its accept backlog instead of wedging the
                    // listener.
                    let Some(_permit) = gate.admit().await else {
                        debug!(
                            peer = %peer_addr,
                            "refusing connection: operational.max_connections + \
                             operational.queue_depth exhausted"
                        );
                        drop(stream);
                        return;
                    };

                    let io = hyper_util::rt::TokioIo::new(stream);
                    // Matches what `into_make_service_with_connect_info` did on
                    // this path before, so handlers still see the real peer via
                    // `PeerAddr` / `ConnectInfo<SocketAddr>` (HEA-2164).
                    let service = hyper_util::service::TowerToHyperService::new(
                        app.layer(axum::Extension(ConnectInfo::<SocketAddr>(peer_addr)))
                            .into_service(),
                    );

                    let mut builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    builder
                        .http2()
                        .max_concurrent_streams(limits.http2_max_concurrent_streams)
                        .max_pending_accept_reset_streams(Some(
                            limits.http2_max_pending_reset_streams,
                        ));

                    let conn = builder.serve_connection_with_upgrades(io, service).into_owned();
                    if let Err(e) = watcher.watch(conn).await {
                        debug!(peer = %peer_addr, error = %e, "connection error");
                    }
                });
            }
            () = &mut shutdown => {
                info!("HTTP server shutting down, draining in-flight requests");
                break;
            }
        }
    }

    graceful.shutdown().await;
    info!("HTTP server drained all in-flight requests");
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
    drain_timeout: Duration,
) -> Result<(), std::io::Error> {
    serve_tls_router(
        listener,
        super::router(state),
        tls_acceptor,
        shutdown,
        drain_timeout,
    )
    .await
}

/// Starts the HTTPS server with a pre-built router.
///
/// Variant of [`serve_tls`] that accepts an already-assembled axum
/// [`Router`] so callers can merge in additional routers (e.g. the web
/// UI adapter under `/ui/*`) before handing the final tree to axum.
///
/// # Shutdown
///
/// On the shutdown signal the accept loop stops taking new connections and
/// then **drains**: every connection already accepted is told to finish its
/// current exchange and close, and this function waits for all of them.
///
/// It used to `break` and return `Ok(())` on the signal instead, abandoning
/// every spawned connection task. An in-flight request was cut off mid-response
/// and the process still exited 0 (audit 2026-08-28 §4.11#9). The plaintext
/// path never had this defect: `axum::serve` drains for it.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::TimedOut`] when connections are still open
/// after `drain_timeout`, so the caller can exit non-zero rather than report a
/// truncated shutdown as a clean one. Otherwise returns the same errors as
/// [`serve_tls`].
pub async fn serve_tls_router(
    listener: TcpListener,
    app: Router,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    shutdown: tokio::sync::watch::Receiver<()>,
    drain_timeout: Duration,
) -> Result<(), std::io::Error> {
    let local_addr = listener.local_addr()?;
    let limits = server_limits();

    info!(
        %local_addr,
        request_timeout_secs = limits.request_timeout.as_secs(),
        max_connections = limits.max_connections,
        "HTTPS server listening"
    );

    let app = apply_request_timeout(app);
    let gate = connection_gate();
    // Watches every accepted connection so the drain below can both signal
    // them to finish and wait for them.
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();

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
                let gate = Arc::clone(&gate);
                // A watcher, not the whole handle: the TLS handshake happens
                // inside the spawned task, and a handshake that never completes
                // must not hold the drain open.
                let watcher = graceful.watcher();

                tokio::spawn(async move {
                    // Admission before the handshake: an unadmitted connection
                    // must not consume a TLS handshake's worth of CPU.
                    let Some(_permit) = gate.admit().await else {
                        debug!(
                            peer = %peer_addr,
                            "refusing connection: operational.max_connections + \
                             operational.queue_depth exhausted"
                        );
                        drop(stream);
                        return;
                    };
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                            return;
                        }
                    };

                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    // Mirror what `into_make_service_with_connect_info` does on the
                    // plaintext path: layer `ConnectInfo<SocketAddr>` onto the router
                    // before calling `into_service`. This ensures every handler sees
                    // the real peer address via `PeerAddr` / `ConnectInfo<SocketAddr>`
                    // rather than the FALLBACK_PEER sentinel (127.0.0.1).
                    let service = hyper_util::service::TowerToHyperService::new(
                        app.layer(axum::Extension(ConnectInfo::<SocketAddr>(peer_addr)))
                            .into_service(),
                    );

                    // A-39: HTTP/2 rapid-reset defense (CVE-2023-44487).
                    // Cap concurrent streams and RST_STREAM budget to limit
                    // the amplification factor of rapid-reset attacks.
                    let mut builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    builder
                        .http2()
                        .max_concurrent_streams(limits.http2_max_concurrent_streams)
                        .max_pending_accept_reset_streams(Some(
                            limits.http2_max_pending_reset_streams,
                        ));

                    let conn = builder.serve_connection(io, service).into_owned();
                    if let Err(e) = watcher.watch(conn).await {
                        debug!(peer = %peer_addr, error = %e, "connection error");
                    }
                });
            }
            _ = shutdown_rx.changed() => {
                info!(
                    drain_deadline_secs = drain_timeout.as_secs(),
                    "HTTPS server shutting down, draining in-flight requests"
                );
                break;
            }
        }
    }

    // Signal every watched connection to finish, then wait for them.
    tokio::select! {
        () = graceful.shutdown() => {
            info!("HTTPS server drained all in-flight requests");
            Ok(())
        }
        () = tokio::time::sleep(drain_timeout) => {
            warn!(
                drain_deadline_secs = drain_timeout.as_secs(),
                "HTTPS graceful drain deadline exceeded, forcing shutdown"
            );
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "HTTPS graceful drain did not complete within the shutdown timeout",
            ))
        }
    }
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
