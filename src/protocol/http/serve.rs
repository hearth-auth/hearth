//! HTTP/HTTPS server startup and shutdown helpers.
//!
//! # Connection hardening (GA audit 2026-09-28 B6)
//!
//! Every listener here — plaintext, TLS and the HTTP→HTTPS redirect — runs the
//! same accept loop, [`accept_until`], so a limit cannot land on one listener
//! and miss another. Before it, one unauthenticated client held every
//! connection slot: 1100 sockets that each sent a partial request made
//! `/health` time out, and after 40 s the server had closed none of them.
//! Each accepted connection now passes, in order:
//!
//! 1. the per-address cap (`operational.max_connections_per_ip`), checked
//!    synchronously in the accept loop so a refused connection costs no task;
//! 2. the admission gate (`operational.max_connections` / `queue_depth`);
//! 3. on TLS, a handshake deadline (`operational.tls_handshake_timeout_secs`);
//! 4. a first-bytes deadline and hyper's HTTP/1 header-read timeout
//!    (`operational.header_read_timeout_secs`), which also bounds idle
//!    keep-alive connections; HTTP/2 connections get keep-alive pings.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::Router;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::info;
use tracing::{debug, error, warn};

use super::conn_guard::FirstBytesDeadline;
use super::limits::{
    apply_request_timeout, connection_gate, per_ip_limiter, server_limits, ConnectionGate,
    ServerLimits,
};
use super::state::AppState;

/// How long an HTTP/2 peer has to acknowledge a keep-alive `PING`.
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

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
/// `operational.max_connections` / `operational.queue_depth`, the connection
/// hardening described in the module docs, and the HTTP/2 rapid-reset caps
/// from `security.http2.*`.
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
        max_connections_per_ip = limits.max_connections_per_ip,
        header_read_timeout_secs = limits.header_read_timeout.as_secs(),
        "HTTP server listening"
    );

    let app = apply_request_timeout(app);
    let graceful = GracefulShutdown::new();
    accept_until(
        &listener,
        &app,
        None,
        &connection_gate(),
        true,
        &graceful,
        shutdown,
    )
    .await;
    info!("HTTP server shutting down, draining in-flight requests");

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
/// and the process still exited 0 (audit 2026-08-28 §4.11#9).
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
        max_connections_per_ip = limits.max_connections_per_ip,
        header_read_timeout_secs = limits.header_read_timeout.as_secs(),
        tls_handshake_timeout_secs = limits.tls_handshake_timeout.as_secs(),
        "HTTPS server listening"
    );

    let app = apply_request_timeout(app);
    // Watches every accepted connection so the drain below can both signal
    // them to finish and wait for them.
    let graceful = GracefulShutdown::new();

    let mut shutdown_rx = shutdown;
    accept_until(
        &listener,
        &app,
        Some(&tls_acceptor),
        &connection_gate(),
        false,
        &graceful,
        async move {
            let _ = shutdown_rx.changed().await;
        },
    )
    .await;
    info!(
        drain_deadline_secs = drain_timeout.as_secs(),
        "HTTPS server shutting down, draining in-flight requests"
    );

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

/// Accepts connections on `listener` until `shutdown` resolves, serving each
/// on its own task behind the per-address cap, `gate`, and (with `tls`) a
/// handshake deadline.
///
/// Every connection is registered with `graceful`; the caller drains it.
async fn accept_until(
    listener: &TcpListener,
    app: &Router,
    tls: Option<&tokio_rustls::TlsAcceptor>,
    gate: &Arc<ConnectionGate>,
    upgrades: bool,
    graceful: &GracefulShutdown,
    shutdown: impl Future<Output = ()>,
) {
    let limits = server_limits();
    let per_ip = per_ip_limiter();
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

                prepare_accepted(&stream);

                // Synchronous and first: a client already at its allowance
                // costs neither a task nor a place in the admission queue.
                let Some(ip_guard) = per_ip.try_acquire(peer_addr.ip()) else {
                    debug!(
                        peer = %peer_addr,
                        "refusing connection: operational.max_connections_per_ip reached"
                    );
                    drop(stream);
                    continue;
                };

                let app = app.clone();
                let gate = Arc::clone(gate);
                let tls = tls.cloned();
                let limits = limits.clone();
                // A watcher, not the whole handle: the TLS handshake happens
                // inside the spawned task, and a handshake that never completes
                // must not hold the drain open.
                let watcher = graceful.watcher();

                tokio::spawn(async move {
                    // Held for the connection's lifetime.
                    let _ip_guard = ip_guard;
                    // Admission happens inside the task so a saturated server
                    // still drains its accept backlog instead of wedging the
                    // listener — and before the handshake, so an unadmitted
                    // connection does not consume a TLS handshake's worth of CPU.
                    let Some(_permit) = gate.admit().await else {
                        debug!(
                            peer = %peer_addr,
                            "refusing connection: operational.max_connections + \
                             operational.queue_depth exhausted"
                        );
                        drop(stream);
                        return;
                    };

                    let Some(acceptor) = tls else {
                        serve_connection(stream, peer_addr, app, &limits, upgrades, watcher).await;
                        return;
                    };
                    // B6: the handshake used to be awaited with no deadline
                    // while holding the permit taken above.
                    let tls_stream = match tokio::time::timeout(
                        limits.tls_handshake_timeout,
                        acceptor.accept(stream),
                    )
                    .await
                    {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                            return;
                        }
                        Err(_elapsed) => {
                            debug!(
                                peer = %peer_addr,
                                "TLS handshake exceeded operational.tls_handshake_timeout_secs"
                            );
                            return;
                        }
                    };
                    serve_connection(tls_stream, peer_addr, app, &limits, upgrades, watcher).await;
                });
            }
            () = &mut shutdown => break,
        }
    }
}

/// Sets the socket options every accepted connection needs.
///
/// `TCP_NODELAY`: TLS records and HTTP/2 frames leave in separate small
/// writes. With Nagle's algorithm on, each waits for the ACK of the one before,
/// and a client that delays its ACKs stalls the response by about 40 ms.
/// A failure only costs that latency, so it is logged and the connection kept.
fn prepare_accepted(stream: &tokio::net::TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!(error = %e, "could not set TCP_NODELAY on an accepted connection");
    }
}

/// Serves HTTP/1.1 and HTTP/2 on one admitted connection until it closes.
async fn serve_connection<IO>(
    io: IO,
    peer_addr: SocketAddr,
    app: Router,
    limits: &ServerLimits,
    upgrades: bool,
    watcher: Watcher,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = hyper_util::rt::TokioIo::new(FirstBytesDeadline::new(io, limits.header_read_timeout));
    // Add `ConnectInfo<SocketAddr>` to every request so each handler sees the
    // real peer via `PeerAddr` / `ConnectInfo<SocketAddr>` rather than the
    // FALLBACK_PEER sentinel (HEA-2164). The extension wraps the router once:
    // `Router::layer` re-wraps every route, which gave each connection its own
    // copy of the route table (~550 KB with the full router).
    let service = hyper_util::service::TowerToHyperService::new(tower::Layer::layer(
        &axum::Extension(ConnectInfo::<SocketAddr>(peer_addr)),
        app,
    ));

    let builder = connection_builder(limits);
    let result = if upgrades {
        watcher
            .watch(
                builder
                    .serve_connection_with_upgrades(io, service)
                    .into_owned(),
            )
            .await
    } else {
        watcher
            .watch(builder.serve_connection(io, service).into_owned())
            .await
    };
    if let Err(e) = result {
        debug!(peer = %peer_addr, error = %e, "connection error");
    }
}

/// The hyper connection builder every listener uses.
fn connection_builder(
    limits: &ServerLimits,
) -> hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor> {
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    // B6: hyper applies no header-read timeout without a timer. The timeout
    // also closes an HTTP/1.1 keep-alive connection left idle that long.
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);
    // A-39: HTTP/2 rapid-reset defense (CVE-2023-44487) — cap concurrent
    // streams and the RST_STREAM budget. Keep-alive pings drop dead peers.
    builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .max_concurrent_streams(limits.http2_max_concurrent_streams)
        .max_pending_accept_reset_streams(Some(limits.http2_max_pending_reset_streams))
        .keep_alive_interval(limits.http2_keepalive_interval)
        .keep_alive_timeout(HTTP2_KEEPALIVE_TIMEOUT);
    builder
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
///
/// The redirect listener runs the same hardened accept loop as the others
/// (B6), with an admission gate of its own so a flood on port 80 cannot take
/// the HTTPS listener's slots.
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

    let limits = server_limits();
    let gate = Arc::new(ConnectionGate::new(
        limits.max_connections,
        limits.queue_depth,
    ));
    let graceful = GracefulShutdown::new();
    accept_until(&listener, &app, None, &gate, false, &graceful, shutdown).await;
    graceful.shutdown().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // TLS records and HTTP/2 frames leave in separate small writes. With
    // Nagle's algorithm on, such a write waits for the ACK of the one before,
    // and a client that delays its ACKs stalls the response by about 40 ms.
    #[tokio::test]
    async fn an_accepted_connection_turns_off_nagle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (stream, _) = listener.accept().await.expect("accept");
        assert!(
            !stream.nodelay().expect("read TCP_NODELAY"),
            "precondition: a new socket starts with Nagle's algorithm on"
        );

        prepare_accepted(&stream);

        assert!(
            stream.nodelay().expect("read TCP_NODELAY"),
            "an accepted connection must set TCP_NODELAY"
        );
    }
}
