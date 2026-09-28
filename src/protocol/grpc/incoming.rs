//! Hardened connection stream for the gRPC management listener.
//!
//! GA audit 2026-09-28:
//!
//! * **M14** — the listener was always plaintext. [`GrpcIncoming`] performs the
//!   TLS handshake with the same acceptor (and so the same, hot-reloadable
//!   certificate) as the HTTPS listener when one is supplied.
//! * **B6 sibling** — the listener had no connection cap and no deadlines. Each
//!   connection now passes the per-address cap, an admission gate of its own
//!   (so a gRPC flood cannot take the HTTP listener's slots), a TLS handshake
//!   deadline, and a deadline for the HTTP/2 preface.
//!
//! Accepting and handshaking run on a background task that feeds a bounded
//! channel, so one slow handshake never blocks the accept loop.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit};
use tokio::task::JoinHandle;
use tonic::transport::server::{Connected, TcpConnectInfo};
use tracing::debug;

use crate::protocol::http::conn_guard::{FirstBytesDeadline, PerIpGuard, PerIpLimiter};
use crate::protocol::http::limits::{server_limits, ConnectionGate};

/// Connections handed to tonic but not yet picked up.
const HANDOFF_BUFFER: usize = 64;

/// A plaintext or TLS-terminated TCP stream.
enum MaybeTls {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            Self::Tls(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// One admitted gRPC connection. Holds its per-address and admission slots
/// until tonic drops it.
pub(crate) struct GrpcConn {
    io: FirstBytesDeadline<MaybeTls>,
    local_addr: Option<SocketAddr>,
    remote_addr: SocketAddr,
    _permit: OwnedSemaphorePermit,
    _ip_guard: PerIpGuard,
}

impl Connected for GrpcConn {
    // Same connect info as a bare `TcpStream`, so `Request::remote_addr()` —
    // which the per-IP rate-limit interceptor reads — keeps working over TLS.
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        TcpConnectInfo {
            local_addr: self.local_addr,
            remote_addr: Some(self.remote_addr),
        }
    }
}

impl AsyncRead for GrpcConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for GrpcConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// The stream of admitted connections tonic serves.
///
/// Dropping it stops the background accept task.
pub(crate) struct GrpcIncoming {
    rx: mpsc::Receiver<GrpcConn>,
    accept_task: JoinHandle<()>,
}

impl GrpcIncoming {
    /// Starts accepting on `listener`, terminating TLS with `tls` when given.
    ///
    /// Stops accepting once `stop` changes (or its sender is dropped).
    #[must_use]
    pub(crate) fn start(
        listener: TcpListener,
        tls: Option<tokio_rustls::TlsAcceptor>,
        stop: watch::Receiver<()>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(HANDOFF_BUFFER);
        let accept_task = tokio::spawn(accept_loop(listener, tls, tx, stop));
        Self { rx, accept_task }
    }
}

impl Drop for GrpcIncoming {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

impl tokio_stream::Stream for GrpcIncoming {
    type Item = Result<GrpcConn, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().rx.poll_recv(cx).map(|conn| conn.map(Ok))
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    tx: mpsc::Sender<GrpcConn>,
    mut stop: watch::Receiver<()>,
) {
    let limits = server_limits();
    // Separate from the HTTP listeners' gate and per-address map: the gRPC
    // listener is its own surface and must not starve (or be starved by) HTTP.
    let gate = Arc::new(ConnectionGate::new(
        limits.max_connections,
        limits.queue_depth,
    ));
    let per_ip = PerIpLimiter::new(limits.max_connections_per_ip, limits.per_ip_exempt.clone());
    let local_addr = listener.local_addr().ok();

    loop {
        let (stream, remote_addr) = tokio::select! {
            result = listener.accept() => match result {
                Ok(conn) => conn,
                Err(e) => {
                    debug!(error = %e, "gRPC: failed to accept TCP connection");
                    continue;
                }
            },
            _ = stop.changed() => return,
        };

        let Some(ip_guard) = per_ip.try_acquire(remote_addr.ip()) else {
            debug!(
                peer = %remote_addr,
                "gRPC: refusing connection: operational.max_connections_per_ip reached"
            );
            continue;
        };

        let gate = Arc::clone(&gate);
        let tls = tls.clone();
        let tx = tx.clone();
        let limits = limits.clone();
        tokio::spawn(async move {
            let Some(permit) = gate.admit().await else {
                debug!(
                    peer = %remote_addr,
                    "gRPC: refusing connection: operational.max_connections + \
                     operational.queue_depth exhausted"
                );
                return;
            };
            let io = match tls {
                None => MaybeTls::Plain(stream),
                Some(acceptor) => {
                    match tokio::time::timeout(
                        limits.tls_handshake_timeout,
                        acceptor.accept(stream),
                    )
                    .await
                    {
                        Ok(Ok(s)) => MaybeTls::Tls(Box::new(s)),
                        Ok(Err(e)) => {
                            debug!(peer = %remote_addr, error = %e, "gRPC: TLS handshake failed");
                            return;
                        }
                        Err(_elapsed) => {
                            debug!(
                                peer = %remote_addr,
                                "gRPC: TLS handshake exceeded \
                                 operational.tls_handshake_timeout_secs"
                            );
                            return;
                        }
                    }
                }
            };
            let conn = GrpcConn {
                io: FirstBytesDeadline::new(io, limits.header_read_timeout),
                local_addr,
                remote_addr,
                _permit: permit,
                _ip_guard: ip_guard,
            };
            // A closed channel means the server is shutting down; the
            // connection is dropped (and its slots released) here.
            let _ = tx.send(conn).await;
        });
    }
}
