//! Raft peer gRPC server: listens for incoming RPCs from cluster peers,
//! authenticates them via mutual TLS, and forwards to the local Raft node.
//!
//! The server is independent of the generic openraft `Raft<C, ...>` type by
//! accepting an `Arc<dyn IncomingRpcDispatch>` — callers wire this up once the
//! full Raft engine is initialised (see HEA-600).

use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::server::TcpIncoming;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use crate::cluster::rpc::{
    raft_service_server::{RaftService, RaftServiceServer},
    AppendEntriesRequest, AppendEntriesResponse, ForwardWriteRequest, ForwardWriteResponse,
    InstallSnapshotRequest, InstallSnapshotResponse, VoteRequest, VoteResponse,
};
use crate::cluster::wire::MAX_PEER_MESSAGE_BYTES;
use crate::config::ClusterConfig;

// ── IncomingRpcDispatch ───────────────────────────────────────────────────────

/// Dispatch interface for incoming peer RPCs.
///
/// Implemented by the Raft engine integration once a `openraft::Raft` handle
/// is available. Until then, the server returns `UNAVAILABLE`.
pub trait IncomingRpcDispatch: Send + Sync + 'static {
    /// Handle an `AppendEntries` RPC from the cluster leader.
    fn append_entries(
        &self,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;

    /// Handle a `Vote` RPC from a cluster candidate.
    fn vote(
        &self,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;

    /// Handle one snapshot chunk from the leader.
    /// Payload is JSON-encoded `InstallSnapshotRequest<HearthRaftConfig>`.
    fn install_snapshot(
        &self,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;

    /// Handle a write a follower forwarded to this node (see
    /// [`ClusterEngine`](crate::cluster::ClusterEngine)'s write path).
    ///
    /// Payload is a JSON-encoded [`RaftCommand`](crate::cluster::RaftCommand);
    /// the answer is a JSON-encoded
    /// [`ForwardedWriteOutcome`](crate::cluster::ForwardedWriteOutcome). Every
    /// refusal the receiver decides on travels in-band in that outcome, so an
    /// `Err` here means only that the answer could not be encoded.
    fn forward_write(
        &self,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;
}

// ── RaftRpcHandler ────────────────────────────────────────────────────────────

/// tonic service handler that forwards requests to an [`IncomingRpcDispatch`].
#[derive(Clone)]
pub struct RaftRpcHandler<D> {
    dispatch: Arc<D>,
}

impl<D: IncomingRpcDispatch> RaftRpcHandler<D> {
    /// Creates a handler wrapping the given dispatcher.
    pub fn new(dispatch: Arc<D>) -> Self {
        Self { dispatch }
    }
}

#[tonic::async_trait]
impl<D: IncomingRpcDispatch> RaftService for RaftRpcHandler<D> {
    async fn append_entries(
        &self,
        request: Request<AppendEntriesRequest>,
    ) -> Result<Response<AppendEntriesResponse>, Status> {
        let payload = request.into_inner().payload;
        debug!("received AppendEntries from peer");

        self.dispatch
            .append_entries(&payload)
            .await
            .map(|resp| Response::new(AppendEntriesResponse { payload: resp }))
            .map_err(|e| {
                warn!(error = %e, "AppendEntries dispatch error");
                Status::internal(e)
            })
    }

    async fn vote(&self, request: Request<VoteRequest>) -> Result<Response<VoteResponse>, Status> {
        let payload = request.into_inner().payload;
        debug!("received Vote from peer");

        self.dispatch
            .vote(&payload)
            .await
            .map(|resp| Response::new(VoteResponse { payload: resp }))
            .map_err(|e| {
                warn!(error = %e, "Vote dispatch error");
                Status::internal(e)
            })
    }

    async fn install_snapshot(
        &self,
        request: Request<InstallSnapshotRequest>,
    ) -> Result<Response<InstallSnapshotResponse>, Status> {
        let payload = request.into_inner().payload;
        debug!("received InstallSnapshot chunk from peer");

        self.dispatch
            .install_snapshot(&payload)
            .await
            .map(|resp| Response::new(InstallSnapshotResponse { payload: resp }))
            .map_err(|e| {
                warn!(error = %e, "InstallSnapshot dispatch error");
                Status::internal(e)
            })
    }

    async fn forward_write(
        &self,
        request: Request<ForwardWriteRequest>,
    ) -> Result<Response<ForwardWriteResponse>, Status> {
        let payload = request.into_inner().payload;
        debug!("received ForwardWrite from peer");

        self.dispatch
            .forward_write(&payload)
            .await
            .map(|resp| Response::new(ForwardWriteResponse { payload: resp }))
            .map_err(|e| {
                warn!(error = %e, "ForwardWrite dispatch error");
                Status::internal(e)
            })
    }
}

// ── serve ─────────────────────────────────────────────────────────────────────

/// Starts the Raft peer gRPC server bound to `config.peer_address`.
///
/// Requires `tls_cert_path`, `tls_key_path`, and `tls_ca_cert_path` to be
/// readable PEM files. Enforces mutual TLS — unauthenticated peers are
/// rejected at the TLS handshake.
///
/// Returns when the server shuts down (caller should run this in a task).
pub async fn serve<D: IncomingRpcDispatch>(
    config: &ClusterConfig,
    dispatch: Arc<D>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_with_shutdown(config, dispatch, std::future::pending()).await
}

/// Variant of [`serve`] that stops accepting peer RPCs and returns once
/// `shutdown` resolves (GA audit 2026-09-28 L24: the peer server used to run
/// until the process exited, outside the graceful drain).
///
/// # Errors
///
/// Returns an error when [`PeerServer::bind`] fails or the server fails.
pub async fn serve_with_shutdown<D, F>(
    config: &ClusterConfig,
    dispatch: Arc<D>,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    D: IncomingRpcDispatch,
    F: std::future::Future<Output = ()>,
{
    PeerServer::bind(config)
        .await?
        .serve_with_shutdown(dispatch, shutdown)
        .await
}

/// The Raft peer gRPC server, bound and ready to serve.
///
/// [`PeerServer::bind`] does every step that can fail on a bad config: it
/// reads the TLS material, parses `peer_address` and binds it. `serve` awaits
/// it before it spawns the server, so a node that cannot take part in the
/// cluster exits at start-up. The spawned task used to do all of this and
/// only log an error, and the node went on serving without a peer server.
pub struct PeerServer {
    server: Server,
    incoming: TcpIncoming,
    addr: SocketAddr,
    node_id: u64,
}

impl PeerServer {
    /// Reads the peer TLS material and binds `config.peer_address`.
    ///
    /// # Errors
    ///
    /// Returns an error, naming the file or the address, when a TLS file
    /// cannot be read, the TLS material is unusable, `peer_address` is not
    /// an IP address and port, or the bind fails (for example, port in use).
    pub async fn bind(
        config: &ClusterConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let read = |path: &std::path::Path| {
            let path = path.to_path_buf();
            async move {
                tokio::fs::read(&path)
                    .await
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))
            }
        };
        let cert = read(&config.tls_cert_path).await?;
        let key = read(&config.tls_key_path).await?;
        let ca = read(&config.tls_ca_cert_path).await?;

        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .client_ca_root(Certificate::from_pem(ca));
        let server = Server::builder().tls_config(tls)?;

        let addr: SocketAddr = config
            .peer_address
            .parse()
            .map_err(|e| format!("invalid peer_address '{}': {e}", config.peer_address))?;
        // The settings tonic's own `serve` binds with: TCP_NODELAY on, no
        // keepalive.
        let incoming = TcpIncoming::bind(addr)
            .map_err(|e| format!("cannot bind peer_address '{addr}': {e}"))?
            .with_nodelay(Some(true));
        let addr = incoming.local_addr().unwrap_or(addr);

        Ok(Self {
            server,
            incoming,
            addr,
            node_id: config.node_id,
        })
    }

    /// The bound address (useful when `peer_address` names port 0).
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Serves peer RPCs until `shutdown` resolves.
    ///
    /// # Errors
    ///
    /// Returns an error when the server fails.
    pub async fn serve_with_shutdown<D, F>(
        mut self,
        dispatch: Arc<D>,
        shutdown: F,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        D: IncomingRpcDispatch,
        F: std::future::Future<Output = ()>,
    {
        info!(
            node_id = self.node_id,
            addr = %self.addr,
            "Raft peer gRPC server starting (mTLS)"
        );

        self.server
            .add_service(
                RaftServiceServer::new(RaftRpcHandler::new(dispatch))
                    .max_decoding_message_size(MAX_PEER_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_PEER_MESSAGE_BYTES),
            )
            .serve_with_incoming_shutdown(self.incoming, shutdown)
            .await?;

        Ok(())
    }
}

// ── NoopDispatch (test helper) ────────────────────────────────────────────────

/// A no-op dispatcher that returns UNAVAILABLE for all RPCs.
///
/// Useful in tests and before the Raft engine is initialised.
#[derive(Clone)]
pub struct NoopDispatch;

impl IncomingRpcDispatch for NoopDispatch {
    async fn append_entries(&self, _payload: &[u8]) -> Result<Vec<u8>, String> {
        Err("Raft engine not initialised".to_string())
    }

    async fn vote(&self, _payload: &[u8]) -> Result<Vec<u8>, String> {
        Err("Raft engine not initialised".to_string())
    }

    async fn install_snapshot(&self, _payload: &[u8]) -> Result<Vec<u8>, String> {
        Err("Raft engine not initialised".to_string())
    }

    async fn forward_write(&self, _payload: &[u8]) -> Result<Vec<u8>, String> {
        Err("Raft engine not initialised".to_string())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies the handler can be created and cloned (tonic requires Clone).
    #[test]
    fn handler_is_clone() {
        let handler = RaftRpcHandler::new(Arc::new(NoopDispatch));
        let _clone = handler.clone();
    }

    /// Verifies NoopDispatch returns an error rather than panicking.
    #[tokio::test]
    async fn noop_dispatch_returns_error() {
        let d = NoopDispatch;
        let result = d.append_entries(b"{}").await;
        assert!(result.is_err());
    }
}
