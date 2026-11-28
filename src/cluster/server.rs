//! Raft peer gRPC server: listens for incoming RPCs from cluster peers,
//! authenticates them via mutual TLS, and forwards to the local Raft node.
//!
//! The server is independent of the generic openraft `Raft<C, ...>` type by
//! accepting an `Arc<dyn IncomingRpcDispatch>` — callers wire this up once the
//! full Raft engine is initialised (see HEA-600).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio_rustls::rustls::pki_types::CertificateDer;
use tonic::metadata::MetadataMap;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use crate::cluster::peer_identity::{
    admit, certificate_node_id, Admission, LocalPeer, PeerClaim, PeerRefusal, PeerRpc, PeerStanding,
};
use crate::cluster::types::ClusterId;

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
    /// This node's cluster ID, or `None` while it has none (a pristine node).
    fn cluster_id(&self) -> Option<ClusterId>;

    /// Where `node` stands in the membership this node holds: a voter or a
    /// learner, not a member, retired, or unknown on a pristine node.
    fn peer_standing(&self, node: u64) -> PeerStanding;

    /// Makes `id` this node's cluster ID unless it has one, durably, and
    /// returns the one it holds afterwards. Called before the RPC that
    /// carried `id` is served, so the node never answers a leader before its
    /// cluster ID is on disk.
    fn adopt_cluster_id(
        &self,
        id: ClusterId,
    ) -> impl std::future::Future<Output = Result<ClusterId, String>> + Send;

    /// Handle an `AppendEntries` RPC from the cluster leader.
    ///
    /// `leader_quorum_ack_age_ms` is the request's field of that name: how
    /// long before sending it a quorum last acknowledged the leader (see
    /// the read gate). `None` from a leader with none on record, or from an
    /// older build.
    fn append_entries(
        &self,
        payload: &[u8],
        leader_quorum_ack_age_ms: Option<u64>,
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

/// How often a node logs a refused peer RPC at `WARN`; the others in between
/// go to `DEBUG`. A refused peer retries every heartbeat.
const REFUSAL_WARN_INTERVAL_MS: u64 = 30_000;

/// tonic service handler that checks each request's peer identity, then
/// forwards it to an [`IncomingRpcDispatch`].
#[derive(Clone)]
pub struct RaftRpcHandler<D> {
    dispatch: Arc<D>,
    /// This node's ID: every RPC must name it as its target.
    node_id: u64,
    /// When this handler was made; the base of `last_refusal_warn_ms`.
    started: Instant,
    /// Milliseconds after `started` of the last refusal logged at `WARN`
    /// (`u64::MAX` before the first).
    last_refusal_warn_ms: Arc<AtomicU64>,
}

impl<D: IncomingRpcDispatch> RaftRpcHandler<D> {
    /// Creates a handler for node `node_id`, wrapping the given dispatcher.
    pub fn new(node_id: u64, dispatch: Arc<D>) -> Self {
        Self {
            dispatch,
            node_id,
            started: Instant::now(),
            last_refusal_warn_ms: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }

    /// Checks a peer RPC's identity before it is served
    /// (`cluster-membership-changes` design decision 5): the sender's
    /// certificate, its claimed node ID, the target node ID, the cluster ID
    /// and the sender's standing in this node's membership. A pristine node
    /// adopts, and persists, the cluster ID of the first leader RPC it is
    /// sent.
    ///
    /// Runs before the dispatcher sees the RPC, so a refused RPC never
    /// reaches Raft and never counts as contact for the read gate (design
    /// decision 12).
    ///
    /// # Errors
    ///
    /// The refusal as the gRPC status the sender gets, or `UNAVAILABLE` when
    /// the cluster ID could not be persisted.
    pub(crate) async fn admit(
        &self,
        metadata: &MetadataMap,
        peer_certs: Option<&[CertificateDer<'static>]>,
        rpc: PeerRpc,
    ) -> Result<(), Status> {
        let claim = PeerClaim::read(metadata).map_err(|r| self.refuse(r, None, rpc))?;
        let cert_node = peer_certs
            .and_then(<[CertificateDer<'static>]>::first)
            .and_then(|leaf| certificate_node_id(leaf));
        let local = LocalPeer {
            node_id: self.node_id,
            cluster_id: self.dispatch.cluster_id(),
        };
        let admission = admit(local, &claim, cert_node, rpc, |node| {
            self.dispatch.peer_standing(node)
        })
        .map_err(|r| self.refuse(r, Some(&claim), rpc))?;
        if let Admission::AdoptClusterId(id) = admission {
            let held = self.dispatch.adopt_cluster_id(id).await.map_err(|e| {
                warn!(error = %e, "could not persist the cluster ID a leader sent");
                Status::unavailable(format!("could not persist the cluster ID: {e}"))
            })?;
            if held != id {
                return Err(self.refuse(PeerRefusal::WrongCluster, Some(&claim), rpc));
            }
            info!(
                node_id = self.node_id,
                cluster_id = %id,
                leader = claim.source,
                "joined cluster: adopted the cluster ID of the first leader that reached this node"
            );
        }
        Ok(())
    }

    /// Logs a refusal (at `WARN` at most once per
    /// [`REFUSAL_WARN_INTERVAL_MS`]) and returns its status.
    fn refuse(&self, refusal: PeerRefusal, claim: Option<&PeerClaim>, rpc: PeerRpc) -> Status {
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.last_refusal_warn_ms.load(Ordering::Relaxed);
        let due = last == u64::MAX || now.saturating_sub(last) >= REFUSAL_WARN_INTERVAL_MS;
        let source = claim.map(|c| c.source);
        let target = claim.map(|c| c.target);
        if due
            && self
                .last_refusal_warn_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            warn!(
                node_id = self.node_id,
                ?rpc,
                ?source,
                ?target,
                refusal = refusal.code(),
                "refused a peer RPC (logged at most every 30 s)"
            );
        } else {
            debug!(
                node_id = self.node_id,
                ?rpc,
                ?source,
                ?target,
                refusal = refusal.code(),
                "refused a peer RPC"
            );
        }
        refusal.to_status()
    }
}

impl<D: IncomingRpcDispatch> RaftRpcHandler<D> {
    /// Serves an `AppendEntries` whose metadata and client certificates are
    /// given apart from its body (tests have no TLS connection to take them
    /// from).
    pub(crate) async fn serve_append_entries(
        &self,
        metadata: &MetadataMap,
        peer_certs: Option<&[CertificateDer<'static>]>,
        request: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, Status> {
        self.admit(metadata, peer_certs, PeerRpc::AppendEntries)
            .await?;
        debug!("received AppendEntries from peer");
        self.dispatch
            .append_entries(&request.payload, request.leader_quorum_ack_age_ms)
            .await
            .map(|payload| AppendEntriesResponse { payload })
            .map_err(|e| {
                warn!(error = %e, "AppendEntries dispatch error");
                Status::internal(e)
            })
    }

    /// Serves a `Vote` (see [`Self::serve_append_entries`]).
    pub(crate) async fn serve_vote(
        &self,
        metadata: &MetadataMap,
        peer_certs: Option<&[CertificateDer<'static>]>,
        request: VoteRequest,
    ) -> Result<VoteResponse, Status> {
        self.admit(metadata, peer_certs, PeerRpc::Vote).await?;
        debug!("received Vote from peer");
        self.dispatch
            .vote(&request.payload)
            .await
            .map(|payload| VoteResponse { payload })
            .map_err(|e| {
                warn!(error = %e, "Vote dispatch error");
                Status::internal(e)
            })
    }

    /// Serves an `InstallSnapshot` chunk (see [`Self::serve_append_entries`]).
    pub(crate) async fn serve_install_snapshot(
        &self,
        metadata: &MetadataMap,
        peer_certs: Option<&[CertificateDer<'static>]>,
        request: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, Status> {
        self.admit(metadata, peer_certs, PeerRpc::InstallSnapshot)
            .await?;
        debug!("received InstallSnapshot chunk from peer");
        self.dispatch
            .install_snapshot(&request.payload)
            .await
            .map(|payload| InstallSnapshotResponse { payload })
            .map_err(|e| {
                warn!(error = %e, "InstallSnapshot dispatch error");
                Status::internal(e)
            })
    }

    /// Serves a `ForwardWrite` (see [`Self::serve_append_entries`]).
    pub(crate) async fn serve_forward_write(
        &self,
        metadata: &MetadataMap,
        peer_certs: Option<&[CertificateDer<'static>]>,
        request: ForwardWriteRequest,
    ) -> Result<ForwardWriteResponse, Status> {
        self.admit(metadata, peer_certs, PeerRpc::ForwardWrite)
            .await?;
        debug!("received ForwardWrite from peer");
        self.dispatch
            .forward_write(&request.payload)
            .await
            .map(|payload| ForwardWriteResponse { payload })
            .map_err(|e| {
                warn!(error = %e, "ForwardWrite dispatch error");
                Status::internal(e)
            })
    }
}

#[tonic::async_trait]
impl<D: IncomingRpcDispatch> RaftService for RaftRpcHandler<D> {
    async fn append_entries(
        &self,
        request: Request<AppendEntriesRequest>,
    ) -> Result<Response<AppendEntriesResponse>, Status> {
        let certs = request.peer_certs();
        let (metadata, _, body) = request.into_parts();
        self.serve_append_entries(&metadata, certs.as_deref().map(Vec::as_slice), body)
            .await
            .map(Response::new)
    }

    async fn vote(&self, request: Request<VoteRequest>) -> Result<Response<VoteResponse>, Status> {
        let certs = request.peer_certs();
        let (metadata, _, body) = request.into_parts();
        self.serve_vote(&metadata, certs.as_deref().map(Vec::as_slice), body)
            .await
            .map(Response::new)
    }

    async fn install_snapshot(
        &self,
        request: Request<InstallSnapshotRequest>,
    ) -> Result<Response<InstallSnapshotResponse>, Status> {
        let certs = request.peer_certs();
        let (metadata, _, body) = request.into_parts();
        self.serve_install_snapshot(&metadata, certs.as_deref().map(Vec::as_slice), body)
            .await
            .map(Response::new)
    }

    async fn forward_write(
        &self,
        request: Request<ForwardWriteRequest>,
    ) -> Result<Response<ForwardWriteResponse>, Status> {
        let certs = request.peer_certs();
        let (metadata, _, body) = request.into_parts();
        self.serve_forward_write(&metadata, certs.as_deref().map(Vec::as_slice), body)
            .await
            .map(Response::new)
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
                RaftServiceServer::new(RaftRpcHandler::new(self.node_id, dispatch))
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
    fn cluster_id(&self) -> Option<ClusterId> {
        None
    }

    fn peer_standing(&self, _node: u64) -> PeerStanding {
        PeerStanding::Pristine
    }

    async fn adopt_cluster_id(&self, _id: ClusterId) -> Result<ClusterId, String> {
        Err("Raft engine not initialised".to_string())
    }

    async fn append_entries(&self, _payload: &[u8], _age: Option<u64>) -> Result<Vec<u8>, String> {
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::cluster::log_store::{ClusterIdentity, HearthLogStore};
    use crate::cluster::peer_identity::test_pki::TestCa;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    const A: ClusterId = ClusterId::new(uuid::Uuid::from_u128(0xA));
    const B: ClusterId = ClusterId::new(uuid::Uuid::from_u128(0xB));

    /// A dispatcher that records what reaches it. Node 1 and 2 are members,
    /// node 3 is retired, every other ID is not a member.
    struct FakeDispatch {
        identity: Arc<ClusterIdentity>,
        pristine: bool,
        served: AtomicUsize,
        /// The cluster ID `raft.db` held when an RPC reached the dispatcher.
        persisted_when_served: Mutex<Vec<Option<ClusterId>>>,
    }

    impl FakeDispatch {
        fn new(identity: Arc<ClusterIdentity>, pristine: bool) -> Arc<Self> {
            Arc::new(Self {
                identity,
                pristine,
                served: AtomicUsize::new(0),
                persisted_when_served: Mutex::new(Vec::new()),
            })
        }

        fn serve(&self) -> Result<Vec<u8>, String> {
            self.served.fetch_add(1, Ordering::SeqCst);
            let persisted = self.identity.persisted().map_err(|e| e.to_string())?;
            self.persisted_when_served.lock().unwrap().push(persisted);
            Ok(b"ok".to_vec())
        }
    }

    impl IncomingRpcDispatch for FakeDispatch {
        fn cluster_id(&self) -> Option<ClusterId> {
            self.identity.get()
        }

        fn peer_standing(&self, node: u64) -> PeerStanding {
            match node {
                _ if self.pristine => PeerStanding::Pristine,
                1 | 2 => PeerStanding::Member,
                3 => PeerStanding::Retired,
                _ => PeerStanding::NotAMember,
            }
        }

        async fn adopt_cluster_id(&self, id: ClusterId) -> Result<ClusterId, String> {
            self.identity.adopt(id).await.map_err(|e| e.to_string())
        }

        async fn append_entries(&self, _: &[u8], _: Option<u64>) -> Result<Vec<u8>, String> {
            self.serve()
        }

        async fn vote(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            self.serve()
        }

        async fn install_snapshot(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            self.serve()
        }

        async fn forward_write(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            self.serve()
        }
    }

    fn metadata(cluster_id: Option<ClusterId>, source: u64, target: u64) -> MetadataMap {
        let mut md = MetadataMap::new();
        PeerClaim {
            cluster_id,
            source,
            target,
        }
        .stamp(&mut md);
        md
    }

    fn cert_of(ca: &TestCa, node: u64) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(ca.leaf_for_node(node).der)]
    }

    fn aer() -> AppendEntriesRequest {
        AppendEntriesRequest {
            payload: b"entries".to_vec(),
            leader_quorum_ack_age_ms: Some(1),
        }
    }

    /// Sends node 2 an `AppendEntries` from `source`, signed for `cert_node`.
    async fn send(
        handler: &RaftRpcHandler<FakeDispatch>,
        ca: &TestCa,
        claim: (Option<ClusterId>, u64, u64),
        cert_node: u64,
    ) -> Result<AppendEntriesResponse, Status> {
        let certs = cert_of(ca, cert_node);
        handler
            .serve_append_entries(&metadata(claim.0, claim.1, claim.2), Some(&certs), aer())
            .await
    }

    fn refusal(result: Result<AppendEntriesResponse, Status>) -> PeerRefusal {
        let status = result.expect_err("the RPC was served");
        PeerRefusal::from_status(&status).expect("a peer refusal")
    }

    /// Task 1.1: each identity check refuses with its own code, a correct
    /// RPC is served, and no refused RPC reaches the dispatcher (so it never
    /// counts as contact for the read gate: design decision 12).
    #[tokio::test]
    async fn each_wrong_identity_is_refused_with_its_own_code() {
        let ca = TestCa::new();
        let dispatch = FakeDispatch::new(ClusterIdentity::in_memory(Some(A)), false);
        let handler = RaftRpcHandler::new(2, Arc::clone(&dispatch));

        let wrong_target = send(&handler, &ca, (Some(A), 1, 3), 1).await;
        assert_eq!(refusal(wrong_target), PeerRefusal::WrongNode);
        let wrong_cluster = send(&handler, &ca, (Some(B), 1, 2), 1).await;
        assert_eq!(refusal(wrong_cluster), PeerRefusal::WrongCluster);
        let non_member = send(&handler, &ca, (Some(A), 7, 2), 7).await;
        assert_eq!(refusal(non_member), PeerRefusal::NotAMember);
        let retired = send(&handler, &ca, (Some(A), 3, 2), 3).await;
        assert_eq!(refusal(retired), PeerRefusal::Removed);
        let wrong_cert = send(&handler, &ca, (Some(A), 1, 2), 5).await;
        assert_eq!(refusal(wrong_cert), PeerRefusal::CertificateMismatch);
        let no_cert = handler
            .serve_append_entries(&metadata(Some(A), 1, 2), None, aer())
            .await;
        assert_eq!(refusal(no_cert), PeerRefusal::CertificateMismatch);
        let no_claim = handler
            .serve_append_entries(&MetadataMap::new(), Some(&cert_of(&ca, 1)), aer())
            .await;
        assert_eq!(refusal(no_claim), PeerRefusal::MissingIdentity);
        assert_eq!(
            dispatch.served.load(Ordering::SeqCst),
            0,
            "a refused RPC was dispatched"
        );

        let served = send(&handler, &ca, (Some(A), 1, 2), 1)
            .await
            .expect("served");
        assert_eq!(served.payload, b"ok");
        assert_eq!(dispatch.served.load(Ordering::SeqCst), 1);
    }

    /// Task 1.1: every RPC kind is checked, not only `AppendEntries`.
    #[tokio::test]
    async fn every_rpc_kind_is_checked() {
        let ca = TestCa::new();
        let dispatch = FakeDispatch::new(ClusterIdentity::in_memory(Some(A)), false);
        let handler = RaftRpcHandler::new(2, Arc::clone(&dispatch));
        let md = metadata(Some(A), 1, 3);
        let certs = cert_of(&ca, 1);
        let vote = handler
            .serve_vote(&md, Some(&certs), VoteRequest { payload: vec![] })
            .await;
        let snapshot = handler
            .serve_install_snapshot(
                &md,
                Some(&certs),
                InstallSnapshotRequest { payload: vec![] },
            )
            .await;
        let forward = handler
            .serve_forward_write(&md, Some(&certs), ForwardWriteRequest { payload: vec![] })
            .await;
        for status in [vote.err(), snapshot.err(), forward.err()] {
            let status = status.expect("refused");
            assert_eq!(
                PeerRefusal::from_status(&status),
                Some(PeerRefusal::WrongNode)
            );
        }
        assert_eq!(dispatch.served.load(Ordering::SeqCst), 0);
    }

    /// Task 1.2: a pristine node adopts the first cluster ID a leader sends
    /// it, has it in `raft.db` before the RPC is served, and refuses another
    /// one after a restart.
    #[tokio::test]
    async fn a_pristine_node_persists_the_first_cluster_id_before_it_answers() {
        let ca = TestCa::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raft.db");
        {
            let store = HearthLogStore::open(&path).unwrap();
            let identity = store.cluster_identity().unwrap();
            assert_eq!(identity.get(), None);
            let dispatch = FakeDispatch::new(identity, true);
            let handler = RaftRpcHandler::new(2, Arc::clone(&dispatch));

            // A candidate's vote does not make a pristine node join.
            let certs = cert_of(&ca, 1);
            handler
                .serve_vote(
                    &metadata(Some(B), 1, 2),
                    Some(&certs),
                    VoteRequest { payload: vec![] },
                )
                .await
                .expect("vote served");
            assert_eq!(dispatch.cluster_id(), None);

            send(&handler, &ca, (Some(A), 1, 2), 1)
                .await
                .expect("served");
            assert_eq!(dispatch.cluster_id(), Some(A));
            assert_eq!(
                *dispatch.persisted_when_served.lock().unwrap(),
                vec![None, Some(A)],
                "the cluster ID was not in raft.db when the RPC was served"
            );
        }

        let store = HearthLogStore::open(&path).unwrap();
        let identity = store.cluster_identity().unwrap();
        assert_eq!(
            identity.get(),
            Some(A),
            "the cluster ID did not survive a restart"
        );
        let dispatch = FakeDispatch::new(identity, true);
        let handler = RaftRpcHandler::new(2, Arc::clone(&dispatch));
        let other = send(&handler, &ca, (Some(B), 1, 2), 1).await;
        assert_eq!(refusal(other), PeerRefusal::WrongCluster);
        assert_eq!(dispatch.served.load(Ordering::SeqCst), 0);
    }

    /// Finding 3 on #955: a node of a cluster an older release formed holds
    /// a membership but no cluster ID. A member's `AppendEntries` that
    /// carries an ID writes none to `raft.db`, and the node keeps serving
    /// its leader's RPCs, which carry none.
    #[tokio::test]
    async fn a_member_node_without_a_cluster_id_adopts_none_and_keeps_serving() {
        let ca = TestCa::new();
        let dir = tempfile::tempdir().unwrap();
        let store = HearthLogStore::open(&dir.path().join("raft.db")).unwrap();
        let dispatch = FakeDispatch::new(store.cluster_identity().unwrap(), false);
        let handler = RaftRpcHandler::new(2, Arc::clone(&dispatch));

        send(&handler, &ca, (Some(A), 1, 2), 1)
            .await
            .expect("served");
        assert_eq!(dispatch.cluster_id(), None);
        assert_eq!(dispatch.identity.persisted().unwrap(), None);

        send(&handler, &ca, (None, 1, 2), 1)
            .await
            .expect("an RPC without a cluster ID is served");
        assert_eq!(dispatch.served.load(Ordering::SeqCst), 2);
    }

    /// Verifies the handler can be created and cloned (tonic requires Clone).
    #[test]
    fn handler_is_clone() {
        let handler = RaftRpcHandler::new(1, Arc::new(NoopDispatch));
        let _clone = handler.clone();
    }

    /// Verifies NoopDispatch returns an error rather than panicking.
    #[tokio::test]
    async fn noop_dispatch_returns_error() {
        let d = NoopDispatch;
        let result = d.append_entries(b"{}", None).await;
        assert!(result.is_err());
    }
}
