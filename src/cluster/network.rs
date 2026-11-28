//! Outgoing Raft peer transport: implements openraft's `RaftNetworkFactory` and
//! `RaftNetwork` traits over tonic gRPC with mutual TLS.
//!
//! Each peer gets its own lazy `tonic::Channel` (created on first use and
//! cached thereafter). On any transport failure the channel is invalidated so
//! the next call attempts a fresh connection.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openraft::{
    error::{InstallSnapshotError, NetworkError as OraftNetworkError, RPCError, RaftError},
    network::{RPCOption, RaftNetwork, RaftNetworkFactory},
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
};
use serde::Serialize;
use tonic::transport::{Channel, ClientTlsConfig, Identity};
use tracing::{debug, warn};

use crate::cluster::error::TransportError;
use crate::cluster::log_store::ClusterIdentity;
use crate::cluster::peer_identity::{NodeIdServerVerifier, PeerClaim, PeerRefusal};
use crate::cluster::read_gate::ReadGate;
use crate::cluster::rpc::{
    raft_service_client::RaftServiceClient, AppendEntriesRequest as GrpcAer,
    ForwardWriteRequest as GrpcFwr, InstallSnapshotRequest as GrpcIsr, VoteRequest as GrpcVr,
};
use crate::cluster::types::{HearthNode, HearthRaftConfig};
use crate::cluster::wire::{self, APPEND_BATCH_BYTES, MAX_PEER_MESSAGE_BYTES};

/// How long the leader waits for the answer to a snapshot chunk other than
/// the last: one 4 MiB write into the follower's snapshot file
/// (`cluster-file-snapshots`).
const SNAPSHOT_CHUNK_TIMEOUT: Duration = Duration::from_secs(60);

// ── TLS credential bundle ────────────────────────────────────────────────────

/// PEM-encoded TLS credentials shared by all peer connections from this node.
#[allow(clippy::struct_field_names)]
pub(crate) struct TlsCredentials {
    pub(crate) cert_pem: Vec<u8>,
    pub(crate) key_pem: Vec<u8>,
    pub(crate) ca_pem: Vec<u8>,
}

// ── Fault injection ──────────────────────────────────────────────────────────

/// Drop-and-delay control over this node's **outbound** Raft RPCs, per peer.
///
/// This is the seam that lets a test partition a real, socket-backed cluster.
/// It exists because a failover test cannot be written any other way: killing
/// a leader's own gRPC server does not depose it (the leader is the one that
/// *dials*, so it keeps reaching its followers and keeps their leases alive),
/// and killing the followers' servers leaves nobody able to elect. What has to
/// be cut is the leader's outbound edge, which is exactly what this cuts. It
/// is the `FaultFs` pattern from `simulation/src/lib.rs` moved one layer up:
/// a real transport with a controllable failure surface, not a mock.
///
/// A partition is directional. To sever a link both ways, isolate each end
/// from the other:
///
/// ```text
/// leader_faults.isolate(follower_id);
/// follower_faults.isolate(leader_id);
/// ```
///
/// An isolated peer's RPCs are failed with
/// [`TransportError::InjectedPartition`] *before* the channel is touched, so
/// nothing reaches the socket and openraft sees the same `RPCError::Network`
/// it would see from an unreachable host. A delay is applied before the drop
/// check, so a peer can be both slow and reachable.
///
/// Production never constructs one: [`HearthNetworkFactory::new`] leaves the
/// slot `None` and the gate is a null check on an `Option`.
#[derive(Debug, Default)]
pub struct PeerFaults {
    state: Mutex<FaultState>,
}

#[derive(Debug, Default)]
struct FaultState {
    isolated: HashSet<u64>,
    delays: HashMap<u64, Duration>,
    /// Peers whose replies to a forwarded write are discarded after they
    /// arrive, as if the connection dropped once the leader had answered.
    lost_forward_replies: HashSet<u64>,
    /// Forwarded writes put on the wire, per peer.
    forwards_sent: HashMap<u64, u64>,
}

impl PeerFaults {
    /// A fresh injector with no faults armed.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Drop every outbound RPC to `peer` until [`Self::heal`] is called.
    pub fn isolate(&self, peer: u64) {
        self.with_state(|s| {
            s.isolated.insert(peer);
        });
    }

    /// Stop dropping outbound RPCs to `peer`.
    pub fn heal(&self, peer: u64) {
        self.with_state(|s| {
            s.isolated.remove(&peer);
        });
    }

    /// Clear every drop, every delay and every lost-reply fault.
    pub fn heal_all(&self) {
        self.with_state(|s| {
            s.isolated.clear();
            s.delays.clear();
            s.lost_forward_replies.clear();
        });
    }

    /// Discard the reply to every write this node forwards to `peer`, after
    /// the peer has sent it: the request is delivered and served, and the
    /// forwarding node sees the connection fail. This is the one case where a
    /// forwarded write's outcome is unknowable, which is what makes it the
    /// case an exactly-once test has to exercise.
    pub fn lose_forward_replies(&self, peer: u64) {
        self.with_state(|s| {
            s.lost_forward_replies.insert(peer);
        });
    }

    /// How many writes this node has put on the wire to `peer` as a
    /// forwarded write (lost replies included, isolated attempts excluded).
    #[must_use]
    pub fn forwards_sent(&self, peer: u64) -> u64 {
        match self.state.lock() {
            Ok(s) => s.forwards_sent.get(&peer).copied().unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Delay every outbound RPC to `peer` by `delay` before sending it.
    pub fn delay(&self, peer: u64, delay: Duration) {
        self.with_state(|s| {
            s.delays.insert(peer, delay);
        });
    }

    /// Whether outbound RPCs to `peer` are currently being dropped.
    #[must_use]
    pub fn is_isolated(&self, peer: u64) -> bool {
        self.plan(peer).0
    }

    /// Reads the fault plan for `peer` under one short lock. The guard is
    /// dropped before the caller awaits anything.
    fn plan(&self, peer: u64) -> (bool, Option<Duration>) {
        match self.state.lock() {
            Ok(s) => (s.isolated.contains(&peer), s.delays.get(&peer).copied()),
            // A poisoned injector must not silently become "no faults": that
            // would make a partition test pass for the wrong reason. Fail
            // closed — treat the peer as isolated.
            Err(_) => (true, None),
        }
    }

    /// Applies any injected delay to `peer`, then fails with
    /// [`TransportError::InjectedPartition`] if it is isolated. The lock is
    /// released before the delay is awaited.
    async fn gate(&self, peer: u64) -> Result<(), TransportError> {
        let (isolated, delay) = self.plan(peer);
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        if isolated {
            debug!(node_id = peer, "outbound RPC dropped by injected partition");
            return Err(TransportError::InjectedPartition(peer));
        }
        Ok(())
    }

    /// Records a forwarded write put on the wire to `peer` and reports
    /// whether its reply is to be discarded.
    fn on_forward_sent(&self, peer: u64) -> bool {
        match self.state.lock() {
            Ok(mut s) => {
                *s.forwards_sent.entry(peer).or_insert(0) += 1;
                s.lost_forward_replies.contains(&peer)
            }
            // Fail closed, as `plan` does: a poisoned injector loses the reply.
            Err(_) => true,
        }
    }

    fn with_state(&self, f: impl FnOnce(&mut FaultState)) {
        if let Ok(mut s) = self.state.lock() {
            f(&mut s);
        }
    }
}

// ── LocalIdentity ────────────────────────────────────────────────────────────

/// This node's side of every peer RPC's identity metadata.
struct LocalIdentity {
    node_id: u64,
    cluster_identity: Arc<ClusterIdentity>,
}

impl LocalIdentity {
    /// `body` as a request to `target`, carrying this node's claim.
    fn request<T>(&self, target: u64, body: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(body);
        PeerClaim {
            cluster_id: self.cluster_identity.get(),
            source: self.node_id,
            target,
        }
        .stamp(request.metadata_mut());
        request
    }
}

/// Logs a peer's refusal of this node's RPCs at `WARN` when its code differs
/// from the last one logged for that peer, so a peer that refuses every
/// heartbeat logs once, not every 250 ms.
#[derive(Default)]
struct RefusalReporter {
    last: Mutex<Option<PeerRefusal>>,
}

impl RefusalReporter {
    fn report(&self, target: u64, addr: &str, status: &tonic::Status) {
        let Some(refusal) = PeerRefusal::from_status(status) else {
            return;
        };
        let Ok(mut last) = self.last.lock() else {
            return;
        };
        if *last != Some(refusal) {
            *last = Some(refusal);
            warn!(
                node_id = target,
                addr = %addr,
                refusal = refusal.code(),
                message = status.message(),
                "peer refused this node's RPC (logged once per code)"
            );
        }
    }
}

// ── HearthNetworkFactory ─────────────────────────────────────────────────────

/// Creates per-peer gRPC connections on demand.
///
/// Implements [`openraft::network::RaftNetworkFactory`] — openraft calls
/// `new_client(target, node)` whenever it needs a connection to a peer.
pub struct HearthNetworkFactory {
    creds: Arc<TlsCredentials>,
    /// Who this node is: every RPC carries its node ID and cluster ID.
    local: Arc<LocalIdentity>,
    /// Test-only outbound-RPC fault injector. `None` on every node built by
    /// `ClusterEngine::build_clustered`, which is the only constructor
    /// `serve` reaches.
    faults: Option<Arc<PeerFaults>>,
    /// This node's read gate: the source of the quorum-acknowledgement age
    /// every `AppendEntries` carries. `None` sends no age, which a follower
    /// counts as no contact.
    read_gate: Option<Arc<ReadGate>>,
}

impl HearthNetworkFactory {
    /// Creates a new factory for node `node_id` from PEM-encoded certificate
    /// material.
    ///
    /// `cert_pem` and `key_pem` are this node's identity presented to peers;
    /// the certificate must name `node_id` (URI SAN `urn:hearth:node:<id>`).
    /// `ca_pem` is the CA used to verify peer certificates. Every RPC carries
    /// `node_id`, the target's node ID and `cluster_identity`'s cluster ID
    /// (`cluster-membership-changes` design decision 5).
    pub fn new(
        node_id: u64,
        cluster_identity: Arc<ClusterIdentity>,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        ca_pem: Vec<u8>,
    ) -> Self {
        Self {
            creds: Arc::new(TlsCredentials {
                cert_pem,
                key_pem,
                ca_pem,
            }),
            local: Arc::new(LocalIdentity {
                node_id,
                cluster_identity,
            }),
            faults: None,
            read_gate: None,
        }
    }

    /// Routes every outbound RPC this factory's peers send through `faults`.
    ///
    /// Test-only. See [`PeerFaults`].
    #[must_use]
    pub fn with_peer_faults(mut self, faults: Arc<PeerFaults>) -> Self {
        self.faults = Some(faults);
        self
    }
    /// Sends `gate`'s quorum-acknowledgement age with every `AppendEntries`.
    #[must_use]
    pub(crate) fn with_read_gate(mut self, gate: Arc<ReadGate>) -> Self {
        self.read_gate = Some(gate);
        self
    }

    /// A client for forwarding this node's writes to the leader, over the
    /// same mTLS identity (and, in tests, the same fault injector) as the
    /// Raft peer RPCs.
    pub(crate) fn leader_forwarder(&self) -> LeaderForwarder {
        LeaderForwarder {
            creds: Arc::clone(&self.creds),
            local: Arc::clone(&self.local),
            faults: self.faults.clone(),
            channel: Mutex::new(None),
            refusals: RefusalReporter::default(),
        }
    }
}

impl RaftNetworkFactory<HearthRaftConfig> for HearthNetworkFactory {
    type Network = HearthPeerNetwork;

    async fn new_client(&mut self, target: u64, node: &HearthNode) -> HearthPeerNetwork {
        debug!(node_id = target, addr = %node.addr, "allocating peer network slot");
        HearthPeerNetwork {
            target,
            addr: node.addr.clone(),
            creds: Arc::clone(&self.creds),
            local: Arc::clone(&self.local),
            channel: Mutex::new(None),
            faults: self.faults.clone(),
            read_gate: self.read_gate.clone(),
            reported_older_build: std::sync::atomic::AtomicBool::new(false),
            refusals: RefusalReporter::default(),
        }
    }
}

// ── HearthPeerNetwork ────────────────────────────────────────────────────────

/// gRPC connection to a single Raft peer.
///
/// Implements [`openraft::network::RaftNetwork`] — openraft calls the RPC
/// methods on this struct when it needs to replicate entries or vote.
///
/// The underlying [`Channel`] is lazily established and cached. Any transport
/// error invalidates the cache so the next call attempts a reconnect.
pub struct HearthPeerNetwork {
    target: u64,
    addr: String,
    creds: Arc<TlsCredentials>,
    /// See [`HearthNetworkFactory`]'s field of the same name.
    local: Arc<LocalIdentity>,
    /// Cached tonic `Channel`.
    ///
    /// Lock is held only long enough to clone the channel value — NEVER across
    /// an `.await`. Drop the guard, then await the cloned channel.
    channel: Mutex<Option<Channel>>,
    /// Test-only fault injector; `None` in production. See [`PeerFaults`].
    faults: Option<Arc<PeerFaults>>,
    /// See [`HearthNetworkFactory`]'s field of the same name.
    read_gate: Option<Arc<ReadGate>>,
    /// Set once this peer has been reported as unable to decode our log.
    reported_older_build: std::sync::atomic::AtomicBool,
    /// The last refusal code this peer answered with that was logged.
    refusals: RefusalReporter,
}

impl HearthPeerNetwork {
    /// Returns the cached channel, or establishes a fresh mTLS connection.
    async fn get_or_connect(&self) -> Result<Channel, TransportError> {
        let cached = self
            .channel
            .lock()
            .map_err(|e| TransportError::Internal(e.to_string()))?
            .clone();

        if let Some(ch) = cached {
            return Ok(ch);
        }

        // Lock fully dropped before this await.
        let ch = self.connect_mtls().await?;

        // Store for next call; concurrent connections are harmless.
        if let Ok(mut guard) = self.channel.lock() {
            *guard = Some(ch.clone());
        }
        Ok(ch)
    }

    /// Opens a new mTLS-secured tonic channel to this peer.
    async fn connect_mtls(&self) -> Result<Channel, TransportError> {
        connect_mtls(&self.creds, self.target, &self.addr).await
    }

    /// Applies any injected delay, then fails the call if this peer is
    /// currently isolated. A no-op (one `Option` check) when no injector is
    /// installed, which is every production node.
    async fn gate(&self) -> Result<(), TransportError> {
        match self.faults.as_ref() {
            Some(faults) => faults.gate(self.target).await,
            None => Ok(()),
        }
    }

    /// Logs, once per peer, that `status` shows the peer runs an older build
    /// that cannot decode a Raft command this build writes. Replication to it
    /// retries for ever and never succeeds; a rolling upgrade is not
    /// supported (see `docs/guides/upgrading.md`).
    fn report_older_build(&self, status: &tonic::Status) {
        if is_unknown_command_refusal(status)
            && !self
                .reported_older_build
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::error!(
                node_id = self.target,
                addr = %self.addr,
                "peer cannot decode this node's Raft log: it runs an older Hearth build. \
                 Mixed-version clusters are not supported — replication to it is stalled. \
                 Stop every node and start them all on the same build (full-cluster \
                 restart); see the upgrading guide"
            );
        }
    }

    /// Drops the cached channel so the next call reconnects.
    fn invalidate_channel(&self) {
        if let Ok(mut guard) = self.channel.lock() {
            *guard = None;
            debug!(node_id = self.target, addr = %self.addr, "peer channel invalidated");
        }
    }
}

// ── RaftNetwork impl ─────────────────────────────────────────────────────────

impl RaftNetwork<HearthRaftConfig> for HearthPeerNetwork {
    /// Sends `rpc`, or — when its entries would make the message larger than
    /// [`APPEND_BATCH_BYTES`] — the longest prefix that fits (at least one
    /// entry), reporting the rest as openraft's `PartialSuccess` so it sends
    /// them next. A follower clamps its commit index to the entries it has
    /// accepted, so `leader_commit` needs no adjustment.
    async fn append_entries(
        &mut self,
        mut rpc: AppendEntriesRequest<HearthRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, HearthNode, RaftError<u64>>> {
        self.gate().await.map_err(net_err)?;
        let sent_through = fit_append_batch(&mut rpc).map_err(net_err)?;
        let payload = encode_bounded(&rpc).map_err(net_err)?;
        let ch = self.get_or_connect().await.map_err(net_err)?;
        let mut client = RaftServiceClient::new(ch)
            .max_decoding_message_size(MAX_PEER_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_PEER_MESSAGE_BYTES);

        // Read last, just before sending: the age is never younger than it is.
        let leader_quorum_ack_age_ms = self
            .read_gate
            .as_ref()
            .and_then(|gate| gate.quorum_ack_age_ms());
        let request = self.local.request(
            self.target,
            GrpcAer {
                payload,
                leader_quorum_ack_age_ms,
            },
        );
        let resp = client.append_entries(request).await.map_err(|e| {
            self.invalidate_channel();
            self.report_older_build(&e);
            self.refusals.report(self.target, &self.addr, &e);
            net_err(TransportError::Rpc(e))
        })?;

        let resp: AppendEntriesResponse<u64> = wire::decode(&resp.into_inner().payload)
            .map_err(|e| net_err(TransportError::Deserialize(e)))?;
        Ok(match (resp, sent_through) {
            (AppendEntriesResponse::Success, Some(last)) => {
                AppendEntriesResponse::PartialSuccess(Some(last))
            }
            (other, _) => other,
        })
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<HearthRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, HearthNode, RaftError<u64, InstallSnapshotError>>,
    > {
        self.gate().await.map_err(net_err_ise)?;
        let last_chunk = rpc.done;
        let payload = encode_bounded(&wire::WireInstallSnapshot::from(rpc)).map_err(net_err_ise)?;
        let ch = self.get_or_connect().await.map_err(net_err_ise)?;
        let mut client = RaftServiceClient::new(ch)
            .max_decoding_message_size(MAX_PEER_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_PEER_MESSAGE_BYTES);

        // openraft bounds every chunk by `install_snapshot_timeout`, sized
        // for the last chunk, whose answer waits for the follower's check
        // and restore. Any other chunk is one write: a follower that does not
        // answer it within `SNAPSHOT_CHUNK_TIMEOUT` is not waited for.
        let call = client.install_snapshot(self.local.request(self.target, GrpcIsr { payload }));
        let answer = if last_chunk {
            call.await
        } else {
            match tokio::time::timeout(SNAPSHOT_CHUNK_TIMEOUT, call).await {
                Ok(answer) => answer,
                Err(_) => {
                    self.invalidate_channel();
                    return Err(net_err_ise(TransportError::Timeout(SNAPSHOT_CHUNK_TIMEOUT)));
                }
            }
        };
        let resp = answer.map_err(|e| {
            self.invalidate_channel();
            self.refusals.report(self.target, &self.addr, &e);
            net_err_ise(TransportError::Rpc(e))
        })?;

        wire::decode(&resp.into_inner().payload)
            .map_err(|e| net_err_ise(TransportError::Deserialize(e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, HearthNode, RaftError<u64>>> {
        self.gate().await.map_err(net_err)?;
        let payload = encode_bounded(&rpc).map_err(net_err)?;
        let ch = self.get_or_connect().await.map_err(net_err)?;
        let mut client = RaftServiceClient::new(ch)
            .max_decoding_message_size(MAX_PEER_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_PEER_MESSAGE_BYTES);

        let request = self.local.request(self.target, GrpcVr { payload });
        let resp = client.vote(request).await.map_err(|e| {
            self.invalidate_channel();
            self.refusals.report(self.target, &self.addr, &e);
            net_err(TransportError::Rpc(e))
        })?;

        wire::decode(&resp.into_inner().payload)
            .map_err(|e| net_err(TransportError::Deserialize(e)))
    }
}

/// Cuts `rpc`'s entries to the longest prefix whose encoding fits
/// [`APPEND_BATCH_BYTES`] (never fewer than one entry). Returns the last
/// entry kept when anything was cut.
fn fit_append_batch(
    rpc: &mut AppendEntriesRequest<HearthRaftConfig>,
) -> Result<Option<openraft::LogId<u64>>, TransportError> {
    let mut total = 0_usize;
    let mut keep = rpc.entries.len();
    for (i, entry) in rpc.entries.iter().enumerate() {
        total += wire::encoded_len(entry).map_err(TransportError::Serialize)?;
        if total > APPEND_BATCH_BYTES && i > 0 {
            keep = i;
            break;
        }
    }
    if keep == rpc.entries.len() {
        return Ok(None);
    }
    rpc.entries.truncate(keep);
    Ok(rpc.entries.last().map(|e| e.log_id))
}

/// Encodes a peer payload, refusing one the receiver would not accept.
fn encode_bounded<T: Serialize>(value: &T) -> Result<Vec<u8>, TransportError> {
    let payload = wire::encode(value).map_err(TransportError::Serialize)?;
    if payload.len() > MAX_PEER_MESSAGE_BYTES {
        return Err(TransportError::TooLarge(payload.len()));
    }
    Ok(payload)
}

// ── Leader forwarding (follower side) ────────────────────────────────────────

/// Why a forwarded write produced no answer from the leader.
///
/// The split is the whole point: only a write that provably never left this
/// node may be retried against another leader. Once the request may have been
/// delivered, the leader may have proposed it, and a conditional command
/// (`PutIfAbsent`, `IncrementU64`) applied twice is a different result.
#[derive(Debug)]
pub(crate) enum ForwardFailure {
    /// The request never left this node: the connection could not be
    /// established (or a test partition dropped it before the socket).
    NotSent(TransportError),
    /// The request may have reached the leader; its outcome is unknown.
    Unknown(TransportError),
    /// The leader does not serve `ForwardWrite` at all (gRPC
    /// `UNIMPLEMENTED`): it runs an older build. Nothing was proposed, but a
    /// retry cannot help — mixed-version clusters are unsupported.
    Unsupported(TransportError),
}

/// Follower-side client of the `ForwardWrite` peer RPC.
///
/// Holds one cached mTLS channel, to the leader it last forwarded to; a
/// change of leader or any failed call replaces it. It is authenticated
/// exactly like the Raft RPCs: this node's certificate, verified by the
/// leader against the cluster CA, and the leader's, verified against it here.
pub(crate) struct LeaderForwarder {
    creds: Arc<TlsCredentials>,
    /// See [`HearthNetworkFactory`]'s field of the same name.
    local: Arc<LocalIdentity>,
    faults: Option<Arc<PeerFaults>>,
    /// `(leader node id, address, channel)`. Lock held only to clone or
    /// replace the value — never across an `.await`.
    channel: Mutex<Option<(u64, String, Channel)>>,
    /// The last refusal code a leader answered with that was logged.
    refusals: RefusalReporter,
}

impl LeaderForwarder {
    /// Sends one serialized [`RaftCommand`](crate::cluster::types::RaftCommand)
    /// to `leader_id` at `addr` and returns the serialized
    /// [`ForwardedWriteOutcome`](crate::cluster::types::ForwardedWriteOutcome).
    ///
    /// `timeout` bounds the whole call; a call that exceeds it may still be
    /// served by the leader, so it is [`ForwardFailure::Unknown`].
    pub(crate) async fn forward(
        &self,
        leader_id: u64,
        addr: &str,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>, ForwardFailure> {
        if let Some(faults) = self.faults.as_ref() {
            faults
                .gate(leader_id)
                .await
                .map_err(ForwardFailure::NotSent)?;
        }
        let channel = self
            .channel_to(leader_id, addr)
            .await
            .map_err(ForwardFailure::NotSent)?;
        let lose_reply = self
            .faults
            .as_ref()
            .is_some_and(|f| f.on_forward_sent(leader_id));

        let mut client = RaftServiceClient::new(channel)
            .max_decoding_message_size(MAX_PEER_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_PEER_MESSAGE_BYTES);
        let request = self.local.request(leader_id, GrpcFwr { payload });
        let answer = tokio::time::timeout(timeout, client.forward_write(request)).await;
        let reply = match answer {
            Ok(Ok(resp)) => resp.into_inner().payload,
            Ok(Err(status)) if status.code() == tonic::Code::Unimplemented => {
                return Err(ForwardFailure::Unsupported(TransportError::Rpc(status)));
            }
            Ok(Err(status)) => {
                self.invalidate(leader_id);
                self.refusals.report(leader_id, addr, &status);
                return Err(ForwardFailure::Unknown(TransportError::Rpc(status)));
            }
            Err(_) => {
                self.invalidate(leader_id);
                return Err(ForwardFailure::Unknown(TransportError::Timeout(timeout)));
            }
        };
        if lose_reply {
            self.invalidate(leader_id);
            return Err(ForwardFailure::Unknown(TransportError::InjectedLostReply(
                leader_id,
            )));
        }
        Ok(reply)
    }

    /// The cached channel to `leader_id`, or a fresh mTLS connection to it.
    async fn channel_to(&self, leader_id: u64, addr: &str) -> Result<Channel, TransportError> {
        let cached = self
            .channel
            .lock()
            .map_err(|e| TransportError::Internal(e.to_string()))?
            .as_ref()
            .filter(|(id, a, _)| *id == leader_id && a == addr)
            .map(|(_, _, ch)| ch.clone());
        if let Some(ch) = cached {
            return Ok(ch);
        }
        let ch = connect_mtls(&self.creds, leader_id, addr).await?;
        if let Ok(mut guard) = self.channel.lock() {
            *guard = Some((leader_id, addr.to_string(), ch.clone()));
        }
        Ok(ch)
    }

    /// Drops the cached channel if it points at `leader_id`.
    fn invalidate(&self, leader_id: u64) {
        if let Ok(mut guard) = self.channel.lock() {
            if guard.as_ref().is_some_and(|(id, _, _)| *id == leader_id) {
                *guard = None;
            }
        }
    }
}

/// Opens a new mTLS-secured tonic channel to peer `target` at `addr`.
async fn connect_mtls(
    creds: &TlsCredentials,
    target: u64,
    addr: &str,
) -> Result<Channel, TransportError> {
    let identity = Identity::from_pem(&creds.cert_pem, &creds.key_pem);
    // Verifies the chain to the cluster CA and the dialled address as
    // tonic's default does, and also that the certificate names `target`
    // (URI SAN `urn:hearth:node:<id>`): a node now listening at a dead
    // node's address is not taken for it.
    let verifier = NodeIdServerVerifier::new(&creds.ca_pem, target).map_err(TransportError::Tls)?;
    let tls = ClientTlsConfig::new().identity(identity);

    let endpoint = format!("https://{addr}");
    debug!(node_id = target, addr = %endpoint, "connecting to peer over mTLS");

    Channel::from_shared(endpoint.clone())
        .map_err(|e| TransportError::Connect(Box::new(e)))?
        .tls_config_with_verifier(tls, Arc::new(verifier))
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .connect()
        .await
        .map_err(|e| {
            // tonic's error says only "transport error"; the cause (here a
            // refused certificate) is in its source chain.
            let error = error_chain(&e);
            warn!(node_id = target, addr = %endpoint, %error, "peer connection failed");
            TransportError::Connect(error.into())
        })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// `e` and each of its sources, joined by `": "`.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.ends_with(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

/// Whether `status` is a peer refusing an entry because it does not know one of
/// its [`RaftCommand`](crate::cluster::types::RaftCommand) variants — the peer
/// runs an older build. The receiving side maps its decode error to
/// `Status::internal` carrying serde's message verbatim.
fn is_unknown_command_refusal(status: &tonic::Status) -> bool {
    status.code() == tonic::Code::Internal && status.message().contains("unknown variant")
}

/// Wraps a [`TransportError`] as `RPCError::Network` for non-snapshot RPCs.
fn net_err<E: std::error::Error>(e: TransportError) -> RPCError<u64, HearthNode, E> {
    let io = io::Error::new(io::ErrorKind::BrokenPipe, e.to_string());
    RPCError::Network(OraftNetworkError::new(&io))
}

/// Wraps a [`TransportError`] as `RPCError::Network` for `install_snapshot`.
fn net_err_ise(
    e: TransportError,
) -> RPCError<u64, HearthNode, RaftError<u64, InstallSnapshotError>> {
    let io = io::Error::new(io::ErrorKind::BrokenPipe, e.to_string());
    RPCError::Network(OraftNetworkError::new(&io))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::LogId;

    /// What a recording peer saw of each RPC's identity metadata.
    #[allow(clippy::expect_used)]
    mod recording_peer {
        use std::sync::Mutex;

        use tonic::{Request, Response, Status};

        use crate::cluster::peer_identity::PeerClaim;
        use crate::cluster::rpc::{
            raft_service_server::RaftService, AppendEntriesRequest, AppendEntriesResponse,
            ForwardWriteRequest, ForwardWriteResponse, InstallSnapshotRequest,
            InstallSnapshotResponse, VoteRequest, VoteResponse,
        };

        /// A peer that records each RPC's claim and refuses it.
        #[derive(Default)]
        pub(super) struct RecordingPeer {
            pub(super) seen: Mutex<Vec<(&'static str, Result<PeerClaim, String>)>>,
        }

        impl RecordingPeer {
            fn record<T>(&self, rpc: &'static str, request: &Request<T>) -> Status {
                let claim = PeerClaim::read(request.metadata()).map_err(|r| r.to_string());
                self.seen.lock().expect("recording lock").push((rpc, claim));
                Status::unavailable("recorded")
            }
        }

        #[tonic::async_trait]
        impl RaftService for RecordingPeer {
            async fn append_entries(
                &self,
                request: Request<AppendEntriesRequest>,
            ) -> Result<Response<AppendEntriesResponse>, Status> {
                Err(self.record("append_entries", &request))
            }
            async fn vote(
                &self,
                request: Request<VoteRequest>,
            ) -> Result<Response<VoteResponse>, Status> {
                Err(self.record("vote", &request))
            }
            async fn install_snapshot(
                &self,
                request: Request<InstallSnapshotRequest>,
            ) -> Result<Response<InstallSnapshotResponse>, Status> {
                Err(self.record("install_snapshot", &request))
            }
            async fn forward_write(
                &self,
                request: Request<ForwardWriteRequest>,
            ) -> Result<Response<ForwardWriteResponse>, Status> {
                Err(self.record("forward_write", &request))
            }
        }
    }

    /// Task 1.4: every outgoing RPC (the three Raft RPCs and `ForwardWrite`)
    /// carries this node's cluster ID, its node ID and the target's node ID.
    #[tokio::test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    async fn every_outgoing_rpc_carries_the_identity_metadata() {
        use crate::cluster::peer_identity::test_pki::TestCa;
        use crate::cluster::rpc::raft_service_server::RaftServiceServer;
        use crate::cluster::types::ClusterId;
        use openraft::network::RaftNetworkFactory;
        use tonic::transport::{Certificate, Server, ServerTlsConfig};

        let ca = TestCa::new();
        let server_leaf = ca.leaf_for_node(2);
        let client_leaf = ca.leaf_for_node(1);
        let peer = Arc::new(recording_peer::RecordingPeer::default());
        let incoming =
            tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap().to_string();
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                &server_leaf.cert_pem,
                &server_leaf.key_pem,
            ))
            .client_ca_root(Certificate::from_pem(ca.pem()));
        let server = Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(RaftServiceServer::from_arc(Arc::clone(&peer)))
            .serve_with_incoming(incoming);
        let server = tokio::spawn(server);

        let cluster_id = ClusterId::new(uuid::Uuid::from_u128(0xC1));
        let mut factory = HearthNetworkFactory::new(
            1,
            ClusterIdentity::in_memory(Some(cluster_id)),
            client_leaf.cert_pem.into_bytes(),
            client_leaf.key_pem.into_bytes(),
            ca.pem().into_bytes(),
        );
        let node = HearthNode { addr: addr.clone() };
        let mut client = factory.new_client(2, &node).await;
        let option = || RPCOption::new(Duration::from_secs(5));
        let vote = openraft::Vote::new(1, 1);
        let aer = AppendEntriesRequest {
            vote,
            prev_log_id: None,
            entries: vec![],
            leader_commit: None,
        };
        let _ = client.append_entries(aer, option()).await;
        let _ = client.vote(VoteRequest::new(vote, None), option()).await;
        let isr = InstallSnapshotRequest {
            vote,
            meta: openraft::SnapshotMeta::default(),
            offset: 0,
            data: vec![],
            done: true,
        };
        let _ = client.install_snapshot(isr, option()).await;
        let _ = factory
            .leader_forwarder()
            .forward(2, &addr, vec![], Duration::from_secs(5))
            .await;
        server.abort();

        let expected = Ok(PeerClaim {
            cluster_id: Some(cluster_id),
            source: 1,
            target: 2,
        });
        let seen = peer.seen.lock().unwrap().clone();
        let rpcs: Vec<_> = seen.iter().map(|(rpc, _)| *rpc).collect();
        assert_eq!(
            rpcs,
            [
                "append_entries",
                "vote",
                "install_snapshot",
                "forward_write"
            ],
            "every RPC reached the peer"
        );
        for (rpc, claim) in seen {
            assert_eq!(claim, expected, "{rpc}");
        }
    }

    /// A peer on an older build refuses an entry it cannot decode with serde's
    /// "unknown variant" message; that is recognised so the operator is told
    /// the cluster is mixed-version rather than seeing a bare RPC error.
    #[test]
    fn an_older_peer_refusing_an_unknown_command_is_recognised() {
        let refused = tonic::Status::internal(
            "unknown variant `IncrementU64`, expected one of `Put`, `Delete`, `Batch`, \
             `WriteBatch`, `PutIfAbsent` at line 1 column 312",
        );
        assert!(is_unknown_command_refusal(&refused));
        assert!(!is_unknown_command_refusal(&tonic::Status::internal(
            "Raft not initialised"
        )));
        assert!(!is_unknown_command_refusal(&tonic::Status::unavailable(
            "unknown variant"
        )));
    }

    fn entry(index: u64, value_len: usize) -> openraft::Entry<HearthRaftConfig> {
        openraft::Entry {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), index),
            payload: openraft::EntryPayload::Normal(crate::cluster::RaftCommand::Put {
                leader_timestamp: 1,
                realm: crate::core::RealmId::new(uuid::Uuid::nil()),
                key: b"k".to_vec(),
                value: vec![7; value_len],
            }),
        }
    }

    fn request(
        entries: Vec<openraft::Entry<HearthRaftConfig>>,
    ) -> AppendEntriesRequest<HearthRaftConfig> {
        AppendEntriesRequest {
            vote: openraft::Vote::new_committed(1, 1),
            prev_log_id: None,
            entries,
            leader_commit: None,
        }
    }

    /// A batch whose entries exceed `APPEND_BATCH_BYTES` is cut to the
    /// longest prefix that fits and reports the last entry kept, which the
    /// caller turns into openraft's `PartialSuccess`.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn an_oversized_append_batch_is_cut_to_the_budget() {
        let size = 700 * 1024;
        let mut rpc = request((1..=10).map(|i| entry(i, size)).collect());
        let last = fit_append_batch(&mut rpc).unwrap();
        let kept = rpc.entries.len();
        assert!((1..10).contains(&kept), "kept {kept} of 10");
        assert_eq!(last.map(|l| l.index), Some(kept as u64));
        assert!(wire::encode(&rpc).unwrap().len() <= APPEND_BATCH_BYTES);
        // One more entry would not have fitted.
        let mut one_more = request((1..=kept as u64 + 1).map(|i| entry(i, size)).collect());
        assert!(wire::encode(&one_more.entries).unwrap().len() > APPEND_BATCH_BYTES);
        assert!(fit_append_batch(&mut one_more).unwrap().is_some());
    }

    /// A batch that fits is sent whole, and an entry larger than the budget
    /// still travels (alone) rather than never.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_fitting_batch_is_untouched_and_a_huge_entry_travels_alone() {
        let mut small = request((1..=3).map(|i| entry(i, 1024)).collect());
        assert_eq!(fit_append_batch(&mut small).unwrap(), None);
        assert_eq!(small.entries.len(), 3);

        let mut huge = request(vec![entry(1, 3 * 1024 * 1024), entry(2, 10)]);
        let last = fit_append_batch(&mut huge).unwrap();
        assert_eq!(huge.entries.len(), 1);
        assert_eq!(last.map(|l| l.index), Some(1));
        assert!(encode_bounded(&huge).unwrap().len() <= MAX_PEER_MESSAGE_BYTES);
    }

    /// Verifies factory produces a peer network with the expected address.
    #[tokio::test]
    async fn factory_creates_peer_with_correct_addr() {
        let mut factory = HearthNetworkFactory::new(
            1,
            ClusterIdentity::in_memory(None),
            b"cert".to_vec(),
            b"key".to_vec(),
            b"ca".to_vec(),
        );
        let node = HearthNode {
            addr: "127.0.0.1:8421".to_string(),
        };
        let peer = factory.new_client(2, &node).await;
        assert_eq!(peer.addr, "127.0.0.1:8421");
        assert_eq!(peer.target, 2);
    }

    /// Confirms that a connection failure surfaces as `RPCError::Network`
    /// (no panic) so openraft can handle retries gracefully.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn append_entries_returns_network_error_on_connection_failure() {
        let mut factory = HearthNetworkFactory::new(
            1,
            ClusterIdentity::in_memory(None),
            b"bad".to_vec(),
            b"bad".to_vec(),
            b"bad".to_vec(),
        );
        let node = HearthNode {
            addr: "127.0.0.1:19999".to_string(),
        };
        let mut peer = factory.new_client(99, &node).await;

        let dummy = AppendEntriesRequest::<HearthRaftConfig> {
            vote: openraft::Vote::new(0, 1),
            prev_log_id: None,
            entries: vec![],
            leader_commit: None,
        };
        let result = peer
            .append_entries(dummy, RPCOption::new(std::time::Duration::from_millis(100)))
            .await;

        assert!(
            result.is_err(),
            "expected error on unreachable peer, got Ok"
        );
        let e = result.unwrap_err();
        assert!(
            matches!(e, RPCError::Network(_)),
            "expected RPCError::Network, got {e:?}"
        );
    }

    /// Same guarantee for Vote.
    #[tokio::test]
    async fn vote_returns_network_error_on_connection_failure() {
        let mut factory = HearthNetworkFactory::new(
            1,
            ClusterIdentity::in_memory(None),
            b"bad".to_vec(),
            b"bad".to_vec(),
            b"bad".to_vec(),
        );
        let node = HearthNode {
            addr: "127.0.0.1:19999".to_string(),
        };
        let mut peer = factory.new_client(99, &node).await;

        let dummy = VoteRequest::<u64> {
            vote: openraft::Vote::new(0, 1),
            last_log_id: Some(LogId::new(openraft::CommittedLeaderId::new(0, 1), 0)),
        };
        let result = peer
            .vote(dummy, RPCOption::new(std::time::Duration::from_millis(100)))
            .await;

        // Pin the variant (matching the AppendEntries sibling): a bare is_err()
        // would also pass on an unrelated failure (e.g. a serialization error),
        // masking a regression where connection loss stopped mapping to Network.
        let e = result.expect_err("expected error on unreachable peer, got Ok");
        assert!(
            matches!(e, RPCError::Network(_)),
            "expected RPCError::Network on connection failure, got {e:?}"
        );
    }
}
