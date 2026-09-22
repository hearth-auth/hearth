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
use serde::{de::DeserializeOwned, Serialize};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{debug, warn};

use crate::cluster::error::TransportError;
use crate::cluster::rpc::{
    raft_service_client::RaftServiceClient, AppendEntriesRequest as GrpcAer,
    InstallSnapshotRequest as GrpcIsr, VoteRequest as GrpcVr,
};
use crate::cluster::types::{HearthNode, HearthRaftConfig};

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

    /// Clear every drop and every delay.
    pub fn heal_all(&self) {
        self.with_state(|s| {
            s.isolated.clear();
            s.delays.clear();
        });
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

    fn with_state(&self, f: impl FnOnce(&mut FaultState)) {
        if let Ok(mut s) = self.state.lock() {
            f(&mut s);
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
    /// Test-only outbound-RPC fault injector. `None` on every node built by
    /// `ClusterEngine::build_clustered`, which is the only constructor
    /// `serve` reaches.
    faults: Option<Arc<PeerFaults>>,
}

impl HearthNetworkFactory {
    /// Creates a new factory from PEM-encoded certificate material.
    ///
    /// `cert_pem` and `key_pem` are this node's identity presented to peers.
    /// `ca_pem` is the CA used to verify peer certificates.
    pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>, ca_pem: Vec<u8>) -> Self {
        Self {
            creds: Arc::new(TlsCredentials {
                cert_pem,
                key_pem,
                ca_pem,
            }),
            faults: None,
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
}

impl RaftNetworkFactory<HearthRaftConfig> for HearthNetworkFactory {
    type Network = HearthPeerNetwork;

    async fn new_client(&mut self, target: u64, node: &HearthNode) -> HearthPeerNetwork {
        debug!(node_id = target, addr = %node.addr, "allocating peer network slot");
        HearthPeerNetwork {
            target,
            addr: node.addr.clone(),
            creds: Arc::clone(&self.creds),
            channel: Mutex::new(None),
            faults: self.faults.clone(),
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
    /// Cached tonic `Channel`.
    ///
    /// Lock is held only long enough to clone the channel value — NEVER across
    /// an `.await`. Drop the guard, then await the cloned channel.
    channel: Mutex<Option<Channel>>,
    /// Test-only fault injector; `None` in production. See [`PeerFaults`].
    faults: Option<Arc<PeerFaults>>,
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
        let identity = Identity::from_pem(&self.creds.cert_pem, &self.creds.key_pem);
        let ca = Certificate::from_pem(&self.creds.ca_pem);
        let tls = ClientTlsConfig::new().ca_certificate(ca).identity(identity);

        let endpoint = format!("https://{}", self.addr);
        debug!(node_id = self.target, addr = %endpoint, "connecting to peer over mTLS");

        Channel::from_shared(endpoint.clone())
            .map_err(|e| TransportError::Connect(Box::new(e)))?
            .tls_config(tls)
            .map_err(|e| TransportError::Tls(e.to_string()))?
            .connect()
            .await
            .map_err(|e| {
                warn!(node_id = self.target, addr = %endpoint, error = %e, "peer connection failed");
                TransportError::Connect(Box::new(e))
            })
    }

    /// Applies any injected delay, then fails the call if this peer is
    /// currently isolated. A no-op (one `Option` check) when no injector is
    /// installed, which is every production node.
    async fn gate(&self) -> Result<(), TransportError> {
        let Some(faults) = self.faults.as_ref() else {
            return Ok(());
        };
        let (isolated, delay) = faults.plan(self.target);
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        if isolated {
            debug!(
                node_id = self.target,
                "outbound RPC dropped by injected partition"
            );
            return Err(TransportError::InjectedPartition(self.target));
        }
        Ok(())
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
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<HearthRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, HearthNode, RaftError<u64>>> {
        self.gate().await.map_err(net_err)?;
        let payload = json_enc(&rpc).map_err(|e| net_err(TransportError::Serialize(e)))?;
        let ch = self.get_or_connect().await.map_err(net_err)?;
        let mut client = RaftServiceClient::new(ch);

        let resp = client
            .append_entries(GrpcAer { payload })
            .await
            .map_err(|e| {
                self.invalidate_channel();
                net_err(TransportError::Rpc(e))
            })?;

        json_dec(&resp.into_inner().payload).map_err(|e| net_err(TransportError::Deserialize(e)))
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
        let payload = json_enc(&rpc).map_err(|e| net_err_ise(TransportError::Serialize(e)))?;
        let ch = self.get_or_connect().await.map_err(net_err_ise)?;
        let mut client = RaftServiceClient::new(ch);

        let resp = client
            .install_snapshot(GrpcIsr { payload })
            .await
            .map_err(|e| {
                self.invalidate_channel();
                net_err_ise(TransportError::Rpc(e))
            })?;

        json_dec(&resp.into_inner().payload)
            .map_err(|e| net_err_ise(TransportError::Deserialize(e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, HearthNode, RaftError<u64>>> {
        self.gate().await.map_err(net_err)?;
        let payload = json_enc(&rpc).map_err(|e| net_err(TransportError::Serialize(e)))?;
        let ch = self.get_or_connect().await.map_err(net_err)?;
        let mut client = RaftServiceClient::new(ch);

        let resp = client.vote(GrpcVr { payload }).await.map_err(|e| {
            self.invalidate_channel();
            net_err(TransportError::Rpc(e))
        })?;

        json_dec(&resp.into_inner().payload).map_err(|e| net_err(TransportError::Deserialize(e)))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn json_enc<T: Serialize>(val: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(val)
}

fn json_dec<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(bytes)
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

    /// Verifies factory produces a peer network with the expected address.
    #[tokio::test]
    async fn factory_creates_peer_with_correct_addr() {
        let mut factory =
            HearthNetworkFactory::new(b"cert".to_vec(), b"key".to_vec(), b"ca".to_vec());
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
        let mut factory =
            HearthNetworkFactory::new(b"bad".to_vec(), b"bad".to_vec(), b"bad".to_vec());
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
        let mut factory =
            HearthNetworkFactory::new(b"bad".to_vec(), b"bad".to_vec(), b"bad".to_vec());
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
