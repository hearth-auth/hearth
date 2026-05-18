use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openraft::{
    error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable},
    network::{RPCOption, RaftNetwork, RaftNetworkFactory},
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
    BasicNode,
};
use tokio::sync::{mpsc, oneshot};

use crate::cluster::types::{NodeId, TypeConfig};

// ── Inter-node RPC message types ──────────────────────────────────────────────

pub enum NodeRpc {
    AppendEntries {
        req: AppendEntriesRequest<TypeConfig>,
        resp: oneshot::Sender<Result<AppendEntriesResponse<NodeId>, RaftError<NodeId>>>,
    },
    Vote {
        req: VoteRequest<NodeId>,
        resp: oneshot::Sender<Result<VoteResponse<NodeId>, RaftError<NodeId>>>,
    },
    InstallSnapshot {
        req: InstallSnapshotRequest<TypeConfig>,
        resp: oneshot::Sender<
            Result<InstallSnapshotResponse<NodeId>, RaftError<NodeId, InstallSnapshotError>>,
        >,
    },
}

// ── Shared router: maps NodeId ↦ RPC sender ──────────────────────────────────

#[derive(Clone)]
pub struct MemRouter {
    nodes: Arc<Mutex<HashMap<NodeId, mpsc::Sender<NodeRpc>>>>,
    /// Per-node artificial delay injected before delivering AppendEntries.
    delays: Arc<Mutex<HashMap<NodeId, Duration>>>,
    /// Set of (from, to) pairs whose messages are silently dropped.
    /// Simulates a directed network partition without crashing either node.
    partitions: Arc<Mutex<HashSet<(NodeId, NodeId)>>>,
}

impl MemRouter {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
            delays: Arc::new(Mutex::new(HashMap::new())),
            partitions: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn add_node(&self, id: NodeId, tx: mpsc::Sender<NodeRpc>) {
        self.nodes.lock().unwrap().insert(id, tx);
    }

    pub fn remove_node(&self, id: NodeId) {
        self.nodes.lock().unwrap().remove(&id);
    }

    pub fn set_delay(&self, id: NodeId, delay: Duration) {
        let mut map = self.delays.lock().unwrap();
        if delay.is_zero() {
            map.remove(&id);
        } else {
            map.insert(id, delay);
        }
    }

    /// Block all messages between `a` and `b` in both directions.
    pub fn partition_between(&self, a: NodeId, b: NodeId) {
        let mut p = self.partitions.lock().unwrap();
        p.insert((a, b));
        p.insert((b, a));
    }

    /// Restore bidirectional communication between `a` and `b`.
    pub fn heal_partition(&self, a: NodeId, b: NodeId) {
        let mut p = self.partitions.lock().unwrap();
        p.remove(&(a, b));
        p.remove(&(b, a));
    }

    /// Block all messages to and from `id` (vs. every other registered node).
    pub fn isolate_node(&self, id: NodeId, all_node_ids: &[NodeId]) {
        let mut p = self.partitions.lock().unwrap();
        for &other in all_node_ids {
            if other != id {
                p.insert((id, other));
                p.insert((other, id));
            }
        }
    }

    /// Restore all channels to and from `id`.
    pub fn reconnect_node(&self, id: NodeId) {
        let mut p = self.partitions.lock().unwrap();
        p.retain(|&(a, b)| a != id && b != id);
    }

    fn get_sender(&self, id: NodeId) -> Option<mpsc::Sender<NodeRpc>> {
        self.nodes.lock().unwrap().get(&id).cloned()
    }

    fn get_delay(&self, id: NodeId) -> Option<Duration> {
        self.delays.lock().unwrap().get(&id).copied()
    }

    fn is_partitioned(&self, from: NodeId, to: NodeId) -> bool {
        self.partitions.lock().unwrap().contains(&(from, to))
    }
}

// ── NetworkFactory ────────────────────────────────────────────────────────────

pub struct MemNetworkFactory {
    pub router: MemRouter,
    /// The node ID that owns this factory (the sender side of every connection).
    pub source: NodeId,
}

// openraft 0.9 uses native async fn in traits (requires rustc ≥ 1.75).
// Do NOT add #[async_trait] here — it produces lifetime mismatches.
impl RaftNetworkFactory<TypeConfig> for MemNetworkFactory {
    type Network = MemNetwork;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        MemNetwork {
            source: self.source,
            target,
            router: self.router.clone(),
        }
    }
}

// ── Per-connection network handle ────────────────────────────────────────────

pub struct MemNetwork {
    /// The local node ID — used for partition checks.
    source: NodeId,
    target: NodeId,
    router: MemRouter,
}

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, msg.to_owned())
}

impl RaftNetwork<TypeConfig> for MemNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _opt: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        if self.router.is_partitioned(self.source, self.target) {
            return Err(RPCError::Unreachable(Unreachable::new(&io_err("partitioned"))));
        }

        // Inject per-node delay before delivering to the target.
        if let Some(d) = self.router.get_delay(self.target) {
            tokio::time::sleep(d).await;
        }

        let tx = self.router.get_sender(self.target).ok_or_else(|| {
            RPCError::Unreachable(Unreachable::new(&io_err("node removed from router")))
        })?;

        let (resp_tx, resp_rx) = oneshot::channel();
        tx.send(NodeRpc::AppendEntries { req: rpc, resp: resp_tx })
            .await
            .map_err(|_| RPCError::Unreachable(Unreachable::new(&io_err("ae channel closed"))))?;

        resp_rx
            .await
            .map_err(|_| RPCError::Unreachable(Unreachable::new(&io_err("ae response dropped"))))?
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _opt: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        if self.router.is_partitioned(self.source, self.target) {
            return Err(RPCError::Unreachable(Unreachable::new(&io_err("partitioned"))));
        }

        let tx = self.router.get_sender(self.target).ok_or_else(|| {
            RPCError::Unreachable(Unreachable::new(&io_err("node removed from router")))
        })?;

        let (resp_tx, resp_rx) = oneshot::channel();
        tx.send(NodeRpc::Vote { req: rpc, resp: resp_tx })
            .await
            .map_err(|_| RPCError::Unreachable(Unreachable::new(&io_err("vote channel closed"))))?;

        resp_rx
            .await
            .map_err(|_| {
                RPCError::Unreachable(Unreachable::new(&io_err("vote response dropped")))
            })?
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _opt: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        if self.router.is_partitioned(self.source, self.target) {
            return Err(RPCError::Unreachable(Unreachable::new(&io_err("partitioned"))));
        }

        let tx = self.router.get_sender(self.target).ok_or_else(|| {
            RPCError::Unreachable(Unreachable::new(&io_err("node removed from router")))
        })?;

        let (resp_tx, resp_rx) = oneshot::channel();
        tx.send(NodeRpc::InstallSnapshot { req: rpc, resp: resp_tx })
            .await
            .map_err(|_| RPCError::Unreachable(Unreachable::new(&io_err("snap channel closed"))))?;

        resp_rx
            .await
            .map_err(|_| {
                RPCError::Unreachable(Unreachable::new(&io_err("snap response dropped")))
            })?
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}
