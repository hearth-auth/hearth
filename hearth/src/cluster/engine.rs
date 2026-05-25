use std::collections::BTreeSet;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use openraft::{BasicNode, ChangeMembers, Config, Raft};
use tokio::sync::mpsc;

use crate::cluster::router::{MemNetworkFactory, MemRouter, NodeRpc};
use crate::cluster::store::{MemLogStore, MemStateMachine};
use crate::cluster::types::{KVCommand, NodeId, TypeConfig};
use crate::storage::EmbeddedStorageEngine;

/// Concrete Raft type used throughout the Hearth codebase.
pub type HearthRaft = Raft<TypeConfig>;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Point-in-time snapshot of the cluster's voter membership.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MembershipView {
    pub voters: BTreeSet<NodeId>,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("not the leader; redirect to {leader_addr}")]
    NotLeader { leader_addr: String },

    #[error("replication lag exceeded threshold; redirect to {leader_addr}")]
    ReplicationLagExceeded { leader_addr: String },

    #[error("quorum violation: removing a voter from {current} voters would leave {remaining}, minimum required is {minimum}")]
    QuorumViolation {
        current: usize,
        remaining: usize,
        minimum: usize,
    },

    #[error("cluster already bootstrapped")]
    AlreadyBootstrapped,

    #[error("raft error: {0}")]
    Raft(#[from] anyhow::Error),
}

// ── ClusterNode ───────────────────────────────────────────────────────────────

/// A single Hearth node.  Wraps a Raft instance, a shared KV store, and a
/// background lag-monitor that sets `reads_allowed`.
pub struct ClusterNode {
    pub id: NodeId,
    raft: Arc<HearthRaft>,
    /// Shared with `MemStateMachine`: both read/write the same HashMap.
    pub storage: EmbeddedStorageEngine,
    reads_allowed: Arc<AtomicBool>,
    /// Inject per-entry sleep inside apply() to simulate a slow follower.
    /// This makes last_applied lag behind last_log_index so the lag monitor fires.
    pub apply_delay_ms: Arc<AtomicU64>,
}

impl ClusterNode {
    /// Construct and start a cluster node.  Returns the node plus the RPC sender
    /// that must be registered with the router before the cluster is initialized.
    pub async fn new(
        id: NodeId,
        config: Arc<Config>,
        router: MemRouter,
        read_lag_threshold_ms: u64,
    ) -> (Self, mpsc::Sender<NodeRpc>) {
        let kv = EmbeddedStorageEngine::new();
        let log_store = MemLogStore::new();
        let sm = MemStateMachine::new(kv.clone());
        let apply_delay_ms = sm.apply_delay_ms.clone();
        let reads_allowed = Arc::new(AtomicBool::new(true));

        let network_factory = MemNetworkFactory {
            router: router.clone(),
            source: id,
        };

        let raft = Arc::new(
            Raft::new(id, config, network_factory, log_store, sm)
                .await
                .expect("raft init failed"),
        );

        let (rpc_tx, rpc_rx) = mpsc::channel(256);

        // Drive incoming network RPCs.
        tokio::spawn(run_rpc_loop(raft.clone(), rpc_rx));

        // Update reads_allowed from Raft metrics.
        tokio::spawn(lag_monitor(
            raft.clone(),
            reads_allowed.clone(),
            id,
            read_lag_threshold_ms,
        ));

        let node = Self {
            id,
            raft,
            storage: kv,
            reads_allowed,
            apply_delay_ms,
        };
        (node, rpc_tx)
    }

    pub fn raft(&self) -> &Arc<HearthRaft> {
        &self.raft
    }

    pub fn reads_allowed(&self) -> bool {
        self.reads_allowed.load(Ordering::Relaxed)
    }

    /// Write a KV pair.  Returns `ClusterError::NotLeader` if this node is a
    /// follower.  `client_write` blocks until quorum commit.
    pub async fn write(&self, key: String, value: String) -> Result<(), ClusterError> {
        let cmd = KVCommand { key, value };
        self.raft
            .client_write(cmd)
            .await
            .map(|_| ())
            .map_err(|e| ClusterError::Raft(anyhow::anyhow!("{e}")))
    }

    /// Read a value from the local state machine.  Respects `reads_allowed`.
    pub fn get(&self, key: &str) -> Result<Option<String>, ClusterError> {
        if !self.reads_allowed.load(Ordering::Relaxed) {
            return Err(ClusterError::ReplicationLagExceeded {
                leader_addr: "unknown".to_string(),
            });
        }
        Ok(self.storage.get(key))
    }

    pub async fn shutdown(&self) {
        let _ = self.raft.shutdown().await;
    }

    // ── Membership changes ────────────────────────────────────────────────────

    /// Current voter set, read from Raft metrics.
    fn current_voters(&self) -> BTreeSet<NodeId> {
        let metrics = self.raft.metrics();
        let m = metrics.borrow();
        m.membership_config.membership().voter_ids().collect()
    }

    /// Snapshot of the current cluster voter membership.
    pub fn current_membership(&self) -> MembershipView {
        MembershipView { voters: self.current_voters() }
    }

    /// Add `node_id` as a non-voting learner.
    ///
    /// Blocks (`blocking = true`) until the learner has replicated up to the
    /// current commit index.  Call `add_voter` afterward to promote it.
    pub async fn add_learner(
        &self,
        node_id: NodeId,
        node: BasicNode,
    ) -> Result<MembershipView, ClusterError> {
        let voters = self.current_voters();
        tracing::info!(node_id = %node_id, ?voters, "membership change: adding learner");
        self.raft
            .add_learner(node_id, node, true)
            .await
            .map_err(|e| ClusterError::Raft(anyhow::anyhow!("{e}")))?;
        tracing::info!(node_id = %node_id, "membership change: learner added");
        Ok(MembershipView { voters })
    }

    /// Promote `node_id` from learner to voter via joint consensus.
    ///
    /// The node must be a learner that has already caught up before this call.
    pub async fn add_voter(&self, node_id: NodeId) -> Result<MembershipView, ClusterError> {
        let before = self.current_voters();
        let mut after = before.clone();
        after.insert(node_id);
        tracing::info!(node_id = %node_id, ?before, ?after, "membership change: promoting to voter");
        self.raft
            .change_membership(ChangeMembers::ReplaceAllVoters(after.clone()), true)
            .await
            .map_err(|e| ClusterError::Raft(anyhow::anyhow!("{e}")))?;
        tracing::info!(node_id = %node_id, ?after, "membership change: voter promoted");
        Ok(MembershipView { voters: after })
    }

    /// Remove `node_id` from the voter set via joint consensus.
    ///
    /// Returns `ClusterError::QuorumViolation` when the removal would drop the
    /// cluster below the minimum quorum (`⌊n/2⌋ + 1` voters).
    pub async fn remove_voter(&self, node_id: NodeId) -> Result<MembershipView, ClusterError> {
        let before = self.current_voters();
        let n = before.len();
        let minimum = n / 2 + 1;
        let remaining = n.saturating_sub(1);
        if remaining < minimum {
            return Err(ClusterError::QuorumViolation { current: n, remaining, minimum });
        }
        let after: BTreeSet<NodeId> = before.iter().copied().filter(|&id| id != node_id).collect();
        tracing::info!(node_id = %node_id, ?before, ?after, "membership change: removing voter");
        self.raft
            .change_membership(ChangeMembers::ReplaceAllVoters(after.clone()), false)
            .await
            .map_err(|e| ClusterError::Raft(anyhow::anyhow!("{e}")))?;
        tracing::info!(node_id = %node_id, ?after, "membership change: voter removed");
        Ok(MembershipView { voters: after })
    }
}

// ── RPC dispatch loop ─────────────────────────────────────────────────────────

/// Each node runs this loop to dispatch incoming network RPCs to its Raft handle.
pub async fn run_rpc_loop(raft: Arc<HearthRaft>, mut rx: mpsc::Receiver<NodeRpc>) {
    while let Some(msg) = rx.recv().await {
        let raft = raft.clone();
        tokio::spawn(async move {
            match msg {
                NodeRpc::AppendEntries { req, resp } => {
                    let _ = resp.send(raft.append_entries(req).await);
                }
                NodeRpc::Vote { req, resp } => {
                    let _ = resp.send(raft.vote(req).await);
                }
                NodeRpc::InstallSnapshot { req, resp } => {
                    let _ = resp.send(raft.install_snapshot(req).await);
                }
            }
        });
    }
}

// ── Lag monitor ───────────────────────────────────────────────────────────────

/// Background task: watches Raft metrics and updates `reads_allowed`.
///
/// A node allows follower reads when its replication lag (approximated as
/// `(committed_index - applied_index) × 5ms`) is under `threshold_ms`.
/// Leaders are always allowed to serve reads.
async fn lag_monitor(
    raft: Arc<HearthRaft>,
    reads_allowed: Arc<AtomicBool>,
    my_id: NodeId,
    threshold_ms: u64,
) {
    let mut rx = raft.metrics();
    loop {
        if rx.changed().await.is_err() {
            break;
        }
        let m = rx.borrow().clone();

        // Leaders are the source of truth.
        if m.current_leader == Some(my_id) {
            reads_allowed.store(true, Ordering::Relaxed);
            continue;
        }

        // Approximate lag: entries received but not yet applied.
        let last_index = m.last_log_index.unwrap_or(0);
        let applied = m.last_applied.map(|l| l.index).unwrap_or(0);
        let lag_entries = last_index.saturating_sub(applied);
        // Rough heuristic: 5 ms per log entry (conservative for smoke test).
        let lag_ms = lag_entries * 5;
        reads_allowed.store(lag_ms <= threshold_ms, Ordering::Relaxed);
    }
}

// ── TestCluster — test-only harness ──────────────────────────────────────────

/// Convenience wrapper for spinning up an in-process N-node cluster.
/// Included in all builds so integration tests (separate crates) can import it.
pub mod test_harness {
    use super::*;
    use std::collections::BTreeMap;
    use openraft::{BasicNode, SnapshotPolicy};

    pub struct TestCluster {
        pub nodes: BTreeMap<NodeId, ClusterNode>,
        pub router: MemRouter,
        config: Arc<Config>,
        read_lag_threshold_ms: u64,
    }

    impl TestCluster {
        /// Spin up an n-node cluster with default config.
        pub async fn new(n: u64) -> Self {
            Self::new_with_options(n, None).await
        }

        /// Spin up an n-node cluster that triggers a snapshot after every
        /// `snapshot_threshold` new log entries.  Setting this low forces
        /// restarted nodes to install a snapshot rather than replay the log.
        pub async fn new_with_snapshot_threshold(n: u64, snapshot_threshold: u64) -> Self {
            Self::new_with_options(n, Some(snapshot_threshold)).await
        }

        async fn new_with_options(n: u64, snapshot_threshold: Option<u64>) -> Self {
            let router = MemRouter::new();
            let snapshot_policy = snapshot_threshold
                .map(SnapshotPolicy::LogsSinceLast)
                .unwrap_or(SnapshotPolicy::LogsSinceLast(5000));
            let max_in_snapshot_log_to_keep = snapshot_threshold.unwrap_or(1000);
            let config = Arc::new(
                Config {
                    election_timeout_min: 100,
                    election_timeout_max: 300,
                    heartbeat_interval: 50,
                    snapshot_policy,
                    max_in_snapshot_log_to_keep,
                    ..Default::default()
                }
                .validate()
                .expect("config valid"),
            );
            let read_lag_threshold_ms = 500;

            let mut nodes = BTreeMap::new();
            for id in 1..=n {
                let (node, rpc_tx) = ClusterNode::new(
                    id,
                    config.clone(),
                    router.clone(),
                    read_lag_threshold_ms,
                )
                .await;
                router.add_node(id, rpc_tx);
                nodes.insert(id, node);
            }

            // Bootstrap: initialize from node 1 with all members.
            let members: BTreeMap<NodeId, BasicNode> =
                (1..=n).map(|id| (id, BasicNode::default())).collect();
            nodes[&1]
                .raft()
                .initialize(members)
                .await
                .expect("cluster init failed");

            Self {
                nodes,
                router,
                config,
                read_lag_threshold_ms,
            }
        }

        /// Wait for any LIVE node to report a leader.
        /// Polls all nodes so that calling this after kill_node(1) still works.
        pub async fn wait_for_leader(&self) -> NodeId {
            loop {
                for node in self.nodes.values() {
                    let m = node.raft().metrics().borrow().clone();
                    if let Some(leader) = m.current_leader {
                        // Confirm the winner is in our live set.
                        if self.nodes.contains_key(&leader) {
                            return leader;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        pub async fn wait_for_leader_timeout(&self, timeout: Duration) -> NodeId {
            tokio::time::timeout(timeout, self.wait_for_leader())
                .await
                .expect("timed out waiting for leader")
        }

        /// Returns the current leader ID visible to any live node.
        pub fn current_leader(&self) -> Option<NodeId> {
            for node in self.nodes.values() {
                let m = node.raft().metrics().borrow().clone();
                if let Some(l) = m.current_leader {
                    if self.nodes.contains_key(&l) {
                        return Some(l);
                    }
                }
            }
            None
        }

        /// Write to the cluster, retrying on transient leadership errors.
        ///
        /// openraft maps "not leader / forward to X" into a raw Raft error
        /// (not ClusterError::NotLeader), so we retry on ALL errors here
        /// to handle leadership transitions gracefully in tests.
        pub async fn write(
            &self,
            key: impl Into<String>,
            value: impl Into<String>,
        ) -> Result<(), ClusterError> {
            let key = key.into();
            let value = value.into();
            for _ in 0..20 {
                let leader_id = match self.current_leader() {
                    Some(l) => l,
                    None => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };

                if let Some(node) = self.nodes.get(&leader_id) {
                    match node.write(key.clone(), value.clone()).await {
                        Ok(()) => return Ok(()),
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            Err(ClusterError::Raft(anyhow::anyhow!("no leader after retries")))
        }

        /// Write directly to a specific node, bypassing leader detection.
        /// Use this during partitions when `current_leader()` may return
        /// a partitioned node that still thinks it is leader.
        pub async fn write_to_node(
            &self,
            node_id: NodeId,
            key: impl Into<String>,
            value: impl Into<String>,
        ) -> Result<(), ClusterError> {
            let key = key.into();
            let value = value.into();
            for _ in 0..20 {
                if let Some(node) = self.nodes.get(&node_id) {
                    match node.write(key.clone(), value.clone()).await {
                        Ok(()) => return Ok(()),
                        Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                    }
                } else {
                    return Err(ClusterError::Raft(anyhow::anyhow!("node {node_id} not found")));
                }
            }
            Err(ClusterError::Raft(anyhow::anyhow!("write_to_node {node_id}: no success after retries")))
        }

        pub fn read(&self, node_id: NodeId, key: &str) -> Option<String> {
            self.nodes[&node_id].storage.get(key)
        }

        pub fn reads_allowed(&self, node_id: NodeId) -> bool {
            self.nodes[&node_id].reads_allowed()
        }

        pub fn read_with_staleness_check(
            &self,
            node_id: NodeId,
            key: &str,
        ) -> Result<Option<String>, ClusterError> {
            self.nodes[&node_id].get(key)
        }

        /// Kill a node: shut down its Raft instance and remove it from both
        /// the router and the live-nodes map so wait_for_leader skips it.
        pub async fn kill_node(&mut self, node_id: NodeId) {
            if let Some(node) = self.nodes.remove(&node_id) {
                node.shutdown().await;
            }
            self.router.remove_node(node_id);
        }

        /// Restart a previously killed node.  Uses a fresh log/state-machine so
        /// openraft will replicate or snapshot-install everything from the leader.
        pub async fn restart_node(&mut self, node_id: NodeId) {
            let (node, rpc_tx) = ClusterNode::new(
                node_id,
                self.config.clone(),
                self.router.clone(),
                self.read_lag_threshold_ms,
            )
            .await;
            self.router.add_node(node_id, rpc_tx);
            self.nodes.insert(node_id, node);
        }

        pub async fn shutdown(self) {
            for (_, node) in self.nodes {
                node.shutdown().await;
            }
        }

        /// Inject a network-level delay on AppendEntries to `node_id`.
        pub fn set_network_delay(&self, node_id: NodeId, delay: Duration) {
            self.router.set_delay(node_id, delay);
        }

        /// Inject a per-entry apply() delay on `node_id`.
        /// This makes last_applied lag behind last_log_index, which is what
        /// the lag monitor checks to set reads_allowed=false.
        pub fn set_apply_delay(&self, node_id: NodeId, delay_ms: u64) {
            if let Some(node) = self.nodes.get(&node_id) {
                node.apply_delay_ms.store(delay_ms, std::sync::atomic::Ordering::Relaxed);
            }
        }

        /// Spin up a new node and register it with the router without changing
        /// Raft membership.  Call `ClusterNode::add_learner` then `add_voter`
        /// on the leader to bring it into the consensus group.
        pub async fn spin_up_node(&mut self, id: NodeId) {
            let (node, rpc_tx) = ClusterNode::new(
                id,
                self.config.clone(),
                self.router.clone(),
                self.read_lag_threshold_ms,
            )
            .await;
            self.router.add_node(id, rpc_tx);
            self.nodes.insert(id, node);
        }

        /// Returns `(leader_id, &leader_node)` for the current leader, or `None`.
        pub fn leader_node(&self) -> Option<(NodeId, &ClusterNode)> {
            let id = self.current_leader()?;
            Some((id, self.nodes.get(&id)?))
        }

        /// Block all messages between `a` and `b` (simulates a network partition).
        /// Unlike `kill_node`, both nodes stay running and can communicate with others.
        pub fn partition_between(&self, a: NodeId, b: NodeId) {
            self.router.partition_between(a, b);
        }

        /// Restore bidirectional communication between `a` and `b`.
        pub fn heal_partition(&self, a: NodeId, b: NodeId) {
            self.router.heal_partition(a, b);
        }

        /// Cut `id` off from every other live node in the cluster.
        pub fn isolate_node(&self, id: NodeId) {
            let all: Vec<NodeId> = self.nodes.keys().copied().collect();
            self.router.isolate_node(id, &all);
        }

        /// Restore all network links to/from `id`.
        pub fn reconnect_node(&self, id: NodeId) {
            self.router.reconnect_node(id);
        }

        /// All live node IDs.
        pub fn node_ids(&self) -> Vec<NodeId> {
            self.nodes.keys().copied().collect()
        }
    }
}

// ── ClusterEngine — HTTP-facing cluster API ───────────────────────────────────

use std::collections::BTreeMap as PeerMap;

/// Response types for the three admin endpoints.
#[derive(Debug)]
pub struct BootstrapResult {
    pub node_id: NodeId,
    pub term: u64,
    pub leader_id: NodeId,
}

#[derive(Debug)]
pub struct PeerInfo {
    pub id: NodeId,
    pub addr: String,
    pub is_healthy: bool,
}

#[derive(Debug)]
pub struct StatusResult {
    pub role: String,
    pub term: u64,
    pub last_applied_index: Option<u64>,
    pub peers: Vec<PeerInfo>,
}

/// HTTP-facing cluster manager: wraps a `ClusterNode` with peer topology and
/// own node identity, exposing the three `/admin/cluster/*` operations.
pub struct ClusterEngine {
    inner: Arc<ClusterNode>,
    self_node_id: NodeId,
    /// NodeId → "host:port" for all cluster members (including self).
    peer_addrs: PeerMap<NodeId, String>,
}

impl ClusterEngine {
    pub fn new(
        node: Arc<ClusterNode>,
        self_node_id: NodeId,
        peer_addrs: PeerMap<NodeId, String>,
    ) -> Self {
        Self { inner: node, self_node_id, peer_addrs }
    }

    pub fn self_node_id(&self) -> NodeId {
        self.self_node_id
    }

    /// Bootstrap the cluster from the configured peer list.
    /// Returns 409-equivalent `AlreadyBootstrapped` if already initialized.
    pub async fn bootstrap(&self) -> Result<BootstrapResult, ClusterError> {
        use openraft::error::{InitializeError, RaftError};
        let members: PeerMap<NodeId, openraft::BasicNode> = self
            .peer_addrs
            .keys()
            .map(|&id| (id, openraft::BasicNode::default()))
            .collect();
        match self.inner.raft().initialize(members).await {
            Ok(()) => {}
            Err(RaftError::APIError(InitializeError::NotAllowed(_))) => {
                return Err(ClusterError::AlreadyBootstrapped);
            }
            Err(e) => return Err(ClusterError::Raft(anyhow::anyhow!("{e}"))),
        }
        let m = self.inner.raft().metrics().borrow().clone();
        Ok(BootstrapResult {
            node_id: self.self_node_id,
            term: m.current_term,
            leader_id: m.current_leader.unwrap_or(self.self_node_id),
        })
    }

    /// Read current cluster status from Raft metrics (non-blocking).
    pub fn status(&self) -> StatusResult {
        let m = self.inner.raft().metrics().borrow().clone();
        let role = match m.current_leader {
            Some(id) if id == self.self_node_id => "leader",
            Some(_) => "follower",
            None => "candidate",
        }
        .to_string();
        let last_applied_index = m.last_applied.map(|l| l.index);
        let peers = self
            .peer_addrs
            .iter()
            .filter(|(&id, _)| id != self.self_node_id)
            .map(|(&id, addr)| {
                let is_healthy = m
                    .replication
                    .as_ref()
                    .map(|r| r.get(&id).map_or(false, |v| v.is_some()))
                    .unwrap_or(false);
                PeerInfo { id, addr: addr.clone(), is_healthy }
            })
            .collect();
        StatusResult { role, term: m.current_term, last_applied_index, peers }
    }

    /// Gracefully transfer leadership.  Triggers an election so another node
    /// wins; polls for up to 5 s.  The `preferred` target is best-effort.
    ///
    /// # Cancellation safety
    /// `ElectRestoreGuard` ensures `elect(true)` is called on drop even if this
    /// future is cancelled (e.g. HTTP connection drop) between `elect(false)` and
    /// the final restore — preventing permanent election-loss (see HEA-762).
    pub async fn transfer_leadership(
        &self,
        preferred: Option<NodeId>,
    ) -> Result<NodeId, ClusterError> {
        let m = self.inner.raft().metrics().borrow().clone();
        if m.current_leader != Some(self.self_node_id) {
            let leader_addr = m
                .current_leader
                .and_then(|id| self.peer_addrs.get(&id).cloned())
                .unwrap_or_default();
            return Err(ClusterError::NotLeader { leader_addr });
        }
        // Prevent this node from re-winning the next election.  The guard calls
        // elect(true) on drop, so every code path (success, timeout, cancel) restores.
        self.inner.raft().runtime_config().elect(false);
        let _elect_guard = ElectRestoreGuard(Arc::clone(self.inner.raft()));

        self.inner
            .raft()
            .trigger()
            .elect()
            .await
            .map_err(|e| ClusterError::Raft(anyhow::anyhow!("{e}")))?;

        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let new_leader = loop {
            let m = self.inner.raft().metrics().borrow().clone();
            if let Some(leader) = m.current_leader {
                if leader != self.self_node_id {
                    break leader;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ClusterError::Raft(anyhow::anyhow!(
                    "transfer-leadership: timeout waiting for new leader"
                )));
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        let _ = preferred; // accepted for forward-compat; winner is whoever wins
        Ok(new_leader)
    }
}

// ── ElectRestoreGuard ─────────────────────────────────────────────────────────

/// RAII guard that re-enables election on drop.
/// Created immediately after `runtime_config().elect(false)` in
/// `transfer_leadership` so that task cancellation can never leave the node
/// permanently unable to win elections.
struct ElectRestoreGuard(Arc<HearthRaft>);

impl Drop for ElectRestoreGuard {
    fn drop(&mut self) {
        self.0.runtime_config().elect(true);
    }
}
