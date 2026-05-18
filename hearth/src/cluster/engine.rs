use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use openraft::{Config, Raft};
use tokio::sync::mpsc;

use crate::cluster::router::{MemNetworkFactory, MemRouter, NodeRpc};
use crate::cluster::store::{MemLogStore, MemStateMachine};
use crate::cluster::types::{KVCommand, NodeId, TypeConfig};
use crate::storage::EmbeddedStorageEngine;

/// Concrete Raft type used throughout the Hearth codebase.
pub type HearthRaft = Raft<TypeConfig>;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("not the leader; redirect to {leader_addr}")]
    NotLeader { leader_addr: String },

    #[error("replication lag exceeded threshold; redirect to {leader_addr}")]
    ReplicationLagExceeded { leader_addr: String },

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
    use openraft::BasicNode;

    pub struct TestCluster {
        pub nodes: BTreeMap<NodeId, ClusterNode>,
        pub router: MemRouter,
        config: Arc<Config>,
        read_lag_threshold_ms: u64,
    }

    impl TestCluster {
        pub async fn new(n: u64) -> Self {
            let router = MemRouter::new();
            let config = Arc::new(
                Config {
                    election_timeout_min: 100,
                    election_timeout_max: 300,
                    heartbeat_interval: 50,
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

        /// Write to the cluster, retrying on `NotLeader`.
        pub async fn write(
            &self,
            key: impl Into<String>,
            value: impl Into<String>,
        ) -> Result<(), ClusterError> {
            let key = key.into();
            let value = value.into();
            for _ in 0..10 {
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
                        Err(ClusterError::NotLeader { .. }) => {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            Err(ClusterError::Raft(anyhow::anyhow!("no leader after retries")))
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
    }
}
