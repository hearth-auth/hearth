//! AC-1 through AC-4: multi-node Raft HA failover simulation (HEA-738).
//!
//! Tests use an in-memory network factory to create 3-node Raft clusters
//! entirely in-process — no TLS, no gRPC, no real ports.
//!
//! AC-1 — Partition: tokens committed before a network partition are readable
//!         on every node after the partition heals.
//! AC-2 — Leader kill: a new leader is elected within 10 s; no data loss.
//! AC-3 — Rolling restart: zero read errors while nodes restart one at a time.
//! AC-4 — Snapshot catch-up: a cold follower reaches parity via snapshot install.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openraft::{
    error::{InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError},
    network::{RPCOption, RaftNetwork, RaftNetworkFactory},
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
    Config as RaftConfig, SnapshotPolicy,
};
use uuid::Uuid;

use hearth::cluster::types::RaftCommand;
use hearth::cluster::{HearthLogStore, HearthNode, HearthRaftConfig, HearthStateMachine};
use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Shared registry types ─────────────────────────────────────────────────────

type NodeRegistry = Arc<Mutex<HashMap<u64, openraft::Raft<HearthRaftConfig>>>>;
type PartitionSet = Arc<Mutex<HashSet<(u64, u64)>>>;

// ── In-memory network factory ─────────────────────────────────────────────────

/// Per-node network factory. Each node gets its own copy (with its own node ID)
/// but all copies share the cluster-wide registry and partition set via Arc.
#[derive(Clone)]
struct InMemoryNetworkFactory {
    self_id: u64,
    nodes: NodeRegistry,
    partitioned: PartitionSet,
}

impl InMemoryNetworkFactory {
    fn new(self_id: u64, nodes: NodeRegistry, partitioned: PartitionSet) -> Self {
        Self {
            self_id,
            nodes,
            partitioned,
        }
    }
}

impl RaftNetworkFactory<HearthRaftConfig> for InMemoryNetworkFactory {
    type Network = InMemoryPeer;

    async fn new_client(&mut self, target: u64, _node: &HearthNode) -> InMemoryPeer {
        InMemoryPeer {
            source_id: self.self_id,
            target,
            nodes: Arc::clone(&self.nodes),
            partitioned: Arc::clone(&self.partitioned),
        }
    }
}

// ── In-memory peer connection ─────────────────────────────────────────────────

struct InMemoryPeer {
    source_id: u64,
    target: u64,
    nodes: NodeRegistry,
    partitioned: PartitionSet,
}

impl InMemoryPeer {
    fn is_partitioned(&self) -> bool {
        self.partitioned
            .lock()
            .unwrap()
            .contains(&(self.source_id, self.target))
    }

    fn get_raft(&self) -> Option<openraft::Raft<HearthRaftConfig>> {
        self.nodes.lock().unwrap().get(&self.target).cloned()
    }
}

impl RaftNetwork<HearthRaftConfig> for InMemoryPeer {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<HearthRaftConfig>,
        _opt: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, HearthNode, RaftError<u64>>> {
        if self.is_partitioned() {
            let e = io::Error::new(io::ErrorKind::ConnectionRefused, "simulated partition");
            return Err(RPCError::Network(NetworkError::new(&e)));
        }
        match self.get_raft() {
            None => {
                let e = io::Error::new(io::ErrorKind::NotConnected, "node not in registry");
                Err(RPCError::Network(NetworkError::new(&e)))
            }
            Some(raft) => raft.append_entries(rpc).await.map_err(|source| {
                RPCError::RemoteError(RemoteError {
                    target: self.target,
                    target_node: None,
                    source,
                })
            }),
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<HearthRaftConfig>,
        _opt: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, HearthNode, RaftError<u64, InstallSnapshotError>>,
    > {
        if self.is_partitioned() {
            let e = io::Error::new(io::ErrorKind::ConnectionRefused, "simulated partition");
            return Err(RPCError::Network(NetworkError::new(&e)));
        }
        match self.get_raft() {
            None => {
                let e = io::Error::new(io::ErrorKind::NotConnected, "node not in registry");
                Err(RPCError::Network(NetworkError::new(&e)))
            }
            Some(raft) => raft.install_snapshot(rpc).await.map_err(|source| {
                RPCError::RemoteError(RemoteError {
                    target: self.target,
                    target_node: None,
                    source,
                })
            }),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _opt: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, HearthNode, RaftError<u64>>> {
        if self.is_partitioned() {
            let e = io::Error::new(io::ErrorKind::ConnectionRefused, "simulated partition");
            return Err(RPCError::Network(NetworkError::new(&e)));
        }
        match self.get_raft() {
            None => {
                let e = io::Error::new(io::ErrorKind::NotConnected, "node not in registry");
                Err(RPCError::Network(NetworkError::new(&e)))
            }
            Some(raft) => raft.vote(rpc).await.map_err(|source| {
                RPCError::RemoteError(RemoteError {
                    target: self.target,
                    target_node: None,
                    source,
                })
            }),
        }
    }
}

// ── Test cluster helpers ──────────────────────────────────────────────────────

struct NodeHandle {
    id: u64,
    /// `None` once [`TestCluster::crash_node`] has released it to simulate process death.
    raft: Option<openraft::Raft<HearthRaftConfig>>,
    /// `None` once [`TestCluster::crash_node`] has released it. Dropping the last `Arc`
    /// releases the engine's exclusive `data_dir` lock, which is what lets the same
    /// directory be reopened afterwards.
    storage: Option<Arc<EmbeddedStorageEngine>>,
    data_dir: std::path::PathBuf,
    log_db_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl NodeHandle {
    /// The node's Raft handle. Panics if the node has been crashed.
    fn raft(&self) -> &openraft::Raft<HearthRaftConfig> {
        self.raft
            .as_ref()
            .expect("node has been crashed; its Raft handle was released")
    }

    /// The node's storage engine. Panics if the node has been crashed.
    fn storage(&self) -> &Arc<EmbeddedStorageEngine> {
        self.storage
            .as_ref()
            .expect("node has been crashed; its storage engine was released")
    }
}

struct TestCluster {
    nodes: Vec<NodeHandle>,
    registry: NodeRegistry,
    partitioned: PartitionSet,
    realm: RealmId,
    raft_config: Arc<RaftConfig>,
}

fn make_raft_config(snapshot_policy: SnapshotPolicy) -> Arc<RaftConfig> {
    Arc::new(
        RaftConfig {
            heartbeat_interval: 50,
            election_timeout_min: 150,
            election_timeout_max: 300,
            max_in_snapshot_log_to_keep: 0,
            snapshot_policy,
            ..RaftConfig::default()
        }
        .validate()
        .expect("valid raft config"),
    )
}

impl TestCluster {
    async fn new(n: usize, snapshot_policy: SnapshotPolicy) -> Self {
        let registry: NodeRegistry = Arc::new(Mutex::new(HashMap::new()));
        let partitioned: PartitionSet = Arc::new(Mutex::new(HashSet::new()));
        let raft_config = make_raft_config(snapshot_policy);

        let mut members: BTreeMap<u64, HearthNode> = BTreeMap::new();
        for i in 0..n {
            let id = (i + 1) as u64;
            members.insert(
                id,
                HearthNode {
                    addr: format!("mem-node-{id}"),
                },
            );
        }

        let mut nodes: Vec<NodeHandle> = Vec::new();
        for i in 0..n {
            let id = (i + 1) as u64;
            let dir = tempfile::tempdir().expect("tempdir");
            let log_db_path = dir.path().join("raft.db");
            let data_dir = dir.path().join("data");

            let log_store = HearthLogStore::open(&log_db_path).expect("log store");
            let storage_config = StorageConfig::dev(data_dir.clone());
            let storage = Arc::new(
                EmbeddedStorageEngine::open(storage_config.clone()).expect("storage engine"),
            );
            let sm = HearthStateMachine::new(
                Arc::clone(&storage) as Arc<dyn StorageEngine>,
                storage_config,
            );
            let factory =
                InMemoryNetworkFactory::new(id, Arc::clone(&registry), Arc::clone(&partitioned));
            let raft = openraft::Raft::<HearthRaftConfig>::new(
                id,
                Arc::clone(&raft_config),
                factory,
                log_store,
                sm,
            )
            .await
            .expect("raft new");

            registry.lock().unwrap().insert(id, raft.clone());
            nodes.push(NodeHandle {
                id,
                raft: Some(raft),
                storage: Some(storage),
                data_dir,
                log_db_path,
                _dir: dir,
            });
        }

        // Bootstrap from node 1.
        nodes[0]
            .raft()
            .initialize(members)
            .await
            .expect("initialize cluster");

        // Wait up to 5 s for a leader to emerge.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let has_leader = nodes
                .iter()
                .any(|n| n.raft().metrics().borrow().current_leader.is_some());
            if has_leader {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "no leader elected within 5 s during cluster setup"
            );
            tokio::time::sleep(Duration::from_millis(50)).await; // AUDIT: justified-sleep: polling Raft leader election, no event-driven alternative
        }

        let realm = RealmId::new(Uuid::new_v4());
        TestCluster {
            nodes,
            registry,
            partitioned,
            realm,
            raft_config,
        }
    }

    /// Index of the node that currently believes itself to be leader.
    fn leader_idx(&self) -> Option<usize> {
        self.nodes.iter().position(|n| {
            let m = n.raft().metrics().borrow().clone();
            m.current_leader == Some(n.id)
        })
    }

    /// Index of the node that currently believes itself to be leader,
    /// excluding nodes with the given IDs.
    fn leader_idx_excluding(&self, exclude: &[u64]) -> Option<usize> {
        self.nodes.iter().position(|n| {
            if exclude.contains(&n.id) {
                return false;
            }
            let m = n.raft().metrics().borrow().clone();
            m.current_leader == Some(n.id)
        })
    }

    /// Write a key-value pair through the current leader. Retries up to 5 s.
    async fn write_kv(&self, key: &[u8], value: &[u8]) -> u64 {
        self.write_kv_excluding(key, value, &[]).await
    }

    /// Write through the leader, skipping excluded node IDs (e.g., killed nodes).
    async fn write_kv_excluding(&self, key: &[u8], value: &[u8], exclude: &[u64]) -> u64 {
        let cmd = RaftCommand::Put {
            leader_timestamp: 0,
            realm: self.realm.clone(),
            key: key.to_vec(),
            value: value.to_vec(),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(idx) = self.leader_idx_excluding(exclude) {
                if let Ok(resp) = self.nodes[idx].raft().client_write(cmd.clone()).await {
                    return resp.log_id.index;
                }
            }
            assert!(Instant::now() < deadline, "write_kv timed out after 5 s");
            tokio::time::sleep(Duration::from_millis(50)).await; // AUDIT: justified-sleep: polling Raft leader election, no event-driven alternative
        }
    }

    /// Read a key directly from a node's storage (bypasses Raft read path).
    fn read_from(&self, node_idx: usize, key: &[u8]) -> Option<Vec<u8>> {
        self.nodes[node_idx]
            .storage()
            .get(&self.realm, key)
            .expect("storage read")
    }

    /// Partition all traffic between `a_id` and `b_id` (both directions).
    fn partition(&self, a_id: u64, b_id: u64) {
        let mut p = self.partitioned.lock().unwrap();
        p.insert((a_id, b_id));
        p.insert((b_id, a_id));
    }

    /// Heal the partition between `a_id` and `b_id`.
    fn heal(&self, a_id: u64, b_id: u64) {
        let mut p = self.partitioned.lock().unwrap();
        p.remove(&(a_id, b_id));
        p.remove(&(b_id, a_id));
    }

    /// Remove a node from the registry (simulates crash/shutdown for routing).
    fn unregister(&self, id: u64) {
        self.registry.lock().unwrap().remove(&id);
    }

    /// Re-register a raft instance in the registry.
    fn register(&self, id: u64, raft: openraft::Raft<HearthRaftConfig>) {
        self.registry.lock().unwrap().insert(id, raft);
    }

    /// Simulates process death for node `pos`: shuts the Raft node down, removes it from
    /// the in-memory network registry, and drops every handle to its storage engine.
    ///
    /// Dropping the engine is what releases the exclusive `data_dir` advisory lock — the
    /// same thing the kernel does when a real process exits. Without it, reopening the
    /// node's `data_dir` fails with `StorageError::AlreadyLocked`, because a crashed
    /// process cannot still be holding its own database open.
    ///
    /// The node's `TempDir` is deliberately kept alive so the on-disk state survives for
    /// the reopen/replay path.
    async fn crash_node(&mut self, pos: usize) -> u64 {
        let id = self.nodes[pos].id;
        let raft = self.nodes[pos]
            .raft
            .take()
            .expect("node has already been crashed");
        raft.shutdown().await.expect("shutdown (crash)");
        self.unregister(id);
        drop(raft);
        drop(self.nodes[pos].storage.take());
        id
    }

    /// Reinstalls the handles of a node previously released by [`Self::crash_node`], so
    /// later iterations read through the *restarted* engine rather than the dead one.
    fn restore_node(
        &mut self,
        pos: usize,
        raft: openraft::Raft<HearthRaftConfig>,
        storage: Arc<EmbeddedStorageEngine>,
    ) {
        self.nodes[pos].raft = Some(raft);
        self.nodes[pos].storage = Some(storage);
    }

    /// Wait until all listed node indices have applied at least `min_index`.
    async fn wait_applied_on(&self, indices: &[usize], min_index: u64, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let all_ok = indices.iter().all(|&i| {
                let m = self.nodes[i].raft().metrics().borrow().clone();
                m.last_applied.as_ref().map(|id| id.index).unwrap_or(0) >= min_index
            });
            if all_ok {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "nodes did not reach applied index {min_index} within timeout"
            );
            tokio::time::sleep(Duration::from_millis(100)).await; // AUDIT: justified-sleep: polling Raft state convergence, no event-driven alternative
        }
    }

    /// Wait until all nodes have applied at least `min_index`.
    async fn wait_applied(&self, min_index: u64, timeout: Duration) {
        let all: Vec<usize> = (0..self.nodes.len()).collect();
        self.wait_applied_on(&all, min_index, timeout).await;
    }
}

// ── AC-1: Network partition and convergence ───────────────────────────────────

/// Given a 3-node cluster with a simulated network partition between the leader
/// and one follower, when the partition heals, all 3 nodes converge to the same
/// `last_applied_index` and all tokens written before the partition are readable
/// on every node.
#[tokio::test]
async fn simulation_partition_and_convergence() {
    let cluster = TestCluster::new(3, SnapshotPolicy::Never).await;

    // Write 5 tokens before the partition.
    let mut last_idx = 0u64;
    for i in 0u8..5 {
        last_idx = cluster.write_kv(&[i], &[i * 10]).await;
    }

    // Identify leader and a follower to isolate.
    let leader_id = cluster.nodes[cluster.leader_idx().expect("leader")].id;
    let follower_id = cluster.nodes.iter().find(|n| n.id != leader_id).unwrap().id;
    let follower_idx = cluster
        .nodes
        .iter()
        .position(|n| n.id == follower_id)
        .unwrap();

    // Partition leader from one follower. Leader still has quorum with the other.
    cluster.partition(leader_id, follower_id);

    // Write 5 more tokens — succeeds because leader + one follower = quorum.
    for i in 5u8..10 {
        last_idx = cluster.write_kv(&[i], &[i * 10]).await;
    }

    // Heal partition.
    cluster.heal(leader_id, follower_id);

    // AC-1 convergence gate: all 3 nodes must reach last_idx.
    cluster
        .wait_applied(last_idx, Duration::from_secs(10))
        .await;

    // Small propagation buffer before asserting storage reads.
    tokio::time::sleep(Duration::from_millis(200)).await; // AUDIT: justified-sleep: polling Raft state convergence, no event-driven alternative

    // Verify convergence on all applied indices.
    let applied: Vec<u64> = cluster
        .nodes
        .iter()
        .map(|n| {
            n.raft()
                .metrics()
                .borrow()
                .last_applied
                .as_ref()
                .map(|id| id.index)
                .unwrap_or(0)
        })
        .collect();
    assert!(
        applied.iter().all(|&i| i >= last_idx),
        "AC-1 FAIL: not all nodes converged — applied indices: {:?}, expected >= {last_idx}",
        applied
    );

    // All 10 tokens must be readable on the formerly-partitioned follower.
    for i in 0u8..10 {
        let got = cluster.read_from(follower_idx, &[i]);
        assert_eq!(
            got,
            Some(vec![i * 10]),
            "AC-1 FAIL: token key={i} missing on follower (node {follower_id}) after heal"
        );
    }
}

// ── AC-2: Leader kill and re-election ────────────────────────────────────────

/// Given a 3-node cluster actively processing writes, when the leader is killed,
/// a new leader is elected within 10 s, in-flight writes succeed on the new
/// leader, and no token is duplicated.
#[tokio::test]
async fn simulation_leader_kill_and_election() {
    let cluster = TestCluster::new(3, SnapshotPolicy::Never).await;

    // Write 3 tokens to establish committed baseline.
    let mut last_idx = 0u64;
    for i in 0u8..3 {
        last_idx = cluster.write_kv(&[i], &[i * 10]).await;
    }
    // Let state machines apply before kill.
    cluster.wait_applied(last_idx, Duration::from_secs(5)).await;

    // Record and kill the leader.
    let leader_idx = cluster.leader_idx().expect("leader before kill");
    let killed_id = cluster.nodes[leader_idx].id;
    cluster.nodes[leader_idx]
        .raft()
        .shutdown()
        .await
        .expect("shutdown");
    cluster.unregister(killed_id);

    // AC-2(a): new leader must emerge within 10 s.
    let election_start = Instant::now();
    let deadline = election_start + Duration::from_secs(10);
    loop {
        if cluster.leader_idx_excluding(&[killed_id]).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "AC-2 FAIL: no new leader elected within 10 s after leader kill"
        );
        tokio::time::sleep(Duration::from_millis(100)).await; // AUDIT: justified-sleep: polling Raft state convergence, no event-driven alternative
    }
    let election_ms = election_start.elapsed().as_millis();

    // AC-2(b): write 3 more tokens on the new leader (retry path exercises
    // in-flight recovery after the old leader died).
    for i in 3u8..6 {
        last_idx = cluster
            .write_kv_excluding(&[i], &[i * 10], &[killed_id])
            .await;
    }

    // Wait for the 2 surviving nodes to apply all entries.
    let survivors: Vec<usize> = cluster
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.id != killed_id)
        .map(|(i, _)| i)
        .collect();
    cluster
        .wait_applied_on(&survivors, last_idx, Duration::from_secs(5))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await; // AUDIT: justified-sleep: polling Raft state convergence, no event-driven alternative

    // All 6 tokens must be readable on both surviving nodes.
    for &sidx in &survivors {
        // Tokens 0-2 committed before kill.
        for i in 0u8..3 {
            let got = cluster.read_from(sidx, &[i]);
            assert_eq!(
                got,
                Some(vec![i * 10]),
                "AC-2 FAIL: pre-kill token {i} missing on node {}",
                cluster.nodes[sidx].id
            );
        }
        // Tokens 3-5 written after re-election.
        for i in 3u8..6 {
            let got = cluster.read_from(sidx, &[i]);
            assert_eq!(
                got,
                Some(vec![i * 10]),
                "AC-2 FAIL: post-election token {i} missing on node {}",
                cluster.nodes[sidx].id
            );
        }
    }

    // AC-2(c): no duplication — each key has exactly one value.
    for &sidx in &survivors {
        for i in 0u8..6 {
            // Compare the Option directly: `unwrap_or_default()` would fold a
            // missing key into an empty vec, blurring "absent" and "wrong value".
            let v = cluster.read_from(sidx, &[i]);
            assert_eq!(
                v,
                Some(vec![i * 10]),
                "AC-2 FAIL: missing, duplicate, or corrupted value for token {i} on node {}",
                cluster.nodes[sidx].id
            );
        }
    }

    assert!(
        election_ms <= 10_000,
        "AC-2 FAIL: election took {election_ms} ms, exceeds 10 s limit"
    );
}

// ── AC-3: Rolling restart with zero read errors ───────────────────────────────

/// Given a 3-node cluster under load, when each node is restarted one at a
/// time (the restarted node rejoins before the next is stopped), zero
/// validate_token (read) errors are returned from the two non-restarting nodes.
#[tokio::test]
async fn simulation_rolling_restart_zero_errors() {
    let mut cluster = TestCluster::new(3, SnapshotPolicy::Never).await;

    // Establish committed baseline.
    let mut last_idx = 0u64;
    for i in 0u8..5 {
        last_idx = cluster.write_kv(&[i], &[i * 10]).await;
    }
    cluster.wait_applied(last_idx, Duration::from_secs(5)).await;

    let mut read_errors: u64 = 0;

    for restart_pos in 0..3usize {
        // Shut down the node, remove it from routing, and release its storage engine so
        // the exclusive `data_dir` lock is free for the reopen below.
        let restart_id = cluster.crash_node(restart_pos).await;

        // While the node is down, verify the two peers serve reads without error.
        for _ in 0..5 {
            for peer_pos in 0..3usize {
                if peer_pos == restart_pos {
                    continue;
                }
                for i in 0u8..5 {
                    match cluster.nodes[peer_pos].storage().get(&cluster.realm, &[i]) {
                        Ok(_) => {}
                        Err(_) => read_errors += 1,
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await; // AUDIT: justified-sleep: polling Raft leader election, no event-driven alternative
        }

        // Reopen the node from the same on-disk state (simulates process restart).
        let log_store =
            HearthLogStore::open(&cluster.nodes[restart_pos].log_db_path).expect("reopen log");
        let storage_config = StorageConfig::dev(cluster.nodes[restart_pos].data_dir.clone());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(storage_config.clone()).expect("reopen storage"));
        let sm = HearthStateMachine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            storage_config,
        );
        let factory = InMemoryNetworkFactory::new(
            restart_id,
            Arc::clone(&cluster.registry),
            Arc::clone(&cluster.partitioned),
        );
        let restarted = openraft::Raft::<HearthRaftConfig>::new(
            restart_id,
            Arc::clone(&cluster.raft_config),
            factory,
            log_store,
            sm,
        )
        .await
        .expect("raft new after restart");

        cluster.register(restart_id, restarted.clone());
        // Reinstall the live handles so later loop iterations read this node through the
        // restarted engine, not the one that was just released.
        cluster.restore_node(restart_pos, restarted.clone(), Arc::clone(&storage));

        // Wait for the restarted node to catch up before continuing.
        let catch_up_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let m = restarted.metrics().borrow().clone();
            if m.last_applied.as_ref().map(|id| id.index).unwrap_or(0) >= last_idx {
                break;
            }
            assert!(
                Instant::now() < catch_up_deadline,
                "AC-3 FAIL: restarted node {restart_id} did not rejoin within 10 s"
            );
            tokio::time::sleep(Duration::from_millis(100)).await; // AUDIT: justified-sleep: polling Raft state convergence, no event-driven alternative
        }
    }

    assert_eq!(
        read_errors, 0,
        "AC-3 FAIL: {read_errors} read errors observed during rolling restart window"
    );
}

// ── AC-4: Snapshot catch-up for a cold follower ───────────────────────────────

/// Given a 3-node cluster where a follower is isolated immediately (simulating a
/// cold start with no prior log), when the isolation is healed after the leader
/// has taken a snapshot, the cold node reaches `last_applied_index` parity within
/// 30 s via snapshot installation.
#[tokio::test]
async fn simulation_snapshot_catchup_new_follower() {
    // Never auto-snapshot during writes — manual trigger below forces compaction
    // after the 20-write loop completes, so the cold node must use snapshot catch-up.
    let mut cluster = TestCluster::new(3, SnapshotPolicy::Never).await;

    // Always isolate a FOLLOWER — isolating the leader would block all writes
    // because the leader cannot reach quorum with itself alone.
    let leader_idx = cluster.leader_idx().expect("leader at start");
    let leader_id = cluster.nodes[leader_idx].id;

    // Pick the first non-leader as the cold node.
    let cold_idx = (0..3).find(|&i| cluster.nodes[i].id != leader_id).unwrap();
    let cold_id = cluster.nodes[cold_idx].id;

    // Collect the IDs of the two active (non-cold) nodes.
    let peer_ids: Vec<u64> = cluster
        .nodes
        .iter()
        .filter(|n| n.id != cold_id)
        .map(|n| n.id)
        .collect();

    // Partition cold from all peers.
    for &pid in &peer_ids {
        cluster.partition(cold_id, pid);
    }

    // Write 20 tokens on the 2-node quorum; explicitly skip the cold node.
    let mut last_idx = 0u64;
    for i in 0u8..20 {
        last_idx = cluster.write_kv_excluding(&[i], &[i * 2], &[cold_id]).await;
    }

    // Wait for the two active nodes to apply all entries.
    let active_indices: Vec<usize> = (0..3).filter(|&i| i != cold_idx).collect();
    cluster
        .wait_applied_on(&active_indices, last_idx, Duration::from_secs(10))
        .await;

    // Force a snapshot on the leader so old log entries are compacted away.
    cluster.nodes[leader_idx]
        .raft()
        .trigger()
        .snapshot()
        .await
        .expect("trigger snapshot");

    // Allow the snapshot to build and log purge to settle.
    tokio::time::sleep(Duration::from_millis(500)).await; // AUDIT: justified-sleep: waiting for snapshot install completion, no event-driven alternative

    // Heal partition — cold node reconnects with empty log (no prior state).
    for &pid in &peer_ids {
        cluster.heal(cold_id, pid);
    }

    // AC-4 parity gate: cold node must catch up within 30 s via snapshot install.
    let parity_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let m = cluster.nodes[cold_idx].raft().metrics().borrow().clone();
        let applied = m.last_applied.as_ref().map(|id| id.index).unwrap_or(0);
        if applied >= last_idx {
            break;
        }
        assert!(
            Instant::now() < parity_deadline,
            "AC-4 FAIL: cold node {cold_id} has not reached applied index {last_idx} \
             within 30 s (current applied = {applied})"
        );
        tokio::time::sleep(Duration::from_millis(200)).await; // AUDIT: justified-sleep: polling Raft state convergence, no event-driven alternative
    }

    // Verify data by reopening storage from disk: snapshot install atomically renames a
    // freshly-replayed directory over `data_dir`, so the cold node's original `Arc` still
    // points at the renamed-away inode and is genuinely stale. Shut the node down first so
    // its engine (and the exclusive `data_dir` lock) is released before reopening.
    cluster.crash_node(cold_idx).await;
    let fresh_storage =
        EmbeddedStorageEngine::open(StorageConfig::dev(cluster.nodes[cold_idx].data_dir.clone()))
            .expect("reopen cold-node storage after snapshot install");

    for i in 0u8..20 {
        let got = fresh_storage
            .get(&cluster.realm, &[i])
            .expect("storage read");
        assert_eq!(
            got,
            Some(vec![i * 2]),
            "AC-4 FAIL: token key={i} missing on cold node {cold_id} after snapshot catch-up"
        );
    }
}
