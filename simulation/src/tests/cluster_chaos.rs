//! AC-5 through AC-7: Raft chaos scenarios — leader kill mid-write-sequence,
//! WAL replay after crash, and concurrent write contention (HEA-1323).
//!
//! These tests complement the AC-1–AC-4 failover suite in `cluster_failover.rs`
//! by targeting the hardest operational scenarios:
//!
//! AC-5 — Mid-write chaos: the leader is killed while 50 concurrent writes are
//!         in-flight. Every write that Raft committed must be readable on all
//!         surviving nodes after re-election. In-flight writes (neither
//!         committed nor rejected before the kill) are all-or-nothing:
//!         either present on all surviving nodes or absent from all.
//!
//! AC-6 — WAL replay after node crash: a node crashes, reopens its Raft log
//!         and storage from disk, and must reach the same `last_applied` index
//!         as the cluster within 15 s — verifying WAL integrity through crash.
//!
//! AC-7 — Write contention under rolling kills: two waves of writes interleaved
//!         with sequential leader kills. All writes that received a committed
//!         response must be present on every surviving node afterward. No
//!         committed write may be silently discarded across a leadership change.

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

// ── Shared registry types ──────────────────────────────────────────────────────

type NodeRegistry = Arc<Mutex<HashMap<u64, openraft::Raft<HearthRaftConfig>>>>;
type PartitionSet = Arc<Mutex<HashSet<(u64, u64)>>>;

// ── In-memory network factory (mirrors cluster_failover.rs) ───────────────────

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

// ── Test cluster harness ───────────────────────────────────────────────────────

struct NodeHandle {
    id: u64,
    /// `None` once [`ChaosCluster::crash_node`] has released it to simulate process death.
    raft: Option<openraft::Raft<HearthRaftConfig>>,
    /// `None` once [`ChaosCluster::crash_node`] has released it. Dropping the last `Arc`
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

struct ChaosCluster {
    nodes: Vec<NodeHandle>,
    registry: NodeRegistry,
    partitioned: PartitionSet,
    realm: RealmId,
    raft_config: Arc<RaftConfig>,
}

fn make_raft_config() -> Arc<RaftConfig> {
    Arc::new(
        RaftConfig {
            heartbeat_interval: 50,
            election_timeout_min: 150,
            election_timeout_max: 300,
            max_in_snapshot_log_to_keep: 0,
            snapshot_policy: SnapshotPolicy::Never,
            ..RaftConfig::default()
        }
        .validate()
        .expect("valid raft config"),
    )
}

impl ChaosCluster {
    async fn new(n: usize) -> Self {
        let registry: NodeRegistry = Arc::new(Mutex::new(HashMap::new()));
        let partitioned: PartitionSet = Arc::new(Mutex::new(HashSet::new()));
        let raft_config = make_raft_config();

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
                EmbeddedStorageEngine::open(storage_config).expect("storage engine"),
            );
            let sm =
                HearthStateMachine::new(Arc::clone(&storage) as Arc<dyn StorageEngine>);
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

        nodes[0]
            .raft()
            .initialize(members)
            .await
            .expect("initialize");

        // Wait up to 5 s for a leader to emerge.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if nodes
                .iter()
                .any(|n| n.raft().metrics().borrow().current_leader.is_some())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "no leader within 5 s during setup"
            );
            tokio::time::sleep(Duration::from_millis(50)).await; // AUDIT: justified-sleep: polling Raft leader election, no event-driven alternative
        }

        let realm = RealmId::new(Uuid::new_v4());
        ChaosCluster {
            nodes,
            registry,
            partitioned,
            realm,
            raft_config,
        }
    }

    fn leader_idx(&self) -> Option<usize> {
        self.nodes.iter().position(|n| {
            let m = n.raft().metrics().borrow().clone();
            m.current_leader == Some(n.id)
        })
    }

    fn leader_idx_excluding(&self, exclude: &[u64]) -> Option<usize> {
        self.nodes.iter().position(|n| {
            if exclude.contains(&n.id) {
                return false;
            }
            let m = n.raft().metrics().borrow().clone();
            m.current_leader == Some(n.id)
        })
    }

    /// Attempt a single write through the current leader. Returns the log index
    /// on commit success, or `None` if the write was rejected/lost.
    async fn try_write(&self, key: &[u8], value: &[u8], exclude: &[u64]) -> Option<u64> {
        let cmd = RaftCommand::Put {
            leader_timestamp: 0,
            realm: self.realm.clone(),
            key: key.to_vec(),
            value: value.to_vec(),
        };
        let idx = self.leader_idx_excluding(exclude)?;
        self.nodes[idx]
            .raft()
            .client_write(cmd)
            .await
            .ok()
            .map(|r| r.log_id.index)
    }

    /// Write through the leader, retrying until success or timeout.
    async fn write_with_retry(
        &self,
        key: &[u8],
        value: &[u8],
        exclude: &[u64],
        timeout: Duration,
    ) -> Option<u64> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(idx) = self.try_write(key, value, exclude).await {
                return Some(idx);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await; // AUDIT: justified-sleep: polling Raft leader election, no event-driven alternative
        }
    }

    fn read_from(&self, node_idx: usize, key: &[u8]) -> Option<Vec<u8>> {
        self.nodes[node_idx]
            .storage()
            .get(&self.realm, key)
            .expect("storage read")
    }

    fn unregister(&self, id: u64) {
        self.registry.lock().unwrap().remove(&id);
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

    fn register(&self, id: u64, raft: openraft::Raft<HearthRaftConfig>) {
        self.registry.lock().unwrap().insert(id, raft);
    }

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
}

// ── AC-5: Leader kill mid-write-sequence ──────────────────────────────────────

/// AC-5: Given a 3-node cluster, spawn 50 concurrent write tasks (each writing
/// a distinct key). Kill the leader while all 50 tasks are in-flight. After
/// re-election, verify:
///
/// (a) Every write that received a committed response from Raft is present on
///     all surviving nodes with the correct value — no committed write is lost.
///
/// (b) Every write that was NOT committed before the kill is either present on
///     ALL surviving nodes or absent from ALL — the all-or-nothing guarantee.
///     (A write present on some but not all survivors would indicate a split-brain
///     violation — the most severe possible failure.)
#[tokio::test]
async fn simulation_leader_kill_mid_write_sequence() {
    const WRITE_COUNT: u8 = 50;

    let cluster = Arc::new(ChaosCluster::new(3).await);

    // Spawn 50 concurrent writer tasks. Each records whether its write committed.
    let committed: Arc<Mutex<HashMap<u8, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut handles = Vec::new();

    for i in 0..WRITE_COUNT {
        let cluster_ref = Arc::clone(&cluster);
        let committed_ref = Arc::clone(&committed);
        handles.push(tokio::spawn(async move {
            // Each write retries for up to 12 s, covering the election window.
            let result = cluster_ref
                .write_with_retry(&[i], &[i.wrapping_mul(3)], &[], Duration::from_secs(12))
                .await;
            if let Some(idx) = result {
                committed_ref.lock().unwrap().insert(i, idx);
            }
        }));
    }

    // Let writes get in-flight, then kill the leader at an unpredictable point.
    // 30 ms is long enough for some writes to commit but short enough for most
    // to still be in-flight or queued when the leader dies.
    tokio::time::sleep(Duration::from_millis(30)).await; // AUDIT: justified-sleep: deliberate chaos window — kill leader while writes are in-flight

    let killed_id = cluster
        .leader_idx()
        .map(|i| cluster.nodes[i].id)
        .expect("leader must exist before kill");

    cluster.nodes[cluster.leader_idx().unwrap()]
        .raft()
        .shutdown()
        .await
        .expect("shutdown killed leader");
    cluster.unregister(killed_id);

    // Wait for all writer tasks to complete (they retry until success or timeout).
    for handle in handles {
        let _ = handle.await;
    }

    let committed = committed.lock().unwrap().clone();

    // Wait for survivors to apply the highest committed index.
    if let Some(&max_idx) = committed.values().max() {
        let survivor_indices: Vec<usize> = cluster
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.id != killed_id)
            .map(|(i, _)| i)
            .collect();
        cluster
            .wait_applied_on(&survivor_indices, max_idx, Duration::from_secs(10))
            .await;
        // Small propagation buffer: storage apply is async after Raft commit.
        tokio::time::sleep(Duration::from_millis(200)).await; // AUDIT: justified-sleep: polling Raft state convergence, no event-driven alternative
    }

    let survivor_indices: Vec<usize> = cluster
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.id != killed_id)
        .map(|(i, _)| i)
        .collect();

    // AC-5(a): every committed write must be present on all survivors.
    for (&key, &_idx) in &committed {
        for &sidx in &survivor_indices {
            let got = cluster.read_from(sidx, &[key]);
            assert_eq!(
                got,
                Some(vec![key.wrapping_mul(3)]),
                "AC-5(a) FAIL: committed key={key} missing on survivor node {} \
                 (node_idx={sidx})",
                cluster.nodes[sidx].id
            );
        }
    }

    // AC-5(b): for uncommitted writes — either present on ALL survivors or NONE.
    //
    // CAVEAT (HEA-1822 systemic finding #1): this branch is only reachable when
    // the run actually produced uncommitted writes. On a real-thread cluster
    // with no deterministic scheduler (see the crate-level docs) the long write
    // retries usually commit every key, so `committed` covers the whole keyspace
    // and this loop frequently inspects nothing — the split-brain assertion is
    // then vacuous for that pass. It is retained as an opportunistic guard, not
    // a guaranteed-exercised invariant; deterministic split-brain coverage would
    // require a fault-injecting scheduler this harness does not have. The AC-5(a)
    // committed-write check above is the load-bearing invariant of this test.
    for i in 0..WRITE_COUNT {
        if committed.contains_key(&i) {
            continue; // already verified above
        }
        let values: Vec<Option<Vec<u8>>> = survivor_indices
            .iter()
            .map(|&si| cluster.read_from(si, &[i]))
            .collect();
        let all_present = values.iter().all(|v| v.is_some());
        let all_absent = values.iter().all(|v| v.is_none());
        assert!(
            all_present || all_absent,
            "AC-5(b) FAIL: uncommitted key={i} is partially visible across survivors — \
             split-brain violation! values={values:?}"
        );
    }
}

// ── AC-6: WAL replay after node crash ─────────────────────────────────────────

/// AC-6: Given a 3-node cluster that committed N writes, when one node crashes
/// (process killed), reopen its Raft log and storage from the same on-disk paths,
/// and verify the restarted node reaches the same `last_applied` index as the
/// cluster within 15 s — confirming WAL integrity survives a crash.
#[tokio::test]
async fn simulation_wal_replay_after_crash() {
    let mut cluster = ChaosCluster::new(3).await;

    // Write 30 tokens and wait for all nodes to apply them.
    let mut last_idx = 0u64;
    for i in 0u8..30 {
        last_idx = cluster
            .write_with_retry(&[i], &[i.wrapping_mul(7)], &[], Duration::from_secs(5))
            .await
            .expect("write must succeed before crash");
    }

    let all_indices: Vec<usize> = (0..3).collect();
    cluster
        .wait_applied_on(&all_indices, last_idx, Duration::from_secs(10))
        .await;

    // Pick a non-leader follower to "crash" (shutdown without removing from membership).
    let leader_id = cluster.nodes[cluster.leader_idx().expect("leader")].id;
    let crash_pos = cluster
        .nodes
        .iter()
        .position(|n| n.id != leader_id)
        .unwrap();

    // Releases the node's Raft handle *and* its storage engine, so the exclusive
    // `data_dir` lock is freed exactly as it would be if the process had been killed.
    let crash_id = cluster.crash_node(crash_pos).await;

    // Simulate more writes while the node is down (log will need replay on rejoin).
    for i in 30u8..40 {
        let logged = cluster
            .write_with_retry(
                &[i],
                &[i.wrapping_mul(7)],
                &[crash_id],
                Duration::from_secs(5),
            )
            .await
            .expect("write while follower down");
        last_idx = last_idx.max(logged);
    }

    // Reopen the crashed node from its original on-disk state (WAL replay path).
    let log_store =
        HearthLogStore::open(&cluster.nodes[crash_pos].log_db_path).expect("reopen log store");
    let storage_config = StorageConfig::dev(cluster.nodes[crash_pos].data_dir.clone());
    let storage = Arc::new(
        EmbeddedStorageEngine::open(storage_config).expect("reopen storage engine"),
    );
    let sm = HearthStateMachine::new(Arc::clone(&storage) as Arc<dyn StorageEngine>);
    let factory = InMemoryNetworkFactory::new(
        crash_id,
        Arc::clone(&cluster.registry),
        Arc::clone(&cluster.partitioned),
    );
    let restarted = openraft::Raft::<HearthRaftConfig>::new(
        crash_id,
        Arc::clone(&cluster.raft_config),
        factory,
        log_store,
        sm,
    )
    .await
    .expect("raft new after crash");

    cluster.register(crash_id, restarted.clone());

    // AC-6: the restarted node must reach `last_idx` within 15 s.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let m = restarted.metrics().borrow().clone();
        let applied = m.last_applied.as_ref().map(|id| id.index).unwrap_or(0);
        if applied >= last_idx {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "AC-6 FAIL: restarted node {crash_id} did not reach applied index {last_idx} \
             within 15 s after WAL replay (current applied = {applied})"
        );
        tokio::time::sleep(Duration::from_millis(100)).await; // AUDIT: justified-sleep: polling Raft state convergence, no event-driven alternative
    }

    // Read back through the same engine the restarted state machine writes to — `sm` was
    // constructed from `Arc::clone(&storage)`, so this *is* the post-replay state. (Opening
    // a second engine on this `data_dir` would now fail with `AlreadyLocked`, and would be
    // redundant regardless.)
    // Verify all 40 tokens are present on the replayed node.
    for i in 0u8..40 {
        let got = storage.get(&cluster.realm, &[i]).expect("storage read");
        assert_eq!(
            got,
            Some(vec![i.wrapping_mul(7)]),
            "AC-6 FAIL: key={i} missing on node {crash_id} after WAL replay"
        );
    }
}

// ── AC-7: Write contention across two leadership changes ──────────────────────

/// AC-7: Given a 5-node cluster, run two rounds of write+kill. After each kill
/// a new leader is elected. All writes that Raft confirmed as committed must be
/// present on every surviving node after both leadership transitions. Validates
/// that committed writes survive two sequential leadership changes — the pattern
/// most likely to expose incorrect log truncation or index reset bugs.
///
/// NOTE: the writes within each round are issued *sequentially*, not
/// concurrently — the only source of contention is the leadership change
/// itself. The name reflects that (committed-write survival across leadership
/// changes), not concurrent write contention.
///
/// A 5-node cluster is required: killing 2 leaders still leaves 3 survivors,
/// which satisfies the ⌊5/2⌋ + 1 = 3 quorum requirement. A 3-node cluster
/// would lose quorum after the second kill (only 1 node left).
#[tokio::test]
async fn simulation_committed_writes_survive_sequential_leadership_changes() {
    let cluster = Arc::new(ChaosCluster::new(5).await);

    let mut committed_keys: HashMap<u8, u8> = HashMap::new();
    let mut killed_ids: Vec<u64> = Vec::new();

    for round in 0u8..2 {
        let offset = round * 20;
        let leader_idx = cluster
            .leader_idx_excluding(&killed_ids)
            .expect("leader at round start");
        let leader_id = cluster.nodes[leader_idx].id;

        // Write 10 keys under the current leader.
        for i in 0u8..10 {
            let key = offset + i;
            let val = key.wrapping_mul(5);
            let result = cluster
                .write_with_retry(&[key], &[val], &killed_ids, Duration::from_secs(8))
                .await;
            if result.is_some() {
                committed_keys.insert(key, val);
            }
        }

        // Kill the current leader, triggering re-election.
        cluster.nodes[leader_idx]
            .raft()
            .shutdown()
            .await
            .expect("shutdown");
        cluster.unregister(leader_id);
        killed_ids.push(leader_id);

        // Wait for a new leader on the remaining nodes.
        let election_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if cluster.leader_idx_excluding(&killed_ids).is_some() {
                break;
            }
            assert!(
                Instant::now() < election_deadline,
                "AC-7 FAIL (round {round}): no new leader within 10 s"
            );
            tokio::time::sleep(Duration::from_millis(100)).await; // AUDIT: justified-sleep: polling Raft state convergence, no event-driven alternative
        }
    }

    // Wait for all surviving nodes to converge.
    let survivor_indices: Vec<usize> = cluster
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| !killed_ids.contains(&n.id))
        .map(|(i, _)| i)
        .collect();

    tokio::time::sleep(Duration::from_millis(500)).await; // AUDIT: justified-sleep: polling Raft state convergence, no event-driven alternative

    // AC-7: every key that received a committed response must be on all survivors.
    for (&key, &val) in &committed_keys {
        for &sidx in &survivor_indices {
            let got = cluster.read_from(sidx, &[key]);
            assert_eq!(
                got,
                Some(vec![val]),
                "AC-7 FAIL: committed key={key} (val={val}) missing on survivor node {} \
                 after 2 leadership changes",
                cluster.nodes[sidx].id
            );
        }
    }
}
