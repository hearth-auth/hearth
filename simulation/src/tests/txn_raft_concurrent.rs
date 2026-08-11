//! Multi-node Raft race simulation for `PutIfAbsent` (HEA-1457).
//!
//! Oracle invariant:
//! - When two concurrent `PutIfAbsent` commands for the same key are proposed
//!   through the Raft leader, exactly one commits with `success: true` and the
//!   other commits with `success: false`.
//!
//! This test validates the core correctness property: `RaftCommand::PutIfAbsent`
//! is applied sequentially by the state machine, so the first committer wins and
//! the second always observes the key already present.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, HashMap};
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

use hearth::cluster::types::{HearthLogResponse, RaftCommand};
use hearth::cluster::{HearthLogStore, HearthNode, HearthRaftConfig, HearthStateMachine};
use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── In-memory network ─────────────────────────────────────────────────────────

type NodeRegistry = Arc<Mutex<HashMap<u64, openraft::Raft<HearthRaftConfig>>>>;

#[derive(Clone)]
struct InMemFactory {
    nodes: NodeRegistry,
}

impl RaftNetworkFactory<HearthRaftConfig> for InMemFactory {
    type Network = InMemPeer;

    async fn new_client(&mut self, target: u64, _node: &HearthNode) -> InMemPeer {
        InMemPeer {
            target,
            nodes: Arc::clone(&self.nodes),
        }
    }
}

struct InMemPeer {
    target: u64,
    nodes: NodeRegistry,
}

impl InMemPeer {
    fn get_raft(&self) -> Option<openraft::Raft<HearthRaftConfig>> {
        self.nodes.lock().unwrap().get(&self.target).cloned()
    }
}

impl RaftNetwork<HearthRaftConfig> for InMemPeer {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<HearthRaftConfig>,
        _opt: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, HearthNode, RaftError<u64>>> {
        match self.get_raft() {
            None => Err(RPCError::Network(NetworkError::new(&io::Error::new(
                io::ErrorKind::NotConnected,
                "node not in registry",
            )))),
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
        match self.get_raft() {
            None => Err(RPCError::Network(NetworkError::new(&io::Error::new(
                io::ErrorKind::NotConnected,
                "node not in registry",
            )))),
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
        match self.get_raft() {
            None => Err(RPCError::Network(NetworkError::new(&io::Error::new(
                io::ErrorKind::NotConnected,
                "node not in registry",
            )))),
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

// ── Cluster helpers ───────────────────────────────────────────────────────────

struct TestNode {
    id: u64,
    raft: openraft::Raft<HearthRaftConfig>,
    storage: Arc<EmbeddedStorageEngine>,
    _dir: tempfile::TempDir,
}

async fn build_cluster(n: usize) -> (Vec<TestNode>, RealmId) {
    let registry: NodeRegistry = Arc::new(Mutex::new(HashMap::new()));
    let raft_config = Arc::new(
        RaftConfig {
            heartbeat_interval: 50,
            election_timeout_min: 150,
            election_timeout_max: 300,
            snapshot_policy: SnapshotPolicy::Never,
            ..RaftConfig::default()
        }
        .validate()
        .unwrap(),
    );

    let mut members: BTreeMap<u64, HearthNode> = BTreeMap::new();
    for i in 0..n {
        let id = (i + 1) as u64;
        members.insert(
            id,
            HearthNode {
                addr: format!("mem-{id}"),
            },
        );
    }

    let mut nodes: Vec<TestNode> = Vec::new();
    for i in 0..n {
        let id = (i + 1) as u64;
        let dir = tempfile::tempdir().unwrap();
        let log_db_path = dir.path().join("raft.db");
        let data_dir = dir.path().join("data");

        let log_store = HearthLogStore::open(&log_db_path).unwrap();
        let storage_config = StorageConfig::dev(data_dir);
        let storage = Arc::new(EmbeddedStorageEngine::open(storage_config).unwrap());
        let sm = HearthStateMachine::new(Arc::clone(&storage) as Arc<dyn StorageEngine>);
        let factory = InMemFactory {
            nodes: Arc::clone(&registry),
        };
        let raft = openraft::Raft::<HearthRaftConfig>::new(
            id,
            Arc::clone(&raft_config),
            factory,
            log_store,
            sm,
        )
        .await
        .unwrap();

        registry.lock().unwrap().insert(id, raft.clone());
        nodes.push(TestNode {
            id,
            raft,
            storage,
            _dir: dir,
        });
    }

    nodes[0].raft.initialize(members).await.unwrap();

    // Wait for a leader to emerge.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if nodes.iter().any(|n| {
            let m = n.raft.metrics().borrow().clone();
            m.current_leader == Some(n.id)
        }) {
            break;
        }
        assert!(Instant::now() < deadline, "no leader within 5 s");
        tokio::time::sleep(Duration::from_millis(50)).await; // AUDIT: justified-sleep: polling Raft leader election, no event-driven alternative
    }

    let realm = RealmId::new(Uuid::new_v4());
    (nodes, realm)
}

fn leader_idx(nodes: &[TestNode]) -> usize {
    nodes
        .iter()
        .position(|n| {
            let m = n.raft.metrics().borrow().clone();
            m.current_leader == Some(n.id)
        })
        .expect("no leader")
}

async fn raft_put_if_absent(
    nodes: &[TestNode],
    realm: &RealmId,
    key: &[u8],
    value: &[u8],
) -> HearthLogResponse {
    let idx = leader_idx(nodes);
    nodes[idx]
        .raft
        .client_write(RaftCommand::PutIfAbsent {
            leader_timestamp: 0,
            realm: realm.clone(),
            key: key.to_vec(),
            value: value.to_vec(),
        })
        .await
        .expect("client_write")
        .data
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Two concurrent `PutIfAbsent` proposals for the same key through the Raft
/// leader: exactly one commits with `success: true`, the other with `false`.
///
/// This validates the core HEA-1457 invariant: the state machine's sequential
/// apply order makes the check-and-write atomic, so the second committer always
/// sees the key already present.
#[tokio::test]
async fn simulation_raft_put_if_absent_exactly_one_winner() {
    let (nodes, realm) = build_cluster(3).await;
    let key = b"txn:used:race-test-001";

    let (resp_a, resp_b) = tokio::join!(
        raft_put_if_absent(&nodes, &realm, key, b"expiry-a"),
        raft_put_if_absent(&nodes, &realm, key, b"expiry-b"),
    );

    let wins = [resp_a.success, resp_b.success]
        .iter()
        .filter(|&&s| s)
        .count();
    let losses = [resp_a.success, resp_b.success]
        .iter()
        .filter(|&&s| !s)
        .count();

    assert_eq!(wins, 1, "exactly one PutIfAbsent must win");
    assert_eq!(
        losses, 1,
        "the losing PutIfAbsent must return success=false"
    );

    // Key must be present in the leader's storage after both commits.
    let stored = nodes[leader_idx(&nodes)].storage.get(&realm, key).unwrap();
    assert!(stored.is_some(), "key must be stored after winner commits");

    for node in &nodes {
        node.raft.shutdown().await.unwrap();
    }
}

/// A sequential second `PutIfAbsent` for an existing key always returns `false` —
/// the guard is durable, not just a race artifact.
#[tokio::test]
async fn simulation_raft_put_if_absent_durable_guard() {
    let (nodes, realm) = build_cluster(3).await;
    let key = b"txn:used:guard-test-001";

    let first = raft_put_if_absent(&nodes, &realm, key, b"1720000060").await;
    assert!(first.success, "first PutIfAbsent must succeed");

    let second = raft_put_if_absent(&nodes, &realm, key, b"1720000060").await;
    assert!(
        !second.success,
        "second PutIfAbsent for same key must return false"
    );

    // A distinct key must still succeed.
    let other = raft_put_if_absent(&nodes, &realm, b"txn:used:guard-test-002", b"v").await;
    assert!(
        other.success,
        "PutIfAbsent for a different key must succeed"
    );

    for node in &nodes {
        node.raft.shutdown().await.unwrap();
    }
}
