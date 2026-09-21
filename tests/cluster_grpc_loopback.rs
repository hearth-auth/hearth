//! HEA-612: 3-node loopback integration test for the gRPC peer transport.
//!
//! Spins up three `ClusterEngine::build_clustered` instances on `127.0.0.1`
//! loopback addresses, each with its own mTLS identity signed by a throwaway
//! CA generated in a tempdir, bootstraps a Raft cluster from node 1, writes
//! 10 KV entries to the leader, and asserts every node converges on the same
//! state via real gRPC + mTLS round-trips.
//!
//! This is the only test that drives the peer transport over real sockets;
//! `simulation/src/tests/cluster_failover.rs` and `cluster_chaos.rs` cover
//! failover and crash recovery through an in-process `RaftNetwork` instead.
//! (An earlier version of this comment pointed at `tests/cluster_smoke.rs`,
//! which does not exist — see `reports/cluster-ga-readiness-2026-09-21.md` D-5.)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::cluster::{serve, ClusterEngine, HearthNode, PeerFaults};
use hearth::config::ClusterConfig;
use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tempfile::TempDir;
use uuid::Uuid;

// ── Throwaway mTLS bundle ────────────────────────────────────────────────────

/// Generates one self-signed CA plus `n_nodes` leaf certs valid for
/// `127.0.0.1` and `localhost`, writes them as PEM files under `dir`, and
/// returns `(ca_path, [(cert_path, key_path); n_nodes])`.
///
/// Mirrors the rcgen 0.13 pattern already established in `tests/tls.rs` so
/// the test follows the codebase's existing cert convention.
fn generate_cluster_certs(dir: &Path, n_nodes: usize) -> (PathBuf, Vec<(PathBuf, PathBuf)>) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("ca keygen");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, ca_cert.pem()).expect("write ca cert");

    let mut leafs = Vec::with_capacity(n_nodes);
    for i in 1..=n_nodes {
        let leaf_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("leaf params");
        let leaf_key = rcgen::KeyPair::generate().expect("leaf keygen");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("leaf sign");

        let cert_path = dir.join(format!("node-{i}.crt.pem"));
        let key_path = dir.join(format!("node-{i}.key.pem"));
        std::fs::write(&cert_path, leaf_cert.pem()).expect("write leaf cert");
        std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write leaf key");

        leafs.push((cert_path, key_path));
    }
    (ca_path, leafs)
}

// ── Free-port discovery ──────────────────────────────────────────────────────

/// Pre-binds `n` listeners on `127.0.0.1:0` to discover OS-assigned ports,
/// then drops the listeners so the test's gRPC servers can re-bind. There is
/// a small race window between drop and re-bind, but acceptable for an
/// integration test in a controlled environment.
fn pick_free_loopback_ports(n: usize) -> Vec<u16> {
    use std::net::TcpListener;
    let mut ports = Vec::with_capacity(n);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        ports.push(l.local_addr().expect("local_addr").port());
        listeners.push(l);
    }
    drop(listeners);
    ports
}

// ── Test fixture ─────────────────────────────────────────────────────────────

struct TestCluster {
    engines: Vec<Arc<ClusterEngine>>,
    /// Per-node outbound-RPC fault injector, indexed like `engines`.
    faults: Vec<Arc<PeerFaults>>,
    server_handles: Vec<tokio::task::JoinHandle<()>>,
    // Held to keep cert + data files alive for the lifetime of the test.
    _tempdir: TempDir,
}

impl TestCluster {
    /// Builds an n-node loopback cluster with the default write bound.
    async fn build(n: usize) -> Self {
        Self::build_with_write_timeout(n, None).await
    }

    /// Builds an n-node loopback cluster: generates certs, spawns each
    /// node's gRPC server, bootstraps membership from node 1, and returns
    /// once `initialize_cluster` has been accepted.
    ///
    /// Every node is built through
    /// `ClusterEngine::build_clustered_with_peer_faults`, so a test can cut
    /// any node's outbound Raft edge at will.
    async fn build_with_write_timeout(n: usize, write_timeout_ms: Option<u64>) -> Self {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let (ca_path, leaf_certs) = generate_cluster_certs(tempdir.path(), n);
        let ports = pick_free_loopback_ports(n);

        let mut engines = Vec::with_capacity(n);
        let mut faults = Vec::with_capacity(n);
        let mut server_handles = Vec::with_capacity(n);
        let mut configs = Vec::with_capacity(n);

        for i in 0..n {
            let node_id = (i + 1) as u64;
            let data_dir = tempdir.path().join(format!("node-{node_id}-data"));
            std::fs::create_dir_all(&data_dir).expect("create data dir");

            let storage_cfg = StorageConfig::dev(data_dir);
            let storage =
                Arc::new(EmbeddedStorageEngine::open(storage_cfg.clone()).expect("open storage"));

            let (cert_path, key_path) = leaf_certs[i].clone();
            let cluster_cfg = ClusterConfig {
                node_id,
                peer_address: format!("127.0.0.1:{}", ports[i]),
                peers: vec![],
                tls_cert_path: cert_path,
                tls_key_path: key_path,
                tls_ca_cert_path: ca_path.clone(),
                // Generous so the lag-monitor doesn't gate `get()` during the
                // brief replication window after the writes burst.
                read_lag_threshold_ms: Some(10_000),
                write_timeout_ms,
            };

            let node_faults = PeerFaults::new();
            let engine = ClusterEngine::build_clustered_with_peer_faults(
                storage,
                &cluster_cfg,
                &storage_cfg,
                Arc::clone(&node_faults),
            )
            .await
            .expect("build_clustered_with_peer_faults");
            let engine = Arc::new(engine);
            faults.push(node_faults);

            let server_engine = Arc::clone(&engine);
            let serve_cfg = cluster_cfg.clone();
            let handle = tokio::spawn(async move {
                // serve() returns when the underlying tonic Server stops.
                // Errors during forced shutdown are uninteresting for the test.
                let _ = serve(&serve_cfg, server_engine).await;
            });

            engines.push(engine);
            configs.push(cluster_cfg);
            server_handles.push(handle);
        }

        // Give every server a moment to bind its TCP listener before the
        // bootstrap RPC tries to reach the peers.
        tokio::time::sleep(Duration::from_millis(400)).await; // AUDIT: justified-sleep: gRPC listeners need OS scheduling time to bind before the bootstrap RPC attempts connections

        let mut members = BTreeMap::new();
        for cfg in &configs {
            members.insert(
                cfg.node_id,
                HearthNode {
                    addr: cfg.peer_address.clone(),
                },
            );
        }
        engines[0]
            .initialize_cluster(members)
            .await
            .expect("initialize_cluster from node 1");

        Self {
            engines,
            faults,
            server_handles,
            _tempdir: tempdir,
        }
    }

    /// Polls every node's metrics until at least one node reports a stable
    /// leader (and the leader sees itself as the leader). Panics on timeout.
    async fn wait_for_leader(&self, timeout: Duration) -> u64 {
        let start = Instant::now();
        loop {
            for engine in &self.engines {
                let Some(metrics) = engine.raft_metrics() else {
                    continue;
                };
                let Some(leader) = metrics.current_leader else {
                    continue;
                };
                // Confirm the elected leader also reports itself as leader —
                // a freshly-elected node briefly disagrees with its followers.
                let self_view = self
                    .engines
                    .iter()
                    .find_map(|e| e.raft_metrics().filter(|m| m.id == leader));
                if let Some(m) = self_view {
                    if m.current_leader == Some(leader) {
                        return leader;
                    }
                }
            }
            if start.elapsed() > timeout {
                for engine in &self.engines {
                    if let Some(m) = engine.raft_metrics() {
                        eprintln!(
                            "node {} state={:?} current_leader={:?}",
                            m.id, m.state, m.current_leader
                        );
                    }
                }
                panic!("no leader elected within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await; // AUDIT: justified-sleep: poll interval inside leader-election loop; openraft exposes no ready-signal channel
        }
    }

    /// Index of `node_id` within `engines`/`faults`.
    fn pos_of(&self, node_id: u64) -> usize {
        self.engines
            .iter()
            .position(|e| e.raft_metrics().map(|m| m.id == node_id).unwrap_or(false))
            .expect("node id present in cluster")
    }

    /// Every node's ID except `node_id`.
    fn peers_of(&self, node_id: u64) -> Vec<u64> {
        self.engines
            .iter()
            .filter_map(|e| e.raft_metrics().map(|m| m.id))
            .filter(|id| *id != node_id)
            .collect()
    }

    /// Severs the link between `a` and `b` in **both** directions.
    fn partition(&self, a: u64, b: u64) {
        self.faults[self.pos_of(a)].isolate(b);
        self.faults[self.pos_of(b)].isolate(a);
    }

    /// Restores every link in the cluster.
    fn heal_all(&self) {
        for f in &self.faults {
            f.heal_all();
        }
    }

    fn current_term(&self, node_id: u64) -> u64 {
        self.engines[self.pos_of(node_id)]
            .raft_metrics()
            .expect("metrics")
            .current_term
    }

    /// Polls until some node other than `excluded` reports *itself* as
    /// leader. Returns that node's ID, or `None` on timeout.
    async fn wait_for_leader_excluding(&self, excluded: u64, timeout: Duration) -> Option<u64> {
        let deadline = Instant::now() + timeout;
        loop {
            for engine in &self.engines {
                if let Some(m) = engine.raft_metrics() {
                    if m.id != excluded && m.current_leader == Some(m.id) {
                        return Some(m.id);
                    }
                }
            }
            if Instant::now() > deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(100)).await; // AUDIT: justified-sleep: poll interval inside leader-election loop; openraft exposes no ready-signal channel
        }
    }

    /// Polls until every node in `positions` has applied at least `target`.
    async fn wait_applied_on(&self, positions: &[usize], target: u64, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let ok = positions.iter().all(|&p| {
                self.engines[p]
                    .raft_metrics()
                    .and_then(|m| m.last_applied.map(|l| l.index))
                    .unwrap_or(0)
                    >= target
            });
            if ok {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await; // AUDIT: justified-sleep: poll interval inside replication-convergence loop; log commit is async with no notification hook
        }
    }

    fn engine_for(&self, node_id: u64) -> &Arc<ClusterEngine> {
        self.engines
            .iter()
            .find(|e| e.raft_metrics().map(|m| m.id == node_id).unwrap_or(false))
            .expect("engine present for node id")
    }

    /// Best-effort cleanup. Tempdir Drop closes log files; aborting the
    /// server tasks prevents the test process from waiting on them.
    fn shutdown(self) {
        for h in self.server_handles {
            h.abort();
        }
    }
}

// ── Test: 3-node gRPC loopback ───────────────────────────────────────────────

/// Per HEA-612 narrowed acceptance criteria:
///
/// 1. Spin up 3 `build_clustered` instances on loopback with self-signed certs
/// 2. Bootstrap from node 1
/// 3. Wait for leader election via `raft_metrics().current_leader`
/// 4. Write 10 puts on the leader
/// 5. Every node reports `last_applied >= 10` and `get()` returns the same values
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn three_node_grpc_loopback_replicates_ten_writes() {
    // rustls 0.23 requires a process-wide CryptoProvider to be installed
    // before any TLS handshake. The codebase pairs `tonic` with the
    // `tls-ring` feature, so use the ring provider to stay consistent with
    // `src/protocol/tls.rs`. `install_default` is one-shot per process; the
    // `Err` return on a repeat install is uninteresting for the test.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt::try_init();

    let cluster = TestCluster::build(3).await;

    // Election timeouts are 1500–3000 ms; 15 s margin tolerates a slow runner.
    let leader_id = cluster.wait_for_leader(Duration::from_secs(15)).await;
    assert!(
        (1..=3).contains(&leader_id),
        "elected leader {leader_id} outside expected range 1..=3"
    );

    let leader = cluster.engine_for(leader_id);
    let realm = RealmId::new(Uuid::new_v4());

    // Snapshot before writes so the convergence target is relative — no need
    // to know how many prelude entries openraft inserted (membership, NoOp, etc.).
    let initial_applied = leader
        .raft_metrics()
        .and_then(|m| m.last_applied.map(|l| l.index))
        .unwrap_or(0);

    for i in 0..10u32 {
        let key = format!("k{i}");
        let val = format!("v{i}");
        leader
            .put(&realm, key.as_bytes(), val.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("put {key} on leader {leader_id} failed: {e}"));
    }

    // Wait for the leader to apply all 10 client writes before pinning the
    // convergence target for followers.
    //
    // `put()` returns after Raft majority commit, but state-machine application
    // is asynchronous — `last_applied` advances on the apply loop independently.
    // Reading `leader_target` immediately after the put loop can capture a stale
    // index that excludes the final write(s); followers then pass the convergence
    // check prematurely and reads return None for the last key(s).
    let needed = initial_applied + 10;
    let leader_target = {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let idx = leader
                .raft_metrics()
                .and_then(|m| m.last_applied.map(|l| l.index))
                .unwrap_or(0);
            if idx >= needed {
                break idx;
            }
            assert!(
                Instant::now() <= deadline,
                "leader last_applied {idx} never reached {needed} \
                 (initial={initial_applied} + 10 puts) within 5 s"
            );
            tokio::time::sleep(Duration::from_millis(20)).await; // AUDIT: justified-sleep: polling leader apply; openraft has no per-step completion signal
        }
    };
    assert!(
        leader_target >= needed,
        "leader last_applied {leader_target} < {needed} after 10 puts"
    );

    let converge_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let all_caught_up = cluster.engines.iter().all(|engine| {
            engine
                .raft_metrics()
                .and_then(|m| m.last_applied.map(|l| l.index))
                .unwrap_or(0)
                >= leader_target
        });
        if all_caught_up {
            break;
        }
        if Instant::now() > converge_deadline {
            for engine in &cluster.engines {
                if let Some(m) = engine.raft_metrics() {
                    eprintln!(
                        "node {} last_applied={:?} last_log_index={:?}",
                        m.id,
                        m.last_applied.map(|l| l.index),
                        m.last_log_index
                    );
                }
            }
            panic!("replication did not converge to last_applied >= {leader_target} within 10 s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await; // AUDIT: justified-sleep: poll interval inside replication-convergence loop; log commit is async with no notification hook
    }

    // Per-node read consistency: every key must be present and equal on each
    // node, regardless of leader/follower role.
    for engine in &cluster.engines {
        let node_id = engine.raft_metrics().expect("metrics").id;
        for i in 0..10u32 {
            let key = format!("k{i}");
            let expected = format!("v{i}");
            let got = engine
                .get(&realm, key.as_bytes())
                .await
                .unwrap_or_else(|e| panic!("get {key} on node {node_id} failed: {e}"));
            assert_eq!(
                got.as_deref(),
                Some(expected.as_bytes()),
                "node {node_id} returned {got:?} for {key}, expected {expected}"
            );
        }
    }

    cluster.shutdown();
}

// ── Shared setup for the transport-failover tests ────────────────────────────

/// Installs the process-wide rustls provider and brings up a three-node
/// cluster whose leader has applied `n` committed writes.
///
/// Returns `(cluster, leader_id, last_applied_on_leader)`.
async fn cluster_with_committed_baseline(
    write_timeout_ms: Option<u64>,
    n: u32,
) -> (TestCluster, u64, u64) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt::try_init();

    let cluster = TestCluster::build_with_write_timeout(3, write_timeout_ms).await;
    let leader_id = cluster.wait_for_leader(Duration::from_secs(15)).await;
    let realm = baseline_realm();

    for i in 0..n {
        cluster
            .engine_for(leader_id)
            .put(&realm, format!("base{i}").as_bytes(), b"v")
            .await
            .expect("baseline put on leader");
    }

    let applied = cluster
        .engine_for(leader_id)
        .raft_metrics()
        .and_then(|m| m.last_applied.map(|l| l.index))
        .unwrap_or(0);
    let all: Vec<usize> = (0..cluster.engines.len()).collect();
    assert!(
        cluster
            .wait_applied_on(&all, applied, Duration::from_secs(15))
            .await,
        "baseline did not converge on all three nodes before the fault was injected"
    );
    (cluster, leader_id, applied)
}

/// A fixed realm so the helper and the tests agree on where baseline keys live.
fn baseline_realm() -> RealmId {
    RealmId::new(Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("fixed uuid"))
}

// ── Task 26.59: failover over the REAL gRPC transport ────────────────────────

/// Before this test, **no** test in the repository exercised failover and the
/// real network layer at the same time: all ten failover, crash-recovery and
/// partition tests ran against an in-process `RaftNetwork`, and the only
/// socket-backed test (`three_node_grpc_loopback_replicates_ten_writes`) did
/// no failure injection at all
/// (`reports/cluster-ga-readiness-2026-09-21.md`, "Failover and split-brain
/// test count").
///
/// The naive attempts do not work, which is why the seam had to exist first.
/// Aborting the leader's own gRPC server does not depose it — the leader is
/// the node that *dials*, so it keeps reaching both followers and keeps their
/// leases alive. Aborting the followers' servers leaves nobody able to elect.
/// What has to be severed is the leader's outbound edge, which is exactly what
/// `PeerFaults` severs, one layer *inside* the real mTLS transport: the
/// handshake, the tonic channel, the JSON codec and the incoming-RPC dispatch
/// are all still the production ones.
///
/// Asserts the full failover cycle:
/// 1. the majority elects a replacement at a strictly higher term;
/// 2. that replacement commits a write the isolated node never saw;
/// 3. after the heal, the deposed node rejoins and converges on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_leader_isolated_over_the_real_grpc_transport_is_replaced_and_writes_survive() {
    let (cluster, old_leader_id, baseline_idx) =
        cluster_with_committed_baseline(Some(3_000), 3).await;
    let old_term = cluster.current_term(old_leader_id);
    let followers = cluster.peers_of(old_leader_id);

    // Cut the leader's edge to both followers, in both directions. It is now a
    // minority of one; the two followers still reach each other.
    for &f in &followers {
        cluster.partition(old_leader_id, f);
    }

    // ── 1. The majority elects a replacement, at a higher term ───────────────
    let new_leader_id = cluster
        .wait_for_leader_excluding(old_leader_id, Duration::from_secs(25))
        .await
        .unwrap_or_else(|| {
            panic!(
                "FAILOVER FAIL: node {old_leader_id} was isolated from both peers over the real \
                 gRPC transport, yet the remaining majority never elected a replacement within \
                 25 s. Either the partition is not being injected (check PeerFaults::plan) or \
                 election is not happening"
            )
        });
    let new_term = cluster.current_term(new_leader_id);
    assert!(
        new_term > old_term,
        "FAILOVER FAIL: replacement leader {new_leader_id} holds term {new_term}, which is not \
         above the isolated node's term {old_term} — two nodes would then lead the same term"
    );

    // ── 2. The replacement commits a write the isolated node cannot see ──────
    let realm = baseline_realm();
    cluster
        .engine_for(new_leader_id)
        .put(&realm, b"post-failover", b"committed")
        .await
        .unwrap_or_else(|e| panic!("post-failover put on new leader {new_leader_id} failed: {e}"));

    let isolated_pos = cluster.pos_of(old_leader_id);
    let isolated_applied = cluster.engines[isolated_pos]
        .raft_metrics()
        .and_then(|m| m.last_applied.map(|l| l.index))
        .unwrap_or(0);
    assert_eq!(
        isolated_applied, baseline_idx,
        "FAILOVER FAIL: the isolated node {old_leader_id} applied index {isolated_applied}, past \
         the pre-partition {baseline_idx} — its outbound edge is cut, so it can only have \
         advanced if the partition is not being injected"
    );

    // ── 3. After the heal the deposed node rejoins and converges ─────────────
    cluster.heal_all();
    let target = cluster.engines[cluster.pos_of(new_leader_id)]
        .raft_metrics()
        .and_then(|m| m.last_applied.map(|l| l.index))
        .unwrap_or(0);
    assert!(
        cluster
            .wait_applied_on(&[isolated_pos], target, Duration::from_secs(20))
            .await,
        "FAILOVER FAIL: deposed node {old_leader_id} never caught up to index {target} after \
         the partition healed"
    );
    assert_eq!(
        cluster.engines[isolated_pos]
            .get(&realm, b"post-failover")
            .await
            .expect("get on rejoined node")
            .as_deref(),
        Some(b"committed".as_slice()),
        "FAILOVER FAIL: deposed node {old_leader_id} rejoined without the write the replacement \
         leader committed while it was isolated"
    );

    cluster.shutdown();
}

// ── Task 26.58: a write racing a leadership change must be bounded ───────────

/// `propose_with_response` awaited `Raft::client_write` with no timeout.
///
/// A leader that loses contact with a quorum *immediately after* accepting a
/// write never resolves it: the entry is in its own log, the quorum
/// acknowledgement can never arrive, and openraft 0.9 does not step a leader
/// down on a lost quorum, so no `ForwardToLeader` is produced either. The
/// caller — an HTTP handler, holding a connection and on the login path an
/// advisory lock — waited forever.
///
/// This reproduces exactly that: isolate the leader from both peers, then
/// write on it. The whole call is wrapped in a test-side timeout well above
/// the configured bound, so a regression fails with a message instead of
/// hanging the suite.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_write_on_a_leader_that_lost_its_quorum_is_bounded_and_says_so() {
    const BOUND_MS: u64 = 3_000;
    let (cluster, leader_id, _) = cluster_with_committed_baseline(Some(BOUND_MS), 2).await;

    for f in cluster.peers_of(leader_id) {
        cluster.partition(leader_id, f);
    }

    let realm = baseline_realm();
    let started = Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        cluster
            .engine_for(leader_id)
            .put(&realm, b"racing-write", b"unknown-outcome"),
    )
    .await;

    let Ok(result) = outcome else {
        panic!(
            "LIVENESS FAIL: a put on node {leader_id}, isolated from every peer, had not \
             returned after 20 s — the configured {BOUND_MS} ms write bound is not being \
             applied and the caller is hung on an unbounded distributed write"
        )
    };
    let err = result.expect_err(
        "a leader isolated from every peer cannot reach quorum, so the write must not report \
         success",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("did not reach quorum commit") && msg.contains("outcome is unknown"),
        "the bound fired but the error does not say what happened; a caller cannot tell a \
         timed-out write (outcome unknown, must re-read) from a rejected one. Got: {msg}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the write returned after {:?}, far past the configured {BOUND_MS} ms bound",
        started.elapsed()
    );

    cluster.heal_all();
    cluster.shutdown();
}

// ── Task 26.57: the documented graceful step-down actually steps down ────────

/// `ClusterEngine::transfer_leadership` is the documented graceful-shutdown
/// path (`docs/guides/clustering.md` § Graceful Shutdown). On a healthy
/// three-node cluster it always returned "leadership transfer timed out after
/// 5 s" and leadership never moved.
///
/// Asserts the property the endpoint promises — after the call returns, this
/// node is no longer the leader and a different node is — plus that the
/// cluster is still writable, which is what catches a step-down that left
/// `heartbeat` disabled and the cluster in a rolling election.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn transfer_leadership_moves_leadership_off_this_node() {
    let (cluster, old_leader_id, _) = cluster_with_committed_baseline(None, 2).await;

    let new_leader_id = cluster
        .engine_for(old_leader_id)
        .transfer_leadership()
        .await
        .unwrap_or_else(|e| {
            panic!(
                "STEP-DOWN FAIL: transfer_leadership on the healthy three-node cluster's leader \
                 (node {old_leader_id}) returned an error instead of moving leadership: {e}"
            )
        });

    assert_ne!(
        new_leader_id, old_leader_id,
        "STEP-DOWN FAIL: transfer_leadership reported node {new_leader_id} as the new leader, \
         which is the node that was asked to step down"
    );
    let old_state = cluster.engines[cluster.pos_of(old_leader_id)]
        .raft_metrics()
        .expect("metrics")
        .state;
    assert_ne!(
        old_state,
        openraft::ServerState::Leader,
        "STEP-DOWN FAIL: transfer_leadership returned success but node {old_leader_id} still \
         reports itself as Leader"
    );

    // The cluster must still be writable through the node that took over —
    // this is what fails if the step-down left `heartbeat` disabled and the
    // cluster in a rolling election.
    let realm = baseline_realm();
    cluster
        .engine_for(new_leader_id)
        .put(&realm, b"after-step-down", b"committed")
        .await
        .unwrap_or_else(|e| {
            panic!(
                "STEP-DOWN FAIL: the cluster is not writable through the new leader \
                 (node {new_leader_id}) after the step-down: {e}"
            )
        });

    let all: Vec<usize> = (0..cluster.engines.len()).collect();
    let target = cluster.engines[cluster.pos_of(new_leader_id)]
        .raft_metrics()
        .and_then(|m| m.last_applied.map(|l| l.index))
        .unwrap_or(0);
    assert!(
        cluster
            .wait_applied_on(&all, target, Duration::from_secs(20))
            .await,
        "STEP-DOWN FAIL: the post-step-down write did not converge on all three nodes"
    );

    cluster.shutdown();
}
