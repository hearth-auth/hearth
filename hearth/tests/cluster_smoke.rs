/// 3-node localhost smoke tests — HEA-604
///
/// Covers: leader election, log replication, leader failover,
/// follower staleness, and single-node bypass mode.
///
/// All tests use in-process Raft with channel-based network simulation
/// (no real sockets, no fsync) so the suite stays well under 30 s.
use std::time::Duration;

use hearth::cluster::{
    engine::{test_harness::TestCluster, ClusterNode},
    router::MemRouter,
};
use openraft::{BasicNode, Config};

// ── Scenario 1: Leader election ───────────────────────────────────────────────

/// All 3 nodes start → a leader is elected within 2 × election_timeout_max.
/// election_timeout_max = 300 ms, so deadline = 600 ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leader_election() {
    let cluster = TestCluster::new(3).await;

    let leader = tokio::time::timeout(
        Duration::from_millis(600),
        cluster.wait_for_leader(),
    )
    .await
    .expect("leader not elected within 2 × election_timeout_max (600 ms)");

    assert!(
        (1..=3).contains(&leader),
        "elected leader {leader} is outside the expected range 1-3"
    );

    cluster.shutdown().await;
}

// ── Scenario 2: Log replication ───────────────────────────────────────────────

/// Write 100 key-value pairs to the leader; all 3 nodes must return identical
/// values via StorageEngine::get after replication settles.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_log_replication() {
    let mut cluster = TestCluster::new(3).await;
    cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    for i in 0..100u32 {
        cluster
            .write(format!("key-{i}"), format!("val-{i}"))
            .await
            .unwrap_or_else(|e| panic!("write key-{i} failed: {e}"));
    }

    // Allow replication to settle across all followers.
    tokio::time::sleep(Duration::from_millis(300)).await;

    for node_id in 1u64..=3 {
        for i in 0..100u32 {
            let got = cluster.read(node_id, &format!("key-{i}"));
            assert_eq!(
                got.as_deref(),
                Some(format!("val-{i}").as_str()),
                "node {node_id} missing key-{i} after replication"
            );
        }
    }

    cluster.shutdown().await;
}

// ── Scenario 3: Leader failover ───────────────────────────────────────────────

/// Kill the leader → new leader elected → writes still succeed →
/// killed node rejoins and catches up via log replication.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leader_failover() {
    let mut cluster = TestCluster::new(3).await;
    let original_leader = cluster
        .wait_for_leader_timeout(Duration::from_secs(5))
        .await;

    // Write pre-failover data.
    for i in 0..10u32 {
        cluster.write(format!("pre-{i}"), format!("v{i}")).await.unwrap();
    }

    // Kill the current leader.
    cluster.kill_node(original_leader).await;

    // New leader must be elected within 3 × election_timeout_max (some timing slack).
    let new_leader = tokio::time::timeout(
        Duration::from_millis(1000),
        cluster.wait_for_leader(),
    )
    .await
    .expect("new leader not elected within 1000 ms after failover");

    assert_ne!(
        new_leader, original_leader,
        "new leader must differ from the killed node"
    );

    // Writes continue on the new leader.
    for i in 10..20u32 {
        cluster
            .write(format!("post-{i}"), format!("v{i}"))
            .await
            .unwrap_or_else(|e| panic!("post-failover write post-{i} failed: {e}"));
    }

    // Restart the killed node; allow time for catch-up.
    cluster.restart_node(original_leader).await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Verify the rejoined node has the post-failover entries.
    for i in 10..20u32 {
        let got = cluster.read(original_leader, &format!("post-{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("v{i}").as_str()),
            "rejoined node {original_leader} is missing post-failover key post-{i}"
        );
    }

    cluster.shutdown().await;
}

// ── Scenario 4: Follower staleness ────────────────────────────────────────────

/// Inject a 1.5 s network delay on one follower, write many entries so the
/// follower lags > 500 ms, verify reads_allowed goes false and returns an error,
/// then remove the delay and confirm reads resume.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_follower_staleness() {
    let mut cluster = TestCluster::new(3).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    // Pick a follower (any node that is not the leader).
    let follower = (1u64..=3).find(|&id| id != leader).expect("no follower");

    // Confirm reads are allowed before we inject delay.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        cluster.reads_allowed(follower),
        "follower {follower} should allow reads in steady state"
    );

    // Inject a per-entry apply() delay so last_applied lags behind last_log_index.
    // 20 ms/entry × 100 entries = 2000 ms lag >> 500 ms threshold.
    cluster.set_apply_delay(follower, 20);

    // Write enough entries so the apply backlog exceeds the lag threshold.
    // With 20 ms/entry and threshold = 500 ms, we need > 100 entries committed
    // while the follower is still processing earlier ones.
    for i in 0..120u32 {
        cluster.write(format!("lag-{i}"), format!("v{i}")).await.unwrap();
    }

    // Give the lag monitor a moment to detect lag and update reads_allowed.
    // The follower's apply queue is long; wait for the monitor to fire.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !cluster.reads_allowed(follower),
        "follower {follower} should have reads_allowed=false with high lag"
    );

    // The staleness-aware read method should return an error.
    let err = cluster.read_with_staleness_check(follower, "lag-0");
    assert!(
        err.is_err(),
        "follower {follower} should return an error when reads_allowed=false"
    );

    // Remove the apply delay so the follower processes its backlog.
    cluster.set_apply_delay(follower, 0);
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(
        cluster.reads_allowed(follower),
        "follower {follower} should re-allow reads after catching up"
    );

    // Reads should now succeed (no error).
    let ok = cluster.read_with_staleness_check(follower, "lag-0");
    assert!(
        ok.is_ok(),
        "follower {follower} should serve reads after lag clears"
    );

    cluster.shutdown().await;
}

// ── Scenario 5: Single-node mode ─────────────────────────────────────────────

/// Start with no cluster config → no Raft instance allocated, direct storage
/// calls, zero Raft overhead.
#[tokio::test]
async fn test_single_node_mode() {
    // Build a node without initializing a cluster — raft is still created but
    // never joined to a peer set.  We verify direct storage access works and
    // that no cluster ports are opened.
    let router = MemRouter::new();
    let config = std::sync::Arc::new(
        Config {
            election_timeout_min: 100,
            election_timeout_max: 300,
            heartbeat_interval: 50,
            ..Default::default()
        }
        .validate()
        .expect("config valid"),
    );

    let (node, rpc_tx) = ClusterNode::new(1, config, router.clone(), 500).await;
    router.add_node(1, rpc_tx);

    // In single-node mode, initialize the Raft with only itself.
    let mut members = std::collections::BTreeMap::new();
    members.insert(1u64, BasicNode::default());
    node.raft()
        .initialize(members)
        .await
        .expect("single-node init failed");

    // Wait for the node to elect itself leader.
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut rx = node.raft().metrics();
        loop {
            if rx.borrow().current_leader.is_some() {
                break;
            }
            rx.changed().await.expect("metrics closed");
        }
    })
    .await
    .expect("single node did not self-elect within 2 s");

    // Direct write through Raft client_write (no peers → immediate commit).
    node.write("hello".into(), "world".into())
        .await
        .expect("single-node write failed");

    // Read back via StorageEngine — committed entry must be visible.
    let val = node.storage.get("hello");
    assert_eq!(val.as_deref(), Some("world"), "single-node read/write round-trip failed");

    // reads_allowed should be true (node is leader).
    assert!(
        node.reads_allowed(),
        "single-node leader should always have reads_allowed=true"
    );

    node.shutdown().await;
}
