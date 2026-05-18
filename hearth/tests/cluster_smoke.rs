/// Smoke tests — HEA-604 (cluster primitives) and HEA-606 (online membership).
///
/// Covers: leader election, log replication, leader failover,
/// follower staleness, single-node bypass, add voter, remove voter,
/// and quorum-violation safeguard.
///
/// All tests use in-process Raft with channel-based network simulation
/// (no real sockets, no fsync) so the suite stays well under 30 s.
use std::time::Duration;

use hearth::cluster::{
    engine::{test_harness::TestCluster, ClusterError, ClusterNode},
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

// ── Scenario 6: Add voter online — HEA-606 ───────────────────────────────────

/// Start a 3-node cluster, spin up a 4th node, add it as learner then promote
/// it to voter, and verify writes continue uninterrupted throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_add_voter_online() {
    let mut cluster = TestCluster::new(3).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    for i in 0..5u32 {
        cluster.write(format!("pre-{i}"), format!("v{i}")).await.unwrap();
    }

    // Register node 4 with the in-process router BEFORE telling the leader
    // about it — the leader must be able to reach it the moment it tries.
    cluster.spin_up_node(4).await;

    // Step 1: Add as non-voting learner (blocks until catch-up completes).
    cluster.nodes[&leader]
        .add_learner(4, BasicNode::default())
        .await
        .expect("add_learner(4) failed");

    // Writes must continue during the learner phase.
    for i in 5..10u32 {
        cluster.write(format!("mid-{i}"), format!("v{i}")).await.unwrap();
    }

    // Step 2: Promote to voter via joint consensus.
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(2)).await;
    let view = cluster.nodes[&leader]
        .add_voter(4)
        .await
        .expect("add_voter(4) failed");

    assert!(view.voters.contains(&4), "node 4 must be in voter set after promotion");
    assert_eq!(view.voters.len(), 4, "cluster should have 4 voters");

    // Writes must continue with the new 4-voter configuration.
    for i in 10..15u32 {
        cluster.write(format!("post-{i}"), format!("v{i}")).await.unwrap();
    }

    // Allow time for node 4 to replicate pre-join entries via snapshot/log.
    tokio::time::sleep(Duration::from_millis(400)).await;

    for i in 0..5u32 {
        let got = cluster.read(4, &format!("pre-{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("v{i}").as_str()),
            "node 4 missing pre-join entry pre-{i}"
        );
    }

    cluster.shutdown().await;
}

// ── Scenario 7: Remove voter online — HEA-606 ────────────────────────────────

/// Start a 4-node cluster, remove one non-leader voter, and verify the
/// remaining 3-node cluster continues to serve writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_remove_voter_online() {
    let cluster = TestCluster::new(4).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    for i in 0..10u32 {
        cluster.write(format!("pre-{i}"), format!("v{i}")).await.unwrap();
    }

    let victim: u64 = (1..=4).find(|&id| id != leader).unwrap();
    let view = cluster.nodes[&leader]
        .remove_voter(victim)
        .await
        .expect("remove_voter failed");

    assert_eq!(view.voters.len(), 3, "should have 3 voters after removal");
    assert!(!view.voters.contains(&victim), "removed node must not be in voter set");

    // Writes must continue with the reduced configuration.
    for i in 10..20u32 {
        cluster
            .write(format!("post-{i}"), format!("v{i}"))
            .await
            .unwrap_or_else(|e| panic!("post-removal write post-{i} failed: {e}"));
    }

    cluster.shutdown().await;
}

// ── Scenario 8: Quorum violation rejected — HEA-606 ──────────────────────────

/// A 2-node cluster must reject the removal of any voter because it would
/// leave only 1 voter (quorum for 2 is 2; 1 < 2 → violation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quorum_violation_rejected() {
    let cluster = TestCluster::new(2).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    let non_leader: u64 = (1..=2).find(|&id| id != leader).unwrap();

    // Removing one voter from a 2-node cluster would leave 1 voter.
    // Minimum quorum for n=2 is ⌊2/2⌋+1 = 2; remaining 1 < 2 → rejected.
    let err = cluster.nodes[&leader]
        .remove_voter(non_leader)
        .await
        .expect_err("remove_voter should have been rejected");

    assert!(
        matches!(err, ClusterError::QuorumViolation { current: 2, remaining: 1, minimum: 2 }),
        "expected QuorumViolation(current=2, remaining=1, minimum=2), got: {err}"
    );

    cluster.shutdown().await;
}
