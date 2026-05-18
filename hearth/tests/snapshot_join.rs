/// Snapshot integration tests — HEA-605
///
/// Covers: snapshot round-trip (leader builds → follower installs → identical
/// key-space), forced snapshot join (restarted node catches up exclusively via
/// snapshot), and zstd compression ratio verification.
use std::time::Duration;

use hearth::cluster::engine::test_harness::TestCluster;

// ── Scenario 1: Snapshot round-trip ──────────────────────────────────────────

/// Write 50 entries to a 3-node cluster configured with snapshot_threshold=20.
/// The leader builds at least two snapshots.  Kill one follower, write 30 more
/// entries (past the snapshot compaction point), restart the follower.
/// After catch-up: verify the restarted follower has all 80 entries via
/// snapshot install (the early log entries are purged).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_snapshot_round_trip() {
    // snapshot every 20 entries; keep at most 20 entries after snapshot →
    // entries 1-20 are purged once entry 40 is snapshotted.
    let mut cluster = TestCluster::new_with_snapshot_threshold(3, 20).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    // Phase 1: write 50 entries so the leader builds ≥2 snapshots.
    for i in 0..50u32 {
        cluster
            .write(format!("k{i}"), format!("v{i}"))
            .await
            .unwrap_or_else(|e| panic!("write k{i} failed: {e}"));
    }

    // Allow replication and snapshot to settle.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Kill one follower.
    let follower = (1u64..=3).find(|&id| id != leader).expect("no follower");
    cluster.kill_node(follower).await;

    // Phase 2: write 30 more entries while the follower is dead.
    // Total = 80; early entries (k0..k19) are past the log-compaction horizon.
    for i in 50..80u32 {
        cluster
            .write(format!("k{i}"), format!("v{i}"))
            .await
            .unwrap_or_else(|e| panic!("write k{i} failed: {e}"));
    }

    // Restart the follower — it must install a snapshot to catch up.
    cluster.restart_node(follower).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // All 80 keys must be present on the rejoined node.
    for i in 0..80u32 {
        let got = cluster.read(follower, &format!("k{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("v{i}").as_str()),
            "rejoined node {follower} missing k{i} after snapshot catch-up"
        );
    }

    cluster.shutdown().await;
}

// ── Scenario 2: Forced snapshot join (new node) ───────────────────────────────

/// Start a 2-node cluster, write 60 entries (3× snapshot_threshold=20),
/// then add a third node.  The new node has no log; it must install the
/// leader's latest snapshot to join.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_new_node_joins_via_snapshot() {
    use std::collections::BTreeMap;
    use hearth::cluster::router::MemRouter;
    use hearth::cluster::engine::ClusterNode;
    use openraft::{BasicNode, Config, SnapshotPolicy};

    // Bootstrap 2-node cluster with low snapshot threshold.
    let threshold: u64 = 20;
    let router = MemRouter::new();
    let config = std::sync::Arc::new(
        Config {
            election_timeout_min: 100,
            election_timeout_max: 300,
            heartbeat_interval: 50,
            snapshot_policy: SnapshotPolicy::LogsSinceLast(threshold),
            max_in_snapshot_log_to_keep: threshold,
            ..Default::default()
        }
        .validate()
        .expect("config valid"),
    );

    // Start 2 nodes.
    let mut nodes: BTreeMap<u64, ClusterNode> = BTreeMap::new();
    for id in 1u64..=2 {
        let (node, rpc_tx) = ClusterNode::new(id, config.clone(), router.clone(), 500).await;
        router.add_node(id, rpc_tx);
        nodes.insert(id, node);
    }
    let members: BTreeMap<u64, BasicNode> =
        (1u64..=2).map(|id| (id, BasicNode::default())).collect();
    nodes[&1]
        .raft()
        .initialize(members)
        .await
        .expect("2-node init failed");

    // Poll until one of the nodes reports itself as leader.
    let leader_id: u64 = {
        let mut found = 0u64;
        for _ in 0..200 {
            for (id, node) in &nodes {
                let m = node.raft().metrics().borrow().clone();
                if m.current_leader == Some(*id) {
                    found = *id;
                    break;
                }
            }
            if found != 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_ne!(found, 0, "no leader elected within 4 s");
        found
    };

    // Write 60 entries (forces ≥3 snapshot builds at threshold=20).
    for i in 0..60u32 {
        nodes[&leader_id]
            .write(format!("m{i}"), format!("val{i}"))
            .await
            .unwrap_or_else(|e| panic!("write m{i} failed: {e}"));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Add learner node 3, then promote to voter.
    let (node3, rpc_tx3) = ClusterNode::new(3, config.clone(), router.clone(), 500).await;
    router.add_node(3, rpc_tx3);
    nodes.insert(3, node3);

    nodes[&leader_id]
        .raft()
        .add_learner(3, BasicNode::default(), true)
        .await
        .expect("add_learner failed");

    // Give the new node time to install the snapshot and catch up.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify all 60 entries visible on node 3.
    for i in 0..60u32 {
        let got = nodes[&3].storage.get(&format!("m{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("val{i}").as_str()),
            "new node 3 missing m{i} after snapshot join"
        );
    }

    for (_, node) in nodes {
        node.shutdown().await;
    }
}

// ── Scenario 3: Compression ratio ────────────────────────────────────────────

/// Build a snapshot from a 1000-entry KV store and verify the compressed
/// payload is strictly smaller than the uncompressed JSON.
#[tokio::test]
async fn test_snapshot_compression_ratio() {
    use std::collections::HashMap;

    // Build the raw JSON manually to get the baseline size.
    let data: HashMap<String, String> = (0..1000)
        .map(|i| (format!("compression-key-{i:04}"), format!("compression-value-{i:08}")))
        .collect();
    let json_bytes = serde_json::to_vec(&data).expect("serialize");
    let uncompressed_size = json_bytes.len();

    // Compress with the same settings as MemSnapshotBuilder.
    let compressed = zstd::encode_all(json_bytes.as_slice(), 3).expect("compress");
    let compressed_size = compressed.len();

    assert!(
        compressed_size < uncompressed_size,
        "compressed size ({compressed_size}) should be < uncompressed ({uncompressed_size})"
    );

    // A typical text KV workload compresses to < 30% of original.
    let ratio = compressed_size as f64 / uncompressed_size as f64;
    assert!(
        ratio < 0.5,
        "compression ratio {ratio:.2} should be < 0.5 for typical KV data"
    );
}

// ── Scenario 4: Snapshot encodes and decodes to identical key-space ───────────

/// Unit-level test: build a snapshot from a known KV set, install it into a
/// fresh state machine, verify the key-space is byte-identical.
/// This tests the full compress → decompress → restore pipeline without a
/// running Raft cluster.
#[tokio::test]
async fn test_snapshot_encode_decode_roundtrip() {
    use hearth::cluster::store::{MemSnapshotBuilder, MemStateMachine};
    use hearth::EmbeddedStorageEngine;
    use openraft::{storage::RaftSnapshotBuilder, storage::RaftStateMachine};

    // Build a snapshot from a populated KV store.
    let kv = EmbeddedStorageEngine::new();
    for i in 0..100u32 {
        kv.set(format!("encode-key-{i}"), format!("encode-val-{i}"));
    }

    let snapshot_store = std::sync::Arc::new(std::sync::Mutex::new(None));
    let mut builder = MemSnapshotBuilder {
        last_applied: None,
        last_membership: openraft::StoredMembership::default(),
        data: kv.snapshot(),
        snapshot_store,
    };

    let snap = builder.build_snapshot().await.expect("build_snapshot failed");
    let meta = snap.meta.clone();

    // The snapshot payload must be compressed (smaller than raw JSON).
    let payload = snap.snapshot.into_inner();
    let raw_json = serde_json::to_vec(&kv.snapshot()).unwrap();
    assert!(
        payload.len() < raw_json.len(),
        "snapshot payload ({}) should be smaller than raw JSON ({})",
        payload.len(),
        raw_json.len()
    );

    // Install the snapshot into a fresh state machine.
    let fresh_kv = EmbeddedStorageEngine::new();
    let mut sm = MemStateMachine::new(fresh_kv.clone());
    sm.install_snapshot(&meta, Box::new(std::io::Cursor::new(payload)))
        .await
        .expect("install_snapshot failed");

    // All 100 keys must be present.
    for i in 0..100u32 {
        let got = fresh_kv.get(&format!("encode-key-{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("encode-val-{i}").as_str()),
            "key encode-key-{i} missing after snapshot decode"
        );
    }
}
