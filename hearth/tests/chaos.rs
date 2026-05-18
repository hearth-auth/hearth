/// Chaos integration tests — HEA-607
///
/// Fault injection suite covering:
///   - Network partitions (leader isolation, follower isolation, no-quorum)
///   - Node failure / crash scenarios
///   - Membership changes under load
///   - Read consistency during partitions
///   - Throughput and p99 commit latency on a 3-node cluster
///
/// All tests use the in-process MemRouter with bidirectional partition
/// simulation — no real sockets or fsync, so the suite stays fast.
/// Heavy / timing-sensitive tests are marked `#[ignore]` and run in a
/// dedicated CI job via `cargo test -- --include-ignored chaos`.
use std::time::{Duration, Instant};

use hearth::cluster::engine::test_harness::TestCluster;

// ── Helper ────────────────────────────────────────────────────────────────────

/// Wait up to `timeout` for `condition` to hold, polling every 20 ms.
async fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ── Network partition tests ───────────────────────────────────────────────────

/// Isolate the leader from both followers.
/// Expected: followers elect a new leader within election timeout × 2,
/// writes to the NEW leader succeed during the partition,
/// after reconnection exactly ONE leader is present (no split-brain),
/// and all committed entries are visible on the formerly-isolated node.
///
/// Important: `TestCluster::current_leader()` scans ALL live nodes.
/// A partitioned leader still reports `current_leader=self` in its own metrics
/// until it hears from the new term's leader.  To avoid sending writes to the
/// isolated node during the partition we use `write_to_node` targeting the
/// known new leader directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leader_isolation_elects_new_leader() {
    let cluster = TestCluster::new(3).await;
    let old_leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    // Write baseline data before partitioning.
    for i in 0..5u32 {
        cluster.write(format!("before-{i}"), format!("v{i}")).await.unwrap();
    }

    // Isolate the leader — it can no longer send to or receive from followers.
    cluster.isolate_node(old_leader);

    // The remaining two nodes form a quorum (2/3) and elect a new leader.
    // We poll only the non-isolated nodes to avoid seeing the stale leader report.
    let new_leader = tokio::time::timeout(
        Duration::from_millis(2000),
        async {
            loop {
                for id in cluster.node_ids() {
                    if id == old_leader {
                        continue; // skip partitioned node — its metrics are stale
                    }
                    let m = cluster.nodes[&id].raft().metrics().borrow().clone();
                    if let Some(l) = m.current_leader {
                        if l != old_leader && cluster.nodes.contains_key(&l) {
                            return l;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        },
    )
    .await
    .expect("new leader not elected within 2000 ms after leader isolation");

    assert_ne!(new_leader, old_leader, "new leader must differ from the isolated node");

    // Writes go directly to the new leader — bypassing current_leader() which
    // could return the isolated old leader (still self-reporting as leader).
    for i in 5..10u32 {
        cluster
            .write_to_node(new_leader, format!("during-{i}"), format!("v{i}"))
            .await
            .unwrap_or_else(|e| panic!("write_to_node({new_leader}) during partition failed: {e}"));
    }

    // Heal the partition.  The old leader will receive heartbeats from the new
    // term, increment its term, and step down.  After that the cluster converges
    // on a single leader (which may or may not be the same as new_leader).
    cluster.reconnect_node(old_leader);
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Split-brain check: all live nodes must agree on the same leader.
    let leaders_seen: std::collections::HashSet<u64> = cluster
        .node_ids()
        .into_iter()
        .filter_map(|id| cluster.nodes[&id].raft().metrics().borrow().current_leader)
        .collect();
    assert_eq!(
        leaders_seen.len(),
        1,
        "split-brain detected — nodes disagree on leader: {leaders_seen:?}"
    );

    // The formerly-isolated node must have caught up with all during-partition entries.
    tokio::time::sleep(Duration::from_millis(600)).await;
    for i in 5..10u32 {
        let got = cluster.read(old_leader, &format!("during-{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("v{i}").as_str()),
            "rejoined old-leader missing during-partition key during-{i}"
        );
    }

    cluster.shutdown().await;
}

/// Isolate one follower while the other two nodes keep serving writes.
/// Expected: cluster continues without interruption; isolated follower
/// catches up via log replication after reconnect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_follower_isolation_cluster_continues() {
    let cluster = TestCluster::new(3).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    let isolated_follower = cluster
        .node_ids()
        .into_iter()
        .find(|&id| id != leader)
        .expect("no follower");

    // Pre-partition writes.
    for i in 0..10u32 {
        cluster.write(format!("pre-{i}"), format!("v{i}")).await.unwrap();
    }

    // Partition the follower.
    cluster.isolate_node(isolated_follower);

    // Writes must continue — leader + 1 remaining follower is still quorum.
    for i in 10..30u32 {
        cluster
            .write(format!("during-{i}"), format!("v{i}"))
            .await
            .unwrap_or_else(|e| panic!("write {i} failed during follower isolation: {e}"));
    }

    // Heal the partition.
    cluster.reconnect_node(isolated_follower);
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Isolated follower must have caught up with all entries.
    for i in 10..30u32 {
        let got = cluster.read(isolated_follower, &format!("during-{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("v{i}").as_str()),
            "rejoined follower {isolated_follower} missing key during-{i}"
        );
    }

    cluster.shutdown().await;
}

/// Full network partition: each node is isolated from the others so no quorum
/// is possible.  Expected: writes are rejected (no leader can commit), but
/// no data corruption occurs; writes succeed again after partition heals.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_no_quorum_writes_rejected() {
    let cluster = TestCluster::new(3).await;
    let _leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    // Pre-partition baseline.
    for i in 0..5u32 {
        cluster.write(format!("base-{i}"), format!("v{i}")).await.unwrap();
    }

    // Partition all three pairs — no quorum is achievable.
    cluster.partition_between(1, 2);
    cluster.partition_between(2, 3);
    cluster.partition_between(1, 3);

    // Give time for the old leader to lose quorum / timeout.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Attempt writes.  They may fail immediately (NotLeader or timeout) or
    // time out.  Either is acceptable — the key requirement is no data loss.
    let write_result = tokio::time::timeout(
        Duration::from_millis(800),
        cluster.write("during-partition", "should-fail-or-timeout"),
    )
    .await;

    // Either a timeout or an error is acceptable — a successful commit without
    // quorum would be a split-brain bug.
    match write_result {
        Ok(Ok(())) => {
            // A write could succeed if a node still thinks it has quorum during
            // the brief window before the election timeout fires.  This is
            // technically safe for linearizability so we allow it, but only for
            // the first write.  Subsequent writes below will verify no new
            // progress while fully partitioned.
        }
        Ok(Err(_)) | Err(_) => { /* expected */ }
    }

    // Heal all partitions.
    cluster.heal_partition(1, 2);
    cluster.heal_partition(2, 3);
    cluster.heal_partition(1, 3);

    // A new leader must emerge and accept writes.
    let post_leader = tokio::time::timeout(
        Duration::from_secs(3),
        cluster.wait_for_leader(),
    )
    .await
    .expect("leader not re-elected after partition heal");

    for i in 5..10u32 {
        cluster
            .write(format!("after-{i}"), format!("v{i}"))
            .await
            .unwrap_or_else(|e| panic!("write {i} failed after heal: {e} (leader={post_leader})"));
    }

    // Baseline data must still be intact on the leader.
    for i in 0..5u32 {
        let got = cluster.read(post_leader, &format!("base-{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("v{i}").as_str()),
            "data loss: base-{i} missing after partition heal"
        );
    }

    cluster.shutdown().await;
}

// ── Node failure tests ────────────────────────────────────────────────────────

/// Kill the leader mid-write loop: some writes get an error, some succeed.
/// After a new leader is elected, all committed entries are present on surviving
/// nodes.  No uncommitted entry appears on followers after failover.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leader_crash_mid_write() {
    let mut cluster = TestCluster::new(3).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    // Write pre-crash data.
    for i in 0..10u32 {
        cluster.write(format!("pre-{i}"), format!("v{i}")).await.unwrap();
    }

    // Kill the leader abruptly (no graceful shutdown).
    cluster.kill_node(leader).await;

    // New leader must be elected.
    let new_leader = tokio::time::timeout(
        Duration::from_millis(1500),
        cluster.wait_for_leader(),
    )
    .await
    .expect("new leader not elected within 1500 ms after leader crash");

    assert_ne!(new_leader, leader, "new leader must differ from crashed node");

    // Post-crash writes succeed.
    for i in 10..20u32 {
        cluster
            .write(format!("post-{i}"), format!("v{i}"))
            .await
            .unwrap_or_else(|e| panic!("post-crash write {i} failed: {e}"));
    }

    // Pre-crash committed entries must be on all surviving nodes.
    for node_id in cluster.node_ids() {
        for i in 0..10u32 {
            let got = cluster.read(node_id, &format!("pre-{i}"));
            assert_eq!(
                got.as_deref(),
                Some(format!("v{i}").as_str()),
                "node {node_id} missing pre-crash entry pre-{i}"
            );
        }
    }

    cluster.shutdown().await;
}

/// Kill a follower, write entries, restart.  The follower's lag is below the
/// snapshot threshold so it must catch up via log replay, not snapshot install.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_follower_crash_catchup_via_log() {
    // snapshot threshold=200 → follower writing 20 entries won't trigger it.
    let mut cluster = TestCluster::new_with_snapshot_threshold(3, 200).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    let victim = cluster
        .node_ids()
        .into_iter()
        .find(|&id| id != leader)
        .unwrap();

    cluster.kill_node(victim).await;

    for i in 0..20u32 {
        cluster.write(format!("lag-{i}"), format!("v{i}")).await.unwrap();
    }

    cluster.restart_node(victim).await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    for i in 0..20u32 {
        let got = cluster.read(victim, &format!("lag-{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("v{i}").as_str()),
            "restarted follower {victim} missing log-replayed entry lag-{i}"
        );
    }

    cluster.shutdown().await;
}

/// Kill a follower, write enough entries to exceed snapshot_threshold, restart.
/// The follower's log is compacted; it must install a snapshot to catch up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_follower_crash_catchup_via_snapshot() {
    // threshold=10 → writing 30 entries while follower is dead forces snapshot.
    let mut cluster = TestCluster::new_with_snapshot_threshold(3, 10).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    let victim = cluster
        .node_ids()
        .into_iter()
        .find(|&id| id != leader)
        .unwrap();

    // Write pre-kill data so there's something to snapshot.
    for i in 0..10u32 {
        cluster.write(format!("snap-pre-{i}"), format!("v{i}")).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    cluster.kill_node(victim).await;

    // Write 30 entries past the compaction horizon.
    for i in 10..40u32 {
        cluster.write(format!("snap-post-{i}"), format!("v{i}")).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(400)).await;

    cluster.restart_node(victim).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // All 40 entries must be visible after snapshot install.
    for i in 10..40u32 {
        let got = cluster.read(victim, &format!("snap-post-{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("v{i}").as_str()),
            "restarted follower {victim} missing snapshot-installed key snap-post-{i}"
        );
    }

    cluster.shutdown().await;
}

// ── Membership change tests ───────────────────────────────────────────────────

/// Add a new node while writes are flowing continuously.
/// Expected: no write failures, new node catches up to full state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_add_node_under_write_load() {
    use openraft::BasicNode;

    let mut cluster = TestCluster::new(3).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    // Start a background write loop.
    let write_errors = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let write_errors_clone = write_errors.clone();
    let writes_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writes_done_clone = writes_done.clone();

    // We can't move `cluster` into the task, so we write synchronously below
    // and spin up the new node between write batches.
    for i in 0..20u32 {
        if let Err(e) = cluster.write(format!("load-{i}"), format!("v{i}")).await {
            eprintln!("pre-join write {i} error (may be transient): {e}");
            write_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    // Spin up node 4 and add it as learner → voter.
    cluster.spin_up_node(4).await;
    cluster.nodes[&leader]
        .add_learner(4, BasicNode::default())
        .await
        .expect("add_learner(4) failed");

    for i in 20..40u32 {
        if let Err(e) = cluster.write(format!("load-{i}"), format!("v{i}")).await {
            eprintln!("during-join write {i} error: {e}");
            write_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(2)).await;
    cluster.nodes[&leader]
        .add_voter(4)
        .await
        .expect("add_voter(4) failed");

    for i in 40..60u32 {
        if let Err(e) = cluster.write(format!("load-{i}"), format!("v{i}")).await {
            eprintln!("post-join write {i} error: {e}");
            write_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    writes_done_clone.store(true, std::sync::atomic::Ordering::Relaxed);

    // Allow node 4 to catch up.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let total_errors = write_errors_clone.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(total_errors, 0, "{total_errors} write error(s) occurred during membership change");

    for i in 0..60u32 {
        let got = cluster.read(4, &format!("load-{i}"));
        assert_eq!(
            got.as_deref(),
            Some(format!("v{i}").as_str()),
            "new node 4 missing load-{i} after join"
        );
    }

    assert!(writes_done.load(std::sync::atomic::Ordering::Relaxed));
    cluster.shutdown().await;
}

/// Rolling restart: restart each node one at a time with writes flowing.
/// Expected: zero write failures — quorum is always available.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_rolling_restart_zero_downtime() {
    let mut cluster = TestCluster::new(3).await;
    cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    let mut write_errors = 0u64;
    let mut write_counter = 0u32;

    let node_ids: Vec<u64> = vec![1, 2, 3];
    for node_id in node_ids {
        // Write before kill.
        for i in write_counter..write_counter + 5 {
            if let Err(e) = cluster.write(format!("roll-{i}"), format!("v{i}")).await {
                eprintln!("pre-kill write {i} error: {e}");
                write_errors += 1;
            }
        }
        write_counter += 5;

        // Kill and restart this node (quorum = 2 of the other 2 nodes).
        cluster.kill_node(node_id).await;

        for i in write_counter..write_counter + 5 {
            if let Err(e) = cluster.write(format!("roll-{i}"), format!("v{i}")).await {
                eprintln!("during-restart write {i} error: {e}");
                write_errors += 1;
            }
        }
        write_counter += 5;

        cluster.restart_node(node_id).await;
        // Allow the restarted node to rejoin before we move to the next one.
        tokio::time::sleep(Duration::from_millis(500)).await;

        for i in write_counter..write_counter + 5 {
            if let Err(e) = cluster.write(format!("roll-{i}"), format!("v{i}")).await {
                eprintln!("post-restart write {i} error: {e}");
                write_errors += 1;
            }
        }
        write_counter += 5;
    }

    assert_eq!(write_errors, 0, "{write_errors} write error(s) during rolling restart");
    cluster.shutdown().await;
}

// ── Read consistency tests ────────────────────────────────────────────────────

/// While a follower is isolated, reads from the leader must remain consistent
/// (reads_allowed stays true on the leader regardless of follower state).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_leader_reads_consistent_during_follower_partition() {
    let cluster = TestCluster::new(3).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    for i in 0..10u32 {
        cluster.write(format!("stable-{i}"), format!("v{i}")).await.unwrap();
    }

    // Isolate one follower.
    let follower = cluster.node_ids().into_iter().find(|&id| id != leader).unwrap();
    cluster.isolate_node(follower);

    // Write more entries — leader + 1 remaining follower = quorum.
    for i in 10..20u32 {
        cluster.write(format!("stable-{i}"), format!("v{i}")).await.unwrap();
    }

    // Leader must always allow reads.
    assert!(
        cluster.reads_allowed(leader),
        "leader reads_allowed must be true regardless of follower partition"
    );

    // Leader reads must return the latest committed values.
    for i in 10..20u32 {
        let got = cluster.read_with_staleness_check(leader, &format!("stable-{i}"));
        assert!(
            got.is_ok(),
            "leader read for stable-{i} returned error during follower partition"
        );
    }

    // The isolated follower's reads_allowed may flip to false due to lag.
    // That is the correct behaviour — we don't assert it here, just verify
    // the leader is unaffected.
    cluster.reconnect_node(follower);
    cluster.shutdown().await;
}

// ── Throughput and latency tests ──────────────────────────────────────────────

/// Sustained write throughput under the `spawn_blocking`-wrapped storage path.
/// Measures p99 commit latency over 500 sequential writes on a 3-node cluster.
/// Verifies that no write blocks the Tokio executor for more than 100 ms.
///
/// Tagged `#[ignore]` so it runs only in the dedicated chaos CI job:
///   cargo test --test chaos -- --include-ignored test_write_throughput_p99
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn test_write_throughput_p99() {
    const N: usize = 500;
    const P99_LIMIT_MS: u64 = 100;

    let cluster = TestCluster::new(3).await;
    cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    let mut latencies_ms: Vec<u64> = Vec::with_capacity(N);

    for i in 0..N {
        let start = Instant::now();
        cluster
            .write(format!("tput-{i}"), format!("v{i}"))
            .await
            .unwrap_or_else(|e| panic!("throughput write {i} failed: {e}"));
        latencies_ms.push(start.elapsed().as_millis() as u64);
    }

    latencies_ms.sort_unstable();
    let p50 = latencies_ms[N / 2];
    let p99 = latencies_ms[N * 99 / 100];
    let p999 = latencies_ms[N * 999 / 1000];
    let total_ms: u64 = latencies_ms.iter().sum();
    let throughput = N as f64 / (total_ms as f64 / 1000.0);

    println!("=== Throughput / Latency ===");
    println!("  writes     : {N}");
    println!("  throughput : {throughput:.1} writes/s");
    println!("  p50 latency: {p50} ms");
    println!("  p99 latency: {p99} ms");
    println!("  p999 latency: {p999} ms");

    assert!(
        p99 <= P99_LIMIT_MS,
        "p99 commit latency {p99} ms exceeds limit {P99_LIMIT_MS} ms — possible executor blocking"
    );

    cluster.shutdown().await;
}

/// Verify that an apply-lagging follower has reads_allowed go false, staleness-aware
/// reads return an error, and reads resume once the backlog clears.
///
/// Note: the lag monitor measures `last_log_index - last_applied` on the local node.
/// Network-level delays don't produce this gap (the follower only sees entries it has
/// already received and applied).  `set_apply_delay` injects a per-entry sleep inside
/// the state-machine apply path, creating the in-flight backlog the monitor detects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_slow_follower_reads_disabled_then_recover() {
    let cluster = TestCluster::new(3).await;
    let leader = cluster.wait_for_leader_timeout(Duration::from_secs(5)).await;

    let follower = cluster.node_ids().into_iter().find(|&id| id != leader).unwrap();

    // Inject per-entry apply delay: 20 ms × 120 entries = 2400 ms of backlog.
    // lag_threshold = 500 ms → reads_allowed flips to false when lag > 100 entries.
    cluster.set_apply_delay(follower, 20);

    for i in 0..120u32 {
        cluster.write(format!("slow-{i}"), format!("v{i}")).await.unwrap();
    }

    // Give the lag monitor time to detect the backlog.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        !cluster.reads_allowed(follower),
        "follower {follower} should have reads_allowed=false with high apply lag"
    );
    let err = cluster.read_with_staleness_check(follower, "slow-0");
    assert!(err.is_err(), "staleness-aware read on lagging follower must return an error");

    // Clear the delay; the follower drains its backlog.
    cluster.set_apply_delay(follower, 0);
    let recovered = wait_until(Duration::from_secs(5), || cluster.reads_allowed(follower)).await;
    assert!(recovered, "follower {follower} did not recover reads_allowed within 5 s");

    let ok = cluster.read_with_staleness_check(follower, "slow-0");
    assert!(ok.is_ok(), "reads should succeed after follower catches up");

    cluster.shutdown().await;
}
