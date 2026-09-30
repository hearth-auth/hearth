//! Peer message size: replication must not depend on how large a Raft message
//! is once serialised.
//!
//! The peer transport used to encode every Raft RPC as JSON, where a byte
//! string becomes an array of decimal numbers (about 3.6 bytes per byte), and
//! the peer gRPC server kept tonic's default 4 MiB decode limit. openraft sends
//! up to 300 log entries per `AppendEntries` and snapshot chunks of 3 MiB, so a
//! follower that fell behind a few MiB of writes — or a single large write, or
//! any snapshot above ~1 MiB — received a message it refused to decode, on
//! every retry, for ever: replication to it stalled silently.
//!
//! Every test here writes data whose serialised form exceeds 4 MiB and asserts
//! that a follower catches up. Three real nodes on loopback; nextest runs this
//! binary in the `three-node-cluster` group.

#![allow(clippy::unwrap_used)]

mod cluster_fixture;

use std::sync::Arc;
use std::time::Duration;

use cluster_fixture::{blocking, realm, wait_converged, ThreeNodes};
use hearth::cluster::ClusterEngine;
use hearth::core::RealmId;

/// `len` pseudo-random bytes (splitmix64): incompressible, so a snapshot of
/// them stays as large as the data.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        out.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out.truncate(len);
    out
}

fn big_key(i: usize) -> Vec<u8> {
    format!("big:{i:05}").into_bytes()
}

/// Writes `count` values of `size` random bytes through the leader, 4 at a
/// time (each applied entry is fsync'd, so more only queue up behind the
/// write bound on a slow disk).
async fn write_noise(leader: &Arc<ClusterEngine>, realm: &RealmId, count: usize, size: usize) {
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..count {
        if tasks.len() >= 4 {
            tasks.join_next().await.unwrap().unwrap();
        }
        let (leader, realm) = (Arc::clone(leader), realm.clone());
        tasks.spawn(async move {
            leader
                .put(&realm, &big_key(i), &noise(i as u64, size))
                .await
                .unwrap_or_else(|e| panic!("the leader refused write {i}: {e}"));
        });
    }
    while let Some(done) = tasks.join_next().await {
        done.unwrap();
    }
}

/// Cuts every node's outbound peer RPCs to `lagging`, so it misses what the
/// other two commit.
fn isolate(cluster: &ThreeNodes, lagging: u64) {
    for node in cluster.nodes.iter().filter(|n| n.id != lagging) {
        node.faults.isolate(lagging);
    }
}

fn heal(cluster: &ThreeNodes) {
    for node in &cluster.nodes {
        node.faults.heal_all();
    }
}

/// Asserts node `id` holds exactly what was written for the sampled keys.
async fn assert_holds_noise(
    cluster: &ThreeNodes,
    id: u64,
    realm: &RealmId,
    keys: &[usize],
    size: usize,
) {
    for &i in keys {
        let s = Arc::clone(&cluster.node(id).storage);
        let r = realm.clone();
        let got = blocking(move || s.get(&r, &big_key(i)).unwrap()).await;
        assert!(
            got.as_deref() == Some(noise(i as u64, size).as_slice()),
            "node {id} does not hold write {i} ({} bytes)",
            got.map_or(0, |v| v.len())
        );
    }
}

/// A single write whose Raft entry is larger than 4 MiB once serialised
/// commits and reaches both followers.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_single_multi_mib_write_replicates_to_every_node() {
    let cluster = ThreeNodes::start().await;
    let realm = realm();
    let leader = Arc::clone(&cluster.leader().cluster);

    let value = noise(0, 2 * 1024 * 1024);
    leader
        .put(&realm, &big_key(0), &value)
        .await
        .unwrap_or_else(|e| panic!("a 2 MiB write did not commit: {e}"));
    wait_converged(&cluster.engines(), Duration::from_secs(30)).await;
    for node in &cluster.nodes {
        assert_holds_noise(&cluster, node.id, &realm, &[0], value.len()).await;
    }

    cluster.shutdown();
}

/// A follower that missed 3 MiB of writes catches up: the entries it is
/// owed are ~11 MiB as the old JSON (over the old 4 MiB limit) and more than
/// `APPEND_BATCH_BYTES` as CBOR, so the transport sends them as several
/// `AppendEntries` cut to `APPEND_BATCH_BYTES` (openraft's partial success).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lagging_follower_catches_up_through_a_multi_mib_append_batch() {
    let cluster = ThreeNodes::start().await;
    let realm = realm();
    let lagging = cluster.followers()[0].id;
    let leader = Arc::clone(&cluster.leader().cluster);

    isolate(&cluster, lagging);
    write_noise(&leader, &realm, 96, 32 * 1024).await;
    heal(&cluster);

    wait_converged(&cluster.engines(), Duration::from_secs(60)).await;
    assert_holds_noise(&cluster, lagging, &realm, &[0, 1, 48, 95], 32 * 1024).await;

    cluster.shutdown();
}

/// A follower behind the leader's purged log is brought up to date by a
/// snapshot larger than 4 MiB (incompressible data), sent in several chunks.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_follower_behind_a_purged_log_installs_a_multi_mib_snapshot() {
    let cluster = ThreeNodes::start().await;
    let realm = realm();
    let lagging = cluster.followers()[0].id;
    let leader = Arc::clone(&cluster.leader().cluster);
    let lagging_last = cluster
        .node(lagging)
        .cluster
        .raft_metrics()
        .and_then(|m| m.last_log_index)
        .unwrap_or(0);

    isolate(&cluster, lagging);
    write_noise(&leader, &realm, 64, 96 * 1024).await;
    // Compact every node that could lead after the heal: the lagging node's
    // higher term forces an election, and an unpurged winner would send it
    // log entries instead of a snapshot.
    wait_converged(
        &cluster
            .nodes
            .iter()
            .filter(|n| n.id != lagging)
            .map(|n| Arc::clone(&n.cluster))
            .collect::<Vec<_>>(),
        Duration::from_secs(30),
    )
    .await;
    for node in cluster.nodes.iter().filter(|n| n.id != lagging) {
        let upto = node
            .cluster
            .compact_log()
            .await
            .expect("snapshot and purge");
        assert!(
            upto > lagging_last + 1,
            "precondition: node {}'s purge ({upto}) must pass node {lagging}'s log ({lagging_last})",
            node.id
        );
    }
    heal(&cluster);

    wait_converged(&cluster.engines(), Duration::from_secs(90)).await;
    let snap = cluster
        .node(lagging)
        .cluster
        .raft_metrics()
        .and_then(|m| m.snapshot);
    assert!(
        snap.is_some(),
        "precondition: node {lagging} caught up without installing a snapshot"
    );
    assert_holds_noise(&cluster, lagging, &realm, &[0, 31, 63], 96 * 1024).await;

    cluster.shutdown();
}
