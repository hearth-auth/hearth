//! Peak extra memory of a Raft snapshot build and install on a large store
//! (`cluster-file-snapshots`, requirement "Snapshot memory is bounded").
//!
//! Seeds a store with `users` users of about 2 KB each (a user record, its
//! email index row, a credential and a session), then:
//!
//! 1. builds a snapshot of it through the state machine (as a leader does);
//! 2. sends it to a second, empty node's state machine the way openraft does
//!    (4 MiB chunks into the file `begin_receiving_snapshot` returns, then
//!    `shutdown`, which checks it), and installs it.
//!
//! A sampler thread reads `RssAnon` and `VmRSS` from `/proc/self/status`
//! every 5 ms. Each phase reports, for both, its start value, its peak and the
//! difference. The budget (512 MiB per phase at 1,000,000 users) applies to
//! the `RssAnon` rise, the extra anonymous memory the phase needed; `VmRSS`
//! also counts mapped file pages. The binary uses jemalloc, as the server does.
//!
//! Measured 2026-11-27 (see `docs/perf/snapshot-memory.md`).
//!
//! Run (Linux only; release build; needs about 3x the store size on disk):
//!
//! ```text
//! cargo run --release --example snapshot_memory -- [users] [dir]
//! ```
//!
//! Defaults: 1,000,000 users, a temporary directory.
#![allow(clippy::cast_precision_loss)]

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::cluster::state_machine::HearthStateMachine;
use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// openraft's transfer chunk in Hearth (`cluster::wire::SNAPSHOT_CHUNK_BYTES`).
const CHUNK: usize = 4 * 1024 * 1024;
/// Rows per seeding batch.
const SEED_BATCH: usize = 4_000;
/// The spec's budget per phase.
const BUDGET_MIB: f64 = 512.0;

/// `[RssAnon, VmRSS]` of this process in KiB.
fn rss_kib() -> [u64; 2] {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    [field("RssAnon:"), field("VmRSS:")]
}

/// Samples [`rss_kib`] in the background and keeps the peaks.
struct Sampler {
    peak: Arc<[AtomicU64; 2]>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Sampler {
    fn start() -> Self {
        let now = rss_kib();
        let peak = Arc::new([AtomicU64::new(now[0]), AtomicU64::new(now[1])]);
        let stop = Arc::new(AtomicBool::new(false));
        let (p, s) = (Arc::clone(&peak), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                for (slot, v) in p.iter().zip(rss_kib()) {
                    slot.fetch_max(v, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        Self {
            peak,
            stop,
            thread: Some(thread),
        }
    }

    /// Stops sampling and returns the peaks in KiB.
    fn finish(mut self) -> [u64; 2] {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let now = rss_kib();
        [0, 1].map(|i| self.peak[i].load(Ordering::Relaxed).max(now[i]))
    }
}

/// Runs `phase`, reports its RSS start, peak and rise, and returns the
/// `RssAnon` rise in MiB.
async fn measure<T, F: std::future::Future<Output = T>>(name: &str, phase: F) -> (T, f64) {
    let start = rss_kib();
    let sampler = Sampler::start();
    let began = Instant::now();
    let out = phase.await;
    let elapsed = began.elapsed();
    let peak = sampler.finish();
    let mib = |kib: u64| kib as f64 / 1024.0;
    for (i, label) in ["RssAnon", "VmRSS"].iter().enumerate() {
        println!(
            "{name:<8} {label:<8} start {:>8.1} MiB  peak {:>8.1} MiB  extra {:>7.1} MiB  ({:.1} s)",
            mib(start[i]),
            mib(peak[i]),
            mib(peak[i].saturating_sub(start[i])),
            elapsed.as_secs_f64()
        );
    }
    (out, mib(peak[0].saturating_sub(start[0])))
}

/// A value of `len` bytes that compresses about as well as a JSON record
/// holding hashes and ids: hex text.
fn value(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b"0123456789abcdef"[(x & 0xF) as usize]
        })
        .collect()
}

fn seed(engine: &EmbeddedStorageEngine, realm: &RealmId, users: u64) -> u64 {
    let mut batch = Vec::with_capacity(SEED_BATCH);
    let mut bytes = 0u64;
    for u in 0..users {
        let rows = [
            (format!("user:{u:016x}"), value(u, 1_200)),
            (format!("user_email:u{u}@example.test"), value(u + 1, 36)),
            (format!("cred:{u:016x}:password"), value(u + 2, 420)),
            (format!("session:{u:016x}"), value(u + 3, 300)),
        ];
        for (k, v) in rows {
            bytes += (k.len() + v.len()) as u64;
            batch.push((k.into_bytes(), v));
        }
        if batch.len() >= SEED_BATCH {
            engine.put_batch(realm, &batch).expect("seed batch");
            batch.clear();
        }
        if u > 0 && u % 100_000 == 0 {
            println!("seeded {u} users");
        }
    }
    if !batch.is_empty() {
        engine.put_batch(realm, &batch).expect("seed batch");
    }
    engine.flush_memtable().expect("flush");
    bytes
}

fn open(dir: &Path) -> Arc<EmbeddedStorageEngine> {
    Arc::new(EmbeddedStorageEngine::open(StorageConfig::dev(dir.to_path_buf())).expect("open"))
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let users: u64 = args
        .next()
        .map_or(1_000_000, |a| a.parse().expect("users is a number"));
    let tmp = tempfile::tempdir().expect("temp dir");
    let root: PathBuf = args
        .next()
        .map_or_else(|| tmp.path().to_path_buf(), PathBuf::from);
    let realm = RealmId::new(uuid::Uuid::from_u128(0x5EED));

    let leader_dir = root.join("leader");
    let follower_dir = root.join("follower");
    let leader = open(&leader_dir);
    let began = Instant::now();
    let seeded = {
        let leader = Arc::clone(&leader);
        let realm = realm.clone();
        tokio::task::spawn_blocking(move || seed(&leader, &realm, users))
            .await
            .expect("seed task")
    };
    println!(
        "seeded {users} users: {:.0} MiB of rows in {:.0} s",
        seeded as f64 / (1024.0 * 1024.0),
        began.elapsed().as_secs_f64()
    );

    let mut leader_sm = {
        let leader = Arc::clone(&leader);
        tokio::task::spawn_blocking(move || HearthStateMachine::new(leader))
            .await
            .expect("task")
            .expect("leader state machine")
    };
    let (snapshot, build_mib) = measure("build", async {
        leader_sm
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("build")
    })
    .await;
    let mut sent = snapshot.snapshot;
    let size = sent.seek(std::io::SeekFrom::End(0)).await.expect("seek");
    println!(
        "snapshot stream: {:.0} MiB",
        size as f64 / (1024.0 * 1024.0)
    );

    let follower = open(&follower_dir);
    let mut follower_sm = {
        let follower = Arc::clone(&follower);
        tokio::task::spawn_blocking(move || HearthStateMachine::new(follower))
            .await
            .expect("task")
            .expect("follower state machine")
    };
    let meta = snapshot.meta.clone();
    let ((), install_mib) = measure("install", async {
        let mut received = follower_sm
            .begin_receiving_snapshot()
            .await
            .expect("begin receiving");
        sent.seek(std::io::SeekFrom::Start(0)).await.expect("seek");
        let mut buf = Vec::with_capacity(CHUNK);
        loop {
            buf.clear();
            while buf.len() < CHUNK {
                if sent.read_buf(&mut buf).await.expect("read") == 0 {
                    break;
                }
            }
            if buf.is_empty() {
                break;
            }
            received.write_all(&buf).await.expect("write");
        }
        received
            .shutdown()
            .await
            .expect("the received snapshot checks");
        follower_sm
            .install_snapshot(&meta, received)
            .await
            .expect("install");
    })
    .await;

    let probe = format!("user:{:016x}", users - 1);
    assert_eq!(
        follower.get(&realm, probe.as_bytes()).expect("read"),
        leader.get(&realm, probe.as_bytes()).expect("read"),
        "the follower holds the leader's last user"
    );
    let verdict = |mib: f64| if mib < BUDGET_MIB { "within" } else { "OVER" };
    println!(
        "RssAnon budget {BUDGET_MIB} MiB: build {} ({build_mib:.1} MiB), install {} ({install_mib:.1} MiB)",
        verdict(build_mib),
        verdict(install_mib)
    );
}
