//! #890 — the refresh-token grant's write path on a slow disk.
//!
//! Drives `refresh_tokens` in process, at fixed offered rates, over the
//! production storage stack: the WAL synced on every write, and the
//! single-node `ClusterStorageAdapter` with its write limit
//! (`storage.max_writes_in_flight`). Every file sync sleeps `FSYNC_DELAY_US`
//! first (default 0), to show the path on a slower disk than the local one.
//! On a disk whose sync takes about 3 ms, as the AWS gp3 volume of the #647
//! round A, the default shows the shape of the AWS run.
//!
//! As the k6 refresh journey does, a refresh refused with a retryable error
//! keeps its token for the next try, and a refresh refused as an invalid
//! grant (`400`) starts a new chain (a new session and token pair).
//!
//! Each step prints: completed refreshes/s, errors by class, p50/p99 of the
//! completed ones (measured from the scheduled start, so queueing counts), WAL
//! records per refresh, WAL syncs/s and records per sync, the mean and peak of
//! `hearth_storage_writes_in_flight`, the refused writes, the mean time a
//! write is in flight (Little's law: mean in flight / records per second), the
//! mean WAL sync, and the process CPU.
//!
//! Run:  `cargo run --release --example refresh_write_path`
//!
//! Environment: `FSYNC_DELAY_US` (0), `RATES` ("300,600,900,1200,1500"),
//! `STEP_SECS` (10), `CHAINS` (4000), `WORKERS` (256),
//! `MAX_WRITES_IN_FLIGHT` (32), `DATA_DIR` (a new temporary directory).
//! Pin it to two cores, as a c7i.large, with `taskset -c 0,1`.

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::cluster::{ClusterEngine, ClusterStorageAdapter};
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, IdentityError, SessionContext,
};
use hearth::storage::fs::FileBacking;
use hearth::storage::{
    EmbeddedStorageEngine, Fs, FsFile, RealFs, StorageConfig, StorageEngine, StorageError,
};

/// Microseconds every file sync sleeps before it syncs; 0 while seeding.
static SYNC_DELAY_US: AtomicU64 = AtomicU64::new(0);

fn delay_sync() {
    let us = SYNC_DELAY_US.load(Ordering::Relaxed);
    if us > 0 {
        thread::sleep(Duration::from_micros(us));
    }
}

/// [`RealFs`] whose file syncs take `SYNC_DELAY_US` longer.
struct SlowSyncFs(RealFs);

struct SlowSyncFile(Box<dyn FsFile>);

impl FsFile for SlowSyncFile {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.0.read_to_end(buf)
    }
    fn sync_all(&self) -> io::Result<()> {
        delay_sync();
        self.0.sync_all()
    }
    fn sync_data(&self) -> io::Result<()> {
        delay_sync();
        self.0.sync_data()
    }
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
    fn set_len(&self, size: u64) -> io::Result<()> {
        self.0.set_len(size)
    }
}

impl Fs for SlowSyncFs {
    fn open_append(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        Ok(Box::new(SlowSyncFile(self.0.open_append(path)?)))
    }
    fn create(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        Ok(Box::new(SlowSyncFile(self.0.create(path)?)))
    }
    fn open_read(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        self.0.open_read(path)
    }
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.0.read(path)
    }
    fn read_prefix(&self, path: &Path, len: usize) -> io::Result<Vec<u8>> {
        self.0.read_prefix(path, len)
    }
    fn map_readonly(&self, path: &Path) -> io::Result<FileBacking> {
        self.0.map_readonly(path)
    }
    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        self.0.write(path, data)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.0.create_dir_all(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.0.read_dir(path)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.0.remove_file(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.0.rename(from, to)
    }
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        delay_sync();
        self.0.sync_dir(dir)
    }
}

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// User and session of one refresh chain, and its current refresh token.
struct Chain {
    user: UserId,
    refresh: String,
}

/// The outcome of one refresh.
enum Outcome {
    Ok(Duration),
    /// Refused with a retryable error (a `503` at the HTTP layer).
    Retry,
    /// Refused as an invalid grant (a `400`).
    Invalid,
    Other,
}

/// Process CPU time (user + system) so far.
fn cpu_time() -> Duration {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let fields: Vec<&str> = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest.split_whitespace().collect())
        .unwrap_or_default();
    let ticks = |i: usize| {
        fields
            .get(i)
            .and_then(|f| f.parse::<u64>().ok())
            .unwrap_or(0)
    };
    // utime and stime are fields 14 and 15; `rest` starts at field 3.
    Duration::from_millis((ticks(11) + ticks(12)) * 10)
}

fn percentile(sorted: &[Duration], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let i = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[i].as_secs_f64() * 1000.0
}

#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let delay_us: u64 = env_or("FSYNC_DELAY_US", 0);
    let rates: Vec<u64> = std::env::var("RATES")
        .unwrap_or_else(|_| "300,600,900,1200,1500".to_string())
        .split(',')
        .filter_map(|r| r.trim().parse().ok())
        .collect();
    let step = Duration::from_secs(env_or("STEP_SECS", 10));
    let chains_n: usize = env_or("CHAINS", 4000);
    let workers: usize = env_or("WORKERS", 256);
    let limit: usize = env_or("MAX_WRITES_IN_FLIGHT", 32);
    let tmp = tempfile::tempdir()?;
    let data_dir =
        std::env::var("DATA_DIR").map_or_else(|_| tmp.path().to_path_buf(), PathBuf::from);

    let mut config = StorageConfig::production(
        data_dir.clone(),
        64 * 1024 * 1024,
        64 * 1024 * 1024,
        100_000,
    );
    config.dev_mode = true;
    let inner = Arc::new(EmbeddedStorageEngine::open_with_fs(
        config,
        Arc::new(SlowSyncFs(RealFs)),
    )?);
    let storage: Arc<dyn StorageEngine> =
        Arc::new(ClusterStorageAdapter::with_max_writes_in_flight(
            Arc::new(ClusterEngine::single_node(Arc::clone(&inner))),
            limit,
        ));
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let engine = Arc::new(EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        clock,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit,
    )?);
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("refresh-890-{}", uuid::Uuid::new_v4()),
            config: None,
        })?
        .id()
        .clone();

    println!(
        "#890 refresh write path: sync delay {delay_us} µs, write limit {limit}, \
         {chains_n} chains, {workers} workers, {} s steps, data {}",
        step.as_secs(),
        data_dir.display()
    );
    let chains = Arc::new(Mutex::new(seed(&engine, &realm, chains_n)?));
    SYNC_DELAY_US.store(delay_us, Ordering::Relaxed);

    println!(
        "{:>7} {:>8} {:>7} {:>7} {:>7} {:>7} {:>8} {:>10} {:>8} {:>9} {:>7} {:>7} {:>7} {:>10} {:>8} {:>6}",
        "offered", "ok/s", "err %", "retry", "invalid", "other", "p50 ms", "p99 ms",
        "rec/ref", "syncs/s", "rec/syn", "infl", "peak", "shed", "write ms", "cpu %"
    );
    let metrics = hearth::metrics::metrics();
    for rate in rates {
        let (tx, rx) = mpsc::channel::<Instant>();
        let rx = Arc::new(Mutex::new(rx));
        let outcomes = Arc::new(Mutex::new(Vec::<Outcome>::new()));
        let pool: Vec<_> = (0..workers)
            .map(|_| {
                let (rx, outcomes, chains, engine, realm) = (
                    Arc::clone(&rx),
                    Arc::clone(&outcomes),
                    Arc::clone(&chains),
                    Arc::clone(&engine),
                    realm.clone(),
                );
                thread::spawn(move || loop {
                    let scheduled = {
                        let Ok(rx) = rx.lock() else { return };
                        match rx.recv() {
                            Ok(at) => at,
                            Err(_) => return,
                        }
                    };
                    let chain = chains.lock().ok().and_then(|mut c| c.pop_front());
                    let Some(chain) = chain else { continue };
                    let outcome = refresh_once(&engine, &realm, chain, &chains, scheduled);
                    if let Ok(mut o) = outcomes.lock() {
                        o.push(outcome);
                    }
                })
            })
            .collect();

        let sampling_done = Arc::new(AtomicBool::new(false));
        let sampler = {
            let sampling_done = Arc::clone(&sampling_done);
            thread::spawn(move || {
                let (mut sum, mut n, mut peak) = (0.0, 0u64, 0.0f64);
                while !sampling_done.load(Ordering::Relaxed) {
                    let v = metrics.storage_writes_in_flight.get();
                    sum += v;
                    n += 1;
                    peak = peak.max(v);
                    thread::sleep(Duration::from_micros(250));
                }
                (sum / n.max(1) as f64, peak)
            })
        };

        let (syncs0, prof0, shed0, cpu0) = (
            inner.wal_sync_count(),
            inner.wal_commit_profile(),
            metrics.storage_writes_shed_total.get(),
            cpu_time(),
        );
        let start = Instant::now();
        let interval = Duration::from_secs_f64(1.0 / rate as f64);
        let mut next = start;
        while next < start + step {
            let now = Instant::now();
            if next > now {
                thread::sleep(next - now);
            }
            if tx.send(next).is_err() {
                break;
            }
            next += interval;
        }
        drop(tx);
        for worker in pool {
            let _ = worker.join();
        }
        let elapsed = start.elapsed().as_secs_f64();
        sampling_done.store(true, Ordering::Relaxed);
        let (mean_in_flight, peak_in_flight) = sampler.join().unwrap_or((0.0, 0.0));
        let prof = inner.wal_commit_profile();
        let syncs = inner.wal_sync_count() - syncs0;
        let records = prof.entries - prof0.entries;
        let fsync_ms = (prof.fsync_ns - prof0.fsync_ns) as f64
            / 1e6
            / (prof.batches - prof0.batches).max(1) as f64;
        let shed = metrics.storage_writes_shed_total.get() - shed0;
        let cpu = cpu_time().saturating_sub(cpu0).as_secs_f64() / elapsed * 100.0;

        let outcomes = std::mem::take(&mut *outcomes.lock().map_err(|_| "outcomes lock")?);
        let mut ok: Vec<Duration> = Vec::new();
        let (mut retry, mut invalid, mut other) = (0u64, 0u64, 0u64);
        for o in &outcomes {
            match o {
                Outcome::Ok(d) => ok.push(*d),
                Outcome::Retry => retry += 1,
                Outcome::Invalid => invalid += 1,
                Outcome::Other => other += 1,
            }
        }
        ok.sort();
        let total = outcomes.len().max(1) as f64;
        let records_s = records as f64 / elapsed;
        println!(
            "{:>7} {:>8.1} {:>7.2} {:>7} {:>7} {:>7} {:>8.1} {:>10.1} {:>8.2} {:>9.0} {:>7.1} {:>7.1} {:>7.0} {:>10.0} {:>8.2} {:>6.0}",
            rate,
            ok.len() as f64 / elapsed,
            (retry + invalid + other) as f64 / total * 100.0,
            retry,
            invalid,
            other,
            percentile(&ok, 0.50),
            percentile(&ok, 0.99),
            records as f64 / total,
            syncs as f64 / elapsed,
            records as f64 / syncs.max(1) as f64,
            mean_in_flight,
            peak_in_flight,
            shed,
            if records_s > 0.0 { mean_in_flight / records_s * 1000.0 } else { 0.0 },
            cpu,
        );
        println!("        mean WAL sync {fsync_ms:.2} ms");
    }
    Ok(())
}

/// One refresh of `chain`, which goes back to the pool afterwards: with its
/// new token, with the same token after a retryable refusal, or as a new
/// chain after an invalid grant.
fn refresh_once(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
    chain: Chain,
    chains: &Mutex<VecDeque<Chain>>,
    scheduled: Instant,
) -> Outcome {
    let result = engine.refresh_tokens(realm, &chain.refresh, None, None);
    let (outcome, next) = match result {
        Ok(pair) => (
            Outcome::Ok(scheduled.elapsed()),
            Some(Chain {
                user: chain.user,
                refresh: pair.refresh_token().to_string(),
            }),
        ),
        Err(IdentityError::Storage(e)) if StorageError::retry_class_of(e.as_ref()).is_some() => {
            (Outcome::Retry, Some(chain))
        }
        Err(
            IdentityError::TokenRevoked
            | IdentityError::InvalidToken
            | IdentityError::TokenExpired
            | IdentityError::SessionNotFound
            | IdentityError::InvalidGrant { .. },
        ) => (Outcome::Invalid, new_chain(engine, realm, &chain.user).ok()),
        Err(e) => {
            eprintln!("refresh error: {e}");
            (Outcome::Other, Some(chain))
        }
    };
    if let (Some(next), Ok(mut c)) = (next, chains.lock()) {
        c.push_back(next);
    }
    outcome
}

fn new_chain(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
    user: &UserId,
) -> Result<Chain, IdentityError> {
    let session = engine.create_session(realm, user, &SessionContext::default())?;
    let pair = engine.issue_tokens(realm, user, session.id())?;
    Ok(Chain {
        user: user.clone(),
        refresh: pair.refresh_token().to_string(),
    })
}

/// `n` refresh chains over `n / 8` users, seeded in parallel.
fn seed(
    engine: &Arc<EmbeddedIdentityEngine>,
    realm: &RealmId,
    n: usize,
) -> Result<VecDeque<Chain>, Box<dyn std::error::Error>> {
    let users: Vec<UserId> = (0..n.div_ceil(8))
        .map(|i| {
            engine
                .create_user(
                    realm,
                    &CreateUserRequest {
                        email: format!("u{i}@refresh-890.test"),
                        display_name: format!("user {i}"),
                        first_name: String::new(),
                        last_name: String::new(),
                        attributes: Default::default(),
                    },
                )
                .map(|u| u.id().clone())
        })
        .collect::<Result<_, _>>()?;
    let users = Arc::new(users);
    let seeded: Vec<_> = (0..16)
        .map(|t| {
            let (engine, realm, users) = (Arc::clone(engine), realm.clone(), Arc::clone(&users));
            thread::spawn(move || {
                (t..n)
                    .step_by(16)
                    .map(|i| new_chain(&engine, &realm, &users[i % users.len()]))
                    .collect::<Result<Vec<_>, _>>()
            })
        })
        .collect();
    let mut chains = VecDeque::with_capacity(n);
    for s in seeded {
        chains.extend(s.join().map_err(|_| "seed thread panicked")??);
    }
    Ok(chains)
}
