//! Composed storage engine integrating WAL, memtable, SST, and hot tier.
//!
//! `EmbeddedStorageEngine` implements the `StorageEngine` trait by layering:
//! - **Read path**: hot tier → memtable → SST files (newest first)
//! - **Write path**: WAL append → memtable insert → hot tier invalidate
//! - **Recovery**: WAL replay into fresh memtable on open

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};

use fs2::FileExt as _;

use arc_swap::ArcSwap;

use crate::core::RealmId;
use crate::storage::encryption;
use crate::storage::error::StorageError;
use crate::storage::fs::{Fs, RealFs};
use crate::storage::key_registry::KeyRegistry;
use crate::storage::memtable::{Memtable, MemtableConfig, MemtableValue};
use crate::storage::sst::{self, SstReader, SstWriter};
use crate::storage::tiered::{HotTier, TieredConfig, PRODUCTION_PROMOTE_SAMPLE_RATE};
use crate::storage::wal::{
    BatchEntry, Wal, WalConfig, WalDurabilityHandle, WalEntry, WalOperation,
};
use crate::storage::{
    ScanEntry, StorageDurabilityHandle, StorageDurabilityHandleKind, StorageEngine,
};

/// Publishes the live SST file count to the observability gauge (HEA-1869).
///
/// Called off the hot path after every swap of the SST reader set (initial
/// open, memtable flush, WAL-rotation flush, compaction) so a scrape always
/// reflects the current cold-tier fan-out width.
fn record_sst_file_count(count: usize) {
    #[allow(clippy::cast_precision_loss)]
    crate::metrics::metrics()
        .storage_sst_files
        .set(count as f64);
}

/// Pending write-batch handle for the [`EmbeddedStorageEngine`] group-commit path.
///
/// Returned (wrapped in a [`StorageDurabilityHandle`]) by
/// [`EmbeddedStorageEngine::enqueue_batch`] when `SyncMode::EveryWrite` is active.
/// Passed back to [`EmbeddedStorageEngine::await_batch_durable`], which runs the
/// WAL leader loop (or waits as a follower) and then applies the entries to the
/// memtable once the `fsync` succeeds.
pub(crate) struct PendingBatchHandle {
    pub(crate) am_leader: bool,
    /// Position in the WAL commit stream this batch is waiting on.
    pub(crate) ticket: u64,
    pub(crate) realm_id: crate::core::RealmId,
    pub(crate) entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Name of the marker file written before a two-phase snapshot restore and
/// removed after it completes successfully (HEA-2132).
///
/// If this file is present when the engine opens, the previous process was
/// killed between Phase 1 (delete all keys) and Phase 2 (replay snapshot data).
/// The engine refuses to start and returns [`StorageError::TornSnapshotRestore`]
/// so the operator can take action (delete the file and let the node re-request
/// the snapshot from the leader) rather than silently serving mixed data.
const SNAPSHOT_RESTORE_MARKER: &str = "SNAPSHOT_RESTORE_IN_PROGRESS";

/// Process-wide set of canonical data-directory paths currently held open.
///
/// Prevents two `EmbeddedStorageEngine` instances in the same process from
/// opening the same directory. Cross-process conflicts are caught by the OS
/// advisory lock (`LOCK` file via `flock`).
static OPEN_DIRS: LazyLock<Mutex<HashSet<PathBuf>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// RAII guard that removes `path` from [`OPEN_DIRS`] on drop.
struct DirLockGuard(PathBuf);

impl Drop for DirLockGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = OPEN_DIRS.lock() {
            set.remove(&self.0);
        }
    }
}

/// Configuration for the embedded storage engine.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Directory for WAL and SST files.
    pub data_dir: PathBuf,
    /// WAL configuration.
    pub wal_config: WalConfig,
    /// Memtable configuration.
    pub(crate) memtable_config: MemtableConfig,
    /// Hot tier configuration.
    pub(crate) tiered_config: TieredConfig,
    /// When true, missing KEKs during startup only log a warning
    /// instead of returning an error. Default: false.
    ///
    /// Operators can use this as an escape hatch to recover from a
    /// partly-corrupted `hearth.keys` file without recompiling.
    pub allow_missing_keks: bool,
    /// Background SST compaction configuration.
    pub compaction: CompactionConfig,
    /// When `true`, auto-generation of the host key is permitted if
    /// `HEARTH_MASTER_KEY` is unset (dev/test only). When `false` (production),
    /// startup fails if the env var is absent — preventing a world-readable key.
    pub dev_mode: bool,
    /// Total byte budget for the process-wide decrypted-block cache shared by
    /// all v3 SST readers (HEA-1914). Bounds decrypted cold-tier residency
    /// independent of corpus size. Default 256 MiB.
    pub block_cache_bytes: usize,
}

/// Default byte budget for the shared decrypted-block cache (256 MiB).
pub const DEFAULT_BLOCK_CACHE_BYTES: usize = 256 * 1024 * 1024;

/// Configuration for background SST compaction.
#[derive(Debug, Clone)]
pub struct CompactionConfig {
    /// Whether automatic background compaction is enabled.
    pub enabled: bool,
    /// Interval between periodic full-compaction sweeps in seconds. `0` disables
    /// the periodic sweep (the count trigger below can still run partial
    /// compactions).
    pub interval_secs: u64,
    /// Minimum number of SST files before a periodic **full** compaction runs.
    pub min_sst_count: usize,
    /// Count trigger for **partial** (size-tiered) compaction. When the number of
    /// live SST files reaches this value after a flush, a partial compaction is
    /// scheduled on the background task — merging only one size-tier's worth of
    /// SSTs, never the whole dataset. `0` disables the count trigger (the
    /// reversible default), leaving only the periodic full sweep.
    ///
    /// Bounds cold-read fan-out at roughly `merge_min * log(corpus)` without the
    /// quadratic write amplification a count-triggered *full* merge would incur
    /// (HEA-1885 / HEA-1881).
    pub max_sst_count: usize,
    /// Minimum number of same-size-tier SST files that must accumulate before a
    /// partial compaction merges them into one. Bounds per-tier fan-in (the
    /// size-tiered `min_threshold`). Values below 2 are clamped to 2.
    pub merge_min: usize,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 3600,
            min_sst_count: 3,
            // Count trigger ON by default (HEA-1931). It bounds cold-read SST
            // fan-out at ~`merge_min * log(corpus)` instead of Θ(corpus). Safe to
            // enable by default now that the merge I/O runs off `flush_lock`
            // (HEA-1931), so the count trigger no longer risks order-of-seconds
            // write stalls. `12` is the best fan-out/write-amp trade-off per
            // HEA-1905. Set to `0` to disable.
            max_sst_count: 12,
            merge_min: 4,
        }
    }
}

impl StorageConfig {
    /// Creates a development/test configuration with no fsync and moderate thresholds.
    ///
    /// Suitable for integration tests and `--dev` mode. Uses `SyncMode::None`
    /// for speed and reasonable defaults that exercise flush/eviction paths
    /// without excessive I/O.
    pub fn dev(data_dir: PathBuf) -> Self {
        use crate::storage::wal::SyncMode;
        Self {
            data_dir,
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig::default(),
            tiered_config: TieredConfig::default(),
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
            dev_mode: true,
            block_cache_bytes: DEFAULT_BLOCK_CACHE_BYTES,
        }
    }

    /// Creates a production storage configuration from operator-facing
    /// settings.
    ///
    /// WAL fsync is **always enabled** in production mode — this is a
    /// hard durability guarantee. Operators who need fsync disabled for
    /// benchmarking or development must use [`StorageConfig::dev`] or
    /// construct `WalConfig` directly with `SyncMode::None` and accept the
    /// durability loss explicitly.
    ///
    /// Wires the `[storage]` YAML section values into the internal
    /// `WalConfig`, `MemtableConfig`, and `TieredConfig`. Callers should
    /// pre-compute `hot_tier_capacity` — either from the explicit
    /// `hot_tier_capacity` YAML field or via
    /// [`crate::storage::auto_size::auto_size_hot_tier_capacity`].
    pub fn production(
        data_dir: PathBuf,
        wal_max_size_bytes: u64,
        memtable_flush_bytes: u64,
        hot_tier_capacity: usize,
    ) -> Self {
        use crate::storage::wal::SyncMode;
        Self {
            data_dir,
            wal_config: WalConfig {
                max_size: wal_max_size_bytes,
                sync_mode: SyncMode::EveryWrite,
            },
            memtable_config: MemtableConfig {
                flush_threshold_bytes: usize::try_from(memtable_flush_bytes).unwrap_or(usize::MAX),
            },
            tiered_config: TieredConfig {
                hot_tier_capacity,
                eviction_batch_size: 64,
                // Bound promote-path write-lock/clone churn under cold-read load
                // in production (HEA-1775). Dev/embedded keeps rate=1.
                promote_sample_rate: PRODUCTION_PROMOTE_SAMPLE_RATE,
            },
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
            dev_mode: false,
            block_cache_bytes: DEFAULT_BLOCK_CACHE_BYTES,
        }
    }

    /// Overrides the hot-tier entry capacity on an already-built config.
    ///
    /// `--dev` mode builds storage via [`StorageConfig::dev`], which uses
    /// [`TieredConfig::default`] (100k entries). For most dev corpora the whole
    /// working set fits in that hot tier, so every lookup is a hot-tier hit and
    /// tail latency is corpus-size-independent. Corpus-scale lookup profiles
    /// (HEA-1800) call this to size the hot tier *below* the working set so a
    /// known fraction of lookups fall through to the cold/SST tier, exposing the
    /// real lookup-cost-vs-`n` curve. Production sizes capacity through
    /// [`StorageConfig::production`] instead.
    pub fn set_hot_tier_capacity(&mut self, capacity: usize) {
        self.tiered_config.hot_tier_capacity = capacity;
    }

    /// Overrides the memtable flush threshold (bytes) on an already-built config.
    ///
    /// Lowering this forces the memtable to flush to SST files sooner, which
    /// tests and cold-tier load profiles use to push records out of the
    /// memtable and onto the SST read path without writing a production-sized
    /// corpus. Production sizes this through [`StorageConfig::production`].
    pub fn set_memtable_flush_bytes(&mut self, bytes: usize) {
        self.memtable_config.flush_threshold_bytes = bytes;
    }

    /// Creates a test configuration with fast sync and small thresholds.
    #[cfg(test)]
    pub(crate) fn test_config(data_dir: PathBuf) -> Self {
        use crate::storage::wal::SyncMode;
        Self {
            data_dir,
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig {
                flush_threshold_bytes: 4 * 1024, // 4 KiB for faster test flushes
            },
            tiered_config: TieredConfig {
                hot_tier_capacity: 100,
                eviction_batch_size: 10,
                promote_sample_rate: 1,
            },
            allow_missing_keks: false,
            compaction: CompactionConfig {
                enabled: false,
                interval_secs: 0,
                min_sst_count: 2,
                max_sst_count: 0,
                merge_min: 4,
            },
            dev_mode: true,
            block_cache_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Embedded storage engine composing WAL, memtable, SST files, and hot tier.
pub struct EmbeddedStorageEngine {
    /// Write-ahead log for durability.
    wal: Wal,
    /// Active in-memory sorted store.
    ///
    /// Wrapped in `Arc` so the WAL's pre-rotate flush callback can share it
    /// without a circular ownership dependency at construction time.
    active_memtable: Arc<Memtable>,
    /// On-disk SST files, newest first.
    ///
    /// Wrapped in `Arc<ArcSwap<...>>` for the same reason as `active_memtable`.
    sst_readers: Arc<ArcSwap<Vec<SstReader>>>,
    /// In-memory hot tier for frequently accessed data.
    hot_tier: HotTier,
    /// Base data directory.
    data_dir: PathBuf,
    /// Serializes flush operations.
    ///
    /// Wrapped in `Arc` so the WAL's pre-rotate flush callback can share it.
    flush_lock: Arc<Mutex<()>>,
    /// Serializes compaction operations against each other.
    ///
    /// Held for the *whole* of [`Self::compact_partial`] / [`Self::compact_ssts`]
    /// so two compactions never overlap (they would race on the shared SST file
    /// set and reader list). Crucially this is a *different* lock from
    /// [`Self::flush_lock`]: the O(tier-data) merge I/O runs while holding only
    /// this lock, so writers (which contend on `flush_lock`) are never stalled
    /// for the merge's duration — only for the brief metadata-only commit phase
    /// at the end (HEA-1931). Held before `flush_lock` in every path that takes
    /// both, so no lock-order inversion is possible.
    compaction_lock: Mutex<()>,
    /// Serializes [`put_if_absent`](StorageEngine::put_if_absent) so the
    /// existence check and the write are atomic against each other.
    ///
    /// The default trait implementation does a non-atomic `get` then `put`,
    /// leaving a TOCTOU window: two concurrent tasks can both observe the key
    /// as absent and both write. Holding this lock across the check-and-write
    /// closes that window in single-node mode (HEA-1767). Cluster mode routes
    /// `put_if_absent` through Raft and does not rely on this lock.
    put_if_absent_lock: Mutex<()>,
    /// Monotonically increasing SST file counter.
    ///
    /// Wrapped in `Arc` so the WAL's pre-rotate flush callback can share it.
    sst_counter: Arc<std::sync::atomic::AtomicU64>,
    /// Filesystem abstraction for fault injection in simulation tests.
    fs: Arc<dyn Fs>,
    /// Key registry for per-realm KEK management.
    key_registry: Arc<KeyRegistry>,
    /// System realm identifier used for file-level encryption.
    system_realm: RealmId,
    /// Compaction policy (periodic sweep + partial count trigger).
    compaction: CompactionConfig,
    /// Signalled by [`Self::trigger_flush`] when the live SST count reaches
    /// [`CompactionConfig::max_sst_count`], so the background task can run a
    /// partial compaction off the flush path. Never awaited on the hot path.
    compaction_notify: Arc<tokio::sync::Notify>,
    /// Cumulative count of records written *out* by compaction merges
    /// (`compact_partial` + `compact_ssts`), i.e. the write-amplification
    /// numerator. Off the hot path; incremented under `flush_lock` after each
    /// successful merge. Exposed via [`Self::compaction_records_written`] so the
    /// HEA-1881 write-amplification regression test can pin that size-tiered
    /// partial compaction stays `O(N log N)`, not the `O(N²)` a naive
    /// full-merge-on-trigger would incur. Not a Prometheus metric — kept purely
    /// internal to avoid the global-registry cross-test interference that
    /// process-wide counters suffer under parallel `nextest`.
    compaction_records_written: Arc<std::sync::atomic::AtomicU64>,
    /// Process-wide, byte-bounded cache of decrypted v3 SST blocks, shared by
    /// every reader so decrypted cold-tier residency is `O(cache_cap)`, not
    /// `O(corpus)` (HEA-1914).
    block_cache: Arc<crate::storage::block_cache::BlockCache>,
    /// Process-local guard: removes `data_dir` from `OPEN_DIRS` on drop.
    ///
    /// Must be declared after all fields that use `data_dir` so it is dropped
    /// last (Rust drops fields in declaration order).
    _process_lock: DirLockGuard,
    /// OS-level exclusive advisory lock on `{data_dir}/LOCK`.
    ///
    /// Released by the kernel when this `File` is closed (i.e., on drop), so
    /// a `kill -9`'d process never leaves a stale lock.
    _dir_lock: std::fs::File,
}

impl EmbeddedStorageEngine {
    /// Opens the storage engine at the given directory.
    ///
    /// Creates the directory if needed, discovers existing SST files,
    /// opens the WAL, and replays it into a fresh memtable.
    pub fn open(config: StorageConfig) -> Result<Self, StorageError> {
        Self::open_with_fs(config, Arc::new(RealFs))
    }

    /// Opens the storage engine with a custom filesystem implementation.
    ///
    /// Used by the simulation crate to inject faults via a `FaultFs`.
    #[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
    pub fn open_with_fs(config: StorageConfig, fs: Arc<dyn Fs>) -> Result<Self, StorageError> {
        fs.create_dir_all(&config.data_dir)?;

        // Acquire process-local + OS-level exclusive lock before touching any files.
        // The process-local guard prevents two engines in this process from using
        // the same directory (flock is per-process on Linux, so it cannot catch
        // in-process conflicts). The OS flock catches cross-process conflicts and
        // is released automatically by the kernel on process exit or kill -9.
        let canonical_dir = config
            .data_dir
            .canonicalize()
            .unwrap_or_else(|_| config.data_dir.clone());
        {
            let mut dirs = OPEN_DIRS.lock().expect("OPEN_DIRS mutex poisoned");
            if !dirs.insert(canonical_dir.clone()) {
                return Err(StorageError::AlreadyLocked {
                    data_dir: config.data_dir.clone(),
                });
            }
        }
        // Inserted into OPEN_DIRS above; guard removes it on drop (including early returns below).
        let dir_lock_guard = DirLockGuard(canonical_dir);

        let lock_path = config.data_dir.join("LOCK");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(StorageError::Io)?;
        lock_file
            .try_lock_exclusive()
            .map_err(|_| StorageError::AlreadyLocked {
                data_dir: config.data_dir.clone(),
            })?;

        // Refuse to open a directory that contains a torn snapshot restore marker
        // (HEA-2132). We hold the exclusive lock at this point, so no other process
        // can be writing to the directory concurrently.
        let marker_path = config.data_dir.join(SNAPSHOT_RESTORE_MARKER);
        match fs.read(&marker_path) {
            Ok(content) => {
                let snapshot_id = String::from_utf8(content).unwrap_or_default();
                return Err(StorageError::TornSnapshotRestore {
                    marker_path,
                    snapshot_id,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(StorageError::Io(e)),
        }

        // Load key registry (host key from env/auto-gen)
        let key_registry = Arc::new(KeyRegistry::load_with_fs(
            &config.data_dir,
            Arc::clone(&fs),
            config.dev_mode,
        )?);

        // System realm: a fixed UUID used for file-level encryption keys.
        // Kept stable across restarts so SST/WAL files remain decryptable.
        let system_realm = RealmId::new(
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").map_err(|_| {
                StorageError::Crypto {
                    reason: "failed to parse system realm UUID".to_string(),
                }
            })?,
        );

        // Ensure the system realm has a KEK for file encryption
        key_registry.ensure_kek_for_realm(&system_realm)?;
        let system_kek = key_registry
            .get_kek_for_realm(&system_realm)
            .ok_or_else(|| StorageError::Crypto {
                reason: "failed to get system KEK".to_string(),
            })?;
        let system_kek_id = key_registry.kek_id_for_realm(&system_realm);

        // Open WAL with encryption
        let wal_path = config.data_dir.join("hearth.wal");
        let mut wal = Wal::open_with_fs(
            &wal_path,
            config.wal_config,
            Arc::clone(&fs),
            &system_kek,
            system_kek_id,
        )?;
        let memtable = Memtable::new(config.memtable_config);

        let entries = wal.read_all()?;
        for entry in &entries {
            memtable.apply_wal_entry(entry)?;
        }

        // Discover existing SST files, sorted newest-first by filename
        let mut sst_paths: Vec<(PathBuf, u64)> = fs
            .read_dir(&config.data_dir)?
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "sst"))
            .filter_map(|p| {
                let num = p.file_stem()?.to_str()?.parse::<u64>().ok()?;
                Some((p, num))
            })
            .collect();
        sst_paths.sort_by_key(|(_, num)| std::cmp::Reverse(*num)); // newest first

        // Shared, byte-bounded decrypted-block cache for all v3 SST readers.
        let block_cache = Arc::new(crate::storage::block_cache::BlockCache::new(
            config.block_cache_bytes,
        ));

        let mut sst_readers = Vec::new();
        let mut max_sst_num: u64 = 0;
        for (path, sst_num) in &sst_paths {
            // Read encryption header and extract KEK ID
            let (kek_id, enc_header) = sst::read_encryption_header(path, &*fs)?;
            // Look up the KEK from the registry by matching kek_id bytes to a realm
            let realm_for_kek = RealmId::new(uuid::Uuid::from_bytes(kek_id));
            let kek = if let Some(k) = key_registry.get_kek_for_realm(&realm_for_kek) {
                k
            } else if config.allow_missing_keks {
                tracing::warn!(
                    path = %path.display(),
                    realm = %realm_for_kek,
                    "SST file skipped: KEK not found in registry"
                );
                continue;
            } else {
                return Err(StorageError::Crypto {
                    reason: format!(
                        "SST {} references KEK for realm {} but no KEK is registered; refusing to start",
                        path.display(),
                        realm_for_kek
                    ),
                });
            };
            let dek = match encryption::unwrap_dek(&enc_header, &kek) {
                Ok(d) => d,
                Err(e) => {
                    if config.allow_missing_keks {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "SST file skipped: DEK unwrapping failed"
                        );
                        continue;
                    }
                    return Err(StorageError::Crypto {
                        reason: format!("SST {} DEK unwrapping failed: {}", path.display(), e),
                    });
                }
            };
            let reader =
                SstReader::open_with_fs(path, &*fs, *sst_num, &dek, Arc::clone(&block_cache))
                    .map_err(|e| StorageError::Crypto {
                        reason: format!("SST {} failed to open reader: {}", path.display(), e),
                    })?;
            max_sst_num = max_sst_num.max(*sst_num);
            sst_readers.push(reader);
        }

        let hot_tier = HotTier::new(config.tiered_config);

        // Arc-wrap the shared state needed by both the engine and the WAL's
        // pre-rotate flush callback.
        let active_memtable = Arc::new(memtable);
        record_sst_file_count(sst_readers.len());
        let sst_readers = Arc::new(ArcSwap::from_pointee(sst_readers));
        let flush_lock = Arc::new(Mutex::new(()));
        let sst_counter = Arc::new(std::sync::atomic::AtomicU64::new(max_sst_num + 1));

        // Inject a pre-rotate callback so the WAL flushes the memtable to SST
        // before truncating. Without this, a kill -9 between truncation and the
        // next regular flush would lose all writes since the last SST flush.
        {
            let cb_memtable = Arc::clone(&active_memtable);
            let cb_sst_readers = Arc::clone(&sst_readers);
            let cb_flush_lock = Arc::clone(&flush_lock);
            let cb_sst_counter = Arc::clone(&sst_counter);
            let cb_data_dir = config.data_dir.clone();
            let cb_key_registry = Arc::clone(&key_registry);
            let cb_system_realm = system_realm.clone();
            let cb_fs = Arc::clone(&fs);
            let cb_block_cache = Arc::clone(&block_cache);

            wal.set_pre_rotate_fn(move || {
                let Ok(_guard) = cb_flush_lock.lock() else {
                    return Err(StorageError::Io(std::io::Error::other(
                        "flush mutex poisoned",
                    )));
                };
                // Atomic freeze: snapshot + SST write/register + reset all happen
                // under the memtable write lock, so a write racing with this
                // rotation flush is never silently dropped.
                cb_memtable.flush_streaming(|map| {
                    let sst_num = cb_sst_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let sst_path = cb_data_dir.join(format!("{sst_num:06}.sst"));
                    let system_kek = cb_key_registry
                        .get_kek_for_realm(&cb_system_realm)
                        .ok_or_else(|| StorageError::Crypto {
                            reason: "system KEK not found during WAL rotation flush".to_string(),
                        })?;
                    let system_kek_id = cb_key_registry.kek_id_for_realm(&cb_system_realm);
                    let dek = encryption::generate_dek()?;
                    let enc_header = encryption::wrap_dek(&dek, &system_kek, system_kek_id)?;
                    // Stream entries straight off the parked skiplist with no copy
                    // (HEA-1908): a crossbeam_skiplist Entry guard's key/value refs
                    // are only valid while the guard is alive, so push them into the
                    // writer's `sink` per entry rather than materialising the whole
                    // map into an owned Vec first. This callback is the easy-to-miss
                    // second flush path (it was missed in HEA-1937 F1).
                    SstWriter::write_sst_with_fs(
                        &sst_path,
                        |sink| {
                            for e in map.iter() {
                                sink(e.key(), e.value())?;
                            }
                            Ok(())
                        },
                        map.len(),
                        &*cb_fs,
                        sst_num,
                        &dek,
                        &enc_header,
                    )?;
                    // Rebuild SST reader list, inserting the new file
                    let mut all_sst_paths: Vec<(PathBuf, u64)> = cb_fs
                        .read_dir(&cb_data_dir)?
                        .into_iter()
                        .filter(|p| p.extension().is_some_and(|ext| ext == "sst"))
                        .filter_map(|p| {
                            let num = p.file_stem()?.to_str()?.parse::<u64>().ok()?;
                            Some((p, num))
                        })
                        .collect();
                    all_sst_paths.sort_by_key(|(_, num)| std::cmp::Reverse(*num));
                    let mut rebuilt = Vec::new();
                    for (path, n) in &all_sst_paths {
                        let (kek_id, enc_hdr) = match sst::read_encryption_header(path, &*cb_fs) {
                            Ok(h) => h,
                            Err(_) => continue,
                        };
                        let realm_for_kek = RealmId::new(uuid::Uuid::from_bytes(kek_id));
                        let kek = match cb_key_registry.get_kek_for_realm(&realm_for_kek) {
                            Some(k) => k,
                            None => continue,
                        };
                        let file_dek = match encryption::unwrap_dek(&enc_hdr, &kek) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        if let Ok(reader) = SstReader::open_with_fs(
                            path,
                            &*cb_fs,
                            *n,
                            &file_dek,
                            Arc::clone(&cb_block_cache),
                        ) {
                            rebuilt.push(reader);
                        }
                    }
                    record_sst_file_count(rebuilt.len());
                    cb_sst_readers.store(Arc::new(rebuilt));
                    Ok(())
                })?;
                Ok(())
            });
        }

        Ok(Self {
            wal,
            active_memtable,
            sst_readers,
            hot_tier,
            data_dir: config.data_dir,
            flush_lock,
            compaction_lock: Mutex::new(()),
            put_if_absent_lock: Mutex::new(()),
            sst_counter,
            fs,
            key_registry,
            system_realm,
            compaction: config.compaction,
            compaction_notify: Arc::new(tokio::sync::Notify::new()),
            compaction_records_written: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            block_cache,
            _process_lock: dir_lock_guard,
            _dir_lock: lock_file,
        })
    }

    /// Flushes the memtable to a new SST file and clears it.
    ///
    /// The in-memory swap (park the full map, install a fresh empty one) happens
    /// under the memtable's write lock; the SST write/registration then streams
    /// off the parked map *outside* that lock (see
    /// [`Memtable::flush_streaming`]). A `put`/`put_batch` racing with a flush is
    /// either captured in the SST or kept in the fresh map, never silently
    /// dropped, and stays readable from the parked map meanwhile — but writers
    /// are no longer blocked for the SST encrypt+`fsync`. The outer `flush_lock`
    /// still serializes flushes against each other so SST numbering can't collide
    /// and only one map is ever parked for flushing at a time.
    fn trigger_flush(&self) -> Result<(), StorageError> {
        let Ok(_guard) = self.flush_lock.lock() else {
            return Err(StorageError::Io(std::io::Error::other(
                "flush mutex poisoned",
            )));
        };

        self.active_memtable.flush_streaming(|map| {
            // Generate sequential SST filename
            let sst_num = self
                .sst_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let sst_path = self.data_dir.join(format!("{sst_num:06}.sst"));

            // Generate per-file DEK and wrap with system realm KEK
            let system_kek = self
                .key_registry
                .get_kek_for_realm(&self.system_realm)
                .ok_or_else(|| StorageError::Crypto {
                    reason: "system KEK not found".to_string(),
                })?;
            let system_kek_id = self.key_registry.kek_id_for_realm(&self.system_realm);
            let dek = encryption::generate_dek()?;
            let enc_header = encryption::wrap_dek(&dek, &system_kek, system_kek_id)?;

            // Stream entries straight off the parked skiplist with no copy: each
            // crossbeam_skiplist Entry guard's key/value refs are only valid while
            // the guard is alive, so we push them into the writer's `sink` per
            // entry rather than materialising an owned Vec of the whole map first
            // (HEA-1908). The parked map is immutable during the flush, so
            // `map.len()` is a stable, exact bloom-filter size.
            SstWriter::write_sst_with_fs(
                &sst_path,
                |sink| {
                    for e in map.iter() {
                        sink(e.key(), e.value())?;
                    }
                    Ok(())
                },
                map.len(),
                &*self.fs,
                sst_num,
                &dek,
                &enc_header,
            )?;

            // Rebuild SST reader list from disk (re-open all files). This
            // registers the new SST *before* the memtable is emptied, so reads
            // never miss a just-flushed key.
            let rebuilt_readers = self.reload_sst_readers()?;
            let live_count = rebuilt_readers.len();
            record_sst_file_count(live_count);
            self.sst_readers.store(Arc::new(rebuilt_readers));

            // Count trigger (HEA-1885): once the live SST count reaches the
            // configured threshold, hand a *partial* (size-tiered) compaction to
            // the background task. The merge itself never runs here on the flush
            // path — `notify_one` is a cheap flag-set, safe outside a runtime.
            if self.compaction.max_sst_count > 0 && live_count >= self.compaction.max_sst_count {
                self.compaction_notify.notify_one();
            }

            Ok(())
        })?;

        Ok(())
    }

    /// Re-opens every `*.sst` file in the data directory into a fresh, newest-first
    /// reader list.
    ///
    /// This is the single source of truth for materialising the in-memory reader
    /// Vec from on-disk state. Files are sorted by SST number descending so the
    /// resulting Vec order matches the recency order that recovery
    /// ([`Self::open_with_fs`]) reconstructs — the invariant reads rely on
    /// (newest wins). Individual files that fail to open (missing KEK, corrupt
    /// header) are skipped with a warning rather than aborting the rebuild.
    ///
    /// Callers MUST hold `flush_lock` so the directory scan cannot race a flush
    /// writing a new file.
    fn reload_sst_readers(&self) -> Result<Vec<SstReader>, StorageError> {
        let mut all_sst_paths: Vec<(PathBuf, u64)> = self
            .fs
            .read_dir(&self.data_dir)?
            .into_iter()
            .filter(|p| p.extension().is_some_and(|ext| ext == "sst"))
            .filter_map(|p| {
                let num = p.file_stem()?.to_str()?.parse::<u64>().ok()?;
                Some((p, num))
            })
            .collect();
        all_sst_paths.sort_by_key(|(_, num)| std::cmp::Reverse(*num)); // newest first

        let mut readers = Vec::with_capacity(all_sst_paths.len());
        for (path, sst_num) in &all_sst_paths {
            let (kek_id, enc_header) = match sst::read_encryption_header(path, &*self.fs) {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "SST file skipped: failed to read encryption header"
                    );
                    continue;
                }
            };
            let realm_for_kek = RealmId::new(uuid::Uuid::from_bytes(kek_id));
            let kek = match self.key_registry.get_kek_for_realm(&realm_for_kek) {
                Some(k) => k,
                None => {
                    tracing::warn!(
                        path = %path.display(),
                        realm = %realm_for_kek,
                        "SST file skipped: KEK not found"
                    );
                    continue;
                }
            };
            let dek = match encryption::unwrap_dek(&enc_header, &kek) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "SST file skipped: DEK unwrapping failed"
                    );
                    continue;
                }
            };
            match SstReader::open_with_fs(
                path,
                &*self.fs,
                *sst_num,
                &dek,
                Arc::clone(&self.block_cache),
            ) {
                Ok(reader) => readers.push(reader),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "SST file skipped: failed to open reader"
                    );
                }
            }
        }
        Ok(readers)
    }

    /// Returns a handle the server wiring uses to await partial-compaction
    /// requests raised by the count trigger (HEA-1885). The background
    /// compaction task waits on this alongside its periodic timer.
    pub fn compaction_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.compaction_notify)
    }

    /// Cumulative number of records written out by compaction merges since the
    /// engine opened — the numerator of write amplification (HEA-1881 lever 1).
    ///
    /// Used by the write-amplification regression test to prove size-tiered
    /// partial compaction rewrites `O(N log N)` records under a bulk import
    /// rather than the `O(N²)` a naive full-merge-on-trigger would.
    #[cfg(test)]
    pub(crate) fn compaction_records_written(&self) -> u64 {
        self.compaction_records_written
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns the cumulative number of WAL `sync_all` calls completed since
    /// this engine was opened.
    ///
    /// Dividing this by the number of write operations gives the
    /// fsyncs-per-write ratio under group commit.  Used by the
    /// saturation-throughput benchmark (`examples/saturation_throughput.rs`).
    pub fn wal_sync_count(&self) -> u64 {
        self.wal.sync_count()
    }

    /// Returns a snapshot of the WAL group-commit phase timings (HEA-1959).
    ///
    /// Lets the saturation benchmark decompose the commit cycle into its
    /// device-bound (`fsync`) and batch-size-scaling (encrypt/write/signal)
    /// components.
    pub fn wal_commit_profile(&self) -> crate::storage::wal::CommitProfileSnapshot {
        self.wal.commit_profile()
    }
}

impl EmbeddedStorageEngine {
    /// Compacts all current SST files into a single output SST.
    ///
    /// Returns the number of SSTs compacted (0 if the count is below
    /// `min_sst_count`). Writes to a temporary path and atomically
    /// renames for crash safety.
    ///
    /// Serializes against other compactions via the compaction lock, but holds
    /// `flush_lock` (which writers contend on) only for the brief commit phase —
    /// the merge I/O runs off it, so writers are not stalled for the merge's
    /// O(total-data) duration (HEA-1931). Callers in async contexts should wrap
    /// this in `spawn_blocking` to avoid blocking Tokio worker threads.
    ///
    /// # Crash Safety
    ///
    /// The compacted SST is written to a `.sst.tmp` path and atomically
    /// renamed to `{num:06}.sst`. If the process crashes **after** the
    /// rename but **before** old SST files are deleted, both old and new
    /// SSTs coexist on disk. Recovery handles this correctly — the newer
    /// SST (higher number) takes priority for duplicate keys. The leaked
    /// old files are harmless orphans cleaned up by the next compaction.
    pub fn compact_ssts(&self, min_sst_count: usize) -> Result<usize, StorageError> {
        // Serialize against other compactions for the whole operation, but hold
        // `flush_lock` only for two brief phases — the snapshot+number allocation
        // and the commit. The O(total-data) merge I/O between them runs off
        // `flush_lock` so it never stalls writers (HEA-1931).
        let Ok(_compaction_guard) = self.compaction_lock.lock() else {
            return Err(StorageError::Io(std::io::Error::other(
                "compaction mutex poisoned",
            )));
        };

        // Snapshot the reader set and allocate the output number under `flush_lock`
        // so both are ordered against every flush (HEA-1937 F1). The `Arc` pins the
        // input readers' mmaps alive for the whole merge even if a later flush swaps
        // the list; flushes only *add* newer SSTs (higher numbers), never delete or
        // reorder the inputs we merge here, and `compaction_lock` guarantees no other
        // compaction can. Allocating `sst_num` here — while no flush can be
        // mid-`fetch_add` — guarantees every subsequent flush is numbered *above* the
        // merge output, so newest-first resolution never places the (older) merged
        // data ahead of a concurrently flushed SST. The lock is released before the
        // O(total-data) merge below. Lock order: `compaction_lock` → `flush_lock`.
        let (sst_readers, sst_num) = {
            let Ok(_alloc_guard) = self.flush_lock.lock() else {
                return Err(StorageError::Io(std::io::Error::other(
                    "flush mutex poisoned",
                )));
            };
            let readers = self.sst_readers.load_full();
            if readers.len() < min_sst_count {
                return Ok(0);
            }
            let sst_num = self
                .sst_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (readers, sst_num)
        };
        let input_count = sst_readers.len();

        // Collect old SST numbers for file deletion after successful compaction
        let old_sst_nums: Vec<u64> = sst_readers.iter().map(|r| r.sst_number()).collect();

        // Inputs in oldest-to-newest order (sst_readers is newest-first)
        let readers_oldest_first: Vec<&SstReader> = sst_readers.iter().rev().collect();

        // DEK + encryption header (same pattern as trigger_flush)
        let system_kek = self
            .key_registry
            .get_kek_for_realm(&self.system_realm)
            .ok_or_else(|| StorageError::Crypto {
                reason: "system KEK not found".to_string(),
            })?;
        let system_kek_id = self.key_registry.kek_id_for_realm(&self.system_realm);
        let dek = encryption::generate_dek()?;
        let enc_header = encryption::wrap_dek(&dek, &system_kek, system_kek_id)?;

        let tmp_path = self.data_dir.join(format!("{sst_num:06}.sst.tmp"));
        let final_path = self.data_dir.join(format!("{sst_num:06}.sst"));

        // Write to temp path for crash safety — the expensive merge, OFF the
        // flush path.
        sst::compact_with_fs(
            &readers_oldest_first,
            &tmp_path,
            &*self.fs,
            sst_num,
            &dek,
            &enc_header,
        )?;

        // Release the input-reader snapshot before the commit phase (the reload
        // there re-reads from disk); everything needed for the commit is already
        // captured by number.
        drop(sst_readers);

        // --- Commit phase: hold `flush_lock` only for these metadata ops ---
        let Ok(_guard) = self.flush_lock.lock() else {
            return Err(StorageError::Io(std::io::Error::other(
                "flush mutex poisoned",
            )));
        };

        // Atomic rename — crash-safe: partial writes leave a .tmp, not a corrupt .sst
        self.fs.rename(&tmp_path, &final_path)?;
        // Fsync the data directory so the rename (the new inode becoming the
        // canonical `.sst`) is durable. Without this a power loss before the
        // directory update commits could resolve the tmp/old entries on restart
        // (HEA-1855).
        self.fs.sync_dir(&self.data_dir)?;

        // Delete the merged-away input SSTs. A failure here is FATAL to the
        // commit. This is a full merge, so the output dropped every tombstone
        // (`compact_with_fs`); an input that survives still carries its pre-delete
        // value while the merged output no longer carries the shadowing tombstone,
        // so a lookup would fall through to the orphan and resurrect a deleted key
        // (HEA-1982). Rather than warn-and-continue — which then lets
        // `reload_sst_readers()` re-open the orphan — abort and leave the in-memory
        // reader set untouched, so the still-present inputs keep shadowing deleted
        // keys until a retry succeeds. Only the merged inputs are removed; any SST
        // a flush added *during* the merge (higher number, not in `old_sst_nums`)
        // is left untouched.
        //
        // Unlink OLDEST-first (`old_sst_nums` is newest-first, so iterate reversed):
        // a value-bearing SST is always removed *before* the newer tombstone that
        // shadows it. Any partial prefix of oldest-first unlinks — whether a mid-loop
        // error aborts the commit or a crash lands mid-loop — can only leave *more*
        // tombstones than values on disk, never a value orphaned ahead of its
        // shadowing tombstone, so the next reload can never resurrect a deleted key.
        // Newest-first would delete the tombstone first and reopen this exact bug on
        // a partial failure (HEA-1986). A `NotFound` means a prior aborted attempt
        // already removed this input; treat it as success so a retry converges.
        for old_num in old_sst_nums.iter().rev() {
            let old_path = self.data_dir.join(format!("{old_num:06}.sst"));
            match self.fs.remove_file(&old_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(StorageError::Io(std::io::Error::new(
                        e.kind(),
                        format!(
                            "compaction: failed to unlink merged-away SST {}: {e}; aborting \
                             commit to avoid resurrecting a deleted key (HEA-1982)",
                            old_path.display()
                        ),
                    )));
                }
            }
        }
        // Make the unlinks durable before the tombstone-free output becomes the
        // sole on-disk authority, shrinking the crash window in which a surviving
        // orphan could still be observed (HEA-1855 / HEA-1857).
        self.fs.sync_dir(&self.data_dir)?;

        // Rematerialise the reader list from disk rather than assuming the merged
        // output is the only live SST: a flush that landed while the merge ran
        // (off `flush_lock`) added a newer SST that MUST survive. Reload gives the
        // correct newest-first order (new flush > merged output > nothing), so no
        // just-flushed key is dropped.
        let rebuilt = self.reload_sst_readers()?;
        record_sst_file_count(rebuilt.len());
        if let Some(merged) = rebuilt.iter().find(|r| r.sst_number() == sst_num) {
            self.compaction_records_written.fetch_add(
                u64::from(merged.entry_count()),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        self.sst_readers.store(Arc::new(rebuilt));

        Ok(input_count)
    }

    /// Runs one **partial (size-tiered)** compaction, bounding cold-read SST
    /// fan-out without the quadratic write amplification of a full merge
    /// (HEA-1885, the CTO-required shape for HEA-1881 lever 1).
    ///
    /// Selects a single *contiguous, same-size-tier* run of at least
    /// [`CompactionConfig::merge_min`] SSTs (see [`select_partial_run`]) and
    /// merges only those into one output, leaving every other SST untouched.
    /// Returns the number of SSTs merged (0 if no tier has enough files yet).
    ///
    /// # Correctness — recency ordering
    ///
    /// Reads resolve by reader-Vec order (newest first) and recovery rebuilds
    /// that Vec by sorting files by SST number descending. To keep the two in
    /// lock-step, the merged output reuses the **highest number in the run** and
    /// its file path. Because the run is contiguous in the number-sorted Vec, no
    /// surviving SST has a number inside the run's band, so splicing the merged
    /// output in at that number preserves the strictly-descending invariant —
    /// across restarts as well as in memory.
    ///
    /// # Correctness — tombstones
    ///
    /// Tombstones are dropped only when the run reaches the *oldest* SST; a merge
    /// that leaves older SSTs live keeps tombstones so a delete cannot be
    /// resurrected from an un-merged older file.
    ///
    /// # Crash safety
    ///
    /// Same contract as [`Self::compact_ssts`]: the merge is written to a `.tmp`
    /// path and atomically renamed over the run's newest file; a crash before the
    /// rename leaves the original files intact. A *runtime* unlink failure on an
    /// older run member is fatal to the commit (see the commit phase), so a
    /// tombstone-dropping merge can never leave a surviving orphan behind a
    /// tombstone-free output. A crash landing between the rename and the unlinks
    /// can still leave such an orphan on disk; closing that window durably needs a
    /// compaction manifest (HEA-1857).
    ///
    /// Serializes against other compactions via the compaction lock; `flush_lock`
    /// (which writers contend on) is held only for the brief commit phase, never
    /// across the merge I/O (HEA-1931). Like [`Self::compact_ssts`], async callers
    /// should wrap it in `spawn_blocking`.
    pub fn compact_partial(&self) -> Result<usize, StorageError> {
        let merge_min = self.compaction.merge_min.max(2);

        // Serialize against other compactions for the whole operation. `flush_lock`
        // is deliberately NOT taken here — the O(tier-data) merge I/O below runs
        // off it so writers are never stalled for the merge's duration, only for
        // the brief commit phase at the end (HEA-1931).
        let Ok(_compaction_guard) = self.compaction_lock.lock() else {
            return Err(StorageError::Io(std::io::Error::other(
                "compaction mutex poisoned",
            )));
        };

        // Snapshot + select the run. The `Arc` pins the input readers' mmaps
        // alive for the whole merge even if a concurrent flush swaps the list.
        // Concurrent flushes only add *newer* SSTs (prepended at the newest end),
        // never touch our run members nor add anything older, so `target_num`,
        // `other_nums`, and `drop_tombstones` (the run still being the oldest)
        // stay valid through the merge; `compaction_lock` keeps any other
        // compaction out.
        let sst_readers = self.sst_readers.load();
        let Some((start, end)) = select_partial_run(&sst_readers, merge_min) else {
            return Ok(0);
        };

        // `sst_readers` is newest-first; index `start` is the newest run member
        // (highest number) and `end` the oldest. The merged output reuses the
        // newest number/path so it splices back at the correct recency slot.
        let run = &sst_readers[start..=end];
        let target_num = run[0].sst_number();
        let other_nums: Vec<u64> = run[1..].iter().map(SstReader::sst_number).collect();
        let input_count = run.len();

        // Merge inputs oldest-to-newest (newest value wins, matching read order).
        let inputs_oldest_first: Vec<&SstReader> = run.iter().rev().collect();

        // Tombstones may only be discarded when the oldest SST is part of the run;
        // otherwise an older, un-merged SST could resurrect a deleted key.
        let drop_tombstones = end == sst_readers.len() - 1;

        // DEK + encryption header (same pattern as `compact_ssts`).
        let system_kek = self
            .key_registry
            .get_kek_for_realm(&self.system_realm)
            .ok_or_else(|| StorageError::Crypto {
                reason: "system KEK not found".to_string(),
            })?;
        let system_kek_id = self.key_registry.kek_id_for_realm(&self.system_realm);
        let dek = encryption::generate_dek()?;
        let enc_header = encryption::wrap_dek(&dek, &system_kek, system_kek_id)?;

        let tmp_path = self
            .data_dir
            .join(format!("{target_num:06}.sst.partial.tmp"));
        let final_path = self.data_dir.join(format!("{target_num:06}.sst"));

        sst::compact_with_fs_opts(
            &inputs_oldest_first,
            &tmp_path,
            &*self.fs,
            target_num,
            &dek,
            &enc_header,
            drop_tombstones,
        )?;

        // Drop the load guard before the commit phase (reload re-reads from
        // disk). Everything needed for the splice is already captured.
        drop(sst_readers);

        // --- Commit phase: hold `flush_lock` only for these metadata ops, so a
        // writer contends with compaction for the rename+fsync+reload, never for
        // the merge I/O above (HEA-1931). ---
        let Ok(_guard) = self.flush_lock.lock() else {
            return Err(StorageError::Io(std::io::Error::other(
                "flush mutex poisoned",
            )));
        };

        // Atomically replace the run's newest file with the merged output, then
        // fsync the directory so the rename is durable (HEA-1855).
        self.fs.rename(&tmp_path, &final_path)?;
        self.fs.sync_dir(&self.data_dir)?;

        // Delete the other (older) run members. A failure here is FATAL to the
        // commit. When `drop_tombstones` was set (the run reached the oldest SST)
        // the merged output carries no delete markers, so an older run member that
        // survives would resurrect a deleted key on the next reload (HEA-1982);
        // warn-and-continue then let `reload_sst_readers()` re-open that orphan.
        // Aborting instead leaves the pre-commit reader set in place, so the
        // original (tombstone-bearing) run members keep shadowing deleted keys
        // until a retry succeeds.
        //
        // Unlink OLDEST-first (`other_nums` is newest-first, so iterate reversed):
        // a value-bearing member is always removed before the newer tombstone that
        // shadows it, so any partial prefix — mid-loop error or crash — can only
        // leave more tombstones than values on disk, never a resurrectable orphan
        // (HEA-1986). A `NotFound` means a prior aborted attempt already removed the
        // member; treat it as success so a retry converges.
        for old_num in other_nums.iter().rev() {
            let old_path = self.data_dir.join(format!("{old_num:06}.sst"));
            match self.fs.remove_file(&old_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(StorageError::Io(std::io::Error::new(
                        e.kind(),
                        format!(
                            "partial compaction: failed to unlink merged-in SST {}: {e}; \
                             aborting commit to avoid resurrecting a deleted key (HEA-1982)",
                            old_path.display()
                        ),
                    )));
                }
            }
        }
        // Make the unlinks durable before the merged output becomes the sole
        // authority for the run's key band (HEA-1855 / HEA-1857).
        self.fs.sync_dir(&self.data_dir)?;

        // Rematerialise the reader list from disk (newest-first). The merged file
        // now sits at `target_num`, exactly where the run's newest member was.
        let rebuilt = self.reload_sst_readers()?;
        let live_count = rebuilt.len();
        record_sst_file_count(live_count);
        // Attribute the merged output's record count to write amplification. The
        // output reused `target_num`, so it is the reader now sitting at that
        // number (see the recency-ordering contract above).
        if let Some(merged) = rebuilt.iter().find(|r| r.sst_number() == target_num) {
            self.compaction_records_written.fetch_add(
                u64::from(merged.entry_count()),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        self.sst_readers.store(Arc::new(rebuilt));

        Ok(input_count)
    }
}

/// Selects a contiguous run of same-size-tier SSTs to merge, or `None` if no tier
/// has accumulated `merge_min` files yet (HEA-1885).
///
/// `readers` is newest-first (index 0 = newest, highest number). A "tier" is a
/// maximal contiguous span whose largest member is within [`SIZE_TIER_RATIO`] of
/// its smallest (bucketing by entry count, a proxy for on-disk size). The first
/// (newest) span reaching `merge_min` files is returned as an inclusive
/// `(start, end)` index range. Restricting to a *contiguous* span guarantees the
/// merged output's number band contains no surviving SST, which the splice in
/// [`EmbeddedStorageEngine::compact_partial`] relies on for recovery-consistent
/// ordering.
fn select_partial_run(readers: &[SstReader], merge_min: usize) -> Option<(usize, usize)> {
    /// Size spread (max/min entry count) tolerated within one tier. A merged SST
    /// (~`merge_min`× the entries of a flush) sits in the next tier up, so it is
    /// never re-merged with fresh flushes — this is what keeps write
    /// amplification `O(log N)` instead of quadratic.
    const SIZE_TIER_RATIO: f64 = 2.0;

    let n = readers.len();
    let mut i = 0;
    while i < n {
        let base = f64::from(readers[i].entry_count().max(1));
        let mut lo = base;
        let mut hi = base;
        let mut j = i;
        while j + 1 < n {
            let next = f64::from(readers[j + 1].entry_count().max(1));
            let nlo = lo.min(next);
            let nhi = hi.max(next);
            if nhi / nlo <= SIZE_TIER_RATIO {
                lo = nlo;
                hi = nhi;
                j += 1;
            } else {
                break;
            }
        }
        if j - i + 1 >= merge_min {
            return Some((i, j));
        }
        i = j + 1;
    }
    None
}

impl StorageEngine for EmbeddedStorageEngine {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let metrics = crate::metrics::metrics();

        // 1. Hot tier (lock-free, O(1))
        // HotTier::get returns Arc<[u8]> to avoid a heap clone inside the hot tier.
        // We convert to Vec<u8> here at the StorageEngine trait boundary.
        //
        // The ONLY instrumentation on the hot-tier-hit path is a single
        // lock-free atomic counter increment (HEA-1869). The hit is
        // intentionally *not* timed: an `Instant::now()` here would be a clock
        // read on the zero-syscall hot path and regress `bench-gate`. Hot-hit
        // latency is covered by the `storage_hot_tier` bench gate instead.
        if let Some(arc_val) = self.hot_tier.get(realm_id, key) {
            metrics.inc_get_hot_hit();
            return Ok(Some(arc_val.to_vec()));
        }

        // Fall-through path — off the hot path. Time it and attribute the
        // latency and SST-probe count to the tier that resolves the read.
        let started = std::time::Instant::now();

        // 2. Active memtable — O(log n) BTreeMap lookup.
        // `get_entry` distinguishes a tombstone from an absent key so we can
        // stop searching deeper layers on a delete. This MUST NOT fall back to
        // an `iter_realm` linear scan: at 500k entries in a single realm that
        // turned every point lookup (e.g. a user-detail page) into an O(N)
        // clone-and-scan — seconds per `get` (HEA-1614).
        match self.active_memtable.get_entry(realm_id, key) {
            Some(MemtableValue::Data(data)) => {
                // Promote to hot tier on memtable hit
                self.hot_tier.promote(realm_id, key, &data);
                metrics.record_get_fallthrough("memtable_hit", started.elapsed(), 0);
                return Ok(Some(data));
            }
            Some(MemtableValue::Tombstone) => {
                // Key was deleted — stop searching deeper layers
                metrics.record_get_fallthrough("miss", started.elapsed(), 0);
                return Ok(None);
            }
            None => {}
        }

        // 3. SST files newest-to-oldest (binary search)
        let sst_readers = self.sst_readers.load();
        let mut ssts_probed: u64 = 0;
        for reader in sst_readers.iter() {
            ssts_probed += 1;
            if let Some(value) = reader.get(realm_id, key)? {
                match value {
                    MemtableValue::Data(data) => {
                        // Cold hit — promote to hot tier
                        self.hot_tier.promote(realm_id, key, &data);
                        metrics.record_get_fallthrough("sst_hit", started.elapsed(), ssts_probed);
                        return Ok(Some(data));
                    }
                    MemtableValue::Tombstone => {
                        // Tombstone in SST — stop searching older SSTs
                        metrics.record_get_fallthrough("miss", started.elapsed(), ssts_probed);
                        return Ok(None);
                    }
                }
            }
        }

        metrics.record_get_fallthrough("miss", started.elapsed(), ssts_probed);
        Ok(None)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let _timer = crate::metrics::metrics()
            .storage_operation_duration_seconds
            .with_label_values(&["put"])
            .start_timer();

        // 1. WAL append + fsync
        let entry = WalEntry {
            timestamp: crate::core::Timestamp::now(),
            realm_id: realm_id.clone(),
            operation: WalOperation::Put,
            key: key.to_vec(),
            value: value.to_vec(),
        };
        self.wal
            .append_with_pre_rotate(&entry, || self.trigger_flush())?;

        // 2. Memtable insert
        self.active_memtable.put(realm_id, key, value)?;

        // 3. Hot tier invalidate (stale cached value)
        self.hot_tier.invalidate(realm_id, key);

        // 4. Check flush threshold
        if self.active_memtable.should_flush() {
            self.trigger_flush()?;
        }

        Ok(())
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        let _timer = crate::metrics::metrics()
            .storage_operation_duration_seconds
            .with_label_values(&["delete"])
            .start_timer();

        // 1. WAL append + fsync
        let entry = WalEntry {
            timestamp: crate::core::Timestamp::now(),
            realm_id: realm_id.clone(),
            operation: WalOperation::Delete,
            key: key.to_vec(),
            value: vec![],
        };
        self.wal
            .append_with_pre_rotate(&entry, || self.trigger_flush())?;

        // 2. Memtable tombstone
        self.active_memtable.delete(realm_id, key)?;

        // 3. Hot tier invalidate
        self.hot_tier.invalidate(realm_id, key);

        // 4. Check flush threshold
        if self.active_memtable.should_flush() {
            self.trigger_flush()?;
        }

        Ok(())
    }

    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        // Trivial case: the caller supplied no work. Treat as a no-op so
        // higher layers don't need to guard against empty batches.
        if entries.is_empty() {
            return Ok(());
        }

        let _timer = crate::metrics::metrics()
            .storage_operation_duration_seconds
            .with_label_values(&["put_batch"])
            .start_timer();

        // 1. Build and append a single WAL record containing all entries.
        //    The existing `[len][payload][crc32]` framing + `read_all()`'s
        //    "stop on bad CRC/truncation" recovery policy together give us
        //    all-or-nothing durability for free.
        let sub_entries: Vec<BatchEntry> = entries
            .iter()
            .map(|(k, v)| BatchEntry {
                operation: WalOperation::Put,
                key: k.clone(),
                value: v.clone(),
            })
            .collect();
        let payload = crate::storage::wal::encode_batch_payload(&sub_entries)?;
        let wal_entry = WalEntry {
            timestamp: crate::core::Timestamp::now(),
            realm_id: realm_id.clone(),
            operation: WalOperation::Batch,
            key: Vec::new(),
            value: payload,
        };
        self.wal
            .append_with_pre_rotate(&wal_entry, || self.trigger_flush())?;

        // 2. Apply all sub-entries to the in-memory state. The memtable update
        //    is done in a single copy-on-write cycle (one map clone for the
        //    whole batch, not one per entry) so bulk loads stay O(N), then we
        //    invalidate any cached reads. If a failure occurs here (e.g.,
        //    memtable mutex poisoned), the WAL record is already durable;
        //    recovery on the next open replays the batch in full.
        self.active_memtable.put_batch(realm_id, entries)?;
        for (key, _value) in entries {
            self.hot_tier.invalidate(realm_id, key);
        }

        // 3. Single flush check at the tail — the batch may have pushed us
        //    over the threshold, but we don't need to check per-entry.
        if self.active_memtable.should_flush() {
            self.trigger_flush()?;
        }

        Ok(())
    }

    // ── Split-commit API (HEA-1948) ──────────────────────────────────────────

    fn enqueue_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<StorageDurabilityHandle, StorageError> {
        if entries.is_empty() {
            return Ok(StorageDurabilityHandle(
                StorageDurabilityHandleKind::Immediate,
            ));
        }

        let sub_entries: Vec<BatchEntry> = entries
            .iter()
            .map(|(k, v)| BatchEntry {
                operation: WalOperation::Put,
                key: k.clone(),
                value: v.clone(),
            })
            .collect();
        let payload = crate::storage::wal::encode_batch_payload(&sub_entries)?;
        let wal_entry = WalEntry {
            timestamp: crate::core::Timestamp::now(),
            realm_id: realm_id.clone(),
            operation: WalOperation::Batch,
            key: Vec::new(),
            value: payload,
        };

        let wal_handle = self
            .wal
            .enqueue_entry(&wal_entry, || self.trigger_flush())?;

        match wal_handle {
            WalDurabilityHandle::Immediate => {
                // SyncMode::None path: write already committed, apply to memtable now.
                self.active_memtable.put_batch(realm_id, entries)?;
                for (key, _) in entries {
                    self.hot_tier.invalidate(realm_id, key);
                }
                if self.active_memtable.should_flush() {
                    self.trigger_flush()?;
                }
                Ok(StorageDurabilityHandle(
                    StorageDurabilityHandleKind::Immediate,
                ))
            }
            WalDurabilityHandle::Pending { am_leader, ticket } => {
                // EveryWrite path: WAL entry is queued but not yet fsync'd.
                // Store entries for post-durability memtable update in await_batch_durable.
                Ok(StorageDurabilityHandle(
                    StorageDurabilityHandleKind::Pending(PendingBatchHandle {
                        am_leader,
                        ticket,
                        realm_id: realm_id.clone(),
                        entries: entries.to_vec(),
                    }),
                ))
            }
        }
    }

    fn await_batch_durable(&self, handle: StorageDurabilityHandle) -> Result<(), StorageError> {
        let pending = match handle.0 {
            StorageDurabilityHandleKind::Immediate => return Ok(()),
            StorageDurabilityHandleKind::Pending(p) => p,
        };

        // Run the group-commit leader loop (or wait as a follower) until the
        // WAL entry is covered by a sync_all.
        let wal_result = self.wal.await_entry_durable(
            WalDurabilityHandle::Pending {
                am_leader: pending.am_leader,
                ticket: pending.ticket,
            },
            || self.trigger_flush(),
        );

        // Apply entries to the memtable only after confirmed durability. On WAL
        // failure we skip the memtable update; the WAL is fenced after a write
        // fault, so callers that retry will see the fence error. On the next
        // open, WAL replay restores the memtable from the last successfully
        // committed record.
        if wal_result.is_ok() {
            self.active_memtable
                .put_batch(&pending.realm_id, &pending.entries)?;
            for (key, _) in &pending.entries {
                self.hot_tier.invalidate(&pending.realm_id, key);
            }
            if self.active_memtable.should_flush() {
                self.trigger_flush()?;
            }
        }

        wal_result
    }

    // ── End split-commit API ──────────────────────────────────────────────────

    /// Atomic single-node check-and-write.
    ///
    /// The trait default performs a non-atomic `get` then `put`, which leaves a
    /// TOCTOU window: two concurrent tasks can both observe the key as absent
    /// and both proceed to write. This override serializes the check-and-write
    /// under [`put_if_absent_lock`](Self::put_if_absent_lock) so exactly one
    /// concurrent writer wins for a given key (HEA-1767). The lock is held only
    /// across the in-memory existence check and the `put` — the underlying WAL
    /// append still fsyncs for durability.
    fn put_if_absent(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<bool, StorageError> {
        let Ok(_guard) = self.put_if_absent_lock.lock() else {
            return Err(StorageError::Io(std::io::Error::other(
                "put_if_absent mutex poisoned",
            )));
        };
        if self.get(realm_id, key)?.is_some() {
            return Ok(false);
        }
        self.put(realm_id, key, value)?;
        Ok(true)
    }

    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        // Trivial case: nothing to do.
        if puts.is_empty() && deletes.is_empty() {
            return Ok(());
        }

        let _timer = crate::metrics::metrics()
            .storage_operation_duration_seconds
            .with_label_values(&["write_batch"])
            .start_timer();

        // 1. Build a single WAL batch record containing both puts and deletes.
        //    The existing `[len][payload][crc32]` framing + "stop on bad CRC"
        //    recovery policy gives all-or-nothing durability for the whole set.
        let mut sub_entries: Vec<BatchEntry> = Vec::with_capacity(puts.len() + deletes.len());
        for (k, v) in puts {
            sub_entries.push(BatchEntry {
                operation: WalOperation::Put,
                key: k.clone(),
                value: v.clone(),
            });
        }
        for k in deletes {
            sub_entries.push(BatchEntry {
                operation: WalOperation::Delete,
                key: k.clone(),
                value: Vec::new(),
            });
        }

        let payload = crate::storage::wal::encode_batch_payload(&sub_entries)?;
        let wal_entry = WalEntry {
            timestamp: crate::core::Timestamp::now(),
            realm_id: realm_id.clone(),
            operation: WalOperation::Batch,
            key: Vec::new(),
            value: payload,
        };
        self.wal
            .append_with_pre_rotate(&wal_entry, || self.trigger_flush())?;

        // 2. Apply puts to in-memory state in a single copy-on-write cycle
        //    (one map clone for the whole batch). If this fails after the WAL
        //    write, recovery on next open will replay the full batch.
        self.active_memtable.put_batch(realm_id, puts)?;
        for (key, _value) in puts {
            self.hot_tier.invalidate(realm_id, key);
        }

        // 3. Apply deletes (tombstones) to in-memory state.
        for key in deletes {
            self.active_memtable.delete(realm_id, key)?;
            self.hot_tier.invalidate(realm_id, key);
        }

        // 4. Single flush check at the tail.
        if self.active_memtable.should_flush() {
            self.trigger_flush()?;
        }

        Ok(())
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        let _timer = crate::metrics::metrics()
            .storage_operation_duration_seconds
            .with_label_values(&["scan"])
            .start_timer();

        // Merge results from memtable and all SST files.
        // Use a BTreeMap to deduplicate — memtable entries (newest) win.
        let mut merged: std::collections::BTreeMap<Vec<u8>, MemtableValue> =
            std::collections::BTreeMap::new();

        // SST files oldest-to-newest (reverse of storage order) so newer overwrites older
        let sst_readers = self.sst_readers.load();
        for reader in sst_readers.iter().rev() {
            let entries = reader.range_scan(realm_id, start, end)?;
            for (key, value) in entries {
                merged.insert(key, value);
            }
        }

        // Memtable entries (newest) overwrite SST entries
        let memtable_entries = self.active_memtable.iter_realm(realm_id);
        for (key, value) in memtable_entries {
            if key.as_slice() >= start && key.as_slice() < end {
                merged.insert(key, value);
            }
        }

        // Filter out tombstones and build result
        let result = merged
            .into_iter()
            .filter_map(|(key, value)| match value {
                MemtableValue::Data(data) => Some(ScanEntry { key, value: data }),
                MemtableValue::Tombstone => None,
            })
            .collect();

        Ok(result)
    }

    /// Key-only scan — same merge as [`scan`] but stores only a `bool` (alive
    /// flag) instead of value bytes, then returns surviving keys.
    ///
    /// Avoids allocating value bytes entirely, which is the dominant memory cost
    /// for prefix scans on large realms (e.g. 500k users × 500 B/entry ≈ 250 MB
    /// saved per count query). Used by `count_prefix` and the first phase of
    /// `scan_prefix_paged`.
    fn scan_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<Vec<u8>>, crate::storage::StorageError> {
        let _timer = crate::metrics::metrics()
            .storage_operation_duration_seconds
            .with_label_values(&["scan_keys"])
            .start_timer();

        // BTreeMap<key, is_alive>: true = Data, false = Tombstone.
        // Memtable entries (newest) overwrite SST entries as we insert in
        // oldest-to-newest order.
        let mut merged: std::collections::BTreeMap<Vec<u8>, bool> =
            std::collections::BTreeMap::new();

        let sst_readers = self.sst_readers.load();
        for reader in sst_readers.iter().rev() {
            for (key, alive) in reader.range_scan_keys(realm_id, start, end)? {
                merged.insert(key, alive);
            }
        }

        for (key, alive) in self
            .active_memtable
            .iter_realm_range_keys(realm_id, start, end)
        {
            merged.insert(key, alive);
        }

        Ok(merged
            .into_iter()
            .filter(|(_, alive)| *alive)
            .map(|(k, _)| k)
            .collect())
    }

    /// Enumerates all distinct realm IDs present in the engine.
    ///
    /// Collects realm IDs from both the memtable (active + any map being flushed
    /// to SST) and every live SST file, then returns the union.  Tombstone-only
    /// realms are included — [`StorageEngine::scan`] on an all-tombstone realm
    /// returns empty, making the Phase 1 delete a no-op for that realm.
    ///
    /// This scans every entry in every SST file; it is O(total data size) and
    /// intended only for the cluster snapshot install path, which is a rare
    /// cluster-recovery event (HEA-2131).
    fn list_realms(&self) -> Result<Vec<RealmId>, StorageError> {
        let mut realms = std::collections::BTreeSet::new();

        // Enumerate from the memtable (active map + map currently being flushed).
        for realm_id in self.active_memtable.list_realm_ids() {
            realms.insert(realm_id);
        }

        // Enumerate from every live SST file.
        let sst_readers = self.sst_readers.load();
        for reader in sst_readers.iter() {
            for (key, _) in reader.iter_all()? {
                realms.insert(key.realm_id().clone());
            }
        }

        Ok(realms.into_iter().collect())
    }

    fn begin_snapshot_restore(&self, snapshot_id: &str) -> Result<(), StorageError> {
        let marker_path = self.data_dir.join(SNAPSHOT_RESTORE_MARKER);
        let mut file = self.fs.create(&marker_path)?;
        file.write_all(snapshot_id.as_bytes())?;
        file.sync_all()?;
        self.fs.sync_dir(&self.data_dir)?;
        Ok(())
    }

    fn complete_snapshot_restore(&self) -> Result<(), StorageError> {
        let marker_path = self.data_dir.join(SNAPSHOT_RESTORE_MARKER);
        self.fs.remove_file(&marker_path)?;
        self.fs.sync_dir(&self.data_dir)?;
        Ok(())
    }
}

impl std::fmt::Debug for EmbeddedStorageEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedStorageEngine")
            .field("data_dir", &self.data_dir)
            .field("hot_tier", &self.hot_tier)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RealmId;
    use crate::storage::wal::SyncMode;

    fn setup_engine() -> (tempfile::TempDir, EmbeddedStorageEngine) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::test_config(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open");
        (dir, engine)
    }

    // ===== Step 7 Tests =====

    #[test]
    fn engine_put_get_roundtrip() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        engine.put(&realm, b"key1", b"value1").expect("put");
        let val = engine.get(&realm, b"key1").expect("get");
        assert_eq!(val, Some(b"value1".to_vec()));
    }

    #[test]
    fn put_if_absent_first_writer_wins_single_thread() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        assert!(
            engine.put_if_absent(&realm, b"jti", b"1").expect("first"),
            "first put_if_absent should insert"
        );
        assert!(
            !engine.put_if_absent(&realm, b"jti", b"2").expect("second"),
            "second put_if_absent should observe the key and skip"
        );
        // The original value must survive — the losing writer must not overwrite.
        assert_eq!(
            engine.get(&realm, b"jti").expect("get"),
            Some(b"1".to_vec())
        );
    }

    // HEA-1767: the trait-default `put_if_absent` is a non-atomic get-then-put
    // with a TOCTOU window. `EmbeddedStorageEngine` overrides it to hold a lock
    // across the check-and-write. Under N concurrent tasks racing on the same
    // key, exactly one must win.
    #[test]
    fn put_if_absent_exactly_one_winner_under_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let (_dir, engine) = setup_engine();
        let engine = Arc::new(engine);
        let realm = RealmId::generate();

        const N: usize = 16;
        let barrier = Arc::new(Barrier::new(N));
        let winners = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..N)
            .map(|i| {
                let engine = Arc::clone(&engine);
                let barrier = Arc::clone(&barrier);
                let winners = Arc::clone(&winners);
                let realm = realm.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let value = i.to_string();
                    if engine
                        .put_if_absent(&realm, b"jti", value.as_bytes())
                        .expect("put_if_absent")
                    {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("join");
        }

        assert_eq!(
            winners.load(Ordering::SeqCst),
            1,
            "exactly one concurrent put_if_absent must succeed"
        );
        assert!(
            engine.get(&realm, b"jti").expect("get").is_some(),
            "the winning write must be durable"
        );
    }

    #[test]
    fn engine_delete_removes_value() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        engine.put(&realm, b"key1", b"value1").expect("put");
        assert_eq!(
            engine.get(&realm, b"key1").expect("get"),
            Some(b"value1".to_vec())
        );

        engine.delete(&realm, b"key1").expect("delete");
        assert_eq!(engine.get(&realm, b"key1").expect("get"), None);
    }

    #[test]
    fn engine_scan_returns_range() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();

        engine.put(&realm, b"apple", b"v-apple").expect("put");
        engine.put(&realm, b"banana", b"v-banana").expect("put");
        engine.put(&realm, b"cherry", b"v-cherry").expect("put");
        engine.put(&realm, b"date", b"v-date").expect("put");

        // Scan [banana, date) → banana, cherry
        let results = engine.scan(&realm, b"banana", b"date").expect("scan");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].key, b"banana");
        assert_eq!(results[0].value, b"v-banana");
        assert_eq!(results[1].key, b"cherry");
        assert_eq!(results[1].value, b"v-cherry");
    }

    #[test]
    fn engine_realm_isolation() {
        let (_dir, engine) = setup_engine();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        engine
            .put(&realm_a, b"shared_key", b"value-a")
            .expect("put a");
        engine
            .put(&realm_b, b"shared_key", b"value-b")
            .expect("put b");

        assert_eq!(
            engine.get(&realm_a, b"shared_key").expect("get a"),
            Some(b"value-a".to_vec())
        );
        assert_eq!(
            engine.get(&realm_b, b"shared_key").expect("get b"),
            Some(b"value-b".to_vec())
        );

        // Realm C sees nothing
        let realm_c = RealmId::generate();
        assert_eq!(engine.get(&realm_c, b"shared_key").expect("get c"), None);
    }

    #[test]
    fn engine_wal_recovery() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Write data, then drop the engine (simulates crash)
        {
            let config = StorageConfig::test_config(dir.path().to_path_buf());
            let engine = EmbeddedStorageEngine::open(config).expect("open");
            engine.put(&realm, b"durable1", b"val1").expect("put");
            engine.put(&realm, b"durable2", b"val2").expect("put");
            engine.delete(&realm, b"durable2").expect("delete");
        }

        // Re-open: WAL replay should recover state
        {
            let config = StorageConfig::test_config(dir.path().to_path_buf());
            let engine = EmbeddedStorageEngine::open(config).expect("reopen");

            assert_eq!(
                engine.get(&realm, b"durable1").expect("get"),
                Some(b"val1".to_vec()),
                "value should survive WAL recovery"
            );
            assert_eq!(
                engine.get(&realm, b"durable2").expect("get"),
                None,
                "deleted value should remain deleted after recovery"
            );
        }
    }

    #[test]
    fn engine_memtable_flush_to_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Use very small flush threshold to trigger flush
        let config = StorageConfig {
            data_dir: dir.path().to_path_buf(),
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig {
                flush_threshold_bytes: 100, // Very small — flush after ~2 entries
            },
            tiered_config: TieredConfig {
                hot_tier_capacity: 100,
                eviction_batch_size: 10,
                promote_sample_rate: 1,
            },
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
            dev_mode: true,
            block_cache_bytes: 4 * 1024 * 1024,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        // Write enough data to trigger flush
        for i in 0u32..20 {
            let key = format!("key-{i:04}");
            let val = format!("val-{i:04}");
            engine
                .put(&realm, key.as_bytes(), val.as_bytes())
                .expect("put");
        }

        // Verify SST files were created
        let sst_count = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert!(sst_count > 0, "flush should have created SST files");

        // All data should still be readable (from memtable + SST)
        for i in 0u32..20 {
            let key = format!("key-{i:04}");
            let expected = format!("val-{i:04}");
            let actual = engine.get(&realm, key.as_bytes()).expect("get");
            assert_eq!(
                actual,
                Some(expected.into_bytes()),
                "key {key} should be readable after flush"
            );
        }
    }

    // Regression test for the flush/write data-loss race. With a tiny flush
    // threshold every few writes triggers a flush; multiple threads write
    // concurrently while those flushes run. EVERY acknowledged write must still
    // be readable. The old flush (lock-free `iter_all()` then a later `clear()`)
    // could drop a write that landed between the snapshot and the clear; the
    // streaming `flush_streaming` (park-then-stream) makes that impossible.
    #[test]
    fn concurrent_writes_during_flush_are_not_lost() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let config = StorageConfig {
            data_dir: dir.path().to_path_buf(),
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig {
                flush_threshold_bytes: 256, // flush every ~10 writes → constant flushing
            },
            tiered_config: TieredConfig {
                hot_tier_capacity: 64,
                eviction_batch_size: 8,
                promote_sample_rate: 1,
            },
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
            dev_mode: true,
            block_cache_bytes: 4 * 1024 * 1024,
        };
        let engine = std::sync::Arc::new(EmbeddedStorageEngine::open(config).expect("open"));

        const THREADS: u32 = 4;
        const PER_THREAD: u32 = 800;

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let engine = std::sync::Arc::clone(&engine);
                let realm = realm.clone();
                std::thread::spawn(move || {
                    for i in 0..PER_THREAD {
                        let key = format!("t{t:02}-k{i:05}");
                        let val = format!("t{t:02}-v{i:05}");
                        engine
                            .put(&realm, key.as_bytes(), val.as_bytes())
                            .expect("put");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("writer thread panicked");
        }

        // Every acknowledged write must survive the concurrent flushing.
        let mut lost = Vec::new();
        for t in 0..THREADS {
            for i in 0..PER_THREAD {
                let key = format!("t{t:02}-k{i:05}");
                let expected = format!("t{t:02}-v{i:05}");
                match engine.get(&realm, key.as_bytes()).expect("get") {
                    Some(v) if v == expected.as_bytes() => {}
                    _ => lost.push(key),
                }
            }
        }
        assert!(
            lost.is_empty(),
            "{} acknowledged writes were lost during concurrent flushes (e.g. {:?})",
            lost.len(),
            &lost[..lost.len().min(5)]
        );
    }

    // Step 6 test #3: cold read promotes to hot tier (requires composed engine)
    #[test]
    fn engine_cold_promotes_to_hot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Write data and flush to SST (making it "cold")
        {
            let config = StorageConfig {
                data_dir: dir.path().to_path_buf(),
                wal_config: WalConfig {
                    max_size: 64 * 1024 * 1024,
                    sync_mode: SyncMode::None,
                },
                memtable_config: MemtableConfig {
                    flush_threshold_bytes: 50, // Very small
                },
                tiered_config: TieredConfig {
                    hot_tier_capacity: 100,
                    eviction_batch_size: 10,
                    promote_sample_rate: 1,
                },
                allow_missing_keks: false,
                compaction: CompactionConfig::default(),
                dev_mode: true,
                block_cache_bytes: 4 * 1024 * 1024,
            };
            let engine = EmbeddedStorageEngine::open(config).expect("open");

            // Write enough to trigger flush
            for i in 0u32..10 {
                let key = format!("cold-{i:04}");
                engine
                    .put(&realm, key.as_bytes(), b"cold-value")
                    .expect("put");
            }
        }

        // Re-open: data is in SST (cold), hot tier is empty
        {
            let config = StorageConfig {
                data_dir: dir.path().to_path_buf(),
                wal_config: WalConfig {
                    max_size: 64 * 1024 * 1024,
                    sync_mode: SyncMode::None,
                },
                memtable_config: MemtableConfig::default(),
                tiered_config: TieredConfig {
                    hot_tier_capacity: 100,
                    eviction_batch_size: 10,
                    promote_sample_rate: 1,
                },
                allow_missing_keks: false,
                compaction: CompactionConfig::default(),
                dev_mode: true,
                block_cache_bytes: 4 * 1024 * 1024,
            };
            let engine = EmbeddedStorageEngine::open(config).expect("reopen");

            // Hot tier should be empty initially
            assert!(
                !engine.hot_tier.contains(&realm, b"cold-0000"),
                "hot tier should be empty on fresh open"
            );

            // Read from cold (SST) — should promote to hot tier
            let val = engine.get(&realm, b"cold-0000").expect("cold read");
            assert_eq!(val, Some(b"cold-value".to_vec()));

            // Now it should be in the hot tier
            assert!(
                engine.hot_tier.contains(&realm, b"cold-0000"),
                "cold read should promote to hot tier"
            );

            // Second read should hit hot tier (faster path)
            let val2 = engine.get(&realm, b"cold-0000").expect("hot read");
            assert_eq!(val2, Some(b"cold-value".to_vec()));
        }
    }

    // HEA-1800: a corpus-scale load profile sizes the dev hot tier *below* the
    // working set via `set_hot_tier_capacity` so lookups spill to the cold/SST
    // tier. The override must take effect (bounded hot tier) while every record
    // still reads back correctly — the tier miss is a latency event, not a
    // correctness one.
    #[test]
    fn dev_hot_tier_capacity_override_forces_misses_but_stays_correct() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::dev(dir.path().to_path_buf());
        // Force flushes so records leave the memtable, and cap the hot tier well
        // below the record count so most reads must miss it.
        config.memtable_config = MemtableConfig {
            flush_threshold_bytes: 256,
        };
        config.set_hot_tier_capacity(16);
        assert_eq!(
            config.tiered_config.hot_tier_capacity, 16,
            "override must be reflected in the tiered config"
        );

        let engine = EmbeddedStorageEngine::open(config).expect("open");

        const N: u32 = 500;
        for i in 0..N {
            let key = format!("rec-{i:05}");
            let val = format!("val-{i:05}");
            engine
                .put(&realm, key.as_bytes(), val.as_bytes())
                .expect("put");
        }

        // The hot tier can never hold more than its capacity, so a corpus this
        // much larger than the cap guarantees cold/SST misses on most keys.
        assert!(
            engine.hot_tier.len() <= 16,
            "hot tier ({}) must stay within the overridden capacity",
            engine.hot_tier.len()
        );

        // Every record still reads back correctly regardless of tier residency.
        for i in 0..N {
            let key = format!("rec-{i:05}");
            let expected = format!("val-{i:05}");
            let got = engine.get(&realm, key.as_bytes()).expect("get");
            assert_eq!(
                got,
                Some(expected.into_bytes()),
                "record {i} must survive a hot-tier miss"
            );
        }
    }

    #[test]
    fn engine_scan_merges_memtable_and_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let config = StorageConfig {
            data_dir: dir.path().to_path_buf(),
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig {
                flush_threshold_bytes: 100,
            },
            tiered_config: TieredConfig::default(),
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
            dev_mode: true,
            block_cache_bytes: 4 * 1024 * 1024,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        // Write keys that will end up in SST (flush triggered by small threshold)
        engine.put(&realm, b"aaa", b"sst-val").expect("put");
        engine.put(&realm, b"bbb", b"sst-val").expect("put");
        engine.put(&realm, b"ccc", b"sst-val").expect("put");

        // These keys should be in memtable (written after last flush or still in memtable)
        engine.put(&realm, b"ddd", b"mem-val").expect("put");
        engine.put(&realm, b"eee", b"mem-val").expect("put");

        // The 100-byte flush threshold guarantees the first writes were flushed
        // to at least one SST while the tail stayed in the memtable, so a correct
        // scan must genuinely merge both layers rather than read a single tier.
        assert!(
            !engine.sst_readers.load().is_empty(),
            "flush threshold must have produced ≥1 SST so the scan actually spans layers"
        );

        // Scan the full range — should merge SST + memtable
        let results = engine.scan(&realm, b"aaa", b"fff").expect("scan");

        // Every one of the 5 keys must appear with its exact value, regardless of
        // which layer it lives in — a `>= 4` check silently tolerated a dropped key.
        let found: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = results
            .iter()
            .map(|r| (r.key.clone(), r.value.clone()))
            .collect();
        assert_eq!(
            found,
            [
                (b"aaa".to_vec(), b"sst-val".to_vec()),
                (b"bbb".to_vec(), b"sst-val".to_vec()),
                (b"ccc".to_vec(), b"sst-val".to_vec()),
                (b"ddd".to_vec(), b"mem-val".to_vec()),
                (b"eee".to_vec(), b"mem-val".to_vec()),
            ]
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>(),
            "cross-layer scan must return all 5 keys with their exact values"
        );

        // Results should be sorted
        for window in results.windows(2) {
            assert!(
                window[0].key <= window[1].key,
                "scan results should be sorted: {:?} > {:?}",
                window[0].key,
                window[1].key
            );
        }
    }

    /// Compile-time guarantee (no runtime assertions by design): the engine must
    /// stay `Send + Sync` so it can be shared across Tokio worker threads behind
    /// an `Arc`. If a future field loses `Send`/`Sync`, this fails to *compile*,
    /// which is the enforcement point — a runtime assert could not catch it.
    #[test]
    fn engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EmbeddedStorageEngine>();
    }

    #[test]
    fn engine_refuses_to_start_with_missing_keks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Build engine, flush data to create an SST file
        {
            let config = StorageConfig {
                data_dir: dir.path().to_path_buf(),
                wal_config: WalConfig {
                    max_size: 64 * 1024 * 1024,
                    sync_mode: SyncMode::None,
                },
                memtable_config: MemtableConfig {
                    flush_threshold_bytes: 50,
                },
                tiered_config: TieredConfig {
                    hot_tier_capacity: 100,
                    eviction_batch_size: 10,
                    promote_sample_rate: 1,
                },
                allow_missing_keks: false,
                compaction: CompactionConfig::default(),
                dev_mode: true,
                block_cache_bytes: 4 * 1024 * 1024,
            };
            let engine = EmbeddedStorageEngine::open(config).expect("open");
            for i in 0u32..5 {
                engine
                    .put(&realm, format!("k-{i}").as_bytes(), b"v")
                    .expect("put");
            }
        }

        // Delete the key registry so KEKs are lost, and the WAL (which also
        // has a wrapped DEK that can't be unwrapped without the old KEK).
        std::fs::remove_file(dir.path().join("hearth.keys")).expect("remove keys");
        std::fs::remove_file(dir.path().join("hearth.wal")).expect("remove wal");

        // Reopen: SSTs reference a KEK that no longer exists, should fail
        let config = StorageConfig {
            data_dir: dir.path().to_path_buf(),
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig::default(),
            tiered_config: TieredConfig::default(),
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
            dev_mode: true,
            block_cache_bytes: 4 * 1024 * 1024,
        };
        let result = EmbeddedStorageEngine::open(config);
        assert!(
            matches!(result, Err(StorageError::Crypto { .. })),
            "expected StorageError::Crypto, got: {result:?}"
        );
    }

    #[test]
    fn engine_allow_missing_keks_silently_drops_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Build engine, flush data to create an SST file
        {
            let config = StorageConfig {
                data_dir: dir.path().to_path_buf(),
                wal_config: WalConfig {
                    max_size: 64 * 1024 * 1024,
                    sync_mode: SyncMode::None,
                },
                memtable_config: MemtableConfig {
                    flush_threshold_bytes: 50,
                },
                tiered_config: TieredConfig {
                    hot_tier_capacity: 100,
                    eviction_batch_size: 10,
                    promote_sample_rate: 1,
                },
                allow_missing_keks: false,
                compaction: CompactionConfig::default(),
                dev_mode: true,
                block_cache_bytes: 4 * 1024 * 1024,
            };
            let engine = EmbeddedStorageEngine::open(config).expect("open");
            for i in 0u32..5 {
                engine
                    .put(&realm, format!("k-{i}").as_bytes(), b"v")
                    .expect("put");
            }
        }

        // Remove key registry and WAL so SST DEKs can't be unwrapped
        std::fs::remove_file(dir.path().join("hearth.keys")).expect("remove keys");
        std::fs::remove_file(dir.path().join("hearth.wal")).expect("remove wal");

        // Reopen with allow_missing_keks: SST is silently dropped, open succeeds
        let config = StorageConfig {
            data_dir: dir.path().to_path_buf(),
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig::default(),
            tiered_config: TieredConfig::default(),
            allow_missing_keks: true,
            compaction: CompactionConfig::default(),
            dev_mode: true,
            block_cache_bytes: 4 * 1024 * 1024,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open with allow_missing_keks");
        // Data that was only in the SST is no longer reachable
        for i in 0u32..5 {
            assert_eq!(
                engine
                    .get(&realm, format!("k-{i}").as_bytes())
                    .expect("get"),
                None,
                "SST-dropped key k-{i} should not be found"
            );
        }
    }

    #[test]
    fn engine_compaction_reduces_sst_count_and_preserves_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.memtable_config.flush_threshold_bytes = 50;
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 0,
            merge_min: 4,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..50 {
            engine
                .put(
                    &realm,
                    format!("c-{i:04}").as_bytes(),
                    format!("val-{i:04}").as_bytes(),
                )
                .expect("put");
        }

        let sst_before = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert!(
            sst_before >= 2,
            "expected at least 2 SST files before compaction, got {sst_before}"
        );

        let compacted = engine.compact_ssts(2).expect("compact_ssts");
        assert_eq!(
            compacted, sst_before,
            "compacted count should match input SST count"
        );

        let sst_after = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert_eq!(
            sst_after, 1,
            "after compaction there should be exactly 1 SST file, got {sst_after}"
        );

        for i in 0u32..50 {
            let key = format!("c-{i:04}");
            assert_eq!(
                engine.get(&realm, key.as_bytes()).expect("get"),
                Some(format!("val-{i:04}").into_bytes()),
                "key {key} should be accessible after compaction"
            );
        }
    }

    #[test]
    fn engine_compaction_skips_when_below_min_sst_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 0,
            merge_min: 4,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        engine.put(&realm, b"a", b"val-a").expect("put");

        let compacted = engine.compact_ssts(5).expect("compact_ssts");
        assert_eq!(
            compacted, 0,
            "compaction should skip when SST count is below min_sst_count"
        );
    }

    #[test]
    fn engine_compaction_succeeds_at_exact_min_sst_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.memtable_config.flush_threshold_bytes = 50;
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 0,
            merge_min: 4,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..30 {
            engine
                .put(
                    &realm,
                    format!("b-{i:04}").as_bytes(),
                    format!("vb-{i:04}").as_bytes(),
                )
                .expect("put");
        }

        let sst_before = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();

        // The 30 puts above (values ~5 bytes) at a 50-byte flush threshold must
        // reliably produce at least `min_sst_count` SSTs, otherwise the boundary
        // this test exists to cover is never reached — assert it unconditionally
        // rather than silently no-op'ing the whole body behind an `if`.
        assert!(
            sst_before >= 2,
            "setup must flush ≥2 SSTs to exercise the exact-min_sst_count boundary, got {sst_before}"
        );

        let compacted = engine.compact_ssts(2).expect("compact_ssts");
        assert_eq!(
            compacted, sst_before,
            "compaction at exact min_sst_count boundary should compact every SST"
        );

        for i in 0u32..30 {
            let key = format!("b-{i:04}");
            assert_eq!(
                engine.get(&realm, key.as_bytes()).expect("get"),
                Some(format!("vb-{i:04}").into_bytes()),
                "value for {key} must survive compaction at the boundary"
            );
        }
    }

    #[test]
    fn engine_compaction_removes_tombstones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.memtable_config.flush_threshold_bytes = 50;
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 0,
            merge_min: 4,
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..20 {
            engine
                .put(
                    &realm,
                    format!("k-{i:04}").as_bytes(),
                    format!("val-{i:04}").as_bytes(),
                )
                .expect("put");
        }
        for i in 0u32..10 {
            engine
                .delete(&realm, format!("k-{i:04}").as_bytes())
                .expect("delete");
        }

        // Extra writes to force flushes (push tombstones into SSTs)
        engine.put(&realm, b"flush-a", b"x").expect("put");
        engine.put(&realm, b"flush-b", b"x").expect("put");

        let compacted = engine.compact_ssts(2).expect("compact");
        assert!(compacted > 0, "should have compacted at least 2 SSTs");

        // Compacted SST must have zero tombstones
        let readers = engine.sst_readers.load();
        assert_eq!(readers.len(), 1, "should be 1 SST after compaction");
        for (_key, value) in readers[0].iter_all().expect("iter_all") {
            assert!(
                !matches!(value, MemtableValue::Tombstone),
                "compacted SST must contain zero tombstones"
            );
        }

        // Deleted keys must be unreachable
        for i in 0u32..10 {
            assert_eq!(
                engine
                    .get(&realm, format!("k-{i:04}").as_bytes())
                    .expect("get"),
                None,
                "deleted key k-{i:04} must not be reachable after compaction"
            );
        }

        // Live keys must still be reachable
        for i in 10u32..20 {
            assert_eq!(
                engine
                    .get(&realm, format!("k-{i:04}").as_bytes())
                    .expect("get"),
                Some(format!("val-{i:04}").into_bytes()),
            );
        }
    }

    /// A [`Fs`] decorator that makes every `*.sst` `remove_file` fail with
    /// `PermissionDenied`, emulating a compaction unlink that cannot retire a
    /// merged-away input SST (a full disk, a read-only mount, or a crash landing
    /// between the rename and the unlinks). Every other operation delegates
    /// straight to [`RealFs`], so real files, mmaps, and fsyncs behave exactly as
    /// in production. Used to prove a failed unlink cannot resurrect a deleted key
    /// (HEA-1982).
    struct UnlinkFailFs {
        inner: RealFs,
    }

    impl crate::storage::fs::Fs for UnlinkFailFs {
        fn open_append(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.open_append(path)
        }

        fn create(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.create(path)
        }

        fn open_read(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.open_read(path)
        }

        fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
            self.inner.read(path)
        }

        fn map_readonly(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<crate::storage::fs::FileBacking> {
            self.inner.map_readonly(path)
        }

        fn write(&self, path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
            self.inner.write(path, data)
        }

        fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()> {
            self.inner.create_dir_all(path)
        }

        fn read_dir(&self, path: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
            self.inner.read_dir(path)
        }

        fn remove_file(&self, path: &std::path::Path) -> std::io::Result<()> {
            if path.extension().is_some_and(|e| e == "sst") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected unlink failure",
                ));
            }
            self.inner.remove_file(path)
        }

        fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
            self.inner.rename(from, to)
        }

        fn sync_dir(&self, dir: &std::path::Path) -> std::io::Result<()> {
            self.inner.sync_dir(dir)
        }
    }

    /// HEA-1982 — a **full** compaction that cannot unlink a merged-away input SST
    /// MUST NOT resurrect a deleted key. The full merge drops tombstones, so if the
    /// old value-bearing SST survives while the merged output no longer carries the
    /// tombstone, a lookup falls through to the orphan and the deleted key comes
    /// back. The unlink failure must instead abort the commit and leave the
    /// tombstone-bearing reader set in place.
    #[test]
    fn full_compaction_unlink_failure_keeps_deleted_key_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 0,
            merge_min: 4,
        };
        let engine =
            EmbeddedStorageEngine::open_with_fs(config, Arc::new(UnlinkFailFs { inner: RealFs }))
                .expect("open");

        // doomed=value in the oldest SST, its tombstone in a newer SST, plus a live
        // key so the merge has real content and there are >= 2 SSTs to compact.
        engine
            .put(&realm, b"doomed", b"secret")
            .expect("put doomed");
        engine.trigger_flush().expect("flush 1");
        engine.delete(&realm, b"doomed").expect("delete doomed");
        engine.trigger_flush().expect("flush 2");
        engine.put(&realm, b"live", b"present").expect("put live");
        engine.trigger_flush().expect("flush 3");

        // Baseline: the delete is visible before compaction.
        assert_eq!(
            engine.get(&realm, b"doomed").expect("get"),
            None,
            "doomed must read as deleted before compaction"
        );

        // The compaction merges + drops tombstones, then fails to unlink the old
        // inputs. That failure MUST be fatal to the commit.
        let err = engine.compact_ssts(2);
        assert!(
            err.is_err(),
            "compaction must fail the commit when an input SST cannot be unlinked"
        );

        // The deleted key must STAY deleted — no resurrection from the un-unlinked
        // value-bearing input SST.
        assert_eq!(
            engine
                .get(&realm, b"doomed")
                .expect("get after failed compaction"),
            None,
            "a failed unlink must not resurrect the deleted key"
        );
        // The live key must still be reachable.
        assert_eq!(
            engine.get(&realm, b"live").expect("get live"),
            Some(b"present".to_vec()),
            "live key must survive the failed compaction"
        );
    }

    /// HEA-1982 — the same guarantee for the **partial** (size-tiered) path. When
    /// the selected run reaches the oldest SST the merge drops tombstones; a
    /// surviving older run member would then resurrect a deleted key. Two same-size
    /// SSTs (value, then tombstone) form a `merge_min = 2` run that reaches the
    /// oldest, and the older member's unlink is injected to fail.
    #[test]
    fn partial_compaction_unlink_failure_keeps_deleted_key_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.compaction = CompactionConfig {
            enabled: true,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 8,
            merge_min: 2,
        };
        let engine =
            EmbeddedStorageEngine::open_with_fs(config, Arc::new(UnlinkFailFs { inner: RealFs }))
                .expect("open");

        // SST0 (oldest): doomed=value. SST1 (newest): doomed=tombstone. Both hold a
        // single entry, so they share a size tier and form one mergeable run whose
        // end is the oldest SST => the merge drops the tombstone.
        engine
            .put(&realm, b"doomed", b"secret")
            .expect("put doomed");
        engine.trigger_flush().expect("flush 1");
        engine.delete(&realm, b"doomed").expect("delete doomed");
        engine.trigger_flush().expect("flush 2");

        assert_eq!(
            engine.get(&realm, b"doomed").expect("get"),
            None,
            "doomed must read as deleted before compaction"
        );

        let err = engine.compact_partial();
        assert!(
            err.is_err(),
            "partial compaction must fail the commit when a run member cannot be unlinked"
        );

        assert_eq!(
            engine
                .get(&realm, b"doomed")
                .expect("get after failed compaction"),
            None,
            "a failed unlink must not resurrect the deleted key in the partial path"
        );
    }

    /// A [`Fs`] decorator that allows the first `allow` `*.sst` `remove_file`
    /// calls, then fails every subsequent one with `PermissionDenied`. Emulates a
    /// disk that begins failing *partway* through the compaction unlink loop
    /// (ENOSPC, EIO, a read-only remount) — the case a whole-loop failure never
    /// exercises. Every other op delegates to [`RealFs`]. Used to prove the
    /// oldest-first unlink order cannot resurrect a deleted key on a partial unlink
    /// failure (HEA-1986).
    struct FailAfterNthUnlinkFs {
        inner: RealFs,
        allow: std::sync::atomic::AtomicUsize,
    }

    impl crate::storage::fs::Fs for FailAfterNthUnlinkFs {
        fn open_append(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.open_append(path)
        }

        fn create(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.create(path)
        }

        fn open_read(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.open_read(path)
        }

        fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
            self.inner.read(path)
        }

        fn map_readonly(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<crate::storage::fs::FileBacking> {
            self.inner.map_readonly(path)
        }

        fn write(&self, path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
            self.inner.write(path, data)
        }

        fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()> {
            self.inner.create_dir_all(path)
        }

        fn read_dir(&self, path: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
            self.inner.read_dir(path)
        }

        fn remove_file(&self, path: &std::path::Path) -> std::io::Result<()> {
            if path.extension().is_some_and(|e| e == "sst") {
                // Allow the first `allow` `.sst` unlinks, then fail every one after.
                // Compaction unlinks serialize under the flush lock, so a plain
                // load / conditional store is race-free here.
                let remaining = self.allow.load(std::sync::atomic::Ordering::SeqCst);
                if remaining == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "injected unlink failure after N successes",
                    ));
                }
                self.allow
                    .store(remaining - 1, std::sync::atomic::Ordering::SeqCst);
            }
            self.inner.remove_file(path)
        }

        fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
            self.inner.rename(from, to)
        }

        fn sync_dir(&self, dir: &std::path::Path) -> std::io::Result<()> {
            self.inner.sync_dir(dir)
        }
    }

    /// HEA-1986 — a **partial** unlink failure (disk starts failing *mid-loop*)
    /// MUST NOT resurrect a deleted key. With the pre-fix newest-first unlink order
    /// the loop removes the newer tombstone-bearing SST first; if the failure then
    /// lands on the older value-bearing SST, the tombstone-free merged output plus
    /// the surviving value SST resurrect the deleted key on the next on-disk reload.
    /// The oldest-first order removes each value SST *before* its shadowing
    /// tombstone, so any partial prefix of unlinks leaves only extra tombstones —
    /// never a resurrectable orphan.
    ///
    /// Three same-size SSTs form a full merge that drops tombstones: SST0 (oldest)
    /// = `doomed` value, SST1 = `doomed` tombstone, SST2 (newest) = `live`. The FS
    /// allows two `.sst` unlinks then fails the third, so the loop aborts partway.
    /// A subsequent flush calls `reload_sst_readers()` (see [`Self::trigger_flush`]),
    /// rebuilding the in-memory set from what actually survived on disk — the true
    /// resurrection test. (Reopening the engine would replay the delete from the WAL
    /// and mask the on-disk bug, so this must observe the reload without a restart.)
    #[test]
    fn full_compaction_partial_unlink_failure_keeps_deleted_key_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 0,
            merge_min: 4,
        };
        let engine = EmbeddedStorageEngine::open_with_fs(
            config,
            Arc::new(FailAfterNthUnlinkFs {
                inner: RealFs,
                allow: std::sync::atomic::AtomicUsize::new(2),
            }),
        )
        .expect("open");

        engine
            .put(&realm, b"doomed", b"secret")
            .expect("put doomed");
        engine.trigger_flush().expect("flush 1");
        engine.delete(&realm, b"doomed").expect("delete doomed");
        engine.trigger_flush().expect("flush 2");
        engine.put(&realm, b"live", b"present").expect("put live");
        engine.trigger_flush().expect("flush 3");

        assert_eq!(
            engine.get(&realm, b"doomed").expect("get"),
            None,
            "doomed must read as deleted before compaction"
        );

        // Merges + drops tombstones, unlinks two inputs, then the third unlink
        // fails and aborts the commit.
        let err = engine.compact_ssts(2);
        assert!(
            err.is_err(),
            "compaction must fail the commit when an input SST unlink fails mid-loop"
        );

        // In-memory (pinned pre-commit readers) must still read the delete.
        assert_eq!(
            engine.get(&realm, b"doomed").expect("get after abort"),
            None,
            "in-memory reader set must keep the delete after a mid-loop abort"
        );

        // Force a fresh reload from disk WITHOUT a restart: a flush rebuilds the
        // reader Vec from the surviving files. Under the pre-fix newest-first order
        // the tombstone SST was unlinked before the value SST that outlived the
        // abort, so the tombstone-free merged output plus the surviving value SST
        // resurrect `doomed` here. Oldest-first keeps it deleted.
        engine.put(&realm, b"probe", b"x").expect("put probe");
        engine.trigger_flush().expect("flush probe");
        assert_eq!(
            engine.get(&realm, b"doomed").expect("get after reload"),
            None,
            "a partial unlink failure must not resurrect the deleted key on the next reload (HEA-1986)"
        );
        assert_eq!(
            engine.get(&realm, b"live").expect("get live after reload"),
            Some(b"present".to_vec()),
            "the live key must survive the aborted compaction"
        );
    }

    /// Counts `*.sst` files (ignoring `.tmp`) in a data directory.
    fn count_sst_files(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count()
    }

    /// HEA-1885 — count-triggered PARTIAL (size-tiered) compaction must bound the
    /// live SST fan-out at a small constant while preserving every key, including
    /// one flushed into the *oldest* SST, and must never resurrect a deleted key.
    #[test]
    fn partial_compaction_bounds_sst_count_and_preserves_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Tiny flush threshold + large values => roughly one SST per put, so an
        // uncapped run of 300 inserts would leave ~300 SSTs on disk.
        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.memtable_config.flush_threshold_bytes = 50;
        config.compaction = CompactionConfig {
            enabled: true,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 8, // count trigger
            merge_min: 3,     // per-tier fan-in
        };
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        let value = vec![b'x'; 80];

        // Marker written first so it lands in the very oldest SST.
        engine
            .put(&realm, b"aaa-oldest-marker", b"oldest-value")
            .expect("put marker");
        // A key we will delete early, then keep writing past — its tombstone must
        // never be shadowed away by a partial merge that leaves older SSTs live.
        engine
            .put(&realm, b"aaa-doomed", b"temp")
            .expect("put doomed");
        engine.delete(&realm, b"aaa-doomed").expect("delete doomed");

        const N: u32 = 300;
        let mut max_live: usize = 0;
        for i in 0..N {
            engine
                .put(&realm, format!("k-{i:04}").as_bytes(), &value)
                .expect("put");
            // Emulate the background hand-off deterministically: whenever the live
            // SST count reaches the trigger, run one partial compaction.
            if count_sst_files(dir.path()) >= 8 {
                engine.compact_partial().expect("compact_partial");
            }
            max_live = max_live.max(count_sst_files(dir.path()));
        }

        // The cap: fan-out is bounded by O(merge_min * log(N)), a small constant —
        // NOT the ~300 an uncapped run would produce.
        assert!(
            max_live <= 24,
            "partial compaction must cap SST fan-out at a small constant, peaked at {max_live}"
        );

        // Drain remaining partial merges.
        loop {
            if engine.compact_partial().expect("drain compact_partial") == 0 {
                break;
            }
        }

        // No key may be lost, including the one in the oldest SST.
        assert_eq!(
            engine
                .get(&realm, b"aaa-oldest-marker")
                .expect("get marker"),
            Some(b"oldest-value".to_vec()),
            "key in the oldest SST must survive partial compaction (no loss)"
        );
        for i in 0..N {
            assert_eq!(
                engine
                    .get(&realm, format!("k-{i:04}").as_bytes())
                    .expect("get"),
                Some(value.clone()),
                "k-{i:04} must survive partial compaction"
            );
        }
        // The deleted key must stay deleted (no resurrection from older SSTs).
        assert_eq!(
            engine.get(&realm, b"aaa-doomed").expect("get doomed"),
            None,
            "partial compaction must not resurrect a deleted key"
        );
    }

    /// HEA-1881 lever 1, **mandatory AC** — the count trigger MUST carry a
    /// write-amplification debounce. This pins that size-tiered *partial*
    /// compaction rewrites `O(N log N)` records under a sustained bulk import,
    /// NOT the `O(N²)` that a naive "full-merge whenever count crosses the
    /// threshold" trigger would incur (the quadratic case the CTO flagged as
    /// non-optional to prevent).
    ///
    /// Method: run the identical bulk-import workload twice at two corpus sizes,
    /// once servicing the count trigger with `compact_partial` (the shipped
    /// size-tiered path) and once with `compact_ssts` (a full merge — the
    /// strawman). We read the cumulative records-written counter for each and
    /// compare the *shape* of the growth, not brittle absolute constants:
    ///
    /// * a full merge on every trigger rewrites the whole live set each time, so
    ///   its per-record write cost grows with `N` — the quadratic signature;
    /// * the size-tiered path re-merges a run only once per size tier, so its
    ///   per-record write cost grows only `~log N` — effectively flat here.
    // Record counts here are < 10_000, so u64->f64 is exact; the ratios are the
    // whole point of the test.
    #[allow(clippy::cast_precision_loss, clippy::similar_names)]
    #[test]
    fn partial_compaction_bounds_write_amplification_vs_full_merge() {
        // Runs a bulk import of `n` puts with the periodic sweep disabled,
        // servicing the count trigger deterministically (emulating the
        // background hand-off) with either the size-tiered partial path or a
        // full merge. Returns records written out by compaction (write-amp
        // numerator).
        fn write_amp(n: u32, size_tiered: bool) -> u64 {
            const TRIGGER: usize = 8;

            let dir = tempfile::tempdir().expect("tempdir");
            let mut config = StorageConfig::test_config(dir.path().to_path_buf());
            // ~one SST per put so the corpus is dominated by SST fan-out.
            config.memtable_config.flush_threshold_bytes = 50;
            config.compaction = CompactionConfig {
                enabled: true,
                interval_secs: 0, // periodic sweep OFF — we drive compaction by hand
                min_sst_count: 2,
                max_sst_count: TRIGGER,
                merge_min: 4,
            };
            let engine = EmbeddedStorageEngine::open(config).expect("open");
            let realm = RealmId::generate();
            let value = vec![b'x'; 40];

            for i in 0..n {
                engine
                    .put(&realm, format!("k-{i:05}").as_bytes(), &value)
                    .expect("put");
                // Drain to below the trigger, exactly as the background task
                // would when notified that live count crossed `max_sst_count`.
                while count_sst_files(dir.path()) >= TRIGGER {
                    let merged = if size_tiered {
                        engine.compact_partial().expect("compact_partial")
                    } else {
                        // Strawman: full merge of every live SST on each trigger.
                        engine.compact_ssts(2).expect("compact_ssts")
                    };
                    if merged == 0 {
                        break;
                    }
                }
            }
            engine.compaction_records_written()
        }

        const N: u32 = 100;
        const N2: u32 = 200;

        let partial_n = write_amp(N, true);
        let partial_2n = write_amp(N2, true);
        let full_n = write_amp(N, false);
        let full_2n = write_amp(N2, false);

        // Per-record write amplification (records rewritten per record ingested).
        let partial_amp_n = partial_n as f64 / f64::from(N);
        let partial_amp_2n = partial_2n as f64 / f64::from(N2);
        let full_amp_n = full_n as f64 / f64::from(N);
        let full_amp_2n = full_2n as f64 / f64::from(N2);

        // The full-merge strawman must exhibit the quadratic signature: doubling
        // the corpus meaningfully increases per-record write cost.
        assert!(
            full_amp_2n >= full_amp_n * 1.5,
            "full-merge-on-trigger should show super-linear (quadratic) write amp: \
             amp(N)={full_amp_n:.2} amp(2N)={full_amp_2n:.2}"
        );

        // The size-tiered path must NOT: per-record write cost stays ~flat
        // (grows only ~log N) as the corpus doubles. This is the debounce.
        assert!(
            partial_amp_2n <= partial_amp_n * 1.4,
            "size-tiered partial compaction must keep write amp ~flat (sub-quadratic): \
             amp(N)={partial_amp_n:.2} amp(2N)={partial_amp_2n:.2}"
        );

        // And in absolute terms the debounce rewrites far fewer records than the
        // full merge at the larger corpus.
        assert!(
            partial_2n * 2 <= full_2n,
            "size-tiered partial compaction should rewrite far fewer records than \
             full-merge-on-trigger at 2N: partial={partial_2n} full={full_2n}"
        );
    }

    /// A [`Fs`] decorator that blocks the first `create` of a `*.tmp` path
    /// (i.e. a compaction merge's temporary output) until the test releases it,
    /// signalling the moment the block is reached. Every other operation is a
    /// straight delegation to the wrapped [`RealFs`], so real files, mmaps, and
    /// fsyncs behave exactly as in production.
    ///
    /// Used to prove that `flush_lock` is *not* held while merge I/O runs
    /// (HEA-1931): while the merge is parked inside `create`, a concurrent flush
    /// must still be able to acquire `flush_lock`.
    struct MergeGateFs {
        inner: RealFs,
        /// Fires once, when the gated `*.tmp` create is first entered.
        reached: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
        /// Set to `true` (with a notify) by the test to let the merge proceed.
        release: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }

    impl crate::storage::fs::Fs for MergeGateFs {
        fn open_append(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.open_append(path)
        }

        fn create(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            let is_tmp = path.extension().is_some_and(|e| e == "tmp");
            if is_tmp {
                // Signal once, then park until the test releases the gate.
                if let Some(tx) = self.reached.lock().expect("reached lock").take() {
                    let _ = tx.send(());
                    let (lock, cv) = &*self.release;
                    let mut released = lock.lock().expect("release lock");
                    while !*released {
                        released = cv.wait(released).expect("release wait");
                    }
                }
            }
            self.inner.create(path)
        }

        fn open_read(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.open_read(path)
        }

        fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
            self.inner.read(path)
        }

        fn map_readonly(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<crate::storage::fs::FileBacking> {
            self.inner.map_readonly(path)
        }

        fn write(&self, path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
            self.inner.write(path, data)
        }

        fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()> {
            self.inner.create_dir_all(path)
        }

        fn read_dir(&self, path: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
            self.inner.read_dir(path)
        }

        fn remove_file(&self, path: &std::path::Path) -> std::io::Result<()> {
            self.inner.remove_file(path)
        }

        fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
            self.inner.rename(from, to)
        }

        fn sync_dir(&self, dir: &std::path::Path) -> std::io::Result<()> {
            self.inner.sync_dir(dir)
        }
    }

    /// HEA-1931 — merge I/O MUST run off `flush_lock`, so a partial compaction
    /// cannot stall writers for the O(tier-data) duration of the merge.
    ///
    /// We gate the compaction's `*.tmp` merge write inside a decorator `Fs`, run
    /// `compact_partial` on a worker thread, and — while the merge is parked
    /// mid-write — assert the *main* thread can still acquire `flush_lock`. Before
    /// the fix, `compact_partial` held `flush_lock` across the whole merge, so the
    /// `try_lock` here would fail; after it, the lock is free during merge I/O.
    #[test]
    fn compaction_merge_io_does_not_hold_flush_lock() {
        use std::sync::atomic::Ordering;

        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // ~one SST per put so a short run accumulates a mergeable same-size tier.
        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.memtable_config.flush_threshold_bytes = 50;
        config.compaction = CompactionConfig {
            enabled: true,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 8,
            merge_min: 3,
        };

        let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let gate_fs = Arc::new(MergeGateFs {
            inner: RealFs,
            reached: Mutex::new(Some(reached_tx)),
            release: Arc::clone(&release),
        });

        let engine = Arc::new(EmbeddedStorageEngine::open_with_fs(config, gate_fs).expect("open"));

        // Write enough distinct SSTs to form a merge run.
        let value = vec![b'x'; 80];
        for i in 0..8u32 {
            engine
                .put(&realm, format!("k-{i:04}").as_bytes(), &value)
                .expect("put");
        }
        assert!(
            count_sst_files(dir.path()) >= 3,
            "expected several SSTs to accumulate before compaction"
        );

        // Run the partial compaction on a worker; it will park inside the gated
        // merge write until we release it.
        let merge_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker = {
            let engine = Arc::clone(&engine);
            let merge_done = Arc::clone(&merge_done);
            std::thread::spawn(move || {
                let merged = engine.compact_partial().expect("compact_partial");
                merge_done.store(true, Ordering::SeqCst);
                merged
            })
        };

        // Wait until the merge is genuinely mid-write (parked inside `create`).
        reached_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("merge should reach the gated tmp write");

        // The merge has NOT yet been released, so it is actively "doing" merge
        // I/O. `flush_lock` must be free right now.
        assert!(
            !merge_done.load(Ordering::SeqCst),
            "merge must still be parked mid-write for this assertion to be meaningful"
        );
        {
            let guard = engine.flush_lock.try_lock();
            assert!(
                guard.is_ok(),
                "flush_lock must NOT be held during SST merge I/O (HEA-1931)"
            );
        }

        // Release the merge and let it commit.
        {
            let (lock, cv) = &*release;
            *lock.lock().expect("release lock") = true;
            cv.notify_all();
        }
        let merged = worker.join().expect("compaction thread");
        assert!(merged >= 3, "partial compaction should have merged the run");

        // Data survives the off-lock merge.
        for i in 0..8u32 {
            assert_eq!(
                engine
                    .get(&realm, format!("k-{i:04}").as_bytes())
                    .expect("get"),
                Some(value.clone()),
                "k-{i:04} must survive off-lock compaction"
            );
        }
    }

    /// A [`Fs`] decorator for the HEA-1937 F1 regression test. Once *armed*, it:
    ///
    /// * parks the first flush `*.sst` create (a direct write by `trigger_flush`,
    ///   distinguished from compaction output by its non-`tmp` extension),
    ///   signalling `flush_reached` and holding until the test releases it — this
    ///   keeps the flush parked *while it holds `flush_lock`*, and
    /// * signals `comp_reached` (without parking) when a compaction merge's
    ///   `*.tmp` create is entered, so the test can observe whether `compact_ssts`
    ///   reached its merge while a flush was still parked.
    ///
    /// Pre-arm creates delegate straight through, so building the initial SSTs is
    /// unaffected. Every non-`create` op is a plain delegation to [`RealFs`].
    struct FlushGateFs {
        inner: RealFs,
        armed: Arc<std::sync::atomic::AtomicBool>,
        /// Fires once when the armed flush `*.sst` create is entered.
        flush_reached: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
        /// Set to `true` (with notify) by the test to release the parked flush.
        flush_release: Arc<(Mutex<bool>, std::sync::Condvar)>,
        /// Fires once when a compaction merge `*.tmp` create is entered.
        comp_reached: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
    }

    impl crate::storage::fs::Fs for FlushGateFs {
        fn open_append(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.open_append(path)
        }

        fn create(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
                match path.extension().and_then(|e| e.to_str()) {
                    // Flush writes `NNNNNN.sst` directly — park it (while it holds
                    // `flush_lock`) until the test releases the gate.
                    Some("sst") => {
                        if let Some(tx) = self.flush_reached.lock().expect("flush_reached").take() {
                            let _ = tx.send(());
                            let (lock, cv) = &*self.flush_release;
                            let mut released = lock.lock().expect("flush_release lock");
                            while !*released {
                                released = cv.wait(released).expect("flush_release wait");
                            }
                        }
                    }
                    // Compaction merge writes `NNNNNN.sst.tmp` — signal only, so the
                    // test learns the merge got past its snapshot.
                    Some("tmp") => {
                        if let Some(tx) = self.comp_reached.lock().expect("comp_reached").take() {
                            let _ = tx.send(());
                        }
                    }
                    _ => {}
                }
            }
            self.inner.create(path)
        }

        fn open_read(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.open_read(path)
        }

        fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
            self.inner.read(path)
        }

        fn map_readonly(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<crate::storage::fs::FileBacking> {
            self.inner.map_readonly(path)
        }

        fn write(&self, path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
            self.inner.write(path, data)
        }

        fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()> {
            self.inner.create_dir_all(path)
        }

        fn read_dir(&self, path: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
            self.inner.read_dir(path)
        }

        fn remove_file(&self, path: &std::path::Path) -> std::io::Result<()> {
            self.inner.remove_file(path)
        }

        fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
            self.inner.rename(from, to)
        }

        fn sync_dir(&self, dir: &std::path::Path) -> std::io::Result<()> {
            self.inner.sync_dir(dir)
        }
    }

    /// HEA-1937 F1 — `compact_ssts` must snapshot its reader set and allocate its
    /// output number *under `flush_lock`*, so its merge output can never be
    /// numbered *below* a concurrently flushed SST (which would invert recency and
    /// permanently shadow the just-flushed value).
    ///
    /// Scenario: a key's OLD value lives in an early SST; a flush writing the key's
    /// NEW value is parked mid-`create` (holding `flush_lock`); `compact_ssts` runs
    /// concurrently. Before the fix, `compact_ssts` snapshotted the stale reader
    /// set (missing the new SST) yet took a *higher* number, so after commit the
    /// merged OLD data shadowed the NEW SST and `get()` returned the OLD value.
    /// After the fix, `compact_ssts` blocks on `flush_lock` at snapshot time, so it
    /// sees the new SST and numbers its output above it — NEW wins.
    #[test]
    fn compact_ssts_cannot_invert_recency_against_concurrent_flush() {
        use std::sync::atomic::Ordering;

        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // High flush threshold so puts stay in the memtable until we flush
        // explicitly — we drive SST creation by hand for full ordering control.
        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.memtable_config.flush_threshold_bytes = 64 * 1024 * 1024;
        config.compaction = CompactionConfig {
            enabled: true,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 0, // no auto-compaction; the test drives compact_ssts
            merge_min: 2,
        };

        let flush_release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let (flush_reached_tx, flush_reached_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (comp_reached_tx, comp_reached_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate_fs = Arc::new(FlushGateFs {
            inner: RealFs,
            armed: Arc::clone(&armed),
            flush_reached: Mutex::new(Some(flush_reached_tx)),
            flush_release: Arc::clone(&flush_release),
            comp_reached: Mutex::new(Some(comp_reached_tx)),
        });

        let engine = Arc::new(EmbeddedStorageEngine::open_with_fs(config, gate_fs).expect("open"));

        let target = b"target".as_slice();
        let old_value = vec![b'O'; 32];
        let new_value = vec![b'N'; 32];

        // Build three older SSTs (0,1,2). SST 0 holds target=OLD; the others carry
        // distinct filler so each flush produces a non-empty file.
        engine
            .put(&realm, target, &old_value)
            .expect("put old target");
        engine.trigger_flush().expect("flush sst0");
        engine.put(&realm, b"filler-1", &old_value).expect("put f1");
        engine.trigger_flush().expect("flush sst1");
        engine.put(&realm, b"filler-2", &old_value).expect("put f2");
        engine.trigger_flush().expect("flush sst2");
        assert!(
            count_sst_files(dir.path()) >= 3,
            "expected three older SSTs before the concurrent flush"
        );

        // Stage the NEW value in the memtable; it will become the concurrently
        // flushed SST that compaction must not shadow.
        engine
            .put(&realm, target, &new_value)
            .expect("put new target");

        // Arm the gate and run the flush of the NEW value on a worker: it takes
        // `flush_lock`, allocates its number, then parks inside the `.sst` create.
        armed.store(true, Ordering::SeqCst);
        let flush_worker = {
            let engine = Arc::clone(&engine);
            std::thread::spawn(move || engine.trigger_flush().expect("concurrent flush"))
        };
        flush_reached_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("flush should reach the gated .sst create");

        // With the flush parked (still holding `flush_lock`), run compact_ssts.
        let compact_worker = {
            let engine = Arc::clone(&engine);
            std::thread::spawn(move || engine.compact_ssts(2).expect("compact_ssts"))
        };

        // If compaction reaches its merge `.tmp` while the flush is still parked, it
        // snapshotted the stale reader set (the pre-fix bug). The fixed code blocks
        // at snapshot on `flush_lock` and cannot reach the merge until we release the
        // flush, so this receive MUST time out. Asserting the timeout pins the
        // *mechanism* (compaction parked at snapshot), not just the final outcome, so
        // the test stays red under any future refactor that reintroduces the stale
        // snapshot by a different route while keeping numbering correct.
        assert!(
            comp_reached_rx
                .recv_timeout(std::time::Duration::from_millis(500))
                .is_err(),
            "compact_ssts reached its merge while a flush held flush_lock — \
             snapshot/alloc is not ordered against flushes (HEA-1937 F1)"
        );

        // Release the parked flush so both operations complete.
        {
            let (lock, cv) = &*flush_release;
            *lock.lock().expect("release lock") = true;
            cv.notify_all();
        }
        flush_worker.join().expect("flush thread");
        let merged_inputs = compact_worker.join().expect("compact thread");

        // The merge must actually have consumed the older SSTs. Without this, an
        // `Ok(0)` early return (e.g. a future refactor that skips the merge) would
        // leave the OLD SST unmerged and let the final recency check pass for a
        // reason unrelated to what is under test (TESTING.md anti-pattern class B).
        assert!(
            merged_inputs >= 3,
            "compact_ssts must merge at least the three older SSTs \
             (merged {merged_inputs}); a vacuous 0-input compaction would make the \
             recency assertion below pass for the wrong reason"
        );

        // The NEW value flushed concurrently must win — recency was not inverted.
        assert_eq!(
            engine.get(&realm, target).expect("get target"),
            Some(new_value),
            "the concurrently flushed NEW value must not be shadowed by the \
             compaction merge of OLDER SSTs (HEA-1937 F1)"
        );
    }

    /// Encryption-at-rest: raw SST and WAL bytes must not contain plaintext.
    ///
    /// Writes a recognizable sentinel value, forces a flush to produce an SST
    /// file, then reads the raw on-disk bytes to confirm the sentinel does not
    /// appear in plaintext. Also checks the WAL file. The engine must still be
    /// able to retrieve the value through the normal read path (proving the
    /// data is encrypted, not lost).
    #[test]
    fn engine_data_is_encrypted_at_rest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let sentinel: &[u8] = b"HEARTH_ENCRYPTION_SENTINEL_XR7Q";

        let config = StorageConfig {
            data_dir: dir.path().to_path_buf(),
            wal_config: WalConfig {
                max_size: 64 * 1024 * 1024,
                sync_mode: SyncMode::None,
            },
            memtable_config: MemtableConfig {
                flush_threshold_bytes: 50,
            },
            tiered_config: TieredConfig::default(),
            allow_missing_keks: false,
            compaction: CompactionConfig::default(),
            dev_mode: true,
            block_cache_bytes: 4 * 1024 * 1024,
        };

        {
            let engine = EmbeddedStorageEngine::open(config).expect("open");
            for i in 0u32..5 {
                engine
                    .put(&realm, format!("k-{i}").as_bytes(), sentinel)
                    .expect("put");
            }
            // Engine must still be able to read back the value.
            assert_eq!(
                engine.get(&realm, b"k-0").expect("get"),
                Some(sentinel.to_vec()),
                "sentinel must be readable through the engine"
            );
        }

        // At least one SST file must exist after flush.
        let sst_files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .collect();
        assert!(
            !sst_files.is_empty(),
            "expected at least one SST file after flush"
        );

        // Raw SST bytes must not contain the sentinel in plaintext.
        for entry in &sst_files {
            let raw = std::fs::read(entry.path()).expect("read sst");
            assert!(
                !raw.windows(sentinel.len()).any(|w| w == sentinel),
                "SST file {:?} contains plaintext sentinel — encryption-at-rest not working",
                entry.path()
            );
        }

        // Raw WAL bytes must not contain the sentinel in plaintext. The WAL is
        // always created on open, so require its presence — an `if exists` guard
        // silently skipped the check if the on-disk name ever drifted.
        let wal_path = dir.path().join("hearth.wal");
        assert!(
            wal_path.exists(),
            "WAL file {wal_path:?} must exist so its encryption-at-rest is actually checked"
        );
        let raw = std::fs::read(&wal_path).expect("read wal");
        assert!(
            !raw.windows(sentinel.len()).any(|w| w == sentinel),
            "WAL file contains plaintext sentinel — WAL encryption-at-rest not working"
        );
    }

    // ── F3 regression: production() must always fsync ─────────────────────────

    /// `StorageConfig::production()` must unconditionally use `SyncMode::EveryWrite`.
    /// Before HEA-1180, the constructor accepted a `fsync: bool` that could silently
    /// disable WAL durability in production.
    #[test]
    fn production_config_always_fsyncs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StorageConfig::production(
            dir.path().to_path_buf(),
            64 * 1024 * 1024,
            4 * 1024 * 1024,
            1000,
        );
        assert_eq!(
            cfg.wal_config.sync_mode,
            SyncMode::EveryWrite,
            "production() must always use SyncMode::EveryWrite"
        );
    }

    // ── F2 regression: hot-tier get must be zero-alloc ───────────────────────

    /// Verifies that `HotTier::get` returns `Arc<[u8]>` and that the Arc is the
    /// same allocation as the one stored in the tier (pointer equality, not just
    /// value equality), confirming no extra copy was made on cache hit.
    #[test]
    fn hot_tier_get_returns_shared_arc_no_extra_copy() {
        use crate::storage::tiered::{HotTier, TieredConfig};
        let tier = HotTier::new(TieredConfig {
            hot_tier_capacity: 10,
            eviction_batch_size: 10,
            promote_sample_rate: 1,
        });
        let realm = RealmId::generate();
        tier.promote(&realm, b"key", b"data");

        let first = tier.get(&realm, b"key").expect("should be cached");
        let second = tier.get(&realm, b"key").expect("should still be cached");

        // Arc::ptr_eq checks that both point to the same backing allocation.
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "two successive gets should return the same Arc allocation"
        );
        assert_eq!(&*first, b"data" as &[u8]);
    }

    // ── F1 regression: WAL rotation must flush memtable before truncating ─────

    /// After WAL rotation, all data that was in the memtable must be readable
    /// from the SST layer. Before HEA-1180 the WAL was truncated without flushing,
    /// so a simulated kill after rotation would lose those writes.
    ///
    /// To make the crash-loss claim load-bearing (the original test only read
    /// back through the live engine, where memtable-resident keys would answer
    /// regardless of whether the flush happened), the engine is dropped and
    /// re-opened from the same directory before the final reads. A key that was
    /// truncated out of the rotated WAL without first being flushed to an SST
    /// would be unrecoverable after reopen.
    #[test]
    fn wal_rotation_flushes_memtable_to_sst_before_truncating() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        // Values are 512 bytes each.
        let big_val = vec![0xABu8; 512];

        {
            // Use a tiny WAL (4 KiB) so rotation triggers quickly.
            let mut config = StorageConfig::test_config(dir.path().to_path_buf());
            config.wal_config.max_size = 4 * 1024;
            let engine = EmbeddedStorageEngine::open(config).expect("open");

            // Write enough data to force WAL rotation.
            for i in 0u32..16 {
                engine
                    .put(&realm, format!("rot-key-{i:04}").as_bytes(), &big_val)
                    .expect("put");
            }

            // After rotation the pre_rotate_fn must have produced at least one SST.
            assert!(
                !engine.sst_readers.load().is_empty(),
                "WAL rotation must have triggered a memtable flush → at least one SST must exist"
            );
        }

        // Reopen from disk (simulates a restart): pre-rotation keys must be
        // recoverable from SSTs and post-rotation keys from the new WAL segment.
        let reopened =
            EmbeddedStorageEngine::open(StorageConfig::test_config(dir.path().to_path_buf()))
                .expect("reopen");
        for i in 0u32..16 {
            let got = reopened
                .get(&realm, format!("rot-key-{i:04}").as_bytes())
                .expect("get");
            assert_eq!(
                got.as_deref(),
                Some(big_val.as_slice()),
                "rot-key-{i:04} must survive WAL rotation + reopen (flushed, not truncated away)"
            );
        }
    }

    // ===== scan_keys tests (HEA-1622) =====

    #[test]
    fn scan_keys_returns_only_keys() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        engine
            .put(&realm, b"usr:alice", b"large-value-bytes")
            .expect("put");
        engine
            .put(&realm, b"usr:bob", b"another-large-value")
            .expect("put");
        let end = crate::storage::prefix_scan_end(b"usr:");
        let mut keys = engine.scan_keys(&realm, b"usr:", &end).expect("scan_keys");
        keys.sort();
        assert_eq!(keys, vec![b"usr:alice".to_vec(), b"usr:bob".to_vec()]);
    }

    #[test]
    fn scan_keys_excludes_tombstones() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        engine.put(&realm, b"usr:alice", b"val").expect("put");
        engine.put(&realm, b"usr:bob", b"val").expect("put");
        engine.delete(&realm, b"usr:bob").expect("delete");
        let end = crate::storage::prefix_scan_end(b"usr:");
        let keys = engine.scan_keys(&realm, b"usr:", &end).expect("scan_keys");
        assert_eq!(keys, vec![b"usr:alice".to_vec()]);
    }

    #[test]
    fn scan_keys_realm_isolation() {
        let (_dir, engine) = setup_engine();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();
        engine.put(&realm_a, b"usr:a", b"v").expect("put a");
        engine.put(&realm_b, b"usr:x", b"v").expect("put b");
        engine.put(&realm_b, b"usr:y", b"v").expect("put b2");
        let end = crate::storage::prefix_scan_end(b"usr:");
        let keys_a = engine
            .scan_keys(&realm_a, b"usr:", &end)
            .expect("scan_keys");
        assert_eq!(keys_a, vec![b"usr:a".to_vec()]);
    }

    #[test]
    fn scan_keys_empty_prefix_returns_empty() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        engine.put(&realm, b"usr:x", b"v").expect("put");
        // Empty start==end means no range → empty
        let keys = engine.scan_keys(&realm, b"", b"").expect("scan_keys");
        assert!(keys.is_empty());
    }

    // ===== count_prefix / scan_prefix_paged tests (HEA-1616) =====

    fn put_prefixed(engine: &EmbeddedStorageEngine, realm: &RealmId, prefix: &str, n: usize) {
        for i in 0..n {
            let key = format!("{prefix}:{i:05}");
            engine
                .put(realm, key.as_bytes(), b"v")
                .expect("put in put_prefixed");
        }
    }

    #[test]
    fn count_prefix_zero_when_empty() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        let count = engine.count_prefix(&realm, b"usr:", 10_000).expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn count_prefix_exact_count() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        put_prefixed(&engine, &realm, "usr:", 7);
        let count = engine.count_prefix(&realm, b"usr:", 10_000).expect("count");
        assert_eq!(count, 7);
    }

    #[test]
    fn count_prefix_caps_at_cap() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        // Insert 20 items but cap at 10 — count must be capped.
        put_prefixed(&engine, &realm, "usr:", 20);
        let count = engine.count_prefix(&realm, b"usr:", 10).expect("count");
        assert_eq!(count, 10);
    }

    #[test]
    fn count_prefix_cap_boundary_exact() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        put_prefixed(&engine, &realm, "usr:", 10);
        // Exactly cap many items — count must equal cap.
        let count = engine.count_prefix(&realm, b"usr:", 10).expect("count");
        assert_eq!(count, 10);
    }

    #[test]
    fn count_prefix_realm_isolation() {
        let (_dir, engine) = setup_engine();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();
        put_prefixed(&engine, &realm_a, "usr:", 5);
        put_prefixed(&engine, &realm_b, "usr:", 99);
        // realm_a's count must not be affected by realm_b's data.
        let count = engine
            .count_prefix(&realm_a, b"usr:", 10_000)
            .expect("count");
        assert_eq!(count, 5);
    }

    #[test]
    fn scan_prefix_paged_offset_zero() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        put_prefixed(&engine, &realm, "usr:", 15);
        let (window, total) = engine
            .scan_prefix_paged(&realm, b"usr:", 0, 5, 10_000)
            .expect("paged scan");
        assert_eq!(total, 15);
        assert_eq!(window.len(), 5);
    }

    #[test]
    fn scan_prefix_paged_offset_mid() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        put_prefixed(&engine, &realm, "usr:", 15);
        let (window, total) = engine
            .scan_prefix_paged(&realm, b"usr:", 10, 5, 10_000)
            .expect("paged scan");
        assert_eq!(total, 15);
        assert_eq!(window.len(), 5);
    }

    #[test]
    fn scan_prefix_paged_offset_past_end() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        put_prefixed(&engine, &realm, "usr:", 5);
        let (window, total) = engine
            .scan_prefix_paged(&realm, b"usr:", 100, 10, 10_000)
            .expect("paged scan");
        assert_eq!(total, 5, "total still reflects full count");
        assert!(window.is_empty(), "past-end offset returns no items");
    }

    #[test]
    fn scan_prefix_paged_last_page_partial() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        put_prefixed(&engine, &realm, "usr:", 7);
        // Offset 5, limit 10 — only 2 items remain.
        let (window, total) = engine
            .scan_prefix_paged(&realm, b"usr:", 5, 10, 10_000)
            .expect("paged scan");
        assert_eq!(total, 7);
        assert_eq!(window.len(), 2);
    }

    #[test]
    fn scan_prefix_paged_empty_store() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        let (window, total) = engine
            .scan_prefix_paged(&realm, b"usr:", 0, 10, 10_000)
            .expect("paged scan on empty store");
        assert_eq!(total, 0);
        assert!(window.is_empty());
    }

    #[test]
    fn scan_prefix_paged_realm_isolation() {
        let (_dir, engine) = setup_engine();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();
        put_prefixed(&engine, &realm_a, "usr:", 3);
        put_prefixed(&engine, &realm_b, "usr:", 50);
        let (window, total) = engine
            .scan_prefix_paged(&realm_a, b"usr:", 0, 100, 10_000)
            .expect("paged scan");
        assert_eq!(total, 3);
        assert_eq!(window.len(), 3);
    }

    #[test]
    fn scan_prefix_paged_total_is_capped() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        put_prefixed(&engine, &realm, "usr:", 20);
        let cap = 10;
        let (window, total) = engine
            .scan_prefix_paged(&realm, b"usr:", 0, 5, cap)
            .expect("paged scan");
        assert_eq!(total, cap, "total must be capped at cap value");
        assert_eq!(window.len(), 5);
    }

    // ===== HEA-1622: two-phase paged scan (key-only count + bounded value scan) =====

    #[test]
    fn scan_prefix_paged_window_carries_values() {
        // Values must be present in the window even with the two-phase approach.
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        for i in 0..10u32 {
            let key = format!("usr:{i:04}");
            let val = format!("val-{i}");
            engine
                .put(&realm, key.as_bytes(), val.as_bytes())
                .expect("put");
        }
        let (window, total) = engine
            .scan_prefix_paged(&realm, b"usr:", 3, 4, 0)
            .expect("paged scan");
        assert_eq!(total, 10);
        assert_eq!(window.len(), 4);
        // Key ordering must be preserved and values must match keys.
        assert_eq!(window[0].key, b"usr:0003");
        assert_eq!(window[0].value, b"val-3");
        assert_eq!(window[3].key, b"usr:0006");
        assert_eq!(window[3].value, b"val-6");
    }

    #[test]
    fn scan_prefix_paged_last_window_bounded_correctly() {
        // Last page: window touches the end — win_end falls back to prefix_end.
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        for i in 0..7u32 {
            engine
                .put(&realm, format!("usr:{i:04}").as_bytes(), b"v")
                .expect("put");
        }
        let (window, total) = engine
            .scan_prefix_paged(&realm, b"usr:", 5, 10, 0)
            .expect("paged scan");
        assert_eq!(total, 7);
        assert_eq!(window.len(), 2);
        assert_eq!(window[0].key, b"usr:0005");
        assert_eq!(window[1].key, b"usr:0006");
    }

    // ===== HEA-1614: cap == 0 means "no ceiling" (exact total) =====

    #[test]
    fn count_prefix_cap_zero_means_uncapped() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        put_prefixed(&engine, &realm, "usr:", 12);
        // `cap == 0` must report the exact count, not `min(12, 0) == 0`.
        let count = engine.count_prefix(&realm, b"usr:", 0).expect("count");
        assert_eq!(count, 12);
    }

    // ===== Directory-lock tests =====

    #[test]
    fn dir_lock_second_open_fails_with_already_locked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config1 = StorageConfig::test_config(dir.path().to_path_buf());
        let engine1 = EmbeddedStorageEngine::open(config1).expect("first open should succeed");

        // Second open on the same dir must fail.
        let config2 = StorageConfig::test_config(dir.path().to_path_buf());
        let err =
            EmbeddedStorageEngine::open(config2).expect_err("second open on same dir must fail");
        assert!(
            matches!(err, StorageError::AlreadyLocked { .. }),
            "expected AlreadyLocked, got: {err}"
        );

        // After the first engine is dropped the directory is unlocked.
        drop(engine1);
        let config3 = StorageConfig::test_config(dir.path().to_path_buf());
        EmbeddedStorageEngine::open(config3)
            .expect("open after drop of first engine should succeed");
    }

    #[test]
    fn scan_prefix_paged_cap_zero_reports_exact_total_above_default() {
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        // More than DEFAULT_COUNT_CAP (10_000) rows. `cap == 0` must NOT
        // truncate the reported total to 10_000 — the admin UI needs the true
        // count to page through the whole realm (HEA-1614 large-scale seeder).
        let n = 10_050usize;
        let puts: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
            .map(|i| (format!("usr:{i:06}").into_bytes(), b"v".to_vec()))
            .collect();
        engine
            .write_batch(&realm, &puts, &[])
            .expect("batch insert");
        let (window, total) = engine
            .scan_prefix_paged(&realm, b"usr:", 0, 25, 0)
            .expect("paged scan");
        assert_eq!(
            total, n as u64,
            "cap=0 must report the true total, not the 10k cap"
        );
        assert_eq!(window.len(), 25);
    }

    // ── list_realms (HEA-2131) ────────────────────────────────────────────────

    #[test]
    fn list_realms_empty_engine_returns_empty() {
        let (_dir, engine) = setup_engine();
        let realms = engine.list_realms().expect("list_realms");
        assert!(realms.is_empty(), "fresh engine must report no realms");
    }

    #[test]
    fn list_realms_returns_written_realms() {
        let (_dir, engine) = setup_engine();
        let r1 = RealmId::generate();
        let r2 = RealmId::generate();

        engine.put(&r1, b"k1", b"v1").expect("put r1");
        engine.put(&r2, b"k2", b"v2").expect("put r2");

        let mut realms = engine.list_realms().expect("list_realms");
        realms.sort();
        let mut expected = vec![r1.clone(), r2.clone()];
        expected.sort();
        assert_eq!(
            realms, expected,
            "list_realms must include all written realms"
        );
    }

    #[test]
    fn list_realms_includes_tombstone_only_realms() {
        // A realm where all keys are deleted still appears: scan on it returns empty
        // (correct), so Phase 1 of snapshot install calls write_batch with an empty
        // delete list (a no-op). The important invariant is it does NOT panic.
        let (_dir, engine) = setup_engine();
        let realm = RealmId::generate();
        engine.put(&realm, b"k", b"v").expect("put");
        engine.delete(&realm, b"k").expect("delete");

        let realms = engine.list_realms().expect("list_realms");
        assert!(
            realms.contains(&realm),
            "a tombstone-only realm must still appear in list_realms"
        );
    }

    #[test]
    fn list_realms_sees_data_in_sst_after_flush() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Small flush threshold so writing a few entries triggers an SST flush.
        let mut config = StorageConfig::test_config(dir.path().to_path_buf());
        config.memtable_config.flush_threshold_bytes = 1; // flush immediately
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        let r1 = RealmId::generate();
        let r2 = RealmId::generate();
        engine.put(&r1, b"k1", b"v1").expect("put r1");
        engine.put(&r2, b"k2", b"v2").expect("put r2");

        let mut realms = engine.list_realms().expect("list_realms after sst flush");
        realms.sort();
        let mut expected = vec![r1.clone(), r2.clone()];
        expected.sort();
        assert_eq!(
            realms, expected,
            "list_realms must include realms whose data flushed to SST files"
        );
    }
}
