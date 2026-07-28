## Storage & Cluster Behaviors

Code-derived inventory of observable behaviors in `src/storage/` (WAL, memtable, SSTs, tiered storage, atomicity, realm isolation, crash recovery, compaction) and `src/cluster/` (openraft consensus, single-node bypass, membership). One row per distinct behavior an integration or black-box test could target. Entry points are public/`pub(crate)` traits and functions; file:line refer to definitions.

### Storage engine — public trait surface (`StorageEngine`)

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Point read by realm+key; `None` if absent | `StorageEngine::get` | src/storage/mod.rs:65 | ARCHITECTURE §1.3, §7.1 |
| Insert/update a key for a realm | `StorageEngine::put` | src/storage/mod.rs:68 | ARCHITECTURE §6.1 |
| Delete a key (tombstone) for a realm | `StorageEngine::delete` | src/storage/mod.rs:71 | ARCHITECTURE §7.3 |
| Range scan `[start,end)`, sorted, merged across memtable+SST | `StorageEngine::scan` | src/storage/mod.rs:76 | ARCHITECTURE §7.1 (bounded scans) |
| Atomic multi-put batch (all-or-nothing after crash) | `StorageEngine::put_batch` | src/storage/mod.rs:94 | ARCHITECTURE §6.1 (atomic batch writes) |
| Compare-and-set write only if key absent (no TOCTOU; Raft-routed in cluster) | `StorageEngine::put_if_absent` | src/storage/mod.rs:118 | ARCHITECTURE §32 (cluster) |
| Key-only range scan (no value allocation) | `StorageEngine::scan_keys` | src/storage/mod.rs:140 | ARCHITECTURE §3.x (alloc discipline) |
| Count entries under a prefix with optional cap ceiling | `StorageEngine::count_prefix` | src/storage/mod.rs:158 | ARCHITECTURE §7.1 |
| Offset-paginated prefix scan returning window+total | `StorageEngine::scan_prefix_paged` | src/storage/mod.rs:188 | ARCHITECTURE §7.1 |
| Atomic mixed puts+deletes batch (crash-safe unit) | `StorageEngine::write_batch` | src/storage/mod.rs:237 | ARCHITECTURE §6.1 |
| Exclusive prefix end-bound helper for scans | `prefix_scan_end` | src/storage/mod.rs:51 | ARCHITECTURE §7.1 |

### Storage engine — embedded implementation & lifecycle

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Open engine; WAL replay reconstructs memtable state on startup | `EmbeddedStorageEngine::open` | src/storage/engine.rs:225 | ARCHITECTURE §6.1 (WAL replay) |
| Dev config (no fsync, `SyncMode::None`) | `StorageConfig::dev` | src/storage/engine.rs:71 | CONFIGURATION; validate.rs dev overrides |
| Production config always fsyncs (`SyncMode::EveryWrite`, non-negotiable) | `StorageConfig::production` | src/storage/engine.rs:95 | ARCHITECTURE §6.1; F3 regression test engine.rs:1929 |
| Manual SST compaction when count ≥ threshold; merges + drops tombstones | `EmbeddedStorageEngine::compact_ssts` | src/storage/engine.rs:575 | ARCHITECTURE §6.2, §7.3 (physical deletion) |
| Debug-mode realm-mismatch tripwire on returned records | `EmbeddedStorageEngine::get` (impl) | src/storage/engine.rs:664 | ARCHITECTURE §7.2 (runtime assertions) |

### WAL

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Append entry; fsync before ack when `SyncMode::EveryWrite` | `Wal::append` | src/storage/wal.rs:560 | ARCHITECTURE §6.1 |
| Append with segment pre-rotation hook | `Wal::append_with_pre_rotate` | src/storage/wal.rs:575 | ARCHITECTURE §6.4 (segments) |
| Sync mode enum (EveryWrite vs None) governs durability | `SyncMode` | src/storage/wal.rs:364 | ARCHITECTURE §6.1 |
| Explicit fsync of WAL file | `Wal::sync` (fsync) | src/storage/wal.rs:749 | ARCHITECTURE §6.1 |
| Deserialize entry; reject bad-CRC / truncated tail (crash safety) | `WalEntry::deserialize` | src/storage/wal.rs (fuzz target fuzz/…/wal_entry_deserialize.rs) | ARCHITECTURE §6.1; sim wal_crash.rs |

### Memtable / SST

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Memtable point read | `Memtable::get` | src/storage/memtable.rs:267 | ARCHITECTURE §6.1 |
| Flush memtable to SST under lock (snapshot-then-empty; preserves data on error) | `Memtable::flush_under_lock` | src/storage/memtable.rs:204 | ARCHITECTURE §6.1 |
| SST open / point read | `Sst::open`, `Sst::get` | src/storage/sst.rs:338, 490 | ARCHITECTURE §6.2 |
| Compaction merges, dedups, removes tombstones | `sst::compact` / `compact_with_fs` | src/storage/sst.rs:729, 747 | ARCHITECTURE §6.2, §7.3 |

### Tiered storage (hot/cold)

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Hot-tier lock-free read (Arc value) | `HotTier::get` | src/storage/tiered.rs:128 | ARCHITECTURE §3.2 (no locks on read), §6.2 |
| Cold→hot promotion (async, non-blocking to readers; probabilistic admission) | `HotTier::promote` | src/storage/tiered.rs:162 | ARCHITECTURE §6.2 (promotion non-blocking) |
| Hot-tier membership check | `HotTier::contains` | src/storage/tiered.rs:284 | ARCHITECTURE §6.2 |
| Hot-tier occupancy (eviction bound) | `HotTier::len` | src/storage/tiered.rs:279 | ARCHITECTURE §6.2 (eviction non-blocking) |

### Encryption at rest / key registry

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Per-realm envelope encryption of values at rest | `src/storage/encryption.rs` | src/storage/encryption.rs | ARCHITECTURE §6.3 |
| KEK registry persisted to `hearth.keys` with CRC framing + fsync (tmp→fsync→rename) | `src/storage/key_registry.rs` | src/storage/key_registry.rs:255, 495 | ARCHITECTURE §6.3 |
| Storage format migrations on startup | `src/storage/migrations.rs` | src/storage/migrations.rs | ARCHITECTURE §6.4 |

### Realm isolation & lifecycle (cross-layer, storage-enforced)

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Every op requires `RealmId` newtype; keys realm-prefixed; scans single-realm bounded | `StorageEngine` trait (all methods) | src/storage/mod.rs:63 | ARCHITECTURE §7.1 |
| Realm deletion cascade writes tombstones across all prefixes (idempotent) | `IdentityEngine::delete_realm` | src/identity/engine/mod.rs:4691 | ARCHITECTURE §7.3; sim realm_crash.rs |

### Cluster — engine wrapper (`ClusterEngine`)

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Single-node bypass (writes go direct to storage, zero Raft overhead) | `ClusterEngine::single_node` | src/cluster/engine.rs:98 | ARCHITECTURE §32 (invisible single-node) |
| Build clustered engine (openraft, mTLS network) | `ClusterEngine::build_clustered` | src/cluster/engine.rs:114 | ARCHITECTURE §32 |
| Initialize cluster membership | `ClusterEngine::initialize_cluster` | src/cluster/engine.rs:201 | ARCHITECTURE §32 (membership) |
| Expose Raft metrics (leader/lag/term) | `ClusterEngine::raft_metrics` | src/cluster/engine.rs:216 | ARCHITECTURE §32.1 |
| Follower read staleness threshold (default lag ceiling) | `ClusterEngine::read_lag_threshold_ms` | src/cluster/engine.rs:221 | ARCHITECTURE §32.1 (bounded staleness, 500ms) |
| Graceful leadership transfer on shutdown | `ClusterEngine::transfer_leadership` | src/cluster/engine.rs:255 | ARCHITECTURE §12 (drain), §457 |
| Leader-routed get/put/delete/scan/put_batch/put_if_absent through Raft | `ClusterEngine::{get,put,delete,scan,put_batch,put_if_absent}` | src/cluster/engine.rs:370–493 | ARCHITECTURE §32 (writes via Raft) |
| Storage-trait adapter wrapping cluster engine | `ClusterStorageAdapter::new` | src/cluster/engine.rs:659 | ARCHITECTURE §1.3 |

### Cluster — openraft trait implementations & RPC

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| State machine applies committed entries to storage | `HearthStateMachine::apply` | src/cluster/state_machine.rs:203 | ARCHITECTURE §32 (RaftStateMachine) |
| Raft log store: append/read/open (redb-backed) | `HearthLogStore::open`, `append` | src/cluster/log_store.rs:195, 339 | ARCHITECTURE §32 (RaftLogStorage) |
| Outgoing peer RPC over lazy mTLS gRPC (AppendEntries/Vote/InstallSnapshot) | `HearthNetworkFactory` / `HearthPeerNetwork::append_entries` | src/cluster/network.rs:156 | ARCHITECTURE §32 |
| Incoming Raft RPC server (tonic + mTLS) dispatch | `serve`, `RaftRpcHandler`, `IncomingRpcDispatch` | src/cluster/server.rs:124, 28 | ARCHITECTURE §32 |
| Log-data / command / node types + Raft config | `HearthLogData`, `RaftCommand`, `HearthNode`, `HearthRaftConfig` | src/cluster/types.rs | ARCHITECTURE §32 |

### Notes: untested / undocumented observations

- **`put_if_absent` cluster path** (mod.rs:118) documents Raft-routed atomicity, but the trait default is a non-atomic get+put "correct only for single-node." A black-box test asserting cross-node atomicity would exercise `ClusterEngine::put_if_absent` (engine.rs:493) — the atomic guarantee lives only in the cluster impl.
- **Follower bounded-staleness enforcement** (ARCHITECTURE §32.1: follower MUST stop serving reads past the lag threshold and redirect to leader). `read_lag_threshold_ms` exists (engine.rs:221) but I found no read-rejection/redirect entry point in `ClusterEngine::get` — the enforcement side of the spec looks unimplemented or untested at the storage boundary.
- **Format versioning / previous-minor read** (ARCHITECTURE §6.4): `migrations.rs` is small (3.7k) and greenfield notes say no migration tooling — the "read previous minor version WAL/SST" MUST is likely aspirational, not test-covered.
- **Encryption-at-rest** (encryption.rs) and **WAL per-segment DEK** (§6.3): confirmed present in code, but no dedicated storage-encryption entry point surfaced in the public trait — coverage lives in module tests, not black-box reachable.
- Crash-recovery behaviors (WAL bad-CRC/truncation discard, rotation crash) are covered by `simulation/src/tests/wal_crash.rs` and `wal_rotation_crash.rs` (madsim), not by the standard nextest black-box harness.
