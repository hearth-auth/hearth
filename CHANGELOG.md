# Changelog

All notable changes to Hearth will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Hearth has not yet cut a versioned release; all shipped work appears under `[Unreleased]`.

## [Unreleased]

### Security

- **WAL rotation must flush memtable before truncating (HEA-1180 / F1)** —
  `Wal::rotate_locked` truncated the WAL file before the in-memory memtable had
  been written to an SST. A `kill -9` between truncation and the next regular
  memtable flush would lose every write since the last SST flush. Fixed: the WAL
  now accepts a pre-rotation callback; `EmbeddedStorageEngine` injects a
  memtable→SST flush so all data is durable before the segment is reused. Regression
  test `wal_rotation_flushes_memtable_to_sst_before_truncating` added.

- **`StorageConfig::production()` always enforces fsync (HEA-1180 / F3)** —
  the constructor accepted a `fsync: bool` parameter that, when `false`, silently
  produced `SyncMode::None` and disabled WAL durability in production. Removed the
  parameter; `production()` now unconditionally uses `SyncMode::EveryWrite`.
  Operators who need fsync off must use `StorageConfig::dev()` or construct
  `WalConfig` directly. A `tracing::warn!` is emitted when a legacy config file
  has `fsync: false` and the production constructor is in use. Regression test
  `production_config_always_fsyncs` added.

### Performance

- **Hot-tier cache hits are now zero-alloc (HEA-1180 / F2)** —
  `HotTier::get` previously made two heap allocations on every cache hit: one to
  build a lookup `CompositeKey` (owned `Vec<u8>`) and one to clone the cached
  `Vec<u8>` value. Both are eliminated: the lookup now uses
  `hashbrown::HashMap::raw_entry` with a computed hash and a borrow-comparison
  closure (no key allocation), and cached values are stored as `Arc<[u8]>` so hits
  return a refcount increment instead of a `memcpy`. Regression test
  `hot_tier_get_returns_shared_arc_no_extra_copy` added.

### Security (continued)

- **gRPC cross-realm BFLA (HEA-799)** — all five realm-management gRPC handlers
  (`list_realms`, `get_realm`, `create_realm`, `update_realm`, `delete_realm`) previously
  discarded the authenticated realm (`_auth`) and operated on any caller-supplied realm ID.
  An admin of realm A could read, modify, or destroy realm B with a valid realm-A token.
  Fixed: each handler now enforces that regular realm admins may only operate on their own
  realm; only system-realm admins may act cross-realm or create new realms. Regression tests
  added in `tests/grpc_cross_realm_bfla.rs` (HEA-799).
