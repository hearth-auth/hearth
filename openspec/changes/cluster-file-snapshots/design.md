## Context

**Today.** `HearthRaftConfig::SnapshotData` is `std::io::Cursor<Vec<u8>>`. `HearthSnapshotBuilder::build_snapshot` scans every realm of the live engine into a `Vec<RealmData>`, encodes it as CBOR, gzips it, and keeps the compressed bytes in `current_snapshot` to serve followers. `begin_receiving_snapshot` returns an empty `Cursor`; openraft writes every chunk into it. `install_snapshot` decompresses the whole payload, then `restore_snapshot_in_place` writes a marker, deletes every key of every realm (Phase 1: one `scan` per realm into a `Vec` of keys), writes the payload (Phase 2: one `put_batch` per realm), writes the applied state and removes the marker. Nothing is on disk, so a restarted node has no snapshot; openraft builds one at start-up when its log was purged (`StorageHelper::get_initial_state`).

**openraft 0.9.25.** `SnapshotData` must be `AsyncRead + AsyncWrite + AsyncSeek + Unpin + Send + 'static`. The leader sends with `Chunked::send_snapshot`: `seek(End(0))` for the length, then for each chunk `seek(Start(offset))` and up to `snapshot_max_chunk_size` (4 MiB here) of `read_buf`. The receiver (`Chunked::receive_snapshot`) calls `begin_receiving_snapshot` at offset 0, `seek` when the offset is not the next one, `write_all` for each chunk, and, on the last chunk, `shutdown()`. A `shutdown` error goes back to the sender as the RPC's error; the receiving Raft core is not involved, and the leader's replication retries from offset 0 (`SnapshotMismatch` on the next chunk). An error from `RaftStateMachine::install_snapshot` instead stops the receiving node's Raft core. The last chunk's RPC covers the install, under `install_snapshot_timeout` (default 200 ms).

**Keys.** The storage engine encrypts SST and WAL files with a random data key per file, wrapped by the system realm's KEK (a 76-byte header: KEK id, nonce, wrapped key, tag). The KEKs live in `hearth.keys`, wrapped by the host key (`HEARTH_MASTER_KEY`). Each node creates its own system KEK on first open, so two nodes never share it. Backups use a different model: a portable archive, chunked AES-256-GCM (`src/backup/stream.rs`) under a key wrapped by an operator passphrase.

**Point in time.** `StorageEngine::read_snapshot()` (#643) returns a read-only view of the engine at one moment, after a memtable flush. Its `visit_entries` streams rows and skips the shared block cache.

## Goals / Non-Goals

**Goals:**
- A 1M-user snapshot (about 2 GB) builds and installs with less than 512 MiB of extra memory on each side.
- The snapshot holds exactly the entries up to its declared index (#818).
- No plaintext copy of the store on disk.
- A received snapshot is checked before the store changes; a bad one costs a resend, not a node.
- A node keeps its snapshot across a restart.

**Non-Goals:**
- Resuming a transfer after a restart of either side. openraft's receive state is in memory; a new transfer starts at offset 0.
- Resuming a torn install from the snapshot file. A crash between the restore marker and its removal still refuses the restart (HEA-2132). The file would make a resume possible; that is a follow-up.
- The snapshot policy (every 5,000 entries) and `max_in_snapshot_log_to_keep`.
- G3 (node-local tracker rows travel in snapshots).

## Decisions

### 1. `SnapshotData` is a file, behind a small async adapter

`SnapshotData = SnapshotFile`. `SnapshotFile` wraps a synchronous sealed file (decision 3) and runs every read, write, seek and shutdown on the blocking pool, the way `tokio::fs::File` does: one operation in flight, a write is accepted at once and its error reported by the next call. openraft's 4 MiB reads and writes become one blocking task each.

| Option | Pros | Cons |
|---|---|---|
| **A. Keep openraft's chunked transport; a file type that encrypts at rest and serves plaintext** | No proto or network change; each node's key stays on that node | A seekable encrypted file and an async adapter to write |
| B. `generic-snapshot-data` and a Hearth streaming RPC | Full control of the transfer, resume possible | A new peer RPC (`raft.proto`), a second transfer path to test, larger change |
| C. `SnapshotData = tokio::fs::File` holding ciphertext under one cluster-wide key (derived from `HEARTH_MASTER_KEY`) | Simplest code; ciphertext on the wire too | Needs the same host key on every node, including `--dev` and in-process test clusters, which each make their own `hearth.host_key`; a host-key rotation in progress breaks transfers; not how the store encrypts files |

**Choice: A.**

### 2. Two layers: a portable record stream inside a node-local sealed file

The **stream** is what openraft sends, so it is the same on every node: an 8-byte magic `HRSNAP01`, then one zstd frame (level 1) of records:

| Tag | Record | Body |
|---|---|---|
| `0x01` | META, exactly once, first | `u32` length, JSON `SnapshotMeta` |
| `0x02` | REALM | 16-byte realm UUID |
| `0x03` | ROW, only after a REALM | `u32` key length, key, `u32` value length, value |
| `0x04` | END, exactly once, last | `u64` realms, `u64` rows, SHA-256 of every record byte before END |

Integers are little-endian. The decoder refuses an unknown tag, a ROW before any REALM, a key or a value over 16 MiB (the builder refuses to write one), a second META, bytes after END, and an END whose counts or digest do not match. It holds one row at a time. The applied-state rows (`\0raft:sm:applied`, `\0raft:sm:membership`) stay out of the stream, as today. zstd replaces gzip: it is faster at the same ratio, and the crate is already a dependency (backups).

The **sealed file** is how a node keeps the stream on disk: an 8-byte magic `HSEALF01`, the 76-byte wrapped-key header that SST and WAL files use (a new random data key per file, wrapped by the system KEK), then chunks. Each chunk is a 12-byte random nonce, the AES-256-GCM ciphertext of 64 KiB of plaintext (the last chunk 0–64 KiB), and a 16-byte tag. The additional data of chunk `i` is the file header, `i` as a big-endian `u64`, and a last-chunk flag, so a changed, moved, dropped or appended chunk fails its tag, and a file cut after a full chunk has no chunk sealed as last. Chunks have a fixed size, so plaintext offset `p` is in chunk `p / 64 KiB`: openraft's seeks need no index. A random nonce per chunk keeps a chunk that is written again (after a backward seek on a retried transfer chunk) from reusing a nonce.

| Option | Pros | Cons |
|---|---|---|
| **A. Per-file key wrapped by the system KEK (as SST/WAL)** | Same keys, rotation and failure modes as the store; nothing new for an operator | A KEK rotation that drops the old KEK makes an older snapshot file unreadable; the node then deletes it and builds a new one |
| B. The backup format (passphrase-wrapped key) | Existing code | Needs an operator secret on every node; not seekable |
| C. Plaintext file, rely on disk encryption | Least code | A plaintext copy of every row, including password hashes and wrapped keys, beside an encrypted store |

**Choice: A.** The sealed-file module lives in `src/storage/` (it needs the KEK registry); the cluster layer gets a handle from `EmbeddedStorageEngine`. Its I/O goes through the engine's `Fs`, so `FaultFs` can inject faults; `FsFile` gains a partial `read`.

### 3. Layout and clean-up under the data directory

Files live in `{data_dir}/raft-snapshots/`:

| Name | Meaning |
|---|---|
| `build-<uuid>.part` | A build in progress |
| `recv-<uuid>.part` | A transfer in progress, or received and checked but not installed |
| `snap-<uuid>.snap` | The node's current snapshot (built, or installed) |

Names are local UUIDs, never the leader's `snapshot_id`, which arrives over the network. A file becomes `snap-*` only by rename after `fsync`, followed by a directory `fsync`. A node keeps one `snap-*`: when a newer one is offered, the older file is unlinked (an open reader keeps its inode until it finishes sending). At start-up the node deletes every `*.part`, reads the META of every `snap-*`, keeps the newest whose `last_log_id` is at or below the store's applied index, checks it end to end, and deletes the rest. A snapshot ahead of the applied index is never offered to openraft: openraft would take it as covering entries the store does not hold. A file that fails the check is deleted with a warning; openraft builds a new one if its log was purged.

**Disk need:** up to two snapshot files (about the compressed store size each) plus, while a build runs, the SST files its read snapshot keeps alive past compaction. No config key: the location is fixed, like `raft.db` and `hearth.keys`. Backups do not need the directory: a node rebuilds it, and a restore starts a node from a backup, not from a snapshot.

### 4. The build reads one point in time (#818)

`get_snapshot_builder` runs inside openraft's state-machine worker, so no entry applies while it runs. It takes `engine.read_snapshot()` there (on the blocking pool: it flushes the memtable) together with `last_applied` and the membership. `build_snapshot` then streams every realm of that view into `build-<uuid>.part` while the worker applies more entries against the live engine. The view holds exactly the entries up to `last_applied`, so a follower that installs the snapshot and replays from `last_applied + 1` applies each entry once. If the engine has no read snapshot (a test double), the build reads the live engine, as today, and logs it at `debug`.

This fixes #818. The W5 sidecar logic stays: it also covers the case where a node re-applies entries after a restart in the middle of an install.

### 5. A received snapshot is checked at the end of the transfer

`SnapshotFile::shutdown` on a received file seals the last chunk, `fsync`s the file, then reads the whole file back: every chunk tag, the record stream and the END record. Only then does openraft call `install_snapshot`. A failure returns an error from the last chunk's RPC; the store is untouched, the node's Raft core keeps running, and the leader sends the snapshot again from offset 0. `install_snapshot` still compares the file's META with openraft's `meta` (snapshot id, last log id, membership) before the restore and refuses a mismatch.

| Option | Pros | Cons |
|---|---|---|
| **A. Check in `shutdown`, before openraft installs** | A bad transfer costs a resend; nothing deleted | One extra read of the file (decrypt + decompress, seconds at 2 GB) |
| B. Check inside `install_snapshot` before Phase 1 | Same read | A failure there stops the node's Raft core |
| C. Check while restoring | No extra read | A failure in Phase 2 leaves a torn store |

**Choice: A**, plus the META comparison in `install_snapshot`.

### 6. The restore is streamed, in the same phases

`restore_snapshot_in_place` keeps its order: restore marker, Phase 1 (delete every key of every realm on disk), Phase 2 (write the snapshot's rows), the applied-state rows, marker removal. Phase 1 collects at most 4,096 keys or 4 MiB with `visit_keys`, deletes them in one `write_batch`, and continues after the last key. Phase 2 decodes the file and writes rows in batches of at most 4,096 rows or 4 MiB with `put_batch`. Each batch is durable before the next (WAL `fsync`). The function takes a stream reader instead of a decoded payload; its signature and its call site in `install_snapshot` stay where `cluster-read-fencing` closes its gate (before the call, reopened after `on_replicated_reset`).

### 7. Durability before an acknowledgement

- Build: seal, `fsync` the file, rename to `snap-*`, `fsync` the directory, then offer it.
- Receive: seal and `fsync` before the check (decision 5).
- Install: every restore batch is durable; after the marker is removed, the file is renamed `recv-*` → `snap-*` and the directory `fsync`ed before `install_snapshot` returns, so the node's answer to the last chunk means the store and the snapshot file are both on disk.

### 8. The last chunk's timeout covers an install

openraft applies `install_snapshot_timeout` to every chunk and to the last one, whose RPC includes the check and the install. At the default 200 ms a large install always times out on the leader, which then sends the whole snapshot a second time (the second install is a no-op, because the snapshot is no longer newer). Hearth sets it to 15 minutes. A non-last chunk to a peer that does not answer then waits up to 15 minutes, but only that peer's snapshot task waits: heartbeats and other peers continue. Task 3.8 checks the value against the measured 1M-user install time.

### 9. Chunk and batch sizes

| Size | Value | Why |
|---|---|---|
| Transfer chunk | 4 MiB (`SNAPSHOT_CHUNK_BYTES`, unchanged) | Well under the 16 MiB peer message limit |
| Sealed chunk | 64 KiB | 28 bytes overhead per chunk (0.04 %); a seek decrypts at most one chunk |
| Restore batch | 4,096 rows or 4 MiB | One WAL commit per batch; bounded memory |
| zstd | level 1 | Speed: the build holds its read snapshot until it ends |

## Risks / Trade-offs

- [A node runs out of disk during a build or receive] → The write fails, the `.part` file is deleted, the build or transfer fails and is retried; the store is not touched. The disk need is documented (decision 3).
- [The read snapshot keeps SSTs alive during a long build] → Compaction frees them after the build. A build at 1M users takes seconds to tens of seconds (measured in task 3.8).
- [Start-up reads the whole snapshot file once] → Seconds at 2 GB. It keeps a corrupt file from reaching openraft's sender, where a read error stops the leader's Raft core.
- [Format change] → Mixed-release clusters cannot exchange snapshots: the check refuses the stream magic, and the leader keeps retrying. Cluster mode is experimental; upgrade all nodes together.

## Migration Plan

Nothing to migrate: today's snapshots are never on disk. A node on this release builds its first file snapshot on its next snapshot trigger, or at start-up when its log was purged. Rollback: an older release ignores `raft-snapshots/`.

## Open Questions

None. The owner may want the snapshot policy (every 5,000 entries, a full build each time) revisited for large stores; that is outside this change.
