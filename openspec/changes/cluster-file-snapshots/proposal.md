## Why

A cluster node keeps its Raft snapshot in memory only (`docs/guides/clustering.md` P-2; `SnapshotData = std::io::Cursor<Vec<u8>>` in `src/cluster/types.rs`). At 1M users a snapshot is about 2 GB. The leader builds it as several full copies at once: every row in a `Vec`, then the whole CBOR encoding, then the gzip output, which it keeps afterwards. The receiving node buffers every chunk in one `Vec` and then decompresses all of it before it writes a row. A node on a 4 GiB server can run out of memory when a follower or a new node catches up by snapshot. A restarted node has no snapshot until it builds a new one.

The build also reads the live engine, not one point in time (#818). A snapshot labelled with index N can hold effects of entries after N, so a node that installs it and then replays N+1… applies some entries twice.

Online membership changes (`cluster-membership-changes`, PR #942) need this first: a new node at 1M users catches up by snapshot. The owner approved on 2026-11-26 that P-2 comes first.

## What Changes

- Snapshots are files under the data directory, `{data_dir}/raft-snapshots/`. The leader streams rows into the file; openraft sends it in the existing 4 MiB chunks; the receiving node writes each chunk to a file and installs from the file in bounded batches. Memory on each side no longer grows with the store.
- Snapshot files are encrypted at rest the way SST and WAL files are: a random per-file key wrapped by the node's storage key-encryption key, and AES-256-GCM over fixed-size chunks.
- A received snapshot is checked end to end (every chunk tag, the record stream, row and realm counts, a SHA-256 digest) before the node deletes any key. A snapshot that fails the check leaves the store as it was, and the leader sends it again.
- The build reads one point in time: a storage read snapshot taken while the state machine is held, so the data and the declared index agree (#818).
- A built or installed snapshot is made durable (file `fsync`, rename, directory `fsync`) before the node reports it. After a restart the node loads it and serves it without a rebuild. Partial files left by a crash are removed at startup.
- **BREAKING (cluster only):** the snapshot format changes from one CBOR + gzip blob to a record stream. Nodes on different releases cannot send each other snapshots. Cluster mode is experimental and has no users.

## Capabilities

### New Capabilities

### Modified Capabilities
- `cluster-consistency`: ADDED requirements "S1 A snapshot holds one point in time", "S2 Snapshot memory is bounded", "S3 Snapshot files are encrypted at rest", "S4 A received snapshot is checked before it changes the store", "S5 A snapshot survives a restart".

## Impact

- `src/cluster/state_machine.rs` (build, receive, install, `restore_snapshot_in_place`), `src/cluster/types.rs` (`SnapshotData`), a new `src/cluster/snapshot_file.rs` (the async file openraft reads and writes) and `src/cluster/snapshot_stream.rs` (the record format), `src/cluster/engine.rs` (state machine construction, `install_snapshot_timeout`).
- `src/storage/`: a new sealed-file module (per-file key wrapped by the system KEK, chunked AES-256-GCM) and one accessor on `EmbeddedStorageEngine`. `FsFile` gains a partial `read`.
- Disk: a node needs free space for up to two snapshot files (the current one and one being built or received) and, during a build, for the SST files the read snapshot keeps alive.
- No new config key, no proto change, no SDK change, no new dependency (`zstd`, `sha2` and `ring` are already in use).
- Docs: `docs/guides/clustering.md` (P-2 fixed, disk need), `docs/dev/CONSISTENCY.md`, `docs/dev/ARCHITECTURE.md` §16, `docs/guides/disaster-recovery.md` (the new directory), `CHANGELOG.md`.
- Coordination: `cluster-read-fencing` (task 3) closes a read gate in `install_snapshot` before `restore_snapshot_in_place`. This change keeps that call site and the restore's phase order, so whichever lands second rebases.
