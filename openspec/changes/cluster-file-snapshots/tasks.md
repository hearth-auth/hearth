## 1. Proposal

- [x] 1.1 Proposal, design, delta spec and tasks. Proof: `openspec validate cluster-file-snapshots --strict` passes

## 2. Building blocks (PR 1 of the implementation)

- [ ] 2.1 Test first: unit tests in `src/storage/sealed_file.rs` show a sealed file round-trips 0 bytes, one byte, exactly one chunk, and many chunks; a seek to any offset reads the right bytes; a changed, dropped, reordered or appended chunk, a file cut at a chunk boundary, and a file opened under another KEK are refused; a backward seek while writing rewrites from there; the file holds no plaintext marker. Then write the module, with its I/O through `Fs` (add `FsFile::read`)
- [ ] 2.2 Test first: unit tests in `src/cluster/snapshot_stream.rs` show the record stream round-trips realms and rows, and refuses a wrong magic, an unknown tag, a ROW before a REALM, an oversized key or value, a missing or second META, a wrong END count or digest, a cut stream and bytes after END. Then write the encoder and the streaming decoder
- [ ] 2.3 Test first: unit tests in `src/cluster/snapshot_file.rs` drive `SnapshotFile` through `tokio::io` the way openraft does (seek to the end for the length, seek and read 4 MiB chunks; write chunks, seek back to a resent chunk, shut down). Shutdown of a received file refuses a corrupt stream. Then write the async adapter
- [ ] 2.4 `make check` and `make ci-local-fast`

## 3. Wiring (PR 2 of the implementation)

- [ ] 3.1 Test first: a state-machine test applies entries while a build runs (a storage stub that pauses the build's first realm visit) and shows the snapshot holds exactly the entries up to its declared index (#818). Then take `read_snapshot()` in `get_snapshot_builder` and build from the view
- [ ] 3.2 Test first: the existing round-trip tests in `src/cluster/state_machine.rs` pass with file snapshots; a new test shows the built snapshot is a `snap-*` file under `{data_dir}/raft-snapshots/` and holds no plaintext marker (S3). Then set `SnapshotData = SnapshotFile`, build into a file, and serve it from `get_current_snapshot`
- [ ] 3.3 Test first: a test shows a received snapshot with one changed byte fails at shutdown, leaves the store unchanged, and the same snapshot sent again installs (S4); a test shows `install_snapshot` refuses a file whose META does not match. Then wire `begin_receiving_snapshot` and `install_snapshot`
- [ ] 3.4 Test first: a test with a store larger than one restore batch shows Phase 1 and Phase 2 run in bounded batches and the result equals the leader's key-space. Then stream `restore_snapshot_in_place`, keeping its phase order and its call site for `cluster-read-fencing`
- [ ] 3.5 Test first: tests show a restarted state machine reports the snapshot it built or installed (S5), deletes `*.part` files, ignores and deletes a snapshot above its applied index, and deletes a corrupt one. Then add the start-up scan
- [ ] 3.6 Set `install_snapshot_timeout` (design decision 8); a test in `src/cluster/engine.rs` pins the value
- [ ] 3.7 `examples/snapshot_memory.rs`: fill a store shaped like 1M users (row count and bytes), measure the peak rise of `RssAnon` and `VmRSS` during build and during install with a sampler thread, and the time of each. Record the numbers in `docs/perf/` and in the PR. Proof: both anonymous rises are under 512 MiB (S2)
- [ ] 3.8 Check decision 8's timeout against the measured install time; adjust the constant if the install takes more than a third of it
- [ ] 3.9 Every existing cluster test passes: `make test-detached` (includes `hearth-simulation`), `tests/cluster_*.rs`
- [ ] 3.10 Docs: `docs/guides/clustering.md` (P-2 fixed; disk need), `docs/dev/CONSISTENCY.md` (S1–S5, the #818 note in W5), `docs/dev/ARCHITECTURE.md` §16, `docs/guides/disaster-recovery.md` (`raft-snapshots/`)
- [ ] 3.11 `CHANGELOG.md` under `[Unreleased]`: `### Changed` (file-backed snapshots, format break), `### Fixed` (#818)
- [ ] 3.12 `make check` and `make ci-local-fast`

## 4. Close-out

- [ ] 4.1 Jepsen `snapshot` keeps its expectation (`make jepsen` or the nightly run)
- [ ] 4.2 Archive the change after both PRs merge
