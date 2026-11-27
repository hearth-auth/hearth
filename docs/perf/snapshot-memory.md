# Raft snapshot memory at 1,000,000 users

OpenSpec change `cluster-file-snapshots`, requirement "Snapshot memory is bounded": a snapshot of a
1,000,000-user store builds and installs with less than 512 MiB of extra memory on each side.

## How to run

```text
cargo run --release --example snapshot_memory -- 1000000 /path/on/a/large/disk
```

The example (`examples/snapshot_memory.rs`, Linux only) seeds a store with the given number of
users, about 2 KB each, as four rows: the user record (1,200 B), its email index row, a
credential (420 B) and a session (300 B). The values are hex text, which compresses about as
well as JSON records holding hashes and ids. It then:

1. builds a snapshot through `HearthStateMachine`, as a leader does;
2. sends it to a second, empty node's state machine the way openraft does (4 MiB chunks into
   the file from `begin_receiving_snapshot`, then `shutdown`, which checks the file whole), and
   installs it;
3. sends and installs it again, over the store the first install filled, so the restore's
   delete phase first removes all 4,000,000 keys.

A thread samples `RssAnon` and `VmRSS` from `/proc/self/status` every 5 ms. Each phase prints its start
value, its peak and the difference (the extra memory). The binary uses jemalloc, as the server
does. Allow about 3x the row bytes free on disk (leader store, snapshot file, follower store).

## Result (2026-11-27)

Development machine: 12 cores, 54 GiB RAM, NVMe disk; release build of the
`cluster-file-snapshots` wiring branch. 1,000,000 users, 1,966 MiB of rows; the snapshot stream
is 965 MiB.

| Phase | RssAnon start | RssAnon peak | **RssAnon extra** | VmRSS extra | Time |
|---|---|---|---|---|---|
| Build | 24.2 MiB | 32.3 MiB | **8.1 MiB** | 2,025 MiB | 44.2 s |
| Install | 21.9 MiB | 73.8 MiB | **51.9 MiB** | 77 MiB | 23.3 s |

A later run added the reinstall over a full store (the machine was under heavy load from other
work, load average about 60, so its times are not comparable):

| Phase | RssAnon extra | VmRSS extra | Time |
|---|---|---|---|
| Build | 8.9 MiB | 1,951 MiB | 166 s |
| Install into an empty store | 46.4 MiB | 61 MiB | 181 s |
| **Reinstall over the full store** | **346.3 MiB** | 2,419 MiB | 232 s |

The reinstall stays within the budget, but it needs about 300 MiB more than an install into an
empty store. The restore itself holds the same bounded batches in both cases. The extra memory is
not yet attributed. The first suspect is the storage engine's background compaction, which runs
while the store holds about twice its data (old rows, their tombstones and the new rows). Whether
it grows with the store size is not measured: it is the limit of this measurement.

An earlier run of the same build measured 8.4 MiB (build, 44.1 s) and 50.3 MiB (install,
16.5 s). At 20,000 users it measured 1.1 MiB and 52.5 MiB: neither rise grows with the store.

Both anonymous rises stay far within the 512 MiB budget. The build holds one row and the zstd
encoder's window at a time. The install holds one restore batch (at most 4,096 rows or 4 MiB),
the memtable it writes into, and one 4 MiB transfer chunk.

The build's `VmRSS` rise is the store's SST files, which the storage engine memory-maps and the
build reads once from end to end. Those are file-backed pages: the kernel drops them under memory
pressure instead of failing an allocation, so they do not count against the budget.

The in-memory snapshot this replaces held the whole payload, its compressed copy and, on the
follower, the received copy as anonymous memory: about 2 GB on each side at this size.
