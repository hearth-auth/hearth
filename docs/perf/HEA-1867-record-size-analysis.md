# HEA-1867 — Where the 24 KB/user actually goes

**Date:** 2026-07-28 · **Owner:** CTO · **Trigger:** board question on HEA-1867
**Source measurement:** [HEA-1868 C0](./HEA-1868-C0-MEMORY-COST.md) · **Related:** [HEA-1881 cold-path triage](./HEA-1881-cold-path-triage.md)

---

## 1. Answer in one line

**24 KB is not the record size.** A user's actual stored content is ~2 KB resident / ~4.5 KB
on disk, spread over **5 keys**, not 1. The remaining ~22 KB is allocator high-water caused by
a copy-on-write clone of the *entire memtable* on every single `put`. All three layers are
reducible, and the largest one is a ~20-line structural fix, not a format change.

---

## 2. The three layers

### Layer A — record content: ~2 KB resident / 4.5 KB disk, across 5 keys

`create_user_with_status` (`src/identity/engine/mod.rs:2515-2619`) writes:

| # | Key | Value | Approx. |
|---|-----|-------|---------|
| 1 | `usr:email:{email}` (`:2602`) | UUID as a **36-byte string** | ~90 B |
| 2 | `usr:id:{uuid}` (`:2606`) | `serde_json` `User` | ~300–400 B |
| 3 | `audit:evt:{ts19}:{seq20}:{uuid}` | `serde_json` audit event + 64-hex HMAC | ~490 B |
| 4 | `audit:actor:…` | index entry | ~100 B |
| 5 | `audit:action:…` | index entry | ~100 B |

Audit paths: `record_audit` (`engine/mod.rs:980`) → `audit.append` writes 4 keys
(`src/audit/engine.rs:440-448`); key formats at `src/audit/keys.rs:22-28,66-77`.

Notes:
- The HEA-1868 doc's "≥3 records/user" **undercounts — it is 5.**
- **Audit is ~3 of the 5 keys and roughly half the bytes.** Audit is also excluded from
  tiering, so it is permanently resident.
- Everything is `serde_json` (`engine/mod.rs:2669-2673`, `audit/engine.rs:416`) — field
  names repeated verbatim in every record.
- The email index stores the UUID as a 36-char string rather than 16 raw bytes.
- SST entries are stored **uncompressed** (`src/storage/sst.rs:280-314`).

### Layer B — the ~12× multiplier: full-memtable clone on every put

`Memtable::put` (`src/storage/memtable.rs:123-132`):

```rust
let current = self.data.load_full();
let mut new_map = (*current).clone();   // deep-clones EVERY key and value
new_map.insert(composite, new_value);
self.data.store(Arc::new(new_map));
```

Every `put` reallocates the whole `BTreeMap`. The codebase already documents this cost in
`put_batch`'s own doc comment (`memtable.rs:139-145`): *"turns a bulk insert of B entries
from O(B·N) into O(N + B)"* — but `create_user` uses individual `put` calls, not `put_batch`.

Default `memtable_flush_bytes = 64 MiB` (`src/config/types.rs:224`, asserted at `:3177`).
At ~2 KB content/user that is ~32,000 users — **~160,000 map entries** — cloned on *every*
put, five times per user create. Two full copies are live at once and `arc_swap` defers
freeing the old one, so glibc arena high-water grows and RSS never returns it.

The same copy-on-write pattern is in the hot tier (`src/storage/tiered.rs:187-199`), which
additionally **copies** bytes rather than sharing with the memtable (`Arc::from(value)` at
`tiered.rs:192`) — a promoted user is resident twice.

**Independent corroboration from C0's own raw data.** Per-user create cost rises with corpus
size, which is the signature of O(N)-per-write, not of record size:

| N users | seed time | ms/user |
|---|---|---|
| 200 | 526 ms | 2.63 |
| 1,000 | 4,400 ms | 4.40 |
| 4,000 | 22,423 ms | 5.61 |
| 12,000 | 93,071 ms | 7.76 |

A constant-cost write path would hold ms/user flat. It grows 3×. This was in the C0 table all
along and was not attributed.

### Layer C — the ceiling that record size does NOT fix

`SstReader::open` reads the whole SST, decrypts it wholesale, and materialises every entry in
RAM (`src/storage/sst.rs:319-342, 361, 405, 416-435`). There is no block index, no compression,
and **no unload path** — only whole-`Vec` replacement (`engine.rs:444, 572, 676`).

Therefore **resident memory is Θ(total corpus), not Θ(working set)**, independent of tiering.
This was already flagged in [HEA-1881 §2b](./HEA-1881-cold-path-triage.md). Even a perfect
500 B/user record leaves 100M users ≈ 50 GB resident — the VISION §7.3 tiering promise
("RAM proportional to *active* users") is not implemented below the hot tier.

---

## 3. How much is recoverable

| Lever | Layer | Effect | Cost |
|---|---|---|---|
| Batch the 2 user keys into one `put_batch` | B | 5 clones/user → 2 | trivial |
| Replace CoW `BTreeMap` with a concurrent/sharded map or skiplist | B | removes O(N)-per-write entirely; kills the 12× | medium, contained |
| Binary encoding (bincode/postcard) instead of `serde_json` | A | ~30–40% off every value | medium, storage-format change |
| Email index: 16 raw bytes instead of 36-char UUID string | A | ~20 B/user | trivial |
| Trim audit secondary indexes / compact audit encoding | A | audit is ~half the bytes | medium |
| SST block compression | A (disk) | large on disk | folds into the block-format work |
| Block-based SST + lazy paging + reader eviction | C | RAM becomes Θ(working set) | **large — the real architecture item** |

Realistic landing zone with A+B: **~24 KB → 1–2 KB resident, 4.5 KB → ~1.5 KB disk.**
That clears VISION §7.3's 524 B/user budget only if C also lands.

Greenfield helps here: per [project policy](../../CLAUDE.md) there is no storage-format
backward-compatibility obligation, so encoding and key-shape changes are cheap to make.

---

## 4. Would fixing it fix the other HEA-1867 misses?

| Finding | Fixed by smaller records? | Why |
|---|---|---|
| Memory ceiling (~609k users/host); "millions of users on one node" | **Partly — necessary, not sufficient** | Layers A+B give ~12–20×. But Layer C makes RAM Θ(corpus) regardless. Both required. |
| Disk 4.5 KB/user vs 2.1 KB target | **Yes** | Encoding + audit trim + SST compression clear it outright. |
| Write throughput / write-path scaling | **Yes, materially** | The O(N) clone is a write-path defect, not a size defect. Affects every write: users, sessions, tokens, audit. Previously unattributed. |
| Cold-path Θ(#SSTs) fan-out | **Partly** | Fewer bytes → fewer SSTs for the same corpus. Complexity class unchanged. |
| 500→600 concurrent-user cliff | **No** | Argon2id KDF admission. Addressed by HEA-1887/1892/1895. |
| Issuance p50 29 ms / p99 954 ms | **No** | Argon2id compute floor (~29 ms) plus Little's-Law queueing. Storage is not in that path. |
| `permission_check` negative scaling (−0.549) | **No** | Single RBAC resolution `Mutex` (HEA-1770). Needs sharding. |

**Summary:** it fixes the *capacity* story (the headline ask) and one previously-unattributed
*write-throughput* defect. It does not touch the latency and concurrency misses — those are
CPU-bound and lock-bound, and are tracked separately.

---

## 5. Recommended sequencing

1. **Layer B first** — highest ratio of benefit to risk, no format change, no compatibility
   surface. Fixes both memory high-water and write scaling.
2. **Layer A next** — encoding + key-shape + audit trim. Mechanical, greenfield-cheap.
3. **Layer C as design work** — block-based SST format with per-block encryption, lazy paging,
   and reader eviction. Already scoped as HEA-1881 item C and gated on its measurement item B.
   This is the one that actually decides whether "100M users on one node" is real.

Re-measure C0 after each of 1 and 2 before committing to 3.
