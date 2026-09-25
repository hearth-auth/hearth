# The `arc-swap` heap corruption, and what to do about the remaining sites

Tasks 26.1 and 26.5 (audit 2026-08-28, raised by 25.16 · **CRITICAL**).

`arc-swap` 1.9.2 corrupts the heap under the `load` + `rcu` pattern this
codebase used in thirteen places. This report records how that was pinned to the
crate rather than to our code, what has been fixed, and what each remaining call
site needs.

**Status at 2026-09-21.** Five of the thirteen sites are off the crate: the
authorization decision cache (26.1) and the four non-hot sites (26.5). The
remaining eight are all on the hot path and are deliberately untouched — a read
lock is forbidden there, and the epoch-based reclamation they need is a new
dependency with its own justification. `arc-swap` is therefore still a
dependency of this crate.

**Status at 2026-09-25 — closed.** The eight hot sites moved to `EpochCell`, an
epoch-reclaimed cell on `crossbeam-epoch`, and `arc-swap` is no longer a
dependency: it is out of `Cargo.toml` and both lockfiles, and `deny.toml` bans
it. See [The hot-path half](#the-hot-path-half-2026-09-25) at the end.

## What was measured

The instrument is `rbac::resolution_cache::tests::concurrent_readers_never_observe_stale_after_bump`:
ten reader threads calling `get` while one writer alternates `insert` and
`bump`. It passes cleanly on its own, which is why two earlier diagnoses missed
it. Surfacing the fault needs **both** conditions:

* an allocator that *checks* what is handed to `free`, rather than silently
  recycling a corrupted chunk — `MALLOC_CHECK_=3`; and
* real contention — three copies of the binary running at once, so the readers
  and the writer actually interleave.

| Primitive in `src/rbac/resolution_cache.rs` | Failures in 150 loaded runs |
|---|---|
| `arc_swap::ArcSwap` 1.9.2 | **3** — two `SIGSEGV`, one `free(): invalid size` |
| `RwLock<Arc<T>>` shim, same module otherwise untouched | 0 |
| `SwapCell` (the shipped fix) | 0 |

Reproduce it with:

```bash
MALLOC_CHECK_=3 <lib test binary> --exact \
  rbac::resolution_cache::tests::concurrent_readers_never_observe_stale_after_bump
```

three at a time, 50 rounds.

## Why the fault is the crate's, not ours

Three independent lines, and the third is the decisive one.

1. **The module contains no `unsafe`.** It is 100% safe Rust using only
   `arc-swap`'s public API. Safe Rust cannot produce a use-after-free on its
   own; the `unsafe` that can is inside the crate.

2. **The captured stack names the crate's drop glue**, on a *reader* thread:

   ```
   ShardedResolutionCache::get
     -> drop_glue<arc_swap::Guard<Arc<HashMap<..>>>>
       -> <HybridProtection as Drop>::drop
         -> drop_in_place<Arc<HashMap<..>>> -> HashMap drop
           -> RawTable::drop_inner_table -> ResolvedPermissions drop
             -> Vec<Permission> -> String -> RawVec<u8> -> free() -> abort
   ```

   The reader's guard drop took the refcount to zero and ran the map's real
   destructor while the writer still owned it.

3. **Swapping only the primitive removes the crashes.** Replacing `ArcSwap`
   with a `RwLock<Arc<T>>` shim — same module, same test, same load, nothing
   else changed — took 3 failures in 150 to 0 in 150.

   *Stated honestly:* a write lock also serialises writers, so line 3 alone
   could in principle be a timing artefact rather than proof. It is line 3
   **plus** lines 1 and 2 that settle it. `free(): invalid size` is glibc
   rejecting a corrupted chunk header, which no amount of scheduling luck
   produces from correct code.

## Why there is no upgrade and no safe strategy

Both checked against the vendored crate source, not the issue tracker.

* **1.9.2 is the newest release** (2026-06-28) and changes only a doc note over
  1.9.1. The two before it were both memory-ordering fixes — 1.9.0 "original
  proofs based on wrong reading of standard", 1.9.1 "one more SeqCst" — and the
  crate ships its own `tests/bug-198.rs` crash regression. This is a recurring
  defect class there, not a one-off.
* **The `RwLock` strategy is not reachable from a production build.**
  `strategy/rw_lock.rs` is `#[cfg(feature = "internal-test-strategies")]` and
  its own module doc says *"This is not meant to be used in production code"*.
  There is no `genlock-load` feature; 1.9.2 ships only
  `experimental-strategies`, `experimental-thread-local`,
  `internal-test-strategies` and `weak`.

So the remedy cannot be a dependency bump. It is to move off the crate.

## What shipped in 26.1

`src/rbac/resolution_cache.rs` now uses a local `SwapCell<T>` — a documented
`RwLock<Arc<T>>` with `load` and `rcu` — instead of `ArcSwap`.

This site was done first for three reasons. It is where the crash reproduces.
It is an **authorization** decision cache, so a corrupted read is a security
outcome, not just a crash. And authorization is explicitly **not** on the hot
path — permissions are embedded in the JWT at issue time — so `CLAUDE.md`'s
"no locks on read path" rule does not bind here, where it does bind in
`validate_token`.

Cost: readers still never block readers; a writer now contends with at most
1/64 of them, because the 64-way sharding is unchanged. `SwapCell::rcu` is
strictly stronger than `ArcSwap::rcu` — a write lock makes the
read-modify-write atomic outright, so the closure runs once instead of in a
compare-and-swap retry loop.

## What shipped in 26.5

`SwapCell` moved out of `src/rbac/resolution_cache.rs` to **`src/core/swap_cell.rs`**
(`hearth::core::SwapCell`) when the second consumer arrived. `core` is the one
module every layer may depend on, and the consumers now span `protocol`, `rbac`,
`abuse` and the binary; `SwapCell` is a shared generic container with no domain
logic and no I/O, in the same family as the primitives already in
`core::secrets` and the atomic-backed `FakeClock` in `core::time`.

All four non-hot sites moved with it. Each was re-derived against the hot-path
definition in `CLAUDE.md` — `validate_token`, `lookup_session`, `lookup_user`,
and *not* authorization — before being migrated:

| Site | What moved | Off the hot path because |
|---|---|---|
| `src/protocol/tls.rs` | `ReloadableTlsConfig::certified_key`, `ReloadableResolver::certified_key` | `ResolvesServerCert::resolve` is called by rustls from the `ClientHello` path — **once per handshake, not per request**, and not at all on a resumed session. It is upstream of every auth call, never inside one. |
| `src/abuse/ip_reputation/spamhaus.rs` | `SpamhausDropProvider::filter` | `IpReputationProvider::check` runs on the abuse/reputation path at connection admission. It is not reached by `validate_token`, `lookup_session` or `lookup_user`. |
| `src/abuse/ip_reputation/mod.rs`, `src/abuse/cidr.rs` | documentation only — neither file ever named `arc_swap` in code; both described the call-site pattern | same path as above |
| `src/main.rs` (with `src/rbac/registry.rs`, `src/rbac/engine.rs`) | `RegistrySwap` — the `PermissionRegistry` hot-swap | The registry is built at startup and re-stored on SIGHUP by `run_config_reconciliation`. In `main.rs` it is **write-only**: there is no `load` of it on any request path. |

Two of the five rows the previous revision listed were doc-comment references
rather than code, so the real code change in 26.5 is three sites, not four;
`src/rbac/registry.rs` and `src/rbac/engine.rs` were likewise comment-only.

`SwapCell` gained `store(Arc<T>)` and `from_arc(Arc<T>)` for the TLS and
Spamhaus reload paths, which already hold an `Arc` and replace it wholesale
rather than deriving the next value from the current one.

### Guards added

One concurrent reader/writer test per migrated update path, each
mutation-proven by removing the publish and confirming exactly that test goes
red:

* `core::swap_cell::tests::concurrent_rcu_never_loses_an_update` — 4 writers ×
  250 `rcu` increments against 4 spinning readers; the final count must be
  exactly 1,000. Covers every `rcu` consumer, including the resolution cache.
* `core::swap_cell::tests::concurrent_store_publishes_the_last_value` — 2,000
  stores against 4 spinning readers. This is the guard for the `main.rs`
  registry site, which mutates only through `store`.
* `protocol::tls::tests::concurrent_handshakes_never_miss_a_reload` — 40
  alternating certificate reloads against 4 threads reading the resolver's
  cell. The last reload deliberately lands on a certificate the config did
  *not* start on, so a reload that builds the key but never publishes it leaves
  the old certificate live and fails.
* `abuse::ip_reputation::spamhaus::tests::concurrent_checks_never_miss_a_reload`
  — 200 alternating list reloads against 4 threads calling `check`. One address
  is blocklisted under both lists and one under neither, so a torn or empty
  snapshot breaks a per-snapshot assertion; the final list is deliberately not
  the starting list, so a lost store fails.

## The remaining eight sites — all hot

### Not on the hot path — nothing left

All five non-hot sites are done (26.1 and 26.5 above). Outside `src/identity/`
and `src/storage/` no file imports or calls `arc_swap` any more; what is left
there and in `benches/`/`examples/` is prose recording the history.

### On the hot path — a read lock is NOT allowed

Nothing here is fixed, and 26.5 deliberately did not touch any of it.
`CLAUDE.md` forbids locks on the read path of `validate_token`,
`lookup_session` and `lookup_user`. These need epoch-based reclamation, which
`CLAUDE.md` already names as the sanctioned mechanism.

| Site | What it holds | Why it is hot |
|---|---|---|
| `src/identity/engine/mod.rs:598` | `realm_status_cache` | read on every `validate_token` |
| `src/identity/engine/mod.rs:768` | `session_cache` | `lookup_session` itself |
| `src/identity/engine/mod.rs:776` | `token_claims_cache` | the first thing `validate_token` touches |
| `src/identity/engine/sharded_cache.rs:35` | `ShardedArcSwapMap`, the shared 64-way shard type | backs the above |
| `src/storage/memtable.rs:123` | the active memtable | every storage read |
| `src/storage/engine.rs:339` | `sst_readers` | every storage read that misses the memtable |
| `src/storage/tiered.rs:149` | the hot tier | every storage read |
| `src/storage/block_cache.rs:82` | the block cache | every SST block read |

**Recommended:** `crossbeam-epoch`. It is the mechanism `CLAUDE.md` already
prescribes ("Use epoch-based reclamation"), it is what `arc-swap` implements a
variant of, and it carries far more production mileage. Adding it needs a
dependency-policy justification per `CLAUDE.md` — licence, `cargo-audit`, and a
written reason — which is why this half is still not done.

**Sequencing.** `sharded_cache.rs` is the leverage point: four of the eight hot
sites go through it or copy its shape. Convert that one first, behind the same
public surface, and the identity-engine sites follow without touching their
call sites.

**Until then.** The hot sites carry the same latent fault. Nothing observed has
crashed there, but nothing observed had crashed in the resolution cache either
until the allocator was told to check. Any of them can be probed the same way:
a concurrent reader/writer test, `MALLOC_CHECK_=3`, several copies at once.

**`arc-swap` stays in `Cargo.toml`** until these eight are converted. Removing
the dependency is the closing act of that work, not of 26.5.
(Done on 2026-09-25; see the last section.)

## Regression guard

`concurrent_readers_never_observe_stale_after_bump` stays as it is, at 5,000
writer iterations. It found the bug and it is now the guard for the fix. Its
doc comment records the reproduction recipe, so a future failure there is
self-diagnosing rather than looking like a flake — which is what it looked like
twice before.

## The hot-path half (2026-09-25)

All eight sites in the table above are off the crate, and `arc-swap` is gone
from `Cargo.toml`, `Cargo.lock` and `fuzz/Cargo.lock`. Two guards keep it out:
a `deny.toml` ban (`cargo deny check bans` fails on the pre-removal graph) and
`tests/arc_swap_removed.rs` (manifest and both lockfiles).

### The primitive

`src/core/epoch_cell.rs` — `EpochCell<T>`, plus `EpochCellOption<T>` for the
one `ArcSwapOption` site — keeps the current value as the raw pointer of an
`Arc<T>` in an `AtomicPtr`:

* **Read.** `load()` pins the thread's `crossbeam-epoch` participant and returns
  a guard that dereferences to the value: no lock, no syscall, no write to the
  shared refcount, and no allocation once the thread has pinned before.
  `load_full()` adds one refcount increment for a caller that keeps the value.
* **Write.** `store` swaps the pointer; `rcu` is a compare-and-swap retry loop
  with `ArcSwap::rcu`'s semantics, so a check inside the closure — the claims
  cache's HEA-2097 generation guard — is re-read on every attempt.
* **Reclamation.** A replaced value is retired, not freed. An epoch callback
  raises a flag once every thread that was pinned at the swap has unpinned, and
  the *writer* drops flagged values. The destructor of a replaced map therefore
  never runs on a reader thread — which is exactly where the 26.1 abort ran it.
* Four `unsafe` blocks (the `Arc` raw-pointer round trip and the pinned
  dereference), each with its `// SAFETY:` argument; `ARCHITECTURE.md` §9.2 now
  lists the file as a permitted `unsafe` location.

| Site | Now |
|---|---|
| `identity/engine/mod.rs` — `realm_status_cache`, `session_cache`, `token_claims_cache` | `EpochCell<HashMap<..>>` |
| `identity/engine/sharded_cache.rs` — `ShardedArcSwapMap` | `ShardedEpochMap`: 64 `EpochCell` shards, same surface |
| `storage/memtable.rs` — active map, flushing slot | `EpochCell` / `EpochCellOption` |
| `storage/engine.rs` — `sst_readers` | `EpochCell<Vec<SstReader>>`, read with `load_full` |
| `storage/tiered.rs`, `storage/block_cache.rs` — shard maps | `EpochCell<HashMap<..>>` |

Pinned `load()` is used only for short in-memory reads. A scan of a whole map,
an SST probe that may fault on an mmap, or a writer's clone takes an owned
`load_full()` snapshot instead, because a thread held pinned stalls reclamation
for every cell in the process.

**What reclamation promises.** A write releases what it replaced before it
returns unless some thread stayed pinned through its bounded attempts to end the
grace period; the value is then released by the next write to that cell, by
`reclaim()`, or when the cell drops. Retention is bounded, not zero. The two
cells written once per flush and holding large values — the memtable (a whole
flushed map) and the SST list (a memory map per SST) — call `reclaim()` at the
end of every flush.

**Found on the way.** `flush_streaming` installed the empty active map before
parking the full one, so for one store a concurrent read found a written,
acknowledged key in neither (6,447 misses in 3,000 flushes, measured). Parking
first closed it; that fix is independent of the primitive.

### Measured

The instrument is the one above, strengthened. On glibc 2.34 and later —
this host runs 2.42 — `MALLOC_CHECK_` has no effect unless
`libc_malloc_debug.so` is preloaded, so the 26.1 runs had only glibc's
always-on `free()` checks. The runs below preload it and add
`MALLOC_PERTURB_=165`, which overwrites freed chunks so a stale read sees
garbage rather than intact memory:

```bash
LD_PRELOAD=<glibc>/lib/libc_malloc_debug.so.0 MALLOC_CHECK_=3 MALLOC_PERTURB_=165 \
  <lib test binary> --exact <test>     # three copies at a time
```

| Test | Runs | Failures |
|---|---|---|
| `core::epoch_cell::tests::concurrent_readers_never_observe_a_torn_or_freed_value` | 1,650 | 0 |
| `storage::tiered::tests::concurrent_reads_see_only_values_written_for_their_key` | 1,650 | 0 |
| `identity::engine::sharded_cache::tests::concurrent_writers_on_one_shard_never_lose_an_update` | 1,650 | 0 |
| `storage::block_cache::tests::concurrent_hits_only_return_the_block_cached_under_their_id` | 1,650 | 0 |
| `storage::memtable::tests::a_key_is_never_missing_while_a_flush_moves_it` | 1,650 | 0 |
| `rbac::resolution_cache::tests::concurrent_readers_never_observe_stale_after_bump` (the 26.1 instrument) | 150 | 0 |
| `core::epoch_cell::tests::concurrent_rcu_never_loses_an_update` | 150 | 0 |
| `core::epoch_cell::tests::replaced_values_are_never_dropped_on_a_reader_thread` | 150 | 0 |
| `storage::memtable::tests::concurrent_reads_during_writes_see_consistent_snapshots` | 150 | 0 |
| `storage::engine::tests::concurrent_writes_during_flush_are_not_lost` | 150 | 0 |
| `identity::engine::tests::signing_key_cache_miss_racing_rotation_discards_stale_key` | 150 | 0 |

The 26.1 recipe as written (`MALLOC_CHECK_=3` alone) also gave 0 in 150 for the
resolution-cache instrument and for the `EpochCell` torn-value test.

The instrument is not blind. With the cell's grace period removed (a mutant
that frees the replaced value at once) and `MALLOC_CHECK_=3` alone, the
sharded-map test failed 10 runs in 10 (`free(): invalid pointer`), the
torn-value test 10 in 10 and the block-cache test 9 in 10 (`SIGSEGV`) — but the
hot-tier test 0 in 10: its stale reads found freed memory still intact. With the
preload and `MALLOC_PERTURB_` the hot-tier, block-cache and memtable
(`a_key_is_never_missing_while_a_flush_moves_it`) tests each failed 10 in 10,
which is why the runs above use both.

The zero-allocation bench gates (`session_lookup` and `validate_token`, both
0 allocations per warm call) and the latency gates (`storage_gate`,
`demotion_latency`, `rbac_check`) pass on this branch.
