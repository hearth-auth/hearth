# HEA-1938 — Re-review of the HEA-1937 F1 fix (`934a48df`)

**Verdict: APPROVED.** F1 is closed at the mechanism level, not just the symptom, and the
new regression test genuinely pins it (independently proven RED). Two LOW test-quality
nits below; neither blocks the merge of HEA-1931.

## F1 (HIGH) — closed

`compact_ssts` (`src/storage/engine.rs:785`) now takes `flush_lock` for exactly the
snapshot + `sst_counter.fetch_add`, then releases it before the O(total-data) merge.

Verified the ordering argument against every SST-number allocator in the file — all three
now allocate *and* publish under `flush_lock`:

| Allocator | Site | `fetch_add` under `flush_lock`? | Publishes `sst_readers` under the same guard? |
|---|---|---|---|
| `trigger_flush` | `engine.rs:570`→`578`→`616` | yes | yes |
| WAL pre-rotate flush callback | `engine.rs:459`→`468`→`531` | yes | yes |
| `compact_ssts` | `engine.rs:786`→`795` | yes (new) | commit phase re-takes at `:839` |

Because allocation and publication are both inside the same critical section, there is no
interleaving in which compaction snapshots a reader set that excludes a flush yet takes a
number above it. Either the flush completes first (compaction sees its SST and merges it,
output numbered higher) or the flush runs entirely after (its number is strictly greater
than the merge output). Recency cannot invert in either order.

`compact_partial` remains correct unchanged — it reuses `run[0].sst_number()` rather than
allocating, and flushes only prepend newer SSTs, so `target_num`, `other_nums`, and the
`drop_tombstones` oldest-run test all stay valid across a concurrent flush.

Lock order is uniform: `compaction_lock → flush_lock`. No path takes `flush_lock` and then
a compaction lock — `trigger_flush` only calls `compaction_notify.notify_one()` (a
flag-set), and the two external callers (`src/main.rs:1770`, `:1774`) hold neither.

## F2 (LOW) — closed

`compact_ssts_cannot_invert_recency_against_concurrent_flush` (`engine.rs:2856`) parks a
flush inside its `.sst` `create` — i.e. after `fetch_add`, before publish, holding
`flush_lock` — which is precisely the F1 window, then runs `compact_ssts` concurrently.

**Independently verified**, not taken on report: reverted *only* the source hunk (restored
the unguarded `load_full()` + `fetch_add`) in a detached worktree at `934a48df`, left the
test byte-identical.

- RED: `left: Some([79, …])` (`'O'`) vs `right: Some([78, …])` (`'N'`) — the merged OLD
  data shadowed the flushed NEW SST.
- GREEN with the fix; all 47 `storage::engine` tests pass; `cargo clippy --lib --tests
  --all-features -- -D warnings` clean.

## Nits (LOW, non-blocking)

**N1 — the `comp_reached` signal is plumbed through `FlushGateFs` and then discarded.**
`engine.rs:2914` reads `let _ = comp_reached_rx.recv_timeout(500ms);`. The comment above it
states the correct invariant ("if compaction reaches its merge `.tmp` while the flush is
still parked, it snapshotted the stale reader set") but nothing asserts it, so the entire
`comp_reached` channel is dead test machinery costing a fixed 500 ms. Make it load-bearing:

```rust
assert!(
    comp_reached_rx.recv_timeout(Duration::from_millis(500)).is_err(),
    "compact_ssts reached its merge while a flush held flush_lock — snapshot/alloc \
     is not ordered against flushes (HEA-1937 F1)"
);
```

That pins the *mechanism* (blocked at snapshot) in addition to the outcome, and would stay
red under any future refactor that restores the race by a different route.

**N2 — the `compact_ssts(2)` return value is unused**, so a hypothetical `Ok(0)` early
return would make the final assertion pass vacuously (TESTING.md anti-pattern class B).
Bind it and assert `>= 3` inputs were merged.

Both are worth a small follow-up; neither weakens the F1 evidence, since the RED run
above demonstrates the assertion is currently discriminating.
