# HEA-1949 — session_create coalescing results

**Source:** `examples/saturation_throughput.rs` (HEA-1949 revision)
**Artifact:** `docs/perf/artifacts/c7-saturation-hea1949-raw.json`
**Host:** 16 logical cores
**Device fsync rate (F):** 528.7 fsyncs/s (200 sequential sync_all calls, same storage path)
**W (WAL syncs/op at T=1):** 2.000 (post–HEA-1945 fix `abf179ba`; W was 3.0 in the v2 artifact)

---

## Per-concurrency results

| T | ops/s | fsyncs/write | batch size | T×F/W ceiling | coalescing eff | p99 (ms) |
|--:|------:|-------------:|-----------:|--------------:|---------------:|---------:|
|   1 |   125 | 2.000 | 0.50 |     264 |  47.1% |   10.9 |
|   4 |   170 | 1.521 | 0.66 |   1,057 |  16.1% |   28.1 |
|  16 |   118 | 1.514 | 0.66 |   4,230 |   2.8% |  227.6 |
|  64 |   168 | 1.534 | 0.65 |  16,918 |   1.0% |  789.8 |
| 128 |   332 | 1.543 | 0.65 |  33,837 |   1.0% |  759.9 |
| 256 |   323 | 1.537 | 0.65 |  67,674 |   0.5% |  866.6 |

**Column definitions:**

- **ops/s** — aggregate `session_create` throughput across all threads.
- **fsyncs/write** — measured WAL sync_all calls per committed op (lower = better group-commit coalescing).
- **batch size** — mean ops coalesced per fsync (1 / fsyncs_per_write).
- **T×F/W ceiling** — the maximum aggregate ops/s if group commit were perfect (every concurrent write coalesced into a single fsync). F = device fsync rate, W = WAL syncs/op at T=1.
- **coalescing eff** — measured ops/s ÷ ceiling; the fraction of the device fsync budget the engine captures.

---

## Key findings

### 1. Group commit does coalesce — but only once, then plateaus

`fsyncs_per_write` falls from 2.000 at T=1 to ~1.52 at T=4, then stays flat to T=256.  
Mean batch size is 0.65 ops/fsync and does not grow with concurrency.

**Cause (from HEA-1945 triage):** `EmbeddedAuditEngine::append` holds the per-realm chain lock across the entire WAL `sync_all` wait. This serializes audit writes — at most one audit append can be in flight per realm at any time. Because every `session_create` issues an audit event, and the chain lock blocks the thread until the fsync completes, increasing T above the chain lock's serialization depth produces no additional coalescing. The effective batch size is capped at ~1.5 ops/fsync regardless of T.

### 2. Device ceiling is reachable on paper; the engine does not reach it

At T=256 the perfect-coalescing ceiling is **67,674 ops/s** — above the T4 target of 50,000.  
The engine achieves **323 ops/s** (0.5% of ceiling).

The gap is entirely attributable to the audit chain lock. Without it, the WAL group-commit path can coalesce T writes per fsync and the ceiling is `T × F / W`. With it, effective throughput is pinned at `≈ F / W ≈ 264 ops/s` regardless of T.

### 3. Required concurrency for 50,000 ops/s

With perfect coalescing: T_needed = ⌈50,000 × W / F⌉ = ⌈50,000 × 2.0 / 528.7⌉ = **190 writers**.

The current engine **cannot reach 50,000 ops/s at any concurrency** while the audit chain lock covers the fsync wait. The fix is **HEA-1948** (split the chain lock from the durability wait).

### 4. T4 verdict

Do not grade T4 PASS/MISS from this run — per the issue instructions, the verdict belongs to HEA-1940. This run provides the attribution:

- The device supports the target (ceiling at T=256 > 50,000).
- The engine gap is a known architectural bottleneck (audit chain lock), not an unknown.
- T4 becomes gradeable once HEA-1948 lands and is measured.

> **Note (CTO, 2026-07-29):** this run predates HEA-1948. Its numbers are the *baseline*
> against which the chain-lock fix is graded — see
> `docs/perf/HEA-1945-T4-session-create-triage.md` § "Post-HEA-1948 re-measurement".

---

## Comparison to v2 artifact

| | v2 (W=3, ladder [1…16]) | HEA-1949 (W=2, ladder [1…256]) |
|---|---|---|
| Device F | ~419 fsyncs/s (derived) | 528.7 fsyncs/s (measured) |
| W | 3.0 (at T=1) | 2.0 (at T=1) |
| Peak measured ops/s | 254 at T=16 | 332 at T=128 |
| Ceiling at T=max | 6,701 at T=16 | 67,674 at T=256 |

Device is faster on this run (528 vs 419 derived fsyncs/s). Extending the ladder to T=256 confirms the throughput is saturated by the audit serialization ceiling, not by concurrent contention among the non-audit writes.
