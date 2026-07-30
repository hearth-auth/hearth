# Hearth — Performance Report 2.1

**Status:** `v2.1a — GRADED. 19 PASS / 0 MISS / 4 NOT-MEASURABLE / 7 NOT-MEASURED across 30 rows`
**Owner:** CTO (HEA-1956, amended HEA-1959) · **QA:** HEA-1940 (QA) · **Parent:** HEA-1867
**Last updated:** 2026-07-29 · **Branch:** `feature/perf-updates-7-28-26` · **Head SHA:** `873263d0`
(2.1 as originally graded: head `c709fa58`)
**Previous report:** `docs/perf/PERFORMANCE_REPORT_2_0.md` (v2, graded 2026-07-29, head `981516f1`)

> **Revision 2.1a — 2026-07-29 — T4 regraded MISS → PASS. Three inputs, in order:**
>
> 1. **The board revised the T4 target from 50,000 to 30,000 ops/s**, on the record that the
>    50,000 figure was arbitrary rather than derived ("50k was a totally arbitrary number on my
>    part", board comment on HEA-1959, 2026-07-29). VISION §7.2 is updated to match, including
>    the units correction — durable session creation is an aggregate-at-concurrency number, not
>    an ops/s/**core** number, because there is one WAL and therefore one commit stream.
> 2. **T4 improved 1.22× on top of the 2.1 figure.** HEA-1959 shipped `fdatasync`-for-appends
>    and a one-syscall batched WAL commit: **33,724 → 41,255 ops/s at T=256**, head `873263d0`,
>    `fsync`-before-ack fully intact. Artifact
>    `docs/perf/artifacts/c7-saturation-post-hea1959-sample2-raw.json`; analysis
>    `docs/perf/HEA-1959-commit-cycle.md`.
> 3. **The `T × F / W` ceiling and its "coalescing efficiency" ratio are struck.** They assume
>    `T` independent fsync streams; there is one WAL, one leader, one commit stream, so that
>    denominator grows linearly in `T` while the achievable numerator cannot. The efficiency
>    decay this report called "the entire T4 residual" was an artifact of the model, not a
>    defect — it sent HEA-1955 after a non-bottleneck. The physically meaningful model is
>    `cycle = fsync + serial_per_entry × batch` (HEA-1959 §1). Every table below that prints a
>    `ceiling` or `coalescing eff` column is retained for audit trail and labelled unreachable.
>
> **41,255 vs 30,000 = PASS at 1.38× headroom.** Honest caveat, carried from HEA-1959 §6: four
> runs of the ladder on this shared workstation produced T=256 figures of 35,726 / 42,456 /
> 30,317 / 41,255. The graded number is sample D (41,255), the representative run; the *worst*
> observed run clears the revised bar by only 1.01×. **Grade T4 on a quiet, dedicated host.**

> **What changed in 2.1 — two corrections to the board-facing verdict.**
>
> 1. **K7 was never a MISS.** The 2,840 B/user figure behind it was measured at N=12,000,
>    before the WAL had ever rotated, so an O(1) 64 MiB WAL was being amortised as an O(N)
>    per-user cost. The true post-rotation slope is **1,195.6 B/user** (OLS, R²=0.9998,
>    N≥60k) → **111.3 GiB at 100M users**, **1.80× inside** the 200 GiB budget. K7 is a
>    **PASS**. (HEA-1951.)
> 2. **T4's stated remedy in 2.0 was wrong.** 2.0 said closing T4 "requires an
>    async-durability mode or parallel WAL writers." It did not. Lock placement and write
>    merging took `session_create` from 254 → **33,724 ops/s** (**104×**) with every write
>    still `fsync`'d before acknowledgement. T4 remains a MISS, but at **1.48×**, not 316×,
>    and **no durability trade is on the table.** (HEA-1948 / 1954 / 1955 / 1956.)
>    *(Superseded by 2.1a above: T4 is now a PASS at 41,255 ops/s against a 30,000 target.)*

> **Board-facing caveat 1 — hardware:** Every figure in this report was measured on
> `dev-ryzen-7840hs` (AMD Ryzen 7 7840HS mobile, 8 physical cores / 16 threads, governor
> `powersave`, ~21 GiB RAM available at run time). These are **lower bounds on server-class
> silicon, not predictions.**
>
> **Board-facing caveat 2 — clustering:** Hearth's cluster layer (`openraft`) replicates — it
> does not shard. A 5-node cluster holds the same dataset as one node, five times. **Single-node
> capacity is the capacity floor of the entire product, cluster included.**

---

## 0. Board-facing verdict

**A single Hearth node can hold millions of users in production and serve the read-heavy identity
hot path at the VISION targets by a factor of 2–75×. As of revision 2.1a, no graded row is a
MISS.** The one gap that survived into 2.1 closed as follows:

1. **Session creation throughput (T4): PASS at 1.38×.** Measured **41,255 ops/s at 256
   concurrent writers** against the revised **30,000** target, head `873263d0`, at **1.000
   WAL fsync per durable write** — the theoretical floor. That is **162× the 254 ops/s
   reported in 2.0**, bought entirely with lock placement (HEA-1948), write merging
   (HEA-1954), leader-loop tuning (HEA-1955) and commit-cycle work (HEA-1959: `fdatasync`
   for appends, one `write_all` per batch, one AES key schedule per batch). **No durability
   guarantee was relaxed at any point.** Artifact:
   `docs/perf/artifacts/c7-saturation-post-hea1959-sample2-raw.json`; analysis:
   `docs/perf/HEA-1959-commit-cycle.md`.

   Two things this report previously asserted are **withdrawn**, both from instrumentation
   rather than argument (HEA-1959 §1–§5):

   - The `T × F / W` ceiling and the "coalescing efficiency decays to 25.5%" framing. One WAL
     means one commit stream, so that ceiling is unreachable by construction and the ratio
     measures the model, not the engine. Fitting the real cycle
     (`fsync + serial_per_entry × batch`, R²=0.91) is what located the actual cost: ~10 µs of
     *serial* CPU and syscall work per entry riding on the commit critical path, a third of
     the whole cycle at batch=110. Removing it is what produced the 1.22×.
   - "Batch-window / leader-handoff tuning at high queue depth" as the remedy. The measured
     residual is **thread-wakeup cost**: `signal` is 78% of the remaining serial term
     (3,554 of 4,584 ns/entry), ~3.5 µs per woken writer, O(threads-in-flight) per batch
     regardless of syscall count. Escaping it means not parking a thread per in-flight write —
     an async acknowledgement path, which is an architecture change, parked unstaffed in the
     backlog. Driving that term to zero would yield ~51,820 ops/s, i.e. even the *original*
     50,000 target is reachable without touching durability.

   **Explicitly retracted from 2.0:** the claim that closing T4 "requires an async-durability
   mode or parallel WAL writers." It is false, and it invited a trade — `kill -9` survival for
   a throughput number — that we neither need nor will make. `SyncMode::Async` as a default
   remains rejected. The full 162× was banked with the guarantee intact.

**Disk footprint at 100M users (K7) is corrected from MISS to PASS.** 2.0 graded K7 a 1.4×
MISS on a 2,840 B/user figure taken at N=12,000 — before the WAL's first rotation, so a fixed
64 MiB WAL was being divided across 12k users and charged as a per-user cost. Measured across
N = 5k…200k, WAL/user collapses 1,662 → 326 B as rotation kicks in (it is O(1), bounded by
`max_size`), and the SST slope converges to **1,195.6 B/user** (OLS on N≥60k, R²=0.9998).
That projects to **111.3 GiB at 100M users against a 200 GiB budget — 1.80× headroom.**
The gap never existed. Artifact: `docs/perf/HEA-1951-disk-slope-sweep.md`.

**All other targets PASS on this hardware.** The RAM ceiling for K4–K6 (capacity at 1M/10M/100M
hot users) has been eliminated by SST v3 (HEA-1914): RAM is now bounded by the block cache cap
(`storage.block_cache_bytes`, default 256 MiB), not by corpus size. Measured at 1M users: 97.1 MiB
δRSS with a 64 MiB test cache. The permission_check contention on a global `Mutex<ResolutionCache>`
(v1 exponent −0.549) is fully resolved by the sharded ArcSwap cache (HEA-1906, exponent +0.796).
SST fan-out (E4) now passes by default with `max_sst_count=12` (HEA-1931).

---

## 0.0a What changed from v2 to v2.1

| Commit | Issue | Change | Affects |
|--------|-------|--------|---------|
| `daf65d9c` + `89b161d7` | HEA-1948 | Release the audit chain lock **before** the WAL fsync wait, so group commit can coalesce | T4: 323 → 15,841 ops/s (49×) |
| `8620b0e7` | HEA-1954 | Merge `SessionCreated` into the session `put_batch` — one WAL record per `create_session` (`W` 2 → 1) | T4: ceiling 1.935× |
| `c709fa58` | HEA-1955 | Looping group-commit leader (removes inter-fsync thread-wakeup gap) | T4: p99 at T=256 halved, 23.0 → 11.9 ms |
| *(measurement only)* | HEA-1951 | Disk-slope sweep past WAL rotation, N = 5k…200k | **K7: MISS → PASS** |
| *(this issue)* | HEA-1956 | Re-measure T4 at HEAD; publish this report | T4 regrade, K7 regrade |
| `65e8185f` + `2264195c` + `bbf49734` | HEA-1959 | `fdatasync` for WAL appends (rotation keeps full `fsync`), one `write_all` + one AES key schedule per batch, O(1) commit signalling, commit-phase instrumentation | **T4: 33,724 → 41,255 ops/s (1.22×) → MISS → PASS** |

> **Honest note on HEA-1955.** It was staffed on a prediction that removing the wakeup gap
> would recover coalescing efficiency from 23% toward the 92% seen at T=1. It did not:
> measured recovery is 23.2% → **25.5%**, a 1.10× where ~4× was modelled. Decomposing the
> 2.13× gain at T=256: `1.935× ceiling (HEA-1954) × 1.101× efficiency`. Nearly all of the
> throughput gain is HEA-1954. HEA-1955's real win is latency.
>
> **2.1a addendum:** the "coalescing decay" HEA-1955 was aimed at was not a real quantity — see
> §0 item 1. HEA-1959 instrumented the commit cycle instead of modelling it and found the actual
> serial cost, which is the lesson worth keeping from both issues: **state the measured mechanism
> before proposing the fix.**

## 0.0 What changed from v1 to v2

Six Layer C commits landed after v1 was graded (2026-07-28). Every verdict change in this report
is traceable to one of them:

| Commit | Issue | Change | Affects |
|--------|-------|--------|---------|
| `20ba936d` | HEA-1906 | Replace `Mutex<ResolutionCache>` with sharded `ArcSwap` cache | T3: permission_check scaling |
| `68e7fbbc` + `746ec08a` | HEA-1908 | Streaming memtable flush (hold write lock only for O(1) swap) | Flush transient memory |
| `d6fd6e91` | HEA-1914 | Block-based SST v3 + mmap + bounded block cache | K4, K5, K6: RAM ceiling |
| `54b5df4b` + `50567a46` | HEA-1915/1924 | WAL group commit + LeaderGuard panic safety | T4: fsyncs/write |
| `919b66a4` + `fe362cde` | HEA-1922/1933 | Streaming SST compaction + Bloom-sizing fix | O(corpus) compaction transient |
| `5570b721` + `934a48df` | HEA-1931/1937 | SST merge I/O off flush_lock, max_sst_count 0→12, compact_ssts ordering fix | E4: default config |

---

## 0.1 Verdict vocabulary (unchanged from v0/v1)

| Verdict | Means |
|---|---|
| **PASS** | Measured, on stated hardware, with a fitted number or a direct observation behind it, meeting the VISION target. |
| **MISS** | Measured, on stated hardware, and does **not** meet the VISION target. Requires a ranked remediation entry in §6. |
| **NOT-MEASURABLE** | We have established that this target **cannot be measured** with the equipment, harness, or access we have — and we say *why*. |
| **NOT-MEASURED** | We have not measured it yet. |

## 0.2 Admissibility rules (binding — inherited from v0, unchanged)

1. Every figure carries the hardware it was measured on.
2. No PASS, and no "flat" / "scales well" / "linear" adjective, without a fitted number behind it.
3. Nothing is graded PASS on a run whose ceiling attribution was the generator.
4. Ratios are not costs. Only the *slope* of a multi-point regression yields a per-unit cost.
5. A run that touches swap is void.

---

## 1. Scope (unchanged from v1)

**In scope.** Single-node performance of the `hearth` binary against the targets stated in
VISION §7.1 (latency), §7.2 (throughput) and §7.3 (capacity), plus Axis E — the *shape* of the
degradation curve once the active set exceeds the hot tier.

**Out of scope.** Multi-node / Raft numbers; production-hardware numbers; comparative benchmarks.

---

## 2. Measurement hardware (unchanged)

### Host `dev-ryzen-7840hs`

| Property | Value |
|---|---|
| CPU | AMD Ryzen 7 7840HS w/ Radeon 780M — **mobile/laptop part** |
| Topology | 8 physical cores / 16 threads (SMT on) |
| Clocks | min 419 MHz · max 5137 MHz · **governor `powersave`** |
| RAM | 54 GiB total |
| Disk | WD_BLACK SN850X 2 TB NVMe (`/home`); `/scratch` tmpfs |
| OS / kernel | NixOS 26.11 (Zokor), Linux 7.0.10 |
| Toolchain | rustc 1.97.0 |
| Head SHA at v2 measurement | `981516f1` (branch `feature/perf-updates-7-28-26`) |

**v2-specific admissibility note.** The C0 memory harness (`sst_v3_c0_memory`) ran with
MemAvailable = 21 GiB and Swap used = 21,694 MiB (pre-existing system swap, not process-induced).
Swap delta during each rung was negligible (RSS for 1M-user rung: 97.1 MiB vs 21 GiB available).
Rule 5 is satisfied — no new swap pages were faulted during measurement.

---

## 3. Conformance table (v2 — rows with changed verdicts annotated with ▲)

### 3.1 VISION §7.1 — Latency targets

**The HTTP delta is no longer `NOT-MEASURABLE`.** It was measured at `1b2fda55` by C11
(HEA-1957) and is stated per row in the new *end-to-end* column. This supersedes the
HTTP-layer `NOT-MEASURABLE` finding of HEA-1871/HEA-1876; method and admissibility in §3.5.

> **Reading the two columns.** *Measured* is what the identity/storage engine costs.
> *End-to-end* is what a client over HTTP actually observes, and it is the **only** column
> comparable to a competitor's published figure. Where the engine cost is ~1 µs the HTTP
> surface dominates by ~50×; where it is milliseconds the HTTP surface is noise.

| # | Operation | Target p50 | Target p99 | Measured (engine) | End-to-end HTTP p50 (C11) | Host | Verdict | Source |
|---|---|---|---|---|---|---|---|---|
| L1 ▲ | Token validation | < 50 µs | < 500 µs | ≈ 1.314 µs (C7-v2, 1T hot) | **50.1 µs** p50 / 153.7 µs p99 @1T; 237 µs p50 / 1.59 ms p99 @32T (via `GET /userinfo`) | `dev-ryzen-7840hs` | **PASS** (engine, 38×). End-to-end: **MISS by 0.2%** on p50 at 1T (50.1 vs 50 µs), **PASS** on p99 at 1T (3.3×), **MISS** on both at 32T | C7-v2 `981516f1`; C11 `1b2fda55` `docs/perf/artifacts/c11-http-delta-raw.json` |
| L2 | Session lookup | < 10 µs | < 100 µs | ≈ 0.118 µs (C7-v2, 1T hot) | no dedicated HTTP endpoint — exercised inside L1 | `dev-ryzen-7840hs` | **PASS** (engine) | C7-v2 `981516f1` |
| L3 | Permission check | < 1 µs | < 5 µs | ≈ 0.167 µs (C7-v2, 1T hot) | not on the HTTP surface by design (claims are embedded in the JWT at issue time) | `dev-ryzen-7840hs` | **PASS** (engine) | C7-v2 `981516f1` |
| L4 | Permission resolution | < 100 µs | < 1 ms | ≈ 0.167 µs (C7-v2, cache-hit) | — | `dev-ryzen-7840hs` | **PASS** (engine, cache-hit) | C7-v2 `981516f1` |
| L5 ▲ | User lookup | < 50 µs | < 500 µs | ≈ 0.458 µs (C7-v2, 1T hot) | **50.1 µs** p50 @1T (via `GET /userinfo`; the same request also validates the token, so this is an upper bound for user lookup alone) | `dev-ryzen-7840hs` | **PASS** (engine, 109×); end-to-end p50 lands **on** the 50 µs target | C7-v2 `981516f1`; C11 `1b2fda55` |
| L9 (new) | Token introspection (RFC 7662) | — | — | 44.0 µs (C11, 1T) | **93.0 µs** @1T / 537 µs @32T | `dev-ryzen-7840hs` | no VISION target; recorded for competitive comparison | C11 `1b2fda55` |
| L6a | Token minting (no KDF) | < 1 ms | < 5 ms | — | — | `NOT-MEASURED` | needs isolated host |
| L6b | Password issuance | < 50 ms | < 100 ms | KDF floor: 12.5–29 ms (C9); gated p99: 66–213 ms (HEA-1887) | `dev-ryzen-7840hs` | `NOT-MEASURABLE` (KDF-dominated) | C9 `235e3342`, HEA-1887 |
| L7 | User creation | < 50 ms | < 100 ms | — | — | `NOT-MEASURED` | — |
| L8 | Cold-tier read | — | < 5 ms | 0.77–1.32 µs p50; 97.5–512 µs p99 (C5, 10k–320k corpus) | `dev-ryzen-7840hs` | **PASS** (extrapolated at 100M: ~2.2 ms) | C5 `b2aa7cb9` |

---

### 3.2 VISION §7.2 — Throughput targets

▲ = verdict or key metric changed from v1.

| # | Workload | Target ops/s/core | Target 16-core | Measured/core | Measured 16T | Scaling exp | Host | Verdict | Source |
|---|---|---|---|---|---|---|---|---|---|
| T1 ▲ | Token validation (hot) | 200,000+ | 3,000,000+ | **760,877** | **9,409,220** | +0.889 | `dev-ryzen-7840hs` | **PASS** (engine, 3.8×). **End-to-end HTTP: 16,642 ops/s @1T, 106,641 @32T** — a **44–63× delta**. Against the /core target the end-to-end rate is a **MISS**; it is nonetheless ~11× Ory Hydra's published end-to-end figure | C7-v2 `981516f1`; C11 `1b2fda55` |
| T2 | Mixed read/write (95/5) | 100,000+ | 1,500,000+ | — | — | — | — | `NOT-MEASURED` | harness not constructed |
| T3 ▲ | Permission check | 1,000,000+ | 15,000,000+ | **5,987,782** | **52,048,086** | **+0.796** | `dev-ryzen-7840hs` | **PASS** (engine; was −0.549 in v1) | C7-v2 `981516f1` |
| T4 ▲ | Session creation | **30,000+** agg @ stated concurrency (revised from 50,000 by the board, 2026-07-29) | — | **484** @ T=1 | **41,255** @ T=256 | **+0.851** (2.1 ladder) | `dev-ryzen-7840hs` | **PASS** ▲ (1.38×; was MISS 1.48× in 2.1, MISS 316× in v2). **No end-to-end counterpart exists** — see §3.5 F4 | C7 post-1959 `873263d0` `docs/perf/artifacts/c7-saturation-post-hea1959-sample2-raw.json` |
| T5 (new) | Password login, end-to-end (Argon2id m=19 MiB, t=2, p=1 **+** durable session create) | no VISION target | — | — | **49** @ T=1, **185** @ T=8 | — | `dev-ryzen-7840hs` | recorded; **1.3–1.4× delta** over the same work called in-process (67 / 244 ops/s) — i.e. the HTTP surface is ~0.4% of a login | C11 `1b2fda55` |

> **T3 update (▲ from v1).** The v1 `Mutex<ResolutionCache>` caused negative scaling (exponent
> −0.549, R² 0.918): adding cores reduced aggregate throughput because every `resolve_permissions`
> call serialized globally. HEA-1906 (`20ba936d`) replaced this with a sharded `ArcSwap` cache —
> the read path is now lock-free. v2 measures exponent **+0.796** (R² 0.930): throughput scales
> positively with core count. The 1T rate (5.99 M ops/s/core) clears the 1M/core target by 6×.
> The 16T aggregate (52 M ops/s) clears the 15M target by 3.5×. **T3 is a clean PASS in v2.**

> **T4 update (▲ 2.1a — PASS at 41,255 ops/s).** Graded ladder measured at head `873263d0`
> (HEA-1959, sample D), `dev-ryzen-7840hs`, **W = 1.000** WAL fsyncs per durable write:
>
> | T (concurrent writers) | agg ops/s | batch | fdatasync ms/batch | serial ns/entry | of which `signal` |
> |--:|------:|------:|---------------:|----------------:|------------------:|
> |   1 |    484 |   1.00 | 1.918 | 14,774 | 1,062 |
> |   4 |    926 |   1.76 | 1.839 | 11,468 | 1,938 |
> |  16 |  3,992 |   7.66 | 1.849 |  6,723 | 2,958 |
> |  64 | 15,572 |  31.80 | 1.881 |  4,566 | 3,068 |
> | 128 | 29,098 |  65.40 | 1.917 |  4,637 | 3,450 |
> | 256 | **41,255** | 100.79 | 1.945 | 4,584 | **3,554** |
>
> The device term is now flat across the whole ladder (1.84–1.95 ms, matching the raw device
> rate) — which is exactly what group commit is supposed to achieve, and what the struck
> `T × F / W` model could not express. The entire residual is the serial term, and `signal`
> — releasing ~100 blocked writers at ~3.5 µs each — is **78%** of it. Full mechanism,
> the two fixes, and the four-run variance envelope: `docs/perf/HEA-1959-commit-cycle.md`.
>
> **Verdict: PASS at 1.38×** (41,255 vs the revised 30,000 target).

> **T4 ladder as graded in 2.1 (superseded — retained for audit trail).** Head `c709fa58`,
> device **F = 515.8 fsyncs/s**. The `ceiling` and `coalescing eff` columns are **unreachable
> by construction** (§0 item 1) and must not be quoted forward:
>
> | T (concurrent writers) | agg ops/s | fsyncs/write | batch | ceiling `T×F/W` (unreachable) | coalescing eff (artifact) | p99 (ms) |
> |--:|------:|--------:|-------:|--------:|------:|------:|
> |   1 |    424 | 1.0000 |   1.00 |     516 | 82.2% |  5.2 |
> |   4 |    756 | 0.6526 |   1.53 |   2,063 | 36.6% |  6.6 |
> |  16 |  3,645 | 0.1336 |   7.48 |   8,253 | 44.2% |  6.7 |
> |  64 | 12,974 | 0.0326 |  30.67 |  33,013 | 39.3% |  8.1 |
> | 128 | 24,083 | 0.0154 |  64.95 |  66,026 | 36.5% |  9.4 |
> | 256 | **33,724** | 0.0091 | 109.89 | 132,053 | 25.5% | 11.9 |
>
> Scaling exponent **+0.851** (R² 0.986). Group-commit target (fsyncs/write ≪ 1.0 at ≥16T):
> **MET** — 0.0091 at T=256, i.e. ~110 durable writes per fsync.
>
> **Units restated (per HEA-1945 §Outcome, escalated to and accepted by the board).** v2 graded
> T4 in **ops/s/core**. That applies a compute framing to an I/O-bound operation: durable-write
> throughput scales with *concurrency* and *device fsync rate*, not with core count — a thread
> blocked on `fsync` consumes no CPU, so oversubscription past core count is correct rather
> than an artifact. T4 is therefore graded here as **aggregate ops/s at a stated concurrency on
> a stated device fsync rate**, with `fsyncs/write` as the engine-owned metric. The magnitude
> was **revised from 50,000 to 30,000 by the board on 2026-07-29** (HEA-1959), on the record
> that 50,000 was arbitrary rather than derived.
>
> **Verdict as graded in 2.1: MISS at 1.48×** (33,724 vs 50,000). Superseded by 2.1a. The
> attribution given here — coalescing-efficiency decay, closable by batch-window tuning — was
> **falsified by instrumentation** in HEA-1959; see §0 item 1 for what the cost actually was.

> **T1 note.** Validate_token hot 1T throughput improved from 574,363 (v1, `b29e57dd`) to
> 760,877 (v2, `981516f1`). The improvement is attributed to the removal of hot-path contention
> from the RBAC mutex that was visible even in validate_token's claim-check step.

---

### 3.3 VISION §7.3 — Capacity targets ▲ K4, K5, K6

| # | Metric | Target | Measured / Estimated | Host | Verdict | Source |
|---|---|---|---|---|---|---|
| K1 | Users per node (total) | 100M+ | — | — | `NOT-MEASURED` | C8 swap-voided; SST v3 makes this feasible but not yet measured |
| K2 | Active sessions per node | 10M+ | ~813 B/session (HEA-1907, N=4k) | `dev-ryzen-7840hs` | `NOT-MEASURED` (per-session cost only; absolute cap not validated) | HEA-1907 |
| K3 | Role assignments per node | 100M+ | — | — | `NOT-MEASURABLE` | RBAC seeder does not exist |
| K4 ▲ | Memory (idle, 1M hot users) | < 500 MB | **~329 MB** est. (97.1 MiB at 1M with 64 MiB cache → scaled to 256 MiB prod cache + overhead) | `dev-ryzen-7840hs` | **PASS** ▲ (was MISS at 20×) | C0-v3 `981516f1` `docs/perf/artifacts/c0-sst-v3-memory-raw.txt` |
| K5 ▲ | Memory (idle, 10M hot users) | < 8 GB | **~0.9 GB** est. (97.1 MiB at 1M + 9M × 66 B/user + 192 MiB cache upgrade) | `dev-ryzen-7840hs` | **PASS** ▲ (was MISS at 12×) | C0-v3 `981516f1` |
| K6 ▲ | Memory (idle, 100M hot users) | < 50 GB | **~6.5 GB** est. (97.1 MiB at 1M + 99M × 66 B/user + 192 MiB cache upgrade) | `dev-ryzen-7840hs` | **PASS** ▲ (was MISS at 20×) | C0-v3 `981516f1` |
| K7 ▲ | Disk (100M total users) | < 200 GB | **≈ 111.3 GiB** (OLS slope 1,195.6 B/user, R²=0.9998, N≥60k) | `dev-ryzen-7840hs` | **PASS** ▲ (1.80× headroom; was MISS 1.4× in v2) | HEA-1951 `abf179ba` `docs/perf/HEA-1951-disk-slope-sweep.md` |
| K8 | Binary size | < 50 MB | **41.6 MB** (39.7 MiB, v2 build `981516f1`) | `dev-ryzen-7840hs` | **PASS** | C10 artifact; check `ls -l target/release/hearth` |
| K9 | Cold start to serving | < 2 s | **70 ms** (worst-of-5, empty data dir, v1) | `dev-ryzen-7840hs` | **PASS** | C10 `6e6a24c4` |
| K10 | Cold-to-hot promotion latency | < 5 ms | — | — | `NOT-MEASURED` | C1 shipped telemetry; p50/p99 not benchmarked |

> **K4–K6 update (▲ major change from v1).** SST v3 (HEA-1914, `d6fd6e91`) replaces the
> full-file-in-RAM SST reader with a block-based format: 4 KiB encrypted blocks with a bounded
> `BlockCache` (default 256 MiB). C0-v3 (`sst_v3_c0_memory`, `981516f1`) measures with a 64 MiB
> test cache across the ladder `[10k, 50k, 100k, 500k, 1M]`:
>
> | N users | δRSS (MiB) | δRSS/user (B) | disk/user (B) |
> |---------|-----------|--------------|--------------|
> | 10,000 | 3.1 | 330 | 691 |
> | 50,000 | 7.2 | 151 | 691 |
> | 100,000 | 12.4 | 130 | 691 |
> | 500,000 | 53.0 | 111 | 691 |
> | 1,000,000 | 97.1 | **102** | 423 |
>
> OLS slope: **100 B/user** (was 9,960 B/user in v1 — **99.6× improvement**).
> Per-rung exit criterion (≤4,200 B/user): **PASS** at all rungs.
> HEA-1914 exit-criteria: **PASS** (harness verdict).
>
> The block cache (64 MiB test, 256 MiB production) acts as a working-set cap; RSS growth
> above the binding point (~213k users) is driven by the block index and Bloom filter (O(N)
> but at ~66 B/user above 500k — incremental from 500k→1M). At 1M users the full
> δRSS is 97.1 MiB. Scaling to production (256 MiB cache): 97.1 − 64 + 256 = 289 MiB + ~40 MB
> process overhead ≈ **329 MB** → K4 **PASS** (target 500 MB).
>
> **H4 is RESOLVED.** v1 §5 H4 ("SST full-RAM residency makes tiering ineffective below the hot
> tier") was the root cause of K4–K6 MISSes. HEA-1914 fixes this structurally: no record resides
> in RAM unless its block is in the bounded cache.

> **K7 update (▲ MISS → PASS — the v2 MISS was a measurement artifact).** v1/v2 graded K7 on a
> single-point figure of 2,840 B/user taken at **N = 12,000**. Ratios are not costs (§0.2 rule 4),
> and this one was taken before the WAL had ever rotated: at N=12k the corpus is ~34 MiB, under
> the 64 MiB `max_size`, so a **fixed** WAL was divided by 12,000 users and charged as a
> *per-user* cost. HEA-1951 re-measured across N = 5k…200k with a proper OLS slope:
>
> ```
>         N |     WAL bytes |     SST bytes |  WAL/user |  SST/user |  tot/user | rot
> ----------------------------------------------------------------------------------
>      5000 |       8289266 |       4617805 |      1658 |       924 |      2581 |
>     20000 |      33239266 |      23087283 |      1662 |      1154 |      2816 |
>     60000 |      32730756 |      71531203 |       546 |      1192 |      1738 | #1
>    100000 |      32342328 |     119877850 |       323 |      1199 |      1522 | #2
>    150000 |      48733746 |     177441183 |       325 |      1183 |      1508 |
>    200000 |      65125072 |     239635849 |       326 |      1198 |      1524 |
> ```
>
> The WAL term is **O(1)**, bounded by `max_size` — WAL/user collapses 1,662 → 326 B once
> rotation begins and continues → 0 as N grows. The SST term converges to a flat slope:
>
> ```
> SST_bytes = 1195.58 × N − 314,700     R² = 0.999772   (post-rotation, N ≥ 60k)
> ```
>
> Max residual ±10.5 B across the four post-rotation checkpoints. **Slope 1,195.6 B/user against
> a 2,147 B/user budget (200 GiB ÷ 100M) → 111.3 GiB at 100M users, 1.80× headroom. K7 PASSES.**
>
> Two further notes: (a) the flat slope out to N=200k confirms the HEA-1931 `max_sst_count=12`
> compaction cap holds — the load-bearing assumption behind extrapolating to 100M; (b) this run
> predates the duplicate-`UserCreated` fix landed in HEA-1956, which removes ~39.5% of stored
> bytes per user. K7 headroom is therefore expected to *improve* to roughly 3.2×, not erode.
> **ZSTD block compression is now a nice-to-have, not a requirement** — R9 is closed, not deferred.

---

### 3.4 Axis E — Degradation shape

▲ E4 verdict changed.

| # | Curve | Fitted exponent | R² | Target | Verdict | Source |
|---|---|---|---|---|---|---|
| E1 | user lookup p99 vs corpus | +0.281 (hot); +0.281 (cold-compacted) | 0.25 / 0.76 | ≤ O(log n) | **PASS** (conditional) | C5 `b2aa7cb9` |
| E2 | session lookup p99 | inherits E1 | — | ≤ O(log n) | **PASS** (proxy) | C5 `b2aa7cb9` |
| E3 | validate_token p99 | inherits E1 | — | ≤ O(log n) | **PASS** (proxy) | C5 `b2aa7cb9` |
| E4 ▲ | SST file count vs corpus | **+0.0376** (T12, default) | 0.7133 | ≤ O(log n) | **PASS** ▲ (default config; was MISS default in v1) | E4-v2 `981516f1` `docs/perf/artifacts/e4-rerun-v2-raw.txt` |
| E5 | p99 vs hot-set/capacity ratio | — | — | no cliff | `NOT-MEASURED` | C5 `b2aa7cb9` |
| E6 | Ratio at which p99 breaches budget | — | — | stated | `NOT-MEASURED` | C5 |
| E7 | Overload at 2×/5×/10× | — | — | bounded | `NOT-MEASURABLE` | C6 (server at 0% CPU) |

> **E4 update (▲ default flip, new re-run).** HEA-1931 (`5570b721`) flipped `max_sst_count`
> from 0 (disabled) to 12 (default). HEA-1931 also moved merge I/O off `flush_lock` so per-merge
> write stalls drop from O(SST-size) to commit-time metadata overhead (microseconds instead of the
> ~79s projected in v1 for 64 MiB production SSTs). E4-v2 re-measured all four trigger values on
> HEAD `981516f1`:
>
> | Config | Exponent | R² | Max write-amp | Verdict |
> |--------|----------|----|---------------|---------|
> | C (max_sst_count=0) | 1.0000 | 1.0000 | 1.16× | **MISS** |
> | T8 (max_sst_count=8) | 0.1607 | 0.8382 | 5.77× | **PASS** |
> | **T12 (max_sst_count=12, default)** | **0.0376** | **0.7133** | **4.72×** | **PASS** |
> | T16 (max_sst_count=16) | 0.1094 | 0.6022 | 3.76× | **PASS** |
>
> Per-merge stall at 256 KiB threshold (T12): p50=27.5 ms, p99=143.1 ms, max=359.1 ms.
> At the 64 MiB production flush threshold, merge I/O (now off `flush_lock`) runs concurrently
> with writes; only the commit phase (splice reader-Vec) holds the lock — O(microseconds).
> HEA-1931 acceptance criterion: **T12 exponent 0.0376 ≤ 0.20 → PASS.**
> E1–E3 conditional PASSes now hold in the **default configuration**.

---

### 3.5 Axis C11 — the end-to-end HTTP delta ▲ (new; supersedes HEA-1871/HEA-1876 `NOT-MEASURABLE`)

Full analysis: `docs/perf/HEA-1957-HTTP-DELTA.md`.
Raw: `docs/perf/artifacts/c11-http-delta-raw.json` · Harness: `examples/http_delta.rs`.

Engine phase and HTTP phase run **in the same process, in the same run, against the same
fixture** — the real `protocol::http` and `protocol::web` axum routers on real loopback TCP
listeners, driven by a closed-loop hand-rolled HTTP/1.1 client.

| Operation | T | engine ops/s | HTTP ops/s | **delta ratio** | engine p50 | HTTP p50 | generator headroom |
|---|--:|--:|--:|--:|--:|--:|--:|
| `introspect_token` → `POST /realms/{r}/introspect` | 1 | 21,802 | 9,508 | **2.3×** | 44.0 µs | 93.0 µs | 5.4× |
| | 32 | 125,613 | 55,700 | **2.3×** | 101.9 µs | 537.5 µs | 9.0× |
| `validate_token`+`get_user` → `GET /realms/{r}/userinfo` | 1 | 731,419 | 16,642 | **44.0×** | 1.15 µs | 50.1 µs | 3.1× |
| | 8 | 4,500,392 | 71,029 | **63.4×** | 1.64 µs | 87.8 µs | 3.5× |
| | 32 | 6,045,477 | 106,641 | **56.7×** | 1.96 µs | 237.1 µs | 4.7× |
| `verify_password`+`create_session` → `POST /ui/realms/{r}/login` | 1 | 67 | 49 | **1.4×** | 14.70 ms | 20.08 ms | 1042× |
| | 8 | 244 | 185 | **1.3×** | 32.29 ms | 42.87 ms | 1355× |

All rows: **100% success**, generator headroom **3.1×–1355×**. Admissibility rule 3 is
satisfied numerically, not by assertion: a bare canned-response TCP server in the same
process measures the driver's own ceiling (51,407 / 251,185 / 500,031 ops/s at T=1/8/32),
and every row is published against it.

**HTTP envelope floor** (`GET /healthz`, same stack, engine removed): 32,865 ops/s p50
25.4 µs @1T; 187,070 ops/s @32T. Decomposed at 1T: ~17.2 µs driver + kernel loopback,
**~8.2 µs axum/hyper/tower**. Both engine-backed API endpoints add the **same ~23.5 µs** of
handler cost above that floor regardless of engine work — that constant is the entire
read-path HTTP delta.

**F1.** The delta is inversely proportional to engine work. The HTTP stack costs a near-
constant ~25 µs p50; the ratio is just `(envelope + handler) ÷ (engine cost)`.

**F2.** `T1 = 760,877 validate_token/s/core` **must not** be quoted against a competitor's
HTTP number. The end-to-end figure is 16,642 @1T / 106,641 @32T.

**F3.** `POST /realms/{r}/introspect` is the fair head-to-head endpoint. Hearth **55,700 /s
p50 537 µs** vs Ory Hydra's published **5,109 /s p50 13.3 ms** — **≈11× throughput, ≈25×
lower p50, end-to-end against end-to-end**, and against a real storage engine where Hydra's
figure uses an in-memory adapter with no DB. That is the publishable claim; the 149× that
falls out of the engine-vs-HTTP comparison is not.

**F4.** **T4 has no end-to-end counterpart.** `create_session` is reachable over HTTP only
via web login and the federation callback, both of which pay an Argon2id verify first. The
~30 µs session create is buried under 14.7 ms of KDF, so **T4's residual is invisible from
outside the process.** Further T4 work should be justified on durability-headroom grounds, not
end-to-end latency — which, with T4 now a PASS, is why the remaining wakeup-cost item is parked
in the backlog rather than staffed.

**F5.** The `RequestShaper` default caps **one source IP at 100 rps** (`realm_rps` 1,000).
The measured run disables it — those limits bound one client, not server capacity — but any
published throughput figure must carry that note.

**Excluded, and disclosed:** TLS, physical network/RTT, client-server core isolation, and
connection-establishment cost. All four push the same way, so **the HTTP figures are an
upper bound and the delta ratios a lower bound.**

**Argon2id in force for the login row (stated, because no competitor states theirs):**
`m = 19,456 KiB`, `t = 2`, `p = 1` — production `CredentialConfig::default()`, **not**
`fast_for_testing()`.

---

## 4. The per-user memory numbers (v2)

v2 adds the SST v3 C0-v3 measurement to the three-number table from v1.

| Number | Pre-remediation (C0, `3429ce43`) | Post-Layer-B+A (HEA-1904, `c82d8eb8`) | Post-Layer-C SST v3 (C0-v3, `981516f1`) | Method | Host |
|---|---|---|---|---|---|
| **bytes-resident-per-user (OLS slope)** | 24,141 B | 9,960 B | **100 B** | OLS on 5-rung ladder [10k–1M] | `dev-ryzen-7840hs` |
| δRSS at N = 1,000,000 | ~24 GiB (extrapolated) | ~9.76 GiB (extrapolated) | **97.1 MiB** (measured) | Direct measurement | `dev-ryzen-7840hs` |
| Fixed block-cache overhead (prod, 256 MiB) | N/A | N/A | **~256 MiB** (constant cap) | Config default | — |
| Incremental above cache-binding (>500k users) | N/A | N/A | **~66 B/user** (block-index + Bloom) | Derived from 500k→1M delta | `dev-ryzen-7840hs` |
| **bytes-on-disk-per-user (real User, v1)** | 4,573 B | 2,840 B | 2,840 B (unchanged; SST v3 doesn't reduce payload) | OLS, HEA-1904 | `dev-ryzen-7840hs` |
| **bytes-on-disk-per-user (C0-v3 synthetic, 300B records)** | — | — | **691 B** (at 100k–500k) | C0-v3 harness | `dev-ryzen-7840hs` |

**Max corpus on this host (v2 estimate):**
- Available RAM for corpus: 21 GiB − 256 MiB (cache) − 40 MB (process) ≈ 20.7 GiB
- Above cache-binding: ~20.7 GiB ÷ 66 B/user ≈ **320 million users** (theoretical; host RAM is
  the only limit when RAM is bounded by block index, not corpus data)
- Pre-v3 for comparison: (14 GiB − 40 MB) ÷ 9.96 KB/user ≈ 1.4M users

---

## 5. Standing architectural risk (updated)

**H1 — Cold-lookup fan-out.** CONFIRMED O(#SSTs) transient; O(log n) post-compaction.
UNCHANGED from v1. E4 default is now compacted (T12), so E1–E3 conditional PASSes hold in
the default configuration.

**H2 — Blind hot-tier telemetry.** ADDRESSED by C1. UNCHANGED.

**H3 — Single-node capacity is not escapable by clustering.** UNCHANGED.

**H4 — SST full-RAM residency. RESOLVED by HEA-1914.** `SstReader` no longer decrypts the
whole file into RAM at open time. Block-based SST v3 with a bounded `BlockCache` (256 MiB
default) bounds the storage-layer RSS to O(block_cache_size + N × 66 B) rather than
O(N × record_size). K4–K6 MISSes that were attributed to H4 in v1 now PASS. See §3.3.

**H5 — WAL audit-chain fsync serializes session creation. ▲ RESOLVED in v2.1.** v2 diagnosed
`session_create` as pinned at ~254 ops/s because the per-realm audit hash-chain update was a
separate, uncoalesced fsync. The diagnosis was right; the proposed remedy was wrong.

Two fixes closed it, both preserving `fsync`-before-ack:

1. **HEA-1948** — `EmbeddedAuditEngine::append` held the per-realm chain lock across the entire
   WAL `sync_all` wait, so at most one audit append per realm could be in flight and no amount
   of concurrency produced additional coalescing (batch size pinned at 0.65 ops/fsync from T=4
   to T=256). Releasing the lock before the durability wait restored coalescing: batch size now
   grows monotonically to 109.89 at T=256. **49× at T=256.**
2. **HEA-1954** — `SessionCreated` merged into the session `put_batch`, so caller data and audit
   event share one WAL record. `W` 2 → 1. **1.935× on the ceiling.** This also *closed a crash
   window*: a `kill -9` between the two former records could strand a session with no
   `SessionCreated` event; a CRC failure on the merged record now discards both.

Net: 254 → 33,724 ops/s, **104×**, durability untouched. With HEA-1959: **254 → 41,255, 162×.**

**H5-residual — ~~coalescing efficiency decay~~ serial per-entry work, then thread-wakeup cost.**
2.1 attributed the residual to coalescing efficiency falling 82.2% (T=1) → 25.5% (T=256) against
a `T × F / W` ceiling. **Both the ceiling and the attribution are withdrawn in 2.1a**: the
ceiling assumes `T` independent fsync streams and there is one WAL. HEA-1959 instrumented the
real commit cycle and found ~10 µs/entry of *serial* work on the critical path — three
`write_all` syscalls, an AES key schedule, and a futex wake **per entry** — plus a `sync_all`
that grew with batch size (3.79 ms at batch 31 → 7.38 ms at batch 131) because it was journaling
metadata the WAL does not depend on. Fixes: `fdatasync` for appends (rotation keeps a full
`fsync`), one `write_all` and one key schedule per batch, O(1) commit signalling. Serial cost
8,984 → 4,584 ns/entry; **33,724 → 41,255 ops/s**.

What remains is **thread-wakeup cost**: 3,554 of the 4,584 ns/entry is `signal`, ~358 µs per
batch to release ~100 blocked writers. That is O(threads-in-flight) per batch in the kernel
regardless of syscall count, so collapsing N `notify_one` into one `notify_all` did **not** help
(it got marginally worse — the broadcast also wakes next-batch writers, a genuine thundering
herd). It is a design limit of parking a thread per in-flight write, not a tuning knob. Parked
unstaffed in the backlog. **No durability trade is involved or required at any point.**

---

## 6. Ranked remediation list (v2)

| # | Item | Basis | Affects | Status |
|---|---|---|---|---|
| R1 | **KDF admission gate.** | Measured, C9 | L6b, E7 | **SHIPPED — HEA-1887 + HEA-1892** |
| R2 | **`summary.ceiling` misreports.** | Data inspection | Rule-3 | **DONE — C11 HEA-1880** |
| R3 | **Memtable CoW clone (Layer B).** | Measured, C0 | K4–K7, T4 | **SHIPPED — HEA-1897 `faec7e66`** |
| R4 | **Record encoding (Layer A).** | Measured, C0 | K4–K7 | **SHIPPED — HEA-1898/1899 `c82d8eb8`** |
| R5 | **`permission_check` scales negatively.** | Measured, C7 v1 | T3 | **SHIPPED — HEA-1906 `20ba936d`** (exponent +0.796 in v2) |
| R6 | **E4 default SST fan-out O(n).** | Measured, C2 + HEA-1885 | E4 | **SHIPPED ON — HEA-1931 `5570b721`** (default max_sst_count=12; merge I/O off flush_lock) |
| R7 | **SST full-RAM residency Θ(corpus).** | Code + HEA-1881 | K1, K4–K6 | **SHIPPED — HEA-1914 `d6fd6e91`** (block-based SST v3 + bounded BlockCache). K4–K6 now PASS. |
| **R8** | **WAL audit-chain fsync serializes session_create (T4 MISS).** | Measured, C7 v2 (H5 above) | T4 | **SHIPPED — HEA-1948 `daf65d9c` + HEA-1954 `8620b0e7` + HEA-1955 `c709fa58` + HEA-1959 `873263d0`.** 254 → 41,255 ops/s (162×) with `fsync`-before-ack intact. `W` = 1.000, the floor. The v2 note that this "requires an async-durability mode or parallel WAL writers" is **retracted as false**. |
| **R8a** | ~~**Group-commit coalescing efficiency decays to 25.5% at T=256.**~~ | ~~Measured, HEA-1956~~ | T4 | **CLOSED — THE METRIC WAS THE DEFECT.** `T × F / W` presumes `T` fsync streams; there is one WAL. HEA-1959 replaced it with the fitted cycle model, found ~10 µs/entry of serial commit-path work, and removed most of it: **33,724 → 41,255 ops/s**, T4 **PASS** at 1.38× against the revised 30,000 target. |
| **R8b** | **Commit signalling is O(threads-in-flight).** 3,554 of 4,584 ns/entry serial cost at T=256; ~358 µs/batch to wake ~100 writers. Ceiling if driven to zero: ~51,820 ops/s. | Measured, HEA-1959 §5 | T4 headroom only | **PARKED — NOT STAFFED.** T4 passes without it. Escaping the cost requires a completion/async-acknowledgement path instead of a parked thread per in-flight write — an architecture change. Backlog `5a1c65bb`. **No durability implication.** |
| **R9** | ~~**Disk footprint at 100M users (K7 MISS, 1.4×).**~~ | ~~Measured, HEA-1904~~ | K7 | **CLOSED — NOT A DEFECT.** HEA-1951 showed the 1.4× MISS was a pre-WAL-rotation small-N artifact. True slope 1,195.6 B/user → 111.3 GiB at 100M, 1.80× headroom. ZSTD block compression is a nice-to-have, not a requirement. |

---

## 7. Data contract (v2)

### 7.1 Committed artifacts

| Artifact | Run | Covers |
|----------|-----|--------|
| `docs/perf/artifacts/c7-saturation-v2-raw.json` | C7-v2, `981516f1`, 2026-07-29 | T1, T3, T4 (v2) |
| `docs/perf/artifacts/c7-saturation-post-hea1959-sample2-raw.json` | C7 post-1959 sample D, `873263d0`, 2026-07-29 | **T4 (v2.1a — the graded run)** |
| `docs/perf/artifacts/c7-saturation-post-hea1959-sample2-console.txt` | same run, human-readable | T4 (v2.1a) |
| `docs/perf/artifacts/c7-saturation-post-hea1959-raw.json` / `-console.txt` | C7 post-1959 sample C, same binary | T4 (variance envelope, §0) |
| `docs/perf/artifacts/c7-hea1959-phase-baseline-console.txt` | pre-fix commit-phase split | T4 (mechanism) |
| `docs/perf/artifacts/c7-hea1959-fdatasync-only-console.txt` | fix 1 in isolation | T4 (mechanism) |
| `docs/perf/artifacts/c7-hea1959-batched-writes-console.txt` | fixes 1+2 | T4 (mechanism) |
| `docs/perf/HEA-1959-commit-cycle.md` | HEA-1959 analysis, 2026-07-29 | **T4 (v2.1a — the PASS proof)** |
| `docs/perf/artifacts/c7-saturation-post-hea1955-raw.json` | C7 post-1955, `c709fa58`, 2026-07-29 | T4 (v2.1 — superseded) |
| `docs/perf/artifacts/c7-saturation-post-hea1955-console.txt` | same run, human-readable | T4 (v2.1 — superseded) |
| `docs/perf/HEA-1956-T4-remeasure.md` | HEA-1956 analysis, 2026-07-29 | T4 (v2.1 — superseded) |
| `docs/perf/HEA-1951-disk-slope-sweep.md` | HEA-1951 disk slope, `abf179ba`, 2026-07-29 | **K7 (v2.1 — the PASS proof)** |
| `docs/perf/artifacts/c7-saturation-hea1949-raw.json` | C7 HEA-1949 pre-1948 baseline, 2026-07-29 | T4 (baseline) |
| `docs/perf/artifacts/c7-saturation-post-hea1948-raw.json` | C7 post-1948, `daf65d9c`, 2026-07-29 | T4 (intermediate) |
| `docs/perf/artifacts/c0-sst-v3-memory-raw.txt` | C0-v3, `981516f1`, 2026-07-29 | K4–K6, §4 per-user memory |
| `docs/perf/artifacts/e4-rerun-v2-raw.txt` | E4-v2, `981516f1`, 2026-07-29 | E4 (T12 default + T8/T16) |
| `docs/perf/artifacts/c7-saturation-raw.json` | C7-v1, `b29e57dd`, 2026-07-28 | T1, T3 (v1 baseline) |
| `docs/perf/artifacts/c5-complexity-sweep-raw.json` | C5, `b2aa7cb9`, 2026-07-28 | E1–E4 |
| `docs/perf/artifacts/c9-issuance-argon2.json` | C9, `235e3342`, 2026-07-28 | L6b |
| `docs/perf/artifacts/c10-artifact-facts.json` | C10, `6e6a24c4`, 2026-07-28 | K8, K9 |
| `docs/perf/artifacts/c11-http-delta-raw.json` | C11, `1b2fda55`, 2026-07-29 | **§3.5 HTTP delta — L1, L5, L9, T1, T5** |
| `docs/perf/artifacts/c11-http-delta-console.txt` | same run, human-readable | §3.5 |
| `docs/perf/HEA-1957-HTTP-DELTA.md` | HEA-1957 analysis, 2026-07-29 | §3.5, competitive restatement |

### 7.2 How to reproduce v2 runs

All four measurements run in-process — no external server, no load generator. C11 boots the
real axum routers on ephemeral loopback ports inside the harness process:

```bash
# C7-v2: saturation throughput (permission_check + session_create scaling)
RUSTC_WRAPPER="" PROTOC=$(which protoc) cargo run --release --example saturation_throughput

# C0-v3: per-user memory with SST v3 block cache
RUSTC_WRAPPER="" PROTOC=$(which protoc) cargo run --release --example sst_v3_c0_memory

# E4-v2: SST fan-out across trigger values (including T12 default)
RUSTC_WRAPPER="" PROTOC=$(which protoc) cargo run --release --example sst_growth_e4_rerun

# C11: end-to-end HTTP delta (engine vs HTTP, same process, same run)   [HEA-1957]
RUSTC_WRAPPER="" PROTOC=$(which protoc) cargo run --release --example http_delta
```

C7-v2 / C0-v3 / E4-v2 are deterministic on `feature/perf-updates-7-28-26` HEAD `981516f1`;
C11 was measured at HEAD `1b2fda55` on the same branch and host. C11 takes ≈ 3 minutes,
dominated by provisioning 32 Argon2id credentials at m = 19 MiB.

---

## 8. Programme status (as of 2026-07-29)

**Overall: 19 PASS / 0 MISS / 4 NOT-MEASURABLE / 7 NOT-MEASURED across 30 rows.**
*(2.1 as first published printed "17 PASS / 2 MISS" here against "18 PASS / 1 MISS" in the status
header — a stale count, not a regrade. The body's own row list was the correct one.)*

Change from v1 (13 PASS / 6 MISS):

| Row | v1 Verdict | v2 Verdict | Change |
|-----|-----------|-----------|--------|
| T3 (permission_check) | PASS (note: neg scaling −0.549) | **PASS** (positive scaling +0.796) | ▲ note resolved |
| K4 (memory 1M) | MISS (20×) | **PASS** | ▲ 4 rungs improved |
| K5 (memory 10M) | MISS (12×) | **PASS** | ▲ |
| K6 (memory 100M) | MISS (20×) | **PASS** | ▲ |
| E4 (SST fan-out) | MISS (default) / PASS (lever-1) | **PASS** (default T12) | ▲ default flipped |

**Remaining MISSes (0).**

**Regraded MISS → PASS in 2.1a (1):**

| Row | Was | Now | Basis |
|-----|-----|-----|-------|
| T4 (session_create) | MISS 1.48× (33,724 vs 50,000) | **PASS 1.38×** (41,255 vs 30,000) | Target revised by the board 2026-07-29 (50,000 was arbitrary); **and** +1.22× measured from HEA-1959's commit-cycle fixes. `W`=1.000, batch 100.79, fdatasync flat at 1.94 ms. `fsync`-before-ack intact. |

**Regraded MISS → PASS in 2.1 (1):** K7 (disk at 100M users) — v2's 1.4× MISS was a
pre-WAL-rotation small-N artifact; true slope 1,195.6 B/user → 111.3 GiB, 1.80× headroom
(§3.3, HEA-1951).

**NOT-MEASURED rows (7, unchanged):** K1, K2, K10, L6a, L7, T2, E5, E6, E7
(K1 now feasible on this host with SST v3; blocked on a second measurement run.)

**Open follow-up issues filed:** none blocking. R8 (audit-chain coalescing) is **shipped**;
R8a (coalescing efficiency) is **closed — the metric was the defect**; R8b (O(K) commit
signalling) is **parked unstaffed** in the backlog as pure headroom, `5a1c65bb`; R9 (K7 disk)
is **closed as not-a-defect**.

**Durability position (unchanged, non-negotiable).** The WAL is `fsync`'d before a write is
acknowledged and must survive `kill -9`. `SyncMode::Async` as a default is **rejected**, and as
of v2.1a there is no longer a performance argument for it at all: the full **162×** on T4 was
obtained with the guarantee fully intact, and T4 now **passes** with `fsync`-before-ack in force.
The remaining headroom item (R8b, thread-wakeup cost) is likewise not a durability trade.
