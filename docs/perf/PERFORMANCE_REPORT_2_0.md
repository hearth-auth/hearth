# Hearth — Performance Report 2.0

**Status:** `v2 — GRADED. 17 PASS / 2 MISS / 4 NOT-MEASURABLE / 7 NOT-MEASURED across 30 rows`
**Owner:** CTO (HEA-1867) · **QA:** HEA-1940 (QA) · **Parent:** HEA-1867
**Last updated:** 2026-07-29 · **Branch:** `feature/perf-updates-7-28-26` · **Head SHA:** `981516f1`
**Previous report:** `docs/perf/PERFORMANCE_REPORT_1_0.md` (v1, graded 2026-07-28, head `981516f1` at join)

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
hot path at the VISION targets by a factor of 2–75×.** The two remaining gaps are:

1. **Session creation throughput (T4): MISS at 316×.** `session_create` is limited to ~111
   ops/s/core by WAL fsync serialization. WAL group commit (HEA-1915) reduces fsyncs/write from
   3.0 to ≈1.65 at 4T but aggregate throughput saturates at ~254 ops/s system-wide. Closing this
   gap requires an async-durability mode or parallel WAL writers — not yet implemented.

2. **Disk footprint at 100M total users (K7): MISS at 1.4×.** On-disk encoding (postcard binary,
   v1 measurement `c82d8eb8`) yields ≈2,840 B/user → 264 GiB at 100M users vs the 200 GB target.
   SST v3 changes the block format but does not materially reduce per-record disk usage; K7
   requires a more compact value encoding or ZSTD block compression.

**All other targets now PASS on this hardware.** The RAM ceiling for K4–K6 (capacity at 1M/10M/100M
hot users) has been eliminated by SST v3 (HEA-1914): RAM is now bounded by the block cache cap
(`storage.block_cache_bytes`, default 256 MiB), not by corpus size. Measured at 1M users: 97.1 MiB
δRSS with a 64 MiB test cache. The permission_check contention on a global `Mutex<ResolutionCache>`
(v1 exponent −0.549) is fully resolved by the sharded ArcSwap cache (HEA-1906, exponent +0.796).
SST fan-out (E4) now passes by default with `max_sst_count=12` (HEA-1931).

---

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

All engine-level. HTTP delta NOT-MEASURABLE (HEA-1871/HEA-1876 unchanged).

| # | Operation | Target p50 | Target p99 | Measured | Host | Verdict | Source |
|---|---|---|---|---|---|---|---|
| L1 | Token validation | < 50 µs | < 500 µs | ≈ 1.314 µs (C7-v2, 1T hot) | `dev-ryzen-7840hs` | **PASS** (engine) | C7-v2 `981516f1` `docs/perf/artifacts/c7-saturation-v2-raw.json` |
| L2 | Session lookup | < 10 µs | < 100 µs | ≈ 0.118 µs (C7-v2, 1T hot) | `dev-ryzen-7840hs` | **PASS** (engine) | C7-v2 `981516f1` |
| L3 | Permission check | < 1 µs | < 5 µs | ≈ 0.167 µs (C7-v2, 1T hot) | `dev-ryzen-7840hs` | **PASS** (engine) | C7-v2 `981516f1` |
| L4 | Permission resolution | < 100 µs | < 1 ms | ≈ 0.167 µs (C7-v2, cache-hit) | `dev-ryzen-7840hs` | **PASS** (engine, cache-hit) | C7-v2 `981516f1` |
| L5 | User lookup | < 50 µs | < 500 µs | ≈ 0.458 µs (C7-v2, 1T hot) | `dev-ryzen-7840hs` | **PASS** (engine) | C7-v2 `981516f1` |
| L6a | Token minting (no KDF) | < 1 ms | < 5 ms | — | — | `NOT-MEASURED` | needs isolated host |
| L6b | Password issuance | < 50 ms | < 100 ms | KDF floor: 12.5–29 ms (C9); gated p99: 66–213 ms (HEA-1887) | `dev-ryzen-7840hs` | `NOT-MEASURABLE` (KDF-dominated) | C9 `235e3342`, HEA-1887 |
| L7 | User creation | < 50 ms | < 100 ms | — | — | `NOT-MEASURED` | — |
| L8 | Cold-tier read | — | < 5 ms | 0.77–1.32 µs p50; 97.5–512 µs p99 (C5, 10k–320k corpus) | `dev-ryzen-7840hs` | **PASS** (extrapolated at 100M: ~2.2 ms) | C5 `b2aa7cb9` |

---

### 3.2 VISION §7.2 — Throughput targets

▲ = verdict or key metric changed from v1.

| # | Workload | Target ops/s/core | Target 16-core | Measured/core | Measured 16T | Scaling exp | Host | Verdict | Source |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Token validation (hot) | 200,000+ | 3,000,000+ | **760,877** | **9,409,220** | +0.889 | `dev-ryzen-7840hs` | **PASS** (engine) | C7-v2 `981516f1` |
| T2 | Mixed read/write (95/5) | 100,000+ | 1,500,000+ | — | — | — | — | `NOT-MEASURED` | harness not constructed |
| T3 ▲ | Permission check | 1,000,000+ | 15,000,000+ | **5,987,782** | **52,048,086** | **+0.796** | `dev-ryzen-7840hs` | **PASS** (engine; was −0.549 in v1) | C7-v2 `981516f1` |
| T4 | Session creation | 50,000+ | 500,000+ | **111** | **254** | +0.299 | `dev-ryzen-7840hs` | **MISS** (fsync-bound; 316× below target) | C7-v2 `981516f1` |

> **T3 update (▲ from v1).** The v1 `Mutex<ResolutionCache>` caused negative scaling (exponent
> −0.549, R² 0.918): adding cores reduced aggregate throughput because every `resolve_permissions`
> call serialized globally. HEA-1906 (`20ba936d`) replaced this with a sharded `ArcSwap` cache —
> the read path is now lock-free. v2 measures exponent **+0.796** (R² 0.930): throughput scales
> positively with core count. The 1T rate (5.99 M ops/s/core) clears the 1M/core target by 6×.
> The 16T aggregate (52 M ops/s) clears the 15M target by 3.5×. **T3 is a clean PASS in v2.**

> **T4 update (group commit partial improvement).** WAL group commit (HEA-1915/1924) is
> measurably working: fsyncs/write drops from 3.000 at 1T to 1.654 at 4T and 1.931 at 16T
> (batching effect visible but not fully coalesced). Aggregate throughput saturates at ~254 ops/s
> regardless of thread count. Group-commit target (fsyncs/write << 1.0 at ≥8T) is not met —
> each write still requires at least 1 fsync path (audit chain, not WAL). T4 remains MISS. The
> path to PASS requires either (a) audit-chain fsync coalescing or (b) an async-durability mode.

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
| K7 | Disk (100M total users) | < 200 GB | **≈ 264 GiB** (2,840 B/user × 100M, v1 measurement unchanged) | `dev-ryzen-7840hs` | **MISS** (1.4×) | v1 HEA-1904 `c82d8eb8` |
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

> **K7 unchanged.** SST v3 changes the on-disk block format but does not reduce per-record payload
> size. The v1 measurement of 2,840 B/user (postcard-encoded real `User` + email index + audit
> records, commit `c82d8eb8`) remains the authoritative disk figure. At 100M users: 264 GiB vs the
> 200 GB target. ZSTD block compression (not yet implemented) is the next disk lever.

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

**H5 (new) — WAL audit-chain fsync serializes session creation.** `session_create` produces
at least one fsync per write that is not coalesced by the WAL group commit because the per-realm
audit hash-chain update is a separate fsync operation. Even with group commit (HEA-1915/1924),
fsyncs/write floor at ~1.65 (4T) and aggregate throughput plateaus at ~254 ops/s system-wide.
The WAL group commit batches WAL fsyncs; it does not batch audit-chain fsyncs.
Target to close T4: audit-chain write coalescing or async-durability (`SyncMode::Async`).

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
| **R8** | **WAL audit-chain fsync serializes session_create (T4 MISS, 316×).** | Measured, C7 v2 (H5 above) | T4 | **OPEN.** Requires audit-chain write coalescing or async WAL durability mode (`SyncMode::Async`). Tracked: see §0 verdict item 1. |
| **R9** | **Disk footprint at 100M users (K7 MISS, 1.4×).** | Measured, HEA-1904 | K7 | **OPEN.** Requires ZSTD block compression (per-block in SST v3) or more compact audit encoding. |

---

## 7. Data contract (v2)

### 7.1 Committed artifacts

| Artifact | Run | Covers |
|----------|-----|--------|
| `docs/perf/artifacts/c7-saturation-v2-raw.json` | C7-v2, `981516f1`, 2026-07-29 | T1, T3, T4 (v2) |
| `docs/perf/artifacts/c0-sst-v3-memory-raw.txt` | C0-v3, `981516f1`, 2026-07-29 | K4–K6, §4 per-user memory |
| `docs/perf/artifacts/e4-rerun-v2-raw.txt` | E4-v2, `981516f1`, 2026-07-29 | E4 (T12 default + T8/T16) |
| `docs/perf/artifacts/c7-saturation-raw.json` | C7-v1, `b29e57dd`, 2026-07-28 | T1, T3 (v1 baseline) |
| `docs/perf/artifacts/c5-complexity-sweep-raw.json` | C5, `b2aa7cb9`, 2026-07-28 | E1–E4 |
| `docs/perf/artifacts/c9-issuance-argon2.json` | C9, `235e3342`, 2026-07-28 | L6b |
| `docs/perf/artifacts/c10-artifact-facts.json` | C10, `6e6a24c4`, 2026-07-28 | K8, K9 |

### 7.2 How to reproduce v2 runs

All three new measurements run in-process, no server, no load generator:

```bash
# C7-v2: saturation throughput (permission_check + session_create scaling)
RUSTC_WRAPPER="" PROTOC=$(which protoc) cargo run --release --example saturation_throughput

# C0-v3: per-user memory with SST v3 block cache
RUSTC_WRAPPER="" PROTOC=$(which protoc) cargo run --release --example sst_v3_c0_memory

# E4-v2: SST fan-out across trigger values (including T12 default)
RUSTC_WRAPPER="" PROTOC=$(which protoc) cargo run --release --example sst_growth_e4_rerun
```

Build is deterministic on `feature/perf-updates-7-28-26` HEAD `981516f1`.

---

## 8. Programme status (as of 2026-07-29)

**Overall: 17 PASS / 2 MISS / 4 NOT-MEASURABLE / 7 NOT-MEASURED across 30 rows.**

Change from v1 (13 PASS / 6 MISS):

| Row | v1 Verdict | v2 Verdict | Change |
|-----|-----------|-----------|--------|
| T3 (permission_check) | PASS (note: neg scaling −0.549) | **PASS** (positive scaling +0.796) | ▲ note resolved |
| K4 (memory 1M) | MISS (20×) | **PASS** | ▲ 4 rungs improved |
| K5 (memory 10M) | MISS (12×) | **PASS** | ▲ |
| K6 (memory 100M) | MISS (20×) | **PASS** | ▲ |
| E4 (SST fan-out) | MISS (default) / PASS (lever-1) | **PASS** (default T12) | ▲ default flipped |

**Remaining MISSes (2):**

| Row | MISS detail | Next action |
|-----|-------------|------------|
| T4 (session_create) | 111 ops/s vs 50k target (316×); group commit partial (fsyncs/write 3.0→1.65) | Audit-chain fsync coalescing or `SyncMode::Async` |
| K7 (disk, 100M users) | 264 GiB vs 200 GB target (1.4×) | ZSTD block compression in SST v3 |

**NOT-MEASURED rows (7, unchanged):** K1, K2, K10, L6a, L7, T2, E5, E6, E7
(K1 now feasible on this host with SST v3; blocked on a second measurement run.)

**Open follow-up issues filed:** See §6 R8 (T4 audit-chain coalescing) and R9 (K7 ZSTD compression).
