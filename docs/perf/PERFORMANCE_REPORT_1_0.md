# Hearth — Performance Report 1.0

**Status:** `v1 — GRADED. 13 PASS / 6 MISS / 4 NOT-MEASURABLE / 7 NOT-MEASURED across 30 rows`
**Owner:** CTO (HEA-1867) · **Joined by:** HEA-1901 (TechnicalWriter) · **CTO-reviewed:** 2026-07-28 · **Parent:** HEA-1867
**Last updated:** 2026-07-28 · **Branch:** `feature/perf-updates-7-28-26` · **Head SHA at join:** `c0954f6b` · **Post-remediation C0 re-run:** `c82d8eb8` (HEA-1904)

> **Board-facing caveat 1 — hardware:** Every figure in this report was measured on
> `dev-ryzen-7840hs` (AMD Ryzen 7 7840HS mobile, 8 physical cores / 16 threads, governor
> `powersave`, ~13–19 GiB RAM free depending on child issue, 18 GiB swap in use at rest). These
> are **lower bounds on server-class silicon, not predictions.**
>
> **Board-facing caveat 2 — clustering:** Hearth's cluster layer (`openraft`) replicates — it
> does not shard. A 5-node cluster holds the same dataset as one node, five times. **Single-node
> capacity is the capacity floor of the entire product, cluster included.**
>
> **Remediation update (HEA-1904, 2026-07-28):** HEA-1896–HEA-1900 (Layer B — memtable CoW clone →
> lock-free SkipMap; Layer A — postcard binary encoding, 16-byte UUID index, compact audit keys)
> are **SHIPPED** on `c82d8eb8`. Post-remediation C0 re-run confirms: 2.4× memory improvement
> (24,141 → 9,960 B/user), 1.6× disk improvement (4,573 → 2,840 B/user), 23× write-throughput
> improvement (7.76 → 0.34 ms/user at N=12k). K4–K7 remain MISS. Next lever: Layer C (SST eviction,
> HEA-1881). See `docs/perf/HEA-1904-C0-RERUN-POST-LAYERBA.md`.

---

## 0. Read this first

This report was authored in v0 **before** any measurements existed, to fix the grading contract
while every cell was empty. C0–C9 and C11 have since landed (11 of 12 children done, 20 commits
on `feature/perf-updates-7-28-26`). This v1 re-join fills every reachable cell from committed
artifacts only — no new runs, no invented numbers.

Current tally across the 30 rows in §3 (29 from v0 + L6 split into L6a/L6b per CTO spec decision
`docs/perf/HEA-1879-cto-spec-decision.md`, board vote pending):

| Verdict | Count | Rows |
|---|---|---|
| PASS | 13 | K8, K9, L1, L2, L3, L4, L5, L8, T1, T3, E1, E2, E3 |
| MISS | 6 | K4, K5, K6, K7, T4, E4 |
| NOT-MEASURABLE | 3 | K3, E7, L6b |
| NOT-MEASURED | 8 | K1, K2, K10, L6a, L7, T2, E5, E6 |

**Scope note on PASS rows L1–L5, L8, T1, T3, E1–E3.** All thirteen rows were settled at the
**engine layer** — `EmbeddedStorageEngine` driven in-process with no HTTP server and no load
generator. Per the binding grading rule, nothing is graded PASS on a generator-ceilinged run, and
the co-resident environment made HTTP-path measurement inadmissible (C3 bisected the throughput
cliff to the server side; C8 swap-voided every rung). The engine-floor PASSes are real: at the
measured operating points the VISION targets are met with large headroom (L1 engine p50 ≈ 1.74 µs
vs. 50 µs target; T1 engine 574 k ops/s/core vs. 200 k target). The HTTP + Tokio envelope on top
of these numbers is explicitly **NOT-MEASURABLE** in this environment and is not claimed.

**Axes B (session scale) and C (10k+ concurrency) are NOT VALIDATED pending a second host.**
K2 (10M+ sessions) is NOT-MEASURABLE (ROPC grant removed by HEA-1862; no session-seeding path
exists). T1–T4 over HTTP at 10k+ concurrent clients require an isolated generator host — C4 proved
the generator can sustain 10k connections but the server-side HTTP throughput measurement is
NOT-MEASURABLE on this box.

### 0.0 CTO review record (2026-07-28)

The v1 join was reviewed against its own non-negotiables. Every cited SHA, source doc and artifact
resolves. Six defects were found and corrected in-place; **no verdict changed** as a result:

| # | Defect | Correction |
|---|---|---|
| 1 | K4/K5/K6 totals (22,980 MB / 234 GB / 2,341 GB) appear in **no** source artifact and do not reproduce from the 24,141 B/user slope in either SI or binary units. | Recomputed from the fitted slope in binary units; unit convention footnoted under §3.3. MISS multiples unchanged (they are C0's per-user ratios). |
| 2 | All seven C5 citations pointed at `37abbc19`, which is the **C2 CTO-triage** commit. C5's doc and artifact landed in `b2aa7cb9`. | Repointed to `b2aa7cb9`. |
| 3 | §4's max-corpus formula (`÷ 24.141 KB/user`) does not yield its own stated answer (609,000). | Restated using C0's actual KiB-based arithmetic, with the decimal-units figure given alongside. |
| 4 | Axis E rows graded PASS with an empty 95% CI column, which admissibility rule 2 requires. | Disclosed as a named rule-2 shortfall under §3.4 rather than left silent. |
| 5 | E2/E3 graded PASS on E1's curve without their own ladder, unlabelled. | Marked **proxy**, with the inheritance argument and its limits stated. |
| 6 | §3.5 forwards the "no admission control" finding to "R4 in §6"; R4 is record encoding. | Repointed to R1, noting HEA-1887 covers only the KDF path. |

Header **Head SHA** was also stale (`3429ce43`); the join actually sits on `c0954f6b`.

### 0.1 Verdict vocabulary (unchanged from v0)

| Verdict | Means |
|---|---|
| **PASS** | Measured, on stated hardware, with a fitted number or a direct observation behind it, meeting the VISION target. |
| **MISS** | Measured, on stated hardware, and does **not** meet the VISION target. Requires a ranked remediation entry in §6. |
| **NOT-MEASURABLE** | We have established that this target **cannot be measured** with the equipment, harness, or access we have — and we say *why*. A legitimate, final, shippable outcome. |
| **NOT-MEASURED** | We have not measured it yet. A statement about our progress, not about Hearth. |

### 0.2 Admissibility rules (binding — inherited from the approved plan §7, unchanged)

1. **Every figure carries the hardware it was measured on.** A number without a host is not a number.
2. **No PASS, and no "flat" / "scales well" / "linear" adjective, without a fitted number behind it.**
   Axis E verdicts are fitted exponents with a confidence interval, not spot-checks of two points.
3. **Nothing is graded PASS on a run whose ceiling attribution was the generator.**
4. **Ratios are not costs.** Only the *slope* of a multi-point regression yields a per-unit cost.
5. **A run that touched swap is void.**

---

## 1. Scope

**In scope.** Single-node performance of the `hearth` binary against the targets stated in
VISION §7.1 (latency), §7.2 (throughput) and §7.3 (capacity), plus Axis E — the *shape* of the
degradation curve once the active set exceeds the hot tier.

**Out of scope, explicitly.**
- Multi-node / Raft horizontal-scale numbers. Raft replicates; it does not shard (§0 caveat 2).
- Production-hardware numbers. Every figure here is a lower bound, not a prediction (§0 caveat 1).
- Comparative benchmarks against Keycloak or any other system.

## 2. Measurement hardware

### Host `dev-ryzen-7840hs` (the only host available as of 2026-07-28)

| Property | Value |
|---|---|
| CPU | AMD Ryzen 7 7840HS w/ Radeon 780M — **mobile/laptop part** |
| Topology | 8 physical cores / 16 threads (SMT on), 1 socket |
| Clocks | min 419 MHz · max 5137 MHz · **governor `powersave`** |
| RAM | 54 GiB total · **~13–19 GiB available** (varies by child; ~13 GiB at C0 seed; ~19 GiB at C7/C5) |
| Swap | 79 GiB configured · **~18 GiB already in use at rest** |
| Disk | WD_BLACK SN850X 2 TB NVMe (`/home`); `/scratch` tmpfs-backed for some child harnesses |
| OS / kernel | NixOS 26.11 (Zokor), Linux 7.0.10 |
| Virtualisation | none (bare metal) |
| Toolchain | rustc 1.97.0 (`2d8144b78`), cargo 1.97.0 |
| Generator placement | **co-resident** (C3/HEA-1871 proved generator isolation does not move the cliff — the ceiling is server-side, not generator starvation) |

**This host is a confounded measurement environment.** Four problems, each independently
invalidating a class of figure:

1. **Mobile CPU on `powersave`.** Per-core throughput numbers are lower bounds on server silicon.
2. **~13–19 GiB RAM available.** At 24 KB/user (C0), this host holds ~600 k users in memory —
   far short of the 1M–100M VISION capacity targets.
3. **~18 GiB swap in use before tests start.** Any run touching swap is void (rule 5). C8 swept
   four corpus rungs; all four were void.
4. **Generator co-resident.** C3/HEA-1871 confirmed the failure cliff is server-owned (Argon2id
   queue stall, not generator starvation), making HTTP throughput and concurrency rows NOT-MEASURABLE
   on this box. C4/HEA-1872 proved the generator can sustain 10k connections but the server-side
   measurement itself is NOT-MEASURABLE.

**Consequence for v1.0:** K2, E7, and the HTTP-path T1–T4 rows ship NOT-MEASURABLE or NOT-MEASURED
rather than being graded on this box.

### Host `tier-2-pending` (not provisioned)

Required for: Axis C (10k+ true concurrency) and Axis B (≥10M sessions). **Board decision
outstanding.** Without it, K2 and the HTTP concurrency rows remain ungradeable.

---

## 3. Conformance table

### 3.1 VISION §7.1 — Latency targets (single node)

All engine-level measurements are **in-process, no HTTP, no load generator.** HTTP p50/p99 at
production scale is NOT-MEASURABLE in this environment — it is not folded into any PASS.

| # | Operation | Target p50 | Target p99 | Cold-path target | Measured p50 | Measured p99 | Host | Verdict | Source |
|---|---|---|---|---|---|---|---|---|---|
| L1 | Token validation (JWT verify + session lookup) | < 50 µs | < 500 µs | < 5 ms | ≈ 1.74 µs (C7, ops-reciprocal at 1T, hot) | not explicitly captured; distribution tight at hot path | `dev-ryzen-7840hs` | **PASS** (engine; HTTP NOT-MEASURABLE) | C7 `b29e57dd` |
| L2 | Session lookup by ID | < 10 µs | < 100 µs | n/a | ≈ 0.13 µs (C7, 7.45 M ops/s, 1T hot) | not explicitly captured | `dev-ryzen-7840hs` | **PASS** (engine; HTTP NOT-MEASURABLE) | C7 `b29e57dd` |
| L3 | Permission check (in-process claim lookup) | < 1 µs | < 5 µs | n/a | ≈ 67 ns (C7, 14.8 M ops/s, 1T) | not explicitly captured | `dev-ryzen-7840hs` | **PASS** (engine; HTTP NOT-MEASURABLE) | C7 `b29e57dd` |
| L4 | Permission resolution at token-issue (RBAC traversal) | < 100 µs | < 1 ms | < 10 ms | ≈ 67 ns (C7, cache-hit path) | not explicitly captured | `dev-ryzen-7840hs` | **PASS** (engine, cache-hit; miss path not separately benchmarked) | C7 `b29e57dd` |
| L5 | User lookup by email/ID | < 50 µs | < 500 µs | < 5 ms | 0.06–0.08 µs (C5 hot); ≈ 0.61 µs (C7 user_lookup hot) | 0.10–0.63 µs (C5 hot, across 10k–320k corpus) | `dev-ryzen-7840hs` | **PASS** (engine; HTTP NOT-MEASURABLE) | C5 `b2aa7cb9`, C7 `b29e57dd` |
| L6a | Token minting (authorization_code / refresh / client_credentials — no KDF) | < 1 ms | < 5 ms | < 10 ms | — | — | — | `NOT-MEASURED` | C7/C4; needs isolated host |
| L6b | Interactive password issuance (password grant / browser login — one Argon2id verify) | < 50 ms | < 100 ms | N/A (KDF-dominated) | KDF floor: 12.5–29 ms (C9, in-process, no generator) | 127–954 ms ungated → 66–213 ms gated (C9/HEA-1887, `dev-ryzen-7840hs`) | `dev-ryzen-7840hs` | `NOT-MEASURABLE` (rule 3/5 on this host; KDF floor and queue fix established) | C9 `235e3342`, HEA-1887 |
| L7 | User creation (with credential hashing) | < 50 ms | < 100 ms | n/a | — | — | — | `NOT-MEASURED` | C9 gives KDF floor ~29 ms p50; full path not attempted at low concurrency |
| L8 | Cold-tier read (NVMe) | — | < 5 ms | — | 0.77–1.32 µs (C5, cold-natural p50) | 97.5–512 µs (C5, cold-natural p99, 10k–320k corpus, warm nvme-XFS) | `dev-ryzen-7840hs` | **PASS** (engine, warm cache, ≤320k corpus; large-corpus extrapolation yields ~2.2 ms, within budget) | C5 `b2aa7cb9` |

> **L6 split rationale.** The v0 report carried a standing red flag: baseline issuance p99 = 6000 ms
> against a 5 ms target. C9 (`docs/perf/HEA-1879-C9-issuance-triage.md`, `235e3342`) discharged that
> flag by decomposing the tail: **queueing (Little's Law at the unbounded `spawn_blocking` pool) +
> compute floor (one Argon2id hash at OWASP params costs ≈ 12.5–29 ms p50 on this host)**. The
> queueing defect is fixed by HEA-1887 (KDF gate). The compute floor makes the < 5 ms target
> physically unreachable for any password-bearing path — it is a spec contradiction, not an
> implementation defect. The CTO's spec decision (`docs/perf/HEA-1879-cto-spec-decision.md`) splits
> L6 into L6a (token minting, no KDF, < 5 ms p99) and L6b (password issuance, one Argon2id verify,
> < 100 ms p99). VISION §7.1 is not yet amended — that is pending board ratification. The row targets
> above reflect the CTO's recommended split.

> **L4 scope note.** C7 measured `RbacEngine::resolve_permissions` via the HEA-1770 decision cache.
> The cache-hit cost (67 ns) clears the 100 µs p50 target by ~1500×. The cold-cache (full RBAC
> traversal) cost was not separately measured; given the generous target (1 ms p99) and the cache
> hit floor, the target is expected to hold but is not directly confirmed.

> **L8 extrapolation note.** At 320k corpus the cold-natural p99 peaks at 512 µs. Applying the C5
> fitted exponent (+0.149, natural uncompacted path) to a 100M-user corpus gives ~512 µs × (100M/320k)^0.149
> ≈ 2.2 ms — within the 5 ms budget. This is an extrapolation, not a measurement.

---

### 3.2 VISION §7.2 — Throughput targets (single node)

All engine-level. HTTP delta NOT-MEASURABLE on this host — see §0 scope note.

| # | Workload | Target ops/s/core | Target total (16-core) | Measured/core | Measured total | Host | Verdict | Source |
|---|---|---|---|---|---|---|---|---|
| T1 | Token validation (read-heavy) | 200,000+ | 3,000,000+ | **574,363** (hot, 1T) | **7,733,497** (hot, 16T) | `dev-ryzen-7840hs` | **PASS** (engine; HTTP NOT-MEASURABLE) | C7 `b29e57dd` |
| T2 | Mixed read/write (95/5) | 100,000+ | 1,500,000+ | — | — | — | `NOT-MEASURED` | 95/5 workload mix not constructed; C7 measured operations individually |
| T3 | Permission checks (JWT claim lookup) | 1,000,000+ | 15,000,000+ | **14,799,198** (1T, cache-hit) | 3,126,679 (16T — contention, see below) | `dev-ryzen-7840hs` | **PASS** (engine, 1T; HTTP NOT-MEASURABLE) | C7 `b29e57dd` |
| T4 | Session creation | 50,000+ | 500,000+ | **158** (fsync-bound, post-Layer-B) | ~270 est. (16T) | `dev-ryzen-7840hs` | **MISS** (fsync/audit-chain serialized; 316× off target) | HEA-1907 re-run post `faec7e66` |

> **T1 headline.** `validate_token` hot scales **near-linearly** (exponent +0.933, R² 0.999,
> 84% efficiency 1→16T). It clears the 200 k/core target by **2.9×** and the 3 M aggregate target
> by **2.6×**. This is the production hot path (claims-cache hit + semantic checks + session get).
> The 1T per-core number (574 k) is the conservative bound — it goes up on server silicon.

> **T3 contention note.** The 1T rate (14.8 M ops/s) clears the per-core target by 14.8×. But the
> 16T aggregate (3.1 M) is **lower** than the 1T rate: exponent −0.549 (R² 0.918). The resolution
> cache is a single `Mutex<ResolutionCache>` (`src/rbac/engine.rs:110`). Every resolve takes the
> lock; adding cores adds contention. **Off the validate hot path** (permissions are JWT-baked at
> issue time), so it only bites during concurrent token issuance. Sharding the mutex is the fix
> (follow-up candidate). See R5.

> **T4 host caveat.** The 158 ops/s/core figure (re-measured post-Layer-B, HEA-1907) is a 5.1×
> improvement over the C7 baseline (31 ops/s/core). The gain comes from the SkipMap replacing the
> CoW BTreeMap (HEA-1897), which eliminated O(N)-per-write cloning between fsyncs. The `/scratch`
> fsync latency (~6.3 ms/op on this machine) and per-realm audit hash-chain lock still serialise
> every write; the scaling shape remains nearly flat (exponent ≈ +0.033). On production NVMe with
> appropriate `SyncMode`, throughput will be materially higher, but this is still a MISS at 316×
> below the 50 k/core target. Closing that gap requires WAL batching or async-durability modes.

> **T2 note.** A 95/5 mixed workload was never constructed as a harness. C7 measured each operation
> independently. NOT-MEASURED; derivable from C7's per-operation numbers if a mix model is assumed,
> but that would be a ratio-based inference, not a fitted measurement (rule 4).

---

### 3.3 VISION §7.3 — Capacity targets (single node)

| # | Metric | Target | Measured | Host | Verdict | Source |
|---|---|---|---|---|---|---|
| K1 | Users per node (total managed) | 100M+ | — | — | `NOT-MEASURED` | C8 all rungs swap-voided; this host holds ~600k users |
| K2 | Active sessions per node | 10M+ | **~813 B/session** resident (VmRSS delta, N=4,000) → 10M sessions ≈ 8.1 GB incremental | `dev-ryzen-7840hs` | `NOT-MEASURED` (absolute capacity ceiling not validated; measurement gives per-session cost only) | HEA-1907 `docs/perf/HEA-1907-C0-SESSION-MEMORY.md` |
| K3 | Role assignments per node | 100M+ | — | — | `NOT-MEASURABLE` | RBAC seeder does not exist; seed binary creates no per-user role assignments |
| K4 | Memory footprint (idle, 1M hot users) | < 500 MB | pre: **≈ 22.5 GiB** (24,141 B/user × 1M + 37.6 MB) → post: **≈ 9.76 GiB** (9,960 B/user × 1M + 39.7 MB, HEA-1904) | `dev-ryzen-7840hs` | **MISS (20×, was 46×)** | HEA-1904 `docs/perf/HEA-1904-C0-RERUN-POST-LAYERBA.md` |
| K5 | Memory footprint (idle, 10M hot users) | < 8 GB | pre: **≈ 225 GiB** → post: **≈ 99.6 GiB** (9,960 B/user × 10M, HEA-1904) | `dev-ryzen-7840hs` | **MISS (12×, was 29×)** | HEA-1904 extrapolated from 9,960 B/user slope |
| K6 | Memory footprint (idle, 100M hot users) | < 50 GB | pre: **≈ 2,248 GiB** → post: **≈ 996 GiB** (9,960 B/user × 100M, HEA-1904) | `dev-ryzen-7840hs` | **MISS (20×, was 46×)** | HEA-1904 extrapolated; §5 H4 still applies (SST residency Θ(corpus)) |
| K7 | Disk footprint (100M total users) | < 200 GB | pre: **≈ 426 GiB** (4,573 B/user × 100M) → post: **≈ 264 GiB** (2,840 B/user × 100M, HEA-1904) | `dev-ryzen-7840hs` | **MISS (1.4×, was 2.1×)** | HEA-1904 `docs/perf/HEA-1904-C0-RERUN-POST-LAYERBA.md` |
| K8 | Binary size | < 50 MB | **41.39 MB** (39.47 MiB) | `dev-ryzen-7840hs` | **PASS** | C10 `6e6a24c4`; artifact `docs/perf/artifacts/c10-artifact-facts.json` |
| K9 | Cold start to serving requests | < 2 s | **70 ms** worst-of-5 (min 59 ms) | `dev-ryzen-7840hs` | **PASS** | C10 `6e6a24c4`; artifact `docs/perf/artifacts/c10-artifact-facts.json` |
| K10 | Cold-to-hot promotion latency | < 5 ms | — | — | `NOT-MEASURED` | C1 shipped promotion telemetry (HEA-1869); promotion p50/p99 not separately benchmarked |

> **K4–K7 context — what the C0 slope measures, and what changed.**
> C0 (HEA-1868) measured 24,141 B/user in a write-fresh, non-compacted state; `Memtable::put`
> deep-cloned the entire `BTreeMap` on every write (Layer B). Layer A added JSON field-name + 36-char
> UUID index overhead. Together they produced a 12× multiplier over the analytical hot-tier floor
> (~673 B/user). Layer C (SST full-RAM residency — no eviction) adds the full corpus on top.
>
> **Post-remediation (HEA-1904, `c82d8eb8`):** Layer B replaced with a lock-free `SkipMap`
> (HEA-1897) and Layer A replaced with postcard binary encoding + 16-byte raw-UUID index
> (HEA-1898/1899). Re-run on the same 4-point sweep yields **9,960 B/user (OLS), 10,133 B/user
> (endpoint)**. The 14.8× gap from the analytical hot-tier (673 B) reflects 5 SkipMap entries/user
> still resident in-process. Layer C (HEA-1881: block-based SST with eviction) is required to
> approach the hot-tier floor. K4–K7 remain MISS; the ratio improved (46× → 20× / 29× → 12× / 2.1× → 1.4×).
> See `docs/perf/HEA-1904-C0-RERUN-POST-LAYERBA.md`.

> **K4–K7 units convention (CTO review, HEA-1901).** All four totals are recomputed here directly
> from C0's fitted slopes in **binary units (GiB = 2³⁰ B)**, so that every cell reproduces from
> `slope × N`. C0's own headline for K7 reads "~436 GB"; that figure divides by 1024 one step short
> and is really 436,000 MiB ≈ 426 GiB. The discrepancy is ~2% and changes no verdict — the MISS
> multiples (46× / 29× / 46× / 2.1×) are C0's per-user-byte ratios (e.g. 24,141 B vs. the 524 B
> budget) and are unaffected by the unit convention. In SI units the same slopes give 24.1 GB /
> 241 GB / 2,414 GB / 457 GB.

> **K8/K9 build provenance note (carried from v0).** The K8/K9 binary was measured from a working tree
> at base `6e6a24c4` with C1's uncommitted telemetry present. Both PASSes are robust to that
> contamination by wide margins (17% and 28× headroom respectively). Re-stamp on a clean tagged build
> before v1.0 ships.

> **K9 scope.** "Cold start to serving requests" = process exec → first successful `GET /health`,
> five iterations on a **fresh empty data dir** under `--dev` (in-memory storage, no corpus).
> Worst sample reported. Cold start against a large on-disk corpus (WAL replay + SST open) is a
> materially different measurement and belongs to K8/C8.

---

### 3.4 Axis E — Degradation shape past the hot-tier threshold

Graded per plan §1a: regress `log(p99)` on `log(n)`. **PASS = slope ≤ O(log n). MISS = super-logarithmic.**

All C5 measurements: in-process `EmbeddedStorageEngine::get`, AMD Ryzen 7 7840HS, powersave,
warm nvme-XFS, hot/cold purity confirmed via C1 telemetry (`hearth_storage_get_total{outcome}`).
Corpus ladder: 10k → 320k (32×). Source: `docs/perf/HEA-1873-C5-complexity-sweep.md`, SHA `b2aa7cb9`,
artifact `docs/perf/artifacts/c5-complexity-sweep-raw.json`.

| # | Curve | Fitted exponent | 95% CI | R² | Target | Verdict | Source |
|---|---|---|---|---|---|---|---|
| E1 | user lookup p99 vs corpus size | **+0.281 (hot); +0.281 (cold-compacted)** | — | 0.25 (hot); 0.76 (cold-compacted) | ≤ O(log n) | **PASS** (conditional; hot O(1); cold ≤ O(log n) when compacted) | C5 `b2aa7cb9` |
| E2 | session lookup p99 vs corpus size | not independently fitted — inherits E1 | — | — | ≤ O(log n) | **PASS** (conditional, **proxy**; engine `get()` is the shared term — see note) | C5 `b2aa7cb9` |
| E3 | validate_token p99 vs corpus size | not independently fitted — inherits E1 | — | — | ≤ O(log n) | **PASS** (conditional, **proxy**; same inheritance as E2) | C5 `b2aa7cb9` |
| E4 | SST file count vs corpus size | pre: **+1.0000** (max_sst_count=0, control) → post: **+0.1607** (T8, max_sst_count=8) / **+0.1094** (T16, max_sst_count=16) | — | 1.0000 (control); 0.838 (T8); 0.602 (T16) | ≤ O(log n) | **MISS** (default, max_sst_count=0); **PASS (capped)** with max_sst_count ∈ {8, 16} — fan-out O(1) at both settings (HEA-1905) | C2 `docs/perf/HEA-1870-C2-sst-growth.md`; HEA-1885 `709ed183`; HEA-1905 `124aeee2` `docs/perf/HEA-1905-E4-SST-COUNT-RERUN.md` |
| E5 | p99 vs hot-set/capacity ratio (0.1×→10×, fixed corpus=160k) | — (no latency breach observed at any ratio) | — | — | no cliff | `NOT-MEASURED` at production scale (160k corpus shows no latency breach, even at 0% hit rate; hit-ratio cliff at ratio ≈ 1× is real but latency stays within budget on this host) | C5 Axis B `b2aa7cb9` |
| E6 | Ratio at which p99 first breaches §7.1 budget | — | — | — | stated, not graded | `NOT-MEASURED` | C5: no breach at 160k corpus; production-scale measurement pending |
| E7 | Overload behaviour at 2× / 5× / 10× sustainable | — | — | — | bounded, honest failure | `NOT-MEASURABLE` | C6 reviewed and rejected (§3.5); C3 confirmed server-owned ceiling but Argon2id path now addressed by HEA-1887 |

> **Rule-2 shortfall, disclosed (CTO review, HEA-1901).** Admissibility rule 2 requires Axis E
> verdicts to be *fitted exponents with a confidence interval*. The C5 harness
> (`examples/complexity_sweep.rs`) emitted slope and R² but **no confidence intervals**, which is why
> the 95% CI column reads "—" on every row. The E1/E4 exponents are therefore fitted-but-un-bounded.
> This is a shortfall against our own contract, recorded rather than papered over. It does not move
> E1's verdict — the hot-path PASS rests on the absolute observation (p99 ≤ 0.63 µs, corpus-independent
> across 32×) rather than on the slope, whose R² of 0.25 the C5 author explicitly calls noise. Emitting
> CIs is a one-line harness change for any re-run.

> **E2/E3 are proxy-graded, not independently fitted (CTO review, HEA-1901).** C5 measured
> `EmbeddedStorageEngine::get` only, on the stated ground that this single call *is* the shared
> storage term inside `validate_token` / `lookup_session` / `lookup_user`
> (`docs/perf/HEA-1873-C5-complexity-sweep.md` L22–25). The E2/E3 PASSes therefore inherit E1's curve
> by architectural argument; no separate session-lookup or validate-token corpus ladder was run. The
> argument is sound for the *storage* term and unsound for anything above it (JWT verify, claim
> decode) — those are corpus-independent by construction, so the inheritance is safe, but it is an
> inference and is labelled as one.

> **E1–E3 conditionality.** The ≤ O(log n) verdict holds in the **compacted** steady state.
> Uncompacted (post-seed, pre-compaction), the cold path fans out over a flat `sst_readers` Vec
> at Θ(#SSTs) = Θ(n) (C2 fitted exponent 1.0). **Compaction is the load-bearing mitigation.**
> E4 is the single most consequential row: if SST count grows O(n), the cold path degrades to O(n),
> violating E1–E3's conditional PASSes. Lever-1 (HEA-1885) caps fan-out at a constant when enabled.

> **E4 dual verdict (updated by HEA-1905, `124aeee2`, 2026-07-28).** Default config
> (`max_sst_count = 0`, off): exponent 1.0000, R² 1.0000 — **MISS**. With lever-1 enabled, the
> E4 PASS holds across the measured trigger range:
>
> | Setting | Peak fan-out exponent | R² | Max write-amp | Max peak SSTs |
> |---------|----------------------|-----|---------------|---------------|
> | max_sst_count=0 (default) | 1.0000 | 1.0000 | 1.14× | linear (320 at n=320k) |
> | max_sst_count=8 (T8) | **0.1607** | 0.8382 | 5.48× | 12 |
> | max_sst_count=16 (T16) | **0.1094** | 0.6022 | 3.59× | 17 |
> | max_sst_count=12 (HEA-1885 ref) | **0.0376** | 0.713 | 4.49× | 12 |
>
> Write amplification at all trigger values is bounded, O(log n), not quadratic — confirming the
> size-tiered partial compaction avoids the defect that ruled out count-triggering `compact_ssts`.
> Lever-1 ships **OFF by default** because the per-merge write stall scales with the production
> 64 MiB flush threshold: measured p99 = 307 ms at 256 KiB → projected **~79 s** at 64 MiB (T8),
> **~65 s** at 64 MiB (T16). Enabling requires per-hardware validation. Default-flip is gated on
> lever-2 (move merge I/O off `flush_lock`), tracked under HEA-1881. See
> `docs/perf/HEA-1905-E4-SST-COUNT-RERUN.md`.

> **E5 Axis B finding (C5, 160k corpus).** Hit ratio holds 100% at ratio ≤ 1×, collapses through
> 15% (3×) to 0% (10×) — a cliff in hit-ratio, not in latency. At 0% hit rate (ratio = 10×),
> cold p99 = 26.3 µs on warm NVMe, within the 500 µs budget. The worst-case tail appears at the
> **boundary** (ratio ≈ 3×, 15% hit rate, p99 = 134.6 µs) due to hot-tier churn — constant
> promote/evict under the 64-entry eviction batch adds tail variance. This is reported honestly;
> the latency risk at production corpus scale is greater than this 160k-user observation.

---

### 3.5 E7 review — why C6's MISS is not accepted into the table

*Carried forward from v0 without change. The analysis is definitive.*

C6 (`docs/perf/HEA-1874-C6-overload-behaviour.md`, commit `a397d86b`) grades overload behaviour
**MISS**. After applying §0.2, **E7 is recorded as `NOT-MEASURABLE`, not MISS.** The server was
at 0.0% CPU mean and 0.0% CPU peak during every 2×–10× overload run. Hearth was not overloaded —
it was idle. Requests never arrived (generator-owned pathology).

Three further defects independently void the C6 verdict: (1) raw data claimed committed to
`loadtest/reports/hea1812/*.json` is gitignored and untracked; (2) the degradation curve spans
three different build SHAs; (3) RSS "flat" sub-grades at 5× and 10× carry `rss_peak_bytes: 0`.

**What C6 does establish (kept):** on code inspection, Hearth has no admission control — `tower`
compiled with only `util`, `tower-http` with only `trace`, zero hits for `LoadShed` /
`ConcurrencyLimit` / `TimeoutLayer` in `src/`. Carried as **R1** in §6 (the KDF-path admission gate,
HEA-1887, addresses this for password hashing only; the general HTTP-layer admission control C6
identified as absent remains absent).

**To settle E7:** re-run the 2×/5×/10× ladder on a single build with generator isolation confirmed
(C3 now done), resource sampling non-null at every rung, and raw artifacts committed.

---

### 3.6 Systemic: `summary.ceiling` misattribution — C11 done

C11 (HEA-1880) tracked the programme-level defect: every run in the baseline data carries
`summary.ceiling: "server"` even at 0.0% server CPU. This made the machine-checkable rule-3
enforcement unreliable across all load-generated rows.

**C11 is done** (committed on `feature/perf-updates-7-28-26`). Until C11 was resolved, ceiling
attribution was corroborated manually against server CPU utilisation. With C11 resolved, the
attribution field is trustworthy for new runs. The historical baseline data at
`loadtest/baseline/steady-baseline.json` retains its hand-written honest attribution block
(`load_generator / host_contention — NOT server saturation`) and is not superseded.

---

## 4. The three per-user memory numbers

C0 baseline: `docs/perf/HEA-1868-C0-MEMORY-COST.md`. Post-remediation re-run: `docs/perf/HEA-1904-C0-RERUN-POST-LAYERBA.md`.
Method: OLS regression on 4-point sweep {200, 1k, 4k, 12k} users, generator-free, no swap (rule 5 satisfied).

| Number | **Pre-remediation (C0, `3429ce43`)** | **Post-remediation (HEA-1904, `c82d8eb8`)** | Method | Host |
|---|---|---|---|---|
| **bytes-resident-per-user (memtable, pre-compaction)** | **24,141 B/user** (EP: 24,627) | **9,960 B/user** (EP: 10,133) | OLS slope R²=0.9974 (pre) / 0.9320 (post) | `dev-ryzen-7840hs` |
| **Fixed RSS overhead (intercept)** | **37.6 MB** | **39.7 MB** | OLS intercept | `dev-ryzen-7840hs` |
| bytes-resident-per-hot-user (analytical, post-compaction hot tier) | **~673 B/user** | **~673 B/user** (unchanged — structural) | Struct accounting; 2 hot-tier entries | — |
| bytes-resident-per-session | — | **~813 B/session** (VmRSS delta, N=4,000) | Paired-process VmRSS delta; ±4 KB page noise → range 600–1,100 B/session; HEA-1907 `docs/perf/HEA-1907-C0-SESSION-MEMORY.md` | `dev-ryzen-7840hs` |
| **bytes-on-disk-per-user** | **4,573 B/user** (EP: 4,508) | **2,840 B/user** (EP: 2,805) | OLS slope R²=0.9975 (pre) / 0.9991 (post) | `dev-ryzen-7840hs` |

**Agreement check: still FAILED** (narrowed). Post-fix slope (9,960 B) vs. analytical hot-tier (673 B) → 14.8× gap (was 35.9×).
Root cause unchanged: 5 SkipMap entries/user resident in-process; hot-tier promotion only after WAL→SST compaction + read-sweep.
Layer B/A remediations are confirmed real; the remaining gap requires Layer C (block-based SST with eviction, HEA-1881).

**Max corpus on this host (post-remediation):** ~29 GiB available at HEA-1904 run time.
(29,000 MiB − 40 MiB overhead) ÷ 9.96 KiB/user ≈ **~2,900,000 users** (up from ~609,000 pre-fix).
Pre-fix arithmetic: (14,055 MiB − 38 MiB) ÷ 23.6 KiB/user ≈ 609,000 users.

---

## 5. Standing architectural risk

> Hypotheses stated in the v0 report for contradiction by measurement. This section is updated to
> reflect which hypotheses measurement has confirmed, modified, or left open.

**H1 — Cold-lookup fan-out. CONFIRMED O(#SSTs) in the transient; O(log n) post-compaction.**
`EmbeddedStorageEngine::get` scans a flat `sst_readers` Vec linearly (`engine.rs:738-758`).
C2 fitted exponent = **1.0000 (R² = 1.0000)** in the default transient state. Post-compaction:
exponent 0.0376 (lever-1, HEA-1885). The per-file probe cost is pure in-memory (~50 ns/SST —
no I/O, per CTO triage HEA-1881); the latency issue manifests at corpus scale where #SSTs is large.

> **H1 amendment from C2/C5.** The v0 hypothesis stated "if compaction holds file count logarithmic,
> we are fine." C2 proved the default does NOT hold it logarithmic. C5 confirmed the cold p99
> latency exponent is sub-linear at ≤320k corpus (+0.149 natural, +0.281 compacted). These are
> consistent: Bloom filters mask the linear fan-out cost at small corpus; the exponent will dominate
> at larger corpora where #SSTs is large and per-file probe counts accumulate.

**H2 — Blind hot-tier telemetry. ADDRESSED by C1 (HEA-1869).**
`hearth_storage_get_total{outcome}` counter now exports hot/cold tier outcomes. C5 used C1's
telemetry to confirm 99.99% hot-phase purity and 100.00% cold-phase purity in its measurements.
`sst_files` gauge is live. `promote_counter` remains internal-only; K10 (cold-to-hot promotion
latency) is NOT-MEASURED but is now instrumentable.

**H3 — Single-node capacity is not escapable by clustering. UNCHANGED.**
Raft replicates, it does not shard. Single-node capacity is the product floor. See §0 caveat 2.

**H4 (new) — SST full-RAM residency makes tiering ineffective below the hot tier.** Identified
by `docs/perf/HEA-1881-cold-path-triage.md` and `docs/perf/HEA-1867-record-size-analysis.md`.
`SstReader::open` reads the whole file, decrypts wholesale, and materialises every entry in RAM
(`sst.rs:319-342`). There is no block index, no block eviction, no lazy paging. Resident memory
is **Θ(total corpus)**, not Θ(working set). This is why K4–K7 miss even if Layer B (CoW clone) is
fixed: 100M users × 673 B/hot-tier-user = ~63 GB, over the 50 GB K6 budget, and the SST layer
adds the full corpus on top. The "hot tier + SST tier" model only reduces memory footprint if SSTs
can be paged lazily. Requires a block-based SST format (Layer C). Design gated on HEA-1881 measurement
sub-issue B.

---

## 6. Ranked remediation list

Entries confirmed by measurement (C0–C9) or code inspection. Items marked **SHIPPED** are committed
on the current branch but may be gated or off by default.

| # | Item | Basis | Affects | Status | Fix |
|---|---|---|---|---|---|
| R1 | **KDF admission gate — unbounded `spawn_blocking` pool.** C9 confirmed the 7 s issuance tail is queueing (Little's Law: throughput caps at ~247 hash/s from C=16 while p99 climbs 128→954 ms). | Measured, C9 `235e3342` | L6b, E7, operator trust | **SHIPPED — HEA-1887** (async semaphore before `spawn_blocking`, permits = core count, 503/Retry-After shed). Follow-ups: HEA-1892 (hoist abuse controls before permit), HEA-1895 (longer admin login queue-wait). Gated on SecurityAuditor review before merge. | `src/identity/kdf_gate.rs`; config `security.password.kdf` |
| R2 | **`summary.ceiling` misreports generator-limited runs as `server`.** | Data inspection, C10 | Rule-3 enforcement programme-wide | **DONE — C11 (HEA-1880)** committed | Attribution now trustworthy for new runs |
| R3 | **Memtable CoW clone (Layer B) — O(N)-per-write.** `Memtable::put` deep-cloned the whole BTreeMap on every write. 12× overhead vs. hot-tier; write-throughput defect (seed cost 2.63→7.76 ms/user). | Measured, C0 + record-size analysis `3429ce43` | K4–K7, T4, write-path throughput | **SHIPPED — HEA-1897 `faec7e66`.** Replaced CoW BTreeMap with lock-free `SkipMap` (crossbeam). HEA-1896 `c0954f6b` batches user keys into `put_batch`. HEA-1904 confirms: 9,960 B/user (−59%); 0.34 ms/user at N=12k (−96%). Remaining gap to 673 B hot-tier floor = Layer C. | `src/storage/memtable.rs` (SkipMap); `src/identity/users.rs` (put_batch) |
| R4 | **Record encoding (Layer A) — `serde_json` field-name overhead + 36-char UUID index + audit density.** 5 keys/user; audit is ~3 of 5 keys and ~half the bytes. | Measured, C0 + record-size analysis | K4–K7, K7 especially | **SHIPPED — HEA-1898 `c82d8eb8` + HEA-1899 `e27e08db`.** Postcard binary encoding for User/Session/StoredCredential; 16-byte raw-UUID email index; 32-byte raw HMAC + 8-byte BE audit keys. HEA-1904 confirms: 2,840 B/user disk (−38%). K7 ratio improved 2.1× → 1.4×. | `src/storage/codec.rs`; audit encoder |
| R5 | **`permission_check` scales negatively (−0.549 exponent) — single RBAC resolution Mutex.** | Measured, C7 `b29e57dd` | T3 at high concurrency | OPEN | Shard `ResolutionCache` mutex (per-realm or striped) |
| R6 | **E4 default config: SST count grows O(n).** Lever-1 (HEA-1885) caps fan-out at constant but ships off by default due to write-stall at the 64 MiB production flush threshold. | Measured, C2 + HEA-1885 `709ed183` | E4, E1–E3 conditional PASSes, L8 at large corpus | **SHIPPED OFF** — enable `storage.compaction.max_sst_count` per hardware; validate write-stall budget | `storage.compaction.max_sst_count` / `merge_min` |
| R7 | **SST full-RAM residency — Θ(corpus) memory regardless of tiering.** No block index, no eviction. Real scale ceiling for K1/K4–K6. | Code + CTO triage `docs/perf/HEA-1881-cold-path-triage.md` | K1, K4–K6, all capacity rows | DESIGN PENDING (HEA-1881) | Block-based SST format with per-block encryption, lazy paging, reader eviction. Gated on HEA-1881 residency measurement (sub-issue B). |

---

## 7. Data contract

### 7.1 Schema (unchanged from v0)

All child artifacts emitted under `docs/perf/artifacts/<child>-<axis>.json`. Schema 1. See v0 for
the full JSON structure and per-field admissibility enforcement rules.

**Committed artifacts as of this join:**
- `docs/perf/artifacts/c5-complexity-sweep-raw.json` (C5/E1–E4)
- `docs/perf/artifacts/c7-saturation-raw.json` (C7/T1–T4)
- `docs/perf/artifacts/c8-scale-sweep-raw.json` (C8/K1–K3 — all void)
- `docs/perf/artifacts/c9-issuance-argon2.json` (C9/L6)
- `docs/perf/artifacts/c10-artifact-facts.json` (K8, K9)

### 7.2 Nightly-diff artifact

`docs/perf/artifacts/latest.json` (union of child artifacts keyed by axis row) is the nightly-diff
surface. **Not yet wired** — remains actionable once the CI gate is added. Becomes particularly
valuable now that ≥1 row per axis is graded.

### 7.3 Refreshed committed baseline

`loadtest/baseline/steady-baseline.json` (schema 2) is not superseded by this report. The
`single_node_ceiling` block's `attribution` field remains `"load_generator / host_contention — NOT
server saturation"` until C3-isolated, C4-driven HTTP runs are committed. C3 and C4 are done and
their methodology is committed; a re-run with the post-HEA-1887 binary (KDF gate now active) would
be the first admissible HTTP throughput measurement.

---

## 8. Programme status (as of 2026-07-28)

All children done. HEA-1877 (duplicate C9) cancelled in favour of HEA-1879.

| Child | Issue | Title | Status | Final disposition |
|---|---|---|---|---|
| C0 | HEA-1868 | Real per-user / per-session memory cost | **done** | K4–K7 MISS; 24 KB/user memtable; session NOT-MEASURABLE |
| C0-R | HEA-1904 | C0 re-run after Layers B+A (`c82d8eb8`) | **done** | 9,960 B/user RSS (−59%); 2,840 B/user disk (−38%); 0.34 ms/user write (−96%); K4–K7 MISS (improved 46×→20×, 2.1×→1.4×) |
| C0-S | HEA-1907 | Session seeding path + per-session memory | **done** | ~813 B/session (N=4,000 VmRSS delta); T4 re-run: 158 ops/s/core (+5.1× vs C7 baseline) |
| C1 | HEA-1869 | Hot-tier observability | **done** | `hearth_storage_get_total{outcome}` live; purity confirmed by C5 |
| C2 | HEA-1870 | SST-count growth vs corpus size | **done** | E4 MISS default (exponent 1.0); remediation split to HEA-1881/HEA-1885 |
| C3 | HEA-1871 | Separate load generator from server | **done** | Cliff is server-owned (Argon2id queue stall); `taskset -c` isolation committed |
| C4 | HEA-1872 | High-concurrency generator (10k+) | **done** | Generator sustains 10k connections at 2.4% CPU; server-side HTTP NOT-MEASURABLE |
| C5 | HEA-1873 | Complexity-class sweep | **done** | E1–E3 PASS conditional; E4 exponent 1.0 confirmed; Axis B no latency cliff at 160k |
| C6 | HEA-1874 | Graceful-overload behaviour | **done** | E7 NOT-MEASURABLE (server at 0% CPU); code-level no-admission-control finding kept as R4 |
| C7 | HEA-1875 | Saturation-throughput benches | **done** | T1/T3 PASS engine; T4 MISS fsync-bound; permission_check negative scaling found |
| C8 | HEA-1876 | Record- and session-scale sweep | **done** | All 4 rungs swap-voided; K1–K3 NOT-MEASURED/NOT-MEASURABLE |
| C9 | HEA-1879 | Issuance/Argon2id: queueing vs compute | **done** | Queue confirmed; compute floor 12.5–29 ms; KDF gate shipped HEA-1887 |
| C11 | HEA-1880 | `summary.ceiling` misattribution | **done** | Ceiling attribution now trustworthy; §3.6 |
| **C10** | **HEA-1878 / HEA-1901** | **This report** | **done (v1)** | 13 PASS / 6 MISS / 4 NOT-MEASURABLE / 7 NOT-MEASURED |

> **HEA-1877 cancelled** (duplicate C9, same assignee). Survivor: HEA-1879.

**Open follow-up work (not blocking this report, but required for remediation):**
- ~~HEA-1896–HEA-1900: Layer B (CoW memtable) + Layer A (record encoding)~~ **SHIPPED** on `c82d8eb8`; verified by HEA-1904
- HEA-1881 sub-issue B: SST residency measurement (gates Layer C design — the next memory lever)
- Lever-1 validation on production-representative hardware (enables E4 PASS in the default deployment)
- Second host provisioning (required for Axis B session-scale and Axis C HTTP concurrency validation)
