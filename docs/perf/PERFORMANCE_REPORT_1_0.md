# Hearth — Performance Report 1.0

**Status:** `v0 — GRADING CONTRACT + 2 of 29 rows graded (K8, K9). EVERY LATENCY, THROUGHPUT AND
SCALE ROW IS STILL UNMEASURED. This document does not yet support any claim about Hearth's
performance.`
**Owner:** CTO (HEA-1878 / C10) · **Parent:** HEA-1867 · **Plan:** `docs/perf/HEA-1867-PLAN.md` (rev 3)
**Last updated:** 2026-07-28 · **Git SHA at authoring:** `6e6a24c4`

---

## 0. Read this first

This document is published **before** the measurements it will eventually contain. That is
deliberate, and it is the single most important property of this report.

The row set, the verdict vocabulary, and the admissibility rules below were fixed **while every
cell was still empty**. A conformance report written after the numbers are known is a report
whose table shape can be — usually unconsciously — retrofitted to whatever the numbers happened
to support. Rows that would have failed get merged into rows that pass; a target that turns out
to be unreachable gets quietly restated as "directional." Fixing the contract first removes that
degree of freedom.

Current tally across the 29 rows in §3:

| Verdict | Count | Rows |
|---|---|---|
| PASS | 2 | K8, K9 |
| MISS | 0 | — |
| NOT-MEASURABLE | 1 | E7 (pending C3 — see §3.5) |
| **NOT-MEASURED** | **26** | everything else |

**26 of 29 cells read `NOT-MEASURED`.** That is not a placeholder for "probably fine." It is the
honest current state of our evidence, and §3 is the work-tracking surface for the programme as much
as it is the eventual deliverable.

The two PASSes — **K8 (binary size)** and **K9 (cold start)** — are properties of the built artifact
and of process startup rather than of load, which is why they need none of C0–C9. They are also,
deliberately, the two least interesting rows in the report: neither says anything about whether
Hearth is fast, whether it scales, or what it costs per user. **Nobody should read "2 rows PASS" as
partial validation of the performance story.** The rows that carry that story — L1–L8, T1–T4, K1–K7,
E1–E7 — are all still unmeasured.

### 0.1 Verdict vocabulary (exactly four values, no others)

| Verdict | Means |
|---|---|
| **PASS** | Measured, on stated hardware, with a fitted number or a direct observation behind it, meeting the VISION target. |
| **MISS** | Measured, on stated hardware, and does **not** meet the VISION target. Requires a ranked remediation entry in §6. |
| **NOT-MEASURABLE** | We have established that this target **cannot be measured** with the equipment, harness, or access we have — and we say *why*. A legitimate, final, shippable outcome. |
| **NOT-MEASURED** | We have not measured it yet. A statement about our progress, not about Hearth. Must name the blocking child issue. |

`NOT-MEASURABLE` and `NOT-MEASURED` are **not** synonyms and neither is a soft PASS. Any row that
ships in v1.0 as `NOT-MEASURABLE` must carry a one-line reason and, where applicable, what it would
take to make it measurable.

### 0.2 Admissibility rules (binding — inherited from the approved plan §7)

1. **Every figure carries the hardware it was measured on.** A number without a host is not a number.
2. **No PASS, and no "flat" / "scales well" / "linear" adjective, without a fitted number behind it.**
   Axis E verdicts are fitted exponents with a confidence interval, not spot-checks of two points.
3. **Nothing is graded PASS on a run whose ceiling attribution was the generator.** If
   `summary.ceiling != "server"`, the run grades the harness, not Hearth.
4. **Ratios are not costs.** Dividing peak RSS by user count does not yield a per-user cost. Only
   the *slope* of a multi-point regression does. (See §4 and plan finding 3.)
5. **A run that touched swap is void.** See §2 — on the current host this is a live risk, not a
   hypothetical.

---

## 1. Scope

**In scope.** Single-node performance of the `hearth` binary against the targets stated in
VISION §7.1 (latency), §7.2 (throughput) and §7.3 (capacity), plus Axis E — the *shape* of the
degradation curve once the active set exceeds the hot tier, which is the board's headline question.

**Out of scope, explicitly.**
- **Multi-node / Raft horizontal-scale numbers.** A different axis. Note this does not soften the
  single-node targets — see §5 H3: Hearth's cluster layer replicates, it does not shard, so
  single-node capacity is the capacity floor of the whole product.
- **Production-hardware numbers.** Every figure here is measured on the host named in §2, which is a
  developer laptop-class machine. Figures are lower bounds on server-class silicon, not predictions.
- **Comparative benchmarks** against Keycloak, Redis, or any other system. VISION cites comparables
  for context; this report grades Hearth against Hearth's own stated targets only.

## 2. Measurement hardware

Every figure in this report must cite one of the host profiles below by name. Figures with no host
profile are inadmissible.

### Host `dev-ryzen-7840hs` (the only host available as of 2026-07-28)

| Property | Value |
|---|---|
| CPU | AMD Ryzen 7 7840HS w/ Radeon 780M — **mobile/laptop part** |
| Topology | 8 physical cores / 16 threads (SMT on), 1 socket |
| Clocks | min 419 MHz · max 5137 MHz · **governor `powersave`** |
| RAM | 54 GiB total · **~13 GiB available** · ~41 GiB in use by other workloads |
| Swap | 79 GiB configured · **~18 GiB already in use at rest** |
| Disk | WD_BLACK SN850X 2 TB NVMe (`/home`, 43% used) |
| OS / kernel | NixOS 26.11 (Zokor), Linux 7.0.10 |
| Virtualisation | none (bare metal) |
| Toolchain | rustc 1.97.0 (`2d8144b78`), cargo 1.97.0 |
| Generator placement | **co-resident with the server** (not yet separated — see C3) |

**This host is a confounded measurement environment, and that is itself a finding.** Four separate
problems, each of which independently invalidates a class of figure:

1. **Mobile CPU on the `powersave` governor.** Sustained multi-core load on a 7840HS thermally and
   power-throttles well below its 5.1 GHz peak. Any per-core throughput number (VISION §7.2) taken
   here is a *lower* bound on server-class silicon, and must be labelled as such rather than
   reported as "the" number.
2. **~13 GiB of RAM actually available, not 54 GiB.** Corpus-scale planning must budget against 13
   GiB. At VISION §7.3's own 10M-hot-user target of < 8 GB this is nominally reachable; at the
   (incorrect, ratio-derived) 12 KB/user artifact it is not. C0 decides which.
3. **~18 GiB of swap already in use before we start.** Any seed that grows the working set will
   contend with an already-swapping host. **Any run showing non-zero swap-in during the measurement
   window is void** — its latency tail measures the swap subsystem, not Hearth. Every child issue is
   required to record swap deltas alongside its figures.
4. **Generator co-resident with the server.** Goose and Hearth contend for the same 16 threads. This
   is the confirmed cause of the 500→600-user cliff (see §5) and is why Axes C and D are currently
   ungradeable at any value.

**Consequence for v1.0:** unless a second host is provisioned (plan §8 decision 3, still
unanswered), the concurrency and throughput axes ship as `NOT-MEASURABLE` with reason
*"no isolated generator host"*, rather than being graded on this box. That is the correct outcome,
not a gap to paper over.

### Host `tier-2-pending` (not provisioned)

Required for: Axis C (10k+ true concurrency, remote generator) and Axis B (≥10M sessions) if C0
shows `dev-ryzen-7840hs` cannot hold the corpus. **Board decision outstanding.**

---

## 3. Conformance table

> **Every verdict below is `NOT-MEASURED`.** Each names the child issue that will settle it. This
> table is the programme's scoreboard; it is updated as children land, and no cell may move to PASS
> without satisfying §0.2.

### 3.1 VISION §7.1 — Latency targets (single node)

| # | Operation | Target p50 | Target p99 | Cold-path | Measured p50 | Measured p99 | Host | Verdict | Settled by |
|---|---|---|---|---|---|---|---|---|---|
| L1 | Token validation (JWT verify + session lookup) | < 50 µs | < 500 µs | < 5 ms | — | — | — | `NOT-MEASURED` | C5, C7 |
| L2 | Session lookup by ID | < 10 µs | < 100 µs | n/a | — | — | — | `NOT-MEASURED` | C5, C7 |
| L3 | Permission check (in-process claim lookup) | < 1 µs | < 5 µs | n/a | — | — | — | `NOT-MEASURED` | C7 |
| L4 | Permission resolution at token-issue (RBAC traversal) | < 100 µs | < 1 ms | < 10 ms | — | — | — | `NOT-MEASURED` | C7 |
| L5 | User lookup by email/ID | < 50 µs | < 500 µs | < 5 ms | — | — | — | `NOT-MEASURED` | C5, C7 |
| L6 | Token issuance (full OAuth2 flow) | < 1 ms | < 5 ms | < 10 ms | — | — | — | `NOT-MEASURED` | **C9** |
| L7 | User creation (with credential hashing) | < 50 ms | < 100 ms | n/a | — | — | — | `NOT-MEASURED` | C9 |
| L8 | Cold-tier read (NVMe) | — | < 5 ms | — | — | — | — | `NOT-MEASURED` | C1, C5 |

> **L6 carries a standing red flag.** The committed baseline records issuance p99 = 6000 ms and max
> = 8.40 s against a 5 ms target — a ~1200× breach. It is **not** graded MISS here because that run's
> generator was co-resident and its attribution is disputed (plan finding 4 argues it is a
> `spawn_blocking` queueing defect, not Argon2id compute, since the server sat at 178% of 1600% CPU).
> C9 settles cause before we grade the row. Grading it MISS today would attribute a harness artifact
> to Hearth; grading it PASS is obviously unavailable. `NOT-MEASURED` is the honest cell.

### 3.2 VISION §7.2 — Throughput targets (single node)

| # | Workload | Target ops/s/core | Target total (16-core) | Measured/core | Measured total | Host | Verdict | Settled by |
|---|---|---|---|---|---|---|---|---|
| T1 | Token validation (read-heavy) | 200,000+ | 3,000,000+ | — | — | — | `NOT-MEASURED` | **C7** (engine), C4 (HTTP) |
| T2 | Mixed read/write (95/5) | 100,000+ | 1,500,000+ | — | — | — | `NOT-MEASURED` | C7, C4 |
| T3 | Permission checks (JWT claim lookup) | 1,000,000+ | 15,000,000+ | — | — | — | `NOT-MEASURED` | C7 |
| T4 | Session creation | 50,000+ | 500,000+ | — | — | — | `NOT-MEASURED` | C7, C4 |

> **The 1,677 RPS figure in `loadtest/baseline/steady-baseline.json` must not be entered in this
> table.** It is a *harness* ceiling, not a Hearth ceiling: at that point the server was ~11%
> utilised (178% of 1600% CPU) and the run's own attribution field reads
> `load_generator / host_contention — NOT server saturation`. Quoting it as a Hearth throughput
> number — even to say "we're 1800× off target" — would be a rule-3 violation. We have never offered
> Hearth enough load to find its own limit. C7 finds it in-process; C4 finds it over HTTP.

### 3.3 VISION §7.3 — Capacity targets (single node)

| # | Metric | Target | Measured | Host | Verdict | Settled by |
|---|---|---|---|---|---|---|
| K1 | Users per node (total managed) | 100M+ | — | — | `NOT-MEASURED` | C0, C8 |
| K2 | Active sessions per node | 10M+ | — | — | `NOT-MEASURED` | C0, C8 |
| K3 | Role assignments per node | 100M+ | — | — | `NOT-MEASURED` | C8 |
| K4 | Memory footprint (idle, 1M hot users) | < 500 MB | — | — | `NOT-MEASURED` | **C0** |
| K5 | Memory footprint (idle, 10M hot users) | < 8 GB | — | — | `NOT-MEASURED` | **C0** |
| K6 | Memory footprint (idle, 100M hot users) | < 50 GB | — | — | `NOT-MEASURED` | C0 (extrapolated) |
| K7 | Disk footprint (100M total users) | < 200 GB | — | — | `NOT-MEASURED` | **C0** |
| K8 | Binary size | < 50 MB | **41.39 MB** (39.47 MiB) | `dev-ryzen-7840hs` | **PASS** | C10 (settled) |
| K9 | Cold start to serving requests | < 2 s | **70 ms** worst-of-5 (min 59 ms) | `dev-ryzen-7840hs` | **PASS** | C10 (settled) |
| K10 | Cold-to-hot promotion latency | < 5 ms | — | — | `NOT-MEASURED` | C1 |

> **K8 and K9 are the only rows in this report that need none of C0–C9** — they are properties of the
> built artifact and of startup, not of load. They are settled here.
> Artifact: `docs/perf/artifacts/c10-artifact-facts.json` · Reproduce:
> `bash docs/perf/scripts/c10-artifact-facts.sh`
>
> **K9 scope, stated narrowly so it is not over-claimed.** "Cold start to serving requests" is
> measured as *process exec → first successful `GET /health`*, five iterations, each on a **fresh
> empty data dir** under `--dev` (in-memory storage, no corpus). Samples: 70, 69, 66, 64, 59 ms. We
> report the **worst** sample, not the mean, because worst-case is the operator-visible figure.
> A cold start against a large **on-disk corpus** — where WAL replay and SST open dominate — is a
> materially different measurement and is **not** graded by this row; it belongs to C8. Do not cite
> K9 as evidence that Hearth starts fast at scale.
>
> **Build provenance caveat.** The measured binary was built from the working tree at base commit
> `6e6a24c4` with C1's **uncommitted** hot-tier-telemetry changes present in `src/metrics.rs`,
> `src/storage/engine.rs` and `src/storage/tiered.rs` (HEAD had moved to `a397d86b` by the time the
> artifact was stamped — the shared branch is being worked concurrently). Both verdicts are robust
> to that contamination by a wide margin: 41.39 MB against a 50 MB budget (17% headroom) and 70 ms
> against a 2000 ms budget (28× headroom). Neither margin is threatened by in-flight telemetry
> counters. Both rows should nonetheless be **re-stamped on a clean tagged build** before v1.0 ships.

### 3.4 Axis E — Degradation shape past the hot-tier threshold (**headline deliverable**)

Graded per plan §1a: regress `log(p99)` on `log(n)` across a ≥5-rung geometric corpus ladder at
fixed active set. **PASS = slope ≈ 0 (O(1)) or curve linear in `log n`. MISS = any super-logarithmic
slope**, and we name the dominating term.

| # | Curve | Fitted exponent | 95% CI | Target | Verdict | Settled by |
|---|---|---|---|---|---|---|
| E1 | user lookup p99 vs corpus size | — | — | ≤ O(log n) | `NOT-MEASURED` | **C5** |
| E2 | session lookup p99 vs corpus size | — | — | ≤ O(log n) | `NOT-MEASURED` | **C5** |
| E3 | validate_token p99 vs corpus size | — | — | ≤ O(log n) | `NOT-MEASURED` | **C5** |
| E4 | SST file count vs corpus size | — | — | ≤ O(log n) | `NOT-MEASURED` | **C2** |
| E5 | p99 vs hot-set/capacity ratio (0.1×→10×, fixed corpus) | — | — | no cliff | `NOT-MEASURED` | C5 |
| E6 | Ratio at which p99 first breaches §7.1 budget | — | — | stated, not graded | `NOT-MEASURED` | C5 |
| E7 | Overload behaviour at 2× / 5× / 10× sustainable | — | — | bounded, honest failure | **`NOT-MEASURABLE`** (C3 pending) | C6 → re-run after C3 |

**E4 is the load-bearing row of this entire report.** See §5.

### 3.5 E7 review — why C6's MISS is not accepted into the table

C6 (`docs/perf/HEA-1874-C6-overload-behaviour.md`, commit `a397d86b`) grades overload behaviour
**MISS**. After applying §0.2, **E7 is recorded as `NOT-MEASURABLE`, not MISS.** C6 did careful work
and its *recommendation* is sound, but its evidence does not support a verdict about Hearth. The
distinction matters: a MISS is a claim that we measured Hearth and Hearth failed.

**The disqualifying fact: the server was idle during every overload run.** Reading the raw resource
samples that C6 cites:

| Run | users | RPS | fail | server CPU mean | server CPU peak | RSS peak |
|---|---|---|---|---|---|---|
| `steady-500u` | 500 | 1678 | 0% | 178% | 292% | 3.61 GB |
| `steady-600u` | 600 | 13 | 100% | **5.8%** | 238% | 3.93 GB |
| `steady-700u` | 700 | 30 | 100% | **0.0%** | **0.0%** | 3.93 GB |
| `steady-800u` … `steady-2000u` | 800–2000 | 36–89 | 100% | **0.0%** | **0.0%** | 3.93 GB |
| `steady-3500u`, `steady-5000u`, `ceiling` | 3500–6000 | 156–285 | 100% | *no data* | *no data* | *no data* |

At 2× the knee and beyond, server CPU is **0.0% mean and 0.0% peak** of 1600% available. Hearth was
not overloaded — it was **idle**. Requests never arrived. C6's headline observation ("no 503s at any
overload multiplier; every failure is a silent client timeout") is therefore fully explained by the
generator failing to emit load, and does **not** demonstrate anything about how Hearth sheds load,
because Hearth was never offered any. You cannot grade a system's overload behaviour on a window in
which it did no work. That is rule 3 in substance.

Three further defects, each independently sufficient to keep E7 out of the graded set:

1. **Provenance claim is false.** §6 of C6 states the raw data is in `loadtest/reports/hea1812/*.json`
   "(committed)". It is not: `loadtest/reports/` is **gitignored** (`.gitignore:66`). The entire
   evidence base is untracked local scratch that cannot be re-audited from the repository and will
   not survive a clean checkout. For a conformance report this is a hard provenance failure.
2. **Three different builds are compared in one degradation table.** C6's header cites build
   `a79b2e63`, but that SHA belongs only to `ceiling.json` (6000u). The 1×–2× rows come from
   `dcd2b8c7` and the 5×/10× rows from `6f5b562a`. A degradation curve assembled across three
   unrelated builds is not a curve.
3. **The "no OOM / RSS flat → PASS" sub-grade is unsupported at 5× and 10×.** Those runs carry no
   resource samples at all (`cpu_mean: null`, `rss_peak_bytes: 0`). And where RSS *is* flat, flatness
   is explained by the server being idle — it is not evidence of memory robustness.

**What C6 does establish, and what is kept.** C6's *code-level* claim is independently verifiable and
**confirmed**: Hearth has no admission control. `tower` is compiled with only the `util` feature and
`tower-http` with only `trace` (`Cargo.toml:87-88`) — neither `load-shed`, `limit`, nor `timeout` is
enabled — and a repo-wide search for `LoadShed` / `ConcurrencyLimit` / `TimeoutLayer` in `src/`
returns **zero** hits. So "Hearth cannot return a fast 503 under overload because it has no mechanism
to do so" is true **on code inspection**, and C6's §5 remediation (Tower `LoadShed` +
`ConcurrencyLimit`, bounded blocking pool, request timeout) is the right recommendation. It is
carried into §6 as a remediation item on that basis — *not* on the basis of the overload runs.

**To settle E7:** re-run the 2×/5×/10× ladder after C3 lands generator isolation, on a single build,
with resource sampling confirmed non-null at every rung, and with the raw artifacts committed (or
`loadtest/reports/` un-ignored for the subset that backs published figures).

### 3.6 Systemic: `summary.ceiling` cannot be trusted to enforce rule 3

**Every** run in the table above — including the ones at 0.0% server CPU — carries
`summary.ceiling: "server"` in its JSON. The harness's auto-computed attribution field says the
*server* was the limiter in runs where the server was demonstrably doing nothing.

This is a programme-level problem, not a C6 problem. §7's data contract makes rule 3 machine-checkable
via `ceiling.attribution`, and **that field is currently wrong in the source data**, so the check
would pass runs it is designed to reject. Note the hand-written `single_node_ceiling.failure_onset.attribution`
block in `loadtest/baseline/steady-baseline.json` is honest ("load_generator / host_contention — NOT
server saturation") — it is the *derived* `summary.ceiling` that misreports. Until it is fixed,
**ceiling attribution must be corroborated against server CPU utilisation, not read off the field.**
A run reporting `ceiling: "server"` at near-zero server CPU is generator-limited by definition.
Tracked as **C11** against the loadtest harness.

---

## 4. The three per-user memory numbers

The plan requires these three stated plainly, each with the fixed intercept separated out, derived
from a **multi-point regression at idle with the generator not running** — never from a ratio.

| Number | Value | Fixed intercept | Method | Host | Verdict |
|---|---|---|---|---|---|
| bytes-resident-per-hot-user | — | — | RSS slope + direct accounting, must agree | — | `NOT-MEASURED` (C0) |
| bytes-resident-per-session | — | — | separate sweep, so costs don't contaminate | — | `NOT-MEASURED` (C0) |
| bytes-on-disk-per-user | — | — | SST bytes ÷ users | — | `NOT-MEASURED` (C0) |

**The "~12 KB/user" figure that has circulated is withdrawn and must not be cited.** It was
3.61 GB peak RSS ÷ 300k users from a *single* point taken *under load* with the generator
*co-resident*. It lumps together fixed process overhead, sessions, tokens, RBAC state, the audit
hash chain, memtables, block cache and allocator slack, and attributes the whole sum to users. The
`User` record itself (`src/identity/types/user.rs:111`) serialises to a few hundred bytes, so
VISION's 500 B/hot-user target is tight but not architecturally absurd. **The slope is the cost; the
ratio is an artifact.**

C0 is required to produce both an RSS-slope number and a direct byte-accounting number and to
**require them to agree**. If they disagree, neither ships and C0 explains the gap.

---

## 5. Standing architectural risk (hypothesis, not yet a finding)

> This section states, in advance, what we already believe from reading the code. It is recorded
> here so that the eventual measurement can **contradict** it on the record. None of it is graded.

**H1 — The cold-lookup path is O(#SSTs), not O(log n).** `EmbeddedStorageEngine::get`
(`src/storage/engine.rs:669-715`) resolves: hot tier → active memtable (O(log n) BTreeMap) → **a
linear scan over every SST reader, newest-first** (`engine.rs:697-712`; `sst_readers` is a flat
`Vec`, `engine.rs:187`). Each SST is cheap to reject — O(1) min/max key-range prune
(`sst.rs:446`), then a per-file Bloom filter, then binary search on an in-memory entry vector
(`sst.rs:498-517`) — but **the fan-out itself is linear in file count.** There is no level
structure, no per-level key-range index in the read path, and no block index.

Therefore the complexity class of a hot-tier miss is governed **entirely** by how SST count grows
with corpus size under our compaction policy — row **E4**, which nobody has measured. If file count
grows ~linearly with data, cold lookups are effectively **O(n)** and the board's requirement is
violated at the architecture level. If compaction holds file count logarithmic (or constant per
level), we are fine. This is empirically decidable and cheap to decide, which is why C2 runs first.

Per plan §8 decision 5: if E4 comes back super-logarithmic, the remediation (levelled read path or
per-level key-range index) is storage-engine work **larger than this programme's scope**, and I will
raise it as a separate roadmap issue with a recommendation rather than absorb it here.

**H2 — We are blind exactly where the board wants data.** `src/metrics.rs:147-290` exports no
hot-tier metric at all. The only in-process counters are `promote_counter` / `admitted_promotions`
(`src/storage/tiered.rs:100-103`), used in tests and never exported. There is **no hit counter, no
miss counter, no eviction counter**, and `get` is not even timed (`engine.rs:669`). Consequently the
tier-miss report's "miss rate" (`loadtest/src/report.rs:323`) is a *by-construction arithmetic
estimate* (`1 − capacity/corpus`), not an observed value. It is honest about this, but it means we
currently cannot distinguish a genuine miss from a promotion-admission artifact — note prod ships
`promote_sample_rate = 4` (`tiered.rs:56`), so only 1 in 4 accesses is even eligible for promotion
and a naive short run will **over-report** misses. **Axis E is not measurable until C1 lands.**

**H3 — Single-node capacity is not escapable by clustering.** Hearth's cluster layer (`openraft`) is
a **replicated state machine**: every node applies the same log and holds the **full** dataset. It
buys availability, failover and bounded-staleness follower reads. It does **not** shard and adds
**zero** record capacity. A 5-node Hearth cluster holds exactly as many users as one node — it holds
them five times. So K1's 100M users/node is not an aspirational stretch goal that clustering lets us
dodge; it is the **capacity floor of the entire product, cluster included.** This is what makes H1
and §4 the highest-value items in the programme rather than curiosities.

---

## 6. Ranked remediation list

Populated as rows reach `MISS`. Each entry: the failing row, the measured gap, the dominating term,
the proposed fix, and an effort/risk estimate.

**No row has been graded MISS yet**, because no load-bearing row has been admissibly measured. The
list below therefore contains items justified by **code inspection**, not by measurement, and each
says so. They are ranked by expected impact on the board's question.

| # | Item | Basis | Affects | Fix | Effort / risk |
|---|---|---|---|---|---|
| R1 | **No admission control anywhere in the HTTP stack.** `tower` compiled with only `util`, `tower-http` with only `trace` (`Cargo.toml:87-88`); zero hits for `LoadShed` / `ConcurrencyLimit` / `TimeoutLayer` in `src/`. Hearth has no mechanism to return a fast 503, so under genuine overload it can only queue. | **Code inspection — confirmed.** Not from the C6 runs (§3.5). | E7, and operator trust generally | Tower `LoadShedLayer` + `ConcurrencyLimitLayer` on the router; `tower_http` `TimeoutLayer` as defence in depth; bounded queue + immediate rejection on the Argon2id blocking pool. Per C6 §5, in order 5a → 5c → 5b. | Low effort, low risk on the happy path; needs a calibrated `max_in_flight` default, which needs C7's real numbers. |
| R2 | **`summary.ceiling` misreports generator-limited runs as `server`.** Reports 0.0% server CPU and `ceiling: "server"` simultaneously. | **Data inspection — confirmed.** | Rule 3 enforcement across the *whole* programme; every child artifact | Corroborate attribution against sampled server CPU; refuse `server` attribution below a utilisation floor. | Low effort. **Blocks trustworthy grading of every load-generated row**, so it ranks above its size. |
| R3 | **Cold-lookup fan-out is linear in SST count** (§5 H1). | **Code inspection — hypothesis, pending E4/C2.** | E1–E4, K1 | Levelled read path or per-level key-range index. Out of this programme's scope; raise as roadmap work per plan §8 decision 5. | Large. Do not start before C2 reports. |
| R4 | **No hot-tier hit/miss/eviction telemetry** (§5 H2). | **Code inspection — confirmed.** | All of Axis E, K10, L8 | C1, in flight. | Small; also ships as real production observability. |

---

## 7. Data contract (read this before producing any child-issue output)

C10 is not only the join point — it is also an **input** to C0–C9. Children must emit results in the
schema below, or this report cannot consume them without hand-transcription (which is exactly how
figures lose their hardware attribution).

**Location:** `docs/perf/artifacts/<child>-<axis>.json`, e.g. `docs/perf/artifacts/c2-sst-growth.json`.

```jsonc
{
  "schema": 1,
  "child_issue": "HEA-XXXX",          // the child that produced this
  "axis": "E4",                        // conformance-table row id from §3 (L1..L8, T1..T4, K1..K10, E1..E7)
  "git_sha": "6e6a24c4",
  "timestamp_utc": "2026-07-28T00:00:00Z",

  "host": {                            // REQUIRED — rule 1. Omitting this makes the figure inadmissible.
    "profile": "dev-ryzen-7840hs",     // must match a profile named in §2
    "cpu_model": "AMD Ryzen 7 7840HS",
    "cores_physical": 8, "threads": 16,
    "governor": "powersave",
    "ram_total_gib": 54, "ram_available_gib": 13,
    "generator_placement": "co-resident" // "co-resident" | "pinned-disjoint" | "remote"
  },

  "swap": {                            // REQUIRED — rule 5. Non-zero swap_in_pages ⇒ run is VOID.
    "swap_in_pages": 0, "swap_out_pages": 0, "void_due_to_swap": false
  },

  "ceiling": {                         // REQUIRED for any load-generated figure — rule 3.
    "attribution": "server",           // "server" | "generator_saturated" | "host_contention"
    "reason": "..."
  },

  "measurements": [
    { "name": "user_lookup_p99_us", "value": 0, "unit": "us",
      "corpus_users": 100000, "active_set": 10000, "hot_tier_capacity": 10000,
      "tier_outcome": "sst_hit" }     // "hot_hit" | "memtable_hit" | "sst_hit"
  ],

  "fit": {                             // REQUIRED for any Axis E / "flat"/"scales" claim — rule 2.
    "model": "log(p99) ~ log(n)",
    "exponent": 0.0, "ci95_low": 0.0, "ci95_high": 0.0,
    "r_squared": 0.0, "n_points": 5,
    "dominating_term": "..."           // name it when the exponent is super-logarithmic
  },

  "verdict": "NOT-MEASURED",           // PASS | MISS | NOT-MEASURABLE | NOT-MEASURED
  "verdict_reason": "...",             // REQUIRED when NOT-MEASURABLE or MISS
  "reproduction": "bash loadtest/scripts/..."
}
```

**Rules enforced by the schema, mirroring §0.2:**
- No `host` block ⇒ figure inadmissible (rule 1).
- `verdict: "PASS"` on an Axis E row with no `fit.exponent` ⇒ rejected (rule 2).
- `verdict: "PASS"` with `ceiling.attribution != "server"` ⇒ rejected (rule 3).
- `swap.void_due_to_swap: true` ⇒ all measurements in the file are discarded (rule 5).
- `verdict: "NOT-MEASURABLE"` requires a non-empty `verdict_reason` — the reason is the deliverable.

### 7.1 Nightly-diff artifact

The aggregate `docs/perf/artifacts/latest.json` (union of all child artifacts, keyed by `axis`) is
the nightly-diff surface. A nightly job compares it against the previous commit's copy and reports
any row whose verdict regressed (`PASS → MISS`) or whose p99 moved more than a stated tolerance.
**Not yet wired** — it becomes actionable once ≥1 child has emitted a real artifact, and is tracked
as the final task of this issue.

### 7.2 Refreshed committed baseline

`loadtest/baseline/steady-baseline.json` (schema 2) remains the load-harness baseline and is
**not** superseded by this report. It is refreshed once C3/C4 land, at which point its
`single_node_ceiling` block can for the first time carry `attribution: "server"`. Until then its
headline numbers are harness figures and are quarantined out of §3 per rule 3.

---

## 8. Programme status

As of 2026-07-28. C3, C4, C6, C7, C8 were dispatched by C10 this session — the plan called for
eleven children and only five existed, so C10 could not have joined work that was never handed out.

| Child | Issue | Title | Status | Feeds |
|---|---|---|---|---|
| C0 | HEA-1868 | Real per-user / per-session memory cost | in progress | §4, K4–K7, C8 |
| C1 | HEA-1869 | Hot-tier observability | in progress (uncommitted in `src/`) | Axis E (all), K10, L8 |
| C2 | HEA-1870 | SST-count growth vs corpus size | in progress (`examples/sst_growth.rs`) | **E4** — the load-bearing row |
| C3 | HEA-1871 | Separate load generator from server | in progress (`loadtest/scripts/hea1871-isolated.sh`) | Axes C, D; C4, C6, C8 |
| C4 | HEA-1872 | High-concurrency generator (10k+) | in progress | T1–T4 over HTTP, C6 |
| C5 | HEA-1873 | Complexity-class sweep | todo | E1–E3, E5, E6 |
| C6 | HEA-1874 | Graceful-overload behaviour | done (`a397d86b`) — **reviewed, E7 not accepted; re-run after C3** (§3.5) | E7 |
| C7 | HEA-1875 | Saturation-throughput benches (§7.2) | todo | T1–T4, L1–L5 in-process |
| C8 | HEA-1876 | Record- and session-scale sweep | in progress | K1–K3 |
| C9 | HEA-1877 | Issuance/Argon2id: queueing vs compute | todo | L6, L7 |
| C11 | HEA-1880 | `summary.ceiling` misattribution (filed by C10) | todo | **rule-3 enforcement, all load rows** |
| **C10** | **HEA-1878** | **This report** | **blocked** on the above — K8/K9 settled, E7 reviewed and rejected | — |

> **HEA-1879 is a duplicate of HEA-1877** (both C9, same assignee). Created by C10 from a stale
> listing; HEA-1877 is the survivor. C10 cannot cancel it (CTO authorization boundary on
> engineer-owned issues) — pending board action.

**C6 landed and has been reviewed — see §3.5.** Its MISS verdict is **not** accepted into the
conformance table: the server was at 0.0% CPU during every overload run, so the runs grade the
generator, not Hearth. Its code-level finding (no admission control) is confirmed independently and
kept as remediation item R1. Applying the rules to a child's conclusion rather than importing it is
the whole point of this report; C6 is the first instance of that working as intended, and the review
also surfaced C11, which would otherwise have silently corrupted rule-3 enforcement programme-wide.

**Outstanding board decision:** plan §8 item 3 — provision a second host for Tier 2. Without it,
Axes B and C ship as `NOT-MEASURABLE (no isolated generator host)` rather than graded. See §2.
