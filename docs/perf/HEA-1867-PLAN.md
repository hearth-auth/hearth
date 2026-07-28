# HEA-1867 — Full Performance & Load Test Programme (Plan)

**Owner:** CTO · **Status:** awaiting board approval · **Revision:** 3 · **Mode:** planning only (no implementation yet)

**Rev 3 changes:** board redirected the programme's centre of gravity. The primary
question is no longer "is it fast when everything fits in RAM" but **"what shape is the
curve once the active set exceeds the hot tier, and is that shape O(1)/O(log n)?"** Plus:
measure the *real* per-user memory cost, not a ratio. §1, §3 (findings 5–7), §5 and §8 are
rewritten accordingly. Code-grounded citations added throughout.

## 1. The ask, restated in measurable terms

> "Millions of user records and tens of thousands of active concurrent users on a single
> node without slowing down meaningfully… performance scales, particularly after the active
> user count exceeds the hot-path threshold… as close to O(1) or O(log n) as possible."

Five *independent* axes. They must be measured separately or the results are uninterpretable.

| Axis | Concrete target (source) | Currently measured? |
|---|---|---|
| **A. Record scale** | 100M users/node managed; lookup latency flat as corpus grows (VISION §7.3) | Partially — 300k in committed baseline; 1.2M corpus config exists, never measured |
| **B. Session scale** | 10M active sessions/node (VISION §7.3) | **No** — max ~600k seeded sessions, never measured as a scale axis |
| **C. Request concurrency** | "tens of thousands" concurrent clients | **No** — harness collapses at 600 concurrent users |
| **D. Throughput** | 200k validate/s/core → 3M/s on 16 cores (VISION §7.2) | **No** — nothing measures saturation throughput at all |
| **E. Degradation shape past the hot-tier threshold** | **Board directive:** latency growth ≤ O(log n) in corpus size; no cliff, no collapse, graceful under overload | **No** — and, per finding 5, the current design is not obviously O(log n) here |

Axis E is now the **headline deliverable**. A, B, C, D are the conditions that make E
measurable and the numbers that make it actionable.

Latency targets we grade against are VISION §7.1: validate_token p99 < 500 µs, session
lookup p99 < 100 µs, user lookup p99 < 500 µs, token issuance p99 < 5 ms.

### 1a. How "O(1) or O(log n)" gets graded (definition of the verdict)

A prose claim of "flat" is not gradeable. Axis E is graded by **fitting the curve**, not by
spot-checking two points:

- Sweep corpus size across ≥5 points on a geometric ladder (100k → 300k → 1M → 3M → 10M as
  hardware allows), holding the **active set constant** and holding hot-tier capacity constant.
- At each point record: p50/p99/p999 for user lookup, session lookup, validate_token; hot-tier
  hit ratio; SST file count; bytes resident.
- Fit p99 against corpus size and report the empirical exponent — regress `log(p99)` on
  `log(n)`. **PASS = slope ≈ 0 (O(1)) or the curve is linear in `log n`. MISS = any
  super-logarithmic slope**, and we name the term that dominates.
- Separately sweep **hot-set/capacity ratio** from 0.1× to 10× at *fixed* corpus size, to
  isolate threshold-crossing behaviour from corpus-growth behaviour. These are two different
  independent variables and the existing tier-miss mode conflates them.

The report states an exponent and a confidence interval per operation, not an adjective.

## 2. What we already have (do not rebuild)

- `loadtest/` — Goose harness: seed step, 5 closed-loop journeys, `steady`/`ramp`/`soak`/`tier-miss`
  modes, µs-resolution histograms, per-journey budgets, server RSS/CPU sampling, ceiling
  attribution, committed baseline. Good foundation.
- `loadtest/src/load.rs:747` `run_tier_miss` — already splits `lookup_hot` vs `lookup_cold`
  journeys and reports hot-vs-cold p50/p95/p99 (`loadtest/src/report.rs:238`). This is the
  seed of Axis E and gets extended rather than replaced.
- `benches/` — 13 criterion benches; `make bench-gate` asserts p50/p99 on 5 hot paths.
- `make seed-large` + `examples/large-scale-demo/` — millions-of-users corpus boot.

## 3. Honest read of the evidence we already hold

Seven findings fall out *before* any new run. Each becomes a hypothesis to confirm or kill.

1. **We cannot currently measure the ask.** HEA-1813 bisected the failure onset to
   500→600 concurrent users and attributed it to the *load generator*, not Hearth: across
   the cliff server CPU **collapses** (178% → 5.8% → ~0% of 1600% available) while RSS stays
   flat. Requests stop arriving. Goose and the server contend for the same 16 vCPUs.
   **Axis C is unmeasurable until the generator is separated from the server.**
2. **Throughput is ~3 orders of magnitude below target — but undisproven.** Best clean
   number is 1,677 RPS at 500 users, against a 3,000,000/s target. At that point the server
   was 11% utilised. We have never offered Hearth enough load to find its own limit, so
   1,677 RPS is a *harness* figure and must not be quoted as a Hearth figure.
3. **Memory footprint is unattributed.** Baseline server RSS is 3.61 GB peak / 2.64 GB mean
   at a 300k-user corpus. Dividing gives "~12 KB/user" — that ratio is **not** a per-user
   cost and must not be quoted as one. One point taken under load with the generator
   co-resident lumps together fixed process overhead, sessions, tokens, RBAC state, the audit
   hash chain, memtables, block cache and allocator slack. The `User` record itself
   (`src/identity/types/user.rs:111`) serialises to a few hundred bytes, so VISION's
   500 B/hot-user target is tight but not architecturally absurd. What matters is the
   **slope, not the ratio** — see finding 6 for how we now measure it properly.
4. **Token issuance p99 of 6–7 s is probably a queueing defect, not "Argon2id is slow."**
   The server was only at 178% of 1600% CPU while p99 sat at 7 s and max at 8.4 s.
   Compute-bound work saturates cores; this looks like requests **queueing behind a starved
   `spawn_blocking` pool** with no admission control. 7 s of silent latency is worse operator
   behaviour than a fast 503.

### New in rev 3 — the findings that answer the board's question directly

5. **The cold-lookup path is O(#SSTs), not O(log n) — this is the single biggest risk to
   the board's requirement.** `EmbeddedStorageEngine::get`
   (`src/storage/engine.rs:669-715`) is: hot tier → active memtable (O(log n) BTreeMap) →
   **a linear scan over every SST reader, newest-first** (`engine.rs:697-712`, `sst_readers`
   is a flat `Vec`, `engine.rs:187`). Each SST is cheap to reject — O(1) min/max key-range
   prune (`sst.rs:446`) then a per-file Bloom filter, then binary search on an in-memory
   entry vector (`sst.rs:498-517`) — but the *fan-out itself is linear in file count*.
   There is no level structure or per-level key-range index in the read path, and no block index.

   So the complexity class of a hot-tier miss is governed entirely by **how SST count grows
   with corpus size under our compaction policy** — which nobody has measured. If file count
   grows ~linearly with data, cold lookups are effectively **O(n)** and the board's
   requirement is violated. If compaction holds file count logarithmic (or constant per
   level), we are fine. This is empirically decidable and cheap to decide. **It is now the
   first thing the programme measures.**

6. **Real per-user memory cost is measurable at the byte level, not just by RSS slope.**
   The board asked for the real number, so we do it two ways and require them to agree:
   - **Marginal RSS slope** — seed at ≥3 corpus sizes, idle, generator not running, and
     regress RSS on user count. The intercept is fixed overhead; the slope is the real
     marginal cost per user. Same procedure for sessions on a separate sweep so the two
     costs do not contaminate each other.
   - **Direct accounting** — hot-tier occupancy is entry-count-bound, not byte-bound
     (`TieredConfig::hot_tier_capacity`, `src/storage/tiered.rs:62`, default 100_000; repo
     configs ship 10_000). So resident hot cost per user ≈ serialized entry size + `HashMap`
     +`CompositeKey` overhead, and it is **directly computable and directly assertable in a
     unit test**. On-disk cost per user comes from SST bytes ÷ users.
   These give three numbers the report must state plainly: **bytes-resident-per-hot-user**,
   **bytes-resident-per-session**, **bytes-on-disk-per-user** — each with the fixed intercept
   separated out. VISION §7.3.1's 100M/node claim rests on the third; §7.3's working-set
   claim rests on the first.

7. **We are blind exactly where the board wants data — there is no hit/miss/eviction
   telemetry.** `src/metrics.rs:147-290` exports no hot-tier metric at all; the only
   in-process counters are `promote_counter` / `admitted_promotions`
   (`src/storage/tiered.rs:100-103`), used in tests and never exported. There is **no hit
   counter, no miss counter, no eviction counter**, and `get` is not even timed
   (`engine.rs:669`). Consequently the tier-miss report's "miss rate"
   (`loadtest/src/report.rs:323`) is a *by-construction arithmetic estimate*
   (`1 - capacity/corpus`), not an observed value — it is honest about this, but it means we
   currently cannot tell a genuine miss from a promotion-admission artifact. Note prod ships
   `promote_sample_rate = 4` (`tiered.rs:56`) — only 1 in 4 accesses is even eligible for
   promotion, so the hot set converges slowly and a naive short run will *over-report* misses.
   **Axis E is not measurable until this telemetry exists.** It is a small, low-risk,
   independently useful change (it is also production observability we should ship regardless).

## 4. Hardware constraint — must be resolved by the board

This host: 16 vCPU, 54 GiB RAM with **~17 GiB free**, generator co-resident.

- Until finding 6 lands we do not know the real per-user cost, so the reachable corpus size
  on this host is itself an output of C0, not an input. At the (wrong, over-stated) 12 KB
  figure, 1M ≈ 12 GB is tight and 10M/100M are impossible here. If the true marginal cost is
  ~1 KB, ~10M becomes feasible on this host and Tier 2 shrinks to a concurrency question only.
- Axis C (10k+ concurrent) needs the generator off the server's cores regardless.

**Recommendation:** approve in two tiers.
- **Tier 1 (this host):** telemetry, complexity-class sweep, per-user memory accounting,
  core-pinned generator split, engine-level throughput benches, corpus to the largest size
  the measured per-user cost permits, issuance queueing investigation. This answers Axis E,
  A, D and the memory question, and gives a defensible lower bound on C.
- **Tier 2 (needs a second machine or cloud box):** true 10k+ concurrent-client measurement
  with a remote generator, and ≥10M record/session scale if C0 shows this host cannot hold it.
  Without it, Axes B and C ship as "extrapolated / not validated," stated plainly rather than
  papered over.

## 4a. Why single-node capacity is not escapable by clustering

Hearth's cluster layer (`openraft`, ARCHITECTURE.md §Cluster) is a **replicated state
machine**: every node applies the same log and holds the **full** dataset. It buys
availability, failover and bounded-staleness follower reads. It does **not** shard, and adds
**zero** record capacity. A 5-node Hearth cluster holds exactly as many users as one node —
it holds them five times.

So 100M users/node is not an aspirational stretch goal that clustering lets us dodge. It is
the **capacity floor of the entire product**, cluster included. That is what makes findings
5–6 the highest-value items here rather than curiosities. (Horizontal *capacity* scale-out
would need realm-sharded or range-partitioned placement, which Hearth does not have; out of
scope here, but if finding 5 or 6 confirms badly it becomes a roadmap question I will raise
separately.)

## 5. Work breakdown (child issues, in dependency order)

### Phase 0.5 — The cheap decisive experiments (run first, in parallel)

- **C0 · Real per-user / per-session memory cost.** Multi-point idle seed sweep (≥3 corpus
  sizes, generator not running) regressing RSS on record count, *plus* direct byte-level
  accounting of a hot-tier entry and an SST record. Sessions swept separately from users.
  **Exit:** three stated numbers — bytes-resident-per-hot-user, bytes-resident-per-session,
  bytes-on-disk-per-user — each with the fixed intercept separated, and a go/no-go on VISION
  §7.3/§7.3.1 reachability. Also outputs the max corpus size this host can hold, which sizes
  every later phase.
- **C1 · Hot-tier observability (blocks Axis E).** Export hit / miss / eviction / promotion
  counters and a `get`-path timing histogram, split by tier outcome (hot hit, memtable hit,
  SST hit, SST count probed). Also export live SST file count. Small change, shipped to prod
  as real observability, not test-only scaffolding. **Exit:** tier-miss runs report an
  *observed* hit ratio instead of an arithmetic estimate, and we can attribute any latency
  to the tier it came from.
- **C2 · SST-count growth vs corpus size (settles finding 5).** Measure file count and depth
  after seeding at each ladder rung, both immediately post-seed and post-compaction, and fit
  file count against corpus size. **Exit:** a stated complexity class for the cold path. If
  file count is super-logarithmic, this converts directly into a storage-engine remediation
  issue (levelled read path / per-level key-range index) and becomes the programme's top
  finding.

### Phase 0 — Make the measurement trustworthy (blocks Axes C and D)

- **C3 · Separate the load generator from the server under test.** Core-set isolation
  (server pinned to N cores, generator to the rest, via `taskset`/cgroup), plus a documented
  remote-generator path. Re-bisect the failure onset. **Exit:** the cliff moves materially and
  we can state whether the new limiter is Hearth or still the harness.
- **C4 · High-concurrency generator capable of 10k+ connections.** Goose's closed-loop
  per-user cost is the binding constraint. Add a low-overhead open-loop saturation driver for
  the read-only hot-path journeys, and **separate the connection-concurrency knob from the
  distinct-session-population knob** — 10k live sessions does not require 10k sockets, and
  conflating them is what makes current numbers unreadable. Includes an absolute
  session-count knob; today sessions are only settable as a fraction of users
  (`loadtest/src/params.rs:47`, `:233`), which makes Axis B unreachable by construction.
  **Exit:** a ≥10k-concurrent-client run whose ceiling attribution is `server`, not
  `generator_saturated`.

### Phase 1 — Axis E: the degradation-shape sweep (the headline deliverable)

- **C5 · Complexity-class sweep.** Extend `tier-miss` into a proper two-dimensional
  experiment per §1a: (i) corpus-size ladder at fixed active set, (ii) hot-set/capacity ratio
  ladder 0.1×→10× at fixed corpus. Report fitted exponents per operation, hot/warm/cold
  latency separated using C1's telemetry, and the ratio at which p99 first breaches the
  VISION §7.1 budget. **Exit:** a curve and an exponent per operation, and a named PASS/MISS
  against "≤ O(log n)".
- **C6 · Graceful-overload behaviour.** Push past the knee deliberately — corpus far beyond
  capacity, concurrency past saturation — and characterise the failure mode: does p99 degrade
  smoothly, or does the server collapse / OOM / stall? Grade against "fast, bounded, honest
  failure" (backpressure and 503s beat unbounded latency). **Exit:** a documented behaviour at
  2×, 5× and 10× the sustainable point, plus a recommendation on admission control.

### Phase 2 — Establish the engine's own ceiling (HTTP-independent)

- **C7 · Saturation-throughput benches for VISION §7.2.** In-process ops/s for validate_token,
  session_lookup, user_lookup, permission check, session creation, swept across 1/2/4/8/16
  threads, at both hot-hit and forced-miss states. **Exit:** per-core throughput and a scaling
  curve; whether the engine hits 200k ops/s/core and whether it scales or contends; and the
  honest split between engine cost and HTTP/axum/tokio overhead — the current HTTP budgets
  (engine target + 1 ms loopback envelope) are far too coarse to validate a 500 µs claim.

### Phase 3 — Scale the corpus and sessions to the stated ask

- **C8 · Record- and session-scale sweep.** Drive the ladder to the largest size C0 shows is
  feasible (1M → 10M if reachable), measuring lookup-latency flatness per tier, resident
  bytes, and seed wall-clock (a corpus we cannot build in reasonable time is a real
  operational limit). Grades Axes A and B against VISION §7.3.

### Phase 4 — Grade the known non-conformance

- **C9 · Issuance/Argon2id path: queueing vs compute.** Instrument the blocking pool,
  determine whether 7 s p99 is queue depth or CPU, add bounded admission control if it is
  queueing. Then force the spec decision: either the < 5 ms p99 issuance target is wrong and
  VISION must be corrected, or the implementation is. **Needs a board/product decision on
  which way to resolve it — I will bring a recommendation, not just data.**

### Phase 5 — The deliverable the issue asks for

- **C10 · `docs/perf/PERFORMANCE_REPORT_1_0.md`.** Per-target conformance table across VISION
  §7.1/§7.2/§7.3 with explicit **PASS / MISS / NOT-MEASURABLE** per row; the Axis E curves and
  fitted exponents; the three per-user memory numbers; the hardware every figure was measured
  on; and a ranked remediation list per MISS. Plus a refreshed committed baseline and a
  nightly-diff-ready artifact.

## 6. Sequencing & rough effort

Phase 0.5 runs immediately and in parallel with Phase 0 — C0 is idle-state measurement and
C1/C2 are engine-side, so none of the three needs the harness fixes. C0 sizes every later
phase; C1 unblocks Axis E; C2 can independently kill or clear the biggest architectural risk.

Phase 0 gates Axes C and D only. Phase 1 (Axis E) needs C1 and C2 but **not** Phase 0 — the
degradation-shape sweep is a latency-vs-corpus experiment, not a saturation experiment, so it
runs at modest concurrency where the current harness is already trustworthy. That is
deliberate: the board's top question is answerable without waiting on the generator rework.
Phase 2 is parallel throughout. Phase 3 follows C0 + Phase 0. Phase 5 is the join point.

Eleven child issues (C0–C10), delegated to engineers, with the CTO holding C9's spec decision
and the C10 verdict.

## 7. What this plan will *not* claim

- No multi-node/Raft horizontal-scale numbers — different axis, explicitly out of scope.
- No production-hardware numbers unless Tier 2 is approved; every figure carries the hardware
  it was measured on.
- Nothing graded PASS on the strength of a run whose ceiling attribution was the generator.
- No "flat" or "scales well" adjectives without a fitted exponent behind them.

## 8. Decisions requested

1. **Approve Phase 0.5 (C0, C1, C2) to start immediately**, ahead of everything else — yes/no.
   These are three small issues that between them produce the real per-user memory cost and
   settle whether the cold path is O(log n) or O(n). Cheapest possible path to the board's
   two questions.
2. Approve the full Tier-1 programme (C0–C10, 11 child issues) — yes/no.
3. Provision a second host / cloud instance for Tier 2 (true 10k-concurrent, and ≥10M scale
   if C0 shows this host cannot hold it) — yes/no. If no, Axes B and C ship as explicitly
   not-validated.
4. Pre-authorise the C9 outcome path: if issuance latency proves to be queueing, fix the
   implementation; if it proves compute-bound, I will propose amending the VISION §7.1
   issuance target rather than leaving a permanently-failing budget in the harness.
5. **New:** pre-authorise the C2 outcome path. If SST count proves super-logarithmic, the
   fix is storage-engine work (levelled read path or per-level key-range index) that is
   larger than this programme's scope. I would raise it as a separate roadmap issue with a
   recommendation rather than absorb it here — confirm that split is acceptable.
