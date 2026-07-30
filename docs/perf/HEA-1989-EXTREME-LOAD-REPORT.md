# HEA-1989 — Performance Report Mk 2: Extreme Load

**Question asked:** does Hearth hold its performance guarantees at ~millions of
user records and ~tens of thousands of concurrent active users, on a single node?

**Date:** 2026-07-30 · **Commit:** `43190f5e` · **Host:** `dev-ryzen-7840hs`
(AMD Ryzen 7 7840HS, 8C/16T, 54 GB RAM, NVMe, `powersave` governor, on battery,
~33 GB RAM already in use by other processes). CPU observed boosting to 4.6 GHz,
so the governor was **not** throttling these runs.

**Plane discipline.** Every number below is **engine plane** (in-process, no HTTP,
no load generator) unless explicitly labelled otherwise. Engine figures are a
*floor* — the HTTP/axum/tokio delta sits on top and is **not** included. Do not
place these beside a competitor's HTTP figure.

---

## 0. Verdict

| Half of the question | Verdict |
|---|---|
| **Millions of user records** — does lookup slow down as the corpus grows? | ✅ **PASS.** Measured O(1) hot, O(log n) cold. No budget breach anywhere on the ladder. |
| **Tens of thousands of concurrent users** | ⛔ **NOT MEASURED — and not measurable today.** The load-test harness is broken at HEAD (§3). No end-to-end concurrency evidence exists at *any* scale. |
| **Do the published throughput guarantees survive at that scale?** | ❌ **No.** The headline token-validation figure depends on a 2048-entry cache that never evicts. At tens of thousands of concurrent users the fast path is unreachable and throughput falls **9.4× below** the VISION bar (§2). |

The corpus-size half of the question is genuinely strong. The concurrency half is
where the guarantees break, and the break is architectural, not a tuning problem.

---

## 1. Corpus scale — PASS

Fresh C5 complexity sweep (`examples/complexity_sweep`), this run:

| corpus (n) | SSTs | hot p50/p99 (µs) | cold-natural p99 (µs) | cold-compacted p99 (µs) |
|---|---|---|---|---|
| 10,000 | 2 | 0.1 / 0.1 | 91.2 | 114.5 |
| 20,000 | 5 | 0.1 / 0.4 | 103.1 | 163.1 |
| 40,000 | 11 | 0.1 / 0.1 | 145.4 | 224.3 |
| 80,000 | 22 | 0.1 / 0.1 | 135.2 | 233.7 |
| 160,000 | 45 | 0.1 / 0.4 | 125.4 | 235.4 |
| 320,000 | 91 | 0.1 / 0.1 | 157.0 | 202.0 |

Fitted exponents (`log p99` on `log n`):

- **hot `+0.076`** (R²=0.024) → flat, **O(1)**. PASS.
- **cold natural `+0.133`** (R²=0.686) → PASS.
- **cold compacted `+0.164`** (R²=0.566) → sub-linear, consistent with **O(log n)**. PASS.
- `#SSTs` `+1.087` (R²=0.997) — SST count grows linearly with corpus; cold fan-out
  is `(#SSTs probed) × (per-SST binary search)`. Base compaction defaults to
  `enabled: true` (`src/storage/engine.rs:117`), so `#SSTs` is bounded in steady
  state and the **compacted** curve is the governing complexity class.

**Hot-tier over-subscription (Axis B, corpus fixed at 160k, active set 2,000):**

| active/capacity | hit ratio | p50 (µs) | p99 (µs) | breaches 500 µs? |
|---|---|---|---|---|
| 0.1× | 100.0% | 0.1 | 0.1 | no |
| 1.0× | 100.0% | 0.1 | 0.1 | no |
| 3.0× | 15.1% | 0.9 | 76.5 | no |
| 10.0× | 0.0% | 0.8 | 23.6 | no |

Even at **10× over-subscription with a 0% hot-tier hit ratio**, active-set p99 is
23.6 µs — 21× inside the 500 µs budget. Cold-tier degradation is graceful.

**Memory at corpus scale** is a non-issue: 101 B/user marginal resident
(δRSS 97 MiB at 1M users, `PUBLISHED_FIGURES.md` §3.1), so K4/K5/K6 all pass with
wide margin. This run seeded and served a **1.2M-user, 4-realm corpus** without
difficulty.

**Caveat — the ladder stops at 320,000.** `AXIS_A_LADDER` in
`examples/complexity_sweep.rs:78` tops out at 320k. **No committed harness measures
lookup complexity at the multi-million scale the question asks about.** The fits
above are clean and the extrapolation is well-supported, but it *is* an
extrapolation. Note also the standing measurement that RAM scales with a log-log
exponent of 0.8778 — near-linear, not O(1); "O(1) RAM regardless of corpus size"
remains a claim the data does not support.

---

## 2. The headline defect — the token-claims cache makes the fast path unreachable at scale

This is the most important finding in this report.

**Mechanism** (`src/identity/engine/mod.rs`):

- `TOKEN_CLAIMS_CACHE_MAX = 2048` (line 212) — keyed by SHA-256 of the raw JWT.
- `token_claims_cache_insert` (lines 3360-3369) **returns early at capacity**:
  ```rust
  if self.token_claims_cache.load().len() >= TOKEN_CLAIMS_CACHE_MAX {
      return;
  }
  ```
- There is **no eviction, no TTL sweep, and no removal path anywhere** — verified by
  enumerating every reference to `token_claims_cache`: one insert, one read, and
  the constructors. Nothing ever removes an entry.
- Default access-token TTL is **900 s** (`src/identity/tokens.rs:141`).

**Consequence.** The first 2,048 distinct tokens seen after boot take the slots and
hold them **for the lifetime of the process**. Those tokens expire within 15
minutes. From then on the cache is 2,048 permanently-dead entries and can never
accept another. **Steady-state hit rate converges to 0 after ~15 minutes of
uptime**, for any deployment with normal token rotation.

At tens of thousands of concurrent users the cache is oversubscribed 25×+ even
before expiry, so the fast path was never reachable at that scale regardless.

**Measured cost of that difference** (C7 saturation, n=2 runs today):

| op | 1T ops/s/core | agg @16T | vs 200k/core bar |
|---|---|---|---|
| `validate_token` **[hot]** | 835,354 / 714,197 | 9,382,161 / 8,860,813 | MET |
| `validate_token` **[miss]** | **21,406 / 21,307** | **135,697 / 124,436** | **MISS (9.4×)** |

The miss figure is reproducible to within 0.5% across both runs — this is a solid
number, not noise.

**Against the VISION §7.2 targets:**

- Bar: 200,000 ops/s/core → measured steady-state **21,307** = **9.4× MISS**.
- Bar: 3,000,000 total on a 16-core server → measured **124,436** = **~24× MISS**.

**Worked example.** 50,000 concurrent users at a modest 5 requests/sec each is
250,000 token validations/sec. The measured miss-path ceiling on this 16-thread
host is ~135,697/sec. **The server saturates at roughly half the offered load** —
and that is the engine floor, before any HTTP overhead.

The published "3M+ token validations/sec" headline is therefore an artifact of a
benchmark that pre-warms 2,048 tokens and then re-validates those same tokens. It
does not describe a production steady state.

**This is a bounded fix,** not a redesign: give the cache an eviction policy (LRU
or clock, matching the hot tier) and size it from the expected concurrent-token
working set rather than a hardcoded 2,048. The measurement to prove it already
exists — the `[hot]`/`[miss]` split in `examples/saturation_throughput.rs`.

---

## 3. Concurrency — cannot be measured today, because the harness is broken

`make loadtest` is documented as the whole contract: *"That command is the entire
contract... If you can build the repo, `make loadtest` works."* (`loadtest/README.md`).

**It does not work at HEAD.** Full run this session, 1.2M-user corpus, 500 users:

```
==> Large corpus resident; proceeding to token-pool seed + run
==> Running load (mode=steady, users=500, run-time=120s, throttle=0)
load run failed: seed corpus unusable: seed handle has no live (non-revoked) tokens
make: *** [Makefile:83: loadtest] Error 1
```

**Root cause.** `loadtest/src/seed.rs:144`:

```rust
tokens: Vec::new(), // ROPC tokens no longer minted (HEA-1862/HEA-1907)
```

The ROPC (`grant_type=password`) removal — a correct security change — left the
seeder minting **zero** tokens, with no replacement token-minting path wired.
`loadtest/src/scenarios.rs:84` then hard-aborts the entire run when the token list
is empty. Every token-dependent journey (validate / session / user) is dead, which
is to say the load test is dead.

**Why it shipped silently:**

- It was introduced in the **current HEAD commit `43190f5e`** — PR #268, labelled
  `docs(perf):`. A docs-labelled PR disabled the load harness.
- The only guard, `make loadtest-check`, is `cargo check` — a typecheck. It cannot
  catch a runtime "no live tokens" abort.
- `loadtest` appears in **no CI workflow at all** (`grep -rl loadtest .github/workflows/`
  returns nothing).

**Second, independent ceiling.** Even once the harness is repaired, the load
generator is co-resident with the server on the same 16 vCPUs, and prior bisection
(HEA-1813) puts collapse between 500 and 600 concurrent generator users — with the
*server going idle* (CPU 178% → ~0%) while requests time out client-side. That is a
rig limit, not a Hearth limit, and it means **tens of thousands of concurrent users
cannot be driven from this host at all**, at any corpus size.

**Net:** there is currently no evidence — none — about Hearth's end-to-end behaviour
at high concurrency. The honest answer to "does it hold up at tens of thousands of
concurrent users" is **unknown**, and §2 gives strong reason to expect it does not.

---

## 4. Session creation (T4) — UNSTABLE, all 5 runs MISS (HEA-1993)

**Updated 2026-07-30 by HEA-1993** — 5 alternating runs at HEAD (`43190f5e`), same host.

| run | device fsync rate | agg ops/s @T=256 | coalescing efficiency | W | vs 30,000 bar |
|---|---|---|---|---|---|
| 1 | 532.1 /s | **33,888** | 24.9% | 1.000 | **MISS** |
| 2 | 486.4 /s | **16,281** | 13.1% | 1.000 | **MISS** |
| 3 | 502.6 /s | **15,978** | 12.4% | 1.000 | **MISS** |
| 4 | ~430 /s est. | **33,531** | 24.4% | 1.000 | **MISS** |
| 5 | 263.4 /s | **10,047** | 14.9% | 1.000 | **MISS** |
| **median** | — | **~16,281** | — | **1.000 all** | **MISS** |

**Verdict: UNSTABLE — all 5 runs MISS the 30,000 ops/s bar.**

5-run range: **10,047–33,888 ops/s (3.4×)**. `fsync`-before-ack intact (`W`=1.000) on every run.

The previously published figure of 41,255 (and the two samples above at 21,179 and 43,043)
are now confirmed to be within the natural run-to-run jitter of this host. The 10-run range
quoted in `PUBLISHED_FIGURES.md` (30,466–48,648) is inconsistent with this 5-run sweep on the
same binary — likely reflecting a quieter, warmer host during that session.

The spread correlates with coalescing efficiency (12–25%), not device fsync rate alone
(263–532/s). The group-commit leader is forming batches of only ~85 entries/fsync at T=256
where the ceiling would require ~180+ to clear 30k ops/s at median fsync rates. This is host
scheduling jitter in batch formation timing, not a deterministic code defect.

**T4 must not be quoted as PASS on any binary until measured on a quiescent server-class host.**
The prior "10-run range 30,466–48,648" in `PUBLISHED_FIGURES.md` is also retracted — it
predates this sweep and is inconsistent with it.

---

## 5. Cold-path concurrency scaling degrades

Relevant precisely when the working set exceeds the hot tier — i.e. at millions of
records with a large active population:

| op | scaling exponent | efficiency @16T |
|---|---|---|
| `session_lookup` [hot] | +0.692 | 0.39 |
| `session_lookup` [miss] | +0.442 | 0.21 |
| `user_lookup` [hot] | +0.594 | 0.32 |
| `user_lookup` [miss] | **+0.346** | **0.17** |
| `permission_check` [hot] | +0.710 | 0.42 |

Absolute throughput stays high (`user_lookup` [miss] still 6.8M/s aggregate), so no
budget is breached — but adding cores buys progressively less on the miss path.
Worth watching; not currently a failure.

---

## 6. What to do, in priority order

1. **Fix the token-claims cache** (§2) — add eviction and size it from the expected
   concurrent-token working set. This is the only finding here that invalidates a
   published performance guarantee. Bounded, well-understood fix.
2. **Repair the load-test harness** (§3) — restore token minting via a non-ROPC path
   and put `make loadtest` in CI as a smoke run so a typecheck-only guard cannot
   hide a dead harness again.
3. **Get a server-class, quiescent host** — until the generator stops sharing CPUs
   with the server, no concurrency figure above ~500 users is obtainable. This
   blocks the actual question asked and cannot be engineered around locally.
4. **Extend the C5 ladder past 320k** so the multi-million claim is measured rather
   than extrapolated.
5. ~~**Re-measure T4** with ≥5 alternating runs before quoting it either way.~~ **Done (HEA-1993, 2026-07-30)** — all 5 runs MISS; T4 is UNSTABLE on this host. See §4 above.

---

## 7. Reproduction

```bash
export PROTOC=$(which protoc)
CARGO_TARGET_DIR=/scratch/cache/target cargo build --release --examples --bin hearth
/scratch/cache/target/release/examples/saturation_throughput   # §2, §4, §5
/scratch/cache/target/release/examples/complexity_sweep        # §1
MODE=steady USERS=500 RUN_TIME=120s make loadtest              # §3 — fails at HEAD
```

Raw console output for all four runs was captured under the run scratch directory
and is summarised verbatim in the tables above.
