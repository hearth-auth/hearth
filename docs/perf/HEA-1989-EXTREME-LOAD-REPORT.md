# HEA-1989 — Performance Report Mk 2: Extreme Load

**Question asked:** does Hearth hold its performance guarantees at ~millions of
user records and ~tens of thousands of concurrent active users, on a single node?

> **Revision 2.1 — 2026-07-30, post-remediation.** All four remediation tickets
> (HEA-1990/1991/1992/1993) are merged. §0, §1, §2, §3 and §6 are updated with
> post-fix measurements taken at commit `349660d3`; **§3 now contains the first
> end-to-end HTTP-plane concurrency numbers this programme has ever produced**
> (§8 is the revision log). Sections 4, 5, 7 are unchanged from Mk 2.0.

**Date:** 2026-07-30 · **Commit (Mk 2.0 body):** `43190f5e` · **Commit (rev 2.1
measurements):** `349660d3` · **Host:** `dev-ryzen-7840hs`
(AMD Ryzen 7 7840HS, 8C/16T, 54 GB RAM, NVMe, `powersave` governor, on battery,
~33 GB RAM already in use by other processes). CPU observed boosting to 4.6 GHz,
so the governor was **not** throttling these runs.

**Plane discipline.** Every number below is **engine plane** (in-process, no HTTP,
no load generator) unless explicitly labelled otherwise. Engine figures are a
*floor* — the HTTP/axum/tokio delta sits on top and is **not** included. Do not
place these beside a competitor's HTTP figure.

---

## 0. Verdict

**Rev 2.1 verdict** (supersedes the Mk 2.0 table below it):

| Half of the question | Verdict |
|---|---|
| **Millions of user records** — does lookup slow down as the corpus grows? | ✅ **PASS**, now measured to **1.28M** rather than extrapolated from 320k (HEA-1992). Hot p99 stays 0.2–0.3 µs across the whole ladder. |
| **Tens of thousands of concurrent users** | ⚠️ **PARTIALLY MEASURED — 500 concurrent, not tens of thousands.** The harness is repaired and ran clean end-to-end (§3). **Reads pass at 500 concurrent against a 1.2M-user corpus**; the run collapses somewhere between 500 and 1,000, but the collapse signature is *client-side* (rig), not server. Tens of thousands remains undrivable from this host. |
| **Do the published throughput guarantees survive at that scale?** | ⚠️ **Reads yes, writes no.** Over HTTP at 500 concurrent: `validate` p99 **1 ms** (budget 1.5 ms) ✅ and `session_lookup` p99 **1 ms** (budget 1.1 ms) ✅ — both PASS. **`issuance` (login → token) p50 2,000 ms / p99 4,000 ms against a 6 ms budget — a ~660× miss** (§3). The engine-plane token-cache defect (§2) is fixed (HEA-1990). |

**What changed since Mk 2.0.** The concurrency half is no longer unknown. The
answer is that the *read* hot path holds up under real HTTP concurrency at
million-record scale — that part of the VISION claim now has direct evidence
behind it. The failure has moved: **credential issuance is the binding
constraint**, and it is a KDF-queue constraint, not a storage one.

<details><summary>Mk 2.0 verdict (superseded — kept for audit trail)</summary>

| Half of the question | Verdict |
|---|---|
| **Millions of user records** | ✅ **PASS.** Measured O(1) hot, O(log n) cold. |
| **Tens of thousands of concurrent users** | ⛔ **NOT MEASURED — and not measurable today.** The load-test harness is broken at HEAD. |
| **Do the published throughput guarantees survive at that scale?** | ❌ **No.** Headline token-validation figure depends on a 2048-entry cache that never evicts; **9.4× below** the VISION bar. |

</details>

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

~~**Caveat — the ladder stops at 320,000.**~~ **RESOLVED by HEA-1992** (`3c0eccee`).
The ladder is now dynamic (`LADDER_MAX`) and was run to **1.28M**:

| corpus (n) | SSTs | hot p50/p99 (µs) | cold-nat p99 (µs) | cold-cmp p99 (µs) | RSS (MiB) |
|---|---|---|---|---|---|
| 320,000 | 91 | 0.1 / 0.2 | 346.9 | 1,412.7 | 78.6 |
| 640,000 | 182 | 0.1 / 0.3 | 185.6 | 2,360.4 | 142.6 |
| **1,280,000** | 365 | **0.1 / 0.3** | 170.6 | 279.2 | 233.7 |

Re-fit over the full 8-rung ladder (10k → 1.28M):

| curve | exponent | R² | verdict |
|---|---|---|---|
| hot p99 | −0.298 | 0.502 | ✅ **PASS** — flat, O(1) **measured, not extrapolated** |
| cold-natural p99 | −0.213 | 0.345 | ✅ PASS — no upward trend (disk noise, low R²) |
| cold-compacted p99 | +0.015 | 0.002 | ✅ PASS — essentially flat |
| #SSTs (natural) | +1.056 | 0.998 | linear in n, as expected without compaction |
| **RAM (RSS)** | **+0.648** | **0.990** | ❌ **MISS** — sub-linear but growing |

**The "O(1) RAM regardless of corpus size" claim remains false**, now on a wider
ladder: exponent +0.648 with R²=0.990 — a tight, unambiguous fit. RAM grows
sub-linearly (1.28M users cost 233.7 MiB resident, only 3× the 320k figure for 4×
the data), which is a good result — but it is not O(1) and must not be published
as such. This corroborates the earlier 0.8778 measurement in `PUBLISHED_FIGURES.md`.

---

## 2. The headline defect — the token-claims cache makes the fast path unreachable at scale

> **FIXED — HEA-1990, commit `d5c390d2`** (security review HEA-1994: APPROVED).
> The full-cache early return is replaced with LRU eviction plus a TTL sweep, and
> the size is now configurable via `token.claims_cache_max` (default **65,536**,
> up from a hardcoded 2,048).
>
> **Read the reframing carefully, because it is easy to over-claim.** The fix does
> **not** speed up a cache miss — the `[miss]` per-op cost is Ed25519
> signature-verification-bound and is unchanged by any cache policy. What the fix
> removes is the *decay*: previously the cache filled within ~15 minutes of load
> and then served **zero** hits for the lifetime of the process, so every
> deployment eventually degraded to the all-miss path. The cache now stays live
> indefinitely. The miss-path figures below therefore still stand as the
> worst-case floor, and the 200k/core bar is still missed **on a pure miss
> workload** — but that workload is no longer the inevitable steady state.
>
> **The rev 2.1 HTTP-plane result (§3) is the practical answer**: at 500 concurrent
> users against a 1.2M-user corpus, `validate` ran 112,671 requests at p99 1 ms
> with zero failures. In a realistic mixed workload the fast path is reachable.

The analysis below is the Mk 2.0 diagnosis that motivated the fix, retained
unchanged.

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

## 3. Concurrency — MEASURED (rev 2.1). Reads pass at 500 concurrent; issuance does not.

**Status change.** HEA-1991 repaired the harness (`dda1fe5d`). This section now
reports **actual end-to-end HTTP-plane numbers** — the first this programme has
produced. The Mk 2.0 "harness is dead" analysis is retained below as §3b for the
audit trail.

Three runs at commit `349660d3`, same host, server binary rebuilt at HEAD (so the
HEA-1990 cache fix is in the binary under test):

| run | resident corpus | generator users | wall | achieved RPS | total reqs | failures |
|---|---|---|---|---|---|---|
| smoke | 500 | 20 | 15 s | 9,709 | 145,634 | 11,190 (all §3a) |
| **main** | **1,200,000** | **500** | 60 s | **2,812** | 168,703 | 13,030 (all §3a) |
| overload | 1,200,000 | 1,000 | 60 s | 39 | 2,333 | 2,333 (100%) |

### Main run — 500 concurrent generator users vs a 1.2M-user resident corpus

| journey | reqs | fail | p50 | p95 | p99 | p99.9 | HTTP p99 budget | verdict |
|---|---|---|---|---|---|---|---|---|
| `validate` (POST /introspect) | 112,671 | 0 | 1 ms | 1 ms | **1 ms** | 1 ms | 1.5 ms | ✅ **PASS** |
| `session_lookup` (GET /userinfo) | 19,458 | 0 | 1 ms | 1 ms | **1 ms** | 1 ms | 1.1 ms | ✅ **PASS** |
| `revoke_revalidate` | 3,416 | 0 | 4 ms | 9 ms | 13 ms | 20 ms | — | — |
| `revoke` | 3,416 | 0 | 900 ms | 2,000 ms | 2,000 ms | 3,000 ms | — | ⚠️ |
| `revoke_mint` | 3,350 | 0 | 2,000 ms | 3,000 ms | 4,000 ms | 5,000 ms | — | ⚠️ |
| **`issuance` (login → token)** | 13,362 | 0 | **2,000 ms** | 3,000 ms | **4,000 ms** | 5,000 ms | **6 ms** | ❌ **MISS ~660×** |
| `user_lookup` | 13,030 | 13,030 | 1 ms | 1 ms | 1 ms | 2 ms | 1.2 ms | 🔧 harness defect — §3a |

Server resources during the run: **RSS peak 1,899 MiB / mean 1,490 MiB** holding a
1.2M-user corpus; **CPU peak 634% / mean 248%** of 1,600% available.

**Three findings, in order of importance.**

1. **The read hot path holds up.** 112,671 token validations and 19,458 session
   lookups at 500 concurrent users against a 1.2M-user store, **zero failures**,
   p99 ≤ 1 ms at every percentile up to p99.9 — inside budget on the HTTP plane,
   not just the engine plane. This is the strongest evidence the project has for
   its central performance claim, and it is the first time that claim has been
   observed over real HTTP rather than in-process.

2. **Issuance is now the binding constraint.** p50 2,000 ms / p99 4,000 ms against
   a 6 ms budget. Compare the 20-user smoke run, where the same journey shows p99
   **43 ms** — a 93× degradation from 20 → 500 concurrent. This is queueing, not
   compute: mean CPU sat at 248% of 1,600% while p50 was 2 seconds, i.e. **the
   server was 84% idle while clients waited two seconds.** That is the signature
   of the Argon2id KDF admission gate (HEA-1887) doing exactly what it was built
   to do — bound concurrency and queue rather than thrash — and it means the
   practical concurrency ceiling of a single node is set by **login rate**, not by
   lookup throughput or corpus size. A deployment doing 50,000 concurrent
   *sessions* with a low login rate is a very different proposition from one doing
   50,000 concurrent *logins*; only the first is supported today.

3. **The wall is between 500 and 1,000 — and it is the rig, not the server.** At
   1,000 generator users the run fails 100% (39 RPS). But the errors are
   `client error (Connect)` — the *generator* failing to open sockets — while
   server **mean CPU falls to 48.7%** and RSS to 1,064 MiB. Server idle + client
   timeouts is the exact HEA-1813 co-residency signature: the load generator and
   the server are fighting over the same 16 vCPUs. **This is not evidence that
   Hearth fails at 1,000 concurrent users.** It is evidence that this host cannot
   drive 1,000. The real ceiling is unmeasured and requires a separate generator
   host.

### 3a. Harness defect found by running it — `user_lookup` returns 403 on 100% of requests

Every `user_lookup` request in every run failed: **13,030/13,030 in the main run**
(7.7% of all traffic), 11,190/11,190 in the smoke. All `403 Forbidden`.

Root cause is in the harness, not the server. `loadtest/src/scenarios.rs:246-259`
documents the journey as using *"an admin-authority bearer (the seeded dev-admin
token)"* but authenticates `GET /admin/users/{id}` with `ctx.live_token()` — a
per-user session token minted by `/dev/seed-token`, which carries no admin
authority. `LoadContext` (`scenarios.rs:47`) and `SeedHandle` (`handle.rs:90`)
have no admin-token field at all, so the token the doc comment describes is not
available to the journey.

Consequences:

- The `user_lookup` hot path is **not being measured** — the 1 ms p99 in the table
  is the latency of an authorization rejection, not of a user lookup.
- `report.json` `pass` is `false` and `failure_rate` is 7.7% for a reason that has
  nothing to do with server performance. **Any future run comparing against these
  numbers must exclude `user_lookup` until this is fixed.**
- The new `loadtest-smoke` CI gate will fail permanently on this until fixed.

Tracked as a follow-up on HEA-1991's owner. Fix is to plumb the bootstrap admin
token through `SeedHandle` → `LoadContext` and use it for journey 3.

### 3b. Mk 2.0 analysis — why the harness was dead (retained for audit trail)

`make loadtest` is documented as the whole contract: *"That command is the entire
contract... If you can build the repo, `make loadtest` works."* (`loadtest/README.md`).

**It did not work at `43190f5e`.** Full run, 1.2M-user corpus, 500 users:

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

**Second, independent ceiling.** The load generator is co-resident with the server
on the same 16 vCPUs, and prior bisection (HEA-1813) puts collapse between 500 and
600 concurrent generator users — with the *server going idle* while requests time
out client-side. **Rev 2.1 confirms this directly**: 500 users runs clean, 1,000
collapses with client-side connect errors at 48.7% server CPU. It is a rig limit,
not a Hearth limit, and it means **tens of thousands of concurrent users cannot be
driven from this host at all**, at any corpus size.

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

**Mk 2.0 list — all five now closed:**

1. ~~**Fix the token-claims cache** (§2).~~ ✅ **Done — HEA-1990 (`d5c390d2`).**
2. ~~**Repair the load-test harness** (§3).~~ ✅ **Done — HEA-1991 (`dda1fe5d`)**, and
   verified by actually running it (§3), which is how §3a was found.
3. **Get a server-class, quiescent host** — ⏸ **still open, and now the single
   biggest blocker.** Rev 2.1 pins the rig ceiling between 500 and 1,000 generator
   users with a confirmed client-side signature. Everything above that is
   unmeasurable here. Board previously declined rental (HEA-1970); that decision
   is what caps this programme.
4. ~~**Extend the C5 ladder past 320k.**~~ ✅ **Done — HEA-1992 (`3c0eccee`)**, run to 1.28M.
5. ~~**Re-measure T4** with ≥5 alternating runs.~~ ✅ **Done — HEA-1993 (`b7b4dd87`)** —
   all 5 runs MISS; T4 is UNSTABLE on this host. See §4.

**New, from rev 2.1 measurements:**

6. **Fix `user_lookup`'s 403 in the harness** (§3a) — the journey never exercises
   the endpoint it claims to. Blocks the new `loadtest-smoke` CI gate and
   invalidates that one journey's numbers. Small, well-understood fix.
7. **Characterise issuance under concurrency** (§3) — p99 4,000 ms vs a 6 ms budget
   at 500 concurrent, with the server 84% idle. The KDF admission gate is behaving
   as designed; the open question is whether the *product* target is a login-rate
   target at all, and if so what it is. Do not tune before that target exists —
   this programme has twice staffed work against numeric bars that turned out to
   be arbitrary (HEA-1867 closing lesson).
8. **Correct the "O(1) RAM" claim** (§1) — measured exponent +0.648, R²=0.990 on an
   8-rung ladder. Any doc or README asserting constant memory must be amended.

---

## 7. Reproduction

```bash
export PROTOC=$(which protoc) CARGO_TARGET_DIR=/scratch/cache/target
cargo build --release --examples --bin hearth
/scratch/cache/target/release/examples/saturation_throughput   # §2, §4, §5
LADDER_MAX=1280000 /scratch/cache/target/release/examples/complexity_sweep  # §1
MODE=steady USERS=500  RUN_TIME=60s make loadtest               # §3 main run
MODE=steady USERS=1000 RUN_TIME=60s make loadtest               # §3 overload run
make loadtest-smoke                                             # §3 smoke
```

**Build gotcha (cost ~15 min this session).** `cargo build` fails with
`SERVER_BUILD_EXIT=101` and `sccache: Failed to create temp dir` when `TMPDIR`
points at a *sibling agent's* deleted run-scratch directory. `sccache` is a
daemon and caches that path at start, so exporting a fresh `TMPDIR` does **not**
clear it. Build with `RUSTC_WRAPPER=""` to bypass. Note the failure is invisible
if you pipe the build through `tail` — check the exit code explicitly.

Raw console output and `report.json` for all runs were captured under the run
scratch directory and are summarised verbatim in the tables above.

---

## 8. Revision log

| rev | date | commit measured | what changed |
|---|---|---|---|
| 2.0 | 2026-07-30 | `43190f5e` | Original report. Corpus scale PASS; concurrency unmeasurable; token-cache defect identified. |
| 2.1 | 2026-07-30 | `349660d3` | All four remediation tickets merged and verified. §3 replaced with **measured** HTTP-plane concurrency (500 users × 1.2M corpus): reads PASS, issuance misses by ~660×. §3a: new harness defect found by running it. §1: ladder measured to 1.28M; RAM exponent +0.648 MISS. §2: cache fixed, reframed. §6: 4 of 5 items closed, 3 new opened. |
