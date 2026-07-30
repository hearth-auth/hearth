# HEA-1875 · C7 — Saturation-throughput benches for VISION §7.2

**Parent:** HEA-1867 · **Plan:** `docs/perf/HEA-1867-PLAN.md` (rev 3) · **Phase:** 2 (HTTP-independent)
**Harness:** `examples/saturation_throughput.rs` · **Raw:** `docs/perf/artifacts/c7-saturation-raw.json`
**Status:** DONE — measured, graded, committed.

## Hardware & method

| | |
|---|---|
| **Host** | 16 logical cores (`std::thread::available_parallelism`), Linux |
| **Storage** | `StorageConfig::production` on a temp dir under `/scratch`, `SyncMode::EveryWrite`, hot-tier capacity 40 000, production `promote_sample_rate` |
| **Driver** | In-process — the operation trait methods are called directly from N `std::thread`s. **No HTTP, no axum, no tokio, no load generator in the loop.** |
| **Window** | 2 s per (operation, thread-count) cell; threads start on a barrier and count completed ops until a per-thread deadline. Aggregate ops/s = Σ ops ÷ wall window. |
| **Corpus** | 1 000 users, 2 048 warm sessions + tokens (exactly saturates the 2048-slot token-claims cache), 512 disjoint miss-token sessions. |

Every figure below is **engine-level cost on the host named above**. The harness
loop overhead (index math, batched `Instant::now`) is *included* in the per-op
cost, so each number is a conservative upper bound on cost / lower bound on
throughput. Nothing here is generator-ceilinged: there is no generator.

### Why in-process (the HTTP split is NOT-MEASURABLE)

VISION §7.2's budgets are "engine target + a 1 ms loopback envelope." That
envelope is too coarse to validate a 500 µs claim, and the HTTP path that would
let us measure it is **NOT-MEASURABLE** in this environment: HEA-1871 (C3)
bisected the throughput cliff to the server side, and HEA-1876 (C8) could not
seed the corpus without the generator/server co-residency ceiling voiding the
run. Per the binding grading rule — *nothing is graded PASS on a run whose
ceiling attribution was the generator* — the honest deliverable is the **engine
floor**, measured with the generator removed entirely. The HTTP/axum/tokio delta
on top of these numbers is explicitly **NOT-MEASURABLE** here and is recorded as
such, not folded into a PASS.

## Results (16-core host)

| op [state] | 1T ops/s/core | 16T agg ops/s | scaling exp (R²) | 1→16T eff | ≥200k/core? | verdict |
|---|---:|---:|---:|---:|:---:|---|
| `validate_token` **hot** | 574 363 | 7 733 497 | +0.933 (0.999) | 0.84 | **MET** | **SCALES (near-linear)** |
| `validate_token` **miss** | 13 169 | 110 705 | +0.777 (0.974) | 0.53 | MISS | PARTIAL |
| `session_lookup` **hot** | 7 456 390 | 68 223 347 | +0.793 (0.971) | 0.57 | **MET** | PARTIAL |
| `session_lookup` **miss** | 2 109 880 | 6 848 931 | +0.422 (0.992) | 0.20 | **MET** | CONTENDS |
| `user_lookup` **hot** | 1 635 587 | 9 605 276 | +0.651 (0.985) | 0.37 | **MET** | CONTENDS |
| `user_lookup` **miss** | 2 400 594 | 6 214 900 | +0.339 (0.969) | 0.16 | **MET** | CONTENDS |
| `permission_check` | 14 799 198 | 3 126 679 | **−0.549** (0.918) | 0.01 | **MET** | **CONTENDS (negative)** |
| `session_create` **write** | 31 | 67 | +0.197 (0.551) | 0.14 | MISS | CONTENDS (fsync-bound) |

*Scaling exponent = slope of `log(aggregate ops/s)` on `log(threads)`: 1.0 = perfect
linear scaling, 0.0 = fully serialized, negative = actively degrades under contention.*

## Findings

### 1. `validate_token` — the hot path clears the bar and scales (headline)

The production hot path — token-claims-cache **hit** + every semantic check +
the session-validity `get_session` — runs at **574 k ops/s/core (~1.74 µs/op)**
single-threaded and scales **near-linearly to 7.73 M ops/s across 16 cores**
(exponent +0.933, 84 % efficiency). It clears the 200 k ops/s/core VISION §7.2
bar by **2.9×** and its per-op cost is **~290× under** the 500 µs user-lookup
budget. This is the one operation graded a clean **PASS**: fast *and* scalable.

### 2. `validate_token` miss = the Ed25519 verify floor (~76 µs/op)

A claims-cache **miss** (full Ed25519 verify + `serde_json` parse) costs
**76 µs/op**, so the cache buys a **~44× speedup** on the hot path. The miss path
does **not** meet 200 k/core (13 k/core) and scales only partially (eff 0.53). It
never gates production steady state — a warm token hits the cache — but it sets
the cold-start / cache-thrash ceiling, and corroborates the C9 (HEA-1879)
finding that the crypto path, not storage, dominates uncached token work.

### 3. Reads clear 200 k/core everywhere, but "hot ≠ contention-free"

Every lookup clears 200 k ops/s/core single-threaded (session hot 7.5 M, user
hot 1.6 M, both misses ~2–2.4 M). But **per-core throughput falls as cores are
added** — even on hot hits. The cause is the **sampled promote path**: a hot-tier
hit still takes a promote write-lock 1-in-`promote_sample_rate` times (HEA-1775
bounds but does not remove this), and that shared write plus memory-bandwidth
pressure caps scaling well below linear (session hot eff 0.57, user hot 0.37).
Misses scale worst (eff 0.16–0.20) — they fall through to the shared SST-reader
structures. **Verdict: reads are fast enough per-core but do not scale
linearly; aggregate read throughput is bandwidth/promote-lock bound, not
core-bound.**

### 4. `permission_check` scales *negatively* — the RBAC resolution mutex

`RbacEngine::resolve_permissions` is blistering single-threaded (**14.8 M
ops/s**, 68 ns — the HEA-1770 decision cache doing its job) but aggregate
throughput **drops to 3.1 M at 16 threads** (exponent **−0.549**). Root cause:
the resolution decision cache is a single `Mutex<ResolutionCache>`
(`src/rbac/engine.rs:110`); every resolve takes that global lock, so adding
cores adds pure contention and cache-line ping-pong. This is **off the validate
hot path** (permissions are baked into the JWT at issue time), so it only bites
during concurrent **issuance/refresh** — and there Argon2id is the binding
constraint anyway (C9). But it is a genuine, quantified contention point: at high
concurrent-issuance load the RBAC cache mutex, not compute, caps this call. →
**follow-up candidate: shard the resolution cache** (per-realm or striped),
mirroring the sharded permission cache already used elsewhere.

### 5. `session_create` is fsync/durability-serialized (host-specific absolute)

The write path is **~31 ops/s/core (~32 ms/op)** and does not scale — aggregate
barely moves 31→67 ops/s from 1→16 threads while wall time balloons (16T needs
15 s for 1 024 ops). Two serialization points compound: the **WAL `fsync`
(`SyncMode::EveryWrite`)** and the **per-realm audit hash-chain lock** that a
session-create audit event takes. **The 32 ms absolute is dominated by this
host's `/scratch` fsync latency and must be re-measured on production-representative
storage** — but the *scaling shape* is hardware-independent and robust: writes
are durability-serialized and gain nothing from more cores. Session creation is
firmly **off the hot path**; this is a throughput-planning input, not a hot-path
regression.

## Answers to the C7 exit questions

- **Per-core throughput & scaling curve:** delivered per operation (table + raw JSON), each with a fitted exponent and R².
- **Does the engine hit 200 k ops/s/core?** **Yes for every read and for the validate hot path** (validate hot 574 k, session hot 7.5 M, user hot 1.6 M, all misses ≥2 M). **No** for the validate **miss** (Ed25519-bound, 13 k) or `session_create` (fsync-bound, 31) — both off the steady-state hot path.
- **Does it scale or contend?** **`validate_token` hot scales near-linearly (+0.93).** Reads clear the per-core bar but **sub-scale** under the sampled-promote write-lock and memory bandwidth. **`permission_check` actively degrades** (−0.55) on the RBAC resolution mutex. **Writes are serialized** on WAL fsync + audit chain lock.
- **Honest engine/HTTP split:** the numbers above are the **engine floor**. The HTTP/axum/tokio envelope on top is **NOT-MEASURABLE** in this environment (HEA-1871 C3 / HEA-1876 C8) and is recorded as such — it is *not* folded into any PASS.

## Reproduce

```bash
PROTOC=$(which protoc) cargo run --release --example saturation_throughput
# (if sccache errors on a stale TMPDIR: prefix with RUSTC_WRAPPER="")
```
