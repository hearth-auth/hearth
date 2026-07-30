# HEA-1956 · T4 re-measurement at HEAD — `W` is 1, throughput is 33,724 ops/s, T4 is still MISS by 1.48×

**Date:** 2026-07-29
**Branch:** `feature/perf-updates-7-28-26`
**HEAD at measurement:** `c709fa58` (HEA-1955 looping leader) + the uncommitted
duplicate-`UserCreated` fix in `src/protocol/http/admin.rs` (does not touch the session
write path; committed in this issue's commit).
**Driver:** `examples/saturation_throughput.rs`, unmodified — same HEA-1949 ladder.
**Artifacts:** `docs/perf/artifacts/c7-saturation-post-hea1955-raw.json` (machine),
`docs/perf/artifacts/c7-saturation-post-hea1955-console.txt` (human).
**Host:** `dev-ryzen-7840hs`, 16 logical cores, otherwise idle (no concurrent build or test
run — `make check` was deliberately deferred until after the run).
**Device F:** 515.8 fsyncs/s (200 sequential `sync_all`, same storage path).
**W:** **1.000** at T=1.

---

## Outcome first

| | value |
|---|---|
| Peak measured | **33,724 ops/s at T=256** |
| T4 target | 50,000 ops/s |
| **T4 verdict** | **MISS — 1.48× short** |
| Gap in report 2.0 | 316× |
| Gap now | **1.48×** |
| `W` (WAL fsyncs per durable write) | **1.000** — the theoretical floor |
| Scaling exponent | **+0.851** (r² = 0.986) |

**T4 does not clear 50,000 ops/s.** The issue asked for a straight answer if it did not, so:
the residual factor is **1.48×**, and it is entirely **coalescing efficiency at the top of the
ladder** — 25.5% at T=256 against 36–44% across T=16…128.

---

## 1. Measured ladder (vs. the post-HEA-1948 baseline)

Baseline column is the `21ec5824` run (`c7-saturation-post-hea1948-raw.json`, F=533.0, W=2.0).

| T | ops/s (post-1948) | **ops/s (HEAD)** | gain | fsyncs/write | batch | ceiling `T×F/W` | coalesce eff | (was) | p99 (ms) | (was) |
|--:|-----:|------:|-----:|--------:|-------:|--------:|------:|------:|------:|------:|
|   1 |    245 |   **424** | 1.73× | 1.0000 |   1.00 |     516 | 82.2% | 92.1% |  5.2 |  6.0 |
|   4 |    513 |   **756** | 1.47× | 0.6526 |   1.53 |   2,063 | 36.6% | 48.1% |  6.6 | 10.1 |
|  16 |  1,984 | **3,645** | 1.84× | 0.1336 |   7.48 |   8,253 | 44.2% | 46.5% |  6.7 | 10.9 |
|  64 |  7,286 | **12,974** | 1.78× | 0.0326 |  30.67 |  33,013 | 39.3% | 42.7% |  8.1 | 12.1 |
| 128 | 12,699 | **24,083** | 1.90× | 0.0154 |  64.95 |  66,026 | 36.5% | 37.2% |  9.4 | 14.3 |
| 256 | 15,841 | **33,724** | **2.13×** | 0.0091 | 109.89 | 132,053 | **25.5%** | 23.2% | **11.9** | 23.0 |

Cumulative against the report-2.0 baseline (323 ops/s at T=256): **104×**.

---

## 2. HEA-1954 delivered. HEA-1955 did not.

This is the part of the run that matters, and it contradicts the predictions in
`HEA-1945-T4-session-create-triage.md`. Decomposing the 2.13× at T=256:

```
total gain        2.129×
  = ceiling gain  1.935×   (W 2→1, partly offset by a 3% slower device: 533.0 → 515.8 F)
  × efficiency    1.101×   (23.2% → 25.5%)
```

**HEA-1954 (`8620b0e7`) is confirmed.** `fsyncs_per_write` at T=1 is exactly **1.000**. One
WAL record, one fsync, per durable `create_session`. That is the floor — no further `W`
reduction is available without removing a durability guarantee. Predicted ~2×, delivered
1.935× on the ceiling. **Prediction met.**

**HEA-1955 (`c709fa58`) did not do what it was predicted to do.** It was staffed to recover
the coalescing-efficiency decay from 23% back toward the 92% seen at T=1. Measured recovery:
**23.2% → 25.5%** at T=256, a 1.10× improvement where a ~4× was modelled. The decay is still
there and still has the same shape:

```
eff:  82.2% (T=1) → 36.6% (T=4) → 44.2% (T=16) → 39.3% (T=64) → 36.5% (T=128) → 25.5% (T=256)
```

Removing the inter-fsync thread-wakeup gap was **not** the dominant term in the decay. What
HEA-1955 *did* buy is latency: p99 at T=256 halved, 23.0 → 11.9 ms, and improved at every
rung of the ladder. That is a real and shippable result — it is simply not the result the
issue predicted, and it does not close T4.

Note also that efficiency at **T=1 fell** (92.1% → 82.2%) and at **T=4 fell** (48.1% →
36.6%). At W=1 there is no second fsync for a single writer to amortise, so T=1 is a
different regime and the two numbers are not strictly comparable; but there is no evidence
here that the looping leader helps at low concurrency, and weak evidence it costs a little.

---

## 3. What remains for T4 — one factor, quantified

To reach 50,000 ops/s at T=256 on this device (F=515.8, W=1) the engine needs coalescing
efficiency of **37.9%**. It already sustains **36.5% at T=128 and 39.3% at T=64.** The
requirement is not a new capability; it is *holding the efficiency the engine already
demonstrates* out to T=256 instead of decaying to 25.5%.

Sensitivity:

| if efficiency at T=256 were… | throughput | T4 |
|---|---:|---|
| 25.5% (measured) | 33,724 | MISS 1.48× |
| 36.5% (its own T=128 value) | 48,167 | MISS 1.04× |
| 37.9% | 50,000 | PASS (exactly) |
| 44.2% (its own T=16 value) | 58,367 | PASS 1.17× |

So even a *flat* efficiency curve lands just under target, and a modest improvement over
flat clears it. The remaining work is the batch-window / leader-handoff discipline at very
high queue depth — a tuning problem inside group commit, with no durability implication.

**It is not a lock.** The pre-HEA-1948 signature (batch size pinned regardless of T) is
gone for good: batch size grows monotonically 1.00 → 109.89 across the ladder. Nothing is
serialized.

### Headroom note for the board (extrapolation, not a measurement)

`dev-ryzen-7840hs` is a laptop NVMe at **515.8 fsyncs/s**. Server-class NVMe with
power-loss-protected write cache is routinely 10–100× that. Because `W` is now 1 and the
ceiling is `T × F / W`, T4 throughput is *linear in device fsync rate* at fixed efficiency.
At the measured 25.5% efficiency, T4 clears 50,000 ops/s at **F ≈ 765 fsyncs/s** — a bar
essentially any datacenter SSD clears. This is labelled an extrapolation and is **not**
offered as a PASS; the graded number stays 33,724.

---

## 4. Durability is intact

`SyncMode::Async` was not enabled, not defaulted, and is not required. Every one of the
33,724 ops/s is a write that was `fsync`'d before acknowledgement and survives `kill -9`.
The 104× cumulative improvement over report 2.0 was bought entirely with lock placement and
write merging. The report-2.0 claim that closing T4 "requires an async-durability mode or
parallel WAL writers" is **falsified** and is corrected in PERFORMANCE_REPORT 2.1.

---

## 5. Disposition

- T4: **MISS, 1.48×** — regraded from MISS 316× in report 2.0.
- HEA-1954: delivered as predicted. Closeable.
- HEA-1955: merged, latency win real, **predicted throughput effect not delivered.** Should
  not be closed as "as predicted." The residual coalescing decay needs a fresh child with
  this measurement as its baseline, not HEA-1955's prediction.
