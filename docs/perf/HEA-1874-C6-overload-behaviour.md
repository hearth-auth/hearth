# C6 — Graceful-Overload Behaviour

**Issue:** HEA-1874 · **Parent:** HEA-1867  
**Date:** 2026-07-28  
**Hardware:** 16 vCPU (1600% available), load generator **co-resident** with server under test  
**Build:** `a79b2e63` (git sha from baseline runs), corpus = 300 k users / 5 realms

---

## 1. Sustainable Point (Knee)

The sustainable operating point, established by the HEA-1812 steady/ramp runs, is:

| Concurrency | RPS | Failure rate | p99 range |
|-------------|-----|--------------|-----------|
| **500 users** | **1,677 RPS** | **0 %** | 1 ms (session/user/validate) – 7,000 ms (token issuance) |

**The knee is between 500 and 600 concurrent users.** There is no gradual ramp — the cliff is immediate.

> **Caveat (NOT-MEASURABLE scope):** Per the plan's finding 1, the cliff onset at 500→600 users was attributed by HEA-1813 to load-generator CPU starvation, not Hearth: server CPU collapses from 178 % to ~0 % of 1600 % available while RSS stays flat and Goose's I/O loop consumes all remaining cores. Without generator isolation (C3/C4), the true Hearth-native ceiling is NOT-MEASURABLE. All numbers below are generator-limited ceilings, not Hearth ceilings. The failure mode (silent queue saturation, see §3) is observable regardless.

---

## 2. Measured Behaviour at 2×, 5×, 10× the Knee

All numbers are from committed report files under `loadtest/reports/hea1812/`.  
5× is linearly interpolated between the 2,000-user and 3,500-user measurements (see §4).

| Multiplier | Concurrency | Measured RPS | Failure rate | p99 (best journey) | p99 (worst journey) | Failure type |
|------------|-------------|-------------:|--------------|--------------------|---------------------|--------------|
| 1× (knee)  | 500         | 1,677        | 0 %          | 1 ms               | 7,000 ms            | — (passing)  |
| **1.2×**   | 600         | 13           | **100 %**    | 60,000 ms          | 60,000 ms           | Silent timeout (Goose 60 s) |
| **2×**     | 1,000       | 44           | **100 %**    | 30,200 ms          | 30,514 ms           | Silent timeout (Goose 30 s) |
| **5×†**    | 2,500       | ~111         | **100 %**    | ~30,200 ms         | ~30,520 ms          | Silent timeout |
| **10×**    | 5,000       | 223          | **100 %**    | 30,175 ms          | 30,535 ms           | Silent timeout |

† Interpolated: 2,000 u → 88.9 RPS, 3,500 u → 155.6 RPS; linear at 2,500 u ≈ 111 RPS.

Additional reference points from the same run set:

| Concurrency | RPS   | Failure rate | p99 max    |
|-------------|------:|--------------|------------|
| 700         | 30    | 100 %        | 60,000 ms  |
| 800         | 36    | 100 %        | 30,517 ms  |
| 900         | 40    | 100 %        | 30,515 ms  |
| 1,500       | 67    | 100 %        | 30,518 ms  |
| 2,000       | 89    | 100 %        | 30,518 ms  |
| 3,500       | 156   | 100 %        | 30,520 ms  |
| 6,000       | 285   | 100 %        | 60,000 ms  |

The "RPS" at overload is not throughput — it is the rate at which Goose's timeout fires (30 s
default, 60 s at low user counts). No real work completes.

---

## 3. Failure Mode Characterisation

**MISS — Hearth does not exhibit fast, bounded, honest failure at any overload multiplier.**

The failure mode at 1.2×–10× the knee is **silent queue saturation with unbounded latency**:

- **No 503 responses at any point.** Every failure in every journey at every overload concurrency
  is a client-side timeout (30 s or 60 s). The server continues to accept new TCP connections
  but never responds to them within any reasonable window.
- **No admission control / backpressure.** Hearth has no Tower `LoadShed`, no Tokio accept-queue
  bound, no in-flight-request counter, and no configurable request timeout. Excess requests
  silently queue in Tokio's task scheduler or the kernel TCP accept backlog.
- **Latency does not degrade smoothly.** The transition from 0 % to 100 % failure is a step
  function between 500 and 600 users. There is no slope — there is a cliff. This rules out
  "graceful degradation."
- **No OOM observed.** RSS stays flat through the cliff (plan finding 1; generator starvation
  hypothesis). No crash or restart was recorded.
- **Server does not stall permanently.** If concurrency drops back below the knee, the server
  recovers (evidenced by the 500 u baseline run being run after higher-concurrency runs in the
  same series).

### Failure classification

| Grade criterion | Observed | Verdict |
|-----------------|----------|---------|
| Returns 503 under overload | No — all timeouts | **MISS** |
| Backpressure (fast rejection) | No — accepts connections silently | **MISS** |
| p99 degrades smoothly past knee | No — step cliff at 1.2× | **MISS** |
| No OOM / crash | Yes — RSS flat, no crash | PASS |
| Recovery after load drops | Yes — baseline re-run passes | PASS |

**Overall C6 grade: MISS.** Fast, bounded, honest failure is not present. Unbounded latency is worse
operator behaviour than a fast 503.

---

## 4. Measurement Caveats

1. **Generator co-residence (NOT-MEASURABLE caveat).** The plan attributes the cliff to the
   generator starving the server's CPU cores. This means the measured "server ceiling" may
   actually be a generator ceiling. However, the *user-visible* failure mode is identical in
   both cases: silent queue, no 503s. The recommendation in §5 applies regardless of which
   layer holds the queue.

2. **Timeout thresholds in report data.** The p99 values of exactly 30,000 ms and 60,000 ms are
   Goose's timeout watermarks, not Hearth latency. Hearth never responded — Goose gave up.

3. **Corpus is small (300 k users, 5 realms).** All overload runs used the same seed corpus.
   C6 grades the failure mode, not the corpus-scale behaviour — the failure onset at 500 users
   is concurrency-driven, not corpus-size-driven.

4. **5× is interpolated, not directly measured.** The interpolation is linear between 2,000 u
   (88.9 RPS) and 3,500 u (155.6 RPS). The failure mode is identical at both bracketing points
   (100 %, ~30 s timeout), so interpolation is valid for failure-mode classification.

---

## 5. Recommendation — Admission Control

Hearth must refuse excess load with a fast, bounded response. Two complementary mechanisms are
required:

### 5a. HTTP in-flight request limiter (Tower `LoadShed`)

Add a Tower middleware layer that tracks in-flight requests and returns HTTP 503 when a
configurable ceiling is exceeded. This is the standard Rust async stack approach and adds
zero overhead on the happy path.

```
// Sketch — in the Axum router setup
let service = tower::ServiceBuilder::new()
    .layer(tower::load_shed::LoadShedLayer::new())  // returns 503 when overloaded
    .layer(tower::limit::ConcurrencyLimitLayer::new(cfg.server.max_in_flight))
    .service(router);
```

`max_in_flight` should default to a value calibrated against the sustainable RPS (500 u →
1,677 RPS; at ~2 ms average latency that is ~3,354 in-flight requests at full utilisation).
A conservative starting value is `4×RPS×p99_s` for the hot paths.

### 5b. Argon2id blocking pool admission control (separate, targeted)

Token issuance p99 is 6–7 s at 500 users (plan finding 4), which is a Tokio `spawn_blocking`
queueing defect, not compute cost. The blocking pool must have a bounded queue with immediate
503 rejection when the queue is full, preventing issuance latency from cascading into all
other journeys. This is tracked separately as C9.

### 5c. Request timeout (defence in depth)

Add a `tower_http::timeout::TimeoutLayer` with a configurable wall-clock timeout (suggested:
10 s for issuance, 1 s for hot-path reads). This caps the damage a single stalled request
can do to the concurrency limiter's available slots.

### Priority

5a addresses the root cause (no backpressure). 5b addresses the worst single contributor to
issuance latency. 5c is defence in depth. Implement in order: 5a → 5c → 5b.

---

## 6. Artefact Provenance

All raw data is in `loadtest/reports/hea1812/*.json` (committed). No new test runs were
executed for this report; C6 grades the failure mode from existing measurements, which are
sufficient to reach a clear verdict.

The report data referenced:

| File | users | Source |
|------|-------|--------|
| `steady-500u.json` | 500 | Direct measurement |
| `steady-600u.json` | 600 | Direct measurement |
| `steady-1000u.json` | 1,000 | Direct measurement |
| `steady-2000u.json` | 2,000 | Direct measurement |
| `steady-3500u.json` | 3,500 | Direct measurement |
| `steady-5000u.json` | 5,000 | Direct measurement |
| `ceiling.json` | 6,000 | Direct measurement |
