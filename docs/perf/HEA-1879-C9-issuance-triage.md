# HEA-1879 · C9 — Issuance / Argon2id path: queueing vs compute

**Parent:** HEA-1867 · **Report row:** L6 (token issuance p99), L7 (user creation) ·
**Artifact:** `docs/perf/artifacts/c9-issuance-argon2.json` (schema 1) ·
**Harness:** `examples/argon2_saturation.rs` · **Owner:** SoftwareEngineer (data + fix) →
**CTO** (spec decision) · **Status:** hypothesis **CONFIRMED**; spec decision handed to CTO.

---

## 0. TL;DR

The ~7 s issuance p99 in the committed baseline (`journeys[issuance].p99_ms = 6000`,
`max_us = 8396884`) is **queueing / oversubscription, not Argon2id compute.** Confirmed on
`dev-ryzen-7840hs` by an in-process microbenchmark that decomposes the two.

Two findings, both admissible (no load generator, no swap-void):

1. **The mechanism is queueing.** Argon2id throughput saturates at the core count (~247 hashes/s)
   and does **not** rise with more concurrency (`throughput_scaling_past_cores = 1.02×`), while
   per-hash latency inflates in proportion to pool depth (`latency_growth_past_cores = 2.50×`
   over 16→64; log-log slope 0.66, R²=0.75). That is Little's Law queue delay (L = λW, λ capped),
   the exact signature of requests piling onto the unbounded `spawn_blocking` pool. Compute-bound
   work with headroom plateaus in *throughput* but does **not** inflate *per-item latency*. → the
   7 s tail is pool oversubscription, and there is **no admission control** to prevent it (confirms
   report R1 / C6's code-level finding).

2. **But the compute floor already breaches the target regardless.** One Argon2id hash with
   production params (19 MiB, t=2, p=1) costs **p50 ≈ 29 ms** this run, **≈ 12.5 ms** in the
   quietest observed run — i.e. **2.5×–6× the 5 ms L6 p99 target** even at concurrency=1 with zero
   queueing. **No password-bearing issuance can meet VISION L6's <5 ms p99 while it runs OWASP
   Argon2id inline.** This is a spec contradiction, not an implementation defect, and it is the
   CTO's call (§4).

**L6 verdict in the report table: `NOT-MEASURABLE`** — an admissible *end-to-end* issuance p99
needs the isolated generator host (C3/HEA-1871) to satisfy rule 3, and this swapping host voids any
load run under rule 5. The queue-vs-compute *decomposition* the L6 red-flag demanded is, however,
measured and settled here.

---

## 1. Method

Pure in-process compute microbenchmark (`examples/argon2_saturation.rs`). It hashes with
`CredentialConfig::default()` — the production Argon2id parameters — via `tokio::task::spawn_blocking`,
exactly as the login / password-grant path does (`src/identity/engine/mod.rs:5959`
`verify_password_with_pepper`, wrapped in `spawn_blocking` at the HTTP layer). No HTTP stack and no
load generator run, so **rule 3 generator-attribution risk does not apply** — the only actor doing
work is Hearth's own KDF.

- **Concurrency ladder:** 1, 2, 4, 8, 16, 32, 64 (below, at, and past the 16-thread core count).
- **Denoising:** each rung run 3× on this shared/swapping host; the quietest trial (fewest swap-in
  pages) is kept. Every rung records swap-in/out + MemAvailable deltas; a rung with >512 swap-in
  pages (2 MiB — three orders below the hundreds of MiB each rung churns) is marked `void` per
  rule 5. This run: **0 rungs void**, max 252 swap-in pages, `void_due_to_swap=false` overall.
- **Host (rule 1):** `dev-ryzen-7840hs`, AMD Ryzen 7 7840HS, 16 threads, governor `powersave`,
  ~17 GiB available. Reproduce:
  `cargo run --release --example argon2_saturation -- $(git rev-parse --short HEAD) $(date -u +%Y-%m-%dT%H:%M:%SZ)`

## 2. Results (git_sha `8c94c9bb`, host `dev-ryzen-7840hs`)

| Concurrency | p50 (ms) | p99 (ms) | max (ms) | throughput (hash/s) |
|---:|---:|---:|---:|---:|
| 1  | 29.2 | 36.1  | 36.1  | 34.5  |
| 2  | 27.3 | 34.1  | 34.1  | 71.4  |
| 4  | 23.1 | 36.2  | 38.0  | 161.6 |
| 8  | 39.1 | 52.3  | 60.2  | 186.9 |
| 16 | 48.3 | 127.8 | 223.7 | 241.3 |
| 32 | 48.4 | 511.5 | 654.7 | 247.5 |
| 64 | 120.5| 953.8 | 1232.3| 246.8 |

Read the last two columns together: **from C=16 on, throughput is pinned at ~247 hash/s** (the box
is doing all the Argon2 work it can) **while p99 climbs 128 → 512 → 954 ms.** Every extra concurrent
login past the core count buys **zero** additional throughput and adds **pure queue latency**.
Extrapolating the linear queue growth to the ~500 concurrent users behind the baseline run puts the
tail squarely in the multi-second range the baseline saw — **fully explained without invoking swap
or "Argon2id is slow."**

## 3. The fix (engineer-owned) — bounded admission control on the KDF pool

The defect is that the password-hashing work runs on tokio's default **512-thread** blocking pool
with **no bound**, so offered concurrency translates 1:1 into oversubscription of 16 cores (and,
under memory pressure, into swap). Remediation R1 in the report:

1. **Bound the KDF concurrency** with an async semaphore acquired *before* `spawn_blocking` of any
   Argon2id operation (verify + hash), permits ≈ core count. Past the bound, requests queue
   **briefly and boundedly** rather than all thrashing at once — this converts a 7 s thrash into a
   fast, predictable, short queue and eliminates the swap-pressure failure mode (64 × 19 MiB ≈
   1.2 GiB resident collapses to permits × 19 MiB).
2. **Shed, don't queue unboundedly:** a bounded wait + fast rejection (`503`/`Retry-After`) when the
   queue is full, so overload degrades honestly (also closes R1's Tower `LoadShed`/`ConcurrencyLimit`
   gap end-to-end).
3. **Instrument it:** export in-flight gauge + queue-wait histogram + KDF compute-time histogram so
   the queue is observable in production (currently there is zero telemetry on this path).

**Why this is not shipped in this heartbeat:** (a) the calibrated `max_in_flight` **default needs
C7's (HEA-1875) real saturation numbers** — R1 says so explicitly, and C7 is `todo`; shipping an
arbitrary bound now would be guesswork on the auth hot path. (b) It changes the **auth path**, so it
must go through **SecurityAuditor** before merge (a too-tight bound is a self-inflicted DoS; a
too-loose one doesn't help). Tracked as the follow-up in §5; the measurement here is what unblocks
choosing the bound.

## 4. Spec decision — handed to the CTO (do not amend VISION here)

Finding 2 forces a choice VISION §7.1 currently ducks. **L6 "Token issuance (full OAuth2 flow),
p99 < 5 ms" is not one operation** — it conflates two paths with different physics:

- **Token-minting issuance** (authorization_code exchange, refresh, client_credentials): Ed25519
  sign + claim assembly, **no Argon2id**. <5 ms p99 is plausible here (unmeasured — needs C7/C4).
- **Interactive password issuance** (password/login grant): runs **one Argon2id verify inline**.
  Floored at the compute cost — **≥12.5 ms best-observed, ≈29 ms typical on this host** — so <5 ms
  is **physically unreachable** without weakening the KDF below OWASP, which Security will (rightly)
  refuse.

**Options for the board/CTO (engineer recommends A):**

- **A. Split the L6 row.** Keep <5 ms p99 for the token-minting path; give the password-grant path a
  separate, honest target (e.g. p50 < 50 ms / p99 < 100 ms, matching the L7 "user creation with
  hashing" budget, which already acknowledges hashing cost). *Recommended:* it states the real cost
  to integrators and keeps the fast-path target meaningful.
- **B. Restate L6 as the token-minting path only** and document that interactive login inherits the
  L7 hashing budget. Less explicit than A but a one-line VISION change.
- **C. Keep a single <5 ms L6 and grade it MISS for the password path.** Technically honest but
  actively misleading — it implies the KDF is a bug to be fixed rather than the security control it is.

Either way, the **queueing fix (§3) is orthogonal and still required** — it is what turns the
password path's *tail* from seconds back down to ~(compute floor + short bounded queue), regardless
of which target L6 carries.

## 5. Disposition

- **Data:** settled and committed (artifact + this doc + harness). Hypothesis **confirmed: queueing.**
- **Spec decision:** handed to CTO (§4). Engineer must **not** amend VISION §7.1.
- **Fix:** bounded KDF admission control (§3) — **shipped** under HEA-1887 (§6 below);
  **gated before merge** on C7 (HEA-1875) for the calibrated default and on **SecurityAuditor**
  review (auth-path change).

## 6. Fix delta — bounded KDF admission gate (HEA-1887 / R1)

R1 (§3) shipped: an async semaphore acquired **before** `spawn_blocking` for every Argon2id op,
`permits = core count` by default, bounded queue-wait then `503`/`Retry-After` shed, plus the
`hearth_kdf_*` telemetry the tail was invisible for. Primitive: `src/identity/kdf_gate.rs`; wired
into the web login handlers; config `security.password.kdf`.

**Re-run through the gate** (`examples/argon2_gated_saturation.rs`, `permits=16`,
`max_queue_wait=250ms`, host `dev-ryzen-7840hs`, governor `powersave`, **0 rungs void** — max 2
swap-in pages, so admissible under rule 5). The ladder here is *offered* concurrency — the number of
hash **requests** fired at once — vs the ungated §2 ladder of always-running workers:

| Offered | admitted p99 (ms) — **gated** | §2 p99 (ms) — **ungated** | shed |
|---:|---:|---:|---:|
| 1  | 19.8  | 36.1  | 0 |
| 8  | 32.1  | 52.3  | 0 |
| 16 | 65.4  | 127.8 | 0 |
| 32 | 112.5 | 511.5 | 0 |
| 64 | **212.9** | **953.8** | 0 |

**The p99 tail at C=64 collapses 953.8 → 212.9 ms (~4.5×)** and now tracks `compute_floor (≈20 ms) +
a bounded queue of ⌈offered/permits⌉ waves` instead of inflating with depth — exactly the predicted
behaviour. Memory follows suit: in-flight Argon2 allocations are capped at `permits × 19 MiB`
(≈304 MiB) rather than `offered × 19 MiB` (≈1.2 GiB at C=64), removing the swap-pressure mode.

`shed = 0` across the ladder because 250 ms absorbs the ~4-wave queue at C=64 (`4 × ~20 ms < 250 ms`);
**shedding engages when `offered × compute > permits × max_queue_wait`** — the fast-reject path is
proved deterministically by `identity::kdf_gate::offered_concurrency_past_bound_is_shed_not_queued`
(saturated 2-permit gate, 20 ms budget → probe sheds in <150 ms). The absolute millisecond values
remain host-relative (this box swaps); the **shape** — bounded tail + no throughput loss below the
bound — is the citable result, and an isolated host (C3/HEA-1871) would sharpen the constants.
