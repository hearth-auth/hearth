# Hearth — Published Performance Figures

**Status:** canonical. **Issue:** HEA-1967 (parent HEA-1867). **Date:** 2026-07-29.
**Verification sweep run at:** `1b6b7745`, branch `feature/perf-updates-7-28-26`.

This is the single citable source for every performance number Hearth is willing to
publish. **Nothing goes into a customer-facing document that is not in this table.**
If a figure is not here, it is not cleared for publication.

Every row carries: the number, the **measurement plane**, the host, the durability
posture (for write figures), and the artifact + commit SHA it came from.

---

## 0. How to read this document

### 0.1 Measurement plane — read this before quoting any number

Two planes are reported and they are **not interchangeable**:

| Plane | What it measures | What it excludes |
|-------|------------------|------------------|
| **Engine** | A direct in-process call into `EmbeddedIdentityEngine` / the storage engine. | HTTP parsing, TCP, the tower/axum stack, connection handling, TLS. |
| **HTTP** | A real request over a loopback TCP socket to the running server. | TLS, network RTT, connection establishment (keep-alive reused), any proxy/LB. |

**Every competitor figure we compare against is end-to-end HTTP.** An engine figure
placed next to a competitor's HTTP figure is not a comparison — it is a category
error. This has already been recorded as a blocker on the competitive analysis
(`docs/perf/HEA-1867-COMPETITIVE-COMPARISON.md`).

### 0.2 The published number is the conservative one

Where the HEA-1967 re-run at HEAD measured **better** than report 2.1a, the
**2.1a figure is what we publish**. We publish the number we are certain we beat,
not our best observed run. The HEAD measurement is shown alongside so the margin
is visible, but it is not the claim.

Where the re-run measured **worse**, or failed to reproduce, that is called out
explicitly in §4 and the figure is either withdrawn or re-based downward.

### 0.3 Host

All figures on a single host, `dev-ryzen-7840hs`:

| | |
|---|---|
| CPU | AMD Ryzen 7 7840HS w/ Radeon 780M — **mobile/laptop part** |
| Topology | 8 physical cores / 16 threads (SMT on) |
| Clocks | min 419 MHz · max 5137 MHz · governor `powersave` |
| RAM | 54 GiB |
| Disk | WD_BLACK SN850X 2 TB NVMe (`/home`); `/scratch` is tmpfs |
| OS | NixOS 26.11 (Zokor), Linux 7.0.10 |
| Toolchain | rustc 1.97.0 |
| Device fsync rate | 515.8–541.6 fsyncs/s (measured per run, 200 sequential `sync_all`) |

**This is a laptop on a `powersave` governor, not an isolated server-class
benchmark host.** Two consequences, both material:

1. **It is a floor, not a ceiling.** A server part with a performance governor and
   no thermal ceiling should do better. Our figures understate a production
   deployment.
2. **It was not quiescent during this sweep.** See §4.1 — this measurably corrupted
   the HTTP-plane re-run and is the single biggest caveat in this document.

### 0.4 Durability posture (applies to every write figure)

`fsync`-before-ack is **in effect and was never relaxed** for any figure here.
`fdatasync` for WAL appends, full `fsync` retained for WAL rotation. Group commit
is on. The key evidence is `W`, WAL fsyncs per durable write:

> **`W = 1.000000` at T=1 in both HEA-1967 samples** — one fsync per durable write,
> the theoretical floor. No write is acknowledged before it is on stable storage.

`SyncMode::Async` was evaluated as a default and **rejected**. No figure in this
document depends on relaxed durability.

---

## 1. Latency figures

| ID | Operation | **Plane** | p50 | p99 | Concurrency | Host | Artifact · SHA | Reproduced at HEAD? |
|----|-----------|-----------|-----|-----|-------------|------|----------------|---------------------|
| **L1** | `validate_token` (hot tier) | **engine** | **1.31 µs** | — | T=1 | dev-ryzen-7840hs | `c7-saturation-v2-raw.json` · `981516f1` | ✅ **exceeded** — HEAD measured 0.779–0.795 µs (1.65–1.69× faster), 2.0% spread across 2 samples |
| **L1-H** | `validate_token` + user fetch → `GET /userinfo` | **HTTP** | **50.1 µs** | 153.7 µs | T=1 | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ⚠️ **not reproduced** — see §4.1 |
| **L2** | Session lookup (hot tier) | **engine** | **0.118 µs** | — | T=1 | dev-ryzen-7840hs | `c7-saturation-v2-raw.json` · `981516f1` | ✅ **exceeded** — HEAD 0.0678–0.0693 µs, 2.2% spread |
| **L2-H** | Session lookup over HTTP | **HTTP** | *no endpoint exists* | — | — | — | — | n/a — exercised only inside L1-H |
| **L5** | `lookup_user` (hot tier) | **engine** | ⛔ **WITHDRAWN** | — | T=1 | dev-ryzen-7840hs | `hea1967-c7-saturation-sample{1,2}-raw.json` · `1b6b7745` | ❌ **failed to reproduce — 236% spread.** See §4.2 |
| **L9** | `introspect_token` (RFC 7662) | **engine** | **44.0 µs** | — | T=1 | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ✅ **exceeded** — HEAD 39.2 µs |
| **L9-H** | `POST /introspect` | **HTTP** | **93.0 µs** | — | T=1 | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ⚠️ **not reproduced** — see §4.1 |
| **L6b** | Password login, Argon2id `m=19,456 KiB t=2 p=1` | **engine** | **16.4 ms** | 29.8 ms | T=1 | dev-ryzen-7840hs | `hea1967-c11-http-delta-raw.json` · `1b6b7745` | ✅ re-based **downward** to the HEAD value (2.1a said 14.70 ms) |
| **L6b-H** | Password login → `POST /login` | **HTTP** | **20.1 ms** | 22.4 ms | T=1 | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ✅ **reproduced** — HEAD 19.59 ms (2.4% delta) |

**On L6b:** this is an **Argon2id benchmark, not a server benchmark.** The ~16 ms
p50 is very nearly all KDF compute, deliberately chosen at OWASP parameters. Any
vendor can make this number arbitrarily better by weakening their KDF. We publish
our KDF parameters alongside it; as of the competitive review we are the only
vendor in the comparison set that discloses them. Do not present this as a
throughput advantage or disadvantage without that context.

---

## 2. Throughput figures

| ID | Operation | **Plane** | Single-thread | Peak | Scaling exponent | Durability | Host | Artifact · SHA | Reproduced at HEAD? |
|----|-----------|-----------|---------------|------|------------------|------------|------|----------------|---------------------|
| **T1** | `validate_token` (hot) | **engine** | **760,877 /core/s** | **9,409,220 /s** @16T | +0.889 | n/a (read) | dev-ryzen-7840hs | `c7-saturation-v2-raw.json` · `981516f1` | ✅ **exceeded** — HEAD 1,257,784–1,283,112 /core; 12.39 M @16T |
| **T1-H** | → `GET /userinfo` | **HTTP** | **16,642 /s** @T=1 | **106,641 /s** @T=32 | — | n/a | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ⚠️ **not reproduced** at T≤8; **exceeded** at T=32 (142,426 /s). See §4.1 |
| **T3** | Permission check | **engine** | **5,987,782 /core/s** | **52,048,086 /s** @16T | +0.796 | n/a (read) | dev-ryzen-7840hs | `c7-saturation-v2-raw.json` · `981516f1` | ✅ **exceeded** — HEAD 11.39–12.45 M /core (9.3% spread) |
| **T3-H** | Permission check over HTTP | — | *not on the HTTP surface by design* | — | — | — | — | — | n/a — permissions are embedded in the JWT at issue time |
| **T4** | Session creation (durable) | **engine** | **484 /s** @T=1 | **41,255 /s** @T=256 | +0.851 | **fsync-before-ack, `W`=1.000** | dev-ryzen-7840hs | `c7-saturation-post-hea1959-sample2-raw.json` · `873263d0` | ✅ **exceeded** — HEAD 47,215–47,978 /s @T=256, 1.6% spread |
| **T4-H** | Session creation over HTTP | — | *no end-to-end counterpart exists* | — | — | — | — | — | n/a — no single endpoint isolates it |
| **T5** | Password login, end-to-end | **HTTP** | **49 /s** @T=1 | **185 /s** @T=8 | — | durable session create included | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ✅ **reproduced** — HEAD 51 /s @T=1, 215 /s @T=8 |
| **L9-T** | `introspect_token` | **engine** | **21,802 /s** @T=1 | **125,613 /s** @T=32 | — | n/a | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ✅ **exceeded** — HEAD 24,664 /s @T=1 |
| **L9-TH** | `POST /introspect` | **HTTP** | **9,508 /s** @T=1 | **55,700 /s** @T=32 | — | n/a | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ⚠️ **not reproduced** — see §4.1 |

### 2.1 T4 against its target — read the footnote

T4's target was **revised down from 50,000 to 30,000 ops/s by the board on
2026-07-29**, described at the time as "a totally arbitrary number."

| | ops/s @T=256 | vs 30,000 (current) | vs 50,000 (original) |
|---|---|---|---|
| Report 2.1a (`873263d0`) | 41,255 | 1.38× PASS | 0.83× |
| **HEA-1967 sample 1** (`1b6b7745`) | **47,978.5** | **1.60× PASS** | **0.96×** |
| **HEA-1967 sample 2** (`1b6b7745`) | **47,215.1** | **1.57× PASS** | **0.94×** |

**We are within 4–6% of the target that was removed for being unreachable.** The
board should know that lowering the bar may not have been necessary. This is not a
request to reopen optimization work — T4 tuning remains stood down per HEA-1964 —
it is a correction to the record that informed the decision.

T4 total improvement from report 2.0: **254 → ~47,600 ops/s, ~187×**, with
`fsync`-before-ack intact throughout.

---

## 3. Capacity figures

| ID | Metric | **Plane** | Figure | Budget | Host | Artifact · SHA | Reproduced at HEAD? |
|----|--------|-----------|--------|--------|------|----------------|---------------------|
| **C0** | Marginal RAM per user | **engine** | **100 B/user** (OLS, R²=0.9988); 101 B/user marginal at 1M | — | dev-ryzen-7840hs | `hea1967-c0-memory-raw.txt` · `1b6b7745` | ✅ **reproduced exactly** — slope identical, δRSS@1M 96.7 vs 97.1 MiB (0.4%) |
| **C0-abs** | δRSS at 1M users | **engine** | **97.1 MiB** (64 MiB block cache) | — | dev-ryzen-7840hs | `hea1967-c0-memory-raw.txt` · `1b6b7745` | ✅ 96.7 MiB at HEAD |
| **K4** | RAM, idle, 1M hot users | **engine**, est. | **~329 MB** (scaled to 256 MiB prod cache) | < 500 MB | dev-ryzen-7840hs | `c0-sst-v3-memory-raw.txt` · `981516f1` | ✅ basis reproduced |
| **K5** | RAM, idle, 10M hot users | **engine**, est. | **~0.9 GB** | < 8 GB | dev-ryzen-7840hs | derived from C0 slope | ✅ basis reproduced |
| **K6** | RAM, idle, 100M hot users | **engine**, est. | **~6.5 GB** | < 50 GB | dev-ryzen-7840hs | derived from C0 slope | ✅ basis reproduced |
| **K7** | Disk per user (asymptotic) | **engine** | **1,195.6 B/user** (`SST = 1195.58·N − 314,700`, R²=0.999772, N≥60k) | 2,147 B/user | dev-ryzen-7840hs | `hea1967-k7-disk-slope-raw.txt` · `1b6b7745` | ✅ **reproduced to the digit** |
| **K7-proj** | Disk at 100M users | **engine**, extrapolated | **≈111.3 GiB** | < 200 GB | dev-ryzen-7840hs | `hea1967-k7-disk-slope-raw.txt` · `1b6b7745` | ✅ 1.80× headroom |

### 3.1 Corpus-scale ladder (C0, re-run at HEAD)

| N users | δRSS (MiB) | δRSS/user (B) | disk/user (B) | SSTs | Verdict (≤ 4,200 B/user) |
|---------|-----------|---------------|---------------|------|--------------------------|
| 10,000 | 2.7 | 287 | 691 | 1 | PASS |
| 50,000 | 6.8 | 142 | 691 | 1 | PASS |
| 100,000 | 12.0 | 126 | 691 | 1 | PASS |
| 500,000 | 52.6 | 110 | 691 | 1 | PASS |
| **1,000,000** | **96.7** | **101** | **423** | 1 | **PASS** |

Against the pre-SST-v3 baseline of 9,960 B/user (HEA-1904), this is a **79.3×
reduction at N=100k**. Publishable.

**Two honest caveats on this table:**

- **Criterion (2) is a MISS.** The exit criteria asked for RAM to go *flat* once the
  block-cache cap binds (~213k users). Measured log-log exponent above the cap is
  **0.8778**, not ≤0.10 — RAM is still scaling near-linearly with corpus. The
  *magnitude* is tiny (101 B/user) and passes every budget, but **"O(1) RAM
  regardless of corpus size" is not a claim this data supports.** Do not make it.
- **K7's 1,195.6 B/user was measured with the duplicate-`UserCreated` audit bug
  (HEA-1946 §3.3) still present.** Every user carries one redundant audit chain
  entry. The figure is therefore **conservative** — post-fix it is projected to fall
  ~39.5% to ~723 B/user. Publishing 1,195.6 is safe; it is a pessimistic bound.

### 3.2 Artifact figures

| ID | Metric | Figure | Budget | Source | Re-verified? |
|----|--------|--------|--------|--------|--------------|
| **K8** | Binary size | **41.6 MB** (39.7 MiB) | < 50 MB | C10 artifact · `981516f1` | ⚠️ partial — a release build on this branch measured **42,029,912 B (42.0 MB)**, still PASS, but that binary predates HEAD and was not rebuilt by this sweep |
| **K9** | Cold start to serving | **70 ms** (worst of 5) | < 2 s | C10 · `6e6a24c4` | ❌ not re-measured in this sweep |

K8/K9 are carried forward from report 1.0/2.0 unchanged. They were not in the
HEA-1967 headline scope. They are low-risk but are **not** HEAD-verified; label
them as such if published.

---

## 4. Figures that did NOT reproduce

Per the acceptance criteria: **a figure that no longer reproduces must not be
published.** Two failures, with deltas.

### 4.1 ⚠️ The entire HTTP plane — not reproducible on a non-quiescent host

**This is the most important finding in the sweep.**

I re-ran C11 `http_delta` at HEAD. Engine-direct and HTTP phases come out of the
**same binary, in the same run, back to back**:

| Measurement | 2.1a (`1b2fda55`) | HEA-1967 (`1b6b7745`) | Delta |
|---|---|---|---|
| **engine** `validate_token+get_user` T=1 | 760,877 /s | **951,950 /s** | **+25% better** |
| **engine** `introspect_token` T=1 | 44.0 µs | **39.2 µs** | **11% better** |
| **HTTP** `/healthz` T=1 | 32,865 /s · 25.4 µs | 19,987 /s · 45.0 µs | **1.8× worse** |
| **HTTP** `/healthz` T=8 | 127,542 /s | 26,462 /s | **4.8× worse** |
| **HTTP** `/healthz` T=32 | 187,070 /s | 52,281 /s | **3.6× worse** |
| **HTTP** `/introspect` T=1 | 9,508 /s · 93.0 µs | 3,241 /s · 219.8 µs | **2.9× worse** |
| **HTTP** `/userinfo` T=1 | 16,642 /s · 50.1 µs | 9,567 /s · 78.8 µs | **1.7× worse** |
| **HTTP** `/userinfo` T=32 | 106,641 /s | 142,426 /s | 1.3× *better* |
| **HTTP** `/login` T=1 | 49 /s | 51 /s | reproduces |

**Diagnosis — this is the host, not the code.** The engine got *faster* while the
HTTP wrapper around it got up to 4.8× slower, in a single process. There is no code
path that produces that combination. The cause was measured directly: during the
sweep the box carried `load average 16.45` on a 16-thread part, with a browser
(~55% CPU across processes), Electron, and the agent harness resident. The HTTP
driver is the only phase that must sustain a request generator *and* a server on
contended cores; the engine phase's short bursts win their slices.

**Consequences:**

- The **≈25 µs constant HTTP envelope** established in HEA-1957 measured **≈45 µs**
  here. Every derived HTTP figure inherits that uncertainty.
- The published multipliers move badly: `/userinfo` **44–63× → 99.5×/103.4×/51.1×**;
  `/introspect` **2.3–2.6× → 7.6×/9.4×/5.1×**.
- **Only the login figures survive**, because at ~16 ms of Argon2id per request the
  CPU contention is a rounding error. L6b-H and T5 reproduced within 2.4% and are
  safe to publish.

**Recommendation: do not publish precise HTTP-plane numbers until they are
re-measured on a quiesced, ideally server-class, host.** This is not a small
asterisk — it is precisely the plane on which every competitor comparison is made.
Our least reproducible measurements are our only comparable ones. This should be
staffed before, not after, anything customer-facing ships.

### 4.2 ❌ `lookup_user` (L5) — withdrawn, 236% run-to-run spread

Two back-to-back C7 samples at HEAD, same binary, nothing changed between them:

| | p50 |
|---|---|
| Report 2.1a (`981516f1`) | 0.458 µs |
| HEA-1967 sample 1 | **0.7729 µs** |
| HEA-1967 sample 2 | **0.2296 µs** |
| **Spread across samples** | **236.6%** |

For context, every other metric from the *same two runs* held tight: `session_create`
1.6%, `validate_token` 2.0%, `session_lookup` 2.2%, device fsync rate 2.6%,
`permission_check` 9.3%. L5 is an outlier by two orders of magnitude in stability.

The 2.1a value sits between the two samples, so this is **not evidence of a
regression** — it is evidence that **L5 was never a stable point measurement.** It
passes its `< 50 µs` target with ≥65× headroom under every sample, so the *verdict*
is unaffected; the *number* is not publishable.

**Filed, not fixed** (per scope): the `user_lookup` hot-path measurement in
`examples/saturation_throughput.rs` needs a stability fix — longer measure window,
or a warm-up that actually pins the hot tier — before L5 can be quoted.

### 4.3 Figures that reproduced better than published

Not failures, but recorded for honesty: `validate_token` (+65–69%),
`session_lookup` (−42% latency), `permission_check` (+90–108%), and T4 (+15%) all
measured **better** at HEAD than in 2.1a, consistently across two samples. Per §0.2
we publish the older, lower 2.1a figures. The margin is real but I have not isolated
whether it is a genuine improvement between `981516f1` and `1b6b7745` or a quieter
CPU during this sweep, and I will not publish a number I cannot attribute.

---

## 5. Defects found in the measurement harness

Reported, not fixed — HEA-1967 is explicitly scoped out of remediation.

1. **`examples/saturation_throughput.rs` hardcodes the superseded T4 target.**
   It emits `"t4_target_ops_s": 50000` and consequently `"t4_measured_met": false`.
   **The raw artifact self-grades T4 as a MISS** against a target the board replaced
   with 30,000. Anyone reading the JSON without the report draws the wrong
   conclusion. Needs the constant updated or made a parameter.
2. **`examples/disk_slope_sweep.rs:65` hardcodes `COMMIT_SHA = "abf179ba"`.**
   Run at `1b6b7745`, the K7 artifact still self-labels `abf179ba`. This is false
   provenance in a file whose entire purpose is provenance.
3. **`examples/http_delta.rs:1155` writes to `docs/perf/artifacts/c11-http-delta-raw.json`**
   — the same path as the *published* C11 artifact. Any re-run silently destroys the
   cited evidence. It was backed up and restored by hand for this sweep. Output paths
   should be run-scoped.
4. **No host-quiescence gate.** `http_delta` has a `MIN_GENERATOR_HEADROOM` check
   that passed (all rows ADMISSIBLE) while the measurement was being corrupted by
   ambient load. The admissibility check does not test what it needs to test.
5. **C0 admissibility warning fired and was not blocking:** `Swap used = 28,449 MiB
   — RSS measurements may be unreliable`. C0 reproduced anyway, but a warning that
   never blocks is not a guard.

---

## 6. Summary — what is cleared for publication

### ✅ Publish (HEAD-verified, conservative values)

| Figure | Value | Plane |
|---|---|---|
| `validate_token` latency | 1.31 µs p50 | engine |
| `validate_token` throughput | 760,877 /core/s · 9,409,220 /s @16T | engine |
| Session lookup latency | 0.118 µs p50 | engine |
| Permission check throughput | 5,987,782 /core/s · 52,048,086 /s @16T | engine |
| `introspect_token` latency | 44.0 µs p50 | engine |
| Durable session creation | 484 /s @T=1 · 41,255 /s @T=256, **fsync-before-ack, W=1.000** | engine |
| Password login | 16.4 ms p50 (Argon2id m=19,456 KiB t=2 p=1) | engine |
| Password login | 20.1 ms p50 · 49 /s @T=1 · 185 /s @T=8 | **HTTP** |
| RAM per user | 100 B/user marginal; 97.1 MiB δRSS @1M | engine |
| RAM at 1M/10M/100M users | ~329 MB / ~0.9 GB / ~6.5 GB | engine, est. |
| Disk per user | 1,195.6 B/user → ≈111.3 GiB @100M | engine |

### ⚠️ Publish only with the "measured on a quiescent host, not re-verified" label

`/userinfo` 50.1 µs p50 · 16,642 /s @T=1 · 106,641 /s @T=32 · `/introspect`
93.0 µs p50 · 9,508 /s @T=1 · 55,700 /s @T=32. All HTTP plane, all from
`1b2fda55`, none reproduced at HEAD. **Preferably: re-measure before publishing.**

### ⛔ Do not publish

- **L5 `lookup_user` as a point latency** — 236% spread (§4.2).
- **"O(1) RAM regardless of corpus size"** — measured exponent 0.8778 (§3.1).
- **Any engine figure placed beside a competitor's HTTP figure** (§0.1).
- **K8/K9** without a "not HEAD-verified" label (§3.2).

---

## 7. Reproduction

```bash
export PROTOC=$(which protoc)
cargo build --release --example saturation_throughput --example sst_v3_c0_memory \
                      --example http_delta --example disk_slope_sweep

# NOTE: binaries land in $CARGO_TARGET_DIR (/scratch/cache/target here), not ./target
"$CARGO_TARGET_DIR"/release/examples/saturation_throughput   # T1 T3 T4 L1 L2 L5
"$CARGO_TARGET_DIR"/release/examples/http_delta              # L9 T5 + all HTTP-plane rows
"$CARGO_TARGET_DIR"/release/examples/sst_v3_c0_memory        # C0 K4 K5 K6 + 1M ladder
"$CARGO_TARGET_DIR"/release/examples/disk_slope_sweep        # K7
```

**Run these on an idle machine.** Per §4.1, ambient desktop load corrupts the
HTTP-plane rows by up to 4.8× while leaving the engine rows looking fine — so the
failure is silent. Check `uptime` before trusting any HTTP number.

### 7.1 Artifacts committed by this sweep

| Path | Contents |
|------|----------|
| `docs/perf/artifacts/hea1967-c7-saturation-sample1-raw.json` / `-console.txt` | C7 sample 1 @ `1b6b7745` |
| `docs/perf/artifacts/hea1967-c7-saturation-sample2-raw.json` / `-console.txt` | C7 sample 2 @ `1b6b7745` (repeatability) |
| `docs/perf/artifacts/hea1967-c11-http-delta-raw.json` / `-console.txt` | C11 @ `1b6b7745` (**contended host** — see §4.1) |
| `docs/perf/artifacts/hea1967-c0-memory-raw.txt` | C0 + 1M ladder @ `1b6b7745` |
| `docs/perf/artifacts/hea1967-k7-disk-slope-raw.txt` | K7 disk slope @ `1b6b7745` |

Prior artifacts cited by this document are unchanged; `c11-http-delta-raw.json`
(`1b2fda55`) was restored byte-identical after the re-run overwrote it.

---

## 8. Branch health at `1b6b7745`

`make check` runs clippy (`-D warnings`), `cargo fmt --check`, and the full nextest
workspace suite. All three green:

```
PROTOC=/home/brad/.local/bin/protoc cargo clippy --all-targets  -- -D warnings
cargo fmt --check
PROTOC=/home/brad/.local/bin/protoc cargo nextest run --workspace

     Summary [  54.651s] 4505 tests run: 4505 passed (1 slow), 13 skipped

MAKE_CHECK_EXIT=0
```

The only two `warning:` lines in the whole log are build-script notices
(`warning: hearth@1.0.0: Tailwind CSS rebuilt`) — zero clippy warnings, zero errors.

**`make fmt` specifically** — HEA-1963 reported it broken at
`examples/saturation_throughput.rs`. Verified fixed, run standalone:

```
$ PROTOC=$(which protoc) cargo fmt --check
$ echo $?
0
```

Zero diff, zero output. **The branch is mergeable.**
