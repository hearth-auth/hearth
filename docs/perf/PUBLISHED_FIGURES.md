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
| **L1** | `validate_token` (hot tier) | **engine** | **1.31 µs** | — | T=1 | dev-ryzen-7840hs | `c7-saturation-v2-raw.json` · `981516f1` | ✅ **exceeded** — HEAD measured 0.779–0.795 µs (1.65–1.69× faster); 2 samples only — see §4.2 methodology note |
| **L1-H** | `validate_token` + user fetch → `GET /userinfo` | **HTTP** | **50.1 µs** | 153.7 µs | T=1 | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ⚠️ **not reproduced** — see §4.1 |
| **L2** | Session lookup (hot tier) | **engine** | **0.118 µs** | — | T=1 | dev-ryzen-7840hs | `c7-saturation-v2-raw.json` · `981516f1` | ✅ **exceeded** — HEAD 0.0678–0.0693 µs; 2 samples only — see §4.2 methodology note |
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
| **T1** | `validate_token` (hot) | **engine** | **760,877 /core/s** | **9,409,220 /s** @16T | +0.889 | n/a (read) | dev-ryzen-7840hs | `c7-saturation-v2-raw.json` · `981516f1` | ✅ **exceeded** — 10-run range 830,013–1,338,873 /core (~61%); 2-sample mid-session: 1,257,784–1,283,112; see §4.2 |
| **T1-H** | → `GET /userinfo` | **HTTP** | **16,642 /s** @T=1 | **106,641 /s** @T=32 | — | n/a | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ⚠️ **not reproduced** at T≤8; **exceeded** at T=32 (142,426 /s). See §4.1 |
| **T3** | Permission check | **engine** | **5,987,782 /core/s** | **52,048,086 /s** @16T | +0.796 | n/a (read) | dev-ryzen-7840hs | `c7-saturation-v2-raw.json` · `981516f1` | ✅ **exceeded** — 10-run range 10.9–13.7 M /core (~25%); 2-sample: 11.39–12.45 M /core; see §4.2 |
| **T3-H** | Permission check over HTTP | — | *not on the HTTP surface by design* | — | — | — | — | — | n/a — permissions are embedded in the JWT at issue time |
| **T4** | Session creation (durable) | **engine** | **484 /s** @T=1 | ⛔ **UNSTABLE** — do not quote | +0.851 | **fsync-before-ack, `W`=1.000** | dev-ryzen-7840hs | `c7-saturation-post-hea1959-sample2-raw.json` · `873263d0` | ❌ **RETRACTED** — HEA-1993 (2026-07-30) ran 5 alternating runs at `43190f5e`; all MISS vs 30k; range 10,047–33,888 /s (3.4×); prior "10-run range 30,466–48,648" retracted as inconsistent. T4 needs quiescent server-class host. |
| **T4-H** | Session creation over HTTP | — | *no end-to-end counterpart exists* | — | — | — | — | — | n/a — no single endpoint isolates it |
| **T5** | Password login, end-to-end | **HTTP** | **49 /s** @T=1 | **185 /s** @T=8 | — | durable session create included | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ✅ **reproduced** — HEAD 51 /s @T=1, 215 /s @T=8 |
| **L9-T** | `introspect_token` | **engine** | **21,802 /s** @T=1 | **125,613 /s** @T=32 | — | n/a | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ✅ **exceeded** — HEAD 24,664 /s @T=1 |
| **L9-TH** | `POST /introspect` | **HTTP** | **9,508 /s** @T=1 | **55,700 /s** @T=32 | — | n/a | dev-ryzen-7840hs | `c11-http-delta-raw.json` · `1b2fda55` | ⚠️ **not reproduced** — see §4.1 |

### 2.1 T4 against its target — RETRACTED (HEA-1993, 2026-07-30)

T4's target was **revised down from 50,000 to 30,000 ops/s by the board on
2026-07-29**, described at the time as "a totally arbitrary number."

**⛔ All prior T4 figures are retracted.** HEA-1993 ran 5 alternating runs at HEAD (`43190f5e`);
all MISS vs 30k; 5-run range 10,047–33,888 ops/s (3.4×). `W`=1.000 on every run.

| | ops/s @T=256 | vs 30,000 (current) | status |
|---|---|---|---|
| Report 2.1a (`873263d0`) | 41,255 | 1.38× | ❌ retracted — within natural jitter |
| HEA-1967 sample 1 (`1b6b7745`) | 47,978.5 | 1.60× | ❌ retracted — within natural jitter |
| HEA-1967 sample 2 (`1b6b7745`) | 47,215.1 | 1.57× | ❌ retracted — within natural jitter |
| HEA-1989 run 1 | 21,179 | 0.71× MISS | ❌ below range |
| HEA-1989 run 2 | 43,043 | 1.43× | within jitter |
| **HEA-1993 run 1** | **33,888** | **1.13× MISS** | — |
| **HEA-1993 run 2** | **16,281** | **0.54× MISS** | — |
| **HEA-1993 run 3** | **15,978** | **0.53× MISS** | — |
| **HEA-1993 run 4** | **33,531** | **1.12× MISS** | — |
| **HEA-1993 run 5** | **10,047** | **0.33× MISS** | — |
| **HEA-1993 median** | **~16,281** | **0.54× MISS** | **UNSTABLE** |

T4 is not quotable in any customer-facing or external document until re-measured on a
quiescent server-class host. T4 single-thread figure (484 /s @T=1) remains valid as a
floor measurement and is unaffected by the group-commit instability.

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

### 4.1.1 HEA-1974 (2026-07-29) — the re-measurement was attempted and **stopped at AC6**

The gate that §4.1 called for is implemented (`examples/support/hostenv.rs`,
wired into `http_delta`; see §5 defect 4). It was then run, and it **refused**.
The re-measurement therefore did not happen, and this is the finding, not a
failure to deliver: the only host available is disqualified on grounds that
quiescing cannot fix.

Observed on the one host available, `dev-ryzen-7840hs`, across two runs minutes
apart:

| | run A | run B |
|---|---|---|
| pre-run load average (16 logical CPUs) | **17.24** (108% of capacity) | **10.72** (67%) |
| foreign CPU across host | 247% of one core | 141% of one core |
| gate objections raised | 9 | 6 |
| exit code | **2 (refused)** | **2 (refused)** |

Load moving 17.24 → 10.72 between two runs minutes apart is itself the point:
this host's contention is not a fixed offset that could be subtracted out.

**Three of those objections are host-class — quiescing clears none of them:**

- **Mobile chassis.** AMD Ryzen 7 7840HS is a laptop part with thermal- and
  power-limited sustained clocks (package temp 69.8–71.8 °C at idle-ish load).
  Sustained throughput is not attributable to the code.
- **Scaling governor `powersave`, boost on.** Clocks vary *during* the
  measurement window.
- **No isolated CPUs** (`isolcpus=` unset). Generator, server and every foreign
  process share one schedulable set.

Every competitor figure we compare against was taken on a server-class instance.
A mobile part under DVFS is not a like-for-like denominator even when idle, so
**no HTTP-plane competitive figure from this host is publishable at any load.**

**AC6 disposition: stopped and escalated.** Per the issue's own instruction —
"if a server-class host is not available to you, say so explicitly and stop; do
not substitute another contended run" — no substitute run was taken. Host
provisioning is with the CEO.

**What a valid re-measurement needs:** a server-class host (no battery),
`performance` governor, `isolcpus=` covering the measurement cores, pre-run load
under 5% of capacity. Then `http_delta --samples 3` clears the gate on its own
and emits spread per AC3. Ideally the load generator moves off-box as well — it
is currently co-resident (AC4, and see the `co_residency_note` field in the
artifact), which is the leading suspect for the collapse in the table above.

### 4.2 ❌ `lookup_user` (L5) — withdrawn, 236% run-to-run spread

Two back-to-back C7 samples at HEAD, same binary, nothing changed between them:

| | p50 |
|---|---|
| Report 2.1a (`981516f1`) | 0.458 µs |
| HEA-1967 sample 1 | **0.7729 µs** |
| HEA-1967 sample 2 | **0.2296 µs** |
| **Spread across samples** | **236.6%** |

For context from the *same two runs*: `session_create` 1.6%, `validate_token` 2.0%,
`session_lookup` 2.2%, device fsync rate 2.6%, `permission_check` 9.3%. **These n=2
mid-session figures understate true run-to-run variance by ~30×.** A subsequent 10-run
alternating A/B sweep (5 runs each, 2026-07-30) measured `validate_token`
830,013–1,338,873 /core (~61%), `session_create` 30,466–48,648 /s (~60%), and
`permission_check` 10.9–13.7 M /core (~25%). The cause is a monotonic warm-up ramp
across a benchmarking session: two consecutive samples taken mid-session agree closely
and give false precision. **A spread computed from fewer than 5 runs on
`dev-ryzen-7840hs` is not a variance estimate.** L5 remains an outlier relative to
these corrected baselines, though by a narrower margin (~3–4× in stability, not two
orders of magnitude).

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

1. **`examples/saturation_throughput.rs` hardcodes the superseded T4 target.**
   It emits `"t4_target_ops_s": 50000` and consequently `"t4_measured_met": false`.
   **The raw artifact self-grades T4 as a MISS** against a target the board replaced
   with 30,000. Anyone reading the JSON without the report draws the wrong
   conclusion. Needs the constant updated or made a parameter.
2. **`examples/disk_slope_sweep.rs:65` hardcodes `COMMIT_SHA = "abf179ba"`.**
   Run at `1b6b7745`, the K7 artifact still self-labels `abf179ba`. This is false
   provenance in a file whose entire purpose is provenance.
3. ~~**`examples/http_delta.rs:1155` writes to `docs/perf/artifacts/c11-http-delta-raw.json`**
   — the same path as the *published* C11 artifact.~~ **Fixed in HEA-1970**: the
   output path is now controlled by `--out PATH`; the default still writes to the
   canonical path, but each new measurement can be directed to a dated artefact name.
   Run-scoped naming is the caller's responsibility.
4. ~~**No host-quiescence gate.**~~ **Fixed in HEA-1974**: `http_delta` now calls
   `hostenv::evaluate()` before building the fixture. The gate checks: load average
   vs `MAX_PRERUN_LOAD_PER_CPU = 0.05`, per-process CPU census
   (`MAX_FOREIGN_PROC_CPU_PCT = 5.0`), and host-class signals (battery, governor,
   isolated CPUs). The gate exits with code 2 on any failure; `--allow-contended-host`
   continues with `publishable:false` stamped in the artifact. Verified on
   `dev-ryzen-7840hs`: 9 objections at load 17.24, 6 at load 10.72, both exiting
   before the fixture is built (§4.1.1).

   The gate is also proven in the *passing* direction — `tests/perf_quiescence_gate.rs`
   (13 tests) pins that a synthetic quiesced server-class host is admitted, that each
   objection is raised only by its own condition, that both thresholds are `<=`
   boundaries, and that an unparseable load average fails closed. A gate only ever
   observed to fail is indistinguishable from one hardcoded to fail; these tests are
   what make the refusals above evidence rather than an assumption.
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
| Durable session creation (floor) | 484 /s @T=1, **fsync-before-ack, W=1.000** | engine |
| Password login | 16.4 ms p50 (Argon2id m=19,456 KiB t=2 p=1) | engine |
| Password login | 20.1 ms p50 · 49 /s @T=1 · 185 /s @T=8 | **HTTP** |
| RAM per user | 100 B/user marginal; 97.1 MiB δRSS @1M | engine |
| RAM at 1M/10M/100M users | ~329 MB / ~0.9 GB / ~6.5 GB | engine, est. |
| Disk per user | 1,195.6 B/user → ≈111.3 GiB @100M | engine |

### ⚠️ Publish only with the "measured on a quiescent host, not re-verified" label

*(empty — the HTTP-plane read figures that sat here were moved to ⛔ by HEA-1974.)*

### ⛔ Do not publish

- **`/userinfo` and `/introspect`, all rungs** — 50.1 µs p50 · 16,642 /s @T=1 ·
  106,641 /s @T=32, and 93.0 µs p50 · 9,508 /s @T=1 · 55,700 /s @T=32
  respectively. All HTTP plane, all from `1b2fda55`, none reproduced at HEAD, and
  **HEA-1974 established that no host currently available can reproduce them**
  (§4.1.1). Downgraded from ⚠️ because the ⚠️ label promised a re-verification
  that is now known to be unschedulable without new hardware. Holding them at
  "publish with a caveat" would ship a number we cannot stand behind — the CEO's
  standing instruction is to ship no multiplier rather than a wrong one. These
  return to ✅ or are withdrawn for good once a server-class host exists; the
  decision is deferred to that measurement, not made here.
- **Every HTTP-plane competitive multiplier** — `/userinfo` 44–63× and
  `/introspect` 2.3–2.6× both moved by 2–4× on re-measurement (§4.1). The
  multiplier is a ratio of two numbers, one of which is withdrawn.
- **T4 peak throughput** — 41,255 /s @T=256 (and all prior T4 peak figures) — retracted; HEA-1993 5-run sweep shows UNSTABLE, all MISS, range 10,047–33,888 /s. See §2.1.
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

**`http_delta` now has a mandatory quiescence gate (HEA-1970).** It checks load
average, per-process CPU census, and host-class signals before building the fixture.
The gate exits with code 2 on contended or non-server-class hosts; use
`--allow-contended-host` to collect non-publishable diagnostic data. The gate
determined that `dev-ryzen-7840hs` (a laptop) cannot produce publishable competitive
HTTP figures regardless of load — a server-class host with `performance` governor and
`isolcpus=` is required for §4.1 re-measurement.

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
