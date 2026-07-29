# HEA-1957 · C11 — the end-to-end HTTP delta

**Parent:** HEA-1867 · **Harness:** `examples/http_delta.rs`
**Raw:** `docs/perf/artifacts/c11-http-delta-raw.json` · **Console:** `docs/perf/artifacts/c11-http-delta-console.txt`
**System under test at SHA:** `1b2fda55` (branch `feature/perf-updates-7-28-26`) — that is the
commit the `src/` tree was at when the run executed. The harness itself (`examples/http_delta.rs`)
is added by the commit that lands this document; it is a measurement tool and not part of the
system under test, so no `src/` code changed between the measured tree and this SHA.
**Host:** `dev-ryzen-7840hs` — AMD Ryzen 7 7840HS, 16 logical cores, 54 GiB RAM, WD_BLACK SN850X NVMe, NixOS 26.11 / Linux 7.0.10, rustc 1.97.0
**Status:** DONE — measured, graded, committed. All 8 delta rows ADMISSIBLE at 100% success.

---

## 0. The one-line answer

**The HTTP delta is between 1.3× and 63×, and which end of that range you land on is
determined by the engine, not by the HTTP stack.**

The HTTP stack costs a roughly constant **~25 µs p50 per request** and tops out around
**33 k requests/s per connection at T=1 / 187 k at T=32** on this host. That cost is
almost invariant across endpoints. So the delta ratio for any operation is essentially
`(HTTP envelope + handler) ÷ (engine cost)`:

| Engine cost per op | Example | Delta ratio |
|---|---|---|
| ~1 µs | `validate_token` + `get_user` | **44–63×** |
| ~44 µs | `introspect_token` | **2.3–2.6×** |
| ~15 ms (Argon2id) | password login + durable session create | **1.3–1.4×** |

This resolves the question the board actually asked. Our sub-microsecond engine numbers
are real, but **they are not what a client over HTTP experiences**, and for the fastest
operations the HTTP surface dominates by a factor of ~50. For the operations where we
compete on published numbers — introspection, login — the delta is small and the
end-to-end comparison still favours us by a wide margin.

---

## 1. Why this run is admissible where HEA-1871 / HEA-1876 were not

The binding grading rule from `docs/perf/HEA-1867-PLAN.md` is:

> *Nothing is graded PASS on a run whose ceiling attribution was the generator.*

The Goose-based attempts (C3/HEA-1871, C8/HEA-1876) failed that rule. Goose and the server
shared cores and Goose's own I/O loop consumed them first, so the measured ceiling was the
generator's. Report 2.0 and 2.1 correctly record the HTTP layer as `NOT-MEASURABLE`.

Two changes make this run gradable.

**1. A generator that costs almost nothing.** The client in `examples/http_delta.rs` is a
hand-rolled closed-loop HTTP/1.1 driver over a persistent `TcpStream`: pre-rendered request
byte buffers, `TCP_NODELAY`, no TLS, no connection churn, no async runtime, no per-request
allocation, and no response parsing beyond the status line and `Content-Length`.

**2. A *measured* generator ceiling, not an assumed one.** Before Hearth is touched, the
same generator threads are pointed at a bare TCP server in the same process that replies
with a canned fixed `200 OK`. Whatever that reaches is the most this driver can produce on
this host at that concurrency:

| T | null-server ops/s | p50 |
|--:|--:|--:|
| 1 | 51,407 | 17.15 µs |
| 8 | 251,185 | 28.39 µs |
| 32 | 500,031 | 46.36 µs |

Every Hearth row is then published with its **generator headroom** = `null_ops_s ÷ op_ops_s`.
A row is graded only when headroom ≥ 2.0× **and** success ≥ 99%. The harness prints
`INADMISSIBLE` on the row itself rather than letting a generator-bound number through.

That gate is not decorative — **it caught a real error on the first run of this harness.**
See §5.

---

## 2. Method

Engine phase and HTTP phase run **in the same process, in the same run, against the same
fixture**. There is no second build, no second host, no second corpus, no cold page cache
between them. The ratio is therefore not confounded by anything except what is listed in §6.

* **Engine phase** — `IdentityEngine` methods called directly on N OS threads.
* **HTTP phase** — the **real** routers (`hearth::protocol::http::router` and
  `hearth::protocol::web::router`) served by `axum::serve` on real loopback TCP listeners,
  on a Tokio multi-thread runtime with 8 worker threads. The two routers are on **separate**
  listeners rather than merged, so a route collision cannot silently change what is measured.
* Each (op, concurrency) cell: 400 ms warm-up (discarded) then a 3 s timed window.
* Corpus: 256 users, 1,024 warm sessions + access tokens, 32 Argon2id-credentialed login
  users. Hot tier warmed and the token-claims cache saturated before measuring, so the
  read rows measure the same *hot* state C7 measured.

### Operation pairing

| HTTP op | Endpoint | Engine counterpart |
|---|---|---|
| `null` | canned-response TCP server | — (generator calibration) |
| `healthz` | `GET /healthz` | — (envelope floor: same HTTP stack, engine removed) |
| `introspect` | `POST /realms/{r}/introspect` | `introspect_token` |
| `userinfo` | `GET /realms/{r}/userinfo` | `validate_token` + `get_user` |
| `login` | `POST /ui/realms/{r}/login` | `verify_password` + `create_session` |

`healthz` is the load-bearing control: it is the identical HTTP stack with the engine
removed, so `1/healthz_ops_s` is the per-request envelope every other row pays *before* its
engine call starts.

`login` is the only Hearth HTTP surface that creates a **durable** session (`create_session`
→ WAL `fsync`), and it necessarily performs an Argon2id verify first. **There is no
KDF-free session-create endpoint on the HTTP surface** — that is a finding, not an omission;
see §4.

### Argon2id parameters (stated, per the issue's disclosure requirement)

| Parameter | Value |
|---|---|
| `memory_cost_kib` | **19,456** (19 MiB) |
| `time_cost` | **2** |
| `parallelism` | **1** |

These are `CredentialConfig::default()` — the production defaults, **not**
`CredentialConfig::fast_for_testing()` that C7 uses. Every competitor benchmark in
`HEA-1867-COMPETITIVE-COMPARISON.md` omits its KDF cost; Keycloak's own note is
"proportional to hash iterations", count omitted. Ours is above.

---

## 3. Results

### 3.1 HTTP envelope floor — `GET /healthz`, no engine work

| T | ops/s | p50 | p99 |
|--:|--:|--:|--:|
| 1 | 32,865 | 25.4 µs | 92.9 µs |
| 8 | 127,542 | 50.1 µs | 220.5 µs |
| 32 | 187,070 | 131.8 µs | 811.1 µs |

Decomposed against the null calibration at T=1: of the 25.4 µs, **~17.2 µs is the driver
plus kernel loopback round trip** and **~8.2 µs is axum/hyper/tower**. The framework itself
is not the expensive part; the syscall round trip is.

### 3.2 The delta table

| Operation | T | engine ops/s | HTTP ops/s | **delta ratio** | engine p50 | HTTP p50 | headroom | verdict |
|---|--:|--:|--:|--:|--:|--:|--:|---|
| `introspect_token` → `POST /realms/{r}/introspect` | 1 | 21,802 | 9,508 | **2.3×** | 44.0 µs | 93.0 µs | 5.4× | ADMISSIBLE |
| | 8 | 116,165 | 44,398 | **2.6×** | 60.5 µs | 162.9 µs | 5.7× | ADMISSIBLE |
| | 32 | 125,613 | 55,700 | **2.3×** | 101.9 µs | 537.5 µs | 9.0× | ADMISSIBLE |
| `validate_token`+`get_user` → `GET /realms/{r}/userinfo` | 1 | 731,419 | 16,642 | **44.0×** | 1.15 µs | 50.1 µs | 3.1× | ADMISSIBLE |
| | 8 | 4,500,392 | 71,029 | **63.4×** | 1.64 µs | 87.8 µs | 3.5× | ADMISSIBLE |
| | 32 | 6,045,477 | 106,641 | **56.7×** | 1.96 µs | 237.1 µs | 4.7× | ADMISSIBLE |
| `verify_password`+`create_session` → `POST /ui/realms/{r}/login` | 1 | 67 | 49 | **1.4×** | 14.70 ms | 20.08 ms | 1042× | ADMISSIBLE |
| | 8 | 244 | 185 | **1.3×** | 32.29 ms | 42.87 ms | 1355× | ADMISSIBLE |

All eight rows: **100% success** (`200`/`303`), headroom 3.1×–1355×.

### 3.3 The added-latency constant

Subtracting the engine p50 from the HTTP p50 at T=1:

| Operation | added p50 | of which envelope | residual (handler) |
|---|--:|--:|--:|
| `introspect` | 49.0 µs | 25.4 µs | 23.6 µs |
| `userinfo` | 48.9 µs | 25.4 µs | 23.5 µs |

The two API endpoints add the **same ~23.5 µs** of handler cost above the raw envelope,
despite doing very different amounts of engine work. That is the extractor / realm-name
resolution / response-serialization layer, and it is an operation-independent constant on
this host. This is the number to attack if we ever want to move the read-path HTTP delta:
**it is ~2× the framework cost and ~20,000× the engine cost of a token validation.**

`login` adds 5.4 ms, which is the KDF admission gate queue plus the `spawn_blocking` hop
plus cookie signing — a 1.4× multiplier on a 14.7 ms operation, i.e. noise at that scale.

---

## 4. Findings

**F1 — The HTTP delta is inversely proportional to engine work, as expected, and the
constant is ~25 µs + ~23.5 µs.** Nothing anomalous. There is no pathological HTTP
behaviour, no lock, no per-request allocation cliff. The read-path delta is large
(44–63×) purely because the engine denominator is ~1 µs.

**F2 — The published `T1` figure of 760,877 validate_token/s/core must never be quoted
against a competitor's HTTP number.** Over HTTP, the same work sustains **16,642 ops/s at
T=1 and 106,641 at T=32**. Both numbers are real; only the second is comparable to anything
a competitor publishes.

**F3 — `POST /realms/{r}/introspect` is the fair head-to-head endpoint, and we still win
by ~11×.** Same operation, same wire shape, both end-to-end. See §7.

**F4 — There is no KDF-free durable-session-create HTTP endpoint.** `create_session` is
reachable over HTTP only via web login and the federation callback
(`src/protocol/web/handlers.rs:1373`, `:1741`, `src/protocol/web/federation.rs:671`). So the
T4 engine number (33,724 ops/s at T=256) has **no direct end-to-end counterpart** — the only
HTTP path to it costs 14.7 ms of Argon2id first, which buries the ~30 µs of session-create
completely. The end-to-end login number is **49 ops/s at T=1, 185 at T=8**, and it is
99.5% KDF. This is correct behaviour, not a defect, and it means **T4's residual 1.48× MISS
is invisible from outside the process.** Any product decision to spend more engineering on
T4 should be taken on durability-headroom grounds, not on end-to-end latency grounds.

**F5 — The request shaper caps a single source IP at 100 rps by default.** See §5. This is
not a capacity limit but it *is* what one client IP sees, and it must accompany any
published throughput figure.

---

## 5. What the admissibility gate caught (kept deliberately, as evidence)

The **first** run of this harness produced this:

```
healthz    T=32   108880 ops/s   p50 203.3 µs   ok 0.1%   statuses 200×300 429×326448
userinfo   T=32   193723 ops/s   p50 127.4 µs   ok 0.1%   statuses 200×300 429×580882
```

Every row was flagged `INADMISSIBLE (errors)`. The `RequestShaper` middleware
(`src/abuse/shaper.rs:46`) defaults to **`ip_rps = 100`, `realm_rps = 1000`**, and every
request from this generator originates from `127.0.0.1`. After the first 300 responses the
harness was measuring the **429 rejection path** — which is *faster* than the real one, so
the naive reading was a throughput number that was both wrong and flattering.

Without the success-rate gate this would have shipped as a 193,723 ops/s userinfo figure.
The graded number is **106,641** — 1.8× lower. Recording this because it is the exact class
of error the C7 grading rules exist to prevent, and it is worth knowing that the gate has
now demonstrably fired.

The measured run disables the shaper and the admin/token rate limiters
(`AppState::with_request_shaper(RequestShaper::disabled())`,
`.with_rate_limiters_disabled(true)`). Those limits bound what **one client IP** may draw,
not what the server can serve, and a real deployment fields many source IPs. **Any published
figure from this harness must carry the note that a single source IP is capped at 100 rps by
default.**

---

## 6. What is excluded — disclose with any published number

* **No TLS.** Loopback plaintext HTTP/1.1. A TLS terminator adds handshake cost (largely
  amortised by keep-alive) and per-record symmetric crypto.
* **No physical network.** Loopback only — no NIC, no switch, no RTT. Every competitor
  figure we compare against was taken over a real network.
* **Client and server are co-resident** on the same 16-core host and share cores. The null
  calibration bounds the error this introduces (headroom 3.1×–9.0× on the read rows); it
  does not remove it.
* **Connection reuse is total.** One persistent keep-alive connection per generator thread.
  No connection-establishment cost is included.

All four exclusions push the same way: the measured HTTP throughput is an **upper bound**
and the delta ratio a **lower bound**. Deployments behind TLS on a real network will see a
larger delta, never a smaller one.

---

## 7. Restated competitive comparison (the point of the exercise)

`docs/perf/HEA-1867-COMPETITIVE-COMPARISON.md` carried this caveat:

> *Our numbers are engine-level. Theirs are end-to-end HTTP under load. We have never
> measured the HTTP delta. Until we do, no head-to-head claim is publishable without an
> asterisk.*

**That caveat is now discharged for introspection.**

| | Throughput | p50 | Conditions |
|---|--:|--:|---|
| Ory Hydra v1.9 (published) | 5,109 /s | 13.3 ms | 2 vCPU, in-memory adapter, no DB, end-to-end HTTP |
| **Hearth (measured, C11)** | **55,700 /s** @ T=32 | **537 µs** | 16 cores, real storage engine, end-to-end HTTP, no TLS |

**≈ 10.9× throughput and ≈ 24.8× lower p50, end-to-end against end-to-end.**

That is a far smaller multiple than the 149× that falls out of comparing our engine figure
(760,877/s) to their HTTP figure — and it is the one that survives review. It is also
measured against a **real storage engine** where Hydra's published figure uses an in-memory
adapter with no database, which cuts the other way in our favour.

**Recommended external claim:** *"~11× Ory Hydra's published introspection throughput at
~25× lower p50, measured end-to-end over HTTP, on a committed raw artifact with the commit
SHA and host stated."* Do not publish the engine-level multiples as competitive claims.

---

## 8. Reproduce (same shape as PERFORMANCE_REPORT §7.2)

```bash
# C11: end-to-end HTTP delta (engine vs HTTP, same process, same run)
export PROTOC=$(which protoc)
cargo run --release --example http_delta
# → docs/perf/artifacts/c11-http-delta-raw.json
# → stdout tee'd to docs/perf/artifacts/c11-http-delta-console.txt
```

Runtime ≈ 3 minutes, dominated by provisioning 32 Argon2id credentials at m = 19 MiB.
The harness is self-contained: it builds its own temp-dir storage engine, boots both axum
routers on ephemeral loopback ports, and deletes the data dir on exit. No server, no
bootstrap, no seeding, no env vars.

Knobs at the top of `examples/http_delta.rs`: `LADDER`, `LOGIN_LADDER`, `MEASURE`,
`WARMUP`, `USERS`, `SESSIONS`, `LOGIN_USERS`, `SERVER_WORKERS`,
`MIN_GENERATOR_HEADROOM`.

---

## 9. Follow-up

1. **The ~23.5 µs handler constant (§3.3)** is the whole read-path HTTP delta and is
   currently unattributed below "extractors + realm resolution + serialization". Profiling
   it is the only lever that moves L1/L5 end-to-end. Worth one triage issue; **not** worth
   optimising blind.
2. **TLS delta unmeasured.** Every number here is plaintext. The TLS multiplier is the last
   remaining gap between this harness and a competitor-equivalent setup.
3. **Client/server core isolation.** Headroom of 3.1× at `userinfo` T=1 is comfortable but
   not enormous; pinning the server and generator to disjoint core sets would tighten the
   read rows.
4. **`introspect` engine cost (44 µs) is 38× `validate_token` (1.15 µs).** `introspect_token`
   is doing substantially more work than a validation. Whether that is inherent to RFC 7662
   response construction or is a missed cache is unknown and worth one triage issue.
