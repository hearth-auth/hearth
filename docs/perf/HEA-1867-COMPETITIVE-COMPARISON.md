# HEA-1867 — Hearth vs. competitors: what the published numbers actually say

**Date:** 2026-07-29 · **Author:** CEO · **Status:** board answer, not a marketing artifact yet

Answers the board question: *"How do these metrics compare against our major competitors?"*

Hearth figures are from `PERFORMANCE_REPORT_2_0.md` plus the post-v2 corrections
(HEA-1951 K7, HEA-1948/1954/1955 T4). Competitor figures are published vendor sources,
cited inline.

---

## 0. The headline, stated honestly

On every metric where a competitor publishes a number, **Hearth is between 30× and 4
orders of magnitude ahead** — and our *worst* row, the one we grade internally as a
failure, is still ~200× faster than the best published competitor number for the same
operation.

> **UPDATE 2026-07-29 (HEA-1957) — the caveat below is now discharged, and the
> multiples in this document are correspondingly reduced.** The HTTP delta was measured
> at `1b2fda55` (`docs/perf/HEA-1957-HTTP-DELTA.md`, artifact
> `docs/perf/artifacts/c11-http-delta-raw.json`). It is **44–63× for token validation,
> 2.3× for introspection, 1.3–1.4× for password login.** Read the corrected head-to-head
> in §"Restated on end-to-end terms" immediately below **before** using any figure in the
> rest of this document.

But there was one caveat that governed everything below, and it must not be buried:

> **Our numbers are engine-level. Theirs are end-to-end HTTP under load.**
> ~~We have never measured the HTTP delta~~ (`L1–L8` rows are engine; HEA-1871/HEA-1876
> marked the HTTP layer `NOT-MEASURABLE`). ~~Until we do, no head-to-head claim is
> publishable without an asterisk.~~ **Measured by HEA-1957 on 2026-07-29.**

That gap was the single highest-value remaining measurement in the programme. It is closed.

---

## Restated on end-to-end terms (HEA-1957)

`POST /realms/{r}/introspect` is the one endpoint where the comparison is genuinely
like-for-like: same RFC 7662 operation, same wire shape, both measured end-to-end over HTTP.

| | Throughput | p50 | Conditions |
|---|--:|--:|---|
| Ory Hydra v1.9 (published) | 5,109 /s | 13.3 ms | 2 vCPU, **in-memory adapter, no DB**, end-to-end HTTP |
| **Hearth (measured, C11 `1b2fda55`)** | **55,700 /s** @ T=32 | **537 µs** | 16 cores, **real storage engine**, end-to-end HTTP, no TLS |

**≈ 10.9× throughput, ≈ 24.8× lower p50 — end-to-end against end-to-end.**

That is far smaller than the ~149× that falls out of comparing our engine figure
(760,877 validate_token/s/core) to their HTTP figure. **It is also the multiple that
survives review**, and it is measured against a real storage engine where Hydra's published
figure uses an in-memory adapter with no database.

**Password login, with our KDF disclosed** — end-to-end **49 ops/s @ T=1, 185 @ T=8** at
Argon2id `m = 19,456 KiB, t = 2, p = 1`. Every competitor in this document omits its KDF
parameters (Keycloak's own note is "proportional to hash iterations", count omitted), which
makes their login numbers unfalsifiable. Ours is stated, and the HTTP surface accounts for
only ~0.4% of it — a login is Argon2id and essentially nothing else.

**Rules for external use, binding:**

1. Quote the **end-to-end** column only. Engine-level multiples are not competitive claims.
2. State that our figures exclude TLS and a physical network, so they are an **upper bound**.
3. State the Argon2id parameters alongside any login figure.
4. State that the shipped `RequestShaper` default caps **one source IP at 100 rps**.

---

---

## 1. The one near-apples-to-apples comparison: token validation

This is the only place a competitor published a number on a shape resembling ours
(single process, no external DB in the path).

| System | Throughput | Latency | Config | Source |
|---|---|---|---|---|
| **Hearth** | **760,877 /s/core** · 9,409,220 /s @16T | p50 **1.31 µs** | engine-level, hot tier, embedded storage | C7-v2 `981516f1` |
| Ory Hydra (introspection) | 5,109 /s total (~2,554 /s/core) | p50 13.3 ms · p99 79.9 ms | 2 vCPU, **in-memory adapter, no DB** | [Hydra v1.9](https://www.ory.sh/hydra/docs/v1.9/benchmark/), ~2020 |

Per-core ratio: **≈298×**. Latency ratio: **≈10,000×** at p50.

Caveats that cut *against* us: Ory's figure includes the full HTTP stack, TLS
termination, and JSON serialization; ours includes none of those. Caveats that cut
*for* us: Ory's benchmark is ~5 years old, ran with **zero storage engaged**, and Ory
has since removed it — the current docs page redirects to qualitative marketing copy
with no numbers at all. Ory explicitly declines to publish DB-backed figures.

**Conclusion:** the direction is unambiguous and the margin is enormous, but the exact
multiple is not defensible until we measure over HTTP.

---

## 2. Login throughput — where nobody is fast, including us

Login throughput is not a server benchmark. **It is a password-hashing benchmark.**
Whoever picks the weakest KDF "wins."

| System | Logins/s | KDF disclosed? | Config |
|---|---|---|---|
| Keycloak | **15 /s/vCPU** (tested to 300/s) | No — "proportional to hash iterations", count omitted | 3-pod cluster + Aurora PG HA |
| Zitadel | **39 iter/s** total | No | 2–7 containers, 8 vCPU PG, 600 VUs |
| FusionAuth (2024, reproducible) | **72–82 /s** | No | Cloud, 15M users, 1300 tenants |
| FusionAuth (2019, marketing) | ~1,000 /s | No | 2007-era Dell, 1 GB JVM heap |
| **Hearth** | **≈34–80 /s/core** (Argon2id floor 12.5–29 ms) | **Yes — Argon2id, OWASP params** | single node, embedded |

**We are roughly 2–5× Keycloak per vCPU and comparable to FusionAuth's honest number** —
and we are the only one in the table that discloses the KDF. That disclosure is worth
more competitively than the throughput figure. Ory's headline 513/s client-credentials
number runs at `BCRYPT_COST=8`, which is weak enough that the comparison is not
meaningful.

FusionAuth is instructive as a cautionary tale: their 2019 marketing claim of 1,000
logins/s is contradicted **13×** by their own 2024 measurement of 72–82/s. We should
never ship a number we cannot re-measure.

---

## 3. Session creation (T4) — our known failure, in context

T4 is the one row we grade `MISS` against our own VISION target of 50,000 ops/s.
Post-HEA-1948/1954/1955 it measures **15,841 ops/s at T=256** (up 49× from 323).

| System | Comparable operation | Published rate |
|---|---|---|
| **Hearth (our `MISS`)** | durable session create | **15,841 /s** |
| Keycloak | refresh token | 120 /s/vCPU (tested to 435/s) |
| Keycloak | client credentials | 120 /s/vCPU (tested to 2,000/s) |
| Zitadel | machine JWT grant | 851 /s |
| Zitadel | introspect | **18 /s** — vendor notes "a lot of over fetching on the database" |

**Our failing grade is ~19× the best competitor number in this class and ~880× the
worst.** This is the most important strategic finding in the document: our internal
targets are set against physics, not against the market. That is the right way to set
them — but the board should know we are not shipping a competitive weakness here. We
are shipping a self-imposed standard nobody else attempts.

---

## 4. Memory and storage footprint — the widest gap, and the least contested

**No competitor publishes a per-user memory or storage footprint. Not one.** We do.

| System | Memory | At what scale |
|---|---|---|
| Keycloak | **1,250 MB base per pod** | includes realm cache + **10,000 cached sessions** |
| **Hearth** | **~329 MB** (est., 256 MiB prod block cache) | **1,000,000 hot users** |
| **Hearth** | ~6.5 GB (est.) | 100,000,000 hot users |

Keycloak needs 1.25 GB per pod to cache **ten thousand** sessions. Hearth holds a
**million** users in a quarter of that. Scaling Keycloak's cache 10k→200k pushed their
GC pause from 3.99 ms to 4.91 ms and memory to 1.45 GB — i.e. 20× the sessions costs
them 16% more memory *and* longer pauses, because the JVM heap is the ceiling. Our
ceiling is a configurable block-cache cap (`storage.block_cache_bytes`), not corpus
size. That is an architectural difference, not a tuning difference.

Disk: **1,195.6 B/user** (OLS, R²=0.9998) → **111.3 GiB at 100M users**, 1.80× inside
budget. Expected to fall to ~723 B/user once the duplicate-`UserCreated` bug is fixed.
No competitor offers any figure to compare against.

Max-user claims: FusionAuth says 100M single node (2019, undisclosed hashing, 2007
hardware). Keycloak claims none — their benchmark seeded 100k users. Zitadel, Ory,
Authentik, Supabase Auth, Casdoor: **none**.

---

## 5. Managed competitors — policy ceilings, not capacity

| Vendor | Ceiling | Note |
|---|---|---|
| Auth0 Enterprise | **100 req/s sustained per tenant** | burst add-on to 400/s, capped 48 hrs/month |
| Auth0 Free | 300 req/**min** | |
| Okta | **20 req/s** (1,200/min) on `/oauth2/v1/authorize` | per-username `/token` limited to 4/s |
| AWS Cognito | **120 RPS** UserAuthentication category | |

These are contractual limits, not measurements — they say nothing about the software.
But they are what customers actually hit, and they are the number a prospect compares
against. **A single Hearth node's measured validation throughput exceeds Auth0's
sustained enterprise tenant ceiling by roughly five orders of magnitude.** Even
assuming the HTTP layer costs us 99% of engine throughput, the gap is ~1,000×.

---

## 6. Two corrections owed to VISION.md

Our own positioning document contains figures the research does not support:

1. **`VISION.md:44` — "Auth0 ... hard rate limits (often cited around 300
   requests/second)".** Wrong. Enterprise Public is **100 req/s sustained**; the 300
   figure is the *free tier, per minute*. The claim understates our advantage while
   being factually incorrect — the worst combination. Fix it.

2. **`VISION.md:42` — "Keycloak's token endpoint typically delivers 5–20 ms p50, with
   p99 regularly exceeding 100 ms".** Partially supported. Keycloak's own 2025-10
   benchmark measures **p99 47 ms at 0 ms network RTT**, rising to 130 ms at 20 ms RTT.
   So "p99 >100 ms" is true only with realistic network latency included. Say that
   explicitly rather than leaving it as an unqualified claim — Keycloak's team publishes
   good, honest data and will be believed over us if we overstate.

Neither correction changes the strategic thesis. Both protect it.

---

## 7. What this means, and the one thing we still owe

**Strategically:** the "auth is a database problem" thesis is validated by the
competitive data, not just by our own. Every competitor's bottleneck traces to an
external database (Zitadel literally annotates their own introspect benchmark with "a
lot of over fetching on the database"), a JVM heap ceiling (Keycloak's 1.25 GB/pod for
10k sessions), or a contractual throttle (Auth0/Okta/Cognito). Hearth's numbers are
what happens when none of those exist.

**Credibility:** the market has a low bar for honesty here. Ory's headline number is
five years old with no database attached and has been quietly delisted. FusionAuth's
marketing number is off by 13× from their own later test. Keycloak revised its own
client-credentials guidance *down* from 200 to 120/s/vCPU. Zitadel — to their real
credit — publishes raw k6 output that shows they miss their own stated goals by 30×.

We can win on rigor. Every Hearth figure in this document names a commit SHA, a host, and
a committed raw artifact. Nobody else does that. **That reproducibility is a marketing
asset, and we should treat it as one.**

**The one thing we owe before publishing any of this externally:** an end-to-end HTTP
benchmark. Engine-level microseconds compared against competitors' end-to-end
milliseconds is not a fair fight, and a competent reviewer will say so on day one. The
gap is large enough that we do not need the asterisk — so we should go get the number
and drop it.

---

## Sources

Hearth: `docs/perf/PERFORMANCE_REPORT_2_0.md` · `docs/perf/HEA-1951-disk-slope-sweep.md` ·
`docs/perf/HEA-1945-T4-session-create-triage.md` · `docs/perf/artifacts/`

Competitors:
[Keycloak sizing](https://www.keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing) ·
[Keycloak 26.4 benchmark (2025-10)](https://www.keycloak.org/2025/10/keycloak-benchmark) ·
[Zitadel benchmarks](https://zitadel.com/docs/apis/benchmarks) ·
[Ory Hydra v1.9](https://www.ory.sh/hydra/docs/v1.9/benchmark/) ·
[FusionAuth 100M users (2019)](https://fusionauth.io/blog/got-users-100-million) ·
[FusionAuth entities (2024)](https://fusionauth.io/blog/hundreds-millions-entities) ·
[Auth0 rate limits](https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy/rate-limit-configurations/enterprise-public) ·
[Okta rate limits](https://developer.okta.com/docs/reference/rate-limits/) ·
[AWS Cognito quotas](https://docs.aws.amazon.com/cognito/latest/developerguide/quotas.html)

No published throughput or latency numbers found for: **Authentik**, **Supabase Auth
(GoTrue)**, **Casdoor**.
