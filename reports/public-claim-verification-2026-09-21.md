# Public claim verification and performance methodology — P30 re-run

Task 23.2 (audit 2026-08-28 §7.2, §8.1 item 2). Re-run at `4b098ec6` on
`fix/production-readiness-audit-8-28-26-issues`, 2026-09-21.

**42 claims tested. 17 false at HEAD. 14 of the 17 are now corrected in the
documentation; 3 could not be corrected from here and are reported instead.**

This pass deliberately starts where two siblings stopped.
`reports/documentation-truth-sweep-2026-09-21.md` re-derived all 30 rows of audit §6 and
swept the README, `docs/STATUS.md` and the normative specs — 51 claims, 20 false.
`reports/can-this-test-suite-fail-2026-09-21.md` answered the test-suite half of the
methodology question. Neither touched **`docs/vision/`, `docs/perf/`, `docs/guides/`,
the seven SDK READMEs, the Helm chart docs or the Docker docs**, and neither opened
the performance methodology. That is what is here.

| Bucket | Tested | False at HEAD |
|---|---:|---:|
| Performance methodology (§1) | 14 | 8 |
| Install and deployment paths (§2) | 16 | 7 |
| SDK security claims (§3) | 5 | 0 |
| Conformance claims (§4) | 3 | 2 |
| The three P30 failures (§5) | 4 | 0 (not reproducible — see §5) |
| **Total** | **42** | **17** |

The single most consequential result is in §1: **the README and `VISION.md` were both
publishing a throughput figure that the project's own canonical source had formally
retracted seven weeks earlier.** It is the exact failure mode the brief named — a number
whose method no longer supports it, still typeset as a measurement.

---

## 0. Method, and the one thing that makes this checkable

This project has a genuinely good instrument for performance claims, and it deserves
naming before anything else: **`docs/perf/PUBLISHED_FIGURES.md`** declares itself "the
single citable source for every performance number Hearth is willing to publish. Nothing
goes into a customer-facing document that is not in this table." It carries, per figure,
the measurement plane (engine vs HTTP), the host, the durability posture, the raw artifact
and the commit SHA, plus a §6 that splits every figure into ✅ publish / ⚠️ publish with a
label / ⛔ do not publish.

That turns "is this performance claim true?" into a mechanical test:

1. Take every number in an outward-facing document.
2. Find its row in `PUBLISHED_FIGURES.md`.
3. If the row is ⛔, or the number is not in the document at all, the claim is **false** —
   not because the number is necessarily wrong, but because nothing stands behind it.
4. Where a document asserts provenance ("these match the CI gates in X"), open X and
   check.

Steps 3 and 4 need no benchmark run, which matters here: this machine is shared, the
brief forbids running the suite, and — decisively — **HEA-1974 already established that
this host cannot produce a publishable figure at all.** The quiescence gate in
`examples/support/hostenv.rs` refused `dev-ryzen-7840hs` twice, raising 9 objections at
load average 17.24 and 6 at 10.72, and three of those objections are host-*class*
(mobile chassis, `powersave` governor, no `isolcpus=`) which quiescing cannot clear.
Re-running the harness here would produce a number the project's own gate refuses to
accept. So no benchmark was run, and none should have been.

Everything below is either a documentary test against `PUBLISHED_FIGURES.md`, a source
read, or a live network probe. Each row says which.

---

## 1. Performance methodology

### P-1 — README published a retracted figure — **FALSE** — *corrected*

> `README.md:264` — "Durable session creation (**fsync-before-ack, `W=1.000`**) | — |
> **484 /s** @T=1 · **41,255 /s** @T=256 | engine"

**How tested.** Looked the figure up in the source `README.md:242` itself names as
"source of record for every figure below": `PUBLISHED_FIGURES.md` §6.

**Result.** §6 lists it under **⛔ Do not publish**:

> **T4 peak throughput** — 41,255 /s @T=256 (and all prior T4 peak figures) — retracted;
> HEA-1993 5-run sweep shows UNSTABLE, all MISS, range 10,047–33,888 /s.

§2.1 carries the run table: five alternating runs at `43190f5e` on 2026-07-30 measured
33,888 / 16,281 / 15,978 / 33,531 / 10,047 ops/s — a **3.4× spread with a median of
~16,281**, every run a MISS against the 30,000 target the board set. The published 41,255
sat inside that jitter rather than above it. `W`=1.000 on every run, so **durability is
not in question** — only the rate.

**Verdict: FALSE.** Retracted 2026-07-30; still published 2026-09-21, seven weeks later.
The README cites the document that retracts it, two dozen lines above the table.

**Fixed:** the `@T=256` column is withdrawn. The 484 /s @T=1 floor is retained — §6 still
clears it — and an admonition states the retraction, the measured range, and that `W`=1.000
held throughout so durability is unaffected.

### P-2 — `VISION.md` published the same retracted figure — **FALSE** — *corrected*

> `docs/vision/VISION.md:372` — "Measured 41,255 ops/s at T=256 on `dev-ryzen-7840hs`,
> **engine plane**, with `fsync`-before-ack intact"

Same test, same source, same verdict. Worse in one respect: the surrounding footnote is an
unusually careful piece of writing — it correctly explains why session creation is an
aggregate-at-concurrency figure rather than a per-core one, and it records that the target
was revised from 50,000 because the original was arbitrary. Then it grounds all of that on
the one number that had been withdrawn.

**Verdict: FALSE. Fixed** — the row is marked ungraded, the retraction and the 10,047–33,888
range are stated, the 484 /s floor is kept, and the two background documents are labelled as
predating the retraction.

### P-3 — `HEA-1867-COMPETITIVE-COMPARISON.md` publishes withdrawn competitor multipliers — **FALSE** — *banner added*

> `docs/perf/HEA-1867-COMPETITIVE-COMPARISON.md:14` — "On every metric where a competitor
> publishes a number, **Hearth is between 30× and 4 orders of magnitude ahead**"

**How tested.** Cross-read against `PUBLISHED_FIGURES.md` §4.1, §4.1.1 and §6, and against
the README's own standing position.

**Result.** Three independent failures:

1. §6 ⛔: "**Every HTTP-plane competitive multiplier** — `/userinfo` 44–63× and `/introspect`
   2.3–2.6× both moved by 2–4× on re-measurement (§4.1). The multiplier is a ratio of two
   numbers, one of which is withdrawn." HEA-1974 then downgraded the underlying HTTP figures
   from ⚠️ to ⛔ because no available host can reproduce them at all.
2. The document grades T4 `PASS` at 41,255 ops/s (`:123`, `:133`) — retracted per P-1.
3. `README.md:251` states the project's position: "**We publish no competitor comparison.**
   … We would rather ship no multiplier than a wrong one." A document in the repository
   doing exactly that contradicts it.

**Verdict: FALSE as it stands. Fixed** — a ⛔ supersession banner naming all three reasons.
The body is kept as the record of how the comparison was built and why it was withdrawn;
deleting it would erase the reasoning.

### P-4 — `PERFORMANCE_REPORT_2_1.md` still grades three retracted rows — **FALSE** — *banner added*

> `docs/perf/PERFORMANCE_REPORT_2_1.md:3` — "**Status:** `v2.1a — GRADED. 19 PASS / 0 MISS …`"

The report's revision 2.1a regrades T4 `MISS → PASS` on 41,255 ops/s; it publishes every
HTTP-plane row (L1-H, L9-H, T1-H, L9-TH) and the 44–63× / 2.3–2.6× multipliers; and it
grades L5 `lookup_user` `PASS` at ≈0.458 µs. `PUBLISHED_FIGURES.md` ⛔s all three groups —
L5 for a **236% run-to-run spread** (§4.2), which makes it "not evidence of a regression …
evidence that L5 was never a stable point measurement."

**Verdict: FALSE at HEAD. Fixed** — supersession banner listing the three groups and stating
that the `19 PASS / 0 MISS` line is the 2026-07-29 grade, not the grade now.

### P-5 — `storage-sizing.md` asserts provenance it does not have — **FALSE** — *corrected*

> `docs/guides/storage-sizing.md:29` — "These ranges match the CI gate thresholds in
> `benches/storage_gate.rs`, `benches/point_lookup.rs`, and `benches/demotion_latency.rs`."

**How tested.** Opened all three benches and compared constant by constant.

| Doc row | Doc value | Actual gate | Match? |
|---|---|---|---|
| Hot tier | p50 < 5 µs, p99 < 10 µs | `STORAGE_HOT_P50` = 10 µs, `STORAGE_HOT_P99` = 100 µs (`storage_gate.rs:43,45`); `HOT_P99_CEILING` = 100 µs (`point_lookup.rs:66`) | **No — 2× and 10× looser** |
| Memtable | p50 < 20 µs, p99 < 100 µs | *no gate exists* | **No** |
| SST (warm page cache) | p50 < 10 µs, p99 < 100 µs | *no gate exists* | **No** |
| SST (cold page fault) | p50 < 100 µs, p99 < 5 ms | `COLD_P99_CEILING` = 5 ms (`point_lookup.rs:74`) | p99 only |

One row of four matches, on one of its two columns.

**Verdict: FALSE.** This is the "prediction typeset as a measurement" pattern with an extra
turn: the numbers are presented under the heading "**Typical** p50 / p99" *and* sourced to a
CI gate. Both framings are wrong in opposite directions — a gate is a failure ceiling, not a
typical value, and these are not the gates.

**Fixed:** the columns are relabelled "Planning p50/p99", and a provenance table replaces the
false sentence, naming the real gate limits row by row and the two rows that have no gate. It
points readers at `PUBLISHED_FIGURES.md` §1 for measured figures, with the caveat from P-7.

### P-6 — "p99 stays under 10 µs" — **FALSE (unsupported)** — *corrected*

> `docs/guides/storage-sizing.md:96` — "all reads are lock-free `ArcSwap` loads and p99
> stays under 10 µs."

**How tested.** Searched `PUBLISHED_FIGURES.md` for any cleared p99 read figure.

**Result.** There is none. L1 (`validate_token`) and L2 (session lookup) publish p50 only —
their p99 column is literally `—`. The only p99 figures anywhere in §1 are L1-H (153.7 µs)
and L6b (29.8 ms); L1-H is ⛔. So no p99 read figure has been cleared for publication on
either plane, and the CI gate for this path admits 100 µs.

**Verdict: FALSE as an assertion.** The sentence half-admits it — "This is the design target"
follows immediately — but the two halves contradict each other and a reader takes the first.
**Fixed:** reworded as an explicit design target, with the 100 µs gate and the measured
0.118 µs p50 (L2) both stated.

### P-7 — sizing tables above 1 M users — **PARTLY FALSE (extrapolation presented as data)** — *corrected*

> `docs/guides/storage-sizing.md:137-147` — a "Single-node sizing reference" table running to
> **1 B total users / 10 M active sessions / 128 GiB RAM / p99 read (warm) < 500 µs**.

**How tested.** Compared against the largest corpus ever measured in `docs/perf/`.

**Result.** `PUBLISHED_FIGURES.md` §3.1's ladder tops out at **1,000,000 users**. Everything
at 10 M, 100 M and 1 B is extrapolation from the measured 100 B/user RAM slope and
1,195.6 B/user disk slope. The `p99 read (warm)` column is not extrapolated from anything —
no p99 read figure exists to extrapolate from (P-6).

The table is not dishonest: "Expected hot-tier entries" and a closing note calling them
"estimates" both appear. But the p99 column has no basis at any row, and the 1 B row is three
orders of magnitude past any observation while sitting in the same visual register as the
100 K row.

**Verdict: PARTLY FALSE. Fixed** — an explicit note that nothing above 1 M has been measured,
naming the two slopes the extrapolation rests on and telling readers not to cite the rows as
results.

### P-8 — `T4_TARGET_OPS_S = 50_000` — **CODE DEFECT, still live** — *reported, not fixed*

`PUBLISHED_FIGURES.md` §5 defect 1, filed 2026-07-29, is **unfixed at HEAD**:

```rust
// examples/saturation_throughput.rs:167
/// T4 aggregate throughput target.
const T4_TARGET_OPS_S: f64 = 50_000.0;
```

The board replaced 50,000 with 30,000 on 2026-07-29 — on the record that 50,000 "was a
totally arbitrary number". `VISION.md` §7.2 was updated to match. The harness was not. It
still emits `"t4_target_ops_s": 50000` and `"t4_measured_met": false` into the raw JSON and
prints "T4 target MET / NOT MET" against 50,000 at `:1027-1047`.

**Consequence:** the artifact self-grades T4 a MISS against a target that no longer exists.
Anyone reading the JSON without the report draws the wrong conclusion — in either direction,
since a run that clears 30,000 is stamped `false`. **Report only** (`.rs` is out of scope).

### P-9 — `COMMIT_SHA` hardcoded in a provenance harness — **CODE DEFECT, still live** — *reported, not fixed*

`PUBLISHED_FIGURES.md` §5 defect 2, also unfixed:

```rust
// examples/disk_slope_sweep.rs:65
const COMMIT_SHA: &str = "abf179ba (duplicate-UserCreated NOT yet fixed)";
```

Run at any other commit, the K7 disk-slope artifact still self-labels `abf179ba`. §5 called
this "false provenance in a file whose entire purpose is provenance" and it remains so. The
parenthetical is a partial mitigation — `:329` branches on it to warn about the audit bug —
but the SHA itself is still asserted, not derived. **Report only.**

### P-10 — "sub-millisecond p99 on the hot path" — **NOT FALSE** — *no change*

Appears six times in `VISION.md` (`:13`, `:46`, `:151`, `:180`, `:287`, `:574`) and by
implication in the README.

**How tested.** Against the measured figures and against the 2026-07-31 board directive that
retired the <1 ms target.

**Result.** Every phrasing in `VISION.md` is "**targets** sub-millisecond" or appears under
§7.3's explicit header "These are design targets, not guarantees." That is a prediction
labelled as a prediction, which is the correct form. And it is not contradicted by data:
`validate_token` measures 1.31 µs p50 engine-plane, and the only HTTP-plane p99 ever taken
for the path (153.7 µs, L1-H) is well inside 1 ms even though it is ⛔ for publication.

**Verdict: NOT FALSE.** Worth recording that the 2026-07-31 board directive retired <1 ms as
a *grading* target — "an absolute internal budget is falsifiable only against ourselves" — so
these sentences are stale as policy while remaining true as prose. Not a documentation defect;
left alone rather than churned.

### P-11 — `docs-site` publishes a p99 with no cleared source — **FALSE** — *reported, could not fix*

> `docs-site/src/pages/index.js:647` — a headline stat block:
> `<1 ms` / `p99 validate_token`

**How tested.** Searched `PUBLISHED_FIGURES.md` for a cleared p99 for `validate_token`.

**Result.** There is none — L1's p99 column is `—` and L1-H's p99 (153.7 µs) is ⛔ per §6. The
surrounding hero text says "**targeting** sub-millisecond p99", which is the honest framing;
the stat block drops the verb and presents it as a measured fact, in the largest type on the
page, beside three other stats that are facts.

**Verdict: FALSE by methodology.** Not "the number is wrong" — it is plausibly right — but
nothing in the project's own citable source supports publishing it.

**Could not fix:** `docs-site/src/pages/index.js` is outside this task's edit whitelist
(documentation, SDK READMEs, chart docs, this report). **The required change:** either
restore the verb — make the stat label read `p99 validate_token (target)` — or replace the
value with the figure that *is* cleared, `1.31 µs` p50, engine plane. Needs an agent with
`docs-site/` write scope.

### P-12 to P-14 — three methodology properties that hold — **TRUE**

- **P-12 — plane labelling.** Every figure in the README performance section and in
  `VISION.md` §7.3.1's Keycloak comparison carries an explicit `engine` / `HTTP` /
  `engine, est.` label, and both documents state that placing an engine figure beside a
  competitor's HTTP figure is a category error. Checked row by row. **TRUE**, and this is
  the discipline that makes the rest auditable.
- **P-13 — the conservative-value rule.** `PUBLISHED_FIGURES.md` §0.2 publishes the older,
  lower figure wherever the HEAD re-run measured better, and §4.3 records the four figures
  that improved rather than silently adopting them. Spot-checked against §1: L1 publishes
  1.31 µs while HEAD measured 0.779–0.795 µs. **TRUE.**
- **P-14 — the durability posture behind every write figure.** §0.4 states `fsync`-before-ack
  was never relaxed and evidences it with `W = 1.000000`, and the 2026-07-30 retraction
  (P-1) preserved that even while withdrawing the rate. **TRUE**, and it survived the one
  event most likely to have quietly traded it away.

---

## 2. Install and deployment paths

Documents the sweep did not cover. Every network probe below was run on 2026-09-21.

### I-1 — Kotlin SDK: the documented artifact is not on Maven Central — **FALSE** — *corrected*

> `sdks/kotlin/README.md:14,23` — `implementation("io.hearth:hearth-core:0.1.0")`

**How tested.** Three probes:

| Probe | Result |
|---|---|
| `GET https://repo1.maven.org/maven2/io/hearth/` | **404** — the group directory does not exist |
| `GET https://repo1.maven.org/maven2/io/hearth/hearth-core/0.1.0/` | **404** |
| Maven Central search, `q=g:io.hearth` | **`numFound: 0`** |

**Result.** The group id has never been published. Separately, **version 0.1.0 was never
released either**: `git tag` carries `sdk-kotlin-v1.0.0` through `sdk-kotlin-v1.6.11`, 43 tags.
The `0.1.0` in `build.gradle.kts:7` is a placeholder that
`.github/workflows/sdk-publish-kotlin.yml:105` overwrites from the tag name at publish time —
so the README copied a value that is, by construction, never the shipped one.

**Verdict: FALSE twice over** — wrong version, and no version resolves. This is the same class
as audit §6 row 26 (the Docker/Helm install paths) in a document nobody had opened.

**Fixed:** a Known-gap admonition stating the 404s, the OSSRH publish route and the fact that
43 tags exist without anything landing publicly; a build-from-source workaround
(`gradle publishToMavenLocal`); coordinates corrected to `1.6.11`; and the note that
`build.gradle.kts` carries a placeholder.

### I-2 — Kotlin SDK compatibility table names a server that never shipped — **FALSE** — *corrected*

> `sdks/kotlin/README.md:337` — "| 0.1.x | 0.1.0 |" under "Minimum Hearth server"

**How tested.** `git tag` and `CHANGELOG.md`.

**Result.** The first Hearth release is **1.0.0, 2026-06-21** (`CHANGELOG.md:4305`). There is
no 0.1.0. **FALSE. Fixed** — rewritten as `1.0.x–1.6.x` against server `1.0.0`, with the tag
range and an explicit note that 0.1.0 never shipped.

### I-3 — PHP SDK: `composer require` cannot resolve — **FALSE** — *corrected*

> `sdks/php/README.md:34` — `composer require hearth-auth/php-sdk:^1.0`

**How tested.** Packagist API.

```
GET https://repo.packagist.org/p2/hearth-auth/php-sdk.json
  → {"packages":{"hearth-auth/php-sdk":[]}}        # zero tagged versions
GET https://packagist.org/packages/hearth-auth/php-sdk.json
  → versions: ['dev-main'];  downloads: {total: 0, monthly: 0, daily: 0}
```

**Result.** The package is registered but has **no tagged release** — only the `dev-main`
branch, and zero downloads ever. `composer require hearth-auth/php-sdk:^1.0` fails with "could
not find a version matching `^1.0`".

**Verdict: FALSE — a documented install path that fails at the first command.**
**Fixed:** Known-gap admonition with the probe result, a working `dev-main` alternative and
its stability caveat, and the original command retained as the intended path once a tag ships.

### I-4 — `deploy/README.md` presents the GHCR image as pullable — **FALSE** — *corrected*

> `deploy/README.md:19` — ```ghcr.io/hearth-auth/hearth:latest```, then a
> `docker compose … up -d` quickstart.

**How tested.** Anonymous manifest fetches.

```
ghcr.io/v2/hearth-auth/hearth/manifests/v1.6.10         → 401
ghcr.io/v2/hearth-auth/hearth/manifests/latest          → 401
ghcr.io/v2/hearth-auth/charts/hearth/manifests/1.6.10   → 401
github.com/hearth-auth/hearth                           → 200
```

**Result.** Independently reproduces the doc-truth sweep's row 26 at a later date. The
repository is public; the two GHCR packages are not. The README was given a Known-gap
admonition by that sweep; **`deploy/README.md` — the file an operator actually follows to
deploy — was not.** Same for the Helm path further down the same file.

**Verdict: FALSE. Fixed** — the same admonition, with the `docker login ghcr.io` /
release-binary workarounds and the task-3.4 reference.

### I-5 — `getting-started.mdx` Docker quickstart — **FALSE** — *corrected*

> `docs/guides/getting-started.mdx:28` —
> `docker run --rm --network=host ghcr.io/hearth-auth/hearth:latest serve --dev`

Same 401. This is the **first page a new user reads**. **FALSE. Fixed** — Known-gap note
pointing at the from-source path immediately above it, which needs no Docker and which the
page already calls "recommended".

### I-6 — `upgrading.md` Docker Compose upgrade step — **FALSE** — *corrected*

> `docs/guides/upgrading.md:174` — `docker pull ghcr.io/hearth-auth/hearth:<new-version>`

Same 401, in a runbook, at step 1. **FALSE. Fixed** — Known-gap note with the `docker login`
and release-binary routes.

### I-7 — `deploy/README.md` documents an `.env` location the compose file abandoned — **FALSE** — *corrected*

> `deploy/README.md:56` — "Create a `.env` file in the project root. The compose file loads it
> automatically"

**How tested.** Read `deploy/docker-compose.yml`.

**Result.** It reads `./hearth.env` — i.e. `deploy/hearth.env` — with `required: false`. The
root `.env` was **deliberately removed** (the compose file carries an eight-line comment
citing audit §4.8#17), because compose injects every key of an `env_file` into the container
where `docker inspect` reads it, *and* Hearth reads `HEARTH_*` as configuration, so a stray
key silently overrode the bind-mounted `hearth.yaml`.

**Verdict: FALSE, and the failure mode is the worst kind — the instruction still "works" in
the sense that nothing errors.** A root `.env` is simply ignored now, so an operator who puts
`SMTP_PASSWORD` there gets a server with no SMTP password and no diagnostic.

**Fixed:** rewritten to `deploy/hearth.env`, with the `hearth.env.example` copy step, the
precedence order, and the security reasoning that produced the change.

### I-8 — "Services started: … Mailpit" — **FALSE** — *corrected*

> `deploy/README.md:37-38` lists Mailpit at `:8025` among the services started by
> `docker compose … up -d`.

**How tested.** Read the compose file: `mailpit` carries `profiles: [mail]`, so a bare
`up -d` does not start it. **FALSE. Fixed** — the default set now names Hearth and its
in-process mailcatcher at `/dev/mail`; Mailpit is documented behind `--profile mail`, with the
note that its SMTP port is reachable only as `mailpit:1025` inside the network.

### I-9 — a documented Helm value that does not exist — **FALSE** — *corrected*

> `deploy/README.md` values table: "| `autoscaling.enabled` | `false` | Enable HPA |"
> and, further down: "The `autoscaling` value block is present but disabled by default."

**How tested.** `grep -rn 'autoscaling\|HorizontalPodAutoscaler' deploy/helm/` → **zero
matches**, in `values.yaml` and in every template.

**Result.** The key does not exist. Setting `autoscaling.enabled=true` produces no HPA and no
error — Helm silently ignores unknown values. Two statements, both false, one of them
asserting the block is "present".

**Verdict: FALSE. Fixed** — the row is removed and the prose replaced with a note that no such
value or template exists, plus why horizontal autoscaling would be wrong here anyway
(single-writer WAL on one PVC).

### I-10 to I-16 — deployment claims that hold — **TRUE**

Each verified against the artifact named:

| # | Claim | Test | Verdict |
|---|---|---|---|
| I-10 | Values table: `image.repository`, `image.tag`, `replicaCount` 1, `persistence.enabled` true / `size` 10Gi / `storageClassName` "", `ingress.enabled` false / `className` "", `secret.tlsCert`/`tlsKey`/`env`, `resources.requests` 100m/128Mi, `podDisruptionBudget.enabled` false | line-by-line against `deploy/helm/hearth/values.yaml` | **TRUE** — all 13 rows |
| I-11 | `hearth config --help` | `Config` subcommand present, `src/main.rs:100` | **TRUE** |
| I-12 | `make helm-lint`, `make helm-template`, `make helm-template UPDATE=1` | `Makefile:537,544` | **TRUE** |
| I-13 | "CI-gated by `.github/workflows/helm.yml`" | file exists | **TRUE** |
| I-14 | npm `@hearth-auth/node` and `@hearth-auth/sdk` install | registry `latest` = 1.6.2 on both | **TRUE** |
| I-15 | `pip install hearth-sdk` | PyPI `1.6.8` | **TRUE** |
| I-16 | Rust SDK: "`hearth-sdk` is not yet published to crates.io" + git-tag dependency | honest disclosure; `v1.0.0` tag exists | **TRUE** |

### I-17 — Go SDK install pin was six minors stale — **STALE, not false** — *corrected*

> `sdks/go/README.md:10` — `go get github.com/hearth-auth/hearth/sdks/go@v1.0.0`

**How tested.** Go module proxy.

```
.../@v/v1.0.0.info   → 200, tagged 2026-06-23 (refs/tags/sdks/go/v1.0.0)
.../@v/v1.6.11.info  → 200, tagged 2026-08-28 (refs/tags/sdks/go/v1.6.11)
```

**Verdict: not false — it resolves — but it hands a new user a three-month-old SDK against a
1.6.11 server.** Updated to `v1.6.11` with the proxy list URL so the pin can be re-derived.
The compatibility table was left alone: I have no evidence about 1.6.x-against-1.0.0
compatibility and will not invent a matrix.

### Observation, not a claim — the npm and PyPI packages lag the server

`@hearth-auth/node` and `@hearth-auth/sdk` are at **1.6.2, published 2026-07-08**; PyPI
`hearth-sdk` is at **1.6.8**; the server and the Go and Kotlin tag series are at **1.6.11**
(2026-08-28). No README asserts a version for these, so nothing is false. Recorded because a
version skew of nine releases across a seven-SDK matrix is a release-pipeline question worth
someone's attention, and because it is the kind of thing that becomes a false claim the moment
a compatibility table is written.

---

## 3. SDK security claims — the ones most worth being wrong about

`reports/sdk-verify-matrix-2026-09-09.md` found, at `3c13bcee`, that the Go and Kotlin SDKs
were **SPLIT — CRITICAL**: the explicit verify path verified, but the shipped authorization
middleware "decoded and trusted", with the Go helper's own comment reading "The signature is
NOT verified". Both READMEs claim the opposite. If that were still true at HEAD it would be
the most serious finding in this report, so it was re-tested from source rather than assumed.

### S-1 — Go: "Every helper below **verifies the token before reading any claim**" — **TRUE at HEAD**

`sdks/go/README.md:102-104`, and `:418-420` "The middleware verifies the token's signature
against the cached JWKS and then reads the claims locally".

**How tested.** Read `sdks/go/hearth/middleware.go`, `gin/middleware.go`, `echo/middleware.go`.

**Result.** `RequirePermission` (`middleware.go:84`) documents and implements EdDSA
verification against the cached JWKS plus `exp`/`nbf`/`iss` before any claim read. The gin and
echo guards (`:174`, `:176`) read **exclusively** from claims that `HearthMiddleware` already
verified, and abort 401 when no verified claims are present — `RequirePermission never reads
the raw token`. **The decode-and-trust path is gone.**

Two unverified decodes remain and both are sound: `claims.go:72` and `client.go:201` are
explicitly-labelled inspection accessors, and the `required_action` gate decodes unverified by
design — with the reasoning stated in-line: "This read is deliberately unverified: it can only
ever *reject*, so a forged `token_type` costs the forger their own request and grants nothing.
Every path that can *grant* verifies first." That is the correct argument, and it is correct.

**Verdict: TRUE.** The README's own upgrade note ("Earlier releases decoded the JWT without
checking its signature, so an `alg: none` forgery carrying …") is accurate history.

### S-2 — Kotlin: `EMBEDDED` "Verify the JWT against the cached JWKS, then read its
`permissions` claim" — **TRUE at HEAD**

`sdks/kotlin/README.md:76`, `:217`.

**How tested.** Read `hearth-core/src/main/kotlin/io/hearth/sdk/Middleware.kt`.

**Result.** `:87-93` — `opts.client.verifyToken(token).hasPermission(permission)`, with the
comment "Verify BEFORE reading a claim. Decoding without verifying would let anyone mint an
unsigned token carrying whatever permissions they liked." `checkRequiredAction` is the same
reject-only unverified decode as Go, with the same documented reasoning. **TRUE.**

### S-3 to S-5 — three supporting claims — **TRUE**

- `sdks/node/README.md:28` "Peer dependencies: none. The SDK ships `jose` as a direct
  dependency for JWKS verification" — matches the matrix's finding that every node gate
  consumes a `VerifiedToken` from `jwtVerify`. **TRUE.**
- `sdks/typescript/README.md:12` React peer dependency `>=17 <20`, optional — **TRUE.**
- `sdks/kotlin/README.md:291` "`TokenInvalidError` | Bad signature, malformed JWT, algorithm
  mismatch" — matches the Nimbus verify path. **TRUE.**

---

## 4. Conformance claims

Audit §6's last row left protocol conformance **UNVERIFIED**. The doc-truth sweep closed it
for the README and `TESTING.md` (its N-11): all three protocol layers ship, **no certifying
body's suite has ever been run**, seven hand-written in-repo suites exist, and the verdict was
"do not represent Hearth as certified." It did not reach the two documents below.

### C-1 — `VISION.md` "conform strictly to their respective RFCs" — **FALSE** — *corrected*

> `docs/vision/VISION.md:505` (§8.4 Drop-In Protocol Compatibility) — "Hearth's OIDC,
> OAuth 2.0, SAML, and SCIM endpoints **conform strictly** to their respective RFCs and
> specifications."

**How tested.** Same test as N-11: looked for evidence of any external suite run, and
enumerated what does exist.

**Result.** Seven in-repo suites, all verified present:
`tests/oidc_conformance.rs`, `fapi_conformance.rs`, `fapi2_conformance.rs`,
`rfc8693_conformance.rs`, `rfc8707_conformance.rs`, `rfc9728_conformance.rs`,
`federation_conformance.rs`, plus `scripts/check-sdk-conformance.sh`. No OpenID Foundation
certification, no SAML interop suite, no SCIM compliance suite has been run.

**Verdict: FALSE as stated.** "Conform strictly" is a conformance assertion, and the project
decided three weeks ago it cannot make one.

**Fixed:** rewritten to "are built to their respective RFCs … and are exercised by in-repo
conformance suites", naming all eight, followed by an explicit "**No certifying body's suite
has been run**" admonition repeating N-11's instruction not to represent Hearth as certified.
The genuinely useful part of the claim — that a standard OIDC client library works unmodified
— is retained, because it is a different and supportable statement.

### C-2 — `docs-site` "OIDC — Core 1.0 conformant" — **FALSE** — *reported, could not fix*

> `docs-site/src/pages/index.js:659` — a headline stat: value `OIDC`, label
> `Core 1.0 conformant`.

Same test, same result, and this is **the most externally visible instance of the claim in the
entire project** — the marketing homepage, in the stat bar, stated as a bare fact. It directly
contradicts the README and `TESTING.md` as the doc-truth sweep corrected them.

**Could not fix:** outside the edit whitelist. **The required change:** replace the label with
a non-certifying phrasing — `Core 1.0 implemented`, or `OIDC · OAuth 2.0 · SAML · SCIM` with
no conformance verb at all. Needs an agent with `docs-site/` write scope. **This and P-11 are
the two highest-priority items left open by this task**, because a marketing homepage is the
one surface where a conformance overclaim reaches people who cannot check it.

### C-3 — README and `TESTING.md` conformance text — **TRUE** — *no change, not mine*

Verified that the doc-truth sweep's N-11 correction is in place at HEAD and consistent with
what I found. Per the task's constraints, not re-edited.

---

## 5. The three items P30 failed on

The task asks me to identify the three, reproduce each, and say whether it reproduces at HEAD.
**I could not identify them, and the reason is structural rather than a failure of search.**

**What the repository says.** §7.2 lists P30 with "Rounds failed: 2" and the reason "One repro
did not reproduce; two negative results false. **791 citation occurrences across 413 distinct
file:line pairs, zero unresolved**". §8.1 item 2 repeats it and adds that the material "is
likely substantially sound and is still excluded". That is the complete record.

**Why nothing more exists.** §7.2 states the exclusion rule in terms that settle it:

> Each has a complete written section. None passed a critic. **Nothing from them appears
> anywhere in this report.**

P30's section was never merged into the audit. The three failures are named only inside a
document that was, by policy, not published. I searched the full audit (1,389 lines), all
eleven sibling reports, `docs/`, and `openspec/` — `P30` appears exactly three times, all
three quoted above. `openspec/changes/production-readiness-remediation/tasks.md:292` restates
the same sentence verbatim and adds nothing.

**Verdict: not reproducible, and not reproducible in principle from this repository.** This is
the same situation recorded for the audit's §4.x prose and for task 17.3: the underlying text
is not in the repo, so the honest response is to prove the property independently rather than
guess at three unnamed items. Guessing would be worse than useless — a wrong guess that
"reproduces" would launder an invented finding into the record.

**What can be said, and was tested.** Two structural observations, both testable, both tested:

- **R-1 — P30's visible residue is exactly two §6 rows**, "Performance table (sub-µs
  validation, `W=1.000`, 100 B/user) — **UNVERIFIED**" and "Protocol conformance — **UNVERIFIED**",
  both annotated "The dedicated piece did not clear review. Not assessed here. See §8." Those
  two rows are the entire published surface of P30. **The conformance row is now closed** by
  the doc-truth sweep's N-11 plus C-1/C-2 above. **The performance row is what §1 of this
  report addresses.** Tested by enumerating every §6 row annotated to §8; there are exactly
  these two. **TRUE.**
- **R-2 — the §6 performance row's three named figures, re-derived.** `W=1.000` — **TRUE and
  still cleared** (`PUBLISHED_FIGURES.md` §0.4, §6; it survived the T4 retraction, P-14).
  `100 B/user` — **TRUE and cleared** (§3, C0: OLS slope, R²=0.9988, "reproduced exactly" at
  HEAD, δRSS@1M 96.7 vs 97.1 MiB, 0.4%). "Sub-µs validation" — **misdescribed by the audit**:
  the published figure is **1.31 µs** p50, engine plane, not sub-microsecond. The audit's
  parenthetical is wrong; the README has never claimed sub-µs and does not now. Recorded
  because it is the audit's own count being wrong, in the direction the brief warns about.

- **R-3 — a candidate for "the repro that did not reproduce", offered as a hypothesis and
  labelled as one.** `PUBLISHED_FIGURES.md` §4.1 and §4.2 are, at HEAD, the two documented
  non-reproductions in the performance corpus: the entire HTTP plane (1.7×–4.8× worse on a
  contended host, engine faster in the same process — "there is no code path that produces
  that combination") and L5 `lookup_user` (236% spread across two back-to-back samples). Both
  **reproduce as non-reproductions** at HEAD, in the sense that the conditions producing them
  are unchanged: HEA-1974's quiescence gate refused this host twice on grounds that quiescing
  cannot clear, and no server-class host has been provisioned since. Whether either is *the*
  repro P30 meant is **unknown and unknowable from here**. Stated as a hypothesis, not a
  finding.

**Bottom line on §8.1 item 2:** the three items cannot be reproduced, and saying so is the
correct answer rather than a gap. What P30 was *for* — public claim verification and
performance methodology — has been re-run from scratch in §1–§4 of this report, and it found
eight false performance claims and nine false install/conformance claims that the original
pass either never reached or never published.

---

## 6. Code defects found — reported, not fixed

| # | Defect | Location | Impact |
|---|---|---|---|
| **D-1** | `T4_TARGET_OPS_S = 50_000.0` — the superseded target, hardcoded. Board replaced it with 30,000 on 2026-07-29; `VISION.md` §7.2 was updated, the harness was not. | `examples/saturation_throughput.rs:167`, used at `:747`, `:1021-1047`, emitted at `:1277` | Every raw artifact self-grades T4 a MISS against a target that no longer exists. A run that clears 30,000 is stamped `"t4_measured_met": false`. Anyone reading the JSON without the report draws the wrong conclusion. Filed as `PUBLISHED_FIGURES.md` §5 defect 1 on 2026-07-29; **unfixed 54 days later.** |
| **D-2** | `COMMIT_SHA` hardcoded in the provenance harness. | `examples/disk_slope_sweep.rs:65` | The K7 disk-slope artifact self-labels `abf179ba` regardless of the commit it ran at — false provenance in a file whose purpose is provenance. `PUBLISHED_FIGURES.md` §5 defect 2; **unfixed.** |
| **D-3** | `docs-site` publishes a `p99 validate_token` stat with no cleared source, and an `OIDC Core 1.0 conformant` stat that contradicts the corrected README and `TESTING.md`. | `docs-site/src/pages/index.js:647`, `:659` | The most externally visible claims in the project, on a surface readers cannot check. Outside this task's edit whitelist. Fix in P-11 and C-2. |
| **D-4** | `sdks/kotlin/build.gradle.kts:7` carries `version = "0.1.0"`. | — | Harmless at publish time — `sdk-publish-kotlin.yml:105` stamps the tag — but it is the source the README copied, producing I-1/I-2. The equivalent placeholders in `pyproject.toml` and `Cargo.toml` were corrected long ago (`CHANGELOG.md:4155`); Kotlin was missed. |
| **D-5** | `io.hearth` has never appeared on Maven Central despite 43 `sdk-kotlin-v*` tags and a workflow that publishes to OSSRH on each. | `.github/workflows/sdk-publish-kotlin.yml:107-116` | Either the live publish step has never succeeded, or artifacts are stuck in an OSSRH staging repository that was never released. Not diagnosable without the workflow run logs. **The Kotlin SDK is, in practice, unpublished.** |

---

## 7. Files changed

| File | Change |
|---|---|
| `README.md` | Retracted T4 peak (`41,255 /s @T=256`) withdrawn; retraction, measured range and surviving `W`=1.000 durability stated |
| `docs/vision/VISION.md` | §7.2 T4 row marked ungraded with the retraction and range · §8.4 "conform strictly" withdrawn in favour of the in-repo suites plus a no-certification admonition |
| `docs/perf/HEA-1867-COMPETITIVE-COMPARISON.md` | ⛔ supersession banner — withdrawn multipliers, retracted T4, and the project's no-comparison position |
| `docs/perf/PERFORMANCE_REPORT_2_1.md` | ⛔ supersession banner — T4, the whole HTTP plane, and L5 |
| `docs/guides/storage-sizing.md` | False CI-gate provenance replaced with a real per-row gate table · columns relabelled "Planning" · "p99 stays under 10 µs" reframed as a design target with the real gate and measured p50 · extrapolation note above 1 M users |
| `docs/guides/getting-started.mdx` | GHCR anonymous-pull gap disclosed on the Docker quickstart |
| `docs/guides/upgrading.md` | Same gap disclosed on the Compose upgrade step |
| `deploy/README.md` | GHCR gap disclosed · Mailpit corrected to a profile · root `.env` corrected to `deploy/hearth.env` with the §4.8#17 reasoning · non-existent `autoscaling` value withdrawn (two places) |
| `sdks/kotlin/README.md` | Maven Central gap disclosed with probe results and a source workaround · coordinates `0.1.0` → `1.6.11` · compatibility table corrected (`0.1.0` server never shipped) |
| `sdks/php/README.md` | Packagist no-tagged-release gap disclosed with a `dev-main` workaround |
| `sdks/go/README.md` | Install pin `v1.0.0` → `v1.6.11`, with the proxy list URL |
| `CHANGELOG.md` | One `### Fixed` bullet |

No `.rs` file, nothing under `src/`, `tests/`, `scripts/`, `.github/` or `openspec/`, and
nothing the documentation-truth sweep had already corrected.

---

## 8. Verdict on task 23.2

**P30 does not fully pass. It passes on substance and fails on two items outside this
task's edit scope.**

What passes:

- **The performance methodology is sound and, with the corrections above, honestly
  represented.** `PUBLISHED_FIGURES.md` is a better instrument than most projects have: plane
  discipline, per-figure provenance, a conservative-value rule, an explicit do-not-publish
  list, and a quiescence gate that has actually refused this host and is itself tested in the
  passing direction (`tests/perf_quiescence_gate.rs`, 13 tests — "a gate only ever observed to
  fail is indistinguishable from one hardcoded to fail"). The methodology was never the
  problem. **The problem was that two outward-facing documents had drifted off it**, and that
  drift is now closed.
- **Every remaining published performance figure traces to a ✅ row in `PUBLISHED_FIGURES.md`
  §6.** Re-checked figure by figure after the edits.
- **No SDK decodes and trusts.** The critical split the 2026-09-09 matrix found in Go and
  Kotlin is closed at HEAD, and both READMEs are accurate.
- **The conformance overclaim is closed in `VISION.md`**, matching the README and
  `TESTING.md`.
- **Audit §8.1 item 2's two UNVERIFIED §6 rows are both now resolved** — conformance by N-11
  plus C-1, performance by §1 of this report.

What is outstanding:

1. **`docs-site/src/pages/index.js` carries two false claims** (P-11: a `p99 validate_token`
   figure with no cleared source; C-2: `OIDC Core 1.0 conformant`, contradicting the corrected
   README and `TESTING.md`). Both are outside this task's whitelist. Both are on the project's
   most public surface. **23.2 should not be ticked until these are fixed** — the exact edits
   are specified in P-11 and C-2 and need only an agent with `docs-site/` write scope.
2. **D-1 and D-2 are live harness defects**, filed by this project against itself on
   2026-07-29 and unfixed 54 days later. D-1 in particular means every future T4 artifact will
   self-grade against a dead target. Neither blocks a claim today, because T4's peak is
   withdrawn anyway — but D-1 will silently corrupt the *next* T4 measurement, including the
   one on the server-class host everything else is waiting for.
3. **The three items P30 failed on cannot be reproduced** (§5). Not a gap in this pass: the
   source text does not exist in the repository, and inventing three plausible items would be
   worse than recording the absence. P30's *scope* has been re-run in full.
4. **Unchanged from the doc-truth sweep:** the two GHCR packages remain private (task 3.4),
   and no HTTP-plane figure can be published until a server-class host exists (HEA-1974). Both
   are now disclosed everywhere they matter rather than papered over — five documents carry the
   GHCR gap where one did before.

**Recommendation:** treat 23.2 as **complete pending item 1**. The claim-verification and
performance-methodology work is done and is documented here; what remains is a two-line edit
to a file this task was not permitted to open.
