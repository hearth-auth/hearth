# HEA-1879 · CTO spec decision — L6 "Token issuance" splits into two rows

**Author:** CTO · **Date:** 2026-07-28 · **Input:** `docs/perf/HEA-1879-C9-issuance-triage.md`
(engineer data, commit `235e3342`) · **Status:** recommendation to the board — **VISION not yet amended.**

---

## 1. What the data forces

Two independent facts, both from an admissible run (in-process, no generator, 0 rungs void,
host `dev-ryzen-7840hs`):

1. **The 7 s tail is queueing.** Throughput pins at ~247 hash/s from C=16 (the core count) while
   p99 climbs 128 → 512 → 954 ms. λ capped + W ∝ depth is Little's Law, not compute. **This is an
   implementation defect** (unbounded `spawn_blocking`, no admission control) and is fixed by R1.
2. **The compute floor breaches the target anyway.** One Argon2id verify at OWASP params
   (19 MiB / t=2 / p=1) costs **p50 ≈ 29 ms measured, ≈ 12.5 ms best-observed** — 2.5×–6× the
   L6 `< 5 ms p99` target at **concurrency = 1 with zero queueing**. **This is a spec defect.**

So the answer to "is the target wrong or the implementation wrong?" is **both, in different places** —
and that is precisely why L6 as written cannot be graded. It conflates two operations with different
physics under one number.

## 2. Decision: **Option A — split the L6 row**, with two CTO amendments

I take the engineer's Option A. Options B and C are rejected:

- **B** (restate L6 as token-minting only) leaves the password path with *no* published target. The
  path every human login traverses would be ungoverned. Unacceptable.
- **C** (keep one target, grade the password path MISS) publishes a permanent MISS caused by a
  security control working correctly. It invites a future engineer to "fix" it by weakening the KDF.
  A target you never intend to hit is not a target.

**Amendment 1 — targets are conditional on offered load.** A p99 with no stated concurrency is
unfalsifiable, and it is exactly how the 7 s tail hid in plain sight. Both new rows carry the
condition: *offered KDF concurrency ≤ the admission bound; past the bound the server sheds
(`503` + `Retry-After`) rather than queueing.* This makes R1 the thing that makes the row measurable.

**Amendment 2 — the KDF parameters are a Security-owned input, not a perf knob.** The password-grant
row must say so, so no future perf pass "wins" by dropping memory cost below OWASP.

### Proposed patch — `docs/vision/VISION.md` §7.1

Replace line 352:

```
| Token issuance (full OAuth2 flow) | < 1 ms | < 5 ms | < 10 ms | Keycloak: 5–50ms p50 |
```

with:

```
| Token minting (authorization_code / refresh / client_credentials — no KDF) | < 1 ms | < 5 ms | < 10 ms | Keycloak: 5–50ms p50 |
| Interactive password issuance (password grant / browser login — one Argon2id verify) | < 50 ms | < 100 ms | N/A (KDF-dominated) | Dominated by Argon2id cost — same basis as user creation |
```

and add below the table:

```
The two issuance rows are separated because they are different operations, not different loads:
token minting is Ed25519 sign + claim assembly; interactive password issuance additionally runs one
Argon2id verify at OWASP parameters, whose measured floor (≈12.5–29 ms per hash, HEA-1879) is above
any sub-5 ms target by construction. Argon2id cost is a Security-owned control, not a performance
knob — lowering it to hit a latency number requires Security sign-off, not a perf PR.

All p99 targets in this table hold at offered concurrency within the server's admission bound.
Beyond the bound Hearth sheds (`503` + `Retry-After`); it must not absorb overload as unbounded
queue delay. A p99 quoted without its offered-load condition is not a target.
```

### Downstream sites that must change in the same PR (target propagated to 5 places)

| File | Line | Change |
|---|---|---|
| `docs/vision/VISION.md` | 352 | split as above |
| `docs/specs/TESTING.md` | 152 | split row; regression budget +20% applies to each |
| `docs/specs/TEST_SCENARIOS.md` | 328 | split the P0 scenario checkbox into two — **and reset both to `[ ]`** (see 2b) |
| `docs/specs/TEST_SCENARIOS.md` | 878 | split table row |
| `docs/perf/PERFORMANCE_REPORT_1_0.md` | 150 | L6 → **L6a** (minting) + **L6b** (password grant) |
| `docs/perf/PERFORMANCE_REPORT_1_0.md` | 154 | rewrite the standing red-flag note as **discharged** (see 2b) |
| `docs/perf/PERFORMANCE_REPORT_1_0.md` | 478 | C9 row: `HEA-1877` → `HEA-1879`, `todo` → `done` (see 2b) |

### 2b. Patch-site verification — 2026-07-28, pre-acceptance

The five sites above were re-verified line-exact against the working tree before the board vote
(line offsets drift; the table is only useful if it is checked). All five match. The sweep also
found **three sites the original table missed**, all of which must land in the same PR:

1. **`TEST_SCENARIOS.md:328` is checked `[x]`.** The P0 scenario claims the sub-5 ms issuance target
   is *satisfied*. It is not — C9 shows it is unreachable for the password path and unmeasured for
   the minting path. Both split checkboxes must be written **`[ ]`**. Splitting the row while leaving
   it ticked would launder a NOT-MEASURED into a PASS, which is the exact failure mode this decision
   exists to remove.
2. **`PERFORMANCE_REPORT_1_0.md:154`** carries the standing red-flag prose ("baseline records issuance
   p99 = 6000 ms"). Patching only the table row at :150 leaves the report asserting an open red flag
   that C9 has discharged. Rewrite it to state the decomposition result: queueing defect → HEA-1887;
   compute floor → spec split.
3. **`PERFORMANCE_REPORT_1_0.md:478`** still attributes C9 to `HEA-1877` with status `todo`. Per §3
   HEA-1877 is cancelled in favour of HEA-1879; the row must read `HEA-1879` / `done`.

Net: the doc PR touches **4 files / 8 sites**, not 5. Still one pass, still doc-only. This
verification does not amend the decision or pre-empt the board — VISION remains unamended.

## 3. Grading consequence for C10 (HEA-1878)

- **L6a (token minting)** — `NOT-MEASURED`, owner C7/HEA-1875 + C4/HEA-1872. Never measured in
  isolation; the baseline number mixed it with the KDF path.
- **L6b (password issuance)** — `NOT-MEASURABLE` on the current host (rule 3/rule 5), **with the
  standing red flag discharged**: the queue-vs-compute decomposition it demanded is settled by C9.
  Report must carry the compute floor (p50 ≈ 29 ms, best 12.5 ms, `dev-ryzen-7840hs`, `powersave`)
  as a *floor*, not a grade.
- The report's §8 dup note resolves: **HEA-1877 cancelled in favour of HEA-1879.**

## 4. What does not change

R1 (bounded KDF admission control + shed + telemetry) is **still required and still P1**, whichever
way the spec lands. It is what converts a multi-second thrash into `floor + short bounded queue`, and
it is what makes the new conditional p99 rows measurable at all. It stays gated on C7/HEA-1875 for
the calibrated `max_in_flight` default and on **SecurityAuditor** review before merge (auth path;
a too-tight bound is self-inflicted DoS).

## 5. Approval

VISION §7.1 is a published product commitment, so this goes to the board rather than landing on my
signature. Requested via `request_confirmation` on HEA-1879. On acceptance the doc PR above is
engineer-executable in one pass; on rejection, name the option (B or C) and I will re-issue.
