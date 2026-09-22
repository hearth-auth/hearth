## Context

The source is `reports/production-readiness-audit-2026-08-28.md`, an adversarially reviewed audit
of `b291a723`. 25 of 32 audit pieces cleared a critic; the other 7 are excluded and their findings
appear nowhere in the report.

What the report contains, and what this change must cover:

| Source | Items |
|---|---|
| §2 build-state gates | 8 |
| §4.1–§4.25 subsystem findings | 244 |
| §7.2 pieces excluded from the report | 7 |
| §7.3 subsystems never examined | 7 |
| §8.3 gap-closing actions | 5 |
| §9 systemic risks | 6 |

Three §2 failures were re-confirmed at HEAD `8a39b8c9` before this change was written: the
`unwrap()` at `src/protocol/scim/etag.rs:83`, `h2 0.4.14` in `Cargo.lock`, and
`version = "1.6.9"` in `Cargo.toml`.

The report's own framing constrains the design. Seven of the eleven blockers need nobody at all —
they are integrity and process failures, not vulnerabilities. §9 names the habit that produced
them: **operations that report success while not having succeeded.**

## Goals / Non-Goals

**Goals:**

- Every item the audit identified has exactly one task, and every task names the section it came
  from. Coverage is provable by script, not by assertion.
- Work is ordered so that a fix can be verified when it lands.
- Every fix arrives with a test that fails against the old code.
- The three structural patterns the report names are fixed as classes, not one instance at a time:
  controls that parse and do nothing; capabilities advertised and unreachable; success reported
  without success.

**Non-Goals:**

- This change does not fix anything. It is the plan of record. Fixing starts with `/opsx:apply`.
- It does not re-audit. A finding is taken as the report states it. Where the report records a
  critic's residual objection, that objection travels with the task.
- It does not decide GA. The verdict changes when the tasks are done and re-tested, not here.

## Decisions

### Wave order, and why Wave 0 is a gate

§1 states the condition that precedes all others: `make check` cannot complete, so CI has never
run `cargo fmt --check` or the test suite on this commit. Until the build is green, no fix can be
verified.

Wave 0 is therefore a hard gate. Nothing in Waves 1–4 is marked done before Wave 0 is done.

| Wave | Groups | Content |
|---|---|---|
| 0 | 1 | Make the build green |
| 1 | 2 | The eleven blockers B1–B11 |
| 2 | 3–12 | HIGH findings, one group per capability |
| 3 | 13–22 | MEDIUM / LOW / Informational / claim-defect, one group per capability |
| 4 | 23–24 | Coverage gaps (§7.2, §7.3, §8.3) and systemic guards (§9) |

*Alternative considered:* five separate OpenSpec changes, one per wave. Rejected — the coverage
guarantee is the point of this change, and it is easiest to prove against one `tasks.md`.

*Alternative considered:* one change per audit piece, 25 in total. Rejected — 25 proposals and 25
designs for work that shares one verdict and one gate.

### One task per defect, citing every section that found it

Five pieces reached the unauthenticated `introspect` / `revoke` routes from five angles. Four
reached the zero-valued `jwks_rps_limit`. Four reached the setup token in the log. Three reached
compaction resurrection.

A task list with the same fix five times is a list that gets five different partial fixes. So:
one task per distinct defect, citing every section. 244 rows become roughly 222 tasks. The
citation list is what makes coverage checkable in both directions.

Known merges:

| Defect | Sections |
|---|---|
| Unauthenticated `introspect` / `revoke` | §4.2#3, §4.19#2, §4.22#1, §4.25#1 |
| `jwks_rps_limit` is 0 when `security:` is absent | §4.2#2, §4.13#1, §4.22#2, §4.25#2 |
| Setup token in the production log (B8) | §4.12#8, §4.13#11, §4.14#1, §4.24#2 |
| Compaction resurrection (B7) | §4.11#2, §4.12#2, §4.21#1 |
| `backup` CLI emits zero bytes | §4.9#8, §4.14#6 |
| `/ui` tree escapes the API router's guards | §4.5#1, §4.5#2, §4.5#4, §4.10#8, §4.24#8 |
| SAML `NameID` reaches a byte-slicing panic | §4.4#1, §4.10#3 |
| JWKS publishes unused RS256 / ES256 keys | §4.2#4, §4.15#5 |
| Follower cache staleness | §4.1 objection, §4.15#6, §4.16#5, §4.19#12 |
| `storage.fsync` is ignored | §4.11#12, §6 |

### Task line format

```
- [ ] 6.3 Make signing-key rotation revoke the retired key  (§4.15#1 · P06 · BLOCKER)
```

Description first, so the list reads as work. Then the section references, the audit piece, and
the severity. The severity is the report's, including the one escalation §4.14 records.

### Severity is the report's, and contested ratings travel with the task

Where a critic disputed a rating, the task says so. §4.17's two HIGHs degrade to near-nil behind a
merge-style proxy such as nginx. §4.16#5 is HIGH on a shape the README already labels not
production-supported. §4.20's three MEDIUMs rest on one untested sentence. A task that hides its
own contested rating will be prioritised wrongly.

### Wave 4 is work, not commentary

The audit's gaps are items the audit identified. §8.1 says plainly what is unmeasured: whether the
seven SDKs verify tokens or decode and trust them, and whether the test suite can fail at all.
Those become tasks. §8.3 gives the closing order, and Wave 4 follows it.

### The systemic guards

Fixing eleven blockers does not fix the property that produced them. Group 24 turns each §9
paragraph into a guard:

1. A start-up assertion that every parsed security key reaches a consumer — the class fix for
   "controls that parse and do nothing".
2. A test that distinguishes `fsync`-before-ack from no `fsync` at all.
3. A mutation spot-check in CI: comment out a security-critical check, prove something goes red.
4. A rule that no regression test may be committed red, enforced by the merge gate.
5. A docs-truth sweep driven by §6, which has more FALSE rows than TRUE.
6. An enumeration of every control the Raft state machine bypasses on a follower.

## Risks / Trade-offs

- **A 255-task list reads as unfinishable** → Waves give a stopping point with meaning. Wave 0
  plus Wave 1 is the shortest path from NO-GO to a defensible position.
- **Deduplication can hide a finding** → Every merged task lists every source section, and the
  coverage script checks the report's rows against those citations. A row with no citation is a
  failure, not an omission.
- **Fixes conflict across waves** → Several Wave 3 items are the same code as a Wave 1 blocker,
  for example realm deletion and compaction. Tasks name the shared file so the later task is
  re-checked rather than re-implemented.
- **The report is a snapshot of `b291a723`** → HEAD has moved to `8a39b8c9`. Each task is
  re-confirmed against HEAD when it is picked up. A task that no longer reproduces is closed with
  the evidence, not silently.
- **BREAKING changes land mid-remediation** → Refusing an `overwrite` restore, failing boot on a
  dead security key, and revoking on rotation all change operator-visible behaviour. Each needs a
  `CHANGELOG.md` entry at implementation time, per `CLAUDE.md`.

## Migration Plan

1. Wave 0 lands first and CI is confirmed to run every gate.
2. Wave 1 lands blocker by blocker, each with a test that fails against the old code.
3. Cluster mode is gated behind an explicit experimental opt-in until Wave 4 item P21 has an
   answer. §1 recommends this regardless of P21's result.
4. Waves 2 and 3 land per capability, so a subsystem is finished rather than sampled.
5. The audit is re-run against the remediated tree before the verdict is revisited.

Rollback is per task. No task in this change alters shipped behaviour by itself.

## Open Questions

- Does cluster mode ship gated, or not at all, until P21 clears? §1 says gated; the dedicated
  piece never passed a critic.
- The report is written against `b291a723`. How many findings have already moved at
  `8a39b8c9`? Answered per task as each is picked up.
- Do the seven never-examined subsystems in §7.3 get audited before GA, or does GA scope exclude
  them explicitly? Unexamined surface area in an identity product is itself a finding.
