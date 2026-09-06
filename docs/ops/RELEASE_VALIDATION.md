# Release Validation Runbook

**Audience:** Release engineer running the pre-release validation pass before tagging a Hearth release.
**Goal:** Confirm the release commit passes the full test matrix and benchmark gate before the signed binary and SBOM are published.

This runbook must be completed on the release commit (the commit that bumps `Cargo.toml` version and replaces `## [Unreleased]` in `CHANGELOG.md`). Do not run it on an unrelated working commit.

---

## Prerequisites

- Rust toolchain matching the MSRV declared in `Cargo.toml` (currently **1.88.0**).
- `PROTOC` environment variable pointing to a `protoc` binary (`which protoc` or set via `make PROTOC=protoc`).
- `buf` CLI installed (`brew install bufbuild/buf/buf` or https://buf.build/docs/installation).
- Docker available (used by `make sdk-smoke-local`).
- A quiesced host: no other cargo builds, no background servers on port 8420.

```bash
export PROTOC=$(which protoc)
```

---

## Step 1 — Full Rust test suite

Run the complete workspace test suite with no parallelism cap (uses all available threads).

```bash
cargo nextest run --workspace --no-fail-fast 2>&1 | tee /tmp/nextest-release.log
echo "Exit: $?"
```

Expected: all tests pass (exit 0). A non-zero exit means a test failed — **do not proceed with the release.**

Check the tail of the log for a line like:
```
Summary [  X.Xs]: NNN tests run: NNN passed, 0 failed, 0 skipped
```

If `failed` is non-zero, file an issue, fix the root cause, and re-run from this step.

---

## Step 2 — Test quality gate

Ensures no anti-patterns (vacuous asserts, zero-assert bodies, stale ignores) slipped in. This gate runs faster than the full suite.

```bash
make test-quality 2>&1 | tee /tmp/test-quality-release.log
echo "Exit: $?"
```

Expected: exit 0 with no `FAIL` lines. Any failures name the offending test file and pattern.

---

## Step 3 — Abuse coverage gate

Runs `scripts/check-abuse-coverage.sh` (§3.41). Fails if any A-N row in
`docs/plans/HEA-1114-abuse-prevention.md` lacks at least one negative-scenario test in
`tests/abuse_*.rs`. This is a *coverage* gate — it proves each abuse scenario has a test,
not that the tests pass (Step 1 covers that).

```bash
make abuse-check 2>&1 | tee /tmp/abuse-check-release.log
echo "Exit: $?"
```

Expected: exit 0.

---

## Step 4 — Lint and format

```bash
make clippy
make fmt
```

Both must exit 0. `make fmt` exits non-zero if `rustfmt` would make any changes — run `cargo fmt` to apply and re-check.

---

## Step 5 — Proto check

```bash
make proto-check
```

Runs `buf lint`, `buf breaking --against main` (no wire regressions), and `buf generate` to confirm generated code is in sync. Exit 0 required.

---

## Step 6 — CSS freshness

```bash
make css-check
```

Fails if `src/protocol/web/assets/app.css` is stale relative to the Tailwind inputs. If it fails, run `make css` and commit the result.

---

## Step 7 — Benchmark gate

Runs the five Criterion benchmark suites against the hot path. This is an advisory gate — use it to catch regressions, not as a pass/fail blocker unless a benchmark shows >20% regression against the baseline recorded in `docs/perf/PUBLISHED_FIGURES.md`.

```bash
make bench-gate 2>&1 | tee /tmp/bench-gate-release.log
echo "Exit: $?"
```

The benchmarks are:
- `rbac_check` — RBAC permission resolution
- `session_lookup` — session fetch and validation
- `storage_gate` — WAL write throughput
- `demotion_latency` — hot→cold tier demotion
- `validate_token` — JWT validation (engine plane)

Review the `change:` column in the Criterion output for each benchmark. If any shows a regression of 20% or more against the documented baseline, **stop the release**, file an issue, and investigate before proceeding.

---

## Step 8 — SDK smoke tests

Builds Hearth in dev mode, starts the server, runs the TypeScript and Go SDK example smoke scripts, and tears down the server.

```bash
make sdk-smoke-local 2>&1 | tee /tmp/sdk-smoke-release.log
echo "Exit: $?"
```

Expected: exit 0 with all SDK scripts completing without error. If the server fails to start, check port 8420 is free.

---

## Step 9 — Security gates

`make security-gate` asserts the RFC 6749 §4.3 ROPC password grant is unreachable
(`scripts/check-ropc-ban.sh`, HEA-1814/1816/1862) — it checks *both* the config
allowlist and the HTTP token dispatch, because HEA-1862 showed those two can drift apart.
It does **not** run supply-chain scanning, so run those two separately:

```bash
make security-gate                # ROPC ban assertion — exit 0 required
cargo audit --deny warnings       # RustSec advisories (needs cargo-audit)
cargo deny check                  # licenses + bans + advisories (needs cargo-deny)
```

All three must exit 0. `cargo audit` / `cargo deny` are not Make targets — install with
`cargo install cargo-audit cargo-deny` or via `taiki-e/install-action` as CI does.
`.cargo/audit.toml` carries the sim-only `bincode` exception.

---

## Step 10 — Compile the validation summary

After all steps pass, write a `validation-summary.txt`:

```bash
cat > /tmp/validation-summary.txt << EOF
Hearth $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version') — Release Validation Summary
Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Commit: $(git rev-parse HEAD)

PASS  Step 1 — Full test suite (cargo nextest, $(grep -oP '\d+ passed' /tmp/nextest-release.log | tail -1))
PASS  Step 2 — Test quality gate
PASS  Step 3 — Abuse-check adversarial gate
PASS  Step 4 — Lint (clippy) + format (rustfmt)
PASS  Step 5 — Proto check (buf lint + breaking + generate)
PASS  Step 6 — CSS freshness
PASS  Step 7 — Benchmark gate (no >20% regression)
PASS  Step 8 — SDK smoke tests (TS + Go)
PASS  Step 9 — Security gate (cargo audit + cargo deny)

All 9 steps passed. Release is cleared to tag and publish.
EOF
cat /tmp/validation-summary.txt
```

Replace any `PASS` with `FAIL: <reason>` for any step that did not pass. A summary with any `FAIL` lines means the release is **not cleared to publish**.

> **Note:** you do not need to upload this file by hand. Once the tag is pushed, the
> `validation` job in `release.yml` generates its own `validation-summary.txt` for the
> gates it runs and attaches it to the GitHub Release (see
> [CI automation](#ci-automation-hea-1264) below). Keep this manual summary as your record
> of the steps CI does **not** cover — 5, 6, and 8.

---

## Release tag command

After all steps pass:

```bash
VERSION=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')
git tag -s "v$VERSION" -m "Release v$VERSION"
git push origin "v$VERSION"
```

The `release.yml` workflow fires on the new tag and builds the signed binaries, SBOM, SLSA provenance, and publishes the GitHub Release automatically.

---

## CI automation (HEA-1264)

The `validation` job in `.github/workflows/release.yml` runs a subset of this runbook
automatically on the tagged release commit, so the §13.4 evidence is produced without
manual effort:

| Runbook step | Automated in `validation`? | Gate type |
|---|---|---|
| 1 — Full test suite (`cargo nextest run --workspace`) | ✅ | **Hard** — blocks publish |
| 2 — Test quality (`make test-quality`) | ✅ | **Hard** — blocks publish |
| 3 — Abuse coverage (`make abuse-check`) | ✅ | **Hard** — blocks publish |
| 9 — ROPC ban (`make security-gate`) | ✅ | **Hard** — blocks publish |
| 7 — Benchmarks (`make bench-gate`) | ✅ | Advisory — recorded, reviewed by a human |
| 4 — clippy / fmt | ❌ (gated on every PR by `ci.yml`) | — |
| 5 — proto-check, 6 — css-check | ❌ (gated on every PR by `ci.yml`) | — |
| 8 — SDK smoke (`make sdk-smoke-local`) | ❌ (`sdk-smoke.yml` runs it separately) | — |
| 9 — `cargo audit` / `cargo deny` | ❌ (`security.yml` runs these) | — |

**How the gating works.** Each gate step uses `continue-on-error: true` so the summary
reports every gate rather than stopping at the first failure. A final **Enforce hard
gates** step re-raises any hard-gate failure and fails the job. The publish job declares
`needs: [validation, sign, provenance]`, and `sign` and `provenance` each declare
`needs: validation` as well, so a red test suite produces no GitHub Release, no cosign
signature and no SLSA provenance (audit §4.8#2).

> The benchmark gate is deliberately advisory: judging a regression requires comparing
> against the baseline in `docs/perf/PUBLISHED_FIGURES.md`, which needs human judgement.
> Its output is captured to the summary and to `bench.log` in the workflow artifacts.

**Outputs.** The job uploads a `validation-summary` artifact containing
`validation-summary.txt`, `nextest.log`, and `bench.log`. The publish job attaches
`validation-summary.txt` to the GitHub Release and appends a **Validation** section to
the release notes linking to it.

**Steps you must still run manually** before tagging: 5, 6, and 8 (and 4 if you are
tagging a commit that never went through PR CI). The manual summary in Step 10 remains
useful for recording those.

---

## Publish gating — every release channel

The 2026-08-28 audit recorded two blockers here.

- **B2 (§4.8#1)** — the container image, the Helm chart, seven SDK releases and two
  registry packages shipped from a commit whose own suite failed four tests. Only the
  binary channel was gated.
- **B6 (§4.12#1)** — the v1.6.11 image and chart published **37 minutes before** the
  `validation` job wrote "Release is NOT cleared to publish".

Every channel now waits for a verdict on its own commit before it ships.

The wait is `.github/actions/await-green-commit`. It reads the Checks API for the named
check on the commit. It exits 0 only on `success`. It fails closed on a red verdict, on
a verdict that never arrives, and on an API it cannot read. A missing verdict is not a
pass — that was the old behaviour.

The gate sits at two levels.

**Level 1 — tag creation.** `semantic-release.yml` runs on every push to `main`. It
creates the seven SDK Release objects and pushes the `v*` and `sdk-*-v*` tags that
trigger every other workflow. It now waits for `required-summary` on that commit. A red
commit produces no tag, so no downstream channel is ever triggered.

**Level 2 — each publish.** Every publishing workflow waits again on its own commit.
Level 1 can be bypassed by a hand-pushed tag; level 2 cannot.

| Channel | Workflow | Verdict awaited | Effect |
|---|---|---|---|
| All tags + SDK Release objects | `semantic-release.yml` | `required-summary` | Blocks |
| GitHub Release binaries | `release.yml` | `validation` (same workflow) | Blocks |
| cosign signatures | `release.yml` | `validation` (same workflow) | Blocks |
| SLSA provenance | `release.yml` | `validation` (same workflow) | Blocks |
| Container image | `docker.yml` | `Release validation (test matrix + bench gate)` | Blocks |
| Helm chart | `helm.yml` | `Release validation (test matrix + bench gate)` | Blocks |
| npm `@hearth-auth/node` | `sdk-publish-node.yml` | `required-summary` | Blocks |
| npm `@hearth-auth/sdk` | `sdk-publish-typescript.yml` | `required-summary` | Blocks |
| crates.io `hearth-sdk` | `sdk-publish-rust.yml` | `required-summary` | Blocks |
| PyPI `hearth-sdk` | `sdk-publish-python.yml` | `required-summary` | Blocks |
| Maven Central `io.hearth` | `sdk-publish-kotlin.yml` | `required-summary` | Blocks |
| Go module proxy | `sdk-publish-go.yml` | `required-summary` | Alarms at level 2 |
| Packagist `hearth-auth/php-sdk` | `sdk-publish-php.yml` | `required-summary` | Alarms at level 2 |

Server release tags wait for the release-validation job by name. SDK tags point at a
commit on `main`, so they wait for `required-summary`, the repository's single required
context.

**The Go and PHP channels behave differently at level 2.** `proxy.golang.org` and
Packagist publish from the git tag itself, not from a workflow step. If a tag exists,
the publish has already happened when `sdk-publish-go.yml` or `sdk-publish-php.yml`
starts. Their level-2 gate turns an ungreen tag into a red run to retract; it does not
prevent the publish.

For those two channels, **level 1 is the protection.** Do not hand-push a `sdks/go/v*`
or `sdk-php-v*` tag. Let `semantic-release.yml` cut it, and it will not cut one from a
red commit. If a red level-2 run does appear on either, treat it as a retract signal:
the package is already public.

**The guard.** `make publish-gate-check` asserts that no publish job has stopped waiting.
It runs in `ci.yml`'s `filter` job on every PR. It fails if a publish job's `needs:` chain
reaches no gate, and if a workflow in its channel manifest loses its gate or disappears.
`scripts/tests/check-publish-gating.test.sh` proves the guard fails on an ungated job, so
it cannot decay into a stub that always passes.

### Install-path reachability gate

The audit (§4.8#5, §4.12#4) found the README's Docker and Helm install paths failed at
the first command: both GHCR packages were private, so an anonymous `docker pull` or
`helm install` got a 403 before touching a single byte of Hearth.

The `validation` job now runs `scripts/check-install-paths.sh` as a hard gate. It makes
the anonymous manifest fetch those commands start with, for the exact image tag and chart
version the README pins, with no credentials. A refusal fails validation, and the publish
channels wait on validation, so a release cannot ship while its own install
documentation does not work.

Package visibility is not controlled by this repository, and GitHub has no API for the
toggle. If this gate goes red, an org admin must set both packages to Public:
`github.com` → `hearth-auth` org → Packages → `hearth` (and `charts/hearth`) →
Package settings → Danger Zone → Change visibility → Public. New GHCR packages are
created private by default, so a renamed or recreated package will trip this gate on the
next release — that is the gate working.

---

## Related

- [CHANGELOG.md](../../CHANGELOG.md) — read before releasing; all `## [Unreleased]` entries become the release notes
- [VERSIONING.md](../../VERSIONING.md) — SemVer policy, support windows, deprecation rules
- [docs/release-runbook.md](../release-runbook.md) — semantic-release automation, conventional commits, and how tags trigger the publish workflow
- [docs/guides/upgrading.md](../guides/upgrading.md) — operator upgrade notes generated from this release
