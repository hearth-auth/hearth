# Hearth Release Runbook

This document covers how semantic-release governs version bumps, changelogs, and tag creation for the Hearth monorepo. The release-PR flow that follows each release is in [`docs/dev/DEVELOPMENT.md`](dev/DEVELOPMENT.md#release-cut-procedure) § Release-cut procedure.

## Architecture overview

```
PR merged to main, then the daily release run
  │
  └─▶ semantic-release.yml
        │  (multi-semantic-release — one run, all packages)
        │
        ├─▶ server root  → tag vX.Y.Z      ─▶ release.yml   (binaries, SBOM, SLSA)
        │                                  ─▶ helm.yml      (Helm OCI chart)
        ├─▶ sdks/typescript → tag sdk-ts-vX.Y.Z ─▶ sdk-publish-typescript.yml
        ├─▶ sdks/go      → tag sdks/go/vX.Y.Z  ─▶ sdk-publish-go.yml
        ├─▶ sdks/python  → tag sdk-python-vX.Y.Z ─▶ sdk-publish-python.yml
        └─▶ sdks/php     → tag sdk-php-vX.Y.Z  ─▶ sdk-publish-php.yml
```

Packages with no releasable commits since their last tag are silently skipped.

## Conventional Commits (required)

The PR title is the squash-merge commit message; semantic-release reads it to compute the version bump:

| Prefix | Bump | Example |
|--------|------|---------|
| `fix:` | patch | `fix(oidc): correct nonce validation` |
| `feat:` | minor | `feat(webauthn): resident key support` |
| `fix!:` or `BREAKING CHANGE:` footer | major | `feat!: rename /v1/auth to /v2/auth` |
| `chore:`, `ci:`, `docs:`, `test:`, etc. | none | |

The `commit-lint.yml` workflow rejects non-conforming PR titles before merge.

## Prerequisites — secrets

Before the `semantic-release.yml` workflow can push commits and tags, create:

| Secret | Scope | Notes |
|--------|-------|-------|
| `SEMANTIC_RELEASE_PAT` | `repo`, `workflow` | PAT or GitHub App token. Must NOT be `GITHUB_TOKEN` — tags pushed by the built-in token do not trigger other workflows. |

## How a `fix:` ships (normal flow)

1. Open a PR. Set the title: `fix(scope): description of the fix`.
2. `commit-lint.yml` checks the title — must conform to Conventional Commits.
3. Required CI checks must pass (nextest, clippy, cargo-audit, CodeQL, css-check, proto-check).
4. Obtain ≥ 1 PR review (branch protection enforced).
5. Squash-merge to `main`.
6. `semantic-release.yml` runs once a day at 6:17 AM EST (7:17 AM EDT); only packages whose paths contain changed files get a release. To release before then, start it by hand: `gh workflow run semantic-release.yml --ref main`.
7. A `vX.Y.Z` tag is pushed → `release.yml` builds and publishes signed binaries + Helm chart.

End-to-end time: CI gates → merge → the next daily release run (~5 min) → publish run (~10 min).

## OpenID Foundation conformance run

The OIDF suite needs Docker and about 15 minutes for all three plans (plus the Hearth image
build), so CI does not run it. Run it on `main` before the daily release when the unreleased
changes touch OAuth, OIDC, discovery, client registration or the token, UserInfo or
authorization endpoints, and before each manual release:

```bash
make conformance-oidf-check        # the script's own guards (seconds, no Docker)
make conformance-oidf PLAN=config  # MUST exit 0
make conformance-oidf PLAN=basic   # regression check: compare with the newest report
make conformance-oidf PLAN=dynamic # regression check: compare with the newest report
```

- **Config OP must exit 0.** A failed condition, or a warning or skip with no recorded decision,
  stops the release: fix it, or record a decision in
  `scripts/conformance-oidf/expected-warnings.json` / `expected-skips.json` in a PR.
- **Basic OP and Dynamic OP do not pass today** (see the newest `reports/oidf-conformance-*.md`).
  Compare the failures in `results.txt` with that report. A new failure is a regression: open an
  issue before the release. Whether these plans become a release gate is an owner decision
  (#780, #784).
- Results go to `target/conformance-oidf/<timestamp>/` (`results.txt`, the suite's export and
  the Hearth log). The script stops its own Compose project (`hearth-oidf`) at the end.

## Dry-run verification

To check the computed next version and tag names without a release:

```bash
# On any branch that has commits since the last release tag:
GITHUB_TOKEN=<pat> npx multi-semantic-release \
  --dry-run \
  --packages sdks/typescript sdks/go sdks/python sdks/php .
```

Check that each emitted `tagFormat` exactly matches the trigger pattern in the corresponding publish workflow:

| Package | Emitted tag example | Trigger in workflow |
|---------|--------------------|--------------------|
| server | `vX.Y.Z` | `v[0-9]+.[0-9]+.[0-9]+` in `release.yml`, `helm.yml` |
| TS SDK | `sdk-ts-vX.Y.Z` | `sdk-ts-v*` in `sdk-publish-typescript.yml` |
| Go SDK | `sdks/go/vX.Y.Z` | `sdks/go/v*` in `sdk-publish-go.yml` |
| Python SDK | `sdk-python-vX.Y.Z` | `sdk-python-v*` in `sdk-publish-python.yml` |
| PHP SDK | `sdk-php-vX.Y.Z` | `sdk-php-v*` in `sdk-publish-php.yml` |

## Branch protection requirements (merge gate = release gate)

Configure the following on `main`:

- **Require a pull request before merging** — at least 1 approving review
- **Require status checks to pass before merging** (required-summary job):
  - `nextest` (cargo nextest)
  - `clippy` (clippy -D warnings)
  - `cargo-audit`
  - `CodeQL / security`
  - `css-check` + `proto-check`
  - `required-summary` (gating job — see ci.yml)
- **Require branches to be up to date before merging**
- **Restrict who can push to matching branches** (releases happen via PR only)
- **Do not allow bypass** — even admins must go through PR

## Supply-chain trust (unchanged from prior workstreams)

Continuous deployment does not weaken signing or attestation:
- Binaries: cosign keyless + SLSA L1 (via `release.yml`)
- Container: cosign keyless + CycloneDX SBOM (via `docker.yml`)
- Helm chart: cosign keyless OCI (via `helm.yml`)
- npm packages: OIDC trusted publishing + `--provenance` (via `sdk-publish-typescript.yml`)

## Support window

Only the latest release gets fixes. See [`VERSIONING.md`](../VERSIONING.md#supported-versions).
