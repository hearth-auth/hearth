# Hearth Release Runbook

This document covers how semantic-release governs version bumps, changelogs, and tag creation for the Hearth monorepo.

## Architecture overview

```
PR merged to main (or 1.x / 2.x)
  │
  └─▶ semantic-release.yml
        │  (multi-semantic-release — one run, all packages)
        │
        ├─▶ server root  → tag v1.1.0      ─▶ release.yml   (binaries, SBOM, SLSA)
        │                                  ─▶ helm.yml      (Helm OCI chart)
        ├─▶ sdks/node    → tag sdk-node-v0.0.1 ─▶ sdk-publish-node.yml
        ├─▶ sdks/typescript → tag sdk-ts-v0.0.1 ─▶ sdk-publish-typescript.yml
        ├─▶ sdks/go      → tag sdks/go/v0.1.1  ─▶ sdk-publish-go.yml
        ├─▶ sdks/rust    → tag sdk-rust-v0.2.1 ─▶ sdk-publish-rust.yml
        ├─▶ sdks/python  → tag sdk-python-v0.1.1 ─▶ sdk-publish-python.yml
        ├─▶ sdks/php     → tag sdk-php-v0.0.1  ─▶ sdk-publish-php.yml
        └─▶ sdks/kotlin  → tag sdk-kotlin-v0.1.1 ─▶ sdk-publish-kotlin.yml
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

## Bootstrapping — anchor tags

semantic-release computes the "next" version by looking at the most recent git tag matching each package's `tagFormat`.  Before enabling the live release run, create one anchor tag per package.  See **Version reconciliation** below for the chosen baseline versions and the exact command sequence.

## How a `fix:` ships (normal flow)

1. Open a PR. Set the title: `fix(scope): description of the fix`.
2. `commit-lint.yml` checks the title — must conform to Conventional Commits.
3. Required CI checks must pass (nextest, clippy, cargo-audit, CodeQL, css-check, proto-check).
4. Obtain ≥ 1 PR review (branch protection enforced).
5. Squash-merge to `main`.
6. `semantic-release.yml` fires; only packages whose paths contain changed files get a release.
7. A `v0.1.1` tag (or similar) is pushed → `release.yml` builds and publishes signed binaries + Helm chart.

End-to-end time: CI gates (~5 min) → merge → release run (~5 min) → publish run (~10 min).

## How to cut a backport (maintenance branches)

Maintenance branches are named `1.x`, `2.x`, etc., and map to semantic-release release channels of the same name.

### Setup (once per major line)

```bash
# Create the maintenance branch from the last patch of that major
git checkout -b 1.x v1.9.3   # example: the last v1.x release
git push origin 1.x
```

Branch protection on `1.x` must mirror `main` (required CI green + ≥1 review).

### Backporting a security fix

```bash
# On a feature branch off 1.x
git checkout -b fix/backport-CVE-2026-1234 1.x

# Cherry-pick or re-implement the fix
git cherry-pick <sha-from-main>

# Open a PR targeting 1.x (NOT main)
# PR title: fix(security): backport CVE-2026-1234 (branch protection same as main)
```

On merge to `1.x`:
- `semantic-release.yml` fires on `push.branches: ["1.x"]`
- semantic-release resolves the `1.x` channel, computes `v1.9.4`
- Tags `v1.9.4`, triggers `release.yml`, publishes patch binaries and Helm chart
- DOES NOT change `main`; `main` continues on `v2.x` line

## Version reconciliation — canonical starting versions (Decision D)

`v1.0.0` is the canonical first production release for the server.  The CHANGELOG `[1.0.0]` entry (2026-06-21) is authoritative; the earlier `v0.1.0-rc.*` git tags were provisional pre-release markers from before the versioning scheme was finalised and can be ignored for semantic-release purposes.

Bootstrap steps (run once, **before** enabling semantic-release on main):

```bash
# Tag the commit that corresponds to the [1.0.0] CHANGELOG entry.
# Find it with: git log --oneline --all | grep -i '1.0.0\|HEA-1478'
git tag v1.0.0 <sha-of-1.0.0-commit>

# SDK anchor tags
git tag sdk-node-v0.0.1     <sha>
git tag sdk-ts-v0.0.1       <sha>
git tag sdks/go/v0.1.0      <sha>   # already released; skip if already present
git tag sdk-rust-v0.2.0     <sha>
git tag sdk-python-v0.1.0   <sha>
git tag sdk-php-v0.0.0      <sha>
git tag sdk-kotlin-v0.1.0   <sha>

# Push all anchor tags
git push origin --tags
```

After these anchor tags exist, the first merge to `main` triggers semantic-release, which will produce `v1.1.0` (given the existing `feat:` commits in `[Unreleased]`) and the corresponding SDK version bumps.

| Package | First automated release (after anchor) | Tag format |
|---------|---------------------------------------|-----------|
| server + Helm | `v1.1.0` | `v*` |
| Go SDK | `sdks/go/v0.1.1` | `sdks/go/v*` |
| Node SDK | `sdk-node-v0.0.2` | `sdk-node-v*` |
| TypeScript SDK | `sdk-ts-v0.0.2` | `sdk-ts-v*` |
| Rust SDK | `sdk-rust-v0.2.1` | `sdk-rust-v*` |
| Python SDK | `sdk-python-v0.1.1` | `sdk-python-v*` |
| PHP SDK | `sdk-php-v0.0.1` | `sdk-php-v*` |
| Kotlin SDK | `sdk-kotlin-v0.1.1` | `sdk-kotlin-v*` |

The `Cargo.toml` `version` field is bumped automatically by `@semantic-release/exec` on each server release; the in-binary version is set from the tag via `HEARTH_RELEASE_VERSION` in `build.rs`.

## Dry-run verification

To verify the computed next version and tag names before enabling live releases:

```bash
# On any branch that has commits since the last anchor tag:
GITHUB_TOKEN=<pat> npx multi-semantic-release \
  --dry-run \
  --packages sdks/node sdks/typescript sdks/go sdks/rust sdks/python sdks/php sdks/kotlin .
```

Check that each emitted `tagFormat` exactly matches the trigger pattern in the corresponding publish workflow:

| Package | Emitted tag example | Trigger in workflow |
|---------|--------------------|--------------------|
| server | `v0.1.1` | `v[0-9]+.[0-9]+.[0-9]+` in `release.yml`, `helm.yml` |
| Node SDK | `sdk-node-v0.0.2` | `sdk-node-v*` in `sdk-publish-node.yml` |
| TS SDK | `sdk-ts-v0.0.2` | `sdk-ts-v*` in `sdk-publish-typescript.yml` |
| Go SDK | `sdks/go/v0.1.1` | `sdks/go/v*` in `sdk-publish-go.yml` |
| Rust SDK | `sdk-rust-v0.2.1` | `sdk-rust-v*` in `sdk-publish-rust.yml` |
| Python SDK | `sdk-python-v0.1.1` | `sdk-python-v*` in `sdk-publish-python.yml` |
| PHP SDK | `sdk-php-v0.0.2` | `sdk-php-v*` in `sdk-publish-php.yml` |
| Kotlin SDK | `sdk-kotlin-v0.1.1` | `sdk-kotlin-v*` in `sdk-publish-kotlin.yml` |

## Branch protection requirements (merge gate = release gate)

Configure the following on `main` (and mirror on `1.x`, `2.x`):

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
- npm packages: OIDC trusted publishing + `--provenance` (via `sdk-publish-{node,typescript}.yml`)

## Support window

Latest 2 major lines are maintained. When `v3.x` ships, `v1.x` reaches end-of-life and its maintenance branch is archived (no further cherry-picks; only critical CVEs subject to CTO exception).
