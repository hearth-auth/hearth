# HEA-889 — Local CI Plan

**Status:** plan-only, awaiting approval
**Owner:** CTO
**Revision:** v1 (2026-05-27)

---

## 1. Problem we're actually solving

The dev pain is **not** "we don't run tests locally." It's that the dev loop
diverges from CI in three specific ways the recent `fix(ci)` commits make
plain:

1. **Binary-boot + SDK round-trip is skipped locally.** HEA-884 caught a CSP
   regression in `security.rs`, a wrong JWKS URL in the Go example, and a
   wrong admin endpoint in the TS example. None of those surface in
   `cargo test` — they only fail when the SDK example boots the real binary
   and calls it. Today, only `sdk-smoke.yml` runs that path.
2. **Toolchain drift between dev box and runner.** HEA-885 was protoc missing
   from `sdk-smoke.yml`'s `build-hearth` job. The dev box has protoc; the
   runner did not. A local-CI tool that runs the workflow as a fresh
   container would have caught this before push.
3. **`make check` doesn't equal the `quality` job.** The `quality` job also
   runs `make test-quality`, `make css-check`, `make proto-check`,
   `cargo deny check`, and the anti-pattern script. Developers run `make
   check` (clippy + fmt + nextest), assume green, and lose 20 minutes on a
   CI red they could have caught in 90 seconds.

Goal: a single command — `make ci-local` — that reproduces the **PR-blocking**
CI surface (`ci.yml` + `sdk-smoke.yml`) deterministically, in <10 minutes,
on a fresh worktree.

Out of scope: `release.yml`, `docs-site.yml`, `security.yml` CodeQL,
`bench-regression.yml`, `ui-nightly.yml` cross-browser matrix, `fuzz.yml`.
These are scheduled, tag-triggered, or informational and are not the source
of the pain.

## 2. Option survey

### Option A — `nektos/act`

**What it is.** Runs GitHub Actions workflows in Docker containers locally
by translating `runs-on: ubuntu-latest` to a community-maintained
`catthehacker/ubuntu` image.

| Pros | Cons |
|---|---|
| Reads our existing `.github/workflows/*.yml` unchanged | Image is huge (~18 GB full, ~2 GB slim); first pull is slow |
| Replicates matrix, paths-filter, job DAG, artifact upload/download, `GITHUB_*` envs natively | OIDC, Pages deploy, SLSA reusable workflows do not work — must skip release.yml/docs-site.yml |
| Single binary, no DSL to learn, no new config to maintain | Some actions misbehave on the slim image (e.g., `dtolnay/rust-toolchain` works; `taiki-e/install-action` sometimes needs cache priming) |
| Aligns 1:1 with the workflows our PRs are gated on | macOS legs in `release.yml` cannot be run locally regardless |
| Re-uses our existing composite action (`.github/actions/setup-rust`) | Docker-on-Linux only for full fidelity; macOS host = nested virt overhead |

**Cost to adopt:** ~1 day. Pin `act` version, ship `.actrc` with image
choice + `--bind` for workspace, add `make ci-local` target. No workflow
edits required.

**Caught how many recent breakages?** All five `fix(ci)` categories from the
audit. The protoc-missing one (HEA-885) is the canonical case: act mounts a
fresh container, runs the workflow steps as written, and would have
reported protoc missing exactly as CI did.

### Option B — `dagger/dagger`

**What it is.** A programmable CI engine. Pipelines are written as code
(Go, Python, TypeScript) against the Dagger SDK; Dagger orchestrates
ephemeral containers via BuildKit. Runs locally and in CI.

| Pros | Cons |
|---|---|
| Pipelines are unit-testable; can share modules between dev and CI | We would write our pipeline twice — once in `.github/workflows/*.yml` (until we cut over), once in Dagger SDK |
| Strong content-addressed caching; BuildKit layer reuse across runs | Adoption cost is multi-week, not multi-day |
| Composable across machines and CI providers — vendor-neutral by design | Net-new DSL/SDK that the team has to learn and maintain |
| Excellent for monorepos with polyglot toolchains | Our toolchain is already 90% Rust + a thin Node/Go SDK rim — the polyglot story doesn't pay off |
| Better than act for "shift CI left into local dev as a first-class story" | Replaces GitHub Actions as the source of truth, or accepts dual maintenance |

**Cost to adopt:** 2–3 weeks for parity with current `ci.yml` + `sdk-smoke.yml`.
Plus an ongoing maintenance tax of keeping the Dagger pipeline and GHA
workflows in sync, or a flag-day migration to Dagger-on-GHA-runners.

**Caught how many recent breakages?** Same as act, *after* we've ported the
pipelines. Before then: zero.

### Option C — Improve the Makefile, add a meta-target

**What it is.** Add `make ci-local` that runs:

```
make test-quality      # HEA-571 anti-pattern script
make check             # clippy --all-targets -- -D warnings + fmt + nextest
make css-check
make proto-check
cargo deny check
scripts/check-sdk-conformance.sh
make sdk-smoke-local   # NEW: build, boot binary, run TS + Go examples
```

| Pros | Cons |
|---|---|
| Zero new tooling, zero new image to maintain | Does not protect against toolchain drift — if the dev box has protoc, the dev box won't catch a workflow that forgot to install it |
| Fastest to ship (a few hours), fastest to run (~5 min cold) | Cannot replicate matrix legs (e.g., `sdk-node` Node 18 vs 20) without nvm gymnastics |
| Devs already understand `make` | Doesn't reproduce paths-filter routing or the `required-summary` gate |
| Aligns with our existing "Makefile is the substrate" pattern | Will not help when CI fails because a *workflow file* is wrong (HEA-885 protoc, HEA-884 SDK paths) |

**Cost to adopt:** half a day. **Caught how many recent breakages?** Three
of five categories. Misses HEA-885 (toolchain drift) and HEA-884's SDK
endpoint divergence (because dev's `make sdk-smoke-local` would also be
wrong in the same way the workflow was — same author, same bug).

### Option D — Hybrid (recommended): `act` for fidelity + Makefile meta-target for speed

Two commands, two purposes:

- `make ci-local-fast` (Option C): the 5-minute "I'm about to push" loop —
  runs Makefile targets directly on the host. Catches the 80% case.
- `make ci-local-full` (Option A): the 10–15 minute "the fast loop went green
  but CI just failed and I don't know why" loop — runs `act` against the
  consolidated `ci.yml` + `sdk-smoke.yml` in containers. Catches toolchain
  drift, workflow-file bugs, and missing-step bugs.

This matches the actual two-mode dev workflow: quick checks before push,
full reproduction when CI surprises us.

## 3. What about the other options we considered briefly

- **GitLab CI Runner local mode** — abandoned; GitLab has deprecated local
  exec and we don't use GitLab.
- **Earthly** — interesting Bazel-ish target language, but same dual-maintenance
  cost as Dagger plus a smaller community. Reject for the same reason as
  Dagger.
- **`gh act` plugin** — wrapper around act, no material difference.
- **Self-hosted runners on dev machines** — solves nothing; the failure
  surface is `ubuntu-latest`'s pinned image, not the runner.

## 4. Recommendation

Adopt **Option D (Hybrid)**. Stage in two PRs:

### PR-1 — Makefile meta-target (`make ci-local-fast`)

- New target `ci-local-fast` that runs the seven steps from Option C
  serially with `set -e`.
- New target `sdk-smoke-local`: build `target/debug/hearth`, boot
  `--dev` in the background on a random port, bootstrap, run the TS
  example, run the Go example, tear down. Reuse the scripts already in
  `examples/`.
- Update `CLAUDE.md` § "Development Commands" with the new targets.
- Cost: ~½ day. Zero new dependencies.

### PR-2 — `act`-based full reproduction (`make ci-local-full`)

- Add `.actrc` pinned to `catthehacker/ubuntu:act-22.04` (matches
  `ubuntu-latest` we use today; the `-full` variant has protoc, buf,
  node, go preinstalled — minimises step-level installs).
- Add `make ci-local-full` target: `act pull_request -W .github/workflows/ci.yml -W .github/workflows/sdk-smoke.yml`
  with `--container-architecture linux/amd64` and `--artifact-server-path`.
- Document required local install: `brew install act` (macOS) or
  `gh extension install nektos/gh-act` (cross-platform).
- Pin `act` minor version in `.tool-versions` (mise/asdf) so all devs
  run the same binary.
- Cost: ~1 day, mostly debugging which steps need slim-image tweaks.

### PR-3 (deferred, optional)

If after one month of PR-1+PR-2 in use, we still see "passes locally,
fails in CI" with frequency > 1/week, escalate to Dagger and pay the
multi-week port. Set the bar concretely: count CI-only failures in a
month, decide on data.

## 5. Risks and mitigations

| Risk | Mitigation |
|---|---|
| `act` image diverges from real `ubuntu-latest` over time | Pin both image tag and `act` version in `.actrc` and `.tool-versions`; bump quarterly with explicit verification |
| Devs run `ci-local-fast` and assume `ci-local-full` is unnecessary | Make the fast target's exit message print "for full reproduction, run `make ci-local-full`"; surface in `CONTRIBUTING.md` |
| Docker-on-macOS performance overhead | Document that `ci-local-full` is the "deep" check, not the per-commit loop |
| OIDC-gated jobs (cosign, SLSA, Pages) silently skipped | Explicit `--workflows` allowlist that names only ci.yml + sdk-smoke.yml; document the exclusion list in the Makefile target's help text |
| Toolchain installs in workflows are slow under `act` (no warm runner cache) | Use `act-22.04-full` image variant (preinstalls protoc, node, go); accept ~10 min cold runs as the price of fidelity |

## 6. Success criteria

- A clean clone of `hearth` runs `make setup && make tailwind-install && make ci-local-fast` green in <6 minutes.
- A workflow-level bug (e.g., remove `Install protoc` step from `ci.yml`) is caught by `make ci-local-full` before merging.
- One month after rollout: count of `fix(ci)` commits per month drops measurably from the current baseline (avg ~5/month in the last 30 days per `git log --grep='fix(ci)'`).

## 7. Non-goals

- Replacing GitHub Actions as the canonical CI source of truth.
- Local reproduction of `release.yml`, `docs-site.yml`, `security.yml`
  CodeQL, scheduled `ui-nightly.yml`, `bench-regression.yml`, `fuzz.yml`.
- macOS/Windows matrix legs (we don't have any in PR-blocking workflows).
- Removing or rewriting any existing workflow files.

## 8. Open questions for approval

1. Approve PR-1 + PR-2 as a single tracking issue with two child issues, or
   approve PR-1 first and defer PR-2 until PR-1 is in use for two weeks?
2. Is `act` an acceptable runtime dependency for contributors, or must the
   "fast" target alone be sufficient for non-core contributors?
3. Should the `ci-local-full` target run on the pre-push hook (gated by an
   env var, opt-in) or remain manual-only?
