# hearth-loadtest

Load-testing harness for the Hearth identity server, built on
[goose](https://book.goose.rs/). Tracks the load-test plan in
[HEA-1787](/HEA/issues/HEA-1787).

## Why this crate is excluded from the workspace

`hearth-loadtest` is **not** a workspace member — the root `Cargo.toml`
declares `exclude = ["loadtest"]`. goose pulls in a large transitive
dependency tree (an async HTTP client, reqwest, tooling for reports) that we
do not want compiled on every `cargo nextest run --workspace`, which would
slow the unit-test gate for no benefit. The crate is `publish = false` and is
built/run explicitly instead.

## Building and running

```bash
make loadtest              # cargo run --release -p hearth-loadtest -- ...
make loadtest-check        # cargo check (keeps it from rotting)
make seed ARGS="..."       # run the seed step (see below)
```

Or directly:

```bash
cargo run --release --manifest-path loadtest/Cargo.toml -- seed --help
# unit tests (the crate is workspace-excluded, so run them explicitly):
cargo test --manifest-path loadtest/Cargo.toml
```

## Seed step (HEA-1789)

Load numbers are meaningless against an empty database, so before a run the
harness seeds a **deterministic, parameterized** corpus and persists a JSON
**seed-handle** that Goose users draw real, live credentials from.

```bash
# 1. Start a dev instance (separate terminal):
make dev

# 2. Seed it (defaults mirror the plan):
make seed ARGS="--users-per-realm 500 --sessions-frac 0.5 --revoked-frac 0.1"
```

### Parameters

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--target-host` | `HEARTH_LOADTEST_TARGET_HOST` | `http://127.0.0.1:8420` | Running Hearth to attach to |
| `--realms` | `HEARTH_LOADTEST_REALMS` | `5` | Realms to seed (see constraint below) |
| `--users-per-realm` | `HEARTH_LOADTEST_USERS_PER_REALM` | `200` | User records per realm |
| `--sessions-frac` | `HEARTH_LOADTEST_SESSIONS_FRAC` | `0.5` | Fraction of users given a live token |
| `--revoked-frac` | `HEARTH_LOADTEST_REVOKED_FRAC` | `0.1` | Fraction of live tokens pre-revoked |
| `--seed` | `HEARTH_LOADTEST_SEED` | `1` | Determinism seed (reproducible corpus) |
| `--seed-out` | `HEARTH_LOADTEST_SEED_OUT` | `loadtest/reports/seed-handle.json` | Seed-handle output path |

The dataset shape is echoed to stdout and stored in the seed-handle so every
report can describe the corpus it ran against. The same `--seed` always
produces the same emails and (ephemeral, never-persisted) passwords.

## ⚠️ Security warnings (read before running)

- **Dev / loopback only.** The seed step calls `POST /admin/bootstrap`, mints
  live tokens, and revokes them. Point it **only** at a local dev instance
  (`--dev` mode, loopback address). Never at a shared or production instance —
  it would create real users and tokens and could exhaust admin rate limits.
- **The seed-handle holds live bearer tokens.** It is written owner-only
  (`0600`) into `loadtest/reports/`, which is **git-ignored**. Do not commit
  it, paste it into issues/logs, or move it outside that directory.
- **Secrets are never logged or persisted where they shouldn't be.** The admin
  bootstrap token stays inside the HTTP client only; seeded passwords are
  deterministic and discarded; `SeededToken`'s `Debug` redacts the token.

## Server-capability constraints (important)

Two mechanisms the plan assumed are **not available** on the current REST
surface, so the boot-local seed is narrower than the plan text:

1. **`POST /admin/realms` is disabled** (`405`; realms are declared in
   `hearth.yaml`). The boot-local path seeds only the single dev realm that
   bootstrap creates; `--realms > 1` is clamped to 1 with a warning.
2. **`POST /admin/users` cannot set a password**, so admin-created users have
   no credential and cannot drive the ROPC (`/token` password grant) journey.
   Live tokens are therefore minted for the well-known dev admin
   (`admin@dev.local`), giving many live sessions for one subject. The seeded
   user *records* still populate a realistic `lookup_user` / session-count
   corpus.

### Large / multi-subject corpus (`--target-host` attach path)

For a realistic multi-realm, multi-subject corpus, boot the large-scale demo —
which pre-provisions realms and millions of users **with passwords** via
`hearth.yaml` reconcile seed users — then attach the harness to it:

```bash
make seed-large        # boots ./data/demo with examples/large-scale-demo/hearth.yaml
make seed ARGS="--target-host http://127.0.0.1:8420 --users-per-realm 1000"
```

Wiring per-subject ROPC across the demo users (so live tokens span many
subjects) is a follow-up; the deterministic per-user credential API
(`SeedParams::user_password`) already exists for it.

## Status

Seed step implemented (HEA-1789). Auth-flow, token-validation, session-lookup,
and RBAC-check Goose scenarios are added in follow-up issues under HEA-1787.
