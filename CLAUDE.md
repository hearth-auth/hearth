# Hearth — Development Rules

Hearth is a purpose-built identity database: a single-binary Rust server for authentication, claims-based RBAC authorization, and session management with a custom embedded storage engine. Targets sub-millisecond p99 latency on the hot path.

## Ground Rules (ALWAYS follow)

### Code search — prefer Reflex

Reflex MCP tools (`mcp__reflex__*`) index this repo. Prefer them over `grep`/`glob` for finding code: `search_code` (literal text), `search_regex`, `find_references` (definition + call sites), `get_dependents` (who imports a file). Use `grep` for hidden paths (`.github/`, `.githooks/`), which Reflex does not index. On `Index not found`, run `mcp__reflex__index_project` and retry.

### Commands

| Command | What it does |
|---------|-------------|
| `make check` | clippy + fmt + nextest — run before every PR |
| `make test` | `cargo nextest run --workspace --features hearth/dev-endpoints` |
| `make test-detached` | The full suite, detached — **agents MUST use this for full runs** (see "Long-running commands") |
| `make clippy` | clippy `--all-targets -D warnings`, without and with `dev-endpoints` |
| `make ci-local-fast` | Host-side mirror of PR-blocking CI — run before push |
| `make dev` | `cargo run --features dev-endpoints -- serve --dev` on `127.0.0.1:8420`, data in `./data/dev`; open `/dev` to sign in with one click; mailcatcher at `/dev/mail` |

Every other command (UI tests, coverage, load tests, seeding, scratch pruning), first-clone setup, the dev console and dev accounts, and the (automatic) release procedure: [`docs/dev/DEVELOPMENT.md`](docs/dev/DEVELOPMENT.md).

**Build prerequisites:** `PROTOC` must point to `protoc`; `buf` is required (pre-commit hook and CI); `ui/tailwindcss` for CSS changes (`make tailwind-install`); `hearth.yaml` is gitignored — copy `hearth.example.yaml`.

**`dev-endpoints`** is not a default feature: it compiles in `/admin/bootstrap`, `/dev/seed-*` and the dev admin password. A bare `cargo nextest run` compiles the bootstrap-dependent tests out — pass `--features dev-endpoints`. `--dev` storage does not fsync.

**Admin API gotchas:** every `/admin/*` route needs `X-Realm-ID` (without it: `400`, not `401`). The system realm (nil UUID) always requires MFA: in dev, sign in from `/dev` (one click, or its live TOTP code).

### UI changes

Before pushing a change to templates, admin handlers or `src/protocol/web/`, run `make ui-test-smoke` and `make ui-test-accessibility` against a running `make dev` (details in `docs/dev/DEVELOPMENT.md`).

## Reference Documents

Read these before writing code. They are the canonical source of truth.

### Normative specs — OpenSpec

What Hearth MUST do lives in `openspec/specs/<capability>/spec.md`, one capability per folder
(`openspec list --specs`). Change a spec only through an OpenSpec change (`/opsx:propose`); the
change's delta specs merge into `openspec/specs/` when it is archived. Until then, the delta
specs of the active changes in `openspec/changes/` are part of the contract too.

| Area | Capabilities |
|------|--------------|
| Authorization | `rbac-model`, `rbac-token-claims`, `rbac-admin-api`, `custom-permissions`, `credential-hashing` |
| OAuth 2.0 / OIDC | `oidc-provider`, `client-authentication`, `dpop`, `rp-initiated-logout` |
| Agent auth | `agent-identity`, `mcp-authorization`, `delegated-authorization`, `tool-permissions`, `agent-approvals` |
| Other | `saml-sp-profile`, `sdk-support-contract`, `abuse-prevention`, `ui-routing`, `performance-budgets` |

### Contributor docs

- `docs/dev/ARCHITECTURE.md` — structural rules (MUST/SHOULD per RFC 2119).
- `docs/dev/CONSISTENCY.md` — cluster consistency model: write, read, revocation and clock promises with status, open items (G1–G9), Jepsen test mapping.
- `docs/dev/DEVELOPMENT.md` — all `make` targets, first-clone setup, dev bootstrap + browser login recipe, release cut.
- `docs/dev/TESTING.md` — eight testing layers, TDD workflow, tooling, CI tiers.
- `docs/dev/PROTO.md` — **proto authoring guide.** RPC naming, `google.api.http` conventions, `json_name`, backward-compat rules. Read before touching `proto/`.
- `docs/dev/THEME.md` — mandatory design theme for all UI code.
- `docs/guides/configuration-reference.md` — full `hearth.yaml` reference.
- `docs/vision/VISION.md` — design rationale, performance targets, competitive positioning.

## Workspace Structure

Two crates in the workspace:

| Crate | Path | Purpose |
|-------|------|---------|
| `hearth` | `.` | Main binary + library (`src/main.rs`, `src/lib.rs`) |
| `hearth-simulation` | `simulation/` | Real-thread crash-recovery simulation tests (`FaultFs`), depends on `hearth` with `features = ["test-hooks"]` |

Generated proto code lives at `src/protocol/generated/` (gitignored, produced by `build.rs` on every `cargo build`). Proto sources at `proto/` are the single source of truth.

### Git Hooks

`make setup` enables `.githooks/`. The pre-commit hook runs `cargo fmt` + clippy on staged Rust, regenerates SDK types when `proto/**/*.proto` is staged, and rebuilds `app.css` when UI files are staged (details: `CONTRIBUTING.md`).

## Architecture

### Layer Structure

Six modules with strict downward dependency flow:

| Layer | Path | Role |
|-------|------|------|
| Core | `src/core/` | Shared types and traits only. No logic, no state, no I/O. |
| Protocol | `src/protocol/` | Wire adapters (REST, OIDC, SAML, SCIM). Stateless, thin. |
| Identity | `src/identity/` | Domain logic. Users, credentials, sessions, realms, tokens. |
| RBAC | `src/rbac/` | Claims-based RBAC. Resolves effective permissions for JWT claims. |
| Cluster | `src/cluster/` | Raft consensus via `openraft`. Invisible in single-node mode. |
| Storage | `src/storage/` | WAL, memtable, SSTs, tiered storage. Leaf layer. |

**Rules:**
- Dependencies flow strictly downward. No layer imports from above.
- One lateral exception: `identity/` may call `rbac/` during token issuance. Never the reverse.
- Every layer may depend on `core/`.
- `mod.rs` contains ONLY trait definitions, re-exports, and module declarations. No implementation.
- Internal types default to private. `pub(crate)` where necessary.

### Hot Path Rules

Hot path = `validate_token()`, `lookup_session()`, `lookup_user()` when data is in hot tier. Authorization is NOT on the hot path (permissions are embedded in the JWT at issue time).

Hot path code MUST obey ALL of:
1. **Zero heap allocations** — no `Box::new`, `Vec::new`, `String::from`, `format!()`, `to_string()`. One exception: `EpochCell`'s epoch-collector bookkeeping while cells are being written (at most 1 allocation per 1,024 loads per thread; see `docs/dev/ARCHITECTURE.md` §3.2). No other allocation, amortised or not.
2. **No syscalls for reads** — serve from memory-mapped structures or in-process data.
3. **No locks on read path** — no mutexes, no `RwLock` write locks. Use epoch-based reclamation.
4. **No yielding** — MUST NOT `.await` on I/O. Complete synchronously.

Everything else (user creation, hashing, token issuance, WAL writes, admin ops) is off the hot path.

### Storage Engine

- WAL MUST be `fsync`'d before acknowledging any write. Must survive `kill -9`.
- Every storage operation requires a `RealmId` parameter (newtype, not raw string).
- All keys are prefixed with realm ID. Scans bounded to a single realm.

## TDD Workflow (Mandatory)

1. Write a failing test that describes expected behavior.
2. Run it — confirm it fails (red).
3. Write the minimal implementation to make it pass (green).
4. Refactor while keeping tests green.
5. Add a black box test through the public API if applicable.

**A PR without a test written *before* the implementation is incomplete.**

Avoid false-confidence anti-patterns (vacuous `is_ok()`/`is_err()` asserts, zero-assert test bodies, stale ignores, etc.) — see `docs/dev/TESTING.md` § "Test Quality Anti-Patterns" for the full A–I taxonomy.

### Testing Tooling

- **Test runner**: `cargo nextest` only — never `cargo test`.
- **Watch mode**: `bacon test` for TDD loop.
- **Long-running commands (agents): run them detached.** Claude Code's background-task
  monitor stops a *background* Bash command when the host's free memory is low, and it
  counts reclaimable page cache (the cargo target dir) as used. It kills
  `cargo nextest run --workspace` while tens of GB are still available. So:
  - For the full suite, use `make test-detached`. For any other command that can run
    longer than the 10-minute foreground limit (a `--workspace` build, clippy on
    `--all-targets`, `make loadtest-smoke`, `make bench-gate`), use
    `scripts/run-detached.sh run <name> -- <command>`.
  - The command then belongs to the user's systemd manager, not to the Bash tool. If the
    waiting call is stopped, the command keeps running: continue with
    `scripts/run-detached.sh wait <id>` (the id is printed at start, the log path with
    `scripts/run-detached.sh log <id>`).
  - Do **NOT** start these as `run_in_background` Bash tasks, and do **NOT** work around
    the monitor by splitting the suite into one cargo run per test binary. One
    `--workspace` pass is much faster: nextest runs every binary's tests in parallel.
  - Short, targeted runs (`--lib <filter>`, one `--test <name>`) stay in the foreground.
  - Always pass `--no-fail-fast` to a full run (`make test-detached` does).
- **No doctests — ever.** No `/// ```rust` fenced blocks in doc comments. Use `#[cfg(test)] mod tests` blocks or `tests/`. Runnable examples live under `examples/`.
- **Property tests**: `proptest` (256 cases dev, 10k+ CI).
- **Simulation**: real-thread crash-recovery tests (`hearth-simulation` crate) using `FaultFs` fault injection; no deterministic scheduler.
- **Black box tests**: `TestHarness` (`tests/common/mod.rs`) — in-process + server modes.

## Code Style

- `clippy::pedantic` MUST pass (enforced via `-- -D warnings`). Allowed lints in `Cargo.toml`/`clippy.toml`.
- `clippy::unwrap_used` is **denied**. `unwrap()` permitted ONLY with `#[allow(clippy::unwrap_used)]` + `// INVARIANT:` comment. `expect()` only in tests and startup.
- `rustfmt` with `rustfmt.toml` (max_width=100, edition=2021).
- All `pub`/`pub(crate)` items MUST have doc comments.
- **No `println!`, `eprintln!`, or `log` crate.** Use `tracing` only.
- Hot path MUST NOT log at `info` or above in steady state.
- MUST NOT log passwords, tokens, keys, or PII.
- Entity IDs are newtypes: `UserId(Uuid)`, `RealmId(Uuid)`, etc. No `Deref` — use `.as_uuid()`.
- Sensitive data (passwords, tokens, keys) wraps in `Zeroize`-on-drop types; MUST NOT implement `Debug`/`Display`/`Serialize` revealing contents.

### Error Handling

- Each layer defines its own error enum (`#[non_exhaustive]`, `Error` + `Display`).
- Errors MUST NOT cross layer boundaries as concrete types — convert via `From`.
- Error messages MUST NOT contain sensitive data.

## Security

- **Signing**: Ed25519 for everything Hearth issues and validates. RS256 is permitted only for ID tokens, when a client requests it via `id_token_signed_response_alg` (OIDC Core interop). No HS256, no `alg:none`.
- **Password hashing**: Argon2id, OWASP parameters. Off hot path.
- **Crypto**: `ring` or `RustCrypto`. No hand-rolled crypto. Constant-time secret comparisons.
- **Input validation**: Each layer validates its own invariants. Must not assume upstream validated.
- Every `unsafe` block MUST have a `// SAFETY:` comment. No `unsafe` in protocol or identity layers.
- No `lazy_static` — use `std::sync::OnceLock` or `LazyLock`.
- `Mutex` MUST NOT be held across `.await` points.

## UI Theme (MANDATORY)

All UI code MUST comply with `docs/dev/THEME.md`. Read it before touching anything in `templates/ui/`.

**Key rules:**
- **Dark-mode only.** No light mode, no `dark:` Tailwind prefixes, no theme toggle.
- **Color tokens** from `ui/tailwind.config.js`. Never use raw hex outside the config.
- **Typography**: Fraunces (display), Manrope (body/UI), JetBrains Mono (code/labels).
- **Ember gradient** (`btn-ember`) appears at most once per visible region.
- **Borders**: alpha-based white (`border-white/6`), not solid grays.
- **Primary text**: `graphite-50` (`#f5f1e8`), never `#ffffff`.
- Rebuild Tailwind after CSS/template changes: `cd ui && ./tailwindcss -i input.css -o ../src/protocol/web/assets/app.css --minify`

## Async Model

- **Tokio only.** No other async runtime.
- Blocking operations (file I/O, crypto hashing) use `spawn_blocking`.
- Config is immutable after startup — loaded into `Arc<Config>`.

## Dependency Policy

- New deps must be justified, pass `cargo-audit`, and have compatible license (Apache 2.0/MIT/BSD/MPL-2.0).
- Bans: no ORM, no `lazy_static`, no `async-trait` on hot path, no `reqwest` in production.

## Changelog Process

Every PR that ships a user-visible change **MUST** include a `CHANGELOG.md` entry written at implementation time — not after review, not at release. "User-visible" means any new or changed HTTP endpoint, config key, CLI flag, SDK surface, or security fix.

### Entry format

Entries go under `## [Unreleased]` in `CHANGELOG.md`, in the appropriate category:

| Category | When to use |
|----------|-------------|
| `### Added` | New endpoint, config key, CLI flag, feature, or SDK method |
| `### Changed` | Behavioral change to an existing surface (including breaking changes) |
| `### Fixed` | Bug fix visible to operators or integrators |
| `### Security` | Any security fix, hardening, or CVE remediation |
| `### Removed` | Deleted endpoint, config key, CLI flag, or SDK method |

Write entries from the operator/integrator perspective, not the implementation perspective. One bullet per logical change; reference the issue or PR number in parentheses when relevant (e.g., `(HEA-501)`).

### What does NOT need a changelog entry

- Refactoring with no behavior change
- Test additions or test fixes
- CI/tooling/build changes with no operator-visible effect
- Doc-only PRs

The release-cut procedure is in `docs/dev/DEVELOPMENT.md`.
