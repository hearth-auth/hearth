[![CI](https://github.com/hearth-auth/hearth/actions/workflows/ci.yml/badge.svg)](https://github.com/hearth-auth/hearth/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hearth-auth/hearth/badge)](https://scorecard.dev/viewer/?uri=github.com/hearth-auth/hearth) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0) [![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange)](https://www.rust-lang.org/) ![v1.6.10](https://img.shields.io/badge/status-v1.6.10-brightgreen)

# Hearth — a purpose-built identity database

**Identity is a database problem. Hearth is the database.**

Every other identity provider is an application sitting on top of a generic database — Keycloak on Postgres, Ory split across four binaries, Auth0 on its managed stack. That architecture is why auth is slow, operationally heavy, and fragile. Hearth inverts it: the storage engine is specialized for the identity access pattern, and the OAuth/OIDC/RBAC surfaces are thin protocol adapters on top. That's why it ships as one process instead of four.

---

**Sub-millisecond p99 (engine plane) · One binary · Zero external dependencies**

Token validation, session lookup, and permission checks run in-process against lock-free in-memory structures (`ArcSwap<HashMap>`) — no network hop, no cache round-trip, no database query on the hot path. Deploy as a single binary with one config file and a data directory. No Postgres to provision, no Redis to invalidate, no policy service to operate.

> **Stable 1.6.10:** APIs and on-disk formats are stable. See [CHANGELOG](CHANGELOG.md) for the full release history.

---

## Install

Download pre-built v1.6.10 artifacts from the [Releases page](https://github.com/hearth-auth/hearth/releases/tag/v1.6.10), or use Docker or Helm.

### Released binary — Linux / macOS

```bash
# Example: Linux x86_64. Swap the filename for your platform:
#   hearth-linux-amd64 | hearth-linux-arm64
#   hearth-darwin-amd64 | hearth-darwin-arm64
ARTIFACT=hearth-linux-amd64

BASE=https://github.com/hearth-auth/hearth/releases/download/v1.6.10

curl -LO "${BASE}/${ARTIFACT}"
curl -LO "${BASE}/SHA256SUMS"
curl -LO "${BASE}/SHA256SUMS.sig"
curl -LO "${BASE}/SHA256SUMS.pem"

# 1. Verify the checksum manifest itself. Requires cosign v2+
#    (brew install cosign). Without this step the checksum below proves
#    nothing: anyone who can replace the binary can replace SHA256SUMS
#    beside it. The signature is bound to Hearth's release workflow and
#    logged to Sigstore's public transparency log, so it cannot be forged.
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature   SHA256SUMS.sig \
  --certificate-identity-regexp \
    '^https://github\.com/hearth-auth/hearth/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

# 2. Check the binary against the now-trusted manifest.
#    macOS has no sha256sum — use: shasum -a 256 -c SHA256SUMS --ignore-missing
sha256sum -c SHA256SUMS --ignore-missing

chmod +x "${ARTIFACT}"
"./${ARTIFACT}" --version
```

> Run step 1. On its own, `sha256sum -c` only proves the file you downloaded matches
> the manifest you downloaded from the same place. See
> [docs/guides/verify-release.md](docs/guides/verify-release.md) for per-binary signature
> and SLSA provenance verification.

### Released binary — Windows

```powershell
Invoke-WebRequest `
  -Uri "https://github.com/hearth-auth/hearth/releases/download/v1.6.10/hearth-windows-amd64.exe" `
  -OutFile hearth-windows-amd64.exe
foreach ($f in 'SHA256SUMS','SHA256SUMS.sig','SHA256SUMS.pem') {
  Invoke-WebRequest `
    -Uri "https://github.com/hearth-auth/hearth/releases/download/v1.6.10/$f" `
    -OutFile $f
}

# 1. Verify the checksum manifest itself (cosign v2+). Without this the
#    checksum below proves nothing — see the note under the Linux/macOS block.
cosign verify-blob `
  --certificate SHA256SUMS.pem `
  --signature   SHA256SUMS.sig `
  --certificate-identity-regexp `
    '^https://github\.com/hearth-auth/hearth/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$' `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com `
  SHA256SUMS

# 2. Check the binary against the now-trusted manifest.
$expected = (Select-String 'hearth-windows-amd64.exe' SHA256SUMS).Line.Split(' ')[0]
$actual   = (Get-FileHash hearth-windows-amd64.exe -Algorithm SHA256).Hash.ToLower()
if ($expected -eq $actual) { "OK" } else { throw "CHECKSUM MISMATCH" }

.\hearth-windows-amd64.exe --version
```

### Docker — multi-arch (linux/amd64 + linux/arm64)

> **Known gap — these two commands do not work anonymously today.** Both GHCR packages
> (`hearth-auth/hearth` and `hearth-auth/charts/hearth`) are still **private**: an
> unauthenticated manifest fetch answers `401`, re-verified 2026-09-21. `docker pull` and
> `helm install` below therefore fail at the first request unless you
> `docker login ghcr.io` with an account that has read access. Release validation now gates on
> an anonymous fetch (`scripts/check-install-paths.sh`), so newly published versions will be
> public, but flipping the two existing packages needs a token with `write:packages` and has
> not been done. Until then, use the released binary above or build from source. The claim
> that these are turnkey public install paths is withdrawn, not restated.

```bash
docker pull ghcr.io/hearth-auth/hearth:v1.6.10

# Dev mode — in-memory store, no data persistence (Linux only; --dev requires loopback bind)
docker run --rm --network=host ghcr.io/hearth-auth/hearth:v1.6.10 serve --dev
curl -fsS http://127.0.0.1:8420/health   # → {"status":"ok"}
```

> **Mac / Windows Docker Desktop:** `--network=host` does not map to the host loopback on Docker Desktop. Use the Docker Compose stack (`deploy/docker-compose.yml`) for a cross-platform setup, or run from source (`cargo run -- serve --dev`).

### Helm OCI chart (signed)

```bash
helm install hearth oci://ghcr.io/hearth-auth/charts/hearth \
  --version 1.6.10 \
  --namespace auth \
  --create-namespace
```

The chart is cosign-signed (keyless OIDC). To verify:

```bash
cosign verify \
  --certificate-identity-regexp \
    '^https://github\.com/hearth-auth/hearth/\.github/workflows/helm\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/hearth-auth/charts/hearth:1.6.10
```

For signature and SLSA provenance verification of binaries, see [docs/guides/verify-release.md](docs/guides/verify-release.md). For production deployment (systemd, Docker Compose, Kubernetes), see [`deploy/README.md`](deploy/README.md).

---

## Try it in 30 seconds

```bash
cargo build --release
./target/release/hearth serve --dev          # in-memory store, binds 127.0.0.1:8420
curl -fsS http://127.0.0.1:8420/readyz       # → {"status":"ready","storage":"ok"}
curl -X POST http://127.0.0.1:8420/admin/bootstrap | jq .
```

The bootstrap call returns a realm, an admin user, and a signed JWT — everything you need to drive the OAuth flow immediately:

```json
{
  "realm_id":            "01234567-89ab-cdef-0123-456789abcdef",
  "user_id":             "fedcba98-7654-3210-fedc-ba9876543210",
  "access_token":        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...",
  "refresh_token":       "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...",
  "quickstart":          "# ready-to-paste shell commands (dev only)",
  "admin_password":      "HearthTest123!",
  "system_access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...",
  "system_realm_id":     "00000000-0000-0000-0000-000000000000"
}
```

`admin_password` is only populated on the **first** bootstrap call — store it securely, it is never returned again. Re-bootstrap (when the dev-realm already exists) requires the `Authorization: Bearer <access_token>` header from the first bootstrap and returns `"admin_password": null` (JSON null, not `""` — `jq -r .admin_password` prints the string `null`).

> **No Docker, no Postgres, no config required** — `--dev` mode is fully self-contained. The bootstrap endpoint is disabled in production (`404 Not Found`).

---

## Why Hearth is different

### One engine, not four services

The typical self-hosted identity stack is four moving pieces: an auth server (Keycloak, Ory), a relational database (Postgres, MySQL), a session cache (Redis), and a separate policy engine for fine-grained authorization. Four processes to deploy, four to secure, four versions to keep in sync, four failure domains to reason about — plus a cache that can quietly disagree with the database about who still has access.

Hearth is **one binary, one port, one config file, zero external dependencies**. No database to provision, no cache to invalidate, no policy store to operate, no dual-write synchronization between an identity store and an authorization service. One process to deploy. One thing to back up.

### Specialized storage, not a generic DB

A generic database has to serve every workload; an identity engine only has to serve one, and the shape of that workload is known. Hearth's storage engine is a hybrid built around those shapes:

- **User profiles and credentials** — B-tree-like structures indexed by email, username, external ID, and realm for point lookups.
- **Sessions** — time-partitioned, tuned for TTL-based expiration and recent-window scans.
- **Roles, groups, and role assignments** — adjacency-list indexes that resolve in a single pass at token-issue time; effective permissions are baked into the JWT.
- **Audit log** — append-only with a SHA-256 hash chain per realm.

A **hot/cold tier** holds the active working set in a lock-free in-process hash structure and transparently demotes inactive records to on-disk SSTs, so a single node can manage datasets larger than RAM while serving the active working set from memory. RAM grows sub-linearly with corpus — measured log-log exponent 0.8778 above the block-cache saturation point, not O(1) (see [Performance](#performance)).

### In-JWT authorization, not a network hop

Hearth resolves effective permissions at token-issue time and embeds them directly into the JWT `permissions` claim. **Permission checks are local JWT lookups, not network requests**: clients and downstream services decode the signed token and consult a set that fits in CPU cache. The hot path does not call Hearth for authorization at all. Because role and group state lives in the same storage engine as users, realms, and sessions, the resolve step runs in-process against an adjacency-list index with no external calls — which is the structural reason creating a user and assigning their initial roles is a single atomic storage write instead of a dual-write across two services.

### Your data, your rules

Apache 2.0, self-hosted, no per-seat pricing, no vendor lock-in, no phone-home telemetry. Your users' data stays on your infrastructure.

---

## What's in the box

**Authentication**
- Password login (Argon2id, OWASP parameters)
- OAuth 2.0 Authorization Code + PKCE, Refresh Token, Client Credentials, Device Authorization (RFC 8628)
- Magic link / passwordless
- TOTP (RFC 6238) with recovery codes
- WebAuthn / passkeys (Level 2)
- Social login via external OIDC / OAuth2 providers — Google, Microsoft / Azure AD, Apple, GitHub out of the box; any OIDC Core 1.0 issuer via generic `type: oidc`

**Authorization**
- Claims-based RBAC: roles, nested groups, per-realm and per-org role assignments
- Effective permissions resolved at token-issue time and embedded in the JWT (`roles`, `groups`, `permissions`)
- `GET /v1/me/permissions` for live introspection; SDK helpers for local `hasPermission` / `hasRole` checks
- Three permission-delivery modes per client: `embedded` (default, stateless), `introspection` (live RBAC via `/introspect`), `decision` (per-request allow/deny via `POST /oauth/authorize`) — see [Permission-delivery modes guide](docs/guides/permission-delivery.md)

**Multi-tenancy**
- Realm-isolated keyspace (every key prefixed with `RealmId`)
- Per-realm Ed25519 signing keys with JWKS rotation
- Cascading deletion across users, sessions, credentials, OAuth clients, role assignments, device codes, signing keys

**Protocols**
- OIDC Core 1.0 + Discovery 1.0 + Dynamic Client Registration (RFC 7591; RFC 7592 management endpoints are roadmap)
- Token Introspection (RFC 7662), Revocation (RFC 7009), RP-initiated logout
- SAML 2.0 in **both** roles: Service Provider (inbound federation — SP-initiated and IdP-initiated SSO, plus Single Logout) and Identity Provider (Hearth asserts to third-party SPs at `/realms/{realm}/saml/sso`). Encrypted assertions are not supported — see [docs/specs/SAML.md](docs/specs/SAML.md)
- SCIM 2.0 provisioning (Users, Groups, Service Provider Config)
- Signed webhook subscriptions for auth and admin events
- gRPC management API (RBAC admin surface)
- REST/JSON over HTTP/1.1 and HTTP/2

**Operations**
- Single binary (dynamically linked; no external runtime or database dependency)
- Embedded WAL + memtable + SST storage with hot/cold tiering
- TLS 1.3 + mTLS, SIGHUP cert hot-reload, HTTP→HTTPS redirect
- Audit log with SHA-256 hash chain and per-realm integrity verification
- Prometheus `/metrics`, `/healthz`, `/readyz` endpoints

**Migration**
- Keycloak realm-export import (`hearth migrate keycloak`) — users, clients, realm roles, and PBKDF2-SHA256 credentials imported natively so existing passwords keep working without a forced reset

---

## Performance

All figures measured on `dev-ryzen-7840hs` (AMD Ryzen 7 7840HS, 8 cores / 16 threads, NVMe SSD, `powersave` governor — a mobile laptop part, not an isolated server). Figures from this host are a **floor, not a ceiling**: a server-class CPU on a performance governor should do better. Source of record for every figure below: [`docs/perf/PUBLISHED_FIGURES.md`](docs/perf/PUBLISHED_FIGURES.md) §6.

**Two measurement planes — not interchangeable:**

- **Engine** — a direct in-process call into the embedded engine, excluding HTTP parsing, TCP, TLS, and connection handling.
- **HTTP** — a real loopback request to the running server, excluding TLS and network RTT.

Do not place engine figures beside competitor HTTP figures — that is a category error.

**We publish no competitor comparison.** Every competitor's published figure is end-to-end HTTP, and the only HTTP-plane figure we can currently stand behind is password login below. Producing the rest requires a quiesced server-class host (isolated cores, performance governor, no battery); the host above is a mobile laptop part and is disqualified for that purpose. We would rather ship no multiplier than a wrong one — so until that hardware exists, the numbers below are ours alone, unratioed.

### Hot path (engine plane)

All engine-plane figures were measured on `dev-ryzen-7840hs` as of 2026-07-29; full methodology, raw artifacts, and per-figure notes: [`docs/perf/PUBLISHED_FIGURES.md`](docs/perf/PUBLISHED_FIGURES.md). Published values are conservative: where re-verification measured better than the prior report, the older lower figure is used. A re-verification pass against a current HEAD SHA is pending.

| Operation | p50 latency | Throughput | Plane |
|---|---|---|---|
| Token validation (`validate_token`, hot tier) | **1.31 µs** | **760,877 /core/s** · 9,409,220 /s @16T | engine |
| Session lookup (hot tier) | **0.118 µs** | — | engine |
| Token introspection (RFC 7662) | **44.0 µs** | — | engine |
| Permission check | — | **5,987,782 /core/s** · 52,048,086 /s @16T | engine |
| Password login (Argon2id `m=19,456 KiB t=2 p=1`) | **16.4 ms** | — | engine |
| Durable session creation (**fsync-before-ack, `W=1.000`**) | — | **484 /s** @T=1 · **41,255 /s** @T=256 | engine |

`W=1.000` at T=1 means one WAL `fsync` per durable write — the theoretical floor. No write is acknowledged before it is on stable storage. `SyncMode::Async` was evaluated as a default and rejected; every write figure above carries full durability.

### Password login (HTTP plane, re-verified)

At `m=19,456 KiB t=2 p=1` (OWASP parameters), roughly 16 ms of Argon2id compute per login dominates server overhead by ~400:1, making this the one endpoint whose HTTP-plane figures reproduce reliably across host conditions. This figure reproduced within 2.4% at HEAD.

| Endpoint | p50 | @T=1 | @T=8 | Plane |
|---|---|---|---|---|
| `POST /login` (loopback, no TLS) | **20.1 ms** | **49 /s** | **185 /s** | **HTTP** |

Hearth is the only identity provider in its competitive set that publishes its KDF parameters alongside throughput — which lets you reproduce and verify the figures independently rather than taking a number on faith.

### Memory and disk footprint (engine plane)

No other self-hosted identity provider publishes a measured per-user memory or disk footprint. Hearth does:

| Metric | Figure | Plane |
|---|---|---|
| Marginal RAM per user (OLS slope, R²=0.9988) | **100 B/user** | engine |
| δRSS at 1 million users (64 MiB block cache) | **97.1 MiB** | engine |
| Total process RAM at 1 million hot users (256 MiB block cache, est.) | **~329 MB** | engine, est. |
| Total process RAM at 10 million hot users (est.) | **~0.9 GB** | engine, est. |
| Total process RAM at 100 million hot users (est.) | **~6.5 GB** | engine, est. |
| Disk per user (asymptotic, OLS R²=0.999772, N≥60k) | **1,195.6 B/user** | engine |
| Disk at 100 million users (extrapolated) | **≈111.3 GiB** | engine, est. |

RAM grows sub-linearly with corpus: measured log-log exponent 0.8778 above the block-cache saturation point (~213k users), asymptoting toward 100 B/user marginal cost. The block cache is bounded by `storage.block_cache_bytes` (default 64 MiB; 256 MiB used for production sizing above). Full methodology, hardware details, and reproduction commands: [`docs/perf/PUBLISHED_FIGURES.md`](docs/perf/PUBLISHED_FIGURES.md).

---

## How we build it

Identity infrastructure has zero tolerance for data loss and low tolerance for inconsistency. Hearth backs that with eight testing layers, all runnable locally and wired into CI:

1. **Unit** — inline `#[cfg(test)]`, TDD-first. A failing test precedes every feature.
2. **Integration / black box** — a `TestHarness` runs the same suite in embedded *and* HTTP server modes.
3. **Property** — `proptest`, 256 cases locally, 10,000+ in CI.
4. **Fuzz** — `cargo-fuzz` against wire parsers (CBOR, protobuf, JWT, authenticator data).
5. **Crash-recovery simulation** — real-thread tests against real temp directories with oracle-checked invariants and a `FaultFs` I/O fault hook: [`realm_crash`](simulation/src/tests/realm_crash.rs), [`audit_crash`](simulation/src/tests/audit_crash.rs), [`realm_concurrent_io`](simulation/src/tests/realm_concurrent_io.rs), [`rbac_concurrent_assignments`](simulation/src/tests/rbac_concurrent_assignments.rs).
6. **Adversarial** — timing attacks, brute-force lockout, enumeration resistance, TLS downgrade, privilege escalation.
7. **Conformance** — in-repo suites for OIDC Core 1.0, Discovery 1.0, Dynamic Client Registration, FAPI 2.0, RFC 8693/8707/9728, and the WebAuthn Level 2 ceremony. These are Hearth's own tests read against the specs; **no certifying body's suite has been run against Hearth, and Hearth is not certified.**
8. **Benchmarks** — `criterion`, with regression gating in CI.

**Crash-survival is part of the spec.** The storage engine must survive `kill -9` at any point and recover to a consistent state. Every WAL invariant has a crash-recovery scenario that exercises it.

**CI tiers:** Fast (every commit) · Standard (merge) · Extended (nightly) · Full (weekly).

**Current status.** Phase 0 (148/148 scenarios) and Phase 1 (134/135 scenarios). **5,387 Rust tests — 2,593 unit (`hearth` lib + bin) · 2,715 integration (`tests/`) · 79 crash-recovery simulation (`hearth-simulation`).** 14 of those carry `#[ignore]` (live-LDAP cases and one manual measurement) and do not run by default. Counted with `cargo nextest list --workspace` at `333c74e6` — reproduce it yourself rather than taking the number on faith.

The Rust suite, the seven SDK suites and the SDK conformance check are all in the `needs:` list of the `required-summary` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml), so a red suite blocks merge. This README does not assert a green result for any particular commit: look at the CI badge above, or at the `validation-summary.txt` asset on a given release.

> **1 Phase 1 scenario open** (not yet covered by tests): pbjson int64-as-string coercion — `docs/specs/TEST_SCENARIOS.md` §Proto & API Contract Validation › Unit. Coverage tracked in HEA-1836.

---

## Quick Start

### Prerequisites

- **Rust 1.88.0+** (see [`Cargo.toml`](Cargo.toml) `rust-version`)
- **`protoc`** — `build.rs` runs it on every build to generate the gRPC types.
  Install it (`brew install protobuf`, `apt install protobuf-compiler`, or a
  release from [protobuf/releases](https://github.com/protocolbuffers/protobuf/releases))
  and make sure it is on `PATH`, or set `PROTOC=/path/to/protoc`.
- `buf` (optional — only needed if you edit `proto/**/*.proto`; see [`CONTRIBUTING.md`](CONTRIBUTING.md))

### 1. Build

```bash
cargo build --release
# Binary: target/release/hearth
```

### 2. Run in dev mode

```bash
./target/release/hearth serve --dev
```

Dev mode uses `debug` logging, `fsync` disabled, and enables the `/admin/bootstrap` endpoint. The server binds to `127.0.0.1:8420`.

Storage is still a real WAL + SST store, not a RAM-only mode — it just lives in a throwaway location. The effective directory follows a three-level rule: `HEARTH_DEV_DATA_DIR` if set, else an explicit non-default `storage.data_dir`, else a temp directory removed on exit. Bare `./target/release/hearth serve --dev` takes the third branch, so nothing survives a restart; **`make dev` takes the first** (it sets `HEARTH_DEV_DATA_DIR=./data/dev`, which is gitignored) and therefore **does** persist across restarts — `make dev-reset` wipes it. See [`docs/specs/CONFIGURATION.md`](docs/specs/CONFIGURATION.md#--dev-mode-and-hearth_dev_data_dir).

### 3. Verify

```bash
curl -fsS http://127.0.0.1:8420/readyz
curl -fsS http://127.0.0.1:8420/.well-known/openid-configuration | head
```

### 4. Try it end-to-end

Want to see the OAuth consent flow from a client's perspective? There's
a runnable example at [`examples/oauth-consent-flow/`](examples/oauth-consent-flow/)
— a small Express app that demonstrates the consent screen, per-scope
approval, trusted-client bypass, and user-driven revocation in a
real browser.

For the *other* direction — Hearth as a relying party consuming tokens
from an upstream IdP — see
[`examples/federation-flow/`](examples/federation-flow/). It spins up a
local OIDC provider (built on `node-oidc-provider`) alongside Hearth and
walks through JIT provisioning, confirm-to-link, auto-link, and
self-service unlinking.

See [`examples/`](examples/) for the full list of runnable demos.

---

## Bootstrap an Admin (dev mode only)

Dev mode exposes a convenience endpoint that creates a realm, an admin user, a session, assigns the `realm.admin` role (which carries the `hearth.admin` permission), and issues tokens — everything you need to try the OAuth flow locally:

```bash
curl -fsS -X POST http://127.0.0.1:8420/admin/bootstrap
```

Response (JSON):

```json
{
  "realm_id":            "<uuid>",
  "user_id":             "<uuid>",
  "access_token":        "<jwt>",
  "refresh_token":       "<jwt>",
  "quickstart":          "<shell snippet with realm_id and token interpolated>",
  "admin_password":      "<randomly generated — non-empty on first call only>",
  "system_access_token": "<jwt scoped to the system realm for cross-realm admin ops>",
  "system_realm_id":     "00000000-0000-0000-0000-000000000000"
}
```

`admin_password` is returned **only on the first bootstrap call**. Store it securely — subsequent re-bootstrap calls return JSON `null` for that field. Re-bootstrap (after server restart or token expiry) requires a valid `Authorization: Bearer <access_token>` header from the initial bootstrap; without it the call answers `401`.

Bootstrap creates **two** admin identities that share the returned `admin_password`:

| Identity | Realm | Used for |
|---|---|---|
| `admin@dev.local` | the `dev-realm` it just created | the REST/OIDC walkthrough below — this is the `sub` behind `access_token` |
| `admin@hearth.test` | the system realm (`00000000-…-0000`) | the browser admin console at `/ui/admin/login` |

Signing in at `/ui/admin/login` as `admin@dev.local` answers `401`: operators live in the system realm, so use `admin@hearth.test`. A successful login answers `303` to `/ui`; `/ui/admin` then redirects to `/ui/admin/realms`. There is no `/admin` HTML page — that prefix is the JSON admin API.

Every `/admin/*` JSON route is realm-scoped and requires an **`X-Realm-ID` header** alongside the bearer token. Without it the call answers `400 {"error":"missing X-Realm-ID header"}`, not `401`:

```bash
curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "X-Realm-ID: $REALM_ID" \
     http://127.0.0.1:8420/admin/realms | jq .
```

In production mode the endpoint returns `404 Not Found`.

### Creating the first admin outside `--dev`

`/admin/bootstrap` does not exist in production. A fresh production data directory has no admin at all, and the server logs a `WARN` on every boot until one exists:

```
WARN first-run setup required: open this URL and supply the token from the
     token file in the data directory  setup_url=https://auth.example.com/ui/setup
     token_file=".setup_token"
```

The token itself is deliberately **not** logged in production. Read it from the data directory and append it as a query parameter — `/ui/setup` with no `token` answers `404`, by design, so the flow is not discoverable:

```bash
SETUP_TOKEN=$(cat /var/lib/hearth/data/.setup_token)
echo "https://auth.example.com/ui/setup?token=$SETUP_TOKEN"
```

Open that URL once and create the operator account. The token is single-use and the admin lands in the system realm. Set `onboarding.enabled: false` afterwards to close the flow permanently.

---

## Configuration

`hearth serve` resolves configuration in this order:

1. `--dev` flag → in-memory dev defaults (overrides everything else).
2. `-c, --config <path>` → load the specified YAML file.
3. Otherwise, `./hearth.yaml` if it exists in the working directory.
4. Otherwise, built-in production defaults.

CLI flags `--port` and `--bind` override any of the above.

YAML files support `${VAR_NAME}` environment variable substitution (`src/config/env.rs`); a missing variable is a hard error. Substitution runs over the **raw file text before the YAML parse**, so a `${VAR}` inside a `#` comment is expanded too and an unset variable there fails the whole config. Delete commented-out `${…}` placeholders you are not using, or write them as `${VAR:-}` to declare the empty value intentional.

Copy [`hearth.example.yaml`](hearth.example.yaml) to `hearth.yaml` and edit. Every section is `#[serde(default)]`, so you can omit anything you don't want to change — but the example is a **catalogue, not a starting config**: it is not valid as copied, because of the commented `${…}` placeholders above and because production requires a KEK and an HTTPS decision. Run `hearth config validate hearth.yaml` after editing and work through the errors; the smallest config that validates is:

```yaml
server:
  bind_address: "0.0.0.0"
  port: 443
  tls_cert_path: "/etc/hearth/tls/server.crt"   # or trust_forwarded_proto + trusted_proxies
  tls_key_path:  "/etc/hearth/tls/server.key"
storage:
  data_dir: "/var/lib/hearth/data"
oidc:
  issuer: "https://auth.example.com"
```

plus `HEARTH_KEK` and `HEARTH_MASTER_KEY` in the environment. **`hearth config validate` does not check either environment variable**, so a config it calls valid can still abort `serve` with `HEARTH_MASTER_KEY is not set and auto-generation is disabled in production mode`. Validate, then do a real `serve` on the target host before cutting over.

### Config reference

| Section | Field | Type | Default | Notes |
|---|---|---|---|---|
| `server` | `bind_address` | string | `127.0.0.1` | |
| `server` | `port` | u16 | `8420` | |
| `server` | `tls_cert_path` | path? | — | Requires `tls_key_path` |
| `server` | `tls_key_path` | path? | — | Requires `tls_cert_path` |
| `server` | `tls_client_ca_path` | path? | — | For mTLS |
| `server` | `tls_require_client_cert` | bool | `false` | Requires `tls_client_ca_path` |
| `server` | `default_realm` | string? | — | Realm name used for bare `/ui/*` URLs on multi-realm deployments. See [Web UI realm routing](#web-ui-realm-routing). Must name an existing realm; validated at startup. |
| `storage` | `data_dir` | string | `./data` | |
| `storage` | `wal_max_size_bytes` | u64 | `268435456` | 256 MiB |
| `storage` | `memtable_flush_bytes` | u64 | `67108864` | 64 MiB |
| `storage` | `hot_tier_capacity` | usize | `10000` | |
| `storage` | `fsync` | bool | `true` | **MUST be true in production** |
| `observability` | `log_level` | string | `info` | `trace` \| `debug` \| `info` \| `warn` \| `error` |
| `observability` | `log_format` | string | `text` | `text` \| `json` |
| `operational` | `request_timeout_secs` | u64 | `30` | |
| `operational` | `shutdown_timeout_secs` | u64 | `10` | |
| `operational` | `max_connections` | u32 | `1024` | |
| `operational` | `queue_depth` | u32 | `4096` | |
| `email` | `transport` | string | `log` | `log` \| `smtp` \| `sendgrid` \| `postmark` \| `mailgun` \| `mailtrap` |
| `email` | `from` | string? | — | `From:` header; required for all transports except `log` |
| `email.smtp` | `host` | string | — | SMTP server hostname; required when `transport: smtp` |
| `email.smtp` | `port` | u16 | — | SMTP server port (e.g. `587`, `465`, `1025`) |
| `email.smtp` | `encryption` | string | `starttls` | `none` \| `starttls` \| `tls` |
| `email.smtp` | `username` | string? | — | SMTP AUTH username (pair with `password`) |
| `email.smtp` | `password` | string? | — | SMTP AUTH password (pair with `username`) |
| `email.sendgrid` | `api_key` | string | — | SendGrid v3 API key; required when `transport: sendgrid` |
| `email.postmark` | `server_token` | string | — | Postmark server token; required when `transport: postmark` |
| `email.mailgun` | `api_key` | string | — | Mailgun API key; required when `transport: mailgun` |
| `email.mailgun` | `domain` | string | — | Mailgun sending domain |
| `email.mailgun` | `region` | string | `us` | `us` \| `eu` |
| `email.mailtrap` | `api_token` | string | — | Mailtrap Sending API token; required when `transport: mailtrap` |
| `metrics` | `enabled` | bool | `false` | Set `true` to expose the `/metrics` Prometheus scrape endpoint. Disabled by default — enable only with a `bearer_token` or network-layer access control. |
| `metrics` | `bearer_token` | string? | — | Bearer token required to access `/metrics` (constant-time compare). When absent, the endpoint is unauthenticated — operators SHOULD firewall it or bind to loopback. |

### Environment variables

Secrets are supplied through the environment rather than the YAML file so they never land on disk. `hearth serve` reads the following directly (independently of the `${VAR}` substitution used inside `hearth.yaml`):

| Variable | Required? | Format | Generate | Purpose |
|---|---|---|---|---|
| `HEARTH_MASTER_KEY` | **Required in production** | 64 lowercase hex chars (32 bytes) | `openssl rand -hex 32` | Host key that encrypts every realm's Key Encryption Key (KEK) at rest. Optional only if a persisted `${data_dir}/hearth.host_key` file already exists; on a **fresh production start with no file, startup aborts** with `HEARTH_MASTER_KEY is not set and auto-generation is disabled in production mode` (auto-generation happens only under `--dev`). `hearth config validate` does not check for it. |
| `HEARTH_PREVIOUS_MASTER_KEY` | Rotation only | 64 lowercase hex chars (32 bytes) | *(the prior key)* | The previous `HEARTH_MASTER_KEY` value, set **only during a master-key rotation** so the existing KEKs in `hearth.keys` can be re-encrypted under the new key. Remove it once the next clean start succeeds. |
| `HEARTH_KEK` | Optional | 64 lowercase hex chars (32 bytes / AES-256) | `openssl rand -hex 32` | Storage key-encryption key; overrides `security.key_encryption_key`. Must not be the all-zero key. |
| `HEARTH_SMS_OTP_HMAC_KEY` | Only with real SMS | ≥ 32 bytes | `openssl rand -base64 32` | Cryptographically binds SMS OTP codes to the server. Required **only when `sms.transport` is a real transport** (`twilio`, `awssns`). Under the `log` transport (dev or production) it is optional and a deterministic dev key is substituted. |
| `HEARTH_TURNSTILE_SECRET_KEY` | With Turnstile | Cloudflare secret string | *(Cloudflare dashboard)* | Cloudflare Turnstile secret; overrides `abuse.captcha.turnstile.secret_key`. When Turnstile is enabled and this is unset, every challenge is rejected. |
| `HEARTH_REALM_<REALM>_FINGERPRINT_HMAC_SECRET` | Per configured realm | ≥ 32 bytes | `openssl rand -base64 32` | Per-realm device-fingerprint HMAC secret. `<REALM>` is the SCREAMING_SNAKE_CASE realm name (e.g. `HEARTH_REALM_CUSTOMER_PORTAL_FINGERPRINT_HMAC_SECRET`). See [security hardening](docs/guides/security-hardening.md). |
| `HEARTH_DEV_DATA_DIR` | Dev only | filesystem path | — | Overrides the data directory used under `--dev` (env > config `storage.data_dir` > temp dir). Ignored outside dev mode. |
| `HEARTH_MAILCATCHER_PASSWORD` | Dev only | string | `openssl rand -base64 24` | Password for the in-process mailcatcher UI (`/dev/mail`) when `email.transport: mailcatcher`. Auto-generated (and logged) if unset. |

See [`docs/guides/security-hardening.md`](docs/guides/security-hardening.md) for master-key rotation and per-realm secret provisioning.

---

## Theming the Admin UI

Hearth's admin UI is fully themeable via CSS custom properties. Six named themes ship built in; operators can also supply arbitrary CSS to override any token.

### Named themes

Configure with `branding.theme` in `hearth.yaml`:

| Name | Mode | Description |
|---|---|---|
| `ember` | dark | Default — amber/orange brand on cool graphite |
| `ocean` | dark | Teal/cyan brand on deep graphite |
| `midnight` | dark | Violet/purple brand on deep graphite |
| `forest` | dark | Emerald/green brand on deep graphite |
| `cloud` | light | Blue brand on near-white surfaces |
| `slate` | light | Steel-blue brand on cool blue-gray surfaces |

```yaml
branding:
  theme: slate
```

An unknown theme name is a config error at startup.

### Custom CSS

Append a CSS file after the named theme to override any `--ht-*` variable or add custom rules. The file is read once at startup:

```yaml
branding:
  theme: ember
  custom_css: /etc/hearth/brand.css
```

### Per-realm themes

Each realm can override the global theme independently:

```yaml
realms:
  acme:
    web:
      theme: cloud
      custom_css: /etc/hearth/realms/acme.css
```

The per-realm theme CSS is served from `GET /ui/static/realm-theme/{realm_id}` and is cached with `ETag` support.

### CSS custom property API

All theme tokens are `--ht-*` CSS custom properties. A custom CSS file need only override the variables it changes; unset variables fall back to the `ember` defaults. Key variables:

```css
:root {
  --ht-surface-base:      /* page background (RGB triple, no alpha) */
  --ht-surface-raised:    /* sidebar / panel background */
  --ht-surface-elevated:  /* card / modal background */
  --ht-content-primary:   /* primary text */
  --ht-content-secondary: /* secondary text */
  --ht-content-muted:     /* muted / placeholder text */
  --ht-content-brand:     /* brand-colored text and icons */
  --ht-content-on-brand:  /* text on top of brand gradient buttons */
  --ht-brand-from:        /* gradient start color */
  --ht-brand-via:         /* gradient midpoint */
  --ht-brand-deep:        /* gradient end / hover state */
}
```

For the full token list and design rationale see [`docs/specs/THEME.md`](docs/specs/THEME.md).

---

## Local Development

Run directly with Cargo — no Docker required:

```bash
make dev          # cargo run -- serve --dev
# or
cargo run -- serve --dev
```

`--dev` binds to `http://127.0.0.1:8420` and auto-enables the built-in **mailcatcher** email transport. `make dev` keeps its store in `./data/dev`, so data survives restarts; `make dev-reset` wipes it. Every outbound email (verification links, password resets, setup notifications) is captured in-process and visible in a browser UI at **http://127.0.0.1:8420/dev/mail** — no external mail server or Docker needed.

The inbox password is printed to the terminal at startup:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MailcatcherSender active
  Inbox:    http://127.0.0.1:8420/dev/mail
  Password: <random 16-char password>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

> **Migrating from Docker Compose?** If your `hearth.yaml` has `email.transport: smtp`, `--dev` automatically overrides it to mailcatcher and logs a warning. You can silence it by removing the smtp block or setting `transport: mailcatcher` explicitly.

Production deployment (containerised, persistent storage, real email) lives in [`deploy/`](deploy/).

---

## CLI Reference

```text
hearth serve [--dev] [-c, --config <path>] [--port <u16>] [--bind <addr>] [-v] [--allow-reflection-in-prod]
hearth realm create
hearth app create --server <url> --realm-id <uuid> --name <name> --redirect-uri <url> --token <admin-bearer-token>
hearth migrate keycloak --file <export.json> [--data-dir <path>] [--realm <uuid>] [--dry-run]
hearth migrate auth0 --file <bundle.json> [--data-dir <path>] [--realm <uuid>] [--dry-run]
hearth migrate rotate-pepper --data-dir <path> [--summary-only]
hearth config validate [<path>]            # defaults to ./hearth.yaml
hearth config example [-o <path>]          # print an annotated hearth.yaml
hearth config reload [--url <url>] [--pid-file <path>]   # hot reload: POST, or SIGHUP via PID file
hearth backup create  [-o <archive>] [--realm <name|uuid>] [--include-audit] [--encrypt] [--data-dir <path>]
hearth backup restore -i <archive> [--realm <slug>] [--mode skip|overwrite|merge] [--dry-run]
                      [--allow-missing-signing-key] [--data-dir <path>]
hearth backup verify  -i <archive>
hearth backup inspect -i <archive>
hearth rbac orphans list  [--realm <name|uuid>] [--data-dir <path>]
hearth rbac orphans purge [--realm <name|uuid>] [--data-dir <path>] [--dry-run]
hearth completions <bash|elvish|fish|powershell|zsh>
```

Run `hearth <command> --help` for the authoritative flag list; the block above is the full set of subcommands as of this revision.

- **`serve`** starts the HTTP(S) server. `--dev` implies a throwaway data directory, relaxed validation, and the bootstrap endpoint.
- **`realm create`** prints `{"realm_id": "<uuid>"}` on stdout. It's a pure UUID generator and does not require a running server.
- **`app create`** registers an OAuth 2.0 client by POSTing to `/clients` on a running Hearth server. The server URL must be reachable over HTTP. `--token` is **mandatory** — client registration is a privileged operation, so pass an admin bearer token carrying `hearth.clients.admin` (or `hearth.admin`); in dev mode, the `access_token` from `POST /admin/bootstrap`.
- **`migrate keycloak` / `migrate auth0`** import a realm export directly into the embedded store. Both operate on the data directory offline (no running server needed) — see [Migrating from Keycloak](#migrating-from-keycloak).
- **`config validate`** parses the YAML and validates every realm's permission registry without starting the server; exits 1 on any error. It does **not** check the `HEARTH_*` environment prerequisites — a config it accepts can still be refused by `serve` (for example when `HEARTH_MASTER_KEY` is unset on a fresh production data directory).
- **`backup` / `rbac orphans` / `migrate`** all take `--data-dir` and open the store directly, so the server **must be stopped first** — the data directory carries an exclusive `LOCK`. See the [Backup guide](docs/guides/backup.md).

---

## End-to-End curl Walkthrough

**Prerequisites:** `curl` + `jq` + `openssl` + a Rust toolchain.
Time to first token: under 30 minutes from a clean clone.

### 0. Start Hearth

```bash
make dev
# or: cargo run -- serve --dev
```

Binds to `http://127.0.0.1:8420` with in-memory storage.

### 1. Bootstrap realm + admin user (dev only)

```bash
BOOTSTRAP=$(curl -fsS -X POST http://127.0.0.1:8420/admin/bootstrap)
REALM_ID=$(echo "$BOOTSTRAP" | jq -r .realm_id)
USER_ID=$(echo "$BOOTSTRAP" | jq -r .user_id)
ADMIN_TOKEN=$(echo "$BOOTSTRAP" | jq -r .access_token)

echo "Realm: $REALM_ID"
echo "User:  $USER_ID"
```

The bootstrap endpoint is available only in `--dev` mode. It creates a realm, an admin user, assigns the `realm.admin` role (which carries the `hearth.admin` permission), and returns short-lived tokens. The `admin_password` field is **non-empty on the first call only** — store it securely. Re-bootstrap (to refresh expired tokens) requires `Authorization: Bearer <access_token>` from the initial bootstrap. In production it returns `404 Not Found`.

### 2. Register a client

`POST /clients` **accepts** a `client_secret` and never returns one. You generate
the secret, send it, and keep your copy — the response body carries only
`client_id`, `client_name`, `created_at`, `grant_types` and `redirect_uris`.
Reading `.client_secret` off the response yields `null`.

```bash
CLIENT_SECRET=$(openssl rand -base64 32)

CLIENT=$(curl -fsS -X POST http://127.0.0.1:8420/clients \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_name\":    \"my-app\",
    \"redirect_uris\":  [\"https://myapp.example.com/callback\"],
    \"client_secret\":  \"$CLIENT_SECRET\"
  }")

CLIENT_ID=$(echo "$CLIENT" | jq -r .client_id)

echo "Client ID:     $CLIENT_ID"
echo "Client secret: $CLIENT_SECRET"   # your value — store it now
```

Omit `client_secret` to register a public client. A public client must then omit
`client_secret` from the `/token` calls in steps 5 and 9 as well; PKCE is what
protects it.

### 3. Generate PKCE verifier and challenge

PKCE prevents authorization code interception. Generate a verifier locally; send only the challenge to the server.

```bash
CODE_VERIFIER=$(openssl rand -hex 32)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A \
  | tr '+/' '-_' \
  | tr -d '=')

echo "Verifier:  $CODE_VERIFIER"
echo "Challenge: $CODE_CHALLENGE"
```

### 4. Start an authorization request

The `/authorize` endpoint requires a valid Bearer token — the user's identity is taken from the token's `sub` claim, not from a caller-supplied field.

```bash
AUTH=$(curl -fsS -X POST http://127.0.0.1:8420/authorize \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\":             \"$CLIENT_ID\",
    \"redirect_uri\":          \"https://myapp.example.com/callback\",
    \"response_type\":         \"code\",
    \"scope\":                 \"openid profile email\",
    \"state\":                 \"$(openssl rand -hex 16)\",
    \"code_challenge\":        \"$CODE_CHALLENGE\",
    \"code_challenge_method\": \"S256\"
  }")

CODE=$(echo "$AUTH" | jq -r .code)
echo "Authorization code: $CODE"
```

### 5. Exchange the code for tokens

```bash
TOKENS=$(curl -fsS -X POST http://127.0.0.1:8420/token \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "redirect_uri=https://myapp.example.com/callback" \
  --data-urlencode "code_verifier=$CODE_VERIFIER")

ACCESS_TOKEN=$(echo "$TOKENS" | jq -r .access_token)
REFRESH_TOKEN=$(echo "$TOKENS" | jq -r .refresh_token)
EXPIRES_IN=$(echo "$TOKENS" | jq -r .expires_in)

echo "Access token (first 60 chars): ${ACCESS_TOKEN:0:60}..."
echo "Expires in: ${EXPIRES_IN}s"
```

### 6. Inspect the token claims

```bash
# Decode the JWT payload (base64url → JSON) — no signature verification
echo "$ACCESS_TOKEN" \
  | cut -d. -f2 \
  | tr '_-' '/+' \
  | awk '{ pad = (4 - length($0) % 4) % 4; for(i=0;i<pad;i++) $0=$0"="; print }' \
  | base64 -d \
  | jq .
```

Always present:
- `sub` — stable user identifier
- `roles` — array of role names assigned to the user
- `permissions` — effective permission set resolved at issuance time
- `exp`, `iat`, `iss`, `aud` — standard JWT claims
- `sid`, `tid`, `jti`, `fid`, `token_type` — session, realm (tenant), token id,
  refresh-family id, and token kind

Present only when the user has them — **absent** from the token this walkthrough
mints, because the bootstrap admin belongs to no group and no organization:
- `groups` — array of group slugs
- `oid` — organization ID

`/v1/me/permissions` (step 8) always returns `groups`, as an empty array when
there are none, so use it rather than the token to test group membership.

### 7. Fetch user info (scope-filtered claims)

```bash
curl -fsS http://127.0.0.1:8420/userinfo \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  | jq .
```

Returns OIDC claims filtered by the granted scopes: `sub` always; `profile` → `name`; `email` → `email`, `email_verified`.

### 8. Check live permissions

```bash
curl -fsS http://127.0.0.1:8420/v1/me/permissions \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  | jq .
```

Returns the freshly-resolved RBAC claim set from the server — reflects any role or group changes made since the token was issued.

### 9. Refresh the access token

```bash
NEW_TOKENS=$(curl -fsS -X POST http://127.0.0.1:8420/token \
  -H "X-Realm-ID: $REALM_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET")

echo "$NEW_TOKENS" | jq '{access_token: .access_token[:60], expires_in}'
```

Refresh tokens rotate on use. Presenting an already-rotated refresh token triggers theft detection and revokes the entire grant family, invalidating all tokens issued under it.

---

## External IdP Federation (social login)

Hearth also acts as an OIDC **relying party**: users can sign in with Google, Microsoft / Azure AD, Apple, GitHub, or any OIDC Core 1.0–compliant provider. Connectors are declared per realm in `hearth.yaml`; at login time Hearth renders a "Sign in with Google" button next to the password form and brokers the standard OIDC code flow against the upstream.

### Minimum config

```yaml
realms:
  customer-portal:
    federation:
      # How external identities attach to existing local users when the
      # upstream asserts a verified email that matches a Hearth user.
      # Default is `confirm` (Keycloak-equivalent safety posture).
      link_existing_accounts: confirm
      providers:
        google:
          type: google                 # preset — fills in issuer + endpoints + scopes
          client_id: ${GOOGLE_CLIENT_ID}
          client_secret: ${GOOGLE_CLIENT_SECRET}
```

That's enough. Restart Hearth and the realm's login page shows a "Sign in with Google" button. `${VAR_NAME}` substitution comes from `src/config/env.rs` — missing values are a hard startup error.

### Provider types

| `type` | Protocol | What the preset fills in |
|---|---|---|
| `google` | OIDC | Issuer, authorize / token / userinfo / JWKS URLs, scopes `openid email profile` |
| `microsoft` | OIDC | Azure AD `common` tenant v2.0 endpoints (override `issuer` for single-tenant deployments) |
| `apple` | OIDC | Apple Sign-In endpoints; no userinfo (claims inline in the ID token) |
| `github` | OAuth2 | `/login/oauth/authorize` + `/login/oauth/access_token` + `/user`; email via `/user/emails` when private |
| `oidc` | OIDC | No preset — operator supplies `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `scopes` explicitly |
| `saml` | SAML 2.0 | No preset — operator supplies `entity_id`, `sso_url`, `certificate`; Hearth acts as SP. See the [Federation guide](docs/guides/federation.md) for full config |

`type: oidc` is the escape hatch for any OIDC/OAuth2 provider not in the preset list (Okta, Auth0, Keycloak, Zitadel, on-prem Azure AD B2C, …). `type: saml` federates to enterprise IdPs (Okta, Azure AD, ADFS, PingFederate) over SAML 2.0.

### Account linking

`link_existing_accounts` governs what happens when an external login's verified email matches an existing Hearth user:

| Mode | Behavior | Security posture |
|---|---|---|
| `disabled` | Never link. Always JIT-provision a new user per external identity. | Safest against IdP email spoofing; duplicate accounts are visible and expected |
| `confirm` *(default)* | Redirect to `/ui/federation/confirm-link`; user must authenticate to the local account (password or passkey) before the link attaches. | Matches Keycloak's default First Broker Login flow |
| `auto` | Silent link on `email_verified=true` email match. | **Account-takeover risk** — trusts the IdP entirely; only use when the realm federates to a single high-trust provider |

> ⚠️ **`auto` can hand an existing account to an upstream provider.** Hearth attaches the
> upstream identity to whatever local account holds that email address, with no local
> re-authentication, so every local account is only as safe as the weakest connector in the
> realm. An IdP that does not verify email — GitHub's public profile email, or any generic
> `type: oidc` IdP that can be made to assert `email_verified: true` — lets an attacker
> register upstream with a victim's address and sign straight into the victim's Hearth
> account with its roles and permissions. Keep `confirm` unless the realm federates to
> exactly one IdP that verifies email addresses.

Users can list and unlink their external identities at `/ui/account/linked-accounts`.

### Configuration is YAML-only, permanently

Federation connectors are **system configuration**, not data. Hearth deliberately separates the two:

- **Data** (users, organizations, linked external identities, sessions) — managed through the admin UI and APIs. Changes at runtime, per user, driven by user action.
- **System configuration** (realms, OAuth clients, email transports, **federation connectors**, themes) — YAML-only, reconciled at startup, version-controlled alongside the rest of the deployment.

There will never be an admin UI for adding federation connectors. This is Infrastructure-as-Code by design: connector credentials, issuer URLs, and scopes belong in git next to the rest of your deployment, not in a database that can silently drift from what operators think they deployed.

### Try it

An end-to-end walkthrough with a local OIDC upstream lives at [`examples/federation-flow/`](examples/federation-flow/) — two processes (Hearth + a `node-oidc-provider`-based upstream) that reproduce JIT provisioning, confirm-to-link, auto-link, and self-service unlinking without any external credentials.

For the full feature spec see [`docs/specs/ARCHITECTURE.md`](docs/specs/ARCHITECTURE.md).

---

## API Endpoints

| Group | Method | Path | Purpose |
|---|---|---|---|
| Discovery | `GET` | `/health` | Liveness probe |
| Discovery | `GET` | `/.well-known/openid-configuration` | OIDC Discovery 1.0 metadata |
| Discovery | `GET` | `/jwks` | Per-realm public signing keys (aliases: `/certs`, `/.well-known/jwks.json`) |
| OAuth/OIDC | `GET`/`POST` | `/authorize` | Authorization request — `GET` is the browser redirect entry point, `POST` the form-post variant |
| OAuth/OIDC | `POST` | `/token` | Token exchange (code / refresh / client_credentials / device_code) |
| OAuth/OIDC | `POST` | `/revoke` | RFC 7009 revocation |
| OAuth/OIDC | `POST` | `/introspect` | RFC 7662 introspection |
| OAuth/OIDC | `GET` | `/userinfo` | OIDC UserInfo |
| OAuth/OIDC | `POST` | `/device_authorization` | RFC 8628 device code start |
| OAuth/OIDC | `POST` | `/register` | RFC 7591 dynamic client registration |
| OAuth/OIDC | `POST` | `/clients` | Static client registration (used by `hearth app create`) |
| OAuth/OIDC | `GET`/`POST` | `/end_session` | OIDC RP-initiated logout; fans out to back-channel and front-channel URIs |
| Admin | `GET`/`POST` | `/admin/users` | List / create users |
| Admin | `POST` | `/admin/users/bulk` | Bulk user creation (max 10,000 users per request) |
| Admin | `POST` | `/admin/users/import` | Import users from JSON (max 10,000 users per request) |
| Admin | `GET` | `/admin/users/export` | Export users as JSON |
| Admin | `GET`/`PATCH`/`DELETE` | `/admin/users/{id}` | Read / partially update / delete a user |
| Admin | `GET`/`POST` | `/admin/users/{id}/roles` | List / assign roles to a user |
| Admin | `GET` | `/admin/users/{id}/consents` | List a user's active OAuth consents |
| Admin | `DELETE` | `/admin/users/{id}/consents/{client_id}` | Revoke a user's consent for a client |
| Admin | `GET` | `/admin/users/{id}/effective-permissions` | Resolved permission set for a user |
| Admin | `DELETE` | `/admin/assignments/{id}` | Remove a role assignment |
| Admin | `GET` | `/admin/realms` | List realms (`POST` answers `405` — realms are declared in `hearth.yaml`) |
| Admin | `GET`/`DELETE` | `/admin/realms/{id}` | Read a realm; delete one that is already `Archived` (`PATCH` answers `405` — realms are declared in `hearth.yaml`) |
| Admin | `GET`/`POST` | `/admin/applications` | List / register OAuth clients |
| Admin | `GET`/`PATCH`/`DELETE` | `/admin/applications/{id}` | Read / partially update / delete a client |
| Admin | `GET`/`POST` | `/admin/roles` | List / create RBAC roles |
| Admin | `GET`/`PATCH`/`DELETE` | `/admin/roles/{id}` | Read / partially update / delete a role |
| Admin | `GET`/`POST` | `/admin/groups` | List / create groups |
| Admin | `GET`/`PATCH`/`DELETE` | `/admin/groups/{id}` | Read / partially update / delete a group |
| Admin | `GET`/`POST` | `/admin/groups/{id}/members` | List / add group members |
| Admin | `DELETE` | `/admin/groups/{id}/members/{member_id}` | Remove a group member |
| Admin | `GET` | `/admin/audit` | Query the audit log |
| Admin | `GET`/`POST` | `/admin/webhooks` | List / create webhook subscriptions |
| Admin | `GET`/`PUT`/`DELETE` | `/admin/webhooks/{id}` | CRUD a webhook subscription |
| Admin | `GET` | `/admin/webhooks/{id}/deliveries` | Delivery log for a subscription (default 50, max 200 per page) |
| Admin | `POST` | `/admin/bootstrap` | Dev-only bootstrap — returns 404 in production |
| Self-service | `GET` | `/v1/me/permissions` | Caller's live RBAC claim set |
| Self-service | `GET` | `/oauth/consents` | List the caller's granted OAuth consents |
| Self-service | `DELETE` | `/oauth/consents/{client_id}` | Revoke consent for a specific client |
| WebAuthn | `POST` | `/webauthn/register/begin` | Start passkey registration ceremony |
| WebAuthn | `POST` | `/webauthn/register/complete` | Complete passkey registration |
| WebAuthn | `POST` | `/webauthn/auth/begin` | Start passkey authentication ceremony |
| WebAuthn | `POST` | `/webauthn/auth/complete` | Complete passkey authentication |
| WebAuthn | `GET` | `/webauthn/credentials` | List the caller's registered credentials |
| WebAuthn | `DELETE` | `/webauthn/credentials/{credential_id}` | Remove a passkey credential |
| SCIM 2.0 | `GET` | `/scim/v2/ServiceProviderConfig` | SCIM capability advertisement |
| SCIM 2.0 | `GET` | `/scim/v2/ResourceTypes` | Supported SCIM resource types |
| SCIM 2.0 | `GET` | `/scim/v2/Schemas` | SCIM schema definitions |
| SCIM 2.0 | `GET`/`POST` | `/scim/v2/Users` | List / provision users |
| SCIM 2.0 | `GET`/`PUT`/`PATCH`/`DELETE` | `/scim/v2/Users/{id}` | CRUD / partial update a SCIM user |
| SCIM 2.0 | `GET`/`POST` | `/scim/v2/Groups` | List / provision groups |
| SCIM 2.0 | `GET`/`PUT`/`PATCH`/`DELETE` | `/scim/v2/Groups/{id}` | CRUD / partial update a SCIM group |
| Observability | `GET` | `/healthz` | Kubernetes liveness probe |
| Observability | `GET` | `/readyz` | Kubernetes readiness probe (storage + engine checks) |
| Observability | `GET` | `/metrics` | Prometheus-compatible metrics |

All `/admin/*` routes require a bearer token whose `permissions` claim contains `hearth.admin` for the target realm (typically via the seed `realm.admin` role). SCIM routes use a realm-scoped bearer token.

Per-realm variants of the core OAuth/OIDC endpoints are available at `/realms/{realm_name}/{endpoint}` for multi-realm deployments where callers cannot send `X-Realm-ID`.

---

## Client SDKs

Two first-party SDKs live under [`sdks/`](sdks):

**TypeScript** — [`sdks/typescript/`](sdks/typescript) (package `@hearth-auth/sdk`)

```ts
import { HearthClient } from "@hearth-auth/sdk";
const hearth = new HearthClient({ baseUrl: "https://auth.example.com", realmId });
```

**Go** — [`sdks/go/`](sdks/go) (module `github.com/hearth-auth/hearth/sdks/go`)

```go
import "github.com/hearth-auth/hearth/sdks/go/hearth"
client := hearth.NewClient("https://auth.example.com", realmID)
```

Each SDK has a README with full API docs: [`sdks/typescript/README.md`](sdks/typescript/README.md) and [`sdks/go/README.md`](sdks/go/README.md).

---

## TLS and mTLS

Enable TLS by setting **both** `server.tls_cert_path` and `server.tls_key_path` — either both or neither. When TLS is active, Hearth spawns an HTTP → HTTPS redirect listener on `port - 1` (or `80` if the TLS port is `443`).

For mTLS, add `server.tls_client_ca_path` and set `server.tls_require_client_cert: true`. Sending `SIGHUP` to the process reloads the cert + key from disk without dropping connections.

```yaml
server:
  tls_cert_path: "/etc/hearth/server.crt"
  tls_key_path:  "/etc/hearth/server.key"
  tls_client_ca_path: "/etc/hearth/clients-ca.crt"
  tls_require_client_cert: true
```

---

## Web UI realm routing

Every `/ui/*` page belongs to exactly one realm — that's where the user's session, credentials, and policy live. Hearth resolves the realm for each pre-auth request *before* touching the identity engine, and never walks realms looking for a match. Which realm applies depends on the URL shape and how many realms exist.

| Realm count | `server.default_realm` | Bare `/ui/login` etc. behavior |
|---|---|---|
| 1 | — (ignored) | Implicit — the sole realm is used. Zero config needed. |
| >1 | Set | Resolves to the declared default. Forms POST back to the bare URL. |
| >1 | Unset | Returns **400 with a terse "sign-in URL required" page** — no realm names. Users must be handed `/ui/realms/<name>/...` by their administrator. |

By design, Hearth **never presents an anonymous realm picker**. Enumerating tenants to unauthenticated callers is a discovery leak; Auth0, Okta, and similar providers avoid it by using subdomains or email-based home realm discovery. Hearth's answer is: set `default_realm` if you want a bare URL to work, otherwise publish per-realm URLs directly.

Explicit **`/ui/realms/<name>/...`** URLs bypass the fallback chain entirely. Unknown realm names return 404.

Pre-auth route families (each has a bare and a path-scoped form):

```
/ui/{login, register, register/sent, forgot-password, forgot-password/sent,
     reset-password, verify-email, accept-invitation,
     login/passkey-begin, login/passkey-complete}

/ui/realms/<name>/{...same set...}
```

Bare URLs are convenient; path-scoped URLs are canonical. Email verification links, password-reset links, and form POSTs generated on a path-scoped page all stay path-scoped so the realm binding survives the round trip. Authenticated pages (`/ui/admin/*`, `/ui/account/*`, `/ui`) resolve the realm from the session cookie and need no path segment.

Operators opt in per deployment:

```yaml
server:
  bind_address: 0.0.0.0
  port: 8420
  default_realm: public    # optional; only needed when you host >1 realm
```

Startup hard-fails if `server.default_realm` names a realm that doesn't exist after reconciliation — it's a config bug, not a runtime fallback. Leave it unset on a multi-realm deployment to force every user through an explicit `/ui/realms/<name>/...` URL.

For the exact resolution rules see [`src/protocol/web/realm_resolver.rs`](src/protocol/web/realm_resolver.rs).

---

## Admin console

Hearth administrators live in an invisible **system realm** — distinct from any application realm you declare in `hearth.yaml`. That separation means an operator who administers `customer-portal` and `internal-tools` is the same person either way; they authenticate against Hearth itself, not against one of the tenants.

- **Admin sign-in:** `GET /ui/admin/login`. The session cookie is bound to the system realm, not any app realm.
- **Admin email verification:** `GET /ui/admin/verify-email?token=...` — the link embedded in the first-run setup email.
- **The system realm is read-only through public APIs.** `realms: { system: {} }` in YAML is a config error at parse time (`src/config/validate.rs`). Fifteen engine entry points reject the reserved realm with a 403 `SystemRealmProtected` — by nil UUID where the request is id-addressed, and by the reserved name `system` where it is name-addressed: `create_realm`, `update_realm`, `delete_realm`, `create_user`, `create_user_attributed`, `register_user`, `register_client`, `create_organization`, `update_organization`, `create_agent`, `import_realm`, `import_user`, `import_client`, `seed_demo_users`, and realm reconciliation. **RBAC writes are gated at the protocol edge instead**, not in the engine: `reject_system_realm_write` guards ten REST admin routes (`src/protocol/http/admin.rs`) and seventeen gRPC `RbacAdmin` RPCs (`src/protocol/grpc/rbac_admin.rs`), because the operator console legitimately writes system-realm roles through the engine directly. The realm does not appear in `list_realms()` or `search_realms()`, `get_realm_by_name("system")` returns `None`, and `/ui/realms/system/...` URLs return 404.
- **Operators run the first-run setup exactly once**, regardless of how many application realms they've declared. The admin user is always placed in the system realm; tenant realms stay empty of operators.

Admins administer tenant realms via a `?realm=<name>` query parameter on admin URLs, which persists for the session via the `hearth_ui_admin_target` cookie. Switching realms is done either by visiting `/ui/admin/realms` and clicking "Administer this realm" next to the target, or by typing `?realm=<name>` in the URL. The admin's session cookie is always bound to the system realm; the target realm is orthogonal.

---

## Migrating from Keycloak

Hearth reads Keycloak realm exports natively and imports them into the embedded store offline — no running server required, no HTTP body limits, no forced password reset for end users whose hashes Hearth can verify directly.

### Validate an export

Run `--dry-run` first to parse the export, validate every record, and print a report of what *would* be written:

```bash
./target/release/hearth migrate keycloak \
  --file /path/to/realm-export.json \
  --dry-run
```

### Import into a data directory

Drop `--dry-run` and point `--data-dir` at the directory `hearth serve` will later use:

```bash
./target/release/hearth migrate keycloak \
  --file /path/to/realm-export.json \
  --data-dir ./data
```

Optionally pass `--realm <uuid>` to force a specific Hearth `RealmId` (defaults to the realm's own UUID from the export).

### What gets imported

| Keycloak                     | Hearth                                                     |
|------------------------------|------------------------------------------------------------|
| realm (`id`, `realm`)        | realm                                                     |
| user (`id`, `email`, …)      | user (Keycloak UUID preserved when valid)                  |
| user → `realmRoles`          | RBAC role assignment per role name, scoped to the realm     |
| client + `secret`            | `OAuthClient` (secret re-hashed with Argon2id on import)   |
| password — PBKDF2-SHA256     | PHC string; verifies natively, no password reset required  |
| password — PBKDF2-SHA512     | *Skipped* with a warning; user must reset password         |

### What's not imported (yet)

Groups, composite roles, client roles, federated identity providers, and required actions are out of scope for the initial importer. Users affected by unsupported credentials land in the store with no password set and appear in the report's `warnings` list so operators can reconcile.

See the [full Keycloak migration guide](docs/guides/migrating-from-keycloak.md) for a complete conceptual mapping, export procedure, post-migration checklist, and rollback plan.

## Migrating from Auth0

```bash
hearth migrate auth0 \
  --file auth0-bundle.json \
  --data-dir /var/lib/hearth
```

Auth0 does not provide a single-endpoint export. A reference bundler script at [`examples/auth0-migration-bundler/`](examples/auth0-migration-bundler/) assembles the bundle from the Auth0 Management API. Run `--dry-run` first to validate.

See the [full Auth0 migration guide](docs/guides/migrating-from-auth0.md) for bundle assembly steps, a complete conceptual mapping, and the post-migration checklist.

---

## Architecture at a glance

```
┌──────────────────────────────────────────────────────────────┐
│                     Single binary process                     │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Protocol   REST · gRPC · OIDC · SAML · SCIM · WebUI   │ │
│  └────────────────────────┬────────────────────────────────┘ │
│                            │                                  │
│  ┌─────────────────────────▼──────────────────────────────┐  │
│  │  Identity   Users · Sessions · Realms · OAuth · Email  │  │
│  │                          │ (token issuance only)        │  │
│  │  ┌───────────────────────▼──────────────────────────┐  │  │
│  │  │  RBAC   Roles · Groups · Assignments · Claims    │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  └────────────────────────┬───────────────────────────────┘  │
│                            │                                  │
│  ┌─────────────────────────▼──────────────────────────────┐  │
│  │  Storage   WAL → Memtable → SST · Hot/cold tiering     │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Cluster   openraft (invisible in single-node mode)  │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

| Layer | Path | Role |
|---|---|---|
| Core | `src/core/` | Shared types and traits only. No logic, no state. |
| Protocol | `src/protocol/` | Stateless wire adapters (REST, gRPC, OIDC, SAML, SCIM). |
| Identity | `src/identity/` | Users, credentials, sessions, realms, tokens. |
| RBAC | `src/rbac/` | Roles, groups, assignments, permission resolution into JWT claims. |
| Cluster | `src/cluster/` | Raft consensus (`openraft`). Invisible in single-node mode. **Experimental in 1.x — not production-supported.** |
| Storage | `src/storage/` | WAL, memtable, SSTs, tiered storage. Leaf layer. |

Dependencies flow strictly downward; `identity/` is the only layer allowed to call `rbac/` (to resolve permissions at token-issue time).

**Guides:** [Getting Started](docs/guides/getting-started.md) · [Concepts](docs/guides/concepts.md) · [RBAC](docs/guides/rbac.md) · [Federation & Social Login](docs/guides/federation.md) · [SCIM Provisioning](docs/guides/scim-provisioning.md) · [Webhooks](docs/guides/webhooks.md) · [Organizations](docs/guides/organizations.md) · [Client-Scoped Roles](docs/guides/client-scoped-roles.md) · [Clustering (Experimental)](docs/guides/clustering.md) · [Troubleshooting](docs/guides/troubleshooting.md) · [Migrating from Keycloak](docs/guides/migrating-from-keycloak.md) · [Migrating from Auth0](docs/guides/migrating-from-auth0.md)

---

## Development

After cloning, run `make setup` to install the repo-managed git hooks, then `make check` before each PR (runs `clippy`, `rustfmt`, and `cargo-nextest`). See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## License

Apache-2.0 (see [`LICENSE`](LICENSE)).
