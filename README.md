[![CI](https://github.com/hearth-auth/hearth/actions/workflows/ci.yml/badge.svg)](https://github.com/hearth-auth/hearth/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hearth-auth/hearth/badge)](https://scorecard.dev/viewer/?uri=github.com/hearth-auth/hearth) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0) [![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange)](https://www.rust-lang.org/) ![v4.8.0](https://img.shields.io/badge/status-v4.8.0-brightgreen)

# Hearth — a purpose-built identity database

**Identity is a database problem. Hearth is the database.**

Every other identity provider is an application sitting on top of a generic database — Keycloak on Postgres, Ory split across four binaries, Auth0 on its managed stack. That architecture is why auth is slow, operationally heavy, and fragile. Hearth inverts it: the storage engine is specialized for the identity access pattern, and the OAuth/OIDC/RBAC surfaces are thin protocol adapters on top. That's why it ships as one process instead of four.

---

**Sub-millisecond p99 (engine plane) · One binary · Zero external dependencies**

Token validation, session lookup, and permission checks run in-process against lock-free in-memory structures (epoch-reclaimed `HashMap` snapshots) — no network hop, no cache round-trip, no database query on the hot path. Deploy as a single binary with one config file and a data directory. No Postgres to provision, no Redis to invalidate, no policy service to operate.

> **Stable 4.8.0:** APIs and on-disk formats are stable. See [CHANGELOG](CHANGELOG.md) for the full release history.
>
> **Upgrade from 1.x:** 2.0.x carries the GA audit fixes merged in PRs #358 through #380. It
> changes several defaults and token claim values; read the [upgrading guide](docs/guides/upgrading.md)
> and the breaking entries in the [CHANGELOG](CHANGELOG.md) before you upgrade.

---

## Install

Download pre-built v4.8.0 artifacts from the [Releases page](https://github.com/hearth-auth/hearth/releases/tag/v4.8.0), or use Docker or Helm.

### Released binary — Linux / macOS

```bash
# Example: Linux x86_64. Swap the filename for your platform:
#   hearth-linux-amd64 | hearth-linux-arm64
#   hearth-darwin-amd64 | hearth-darwin-arm64
ARTIFACT=hearth-linux-amd64

BASE=https://github.com/hearth-auth/hearth/releases/download/v3.5.13

curl -LO "${BASE}/${ARTIFACT}"
curl -LO "${BASE}/SHA256SUMS"
curl -LO "${BASE}/SHA256SUMS.sigstore.json"

# 1. Verify the checksum manifest itself. Requires cosign v2.4+
#    (brew install cosign). Without this step the checksum below proves
#    nothing: anyone who can replace the binary can replace SHA256SUMS
#    beside it. The signature is bound to Hearth's release workflow and
#    logged to Sigstore's public transparency log, so it cannot be forged.
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
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
  -Uri "https://github.com/hearth-auth/hearth/releases/download/v4.8.0/hearth-windows-amd64.exe" `
  -OutFile hearth-windows-amd64.exe
foreach ($f in 'SHA256SUMS','SHA256SUMS.sigstore.json') {
  Invoke-WebRequest `
    -Uri "https://github.com/hearth-auth/hearth/releases/download/v4.8.0/$f" `
    -OutFile $f
}

# 1. Verify the checksum manifest itself (cosign v2.4+). Without this the
#    checksum below proves nothing — see the note under the Linux/macOS block.
cosign verify-blob `
  --bundle SHA256SUMS.sigstore.json `
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

```bash
docker pull ghcr.io/hearth-auth/hearth:v4.8.0

# Dev mode — in-memory store, no data persistence (Linux only; --dev requires loopback bind)
docker run --rm --network=host ghcr.io/hearth-auth/hearth:v4.8.0 serve --dev
curl -fsS http://127.0.0.1:8420/health   # → {"status":"ok"}
```

> **Mac / Windows Docker Desktop:** `--network=host` does not map to the host loopback on Docker Desktop. Use the Docker Compose stack (`deploy/docker-compose.yml`) for a cross-platform setup, or run from source (`cargo run --features dev-endpoints -- serve --dev`).

### Helm OCI chart (signed)

```bash
helm install hearth oci://ghcr.io/hearth-auth/charts/hearth \
  --version 4.8.0 \
  --namespace auth \
  --create-namespace
```

The chart is cosign-signed (keyless OIDC). To verify:

```bash
cosign verify \
  --certificate-identity-regexp \
    '^https://github\.com/hearth-auth/hearth/\.github/workflows/helm\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/hearth-auth/charts/hearth:4.8.0
```

For signature and SLSA provenance verification of binaries, see [docs/guides/verify-release.md](docs/guides/verify-release.md). For production deployment (systemd, Docker Compose, Kubernetes), see [`deploy/README.md`](deploy/README.md).

---

## Try it in 30 seconds

```bash
cargo build --release --features dev-endpoints   # bootstrap is opt-in, never in a default build
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
  "system_realm_id":     "00000000-0000-0000-0000-000000000000",
  "totp_secret":         "JBSWY3DPEHPK3PXP...",
  "admin_totp_secret":   "KRUGS4ZANFZSAYJA..."
}
```

`admin_password` is only populated on the **first** bootstrap call — store it securely, it is never returned again. Re-bootstrap (when the dev-realm already exists) requires the `Authorization: Bearer <access_token>` header from the first bootstrap and returns `"admin_password": null` (JSON null, not `""` — `jq -r .admin_password` prints the string `null`).

The `dev-realm` requires MFA. The first bootstrap call enrols TOTP for both admins. It returns `totp_secret` (base32, for `admin@dev.local`) and `admin_totp_secret` (base32, for `admin@hearth.test`) once. Both are empty on re-bootstrap. The returned tokens work without a code.

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
- Three permission-delivery modes per client: `embedded` (default, stateless), `introspection` (live RBAC via `/introspect`), `decision` (per-request allow/deny via `POST /oauth/authorize`) — see [Permission-delivery modes guide](docs/guides/permission-delivery.mdx)

**Multi-tenancy**
- Realm-isolated keyspace (every key prefixed with `RealmId`)
- Per-realm Ed25519 signing keys with JWKS rotation (plus an RSA key for RS256 ID tokens, created only for clients that request `id_token_signed_response_alg: RS256`)
- Cascading deletion across users, sessions, credentials, OAuth clients, role assignments, device codes, signing keys

**Protocols**
- OIDC Core 1.0 + Discovery 1.0 + Dynamic Client Registration (RFC 7591; RFC 7592 management endpoints are roadmap)
- Token Introspection (RFC 7662), Revocation (RFC 7009), RP-initiated logout
- SAML 2.0 as a Service Provider (inbound federation from your corporate IdP — SP-initiated and IdP-initiated SSO). Hearth is not a SAML IdP; applications connect over OIDC. Encrypted assertions and Single Logout are not supported — see [openspec/specs/saml-sp-profile/spec.md](openspec/specs/saml-sp-profile/spec.md)
- SCIM 2.0 provisioning (Users, Groups, Service Provider Config)
- Signed webhook subscriptions for auth and admin events
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

All figures below are from one load test on 2026-10-10 (network plane, build `11960149` = v3.4.0). The source of record is [`docs/perf/2026-10-10-aws-c7i-large.md`](docs/perf/2026-10-10-aws-c7i-large.md), with the raw data and the method.

- **Server:** AWS c7i.large (2 vCPU, 3.8 GB RAM), 1,000,000 users, production build, HTTPS (TLS 1.3, HTTP/2), every write fsynced to the WAL before the acknowledgement.
- **Load:** 2 separate c7i.xlarge hosts with k6, open loop. The network plane includes TLS, TCP and network time.
- **Password hashing:** Argon2id with memory 19,456 KiB, 2 iterations, parallelism 1 (OWASP). At most 2 hashes run at the same time on this server.

"Clean" means 0 dropped requests, errors below 0.1%, and p99 below 1 s.

| Feature | Clean rate | p99 at that rate | Max served |
|---|---|---|---|
| Password login (4 requests, 1 Argon2id check) | 50 logins/s | 207 ms | ~56 logins/s (limited by Argon2id) |
| Token refresh (with rotation) | ≥1,088 refreshes/s | 86 ms | Not reached (server CPU 104% of 200%) |
| Userinfo | 8,000 req/s | 10 ms | ~9,970 req/s |
| Admin user lookup | 10,000 req/s | 21 ms | ~11,200 req/s |
| Token introspection | 4,500 req/s | 18 ms | ~5,410 req/s |
| User creation (admin API) | ≥1,377 creates/s | 56 ms | Not reached (server CPU 51%) |
| Mix: 65% refresh, 15% login, 15% userinfo, 5% admin lookup | 250 journeys/s | 258 ms (login) | 632 journeys/s, with login sheds |

On this 2-vCPU server, password login is the limit: each Argon2id check takes 33–38 ms on one vCPU. The other features have much more headroom. In a 60-minute soak at 120 journeys/s, refresh p99 was 83 ms and login p99 was 166 ms. Server memory grew 291 MiB/h in the second half of the soak; whether it levels off is still open (#445).

We publish no competitor comparison. These figures are for one server size and one run per feature.

---

## How we build it

Hearth has eight testing layers: unit, black box, property, fuzz, crash-recovery simulation,
adversarial, conformance and benchmarks. All of them run locally and in CI.
[`docs/dev/TESTING.md`](docs/dev/TESTING.md) describes each layer. The storage engine must
survive `kill -9` at any point, and every WAL invariant has a crash-recovery test.

Every test suite and the SDK conformance check are in the `needs:` list of the
`required-summary` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml), so a red suite
blocks a merge. This README does not claim a green result for a commit. Look at the CI badge
above, or at the `validation-summary.txt` asset of a release.

**Hearth is not certified** against any standard. The OpenID Foundation conformance suite runs
locally: the latest run (2026-11-08) passes the Config OP profile and fails the Basic OP and
Dynamic OP profiles ([`reports/oidf-conformance-2026-11-08.md`](reports/oidf-conformance-2026-11-08.md)).

---

## Quick Start

### Prerequisites

- **Rust 1.88.0+** (see [`Cargo.toml`](Cargo.toml) `rust-version`)
- **`protoc`** — `build.rs` runs it on every build to generate the API message types from `proto/`.
  Install it (`brew install protobuf`, `apt install protobuf-compiler`, or a
  release from [protobuf/releases](https://github.com/protocolbuffers/protobuf/releases))
  and make sure it is on `PATH`, or set `PROTOC=/path/to/protoc`.
- `buf` (optional — only needed if you edit `proto/**/*.proto`; see [`CONTRIBUTING.md`](CONTRIBUTING.md))

### 1. Build

```bash
cargo build --release
# Binary: target/release/hearth
```

That is a production build. The dev-only surface — `POST /admin/bootstrap`, the `/dev/seed-*`
routes and the hard-coded dev admin password — is behind the `dev-endpoints` cargo feature,
which is **not** on by default. To use the bootstrap flow, build with
`cargo build --release --features dev-endpoints` (or just run `make dev`). `serve --dev` on a
featureless binary still starts, and logs that bootstrap is unavailable.

### 2. Run in dev mode

```bash
./target/release/hearth serve --dev
```

Dev mode uses `debug` logging, `fsync` disabled, and enables the `/admin/bootstrap` endpoint. The server binds to `127.0.0.1:8420`.

Storage is still a real WAL + SST store, not a RAM-only mode — it just lives in a throwaway location. The effective directory follows a three-level rule: `HEARTH_DEV_DATA_DIR` if set, else an explicit non-default `storage.data_dir`, else a temp directory removed on exit. Bare `./target/release/hearth serve --dev` takes the third branch, so nothing survives a restart; **`make dev` takes the first** (it sets `HEARTH_DEV_DATA_DIR=./data/dev`, which is gitignored) and therefore **does** persist across restarts — `make dev-reset` wipes it. See [`docs/guides/configuration-reference.md`](docs/guides/configuration-reference.md#--dev-mode-and-hearth_dev_data_dir).

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

Under `--dev`, `POST /admin/bootstrap` creates a realm, an admin user and tokens. It also
creates the console operator `admin@hearth.test` in the system realm. The first call alone
returns the passwords and the TOTP secrets. In production the route answers `404`.
[`docs/dev/DEVELOPMENT.md`](docs/dev/DEVELOPMENT.md) describes the dev accounts, the response
and re-bootstrap. [Getting Started](docs/guides/getting-started.mdx) uses it to register an app.
To create the first admin in production, see
[Getting Started → the first admin in production](docs/guides/getting-started.mdx#the-first-admin-in-production).

Every `/admin/*` JSON route needs an `X-Realm-ID` header with the bearer token. Without it the
call answers `400`, not `401`.

---

## Configuration

`hearth serve` reads `-c <path>`, else `./hearth.yaml`, else the built-in defaults; `--dev`
overrides all of them. Copy [`hearth.example.yaml`](hearth.example.yaml), which lists every key,
and run `hearth config validate hearth.yaml`. Secrets come from the environment:
`HEARTH_MASTER_KEY` and `HEARTH_KEK` are required in production.
`branding.theme` selects one of six UI themes, and `branding.custom_css` overrides its
`--ht-*` CSS variables.

The [configuration reference](docs/guides/configuration-reference.md) has every key, the
smallest production config, the environment variables and the themes.
[`docs/dev/THEME.md`](docs/dev/THEME.md) lists the CSS tokens.

---

## Local Development

`make dev` runs `cargo run --features dev-endpoints -- serve --dev` on `127.0.0.1:8420`, with
its data in `./data/dev` (`make dev-reset` wipes it). Open `/dev` to sign in with one click.
Every outbound email goes to the built-in mailcatcher at `/dev/mail`. See
[`docs/dev/DEVELOPMENT.md`](docs/dev/DEVELOPMENT.md). Production deployment (container,
persistent storage, real email) is in [`deploy/`](deploy/).

---

## CLI Reference

```text
hearth serve [--dev] [-c, --config <path>] [--port <u16>] [--bind <addr>] [-v]
hearth realm create
hearth app create --server <url> --realm-id <uuid> --name <name> --redirect-uri <url> --token <admin-bearer-token>
hearth migrate keycloak --file <export.json> [--data-dir <path>] [--realm <uuid>] [--dry-run]
hearth migrate auth0 --file <bundle.json> [--data-dir <path>] [--realm <uuid>] [--dry-run]
hearth migrate rotate-pepper --data-dir <path> [--summary-only]
hearth config validate [<path>]            # defaults to ./hearth.yaml
hearth config example [-o <path>]          # print an annotated hearth.yaml
hearth config reload [--url <url>] [--pid-file <path>]   # hot reload: POST, or SIGHUP via PID file
hearth backup create  [-o <archive>] [--realm <name|uuid>] [--include-audit] [--encrypt] [--sign-key <key.pem>]
                      [--data-dir <path>] [--config <hearth.yaml>]
hearth backup restore -i <archive> [--realm <slug>] [--mode skip|overwrite|merge] [--dry-run]
                      [--allow-missing-signing-key] [--verify-key <base64url>] [--allow-unsigned]
                      [--data-dir <path>] [--config <hearth.yaml>]
hearth backup verify  -i <archive>
hearth backup inspect -i <archive>
hearth backup sign    -i <archive> --key-file <key.pem> [-o <archive>]
hearth backup keygen  -o <key.pem>
hearth rbac orphans list  [--realm <name|uuid>] [--data-dir <path>]
hearth rbac orphans purge [--realm <name|uuid>] [--data-dir <path>] [--dry-run]
hearth admin token --user <email> [--ttl <1m..1h>] [--data-dir <path>] [--config <hearth.yaml>]
                   [--sole-cluster-node]
hearth completions <bash|elvish|fish|powershell|zsh>
```

Run `hearth <command> --help` for the authoritative flag list; the block above is the full set of subcommands as of this revision.

- **`serve`** starts the HTTP(S) server. `--dev` implies a throwaway data directory, relaxed validation, and the bootstrap endpoint.
- **`realm create`** prints `{"realm_id": "<uuid>"}` on stdout. It's a pure UUID generator and does not require a running server.
- **`app create`** registers an OAuth 2.0 client by POSTing to `/clients` on a running Hearth server. The server URL must be reachable over HTTP. `--token` is **mandatory** — client registration is a privileged operation, so pass an admin bearer token carrying `hearth.clients.admin` (or `hearth.admin`); in dev mode, the `access_token` from `POST /admin/bootstrap`.
- **`migrate keycloak` / `migrate auth0`** import a realm export directly into the embedded store. Both operate on the data directory offline (no running server needed) — see [Migrating from Keycloak or Auth0](#migrating-from-keycloak-or-auth0).
- **`config validate`** parses the YAML and validates every realm's permission registry without starting the server; exits 1 on any error. It does **not** check the `HEARTH_*` environment prerequisites — a config it accepts can still be refused by `serve` (for example when `HEARTH_MASTER_KEY` is unset on a fresh production data directory).
- **`admin token`** prints a short-lived token for the system realm (the nil UUID) for an operator-console account holding `hearth.admin` — the production source of the `$SYSTEM_TOKEN` the realm and cluster admin API need. The token goes to stdout only and its issuance is audited. A cluster node's data directory is refused; see [System-realm tokens](docs/guides/clustering.md#system-realm-tokens).
- **`backup` / `rbac orphans` / `migrate` / `admin token`** all open the store directly, so the server **must be stopped first** — the data directory carries an exclusive `LOCK`. See the [Backup guide](docs/guides/backup.md).

---

## End-to-End OAuth flow

[Getting Started](docs/guides/getting-started.mdx) takes you from a clean clone to a signed
token. Its `curl` tab does the PKCE authorization-code flow with `curl`, `jq` and `openssl`.
[`docs/guides/concepts.md`](docs/guides/concepts.md) explains refresh-token rotation and grant
families.

---

## External IdP Federation (social login)

Hearth is also an OIDC and SAML **relying party**. Users can sign in with Google, Microsoft,
Apple, GitHub, any OIDC provider (`type: oidc`) or a SAML 2.0 IdP (`type: saml`). Connectors are
declared per realm in `hearth.yaml`, and never through an admin UI.
`federation.link_existing_accounts` (`disabled`, `confirm` (the default) or `auto`) controls how
an external login attaches to a local user with the same email. **`auto` is an account-takeover
risk** unless the realm federates to exactly one IdP that verifies email.
See the [federation guide](docs/guides/federation.md) and
[`examples/federation-flow/`](examples/federation-flow/).

---

## API Endpoints

The OAuth/OIDC endpoints are at the root with an `X-Realm-ID` header, or under
`/realms/{realm_name}/` without one. The admin API is under `/admin/*`; every route needs a token
with `hearth.admin` for the target realm. A running server serves the OpenAPI spec at `/openapi.json`
and a Swagger UI at `/docs`.

- [Route map](docs/guides/api-reference.md#route-map): every endpoint group, with its paths.
- [Admin API guide](docs/guides/admin-api.md): the admin routes, with examples.
- [SCIM provisioning](docs/guides/scim-provisioning.md): SCIM 2.0 at `/realms/{realm_name}/scim/v2`.

---

## Client SDKs

Four first-party SDKs live under [`sdks/`](sdks): TypeScript (browser and Node.js, including
Express, Fastify and Next.js helpers), Go, Python and PHP. The published versions can lag the
source tree; check the registry for the current version.

| SDK | Package | Registry |
|---|---|---|
| TypeScript | `@hearth-auth/sdk` | npm |
| Go | `github.com/hearth-auth/hearth/sdks/go/v4` | Go module proxy, from v4.0.0 (`.../sdks/go/v3` holds the 3.x releases; the old path `.../sdks/go` stops at v1.6.11) |
| Python | `hearth-sdk` | PyPI |
| PHP | `hearth-auth/php-sdk` | Packagist, **`dev-main` only** (no tagged release) |

See [docs/guides/sdks/overview.md](docs/guides/sdks/overview.md) for per-SDK install notes.
Two examples:

**TypeScript** — [`sdks/typescript/`](sdks/typescript) (package `@hearth-auth/sdk`)

```ts
import { HearthClient } from "@hearth-auth/sdk";
const hearth = new HearthClient({ baseUrl: "https://auth.example.com", realmId });
```

**Go** — [`sdks/go/`](sdks/go) (module `github.com/hearth-auth/hearth/sdks/go/v4`)

```go
import "github.com/hearth-auth/hearth/sdks/go/v4/hearth"
client := hearth.NewClient("https://auth.example.com", realmID)
```

Each SDK has a README with full API docs under `sdks/<language>/README.md`, for example [`sdks/typescript/README.md`](sdks/typescript/README.md) and [`sdks/go/README.md`](sdks/go/README.md).

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
- **The system realm is read-only through public APIs.** `realms: { system: {} }` in YAML is a config error at parse time (`src/config/validate.rs`). Fifteen engine entry points reject the reserved realm with a 403 `SystemRealmProtected` — by nil UUID where the request is id-addressed, and by the reserved name `system` where it is name-addressed: `create_realm`, `update_realm`, `delete_realm`, `create_user`, `create_user_attributed`, `register_user`, `register_client`, `create_organization`, `update_organization`, `create_agent`, `import_realm`, `import_user`, `import_client`, `seed_demo_users`, and realm reconciliation. **RBAC writes are gated at the protocol edge instead**, not in the engine: `reject_system_realm_write` guards the REST admin RBAC write routes (`src/protocol/http/admin.rs` and `src/protocol/http/admin/`), because the operator console legitimately writes system-realm roles through the engine directly. The realm does not appear in `list_realms()` or `search_realms()`, `get_realm_by_name("system")` returns `None`, and `/ui/realms/system/...` URLs return 404.
- **Operators run the first-run setup exactly once**, regardless of how many application realms they've declared. The admin user is always placed in the system realm; tenant realms stay empty of operators.

Admins administer tenant realms via a `?realm=<name>` query parameter on admin URLs, which persists for the session via the `hearth_ui_admin_target` cookie. Switching realms is done either by visiting `/ui/admin/realms` and clicking "Administer this realm" next to the target, or by typing `?realm=<name>` in the URL. The admin's session cookie is always bound to the system realm; the target realm is orthogonal.

---

## Migrating from Keycloak or Auth0

`hearth migrate keycloak --file <realm-export.json>` and `hearth migrate auth0 --file <bundle.json>`
import into the data directory offline, with the server stopped. Run each with `--dry-run`
first. Keycloak PBKDF2-SHA256 password hashes verify without a reset. Auth0 has no single
export, so [`examples/auth0-migration-bundler/`](examples/auth0-migration-bundler/) builds the
bundle. The guides have the full mapping, what is not imported, and the checklists:
[from Keycloak](docs/guides/migrating-from-keycloak.md) and
[from Auth0](docs/guides/migrating-from-auth0.md).

---

## Architecture at a glance

```
┌──────────────────────────────────────────────────────────────┐
│                     Single binary process                     │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Protocol   REST · OIDC · SAML · SCIM · WebUI          │ │
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
| Protocol | `src/protocol/` | Stateless wire adapters (REST, OIDC, SAML, SCIM). |
| Identity | `src/identity/` | Users, credentials, sessions, realms, tokens. |
| RBAC | `src/rbac/` | Roles, groups, assignments, permission resolution into JWT claims. |
| Cluster | `src/cluster/` | Raft consensus (`openraft`). Invisible in single-node mode. **Experimental — not production-supported.** |
| Storage | `src/storage/` | WAL, memtable, SSTs, tiered storage. Leaf layer. |

Dependencies flow strictly downward; `identity/` is the only layer allowed to call `rbac/` (to resolve permissions at token-issue time).

**Guides:** [Getting Started](docs/guides/getting-started.mdx) · [Concepts](docs/guides/concepts.md) · [RBAC](docs/guides/rbac.mdx) · [Federation & Social Login](docs/guides/federation.md) · [SCIM Provisioning](docs/guides/scim-provisioning.md) · [Webhooks](docs/guides/webhooks.mdx) · [Organizations](docs/guides/organizations.mdx) · [Client-Scoped Roles](docs/guides/client-scoped-roles.md) · [Clustering (Experimental)](docs/guides/clustering.md) · [Troubleshooting](docs/guides/troubleshooting.md) · [Migrating from Keycloak](docs/guides/migrating-from-keycloak.md) · [Migrating from Auth0](docs/guides/migrating-from-auth0.md)

---

## Development

After cloning, run `make setup` to install the repo-managed git hooks, then `make check` before each PR (runs `clippy`, `rustfmt`, and `cargo-nextest`). See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## License

Apache-2.0 (see [`LICENSE`](LICENSE)).
