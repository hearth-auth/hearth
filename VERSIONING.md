# Versioning Policy

Hearth follows [Semantic Versioning 2.0.0](https://semver.org/). This document defines what is a
breaking change for each public surface, and which releases get fixes.

## Status: normative

The current release line is 4.x. Releases are automatic: `semantic-release` reads the
Conventional Commit messages on `main` and picks the next version (see
[`docs/dev/DEVELOPMENT.md`](docs/dev/DEVELOPMENT.md)).

Hearth has no production users yet. Thus:

- A breaking change is allowed. It MUST carry a `!` or a `BREAKING CHANGE:` footer, so that
  the release is a major version bump. A CHANGELOG entry records a break; it does not
  authorize one in a minor or patch release.
- Hearth removes an old surface. It does not deprecate it first. There is no deprecation
  window, no `### Deprecated` CHANGELOG entry and no compatibility shim. The `### Removed` or
  `### Changed` entry names the replacement.
- On-disk format changes MUST NOT silently corrupt data. If a format is incompatible, Hearth
  MUST fail at startup with a clear error. (Not yet met for a *rollback* to an older binary:
  see [On-disk storage format](#on-disk-storage-format-wal-sst).)

This policy changes when Hearth has production users. The change will be announced in the
CHANGELOG and in this file.

---

## What constitutes a breaking change

A change is breaking for a surface if an operator or integrator who follows the documented
behaviour must update their configuration, code or tooling to keep their system working.

### REST HTTP API

| Route family | Prefix | Versioning |
|---|---|---|
| URL-versioned API | `/v1/…` | URL-versioned. Covers agents, approval requests, tool invocation, `/v1/me/permissions` and the other `/v1` routes. A breaking change ships under `/v2/…`. |
| Admin API | `/admin/…` | Unprefixed. Versioned by the Hearth release version. |
| OIDC / OAuth 2.0 per-realm | `/realms/{realm}/…` | Shape is pinned by the OIDC and OAuth 2.0 specifications, not by Hearth's version. |
| SCIM 2.0 | `/realms/{realm}/scim/v2/…`, `/scim/v2/…` | `v2` is the SCIM protocol version (RFC 7644), not a Hearth API version. |
| Discovery / operational | `/.well-known/…`, `/health` | Unprefixed. Discovery document shapes are pinned by their specs (OIDC Discovery, RFC 9728). `/health` is operational and stable. |

Browser-facing (`/ui/…`) and dev-only (`/dev/…`) routes are **not** a public API surface and
carry no compatibility commitment. `/dev/…` routes are registered only when the server runs in
dev mode, so they are absent from the production route table (regression-guarded by
`dev_seed_password_absent_in_production_mode`).

| Change | Breaking? |
|---|---|
| Remove or rename an endpoint | Yes |
| Remove or rename a request field | Yes |
| Add a required request field | Yes |
| Change the meaning or type of a response field | Yes |
| Change an HTTP status code | Yes |
| Add an optional request field with a safe default | No |
| Add fields to a response body | No |
| Add a new endpoint | No |
| Change an error message string | No (codes are stable) |

### Protocol buffers

Hearth 3.0.0 removed the public gRPC API. The `proto/` files still define the message types
that the REST API serialises, so a change to a message is a REST change and follows the REST
rules above. The cluster's internal Raft transport also uses gRPC; it is not a public surface.

### Configuration (`hearth.yaml`)

| Change | Breaking? |
|---|---|
| Remove a key | Yes |
| Rename a key | Yes (old key removed) |
| Change the type of a value | Yes |
| Tighten validation on an existing key | Yes |
| Add a new optional key | No |
| Change a default value | Yes if the old default was the only safe choice; No otherwise |

Config structs carry `#[serde(deny_unknown_fields)]`, so an unknown key stops startup. A key
that Hearth removed stops startup with an error that names it (`src/config/removed.rs`).

### On-disk storage format (WAL, SST)

- A Hearth binary MUST read the storage formats (WAL, SST files) that the preceding minor
  version wrote.
- A format version bump is a `**Breaking:**` CHANGELOG entry and is one-directional: a newer
  binary reads old data; an older binary refuses new data with a clear error.
- **In-place binary rollback is NOT guaranteed safe, even between patch releases.** The WAL and
  SST *headers* are versioned, but the records inside them are `postcard`-encoded
  (`src/codec.rs`) with no per-record version, and the stored types change between releases.
  An older binary cannot decode such a record, and nothing refuses to start first. **Known
  gap:** until records carry a schema version and the data directory carries a minimum-reader
  marker checked at open, the supported rollback is to restore the pre-upgrade backup
  ([upgrading guide](docs/guides/upgrading.md#rollback-procedure)).

### SDK public API

Hearth ships four SDKs under `sdks/`: `go`, `php`, `python` and `typescript`. Their public
types, method signatures and exported symbols are the stability surface. Removing or renaming
one is breaking. Each SDK's own `CHANGELOG.md` records its removals in sync with the server
release.

An SDK method that calls a server route the server does not implement is a defect, not a
stability commitment. It is removed as a fix.

---

## Supported versions

Only the latest release gets fixes. A fix lands on `main` and ships in the next release. There
are no back-port branches.

---

## Cross-references

- [CHANGELOG.md](CHANGELOG.md): per-release record of breaking changes and removals
- [docs/guides/upgrading.md](docs/guides/upgrading.md): upgrade procedure and operator notes
- [docs/dev/ARCHITECTURE.md](docs/dev/ARCHITECTURE.md) § 4.3 API Versioning and § 6.4 Format
  Versioning: structural rules enforced at the code level
