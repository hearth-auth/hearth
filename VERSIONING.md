# Versioning Policy

Hearth follows [Semantic Versioning 2.0.0](https://semver.org/). This document defines what constitutes a breaking change for each public surface, how long the 1.x line is supported, and how deprecations are communicated before a breaking change ships.

## Status: normative

**1.0 GA shipped on 2026-06-21** (`## [1.0.0]` in [`CHANGELOG.md`](CHANGELOG.md); tag `v1.0.0`). The
current release line is 1.6.x. The rules in this document are therefore **normative today** — they
are not aspirational, and they are not deferred to a future GA milestone.

Two consequences follow, and they bind every PR:

- On-disk format changes must **not** silently corrupt data. If a format is incompatible, Hearth
  must fail at startup with a clear error.
- A change that is breaking under the definitions below requires a **major version bump**. It may
  not ship in a 1.x minor or patch release merely because it carries a `**Breaking:**` CHANGELOG
  entry. A CHANGELOG entry documents a break; it does not authorize one.

---

## What constitutes a breaking change

Different surfaces carry different stability commitments. A change is breaking for a given surface if an operator or integrator following documented behaviour would need to update their configuration, code, or tooling for their system to continue working correctly.

### REST HTTP API

The REST surface is not uniformly version-prefixed today. These route families exist, and the
versioning commitment differs per family:

| Route family | Prefix | Versioning |
|---|---|---|
| URL-versioned API | `/v1/…` | URL-versioned. Covers agents, AATs, approval requests, cross-realm policies, SPIFFE mappings, transaction tokens, tool invocation, `/v1/me/permissions`, and `/v1/{realm}/auth/magic-link`. A breaking change ships under `/v2/…`. |
| Admin API | `/admin/…` | Unprefixed. Versioned by the release version; breaking changes follow the deprecation policy below. |
| OIDC / OAuth 2.0 per-realm | `/realms/{realm}/…` | Shape is pinned by the OIDC and OAuth 2.0 specifications, not by Hearth's version. |
| SCIM 2.0 | `/scim/v2/…` | `v2` is the SCIM protocol version (RFC 7644), not a Hearth API version. |
| Discovery / operational | `/.well-known/…`, `/health` | Unprefixed. Discovery document shapes are pinned by their respective specs (OIDC Discovery, RFC 9728); `/health` is operational and stable. |

Browser-facing (`/ui/…`) and dev-only (`/dev/…`) routes are **not** a public API surface and carry no
compatibility commitment. `/dev/…` routes are registered only when the server runs in dev mode, so they
are absent from the production route table entirely (regression-guarded by
`dev_seed_password_absent_in_production_mode`); they must never be exposed in production.

Extending the `/v1/` prefix to the admin surface is itself a breaking change and is therefore a 2.0 candidate, tracked as a migration-guide item.

The table below defines what counts as breaking for **every** committed family above:

| Change | Breaking? |
|---|---|
| Remove or rename an endpoint | Yes |
| Remove or rename a request field | Yes |
| Add a required request field | Yes |
| Change the meaning or type of a response field | Yes |
| Add an optional request field with a safe default | No |
| Add fields to a response body | No |
| Add a new endpoint | No |
| Change an error message string | No (codes are stable) |
| Change an HTTP status code | Yes |

For a URL-versioned family, a breaking change requires a new prefix (`/v2/…`) and the previous version must be served for at least one full major release. For an unprefixed family, a breaking change requires a major version bump of Hearth itself plus the deprecation notice period below. Concurrent support of two active versions will be documented in [`docs/specs/ARCHITECTURE.md`](docs/specs/ARCHITECTURE.md) § 4.3 and the CHANGELOG.

### gRPC API (`hearth.*` protobuf services)

The same rules apply as for the REST API. Hearth runs `buf breaking --against main` on every proto-touching PR to enforce wire compatibility. A breaking proto change triggers a new service major version suffix (e.g., `RbacAdminV2Service`).

Fields removed from proto definitions must first be deprecated for one major release (annotated with `// Deprecated:` in the `.proto` file and announced in CHANGELOG).

### Configuration (`hearth.yaml`)

| Change | Breaking? |
|---|---|
| Remove a key | Yes |
| Rename a key | Yes (old key removed) |
| Change the type of a value | Yes |
| Tighten validation on an existing key | Yes |
| Add a new optional key | No |
| Change a default value | Yes if the old default was the only safe choice; No otherwise |

Config structs carry `#[serde(deny_unknown_fields)]` from the 1.7 release onward (see the v1.6 → v1.7 entry in [`docs/guides/upgrading.md`](docs/guides/upgrading.md)). Removed keys that were formerly silently ignored will now produce a hard startup error. Check the `### Changed` / `### Removed` section of CHANGELOG before upgrading.

### On-disk storage format (WAL, SST)

- A Hearth binary must be able to read storage formats (WAL, SST files) written by the immediately preceding minor version.
- Format version bumps are announced as `**Breaking:**` entries in CHANGELOG and are always one-directional: a newer binary reads old data; an older binary refuses new data with a clear error.
- In-place binary rollback between patch releases (same minor version) is always safe — the WAL format version has not changed within any shipped 1.x minor release.

### SDK public API

Hearth ships seven SDKs (`sdks/`: `go`, `kotlin`, `node`, `php`, `python`, `rust`, `typescript`).

| Language | Stability surface |
|---|---|
| Go, Kotlin, Node, PHP, Python, Rust, TypeScript | Public types, method signatures, exported symbols |

An SDK method that calls a server route the server does not implement is a defect, not a stability commitment — such methods are removed without a deprecation period (precedent: `createRealm`, removed from all seven SDKs in HEA-2171 because `POST /admin/realms` has always returned `405`).

Removed or renamed SDK methods are breaking. Methods annotated with `@deprecated` (or the language equivalent) are supported for one major release after the deprecation annotation ships. The CHANGELOG for each SDK records deprecations and removals in sync with the server release.

---

## Support window for the 1.x line

| Phase | Duration | What ships |
|---|---|---|
| Active development | Until 1.0 GA | Features, fixes, breaking changes (with CHANGELOG entry) |
| Active support | 18 months from 1.0 GA date | Feature releases, bug fixes, security fixes |
| Security-only | 6 months after active support ends | Security fixes only; no new features or non-security bug fixes |
| End-of-life | 24 months from 1.0 GA date | No further patches; migrate to 2.x |

The 1.0 GA date will be recorded in `CHANGELOG.md` when the `## [Unreleased]` header is replaced with `## [1.0.0] — YYYY-MM-DD`.

**Security fixes** during the security-only phase are released as patch versions (e.g., 1.x.y → 1.x.z). They are back-ported from the 2.x main branch where feasible.

---

## Deprecation policy

Before removing or renaming any endpoint, config key, CLI flag, or SDK method:

1. **Announce** — add a `### Deprecated` entry to CHANGELOG listing the item, the recommended replacement, and the target version of removal.
2. **Notice period** — the deprecated item ships in at least one minor release before removal. For breaking HTTP or gRPC changes, the notice period is one full major version.
3. **Remove** — the item is removed in the announced target version, with a `### Removed` or `**Breaking:**` CHANGELOG entry.

Deprecation annotations in source code:
- Rust: `#[deprecated(since = "1.x.0", note = "...")]`
- TypeScript/Go/Python/Kotlin/PHP: language-native deprecation annotation

---

## Shipping a 2.0

A major version bump is the only mechanism for landing a breaking change once 1.0 GA ships. Every 2.0 release must satisfy all four of the following before the tag is pushed:

1. **Deprecation notice already served.** Every surface being removed or changed in 2.0 shipped a `### Deprecated` CHANGELOG entry in a 1.x minor release at least **one full minor release** before the 2.0 tag, naming the replacement and `2.0.0` as the removal target. A breaking change with no prior 1.x deprecation entry does not ship in 2.0 — it waits for 3.0.
2. **Migration guide published.** `docs/guides/migrating-1x-to-2x.md` must exist and must contain, for every breaking change: the old behaviour, the new behaviour, the concrete edit an operator or integrator makes, and whether the change is detected at startup or silently at runtime. A breaking change absent from the migration guide blocks the release.
3. **Startup detection where possible.** Any breaking config or on-disk format change must fail closed at startup with an error naming the migration guide, rather than degrading at runtime. Changes that cannot be detected at startup must be called out explicitly in the migration guide as silent.
4. **1.x support window honoured.** The 1.x line continues to receive fixes on the schedule in the support-window table above; a 2.0 release does not shorten it.

The migration guide is linked from the 2.0 CHANGELOG heading, the release notes, and the EOL notice below.

---

## EOL communication

End-of-life for the 1.x line will be announced:
- As a pinned GitHub issue on the `hearth-auth/hearth` repository, at least **6 months** before the EOL date.
- As a `### Deprecated` entry in CHANGELOG at the same time.
- As a `WARN`-level log message emitted at startup once the binary's minor version is within the security-only phase.

The GitHub issue will link to a migration guide for the 2.x line.

---

## Cross-references

- [CHANGELOG.md](CHANGELOG.md) — per-release record of breaking changes, deprecations, and removals
- [docs/guides/upgrading.md](docs/guides/upgrading.md) — upgrade procedure and per-version operator notes
- [docs/specs/ARCHITECTURE.md](docs/specs/ARCHITECTURE.md) § 4.3 API Versioning and § 6.4 Format Versioning — structural rules enforced at the code level
