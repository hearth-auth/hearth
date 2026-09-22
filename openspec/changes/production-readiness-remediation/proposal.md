## Why

The pre-GA production readiness audit of 2026-08-28 returned **NO-GO on all five deployment
shapes**. It confirmed 11 blocker-class defects by reproduction and recorded 244 findings across
25 audited subsystems. Only two blockers need an attacker. The rest fire during ordinary
operation: a clean `SIGTERM` loses acknowledged writes, a documented restore command destroys a
tenant, deleted data returns with no crash, and the release pipeline signs and publishes builds
whose own suite is red.

None of that work is tracked. The report is prose, and prose does not get worked through. This
change turns every item the audit identified into a tracked task, so the NO-GO verdict has an
answer for every line that produced it.

The audit also states the condition that precedes all others: **the build does not currently meet
the project's own definition of green.** `make check` cannot complete — clippy aborts on a hard
compile error, so CI has never executed `cargo fmt --check` or the test suite on the audited
commit. Until that is fixed, no remediation can be verified.

Source: `reports/production-readiness-audit-2026-08-28.md`.

## What Changes

- Establish a single remediation backlog covering every audit item: 244 subsystem findings, the
  8 red build gates in §2, the 7 audit pieces excluded in §7.2, the 7 subsystems never examined
  in §7.3, the 5 gap-closing actions in §8.3, and the 6 systemic risks in §9.
- Sequence the work in five waves. Wave 0 makes the build green; it is a hard gate on everything
  after it. Wave 1 clears the eleven blockers. Waves 2 and 3 clear HIGH then MEDIUM/LOW/
  Informational/claim-defect findings. Wave 4 closes the audit's own coverage gaps.
- **BREAKING** — several fixes change operator-visible behaviour by design:
  - `hearth backup restore --mode=overwrite` refuses rather than half-executing.
  - The server fails to boot when a parsed security key reaches no consumer.
  - Signing-key rotation revokes the retired key instead of honouring a 24-hour grace window.
  - `POST /realms/{name}/introspect` and `/revoke` require client authentication.
  - Every publish channel is gated on the same signal the binary channel already uses.
- Every fix lands with a test that fails against the old code. §9 records that two data-integrity
  regression tests were committed red, and that no test in the repository can distinguish
  `fsync`-before-ack from no `fsync` at all.

## Capabilities

### New Capabilities

- `build-release-integrity`: `make check` completes; no artefact publishes from a commit whose
  suite is red; the version an operator sees is the version that is running. (§2, §4.8, §4.12)
- `storage-durability`: the WAL is `fsync`'d before a write is acknowledged, acknowledged writes
  survive `SIGTERM` and `kill -9`, and a test exists that can tell the difference.
  (§2.1, §4.11)
- `deletion-integrity`: deleted data stays deleted across compaction, SST reload, realm deletion
  and re-import. (§4.9, §4.20, §4.21)
- `backup-restore-safety`: a restore either completes or refuses; a backup round-trips every
  credential factor it claims to carry; the `backup` CLI reports what it did. (§4.9, §4.13, §4.18)
- `tenant-isolation`: the realm a request acts on comes from the caller's identity, never from a
  query parameter, and realm status is enforced on every plane. (§4.1, §4.18, §4.19)
- `token-session-integrity`: rotation revokes, refresh does not re-mint revoked authority, and
  every revocation control is consulted on every token-accepting path. (§4.2, §4.15, §4.16, §4.19)
- `authentication-controls`: SAML, MFA, password recovery and the trusted-proxy client-IP chain
  each enforce what they document. (§4.10, §4.17, §4.18, §4.24)
- `control-liveness`: a parsed and validated security key reaches a consumer, or the server
  refuses to start. (§4.7, §4.13, §4.22)
- `web-ui-browser-security`: the `/ui` tree carries the same guards as the API router, and its
  browser-facing controls (CSRF, cookie flags, CSP, HSTS) hold. (§4.5, §4.23)
- `protocol-surface-hardening`: no request reaches a panic, an unbounded parse, an unguarded
  outbound fetch, or a biased secret draw. (§4.3, §4.4, §4.6, §4.25)

### Modified Capabilities

None. `openspec/specs/` is empty, so every capability above is new.

## Impact

- **Storage** (`src/storage/`): WAL rotation and shutdown flush, partial compaction ordering,
  `reload_sst_readers()`, hot-tier fill/invalidation race, SST mmap `SAFETY:` invariant.
- **Identity** (`src/identity/`): realm deletion cascades, archival freeze, signing-key rotation,
  refresh-token rotation and family binding, MFA gates, password recovery.
- **Protocol** (`src/protocol/`): SAML assertion consumer, `/ui` router guard parity, SCIM filter
  depth, `introspect`/`revoke` client authentication, backup HTTP handlers, byte-slicing panics.
- **Config** (`src/core/`, `hearth.example.yaml`, `docs/specs/CONFIGURATION.md`): zero-valued
  sentinels, `dev_mode`, and a start-up assertion that every parsed security key has a consumer.
- **CI and release** (`.github/workflows/`, `deny.toml`, `Cargo.lock`, Helm chart, Dockerfile):
  required checks, `continue-on-error` removal, publish gating, version derivation, image labels.
- **Dependencies**: `h2` to `>=0.4.16` (RUSTSEC-2026-0258), and the yanked `validit 0.2.5`
  reached through `openraft 0.9.25`.
- **Docs** (`README.md`, `CHANGELOG.md`, `docs/specs/*`, `docs/STATUS.md`): §6 of the audit lists
  more FALSE rows than TRUE. Each false claim is either made true or withdrawn.
