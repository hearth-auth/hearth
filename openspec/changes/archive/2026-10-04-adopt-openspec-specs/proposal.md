## Why

The normative specs live in `docs/specs/` as long prose files (about 13,500 lines). They mix requirements with phase trackers, decision logs, Rust API signatures and storage layouts. Nothing checks them, and several drifted from the code. `openspec/specs/` is empty, so the active changes add requirements to nothing.

Beside the specs, the repo carries about 75 historical files: dated audit reports, perf triage notes, one-time reviews. Their findings are fixed or tracked in OpenSpec tasks, and git history keeps them.

This change makes OpenSpec the single home of normative requirements, and removes the historical files.

## What Changes

- Convert the normative specs into OpenSpec capabilities (listed below). The sources are `AUTHORIZATION.md`, `AUTHZ_EXPANSION.md`, `OIDC.md`, `AGENT_AUTH.md`, `SAML.md`, `SDK.md`, `SDK_SURFACE.md`, `docs/sdk-spec.md`, `ABUSE.md`, `docs/plans/HEA-1114-abuse-prevention.md`, `UI_ROUTING.md`, the benchmark targets in `TESTING.md`, and `TEST_SCENARIOS.md`. Delete each source after its conversion.
- Do not convert implementation phases, phase trackers, "critical files" lists, Rust engine API signatures, storage-key layouts or decision logs. Git history keeps them.
- Move the contributor docs `ARCHITECTURE.md`, `TESTING.md`, `PROTO.md` and `THEME.md` to `docs/dev/`. Move `CONFIGURATION.md` to `docs/guides/configuration-reference.md`, so the docs site publishes it. `docs/specs/` no longer exists.
- Delete historical files: 14 dated reports in `reports/`, 51 files in `docs/perf/`, `docs/reviews/`, `IMPLEMENTATION_ORDER.md`, `READINESS_AUDIT_1_0.md`, the `docs/sdk-spec.md` stub and the PITR design spike. Every remaining reference becomes a GitHub permalink pinned to `4d9dda1f`.
- Keep `reports/production-readiness-audit-2026-08-28.md`: `production-readiness-remediation/coverage_check.py` reads it, and that change is still open.
- Point the abuse-coverage gate (`scripts/check-abuse-coverage.sh`) at `openspec/specs/abuse-prevention/spec.md`.
- Replace `AGENTS.md` (a byte-identical copy of `CLAUDE.md`) with a symlink to `CLAUDE.md`.
- No behaviour of the server changes. This change only records the behaviour that the specs already describe.

## Capabilities

### New Capabilities
- `rbac-model`: roles, groups, permissions, the resolution algorithm, and the tenancy invariants of authorization.
- `rbac-token-claims`: the authorization claims in issued tokens, permission-delivery modes, session-version revocation and delegated (`act`) permissions.
- `rbac-admin-api`: the HTTP API for roles, groups and assignments, and the bootstrap seed data.
- `credential-hashing`: the Argon2id parameters for user passwords.
- `custom-permissions`: custom permissions, OAuth scopes, claim profiles and consent.
- `oidc-provider`: the OIDC and OAuth 2.0 profile, JAR, response modes, discovery, and accepted request encodings.
- `client-authentication`: how OAuth clients authenticate at the token endpoint and other endpoints.
- `dpop`: DPoP sender-constrained tokens (RFC 9449).
- `rp-initiated-logout`: OIDC RP-initiated logout.
- `agent-identity`: the agent entity, workload identity, and agent audit.
- `mcp-authorization`: Hearth as the authorization server for MCP.
- `delegated-authorization`: token exchange (RFC 8693), scope attenuation, and agent-to-agent trust.
- `tool-permissions`: the tool-permission grammar and its enforcement.
- `agent-approvals`: intent binding, human-in-the-loop approval and continuous access evaluation.
- `abuse-prevention`: every live abuse guard (A-N and P-N identifiers), with its limits and failure behaviour.
- `ui-routing`: realm-name reservation and admin-route rules.
- `performance-budgets`: the latency and throughput budgets that the benches and the load test enforce.

### Modified Capabilities
None. `openspec/specs/` has no archived specs yet.

Two capabilities use the same names as deltas in active changes: `saml-sp-profile` (`scope-trim-trusted-core`) and `sdk-support-contract` (`scope-trim-trusted-core`, `sdk-standard-libraries`). This change adds the baseline requirements for both, and leaves out every requirement that those deltas already state, so their archive still applies cleanly.

- `saml-sp-profile`: the SAML 2.0 SP profile: bindings, XML hardening, signature and assertion validation, time windows, encryption and errors.
- `sdk-support-contract`: the common contract every Hearth SDK satisfies: configuration, token verification, claims, OAuth flows, errors, middleware and the admin client.

## Impact

- **Docs:** `docs/specs/` is removed. `CLAUDE.md`, `CONTRIBUTING.md`, `README.md`, guides and code comments point to the new paths.
- **CI:** the abuse-coverage gate reads the new spec. The `sdk-conformance` job loses the path in its display name; `required-summary` needs the job id, which does not change.
- **Active changes:** task text in `trusted-core-confidence` and `scope-trim-trusted-core` that names a moved file follows the move. `sdk-standard-libraries` must express its rewrite as MODIFIED requirements against the new `sdk-support-contract` baseline.
- **Code:** comments only. No behaviour change, so no `CHANGELOG.md` entry.
