## Why

`adopt-openspec-specs` checked every converted requirement against the code. For the security-relevant requirements listed here, the code needs work before it satisfies the baseline. Each one is tracked as a scenario that the code must pass, so none of them is missed.

The detail of each gap (where the code falls short, and how) is kept in the draft repository security advisory `GHSA-hxcr-696v-vqw3`, visible to maintainers only, not in this public repo. Read it before starting a task.

This change holds the gaps that a local fix closes. Gaps that need a design moved to four follow-up changes: `scope-consent-integrity`, `delegation-chain-integrity`, `login-abuse-challenge` and `sdk-security-defaults`.

## What Changes

- Each delta is a MODIFIED copy of a baseline requirement with one or more added scenarios.
- Three requirement texts also change:
  - "A-40 Host allowlist and cross-origin isolation": an unset `security.allowed_hosts` defaults to the `oidc.issuer` host, and only the liveness and readiness probes skip the check. A listener binds an IP, so "bind hostnames" had no meaning.
  - "A-47 Unknown fields refused on request bodies": the OAuth 2.0 / OIDC protocol endpoints are the recorded exceptions (RFC 6749 §3.1).
  - "Declarative RBAC configuration" is unchanged in text, but gains a scenario for YAML-managed groups.
- `tasks.md` has one task per scenario: write the test first (red), then the fix (green).
- Every fix ships with a `### Security` entry in `CHANGELOG.md`.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `abuse-prevention`, `agent-identity`, `delegated-authorization`, `rbac-admin-api`, `rbac-model`, `rbac-token-claims`, `saml-sp-profile`: each gains scenarios. A-40 and A-47 also change their text, as listed above.

## Impact

- **Code:** server (`src/`) only.
- **Order:** applies after `adopt-openspec-specs` (archived). No requirement here is also modified by `fix-spec-drift-defects` or by the four follow-up changes, so they can archive in any order.
- **Disclosure:** keep exploit detail out of commits, PR text and public issues until the fix ships.
