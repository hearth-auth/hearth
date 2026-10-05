## 0. Before you start

- [x] 0.1 Read the draft repository security advisory `GHSA-hxcr-696v-vqw3` (maintainers only): it records where each rule fails today. Keep it in draft until the fixes ship
- [x] 0.2 For every task: write the scenario as a failing test first (red), then fix (green). Each fix needs a `### Security` entry in `CHANGELOG.md`
- [x] 0.3 Move the gaps that need a design to their own changes. **Done 2026-10-04:** abuse-prevention A-3, A-16 → `login-abuse-challenge`; A-38 and delegated-authorization revocation and AAT chain validation → `delegation-chain-integrity`; all of `custom-permissions` and `mcp-authorization` → `scope-consent-integrity`; all of `sdk-support-contract` → `sdk-security-defaults`

## 1. `abuse-prevention`

- [x] 1.3 Enforce: A client update refuses unknown fields. Test: scenarios "A client update refuses unknown fields" and "A protocol endpoint ignores an unknown parameter"
- [x] 1.4 Enforce: An unset host allowlist accepts only the issuer host. Test: scenarios "An unset host allowlist accepts only the issuer host" and "Probes skip the host check"
- [x] 1.5 Enforce: Federation login rotates the session. Test: scenario "Federation login rotates the session"
- [x] 1.6 Enforce: PRF is required when `require_prf` is set. Test: scenario "PRF is required when `require_prf` is set"
- [x] 1.7 Enforce: Render paths sanitize SVG and CSS. Test: scenario "Render paths sanitize SVG and CSS"
- [x] 1.8 Enforce: Reserved and in-use emails answer the same body. Test: scenario "Reserved and in-use emails answer the same body"
- [x] 1.9 Enforce: SIGHUP reloads the CRLs. Test: scenario "SIGHUP reloads the CRLs"
- [x] 1.10 Enforce: The configured backoff schedule is used. Test: scenario "The configured backoff schedule is used"
- [x] 1.12 Enforce: The session timeout keys load. Test: scenario "The session timeout keys load"

## 2. `agent-identity`

- [x] 2.1 Enforce: A revoked agent's key does not verify. Test: scenario "A revoked agent's key does not verify"

## 4. `delegated-authorization`

- [x] 4.1 Enforce: A child AAT keeps every parent constraint. Test: scenario "A child AAT keeps every parent constraint"
- [x] 4.2 Enforce: Only the JWT actor token type is accepted. Test: scenario "Only the JWT actor token type is accepted"

## 5. `rbac-admin-api`

- [x] 5.1 Enforce: A YAML-managed role or group cannot be changed at runtime. Test: scenarios "A YAML-managed role cannot be deleted at runtime" and "A YAML-managed group cannot be changed at runtime"
- [x] 5.2 Enforce: A caller-chosen organization is refused. Test: scenario "A caller-chosen organization is refused"
- [x] 5.3 Enforce: An unknown body field is refused. Test: scenario "An unknown body field is refused"

## 6. `rbac-token-claims`

- [x] 6.1 Enforce: An exchange without an actor token is attenuated. Test: scenario "An exchange without an actor token is attenuated"

## 8. `saml-sp-profile`

- [x] 8.1 Enforce: Encrypted content is rejected. Test: scenario "Encrypted content is rejected"
- [x] 8.2 Enforce: The assertion's own issuer must match. Test: scenario "The assertion's own issuer must match"

## 10. `rbac-model`

- [x] 10.1 Enforce: Reserved permissions are not granted directly. Test: scenario "Reserved permissions are not granted directly"
