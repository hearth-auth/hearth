## 0. Before you start

- [ ] 0.1 Read the draft repository security advisory `GHSA-hxcr-696v-vqw3` (maintainers only): it records where each rule fails today. Keep it in draft until the fixes ship
- [ ] 0.2 For every task: write the scenario as a failing test first (red), then fix (green). Each fix needs a `### Security` entry in `CHANGELOG.md`
- [ ] 0.3 SDK tasks: check each one against `sdk-standard-libraries` first; if that change replaces the code path, close the task there

## 1. `abuse-prevention`

- [ ] 1.1 Enforce: A challenged caller is told to solve a challenge. Test: scenario "A challenged caller is told to solve a challenge"
- [ ] 1.2 Enforce: A challenged login is audited and challenged. Test: scenario "A challenged login is audited and challenged"
- [ ] 1.3 Enforce: A client update refuses unknown fields. Test: scenario "A client update refuses unknown fields"
- [ ] 1.4 Enforce: An unset host allowlist accepts only the bind hostnames. Test: scenario "An unset host allowlist accepts only the bind hostnames"
- [ ] 1.5 Enforce: Federation login rotates the session. Test: scenario "Federation login rotates the session"
- [ ] 1.6 Enforce: PRF is required when `require_prf` is set. Test: scenario "PRF is required when `require_prf` is set"
- [ ] 1.7 Enforce: Render paths sanitize SVG and CSS. Test: scenario "Render paths sanitize SVG and CSS"
- [ ] 1.8 Enforce: Reserved and in-use emails answer the same body. Test: scenario "Reserved and in-use emails answer the same body"
- [ ] 1.9 Enforce: SIGHUP reloads the CRLs. Test: scenario "SIGHUP reloads the CRLs"
- [ ] 1.10 Enforce: The configured backoff schedule is used. Test: scenario "The configured backoff schedule is used"
- [ ] 1.11 Enforce: The delegation chain depth ceiling is 3. Test: scenario "The delegation chain depth ceiling is 3"
- [ ] 1.12 Enforce: The session timeout keys load. Test: scenario "The session timeout keys load"

## 2. `agent-identity`

- [ ] 2.1 Enforce: A revoked agent's key does not verify. Test: scenario "A revoked agent's key does not verify"

## 3. `mcp-authorization`

- [ ] 3.1 Enforce: A token request's resource is applied. Test: scenario "A token request's resource is applied"

## 4. `delegated-authorization`

- [ ] 4.1 Enforce: A child AAT keeps every parent constraint. Test: scenario "A child AAT keeps every parent constraint"
- [ ] 4.2 Enforce: Only the JWT actor token type is accepted. Test: scenario "Only the JWT actor token type is accepted"
- [ ] 4.3 Enforce: Revoking a delegation revokes onward exchanges. Test: scenario "Revoking a delegation revokes onward exchanges"
- [ ] 4.4 Enforce: Validation checks every chain link. Test: scenario "Validation checks every chain link"

## 5. `rbac-admin-api`

- [ ] 5.1 Enforce: A YAML-managed role cannot be deleted at runtime. Test: scenario "A YAML-managed role cannot be deleted at runtime"
- [ ] 5.2 Enforce: A caller-chosen organization is refused. Test: scenario "A caller-chosen organization is refused"
- [ ] 5.3 Enforce: An unknown body field is refused. Test: scenario "An unknown body field is refused"

## 6. `rbac-token-claims`

- [ ] 6.1 Enforce: An exchange without an actor token is attenuated. Test: scenario "An exchange without an actor token is attenuated"

## 7. `custom-permissions`

- [ ] 7.1 Enforce: A broadened bundle requires consent again. Test: scenario "A broadened bundle requires consent again"
- [ ] 7.2 Enforce: A bundle is granted only when fully held. Test: scenario "A bundle is granted only when fully held"
- [ ] 7.3 Enforce: A deleted bundle never widens a refreshed token. Test: scenario "A deleted bundle never widens a refreshed token"
- [ ] 7.4 Enforce: A new mapper invalidates consent. Test: scenario "A new mapper invalidates consent"
- [ ] 7.5 Enforce: A skipped orphan reference is audited. Test: scenario "A skipped orphan reference is audited"
- [ ] 7.6 Enforce: A third-party client never gets an unsatisfiable bundle. Test: scenario "A third-party client never gets an unsatisfiable bundle"
- [ ] 7.7 Enforce: An extra permission ends with its registry entry. Test: scenario "An extra permission ends with its registry entry"
- [ ] 7.8 Enforce: Consent is scoped to the organization. Test: scenario "Consent is scoped to the organization"
- [ ] 7.9 Enforce: Consent is scoped to the resource. Test: scenario "Consent is scoped to the resource"
- [ ] 7.10 Enforce: Gates run on granted scopes only. Test: scenario "Gates run on granted scopes only"
- [ ] 7.11 Enforce: Managed client slugs are required and unique. Test: scenario "Managed client slugs are required and unique"
- [ ] 7.12 Enforce: Only resource bundles apply under a resource. Test: scenario "Only resource bundles apply under a resource"
- [ ] 7.13 Enforce: Revoking an application removes every consent row. Test: scenario "Revoking an application removes every consent row"
- [ ] 7.14 Enforce: Slug gates match managed clients only. Test: scenario "Slug gates match managed clients only"
- [ ] 7.15 Enforce: Tier 1 names never come from mapper output. Test: scenario "Tier 1 names never come from mapper output"

## 8. `saml-sp-profile`

- [ ] 8.1 Enforce: Encrypted content is rejected. Test: scenario "Encrypted content is rejected"
- [ ] 8.2 Enforce: The assertion's own issuer must match. Test: scenario "The assertion's own issuer must match"

## 9. `sdk-support-contract`

- [ ] 9.1 Enforce: Go and Python check the audience by default. Test: scenario "Go and Python check the audience by default"
- [ ] 9.2 Enforce: Python permission checks verify the signature. Test: scenario "Python permission checks verify the signature"
- [ ] 9.3 Enforce: The TypeScript facade verifies the signature. Test: scenario "The TypeScript facade verifies the signature"
- [ ] 9.4 Enforce: The refresh token is not kept in `localStorage`. Test: scenario "The refresh token is not kept in `localStorage`"
- [ ] 9.5 Enforce: TypeScript rejects a future `iat`. Test: scenario "TypeScript rejects a future `iat`"

## 10. `rbac-model`

- [ ] 10.1 Enforce: Reserved permissions are not granted directly. Test: scenario "Reserved permissions are not granted directly"
