## 0. Before you start

- [ ] 0.1 Read the draft advisory `GHSA-hxcr-696v-vqw3` (maintainers only)
- [ ] 0.2 Grill and record in `design.md`: where the organization context comes from at `/authorize`; whether OIDC-only requests carry permissions; whether an unknown first-party scope is dropped or refused; what refresh grants after the user loses a permission; whether the refresh re-check applies to first-party clients; whether removing a mapper changes the digest; what an `allowed_clients` entry for a dynamically registered client means; who-granted-it on a consent row; whether a removed scope drops the whole consent row; the per-node orphan-audit rate; what `resource` means on `authorization_code` and `refresh_token`
- [ ] 0.3 For every task: write the scenario as a failing test first (red), then fix (green). Each fix needs a `### Security` entry in `CHANGELOG.md`

## 1. Registry hygiene

- [ ] 1.1 Enforce: An extra permission ends with its registry entry. Test: scenario "An extra permission ends with its registry entry"
- [ ] 1.2 Enforce: A skipped orphan reference is audited. Test: scenario "A skipped orphan reference is audited"
- [ ] 1.3 A missing scope row reads as absent, and reload deletes a bundle removed from YAML. Test: unit tests in `src/rbac/`

## 2. Scope resolution

- [ ] 2.1 Enforce: A bundle is granted only when fully held. Test: scenario "A bundle is granted only when fully held"
- [ ] 2.2 Enforce: A third-party client never gets an unsatisfiable bundle. Test: scenario "A third-party client never gets an unsatisfiable bundle"
- [ ] 2.3 Enforce: Gates run on granted scopes only. Test: scenario "Gates run on granted scopes only"
- [ ] 2.4 Enforce: Only resource bundles apply under a resource. Test: scenario "Only resource bundles apply under a resource"
- [ ] 2.5 Enforce: A deleted bundle never widens a refreshed token. Test: scenario "A deleted bundle never widens a refreshed token"
- [ ] 2.6 Enforce: A token request's resource is applied. Test: scenario "A token request's resource is applied"

## 3. Gates and config

- [ ] 3.1 Enforce: Managed client slugs are required and unique. Test: scenario "Managed client slugs are required and unique"
- [ ] 3.2 Enforce: Slug gates match managed clients only. Test: scenario "Slug gates match managed clients only"
- [ ] 3.3 Enforce: Tier 1 names never come from mapper output. Test: scenario "Tier 1 names never come from mapper output"

## 4. Consent model

- [ ] 4.1 Enforce: Consent is scoped to the organization. Test: scenario "Consent is scoped to the organization"
- [ ] 4.2 Enforce: Consent is scoped to the resource. Test: scenario "Consent is scoped to the resource"
- [ ] 4.3 Enforce: Revoking an application removes every consent row. Test: scenario "Revoking an application removes every consent row"

## 5. Digest and refresh

- [ ] 5.1 Enforce: A new mapper invalidates consent. Test: scenario "A new mapper invalidates consent"
- [ ] 5.2 Enforce: A broadened bundle requires consent again. Test: scenario "A broadened bundle requires consent again"
