## 0. Before you start

- [x] 0.1 Read the draft advisory `GHSA-hxcr-696v-vqw3` (maintainers only)
- [x] 0.2 Grill and record in `design.md`: the organization context at `/authorize`; OIDC-only requests; unknown scopes; refresh after a lost permission; first-party refresh; mapper removal; `allowed_clients` for dynamically registered clients; who granted a consent; a removed scope; the orphan-audit rate; `resource` on `authorization_code` and `refresh_token`
- [ ] 0.3 For every task: write the scenario as a failing test first (red), then fix (green). Each fix needs a `### Security` entry in `CHANGELOG.md`

## 1. Registry hygiene (PR 1)

- [x] 1.1 Enforce: An extra permission ends with its registry entry. Test: scenario "An extra permission ends with its registry entry"
- [x] 1.2 Enforce: A skipped orphan reference is audited. Test: scenario "A skipped orphan reference is audited"
- [x] 1.3 A missing scope row reads as absent, reload deletes a bundle removed from YAML, and config load refuses a bundle with no permissions. Test: unit tests in `src/rbac/`

## 2. Gates and config (PR 1)

- [x] 2.1 Enforce: Managed client slugs are unique, and default to the YAML key. Test: scenarios "Managed client slugs are unique" and "A client without a slug"
- [x] 2.2 Enforce: Slug gates match managed clients only. Test: scenarios "A DCR slug in a gate" and "Slug gates match managed clients only"
- [x] 2.3 Enforce: Tier 1 names never come from mapper output. Test: scenario "Tier 1 names never come from mapper output"

## 3. Scope resolution (PR 2)

- [ ] 3.1 One engine entry point (`design.md` §2), called by the browser gate, `/authorize`, PAR, the code exchange, the device grant, `client_credentials`, refresh and introspection. The code stores the granted scopes
- [ ] 3.2 Enforce: A bundle is granted only when fully held. Test: scenario "A bundle is granted only when fully held"
- [ ] 3.3 Enforce: A third-party client never gets an unsatisfiable bundle. Test: scenario "A third-party client never gets an unsatisfiable bundle"
- [ ] 3.4 Enforce: Gates run on granted scopes only. Test: scenario "Gates run on granted scopes only"
- [ ] 3.5 Enforce: Only resource bundles apply under a resource, and an unknown scope is refused. Test: scenarios "Only resource bundles apply under a resource" and "An unknown scope from a first-party client"
- [ ] 3.6 Enforce: OIDC-only and fully dropped requests. Test: scenarios "Only OIDC scopes for a third-party client" and "Every requested bundle is dropped"
- [ ] 3.7 Enforce: A deleted bundle never widens a refreshed token. Test: scenario "A deleted bundle never widens a refreshed token"
- [ ] 3.8 Enforce: A token request's resource is applied. Test: scenarios "A token request's resource is applied", "A code exchange names another resource" and "A refresh names another resource"

## 4. Organization context and consent (PR 3)

- [ ] 4.1 Enforce: the `organization` parameter. Test: scenarios "A member signs in to an organization", "A non-member names an organization" and "Membership ends before a refresh"
- [ ] 4.2 One `ConsentKey` and one lookup; delete the legacy key code. Enforce: Consent is scoped to the organization. Test: scenario "Consent is scoped to the organization"
- [ ] 4.3 Enforce: Consent is scoped to the resource. Test: scenario "Consent is scoped to the resource"
- [ ] 4.4 Enforce: Revoking an application removes every consent row. Test: scenario "Revoking an application removes every consent row"
- [ ] 4.5 The disclosure set replaces the scope digest. Enforce: A new mapper invalidates consent, and a removed mapper does not. Test: scenarios "A new mapper invalidates consent" and "A removed mapper does not ask again"
- [ ] 4.6 Enforce: A broadened bundle requires consent again. Test: scenario "A broadened bundle requires consent again"
