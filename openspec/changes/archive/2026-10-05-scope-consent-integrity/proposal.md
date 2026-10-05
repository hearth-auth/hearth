## Why

`security-hardening` found that the scope pipeline and the consent model do not yet meet the `custom-permissions` and `mcp-authorization` baseline. The fixes share one design: one scope-resolution entry point used on every issuance path, and one consent key that carries the organization and the resource. They are too large and too coupled for the umbrella change, so they move here.

The detail of each gap is kept in the draft repository security advisory `GHSA-hxcr-696v-vqw3` (maintainers only). Read it before starting a task.

## What Changes

- Every issuance path (browser consent gate, authorize, code exchange, device grant, refresh) resolves the requested scopes through one entry point. A bundle is granted only when the user holds all of it. The token's `scope`, its `permissions` and the claim release gates all use the granted set.
- Under a `resource`, only that resource's registered bundles apply.
- A scope that the registry no longer knows never widens a token.
- `allowed_clients` gates match managed clients by identity, not by a name a registration can copy. Managed client slugs are required and unique.
- Tier 1 claim names never come from mapper output.
- Orphaned references are audited, and an extra permission ends with its registry entry.
- Consent is keyed by user, client, organization and resource. The consent digest covers what the user agreed to disclose. Refresh re-checks it.
- Revoking an application removes every consent row.
- A token request's `resource` is applied on every grant.
- Each fix ships with a `### Security` entry in `CHANGELOG.md`.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `custom-permissions`: scenarios added to eleven requirements.
- `mcp-authorization`: one scenario added to "The `resource` parameter names a registered resource".

## Impact

- **Code:** `src/identity/engine/` (oauth, refresh, consent), `src/rbac/` (resolve, engine, registry), `src/protocol/web/` (authorize gate, consent, device approval), `src/protocol/http/oauth.rs`, `src/config/validate.rs`.
- **Design:** `design.md` is written after a grilling pass. Its open questions are listed in `tasks.md` §0.
- **Order:** after `security-hardening`. No other active change modifies these requirements.
- **Disclosure:** keep exploit detail out of commits, PR text and public issues until the fix ships.
