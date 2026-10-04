## ADDED Requirements

### Requirement: JWKS re-fetch after a resource-server 401
When a protected resource answers HTTP `401` to a token that the SDK verified, the SDK SHALL re-fetch the JWKS once, then retry the verification.

#### Scenario: Key rotated between verification and use
- **WHEN** a resource server answers `401` to a call made with a token the SDK verified against its cached JWKS
- **THEN** the SDK re-fetches the JWKS once, and verifies the token again against the new key set

### Requirement: Tenant and session claim accessors
Every SDK SHALL expose a typed accessor for the `tid` claim (string; the realm or tenant ID, matching the realm's `RealmId`) and for the `sid` claim (string; the session ID, present on access tokens tied to an interactive session). Neither accessor SHALL error when its claim is absent.

#### Scenario: Session ID of an interactive token
- **WHEN** an application reads the session ID from claims of a token issued at interactive login
- **THEN** the typed accessor returns the `sid` value

#### Scenario: Machine token without a session
- **WHEN** an application reads the session ID from claims of a client-credentials token
- **THEN** the typed accessor returns an empty value, and throws nothing

#### Scenario: Realm ID
- **WHEN** an application reads the tenant ID from claims of any Hearth access token
- **THEN** the typed accessor returns the issuing realm's ID from `tid`

### Requirement: Claim hooks re-render on token change
Reactive claim-check bindings SHALL re-render when the underlying token changes: when the caller swaps `getToken`, or calls `hearth.refresh()`. The facade SHALL expose that `refresh()` method. Each SDK with reactive bindings SHALL test the re-render with the framework's test harness.

#### Scenario: Re-render on token change
- **WHEN** the application refreshes its token, and the new token loses `docs.edit`
- **THEN** components that use `useHasPermission("docs.edit")` re-render with `false`

### Requirement: Admin client from the claim-check facade
The TypeScript claim-check facade SHALL expose `hearth.admin(adminAccessToken)`, which returns an `AdminClient` for the facade's `baseUrl` and `realmId`, for example `const admin = hearth.admin(adminAccessToken); await admin.createRole({ name: "docs.editor", permissions: [...] });`.

#### Scenario: Admin client from the facade
- **WHEN** an application calls `hearth.admin(adminAccessToken)` on a facade built with `createHearth({ baseUrl, realmId, getToken })`
- **THEN** it gets an `AdminClient` that sends `adminAccessToken` and `X-Realm-ID: {realmId}` on every call

### Requirement: Required-action error from REST answers
When a call gets HTTP `400` with the body `{"error": "required_actions_pending", "error_code": "HEARTH_REQUIRED_ACTIONS_PENDING", "actions": [...]}`, the SDK SHALL raise `RequiredActionError`, with its pending actions filled from `actions`. Hearth sends this answer to password login and to the `/token` magic-link grant for a user with pending required actions.

#### Scenario: Pending actions on a token grant
- **WHEN** a magic-link exchange answers `400` with `"error": "required_actions_pending"` and `"actions": ["VERIFY_EMAIL"]`
- **THEN** the SDK raises `RequiredActionError` whose pending actions are `["VERIFY_EMAIL"]`, with no redirect URL

### Requirement: SDK releases declare the minimum server version
Each SDK release SHALL declare its minimum compatible Hearth server version in its README and in its package metadata.

#### Scenario: Minimum server version
- **WHEN** a developer reads an SDK's README or its package metadata
- **THEN** they find the minimum Hearth server version that the release supports

### Requirement: SDK line-coverage gate
Every SDK SHALL reach at least 80% line coverage, and its CI job SHALL fail a pull request whose coverage falls below that.

#### Scenario: Coverage drops
- **WHEN** a pull request drops an SDK's line coverage below 80%
- **THEN** that SDK's CI job fails

### Requirement: Live role round-trip test
Every SDK SHALL ship at least one live-server integration test that, in a realm configured in `hearth.yaml`, creates a user, assigns a role, issues a token, checks that `hasPermission` returns `true`, unassigns the role, refreshes, and checks that `hasPermission` returns `false`. Realms are not created through the admin API.

#### Scenario: Live role round trip
- **WHEN** the live integration test assigns a role, issues a token, unassigns the role and refreshes
- **THEN** `hasPermission` returns `true` before the unassignment and `false` after the refresh

### Requirement: SDK dependencies are audited automatically
An automated dependency audit (for example Dependabot) SHALL watch every SDK's dependencies: npm for `sdks/typescript`, Go modules for `sdks/go`, pip or uv for `sdks/python`, and Composer for `sdks/php`.

#### Scenario: Vulnerable PHP dependency
- **WHEN** a dependency in `sdks/php/composer.lock` gets a security advisory
- **THEN** the audit opens an update for `sdks/php`

### Requirement: Go SDK refreshes expired access tokens
The Go SDK SHALL refresh an expired access token transparently: when a call needs the access token and it has expired, the SDK SHALL redeem the refresh token first, and use the new access token.

#### Scenario: Expired access token
- **WHEN** a Go application makes a call after its access token expired, and it holds a valid refresh token
- **THEN** the SDK refreshes the token, and the call succeeds with the new access token

### Requirement: Conformance gate checks every error name and accessor
`scripts/check-sdk-conformance.sh` SHALL check that every SDK defines all 10 error types, including `RequiredActionError`, and all 17 claims accessors, including `inGroup`, `inOrg`, `tokenType`, `organizationId`, `orgGroups` and `get`.

#### Scenario: Missing accessor
- **WHEN** an SDK lacks the `orgGroups` accessor
- **THEN** `scripts/check-sdk-conformance.sh` fails for that SDK
