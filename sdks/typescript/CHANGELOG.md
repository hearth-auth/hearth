# Changelog

All notable changes to `@hearth-auth/browser` and `@hearth-auth/node` are documented here.

## [Unreleased]

### Security
- **Access-token audience is always checked** — `HearthClient.verifyToken` and
  `JwksClient.verify` require `aud` to contain the expected audience (RFC 9068 §4):
  the new `audience` option, default `"hearth"` (exported as `DEFAULT_AUDIENCE`), the
  audience Hearth mints when a client names no resource. An API registered as a
  protected resource sets its resource URI. The client ID is not used as the audience.
  `VerifyOptions.audience` overrides it per call; an empty audience throws
  `ConfigurationError`.
- **A token whose `iat` lies in the future is refused** — more than the 5 s clock skew
  ahead throws `TokenInvalidError`.
- **`createHearth` predicates verify the token** — `hasPermission`, `hasRole`, `inGroup`
  and `inOrg` check the EdDSA signature against the realm JWKS plus `exp`, `nbf`, `iat`,
  `iss` and `aud` before reading a claim, and resolve `false` for a token that does not
  verify.
- **`createHearthAuth` keeps tokens in `sessionStorage` by default** — the refresh token,
  ID token and PKCE verifier/state go to `sessionStorage`; the access token stays in
  memory. New `AuthConfig.storage` (`"sessionStorage"` | `"localStorage"` | `"memory"` |
  a custom `TokenStorage`) and `AuthConfig.storageKeyPrefix` (default `"hearth_"`). At
  creation the facade removes `hearth_refresh_token` and `hearth_id_token` from
  `localStorage` unless `localStorage` is the configured store.

### Changed
- **BREAKING: `createHearth` predicates are asynchronous** — `hasPermission`, `hasRole`,
  `inGroup` and `inOrg` return `Promise<boolean>`. `getToken` may return a string or a
  Promise. With `sessionVersions` enabled they may reject with
  `SessionVersionRevokedError` or `SessionVersionCacheStaleError`. The React hooks still
  return `boolean`: `false` until the check resolves.
- **BREAKING: `createHearth` requires `issuerUrl`** — the realm issuer (for example
  `https://hearth.example.com/realms/acme`) whose JWKS verifies the token. Optional
  `audience` sets the expected `aud`.
- **BREAKING: browser token getters moved onto the auth object** — the module-level
  `getAccessToken`, `getRefreshToken`, `getIdToken`, `isAuthenticated` and `clearTokens`
  exports are removed; call them on the object `createHearthAuth` returns
  (`auth.getAccessToken()`, ...).
- **`startWebAuthnRegistration` now requires a step-up proof (audit 2026-08-28 §4.18#2)** —
  the server refuses passkey enrolment carried by an access token alone with
  `403 step_up_required`, because a stolen token would otherwise mint a permanent
  credential. The method takes a second `stepUp: StepUpProof` argument: `{ password }`,
  `{ totp_code }`, or `{ assertion }`.

### Removed
- **`admin.createRealm()` and the `CreateRealmParams` type** — realms are
  provisioned via `hearth.yaml` and reconciled at startup, not through the admin
  API. The server returns `405 Method Not Allowed` for `POST /admin/realms`, so
  this method never worked against a real server. Manage realms in `hearth.yaml`
  and restart Hearth to apply changes; read them with `getRealm`/`listRealms`
  (HEA-2171).

### Changed
- SDK brought into conformance with the [Hearth SDK Common Specification](../../openspec/specs/sdk-support-contract/spec.md).
- All 9 required error types from spec §5 are now exported.
- Full Claims API (spec §4) implemented on verified token objects.
- JWKS caching follows the 5-rule contract from spec §2.
- README updated with installation, quickstart, and troubleshooting sections (spec §10).
