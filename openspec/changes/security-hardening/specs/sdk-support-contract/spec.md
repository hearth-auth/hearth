## MODIFIED Requirements

### Requirement: JWT validation steps
`verifyToken()` SHALL run these six checks on every token:

| # | Check | Error on failure |
|---|---|---|
| 1 | The signature verifies against the cached JWKS. | `TokenInvalidError` |
| 2 | `exp` is not in the past. | `TokenExpiredError` |
| 3 | `iss` equals the configured issuer (TypeScript and PHP `issuerUrl`, Go `baseURL`, Python `base_url` or the `issuer_url` argument). The issuer in the discovery document does not replace it. | `TokenIssuerError` |
| 4 | `aud` contains the configured `client_id`. Server SDKs only; configurable. | `TokenAudienceError` |
| 5 | `iat` is not in the future. | — |
| 6 | When `nbf` is present, `now` is not before `nbf`. | `TokenNotYetValidError` |

The SDK need not run the checks in this order. A token with two faults (for example expired and with the wrong issuer) MAY get either error, and different SDKs MAY answer differently. A token with one fault SHALL get the same error in every SDK.

#### Scenario: Expired token
- **WHEN** an SDK verifies an access token presented after its `exp` plus the 5 s clock skew
- **THEN** the SDK throws `TokenExpiredError`

#### Scenario: Wrong audience
- **WHEN** the SDK is configured with audience `not-hearth`, and verifies a token issued for `hearth`
- **THEN** the SDK throws `TokenAudienceError`

#### Scenario: Wrong issuer with the same keys
- **WHEN** the SDK is configured with the realm reached as `localhost`, and verifies a token whose `iss` names `127.0.0.1`
- **THEN** the SDK throws `TokenIssuerError`, although the signature verifies

#### Scenario: Token not yet valid
- **WHEN** the SDK verifies a token whose `nbf` is 60 s in the future
- **THEN** the SDK throws `TokenNotYetValidError`

#### Scenario: One fault, same error everywhere
- **WHEN** the four SDKs verify the same token, which has exactly one fault
- **THEN** all four throw the same error type

#### Scenario: TypeScript rejects a future `iat`
- **WHEN** the TypeScript SDK verifies a token whose `iat` is 60 s in the future
- **THEN** the SDK rejects the token

#### Scenario: Go and Python check the audience by default
- **WHEN** the Go or Python client is configured with a client ID, and verifies a token whose `aud` does not contain it, with no per-call audience
- **THEN** the SDK throws `TokenAudienceError`

### Requirement: Claim checks verify the token signature
An SDK MUST verify the JWT signature against the realm's JWKS when it takes in a token for claim checks, and MUST reject unsigned or tampered tokens. The SDK MUST NOT call `/v1/me/permissions` for routine `hasPermission` checks; that endpoint is the escape hatch, not the primary path.

#### Scenario: Tampered token in a claim check
- **WHEN** the token's `permissions` claim was edited after signing, and the application calls `hasPermission` for the added permission
- **THEN** the SDK does not report the permission as held

#### Scenario: Routine check stays local
- **WHEN** the application calls `hasPermission` 100 times
- **THEN** the SDK sends no request to `/v1/me/permissions`

#### Scenario: The TypeScript facade verifies the signature
- **WHEN** the `createHearth` facade's `getToken` returns a token whose `permissions` claim was edited after signing, and the application calls `hasPermission` for the added permission
- **THEN** the facade returns `false`

#### Scenario: Python permission checks verify the signature
- **WHEN** `HearthClient.has_permission(token, permission)` gets a token whose `permissions` claim was edited after signing
- **THEN** it returns `False`

### Requirement: Browser login flow
The TypeScript browser SDK SHALL implement, through `createHearthAuth(config)`:

- **PKCE authorization code flow** (RFC 7636): `startLogin()` redirects; `handleCallback()` exchanges the code for tokens.
- **Silent refresh**: renew the token through a hidden iframe before expiry. The lead time is configurable; default 60 s before `exp`.
- **Logout**: clear the local session, and redirect to RP-initiated logout.
- **Storage abstraction**: default `sessionStorage`; pluggable (`localStorage`, in-memory, custom). The storage key prefix is configurable.
- **Cross-tab state sync**: optional. The SDK SHOULD sync login and logout across tabs through a broadcast channel or storage events.

`handleCallback()` needs no required-action detection. Hearth runs pending required actions itself, at `/required-action/{ACTION}` during `/authorize`, before it issues a code. The callback always carries an ordinary `code`, and the exchange yields an ordinary access token. The server never adds a `required_action_redirect_uri` callback parameter, and never issues a `token_type === "required_action"` token from the code exchange.

#### Scenario: Login round trip
- **WHEN** a single-page app calls `startLogin()`, and the user signs in and returns to the callback
- **THEN** `handleCallback()` exchanges the code with the PKCE verifier, and the app holds an access token

#### Scenario: Custom storage
- **WHEN** the app configures an in-memory store and the key prefix `myapp_`
- **THEN** the SDK keeps its state there under keys that start with `myapp_`, and writes nothing to `sessionStorage`

#### Scenario: Logout
- **WHEN** the app calls `logout()`
- **THEN** the SDK clears the local session, and redirects to the realm's end-session endpoint

#### Scenario: The refresh token is not kept in `localStorage`
- **WHEN** a single-page app uses `createHearthAuth` with no storage option, and signs in
- **THEN** the SDK writes no token to `localStorage`; its state lives in `sessionStorage`
