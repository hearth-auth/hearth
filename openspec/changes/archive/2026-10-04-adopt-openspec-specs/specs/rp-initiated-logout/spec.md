## ADDED Requirements

### Requirement: RP-initiated logout endpoints
Hearth SHALL implement OpenID Connect RP-Initiated Logout 1.0 on two endpoints:

| Endpoint | Method | Realm resolution |
|----------|--------|------------------|
| `/end_session` | `GET`, `POST` | `X-Realm-ID` header (machine clients) |
| `/realms/{realm}/end_session` | `GET`, `POST` | URL path (browser and SPA clients) |

The realm-path endpoint SHALL also clear the Hearth UI session cookies in its response, so a browser redirect after logout forces re-authentication on the next `/authorize` visit.

#### Scenario: A browser logs out through the realm path
- **WHEN** a browser calls `GET /realms/{realm}/end_session` with a valid `id_token_hint`
- **THEN** the session is revoked
- **AND** the response clears the Hearth UI session cookies

#### Scenario: A machine client logs out
- **WHEN** a client calls `POST /end_session` with `X-Realm-ID` and a valid `id_token_hint`
- **THEN** the session is revoked

### Requirement: Logout request parameters
Every logout parameter SHALL be optional:

| Parameter | Rule |
|-----------|------|
| `id_token_hint` | A previously issued ID token: `EdDSA`, or `RS256` for a client that registered it, verified against the realm's active and in-grace keys. It SHALL be accepted when expired. It identifies the session to revoke. |
| `post_logout_redirect_uri` | The URI to send the browser to after logout. It SHALL be used only when `client_id` is present and the URI is one of that client's registered `post_logout_redirect_uris`. Otherwise it SHALL be dropped silently: the logout still succeeds, with no redirect. |
| `client_id` | The client identifier, used to validate `post_logout_redirect_uri` against the client's registered list. The hint's `aud` SHALL NOT stand in for it. |
| `state` | An opaque value echoed to `post_logout_redirect_uri` as `?state=…`. |

When no front-channel page is served and no `post_logout_redirect_uri` survives validation, the endpoint SHALL answer `200` with `{"message":"logged out"}`.

#### Scenario: An expired hint
- **WHEN** a client calls `/end_session` with an expired but validly signed `id_token_hint`
- **THEN** the session the hint names is revoked

#### Scenario: A hint signed with a retiring key
- **WHEN** a client presents an `id_token_hint` signed with a key that is inside its rotation grace window
- **THEN** the hint is accepted

#### Scenario: A registered redirect with state
- **WHEN** a client calls `/end_session` with `client_id`, a registered `post_logout_redirect_uri` and `state=xyz`
- **THEN** the browser is redirected to that URI with `?state=xyz`

#### Scenario: An unregistered redirect
- **WHEN** a client calls `/end_session` with a valid `id_token_hint`, `client_id` and a `post_logout_redirect_uri` that the client did not register
- **THEN** the session is revoked
- **AND** the response is `200` with `{"message":"logged out"}`, with no redirect

#### Scenario: A redirect without client_id
- **WHEN** a client calls `/end_session` with a valid `id_token_hint` and a `post_logout_redirect_uri` but no `client_id`
- **THEN** the session is revoked
- **AND** the browser is not redirected to that URI

### Requirement: Logout requires a hint and is idempotent
A logout request without an `id_token_hint` SHALL be refused with `400 invalid_request`. When the session the hint names is already gone, the endpoint SHALL still complete the logout without an error, so logout is idempotent.

#### Scenario: No hint
- **WHEN** a client calls `/end_session` with no `id_token_hint`
- **THEN** the response is `400 invalid_request`

#### Scenario: The session was already ended
- **WHEN** a client calls `/end_session` with `client_id`, a registered `post_logout_redirect_uri` and an `id_token_hint` whose session was already revoked
- **THEN** the browser is redirected to `post_logout_redirect_uri` without an error

### Requirement: The hint must belong to the named client
When a request carries both `id_token_hint` and `client_id`, the endpoint SHALL refuse a hint whose `aud` does not contain that `client_id` with `400 invalid_request` (RP-Initiated Logout §2). The check SHALL run before anything is revoked.

#### Scenario: A hint issued to another client
- **WHEN** a client calls `/end_session` with its own `client_id` and an `id_token_hint` issued to a different client
- **THEN** the response is `400 invalid_request`
- **AND** no session is revoked

### Requirement: Logout fans out to the session's relying parties
On a successful logout, Hearth SHALL notify every client that holds a grant family in the ended session. Each such client with a `backchannel_logout_uri` SHALL receive a back-channel logout token. When any such client has a `frontchannel_logout_uri`, the response SHALL be an HTML page with one hidden iframe per front-channel logout URI. When a validated `post_logout_redirect_uri` is present, that page SHALL carry a 2-second meta refresh to it. A logout token's `iss`, `sub` and `sid` SHALL be the exact strings the session's ID tokens carry (the realm issuer, `user_<uuid>` and `session_<uuid>`), because the relying party matches them against the ID token it holds (Back-Channel Logout §2.4, §2.6). Its `aud` SHALL be the issued `client_id`. The front-channel iframe URL SHALL carry the same `iss` and `sid` (Front-Channel Logout §2). A failed back-channel delivery SHALL NOT fail the user's logout.

#### Scenario: A back-channel logout token
- **WHEN** a user with a session at a client that registered a `backchannel_logout_uri` logs out
- **THEN** that client receives a logout token whose `iss`, `sub` and `sid` equal those of its ID token
- **AND** whose `aud` is its `client_id`

#### Scenario: A client the session never used
- **WHEN** a user logs out and a client in the realm with a `backchannel_logout_uri` holds no grant family in that session
- **THEN** that client receives no logout token

#### Scenario: A front-channel logout page
- **WHEN** a user with a session at a client that registered a front-channel logout URI logs out without `post_logout_redirect_uri`
- **THEN** the response is a page with an iframe to that URI carrying `iss` and `sid`

#### Scenario: A front-channel page with a redirect
- **WHEN** the same user logs out with `client_id` and a registered `post_logout_redirect_uri`
- **THEN** the response is the iframe page
- **AND** the page carries a 2-second meta refresh to `post_logout_redirect_uri`

### Requirement: Logout tokens are signed with EdDSA for every client
Hearth SHALL sign logout tokens with `EdDSA` for every client, including a client that registered `id_token_signed_response_alg: RS256`. This is a known deviation from OIDC Back-Channel Logout 1.0 §2.4 and §2.6 step 3, which govern the logout token's `alg` by `id_token_signed_response_alg`. An `RS256` relying party that validates logout tokens strictly against its registered algorithm will reject Hearth's logout tokens; it must also accept `EdDSA` from the realm JWKS.

#### Scenario: An RS256 client receives a logout token
- **WHEN** a user of a client that registered `RS256` logs out and the client has a `backchannel_logout_uri`
- **THEN** the logout token the client receives has `alg: EdDSA`
- **AND** it verifies against the realm's Ed25519 key in the JWKS
