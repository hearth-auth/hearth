## ADDED Requirements

### Requirement: Logout ends the browser session that signed the user in
A token session that an authorization-code exchange opens SHALL be linked to the session that authorized the code: the browser session on the UI path, or the bearer token's session on the non-interactive surfaces. RP-initiated logout SHALL revoke the session that the hint names, and then the session linked to it, on both endpoints. A session that is already gone SHALL NOT fail the logout. A link SHALL be deleted when its token session is gone. Other token sessions that the same browser session authorized SHALL stay valid.

#### Scenario: A back-end logout ends the browser session
- **WHEN** a user signs in through the UI, a client exchanges the code, and the client's back end calls `POST /end_session` with `X-Realm-ID` and the ID token as `id_token_hint`
- **THEN** the user's browser session is revoked
- **AND** the next `/authorize` from that browser shows the sign-in page

#### Scenario: Another browser stays signed in
- **WHEN** the same user is also signed in from a second browser, and logs out from the first one
- **THEN** the second browser's session stays valid

#### Scenario: A code minted before the link existed
- **WHEN** a token session has no link, and its ID token is used as `id_token_hint`
- **THEN** the token session is revoked, and the logout succeeds

## MODIFIED Requirements

### Requirement: Logout request parameters
Every logout parameter SHALL be optional:

| Parameter | Rule |
|-----------|------|
| `id_token_hint` | A previously issued ID token: `EdDSA`, or `RS256` for a client that registered it, verified against the realm's active and in-grace keys. It SHALL be accepted when expired. It identifies the session to revoke. |
| `post_logout_redirect_uri` | The URI to send the browser to after logout. It SHALL be used only when the request names a client and the URI is one of that client's registered `post_logout_redirect_uris`. Otherwise it SHALL be dropped silently: the logout still succeeds, with no redirect. |
| `client_id` | The client identifier. When it is absent, the client SHALL be the verified hint's `azp`, or else the hint's `aud` when that holds exactly one value (RP-Initiated Logout 1.0 §3). A hint with more than one `aud` and no `azp` names no client. |
| `state` | An opaque value echoed to `post_logout_redirect_uri` as `?state=…`. |

When no front-channel page is served and no `post_logout_redirect_uri` survives validation, the endpoint SHALL answer `200`. When the request's `Accept` header includes `text/html`, the body SHALL be an HTML page that tells the user they are signed out. Otherwise the body SHALL be `{"message":"logged out"}`.

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
- **WHEN** a client calls `/end_session` with no `Accept` header, a valid `id_token_hint`, `client_id` and a `post_logout_redirect_uri` that the client did not register
- **THEN** the session is revoked
- **AND** the response is `200` with `{"message":"logged out"}`, with no redirect

#### Scenario: The hint names the client
- **WHEN** a client calls `/end_session` with a valid `id_token_hint` whose `aud` is that client, and a `post_logout_redirect_uri` that the client registered, but no `client_id`
- **THEN** the session is revoked
- **AND** the browser is redirected to that URI

#### Scenario: The hint names a client that did not register the URI
- **WHEN** a client calls `/end_session` with a valid `id_token_hint` and a `post_logout_redirect_uri` that the hint's client did not register, and no `client_id`
- **THEN** the session is revoked
- **AND** the browser is not redirected to that URI

#### Scenario: A browser with no redirect
- **WHEN** a browser calls `/realms/{realm}/end_session` with `Accept: text/html` and a valid `id_token_hint`, and no redirect survives validation
- **THEN** the response is `200` with an HTML page that tells the user they are signed out

### Requirement: Logout fans out to the session's relying parties
On a successful logout, Hearth SHALL notify every client that holds a grant family in the ended session. Each such client with a `backchannel_logout_uri` SHALL receive a back-channel logout token. When any such client has a `frontchannel_logout_uri`, the response SHALL be an HTML page with one hidden iframe per front-channel logout URI. When a validated `post_logout_redirect_uri` is present, that page SHALL carry a 2-second meta refresh to it, with `?state=…` when the request carries `state`. A logout token's `iss`, `sub` and `sid` SHALL be the exact strings the session's ID tokens carry (the realm issuer, `user_<uuid>` and `session_<uuid>`), because the relying party matches them against the ID token it holds (Back-Channel Logout §2.4, §2.6). Its `aud` SHALL be the issued `client_id`. The front-channel iframe URL SHALL carry the same `iss` and `sid` (Front-Channel Logout §2). A failed back-channel delivery SHALL NOT fail the user's logout.

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
- **WHEN** the same user logs out with `client_id`, a registered `post_logout_redirect_uri` and `state=xyz`
- **THEN** the response is the iframe page
- **AND** the page carries a 2-second meta refresh to `post_logout_redirect_uri` with `?state=xyz`
