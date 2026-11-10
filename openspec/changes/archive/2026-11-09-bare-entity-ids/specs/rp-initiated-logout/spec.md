## MODIFIED Requirements

### Requirement: Logout fans out to the session's relying parties
On a successful logout, Hearth SHALL notify every client that holds a grant family in the ended session. Each such client with a `backchannel_logout_uri` SHALL receive a back-channel logout token. When any such client has a `frontchannel_logout_uri`, the response SHALL be an HTML page with one hidden iframe per front-channel logout URI. When a validated `post_logout_redirect_uri` is present, that page SHALL carry a 2-second meta refresh to it, with `?state=…` when the request carries `state`. A logout token's `iss`, `sub` and `sid` SHALL be the exact strings the session's ID tokens carry (the realm issuer, the user's bare UUID and the session's bare UUID), because the relying party matches them against the ID token it holds (Back-Channel Logout §2.4, §2.6). Its `aud` SHALL be the issued `client_id`. The front-channel iframe URL SHALL carry the same `iss` and `sid` (Front-Channel Logout §2). A failed back-channel delivery SHALL NOT fail the user's logout.

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
