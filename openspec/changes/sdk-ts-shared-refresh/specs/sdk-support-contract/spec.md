## MODIFIED Requirements

### Requirement: Browser login flow
The TypeScript browser SDK SHALL implement, through `createHearthAuth(config)`:

- **PKCE authorization code flow** (RFC 7636): `startLogin()` redirects; `handleCallback()` exchanges the code for tokens.
- **Silent refresh**: renew the token through a hidden iframe before expiry. The lead time is configurable; default 60 s before `exp`.
- **One refresh at a time**: concurrent calls to `refreshAccessToken()` SHALL share one token request and its result. Hearth rotates the refresh token on each use, and it treats a second use of the same token as replay and revokes the whole token family. So two parallel requests with one token sign the user out.
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

#### Scenario: Two refresh calls at the same time
- **WHEN** an app calls `refreshAccessToken()` twice before the first call completes (for example, from an effect that React's `StrictMode` runs twice)
- **THEN** the SDK sends one refresh-token request, both calls complete with its result, and the rotated refresh token is stored
- **AND** a call after that request completes sends a new request
