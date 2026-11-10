## Why

RP-initiated logout does not sign the user out of Hearth, and it often leaves the browser on a raw JSON page. The first real-world integration hit all of these:

- The ID token's `sid` names the token session that the code exchange created. Logout revokes that session only. The browser session that signed in (`hearth_ui_session`) stays valid. The realm path clears the cookie in the browser that calls it, but a back-end logout through `/end_session` leaves it alone. So the next `/authorize` signs the user in again without a prompt.
- `post_logout_redirect_uri` is used only when the request carries `client_id`. Most relying-party libraries send `id_token_hint` and `post_logout_redirect_uri` only, as RP-Initiated Logout 1.0 §3 allows. Hearth drops the redirect, and the browser shows `{"message":"logged out"}`.
- The rule that the hint's `aud` "SHALL NOT stand in" for `client_id` came from a time when Hearth did not verify the hint's signature. Hearth verifies it now, against the realm's keys.
- The front-channel page's meta refresh drops `state`.

## What Changes

- **Client from the hint.** Without `client_id`, the client is the verified hint's `azp`, or else its `aud` when that has exactly one value. `post_logout_redirect_uri` must still be one of that client's registered URIs. A hint with more than one `aud` and no `azp` names no client, so the redirect is dropped.
- **Logout ends the browser session.** The authorization code records the session that authorized it: the browser session, or the bearer token's session on the non-interactive surfaces. The code exchange links the token session to it. Logout revokes the token session and then the session that authorized it.
- **A browser gets a page, not JSON.** When no redirect survives and the request accepts `text/html`, the response is a "You are signed out" page. Other callers still get `{"message":"logged out"}`.
- **The front-channel page keeps `state`.** Its meta refresh carries `?state=…`, as the plain redirect does.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `rp-initiated-logout`: `client_id` may come from the hint; logout revokes the session that authorized the token session; a browser gets an HTML page instead of JSON; the front-channel redirect carries `state`.

## Impact

- `src/identity/engine/oauth.rs`: `authorize_inner`, `exchange_authorization_code`, `initiate_logout_inner`.
- `src/identity/mod.rs`: `authorize_from_session` takes the browser session's ID.
- `src/identity/oidc.rs`: `StoredAuthorizationCode` gets `authorizing_session_id` (`#[serde(default)]`, so stored codes still decode).
- `src/identity/keys.rs` and `src/identity/cleanup.rs`: a link row from the token session to its authorizing session, and its sweep.
- `src/protocol/web/`: the UI authorize and consent paths pass the session ID.
- `src/protocol/http/session.rs`, `templates/ui/signed_out.html`: the HTML page and `state` on the front-channel page.
- A relying party that relied on the JSON body for a browser request gets HTML. Hearth has no deployments yet.
