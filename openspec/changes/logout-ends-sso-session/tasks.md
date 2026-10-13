## 1. The hint names the client

- [x] 1.1 Write the failing tests in `tests/logout_ends_sso_session.rs`: a hint without `client_id` and a registered `post_logout_redirect_uri` redirects with `state`; a URI that the hint's client did not register gets no redirect.
- [x] 1.2 In `initiate_logout_inner`, take the client from `client_id`, else from the hint's `azp`, else from its `aud` when that holds one value. Validate the URI against that client.
- [x] 1.3 Unit test in `src/identity/engine/oauth.rs`: a hint with two `aud` values and no `azp` names no client.

## 2. Logout ends the session that signed the user in

- [x] 2.1 Write the failing tests: after a UI sign-in, a code exchange and a back-end `POST /end_session`, the UI session is revoked and the next `/authorize` shows the sign-in page; a second browser session of the same user stays valid.
- [x] 2.2 Add `authorizing_session_id` (`#[serde(default)]`) to `StoredAuthorizationCode`. Test that a code stored without it still decodes.
- [x] 2.3 Add `session_id` to `AuthorizeParams`. Set it at each entry point that sets `mfa_proof` from a UI session. Pass it to `authorize_from_session`.
- [x] 2.4 In `authorize_inner`, record the bearer token's session or the browser session in the code.
- [x] 2.5 Add the link key (`encode_session_parent`) in `src/identity/keys.rs`. The exchange writes the link to the root session.
- [x] 2.6 In `initiate_logout_inner`, revoke the linked session after the hint's session, and delete the link. Ignore `SessionNotFound`.
- [x] 2.7 Add `sweep_session_parent_links` to `src/identity/cleanup.rs`, after `sweep_sessions`. Unit test: a link whose token session is gone is deleted, and a live one is kept.

## 3. A browser gets a page

- [x] 3.1 Write the failing tests: `Accept: text/html` with no surviving redirect gets `200` HTML; no `Accept` gets `{"message":"logged out"}`; the front-channel page's meta refresh carries `state`.
- [x] 3.2 Add `templates/ui/signed_out.html` (THEME.md) and its render function in `src/protocol/web/`.
- [x] 3.3 In `end_session`, serve the page for `text/html`. Log the reason for a dropped redirect at `debug`.
- [x] 3.4 Append `state` to the front-channel meta refresh.

## 4. Close out

- [x] 4.1 `CHANGELOG.md` entries under `Changed` and `Fixed`.
- [x] 4.2 `make check`, `make test-detached`, `make ci-local-fast`.
- [x] 4.3 `make ui-test-smoke` and `make ui-test-accessibility` against a dev server.
- [x] 4.4 Manual check in Chromium: sign in to a client, log out without `client_id`, land on the registered URI, and see the sign-in page on the next `/authorize`.
