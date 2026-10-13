## Context

A browser signs in to Hearth's UI and gets a browser session (`hearth_ui_session`). When a client sends the browser to `/authorize`, Hearth mints an authorization code from that session. The code exchange then opens a separate token session (`create_derived_session`). The ID token's `sid` names the token session, and nothing links it to the browser session.

`initiate_logout_inner` verifies the hint, revokes the session its `sid` names, and fans out to that session's relying parties. The browser session survives. The realm path (`/realms/{realm}/end_session`) clears the UI cookies in the browser that calls it, so that one browser is signed out. A back-end call to `/end_session` with `X-Realm-ID` clears nothing, and the next `/authorize` in the user's browser completes without a prompt.

The post-logout redirect is validated only against a `client_id` parameter. The rule "the hint's `aud` SHALL NOT stand in" has this history:

1. 2026-05-13: without `client_id`, any `post_logout_redirect_uri` was accepted. That was an open redirect.
2. 2026-07-02: the redirect was dropped without `client_id`. Hearth did not verify the hint's signature then, so its `aud` could not be trusted.
3. 2026-09-06: Hearth started to verify the hint's signature against the realm's keys (audit finding).
4. 2026-10-04: the move to OpenSpec wrote the code's behavior down as the rule. It records no reason.

## Goals / Non-Goals

**Goals:**
- After RP-initiated logout, the browser session that signed the user in is revoked, whichever endpoint the client calls.
- A client that sends `id_token_hint` and a registered `post_logout_redirect_uri` without `client_id` gets its redirect.
- A browser never ends on raw JSON.

**Non-Goals:**
- Single logout across clients. Other token sessions that the same browser session authorized stay valid, and their clients are not notified. That needs an index from the browser session to its token sessions, which is a later change.
- No change to the hint rules: a hint is still required, verified, and accepted when expired.
- No change to the device grant. Its token session gets no link yet.

## Decisions

### The verified hint names the client

Without `client_id`, the client is the hint's `azp`, or else its `aud` when that holds exactly one value. Hearth's ID tokens carry one `aud`, the issued client ID, so in practice the hint names its client. The URI must still be one of that client's registered `post_logout_redirect_uris`.

RP-Initiated Logout 1.0 §3 names the hint as the way the OP learns the client when `client_id` is absent. The hint's signature is verified against the realm's active and in-grace keys before any claim is read. So the worst case is a redirect to a URI that the hint's own client registered, which is not an open redirect. A holder of a hint can already log the user out, because expired hints are accepted by design. The redirect gives such a holder nothing more.

A hint with several `aud` values and no `azp` is ambiguous, so the redirect is dropped. When both `client_id` and a hint are present, the existing `ClientMismatch` check still runs first.

### Link the token session to the session that authorized it

`StoredAuthorizationCode` gets `authorizing_session_id: Option<SessionId>`, with `#[serde(default)]`, so a code stored before the upgrade still decodes. `authorize_inner` fills it from the bearer token's session on the non-interactive surfaces, and from the browser session on the UI path. `authorize_from_session` takes that session's ID next to its proof.

The exchange writes a link row `session_parent:<token sid>` → `<root sid>` after it creates the token session. The root is the authorizing session's own link target when it has one, else the authorizing session. So a code minted with a bearer token whose session is itself a token session links to the browser session at the top, and logout follows one hop only. The link is a row of its own, not a `Session` field, so the session row format does not change.

At logout, after it revokes the hint's session, the engine reads the link, deletes it, and revokes the authorizing session too. `SessionNotFound` on either session is ignored, so logout stays idempotent.

Alternatives considered:
- **A `parent` field on `Session`.** It changes the stored row format of every session for one optional value.
- **Find the browser session by user.** A user can have several browsers. Revoking all of them on one client's logout is too broad.

### Sweep the link when the token session is gone

The link row follows the pattern of `sweep_session_family_index`. A row is deleted when the token session it names no longer exists. The token session row is always written before its link, so "missing" can only mean "deleted", never "about to be created". The sweep runs after `sweep_sessions`, so one tick deletes an expired session and its link.

### The bare endpoint clears no cookies

The bare `/end_session` is for back ends: it needs `X-Realm-ID`, which a browser navigation cannot send. A cookie in its response reaches the client's back end, not the user's browser. The server-side revocation of the browser session is what signs the browser out, so this change adds no cookies to the bare endpoint.

### A browser gets an HTML page

When no front-channel page is served and no redirect survives, the response depends on `Accept`. If it includes `text/html`, the response is `200` with a small "You are signed out" page (`templates/ui/signed_out.html`, standalone, dark theme, like the continue page). Otherwise it stays `{"message":"logged out"}`. The drop reason (no client, unregistered URI, ambiguous hint) is logged at `debug`, without the URI or any claim.

## Risks / Trade-offs

- [A logout from one client ends the browser session for every client] → This is what logout from the OP means. The other clients' token sessions stay valid until their own expiry (non-goal above).
- [Codes in flight during the upgrade have no `authorizing_session_id`] → Their token sessions get no link, and logout revokes only the token session, as today. Codes live for 10 minutes.
- [A JSON client that sends `Accept: text/html`] → It gets the HTML page. A machine client that wants JSON sends `Accept: application/json` or no `Accept`.
