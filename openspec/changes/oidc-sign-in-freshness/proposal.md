## Why

OIDC Core §3.1.2.1 says that the OP MUST make the user sign in again for `prompt=login`, and when the time since the last sign-in is more than `max_age`. OIDC Core §2 says that the ID token MUST carry `auth_time` when the request has `max_age`. Hearth ignored both parameters and sent no `auth_time`. A relying party that asks for a fresh sign-in before a sensitive action got a code from an old session. The OpenID Foundation modules `oidcc-prompt-login`, `oidcc-max-age-1` and `oidcc-max-age-10000` fail (#782, part of #639 and #652).

## What Changes

- A browser authorization request with `prompt=login`, or with a `max_age` that the session's age exceeds, goes to the sign-in page before a code is issued. With `prompt=none` it gets `login_required`.
- The forced sign-in is a normal sign-in: a new session, and the old session is revoked (session-id rotation stays as it is).
- The authorize request that resumes after the sign-in carries a signed, short-lived, single-use marker, so it does not force a second sign-in.
- The ID token carries `auth_time` for every code that a browser session authorized.
- A `max_age` that is not a non-negative integer gets `invalid_request`.

## Capabilities

### New Capabilities

### Modified Capabilities
- `oidc-provider`: ADDED requirement "A request can demand a fresh sign-in".

## Impact

- `src/protocol/web/reauthentication.rs` (new), `src/protocol/web/oauth_consent.rs`, `src/protocol/web/auth.rs` (`UiSession::authenticated_at`).
- `src/identity/oidc.rs` (`StoredAuthorizationCode::auth_time`), `src/identity/engine/oauth.rs` (the code and the ID token).
- `CHANGELOG.md`. No config, proto or SDK change. Stored codes get one optional field; older rows decode without it.
