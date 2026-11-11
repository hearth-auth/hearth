## 1. Tests first (red)

- [x] 1.1 `tests/oidc_reauthentication.rs`: `auth_time` in the ID token; `max_age` that the session meets; `prompt=login` and `max_age=0` force a sign-in and then issue a code with a new `auth_time` and a new session; `prompt=none` with an exceeded `max_age` gets `login_required`; a replayed, premature or forged marker forces a sign-in again.
- [x] 1.2 Run the file: every case fails (red).

## 2. Implementation

- [x] 2.1 `StoredAuthorizationCode::auth_time` from the browser session; `auth_time` in the ID token.
- [x] 2.2 `UiSession::authenticated_at`.
- [x] 2.3 `src/protocol/web/reauthentication.rs`: the freshness gate and the resume marker; call it from the authorize page on fresh entry.
- [x] 2.4 Run the new tests and the browser-flow tests (green).

## 3. Close-out

- [x] 3.1 `CHANGELOG.md` entry.
- [ ] 3.2 OpenID Foundation run: `oidcc-prompt-login`, `oidcc-max-age-1` and `oidcc-max-age-10000` pass (next `make conformance-oidf` run).
