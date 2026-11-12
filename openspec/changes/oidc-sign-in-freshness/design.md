## Context

The browser authorize page (`/ui/oauth/authorize`, `/ui/realms/{realm}/oauth/authorize`) builds the validated request (plain query, JAR or PAR) and runs the gates: MFA use, required actions, consent, then code issuance. Every browser sign-in (password, passkey, magic link, each second-factor step, federation) revokes the session in the browser's cookie and opens a new one, after the last factor (task 24.1). So a session's creation time is the time its interactive sign-in completed, including a required second factor.

## Goals / Non-Goals

**Goals:**
- `prompt=login` and an exceeded `max_age` force a sign-in; `prompt=none` gets `login_required`.
- `auth_time` in the ID token.
- No loop: the request that resumes after the forced sign-in goes on to the code.

**Non-Goals:**
- `max_age` in a request object or a pushed request: the parameter is read from the query string only. A pushed request ignores outer parameters (RFC 9126 §4). The ID token always carries `auth_time`, so the client can check the age itself.
- Resuming a JAR or PAR request after a forced sign-in: the request object or `request_uri` is single-use and is spent before the sign-in, so the resumed request fails closed with its existing error. #829 tracks it.
- `auth_time` on the device-code grant and the JSON authorize API (no browser sign-in).

## Decisions

1. **`auth_time` = the browser session's creation time.** That is the time of the last completed interactive sign-in, including a required second factor. The code stores it at authorization, so a later session change does not alter it. A code from a bearer token (JSON API) has none.
2. **A forced sign-in is a normal sign-in.** It opens a new session and revokes the old one, as every sign-in does. The session id rotates, so a code issued before the sign-in names the revoked session. This keeps the session-fixation defense of task 24.1. (Owner decision on #782: option B.)
3. **Always send `auth_time`.** OIDC Core §2 allows it in every ID token. The code then does not need to remember whether the request had `max_age`.
4. **The resume marker.** The sign-in page returns the browser to `/ui/realms/{realm}/oauth/authorize?<request>&hearth_reauth=<marker>`. The marker is `{nonce}.{issued_micros}.{mac}`, with the HMAC-SHA256 under the cookie secret over the realm, the nonce, the issue time and every other query parameter. It is accepted only if the signature matches, it is at most 10 minutes old, the session's sign-in completed after it was issued, and its nonce was not used (the nonce is burned in the durable single-use nonce store). A replayed, expired, forged or premature marker forces the sign-in again.
5. **`max_age` counts in microseconds.** `max_age=0` forces a sign-in after any time, as OIDC Core §3.1.2.1 describes.

## Risks / Trade-offs

- [A JAR or PAR request with `prompt=login` fails after the sign-in] → Fail closed: no code without the sign-in. Follow-up: #829.
- [The marker nonce shares the store of the MFA pending-cookie nonces] → A `reauth:` prefix keeps the two apart; the nonces are 128-bit random values.
