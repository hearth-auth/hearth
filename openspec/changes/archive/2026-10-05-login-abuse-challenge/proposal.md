## Why

`security-hardening` found that a challenged sign-in is neither audited nor actually challenged: the caller gets only the generic failure page, and the documented challenge error code is never returned. A real challenge needs a login-page widget, a verification step and a rule for what "challenge" means when no CAPTCHA provider is configured, so it moves here.

The detail is kept in the draft repository security advisory `GHSA-hxcr-696v-vqw3` (maintainers only).

## What Changes

- A challenged sign-in writes an `AbuseDetected` audit event. The reason stays out of the response.
- The login page shows the configured CAPTCHA widget to a challenged caller, and a solved challenge clears the guard.
- The API answers a challenged caller with `HEARTH_ABUSE_CHALLENGE_REQUIRED`.
- Each fix ships with a `### Security` entry in `CHANGELOG.md`.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `abuse-prevention`: scenarios added to "A-3 Distributed-attack detector" and "A-16 CAPTCHA-of-last-resort challenge".

## Impact

- **Code:** `src/protocol/web/handlers.rs` (login), `templates/ui/login.html`, `src/abuse/`, `src/protocol/error_codes.rs`.
- **UI:** follows `docs/dev/THEME.md`; run the UI smoke and accessibility checks.
- **Design:** `design.md` settles three points before coding: what a challenge means under the default no-op CAPTCHA provider, which API sign-in endpoints answer the challenge code, and whether a challenged API caller gets `403` or `429` (A-3 and A-16 disagree today).
- **Order:** after `security-hardening`.
