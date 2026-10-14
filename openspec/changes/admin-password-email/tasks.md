## 1. Tests first

- [x] 1.1 Engine tests: `request_password_email` returns `Setup` for a user with no password and `Reset` for a user with one; a setup link redeems after 24 hours and a reset link does not; the limit is shared with `request_password_reset`; a realm without password sign-in is refused; a newer link supersedes a setup link.
- [x] 1.2 Config tests: `set_password_token_ttl` parses, defaults to 72 hours, and A-14 refuses more than 7 days without `allow_unsafe_ttl`.
- [x] 1.3 Black-box `tests/admin_password_email.rs`: the REST route with the mailcatcher: `200` + `SETUP` and the welcome email with a link that sets the password; `200` + `RESET` for a user with a password; `404`, `403` (ceiling), `429` (fourth call), `503` (no transport).
- [x] 1.4 Console: the bulk "Send invite" action sends the welcome email to a user with no password.
- [x] 1.5 Run them red.

## 2. Implementation

- [x] 2.1 `StoredPasswordReset.purpose`, `request_password_email`, the TTL by purpose, and the non-consuming purpose lookup.
- [x] 2.2 The `set_password_token_ttl` key, its A-14 cap, docs and `hearth.maximal.yaml`.
- [x] 2.3 The `welcome` sender, built-in templates and the `{{set_password_url}}` placeholder.
- [x] 2.4 `src/protocol/password_email.rs`; the console action and the bulk action use it.
- [x] 2.5 The proto RPC, the REST handler and route, the OpenAPI document, the SDK admin types, and `sendPasswordEmail` in the Go, TypeScript, Python and PHP `AdminClient`.
- [x] 2.6 The reset page title for a set-password link.

## 3. Close out

- [x] 3.1 `CHANGELOG.md` entries.
- [ ] 3.2 `make check`, `make test-detached`, `make ci-local-fast`.
- [ ] 3.3 `make ui-test-smoke` and `make ui-test-accessibility` against a dev server on a free port.
