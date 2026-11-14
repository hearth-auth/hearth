## 1. Tests first (red)

- [x] 1.1 Engine and HTTP tests: a confidential client with `require_pkce: false` gets a code without `code_challenge` and exchanges it without `code_verifier`; a `code_verifier` for that code is `invalid_grant`; a request with `code_challenge_method=plain` is still refused; a public client needs PKCE also with `require_pkce: false` in its record.
- [x] 1.2 Admin API and config: `require_pkce: false` for a public client is refused (create, `PATCH`, `hearth.yaml`); the response shows the value; the default is `true`.
- [x] 1.3 Run them: red.

## 2. Implementation

- [x] 2.1 `OAuthClient::require_pkce` (serde default `true`) and `pkce_required()`.
- [x] 2.2 The authorize, PAR and browser gates use `pkce_required()`.
- [x] 2.3 The code exchange refuses a `code_verifier` for a code without a challenge.
- [x] 2.4 Config key, validation and reconcile; admin API create and update; proto field; backup import.
- [x] 2.5 Tests green.

## 3. Close-out

- [x] 3.1 Docs (configuration reference, API reference, backup guide) and `CHANGELOG.md`.
- [x] 3.2 `scripts/conformance-oidf/hearth.yaml`: the static clients set `require_pkce: false`.
- [ ] 3.3 OpenID Foundation run: the Basic OP plan runs past the PKCE stop with the release image.
