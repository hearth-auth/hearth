## Why

Hearth's UI sends `Content-Security-Policy: form-action 'self'` in production. Chrome applies `form-action` to every redirect that follows a form submission, not only to the first request. The hosted sign-in, second-factor, required-action and consent forms all post to Hearth, and Hearth answers with a `303` chain that ends on the client's `redirect_uri`. When that URI is on another origin, which is the normal case, Chrome blocks the navigation and the user never reaches the application. The first real-world integration found this in production. Hearth's own reference-integration suite hit the same wall and was fixed for `--dev` only, through `security.dev_csp_form_action_origins`.

## What Changes

- A form submission in the hosted sign-in flow never ends in a redirect off Hearth's origin. Where such a form POST answered `303`, Hearth now answers `200` with a small continue page. The page navigates to the same target with `<meta http-equiv="refresh">` and also shows a link. A meta refresh is not a form submission, so `form-action 'self'` no longer applies to the rest of the chain, including any redirect that the application itself makes after its callback.
- The change covers the sign-in POSTs (realm, realm-scoped and admin), the TOTP, email-OTP and required-MFA-enrolment POSTs, the required-action POSTs and the consent POST (approve and deny).
- **BREAKING:** the config key `security.dev_csp_form_action_origins` is removed. The CSP `form-action` directive is always `'self'`, in dev and in production.
- `Permissions-Policy` no longer names `bluetooth` and `interest-cohort`. Chrome does not recognize them and logs a console error on every Hearth page.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `oidc-provider`: adds a requirement that a hosted form submission never ends in a redirect off Hearth's origin.

## Impact

- **Code:** a new response layer in `src/protocol/web/`, a new template under `templates/ui/`, the route table in `src/protocol/web/mod.rs`, `src/protocol/web/security.rs` (CSP builder and `Permissions-Policy`), and the config types and key list in `src/config/`.
- **Behavior:** the affected POSTs answer `200` with a continue page instead of `303`. Browsers follow it at once. Clients that scrape these forms and read `Location` must read the page instead.
- **Config:** `security.dev_csp_form_action_origins` is removed from `hearth.maximal.yaml`, the full-stack demo config and the docs.
- **Tests:** the integration tests that assert a `303` from these POSTs, the consent Playwright flow, and the reference-integration suite.
