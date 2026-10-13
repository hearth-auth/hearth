## 1. Continue-page layer

- [x] 1.1 Write unit tests in `src/protocol/web/continue_page.rs` first: a `POST` that answers `303` becomes `200` `text/html` with a meta refresh and a link to the target; the URL is HTML-escaped; every `Set-Cookie` header is kept; `Location` is removed; a `GET`, a `200` and a `302` pass through unchanged.
- [x] 1.2 Add `templates/ui/continue.html` (dark theme tokens, `app.css`, no layout) and the layer `continue_page::end_form_navigation`, so the tests in 1.1 pass.

## 2. Wire the layer to the sign-in POST routes

- [x] 2.1 Write `tests/form_action_continue.rs` first: through the real web router, the sign-in POST during an authorization request answers `200` with a continue page whose target is the UI authorize URL and sets the session cookie; following the target reaches the client's `redirect_uri` with a code. Add the same check for consent approve and deny and for a required action. The TOTP and email-OTP challenges are covered by the updated `web_ui_mfa_login` and `mfa_otp_second_factor_login` tests.
- [x] 2.2 Apply the layer with `.route_layer` to the sign-in (realm, realm-scoped, admin), `/mfa-challenge`, `/mfa-otp-challenge`, `/mfa-enroll-required/activate`, the four required-action POST routes and `/oauth/consent`, so 2.1 passes.
- [x] 2.3 Make `tests/support/browser.rs::location` return the redirect target of either a `303` or a continue page (`Refresh` header), and move the integration tests that post to these routes onto it or onto an equal local helper.
- [x] 2.4 Update the load tools that score a sign-in: `loadtest/live/k6/lib.js` and `examples/http_saturation.rs` (unit tests `login_continue_page_to_ui_counts_as_success`, `refused_login_does_not_count_as_success`, `refresh_target_is_read_from_the_head` first).

## 3. Strict `form-action` everywhere

- [x] 3.1 Write `tests/form_action_continue.rs::dev_mode_keeps_the_strict_form_action_directive` first: under `--dev` the CSP has exactly `form-action 'self'`. Drop the dev-origin unit tests in `src/protocol/web/security.rs`.
- [x] 3.2 Remove `security.dev_csp_form_action_origins` from the config types, the key list, `build_csp`, the router gate, `hearth.maximal.yaml`, the full-stack demo config, `docs/security/csp.md` and `docs/guides/configuration-reference.md`.

## 4. Permissions-Policy

- [x] 4.1 Extend `tests/abuse_http.rs::a40_coop_coep_headers_present` first: the `Permissions-Policy` value names neither `bluetooth` nor `interest-cohort` and still denies camera, microphone, geolocation, payment and usb.
- [x] 4.2 Remove `bluetooth=()` and `interest-cohort=()` from the header in `src/protocol/web/security.rs`.

## 5. Browser verification and docs

- [x] 5.1 Run the reference-integration Playwright suite (`tests/ui/integration/`) in Chromium with the strict directive. Update `tests/ui/flows/oauth_consent.spec.ts` to read the continue page.
  - Result: the SPA on `localhost:5173` signs in on `localhost:8420` and lands on its dashboard (flow 1), and self-registration passes (flow 2).
  - 7 flows fail later, at token verification, with the same result on `main`. The SDKs expect `aud: "hearth"` (#402), but the server sets `aud` to `oidc.issuer` when one is configured. That fix is a separate change.
- [x] 5.2 Add the `CHANGELOG.md` entries (Fixed: sign-in to a client on another origin; Removed: the config key; Fixed: the console error).
