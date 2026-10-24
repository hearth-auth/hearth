## 1. Realm policy

- [ ] 1.1 Test first: realm config tests that `passkey_prompt` defaults to `every_login` and `passkey_prompt_interval_days` to `7`; that `hearth.yaml` with `passkey_prompt_interval_days: 0` is refused at startup; that the admin API answers `400` for `0` and keeps the previous value ("An invalid interval").
- [ ] 1.2 Add both fields to the realm type, the `hearth.yaml` realm configuration, the admin API (request and response bodies) and the realm settings page in the admin console.
- [ ] 1.3 Test first: an admin-console test that the realm settings page shows and saves both fields with realm-qualified URLs (`ui-routing` R-8).

## 2. Prompt decision

- [ ] 2.1 Test first: unit tests for the decision function, one per condition in "A passkey prompt follows a sign-in without a passkey": policy `off`; `allowed_auth_methods` without `passkey`; `webauthn_required: true`; sign-in by passkey; account with a passkey; `interval` inside and after the window; `prompt=none`.
- [ ] 2.2 Implement the decision function in the identity layer (it reads realm settings, the account's passkeys and the "Not now" timestamp; no protocol types).
- [ ] 2.3 Test first: a storage test that "Not now" under `interval` writes the account timestamp, and that "Not now" under `every_login` writes nothing. Then implement the timestamp write.

## 3. Pipeline step and page

- [ ] 3.1 Test first: integration tests through `TestHarness` for "A password user without a passkey" (the authorization code is issued only after the prompt) and "Required actions come first" (`UPDATE_PASSWORD` runs before the prompt).
- [ ] 3.2 Add the prompt step to the hosted sign-in pipeline after required actions and before the authorization code or the `return_to` redirect, for realm sign-in and admin console sign-in.
- [ ] 3.3 Read `docs/dev/THEME.md`. Then create the prompt template under `templates/ui/`: one `btn-ember` ("Create a passkey"), a secondary "Not now", the WebAuthn-support check that swaps in "Continue", and no light-mode styles. Rebuild `app.css`.
- [ ] 3.4 Test first: handler tests for "The user dismisses the prompt" (one action continues the sign-in), "The user cancels the ceremony" (the prompt shows again) and "A browser without passkey support" ("Continue" records no "Not now").

## 4. Enrolment ticket

- [ ] 4.1 Test first: integration tests for every scenario of "Enrolment from the prompt needs no second step-up proof": enrolment with the ticket; reuse; expiry at 300 s (injected clock); another session's ticket; a ticket offered for passkey removal gets `403 step_up_required`.
- [ ] 4.2 Implement ticket creation in the prompt step (256-bit random, server-side, bound to the session, 300 s, single-use) and its acceptance in the account page's passkey registration handlers only.
- [ ] 4.3 Test first: a test that the ticket appears in the prompt page body and in no `Set-Cookie` header.

## 5. Metrics

- [ ] 5.1 Test first: a metrics test for "A dismissal is counted", plus `enrolled` and `unsupported`, and that the counter carries only the `outcome` label.
- [ ] 5.2 Implement `hearth_passkey_prompt_total{outcome}`.

## 6. UI verification and documentation

- [ ] 6.1 Add the prompt page to `make ui-test-smoke` and `make ui-test-accessibility` (a password sign-in for a user without a passkey reaches the page; "Not now" reaches the client). Run both against `make dev`.
- [ ] 6.2 Update `docs/guides/configuration-reference.md` (realm fields, the metric) and the passkey guide (the prompt, the policy values, the enrolment ticket).
- [ ] 6.3 Add `CHANGELOG.md` entries under `[Unreleased]` / Added: the passkey prompt, the realm policy fields, the metric.
- [ ] 6.4 Resolve design open questions 1 (default policy) and 2 (account page banner) with the owner; record the answers in `design.md`.
- [ ] 6.5 Run `make check` and `make test-detached`.
