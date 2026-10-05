## 0. Before you start

- [ ] 0.1 Read the draft advisory `GHSA-hxcr-696v-vqw3` (maintainers only)
- [x] 0.2 Write `design.md`: the no-op provider rule, the API sign-in endpoints in scope, and one status code for a challenged API caller (reconcile A-3 and A-16 in the spec)
- [x] 0.3 For every task: write the scenario as a failing test first (red), then fix (green). Each fix needs a `### Security` entry in `CHANGELOG.md`

## 1. Challenge

- [x] 1.1 Scenario "A challenged login is audited and challenged" (A-3). Test: `a3_challenged_login_is_audited_and_challenged` (`tests/abuse_detector.rs`)
- [x] 1.2 Scenario "A guard refuses a login" (no provider: generic page). Test: `a3_challenged_login_is_audited_and_challenged` (`tests/abuse_detector.rs`)
- [x] 1.3 Scenario "A challenged login sees the widget when a provider is configured". Test: `a3_challenged_login_shows_the_widget_whatever_the_address` (`tests/abuse_detector.rs`)
- [x] 1.4 Scenario "A sustained attack does not flood the audit log". Tests: `a3_challenged_sustained_attack_does_not_flood_the_audit_log` (`tests/abuse_detector.rs`), `challenge_audit_is_written_once_per_key_per_window` (`src/abuse/runtime.rs`)
- [x] 1.5 Scenario "A challenged magic-link request". Test: `a3_challenged_magic_link_request` (`tests/abuse_detector.rs`)
- [x] 1.6 Scenario "Without a provider, the API answers with a timed lockout". Tests: `a3_challenged_api_without_a_provider_is_a_timed_lockout` (`tests/abuse_detector.rs`), `a3_challenge_carries_the_time_left_in_its_window` (`src/abuse/runtime.rs`)
- [x] 1.7 Scenario "A hot IP keeps guessing". Test: `a16_hot_ip_login_attempt_is_shown_the_widget` (`tests/abuse_captcha.rs`)
- [x] 1.8 Scenario "A challenged caller is told to solve a challenge". Test: `a16_challenged_caller_is_told_to_solve_a_challenge` (`tests/abuse_captcha.rs`)
- [x] 1.9 Scenario "The challenge is solved" and "A solved CAPTCHA lets the sign-in continue". Tests: `a16_solved_captcha_lets_the_login_continue`, `a16_solved_captcha_lets_the_json_sign_in_continue` (`tests/abuse_captcha.rs`), `a_solved_captcha_clears_the_challenge_state` (`src/abuse/runtime.rs`)
- [x] 1.10 Scenario "A wrong CAPTCHA token counts as a failure". Tests: `a16_wrong_captcha_token_counts_as_a_failure` (`tests/abuse_captcha.rs`), `a_rejected_captcha_token_counts_as_a_failure` (`src/abuse/runtime.rs`)
- [x] 1.11 Scenario "Failed passkey sign-ins count". Tests: `a16_failed_passkey_sign_ins_count` (`tests/abuse_captcha.rs`), `pre_auth_passkey_applies_the_a16_state_only` (`src/abuse/runtime.rs`)

## 2. Surfaces and docs

- [x] 2.1 `HEARTH_ABUSE_CHALLENGE_REQUIRED` in `src/protocol/error_codes.rs` and `docs/guides/error-codes.md`
- [x] 2.2 Optional `captcha_token` on `POST /v1/{realm}/auth/magic-link` and `POST /webauthn/auth/complete`; `make openapi`
- [x] 2.3 Login page widget at `<!-- captcha-widget-slot -->`, and a per-page CSP that admits the provider's origin
- [x] 2.4 `CHANGELOG.md`: `### Security` and `### Added` entries
- [ ] 2.5 Run `make ui-test-smoke` and `make ui-test-accessibility` against `make dev`
