## 0. Freeze and order

- [ ] 0.1 Archive `scope-trim-trusted-core` first
- [x] 0.2 Add the feature-freeze rule and its end condition to `CONTRIBUTING.md` (design decision 1)
  - Done during `scope-trim-trusted-core` task 14.4.
- [ ] 0.3 `README.md` and `docs/STATUS.md`: say Hearth is not yet production-ready, and name the open gates (the "A gate is open" scenario)

## 1. Known defects carried from the scope trim (allowed under the freeze)

- [ ] 1.1 `amr`: no flow fills `amr_values` since the SMS removal, so TOTP and passkey logins emit no `amr` claim. Red test per login method, then fill it (`src/identity/oidc.rs`)
- [ ] 1.2 The HTTP device grant answers `401` for `invalid_dpop_proof`; RFC 9449 §5 says `400`. Red test, then fix
- [ ] 1.3 `/authorize` answers an unsupported `response_mode` as `invalid_request` with the description `unsupported_response_mode`. Decide the right error, red test, fix
- [ ] 1.4 The engine's `authorize()` ignores a JAR's `response_mode` (RFC 9101 §4). Red test, then fix
- [ ] 1.5 An `UPDATE_PASSWORD` required action followed by consent bounces to login (the password change revokes the session, and the resume issues no new cookie). Red test, then fix
- [ ] 1.6 `HEARTH_ABUSE_CHALLENGE_REQUIRED` is documented but never emitted. Emit it or delete it from the docs
- [ ] 1.7 `/admin/realms` answers `405` before authentication. Red test (unauthenticated caller gets the auth error), then fix
- [ ] 1.8 `allow_reserved_permissions: true` is set only by tests. Decide: remove the key, or document it
- [ ] 1.9 `cargo deny` warns about unused license allowances. Remove them
- [ ] 1.10 The startup warning when a realm sets `mfa: optional` is not asserted by a test. Add the assertion

## 2. External OIDC conformance

- [ ] 2.1 `scripts/conformance-oidf.sh` and `make conformance-oidf`: pinned suite tag, Docker stack, `serve -c` with TLS and a real KEK, refuses `--dev`, exits non-zero on any failed condition
- [ ] 2.2 Run Config OP; confirm the RS256 failure from 2026-09-21 is gone
- [ ] 2.3 Run Basic OP and Dynamic OP; fix each failure with a red test first
- [ ] 2.4 Record each warning and its decision (design Open Question 1 for `resource_indicators_supported`)
- [ ] 2.5 Write the run report under `reports/`, and update `docs/dev/TESTING.md` §7
- [ ] 2.6 Add the run to `docs/release-runbook.md` as a release step

## 3. Entry-point invariant registry

- [ ] 3.1 Survey every entry point that creates a session or issues a token: HTTP routes (login forms, passkey, magic link, TOTP step, social and SAML callbacks, `/token` grants, device grant, token exchange) and CLI commands
- [ ] 3.2 Write the registry and the router-walk guard in `tests/entry_point_invariants.rs`; red on a deliberately unregistered route
- [ ] 3.3 Invariants: realm status, organization status, user status, client status, MFA policy, pre-token webhook policy. One table-driven test each
- [ ] 3.4 Fix every entry point the tests find, red test first
- [ ] 3.5 Add one `ci/mutations.toml` entry per invariant (verify each with `--only <id>`)

## 4. Mutation testing

- [ ] 4.1 Nightly `cargo-mutants` workflow on `src/identity/`, `src/rbac/`, `src/protocol/http/`, sharded
- [ ] 4.2 First run; write `ci/mutants-budget.toml` (design Open Question 3)
- [ ] 4.3 Budget check script with a self-test that proves it can fail
- [ ] 4.4 Triage the survivors in the token-issuance and session code: a test, or an exclusion with a reason

## 5. External pentest

- [ ] 5.1 Rewrite `docs/security-audit/pentest-scope.md` from the router and `docs/STATUS.md`; a check fails on a named path that does not exist
- [ ] 5.2 Owner: choose the firm and the budget (design Open Question 2)
- [ ] 5.3 Engagement against a tagged build
- [ ] 5.4 Fix every Critical and High finding with a regression test; firm re-test
- [ ] 5.5 Record a decision for each Medium and Low finding

## 6. The claim

- [ ] 6.1 When every gate passes, update `README.md` and `docs/STATUS.md` with the claim and links to the evidence
- [ ] 6.2 CHANGELOG entries for the fixes in groups 1, 2 and 3
