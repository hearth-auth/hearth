Each numbered group ships as one PR, in this order (design decision 1). Each PR passes `make check`, `make test-quality`, `make test-no-dev-endpoints` and `make ci-local-fast` before you push. Each PR adds its own `CHANGELOG.md` entries under `## [Unreleased]`. Red tests come first (TDD).

## 1. Shared groundwork

- [ ] 1.1 Write red tests for the removed-key table: an `sms:` block and a `server.grpc_port` key each stop startup with an error that names the key, the feature and `3.0.0`
- [ ] 1.2 Add the removed-key table in `src/config/` and rewrite the `deny_unknown_fields` parse error through it. Each later group adds its own keys to the table
- [ ] 1.3 Add a red black-box helper to `tests/common/mod.rs` that asserts a route answers `404` like an unknown path. Later groups use it

## 2. SAML IdP side (PR 1)

- [ ] 2.1 Red tests: the six IdP routes answer `404`; `realms.<name>.saml_service_providers` stops startup; a v2 archive with `saml_service_providers.ndjson` restores with one warning
- [ ] 2.2 Green-before-delete guard: confirm the SP-side tests in `tests/saml.rs`, `tests/saml_web_hardening.rs` and `tests/web_ui_federation.rs` pass. Move the SP-side cases into `tests/saml_sp.rs`
- [ ] 2.3 Delete `src/identity/federation/saml/idp.rs`, the IdP handlers in `src/protocol/web/saml.rs` (`idp_metadata`, `idp_sso_get/post`, `idp_complete_sso`, `idp_sso_init`, `idp_slo_get/post`, `idp_complete_slo`, `reject_session_realm_mismatch`, `asserted_attributes`) and their routes in `src/protocol/web/mod.rs:1243–1266`
- [ ] 2.4 Delete the SP registry: the engine trait methods (`identity/mod.rs:2254–2281`, the caller-less `record/list_saml_sp_session*`), the engine impl, the `saml:sp:` storage keys, `reconcile_saml_sps_for_realm`, `SamlServiceProviderYaml` and its validation
- [ ] 2.5 Delete the IdP-only code in `logout.rs` and the `build_response_xml`/`ResponseBuilder` paths in `response.rs`. Move any test-only helpers the SP tests need into a `#[cfg(test)]` module
- [ ] 2.6 Backup: stop exporting `saml_service_providers.ndjson`; make the importer skip it with a warning (`backup/export.rs`, `import.rs`, `types.rs`, `main.rs:5429`)
- [ ] 2.7 Update `docs/specs/SAML.md`, `federation.md`, `backup.md`, `security-hardening.md`, `error-codes.md`, `CONFIGURATION.md`, the hearth-yaml examples and README
- [ ] 2.8 CHANGELOG `### Removed` entry for the SAML IdP side

## 3. SAML SP strict profile (PR 2)

- [ ] 3.1 Red tests from `specs/saml-sp-profile`: DOCTYPE, two assertions, two signatures, and a wrapped-copy XSW case that names a different user
- [ ] 3.2 Enforce the structural checks in the SP response parser before signature verification
- [ ] 3.3 Read the subject and attributes only from the element the verified reference identifies
- [ ] 3.4 Choose a maintained third-party XSW corpus, vendor it under `tests/fixtures/saml-xsw/` with its licence, and add a CI step that runs it
- [ ] 3.5 CHANGELOG `### Security` entry

## 4. Public gRPC (PR 3)

- [ ] 4.1 Red tests: a single-node server listens only on the HTTP port; each `grpc_*` key and `security.grpc` stops startup; a 3-node cluster still elects a leader and replicates
- [ ] 4.2 Delete `src/protocol/grpc/`, the startup wiring (`main.rs:1836`, `3248–3280`), the config keys, the `shaper.rs` gRPC interceptor and `examples/grpc-admin-flow`
- [ ] 4.3 Drop `tonic-health`, `tonic-reflection` and the unused `tonic-types` from `Cargo.toml`. Keep `tonic`, `tonic-prost`, `prost`, `pbjson` and `pbjson-types`
- [ ] 4.4 Remove the `service` blocks from `proto/hearth/{identity,rbac,events}/v1`. Regenerate `openapi.proto-derived.json` and diff `docs/api/openapi.json`. If the REST paths disappear, keep the `service` blocks as schema-only and document that in `PROTO.md` (design decision 3)
- [ ] 4.5 Delete the ~13 gRPC-only test files. Port any assertion that guards REST behaviour into a REST test first
- [ ] 4.6 Update `buf.gen.yaml`, the Makefile `proto-gen`/`proto-check` targets, `.githooks/pre-commit`, and the `proto-freshness`/`proto-governance` CI jobs to match
- [ ] 4.7 Update `docs/specs/PROTO.md`, `docs/api/grpc-only.txt` (delete), `api-reference.md`, `admin-api.md`, `CONFIGURATION.md`, `ARCHITECTURE.md`, `clustering.md`
- [ ] 4.8 CHANGELOG `### Removed` entry for public gRPC

## 5. MFA policy (PR 4)

- [ ] 5.1 Red tests from `specs/mfa-policy`: the default is required; the explicit opt-out is honoured; email OTP and magic link do not satisfy MFA; a passkey alone does; org tightening; org cannot loosen; the startup `WARN`; the console banner; an audit event on change
- [ ] 5.2 Add `effective_mfa_requirement(...)` in the identity layer, and route every `mfa_required.unwrap_or(...)` site through it (`web/second_factor.rs:124`, `web/handlers.rs:2669`, `engine/oauth.rs:1389`, `engine/mod.rs:18971`, plus any others a search finds)
- [ ] 5.3 Add the CI lint (clippy `disallowed-methods` or a `scripts/` check) that fails on a direct read of `mfa_required` outside the resolver, with a red self-test
- [ ] 5.4 Split the email OTP proof from `MfaProof::Proved`, and make `satisfies_mfa_required` accept only WebAuthn, TOTP and recovery-code proofs
- [ ] 5.5 Add `mfa_required` to organizations (storage, admin REST, console, SCIM-created orgs default `false`), and feed it to the resolver
- [ ] 5.6 Add the startup `WARN`, the console warning banner (follow `docs/specs/THEME.md`), and the audit events
- [ ] 5.7 Keep the production default under `--dev` (owner decision). Make `/admin/bootstrap` and the quick start in `CLAUDE.md` and README describe the enrolment step for the dev admin. Update `make dev`-based scripts (`make sdk-smoke-local`, UI smoke, `make seed`) that sign in as the dev admin
- [ ] 5.8 A cluster test: the leader and a follower reach the same MFA decision for the same user
- [ ] 5.9 CHANGELOG `### Changed` (default required, email OTP no longer MFA) and `### Added` (org MFA) entries

## 6. Risk scoring, adaptive MFA and SMS OTP (PR 5)

- [ ] 6.1 Red tests: `security.risk_scorer` and `sms:` stop startup; the SMS routes and `/admin/users/{id}/device-fingerprints` answer `404`; refresh rotation works with no scorer; `mfa_methods: ["sms"]` is rejected
- [ ] 6.2 Delete `src/abuse/risk_scorer.rs`, `src/identity/risk.rs`, `device_fp.rs`, `device_fingerprint.rs`, the realm `adaptive_mfa` and `risk_scorer_config` fields, the call at `engine/mod.rs:4132–4145`, the step-up recording (`engine/oauth.rs:1564`), the sweeper (`main.rs:2286`), the admin route and the `DeviceFingerprintsErased` audit action
- [ ] 6.3 Delete `src/identity/sms/`, `src/protocol/web/sms_challenge.rs`, `RequiredAction::EnrollPhoneOtp` and its required-action code, the SMS config keys, `HEARTH_SMS_OTP_HMAC_KEY`, the realm `sms_otp_*` fields, the `sms_*` volume-shield settings, `check_outbound_sms`, and the SMS paths in `abuse/detector.rs`
- [ ] 6.4 Delete the risk, device-fingerprint and SMS test files listed in the footprint survey
- [ ] 6.5 Delete `docs/guides/sms-mfa-deployment.md`; update `required-actions.md`, `CONFIGURATION.md`, `ABUSE.md`, `privacy.md`, `concepts.md`
- [ ] 6.6 CHANGELOG `### Removed` entries

## 7. ROPC password grant (PR 6)

- [ ] 7.1 Red tests: `grant_type=password` answers `400 unsupported_grant_type` for a public and a confidential client; discovery `grant_types_supported` has no `password`; DCR refuses `password` in `grant_types`; a config client listing `password` stops startup with a named error
- [ ] 7.2 Add a token helper for tests behind the `test-hooks` feature (or use the authorization-code flow via `TestHarness`), and move the 27 `password_grant_token` test calls in 6 files to it. Prove with `make test-no-dev-endpoints` that the helper is absent from a production build
- [ ] 7.3 Delete `password_grant_token`/`password_grant_token_inner`, `PasswordGrantRequest`, the `grant_type=password` dispatch in `src/protocol/http/oauth.rs`, the adaptive-MFA check and recording at `engine/oauth.rs:1401` and `1464`, and the ROPC grant-type gate
- [ ] 7.4 Delete `tests/ropc_grant_type_gate.rs` and `tests/required_actions_ropc_bypass.rs`, after porting any assertion that guards a kept path
- [ ] 7.5 Update `OIDC.md`, `CONFIGURATION.md`, `api-reference.md`, `docs/api/openapi.json` and any guide that shows `grant_type=password`
- [ ] 7.6 CHANGELOG `### Removed` entry

## 8. JARM and the FAPI 2.0 profile (PR 7)

- [ ] 8.1 Red tests: a DPoP-required client or agent with no `DPoP` proof is refused on each grant (auth code, client credentials, refresh, JWT bearer, device code, step-up) without any FAPI profile; discovery has no JARM or FAPI fields; `fapi_profile` and `profile: fapi2` stop startup; `response_mode=query.jwt` is refused as unsupported
- [ ] 8.2 Check whether `dpop.rs` enforces DPoP-required on its own. If any grant relied on `require_fapi_sender_constraint`, move that check into the DPoP path first
- [ ] 8.3 Delete `require_fapi_sender_constraint` and its call sites, `FapiProfile`, `ClientProfile::Fapi2`, the FAPI authorize gate, the FAPI-only PAR checks, the secret refusals, `check_fapi2_client_keys`, `realm_enforces_fapi`/`refuse_rs256_under_fapi`, the FAPI DCR rules, `IdentityError::FapiViolation`
- [ ] 8.4 Delete JARM: the `*.jwt` `ResponseMode` variants, `JarmClaims`/`JarmErrorClaims`, `new_jarm`/`jarm_jwt`, `sign_jarm_error_jwt`, `authorization_signed_response_alg`, and the JARM branches in `authorize_gate.rs` and `oauth_consent.rs`
- [ ] 8.5 Keep the client `jwks` field (used by `private_key_jwt` and JAR, design decision 9); delete only its "Required with `profile: fapi2`" doc line
- [ ] 8.6 Delete `fapi_conformance.rs`, `fapi2_conformance.rs`, `jarm.rs`, `fapi_client_auth.rs`, `client_secret_fapi_advanced_kdf.rs`, `engine/tests/fapi2_client_keys.rs`. Fix the ~30 incidental FAPI mentions in other tests
- [ ] 8.7 Delete `docs/guides/fapi2.md`; update `OIDC.md`, `CONFIGURATION.md`, `security-model.md`, `backup.md`, `api-reference.md`, `AGENT_AUTH.md` line 4, README, `STATUS.md`
- [ ] 8.8 CHANGELOG `### Removed` entries

## 9. LDAP and abuse extras (PR 8)

- [ ] 9.1 Red tests: each removed abuse config key stops startup; signup still works without email reputation; login still works without the tarpit; the shaper, detector email shield, agent monitor, device approval and CAPTCHA tests stay green
- [ ] 9.2 Delete `src/identity/ldap/`, `pub mod ldap;`, `ldap3`, `tests/ldap_federation.rs`, the `ldap-integration` CI job, the `ldap` path filter and its required-summary entries
- [ ] 9.3 Delete `src/abuse/ip_reputation/` (and `maxminddb`), `email_reputation.rs` (and its call at `web/handlers.rs:5474`), `bot_signal.rs`, `tarpit.rs`
- [ ] 9.4 Slim `src/abuse/runtime.rs` to the guards with kept users: pre-auth login checks, outbound email caps, `cidr_policy_denies`
- [ ] 9.5 Update docs that mention LDAP or the removed abuse features (`federation.md`, README, `STATUS.md`, `VISION.md`, `TESTING.md`, `ABUSE.md`, both migrating-from guides)
- [ ] 9.6 CHANGELOG `### Removed` entries

## 10. Pre-token webhook default (PR 9)

- [ ] 10.1 Red tests from `specs/pre-token-webhook-failure`: the default fails closed on timeout; explicit `fail_open` still issues the token; reserved claims are dropped
- [ ] 10.2 Change `#[default]` from `FailOpen` to `FailClosed` in `src/identity/types/realm.rs:455–457`
- [ ] 10.3 CHANGELOG `### Changed` entry

## 11. SDKs (PR 10, may split per SDK)

- [ ] 11.1 Port the Node-only features (Next.js helpers, discovery, flows, token, authorize) into `sdks/typescript` with their tests
- [ ] 11.2 Delete `sdks/node`, `sdks/kotlin`, `sdks/rust`, their CI jobs (`sdk-node`, `sdk-kotlin`, `sdk-rust`) and required-summary entries, `sdk-publish-kotlin.yml`, `sdk-publish-rust.yml`, the semantic-release matrix entries, `.releaserc.json` files, Dependabot entries, `security.yml:332`, the Makefile `sdk-lint` lines, and the SDK guides
- [ ] 11.3 For each of TS, Go, Python and PHP: replace handwritten JWT/JWKS verification with the chosen JOSE library, with red tests for an Ed25519 token and a tampered token first
- [ ] 11.4 Generate each admin client from `docs/api/openapi.json`, wrap it, and add a CI staleness check
- [ ] 11.5 Build the shared e2e conformance harness: one scenario set, run against all four SDKs against a live server (extend `make sdk-smoke-local`)
- [ ] 11.6 Update `docs/specs/SDK.md`, `SDK_SURFACE.md`, `sdk-spec.md`, `release-runbook.md`, `ops/RELEASE_VALIDATION.md`, `overview.md`, `getting-started.mdx`
- [ ] 11.7 CHANGELOG `### Removed` (Kotlin, Rust, Node SDKs) and `### Changed` (TS SDK absorbs Node) entries

## 12. Vision and spec cleanup (PR 11)

- [ ] 12.1 Delete the embedded-mode promise: `VISION.md` §6.2 and lines 314, 479, 581, 674; `TESTING.md:36, 236–304` (rewrite as "in-process harness"); `TEST_SCENARIOS.md:45`; `IMPLEMENTATION_ORDER.md:23`; `ARCHITECTURE.md:179`. Leave the token-embedded-permissions uses of "embedded" alone
- [ ] 12.2 Rename `HarnessMode::Embedded` to `HarnessMode::InProcess` and `TestHarness::embedded` to `TestHarness::in_process` (mechanical)
- [ ] 12.3 Re-derive `docs/STATUS.md` from the tree after groups 2–10
- [ ] 12.4 Add a note to `VERSIONING.md`: v3.0.0 removes features without a deprecation window, because there were no production users

## 13. Release v3.0.0

- [ ] 13.1 Run `make test-detached` on the release candidate; the full suite is green
- [ ] 13.2 Compare per-module coverage before and after; the kept modules must not drop
- [ ] 13.3 Cut v3.0.0 with the release-cut procedure in `CLAUDE.md`, and update the README pins
- [ ] 13.4 Declare the feature freeze, and open the follow-up change for the confidence work (external conformance suites, invariant tests across entry points, mutation testing, pentest)
