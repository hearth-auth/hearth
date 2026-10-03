Each numbered group ships as one PR, in this order (design decision 1). Each PR passes `make check`, `make test-quality`, `make test-no-dev-endpoints` and `make ci-local-fast` before you push. Each PR adds its own `CHANGELOG.md` entries under `## [Unreleased]`. Red tests come first (TDD).

## 1. Shared groundwork

- [x] 1.1 Write red tests for the removed-key check. **Changed during apply:** `sms:` and `server.grpc_port` are still valid keys until groups 4 and 6 remove them, so the group 1 tests run against a fixture table (`src/config/removed.rs` tests). Each removal group adds its keys to `REMOVED_KEYS` with its own integration test through both parse paths
- [x] 1.2 Add the removed-key table in `src/config/` and rewrite the `deny_unknown_fields` parse error through it. Each later group adds its own keys to the table
- [x] 1.3 Add a black-box helper (`tests/common/routes.rs`, `assert_route_absent` over the composed router, self-tested in `tests/route_absence_helper.rs`) that asserts a route answers `404` like an unknown path. Later groups use it

## 2. SAML IdP side (PR 1)

- [x] 2.1 Red tests: the six IdP routes answer `404`; `realms.<name>.saml_service_providers` stops startup; a v2 archive with `saml_service_providers.ndjson` restores with one warning
- [x] 2.2 Green-before-delete guard: confirm the SP-side tests pass. `tests/saml.rs` was already SP-side apart from two IdP tests, so it became `tests/saml_sp.rs`; the IdP tests left `tests/saml_web_hardening.rs`. `sign_element`, `build_response_xml` and `ResponseBuilder` stay in the library as fixtures the SP tests use to play the upstream IdP — no route reaches them
- [x] 2.3 Delete `src/identity/federation/saml/idp.rs`, the IdP handlers in `src/protocol/web/saml.rs` (`idp_metadata`, `idp_sso_get/post`, `idp_complete_sso`, `idp_sso_init`, `idp_slo_get/post`, `idp_complete_slo`, `reject_session_realm_mismatch`, `asserted_attributes`) and their routes in `src/protocol/web/mod.rs:1243–1266`
- [x] 2.4 Delete the SP registry: the engine trait methods (`identity/mod.rs:2254–2281`, the caller-less `record/list_saml_sp_session*`), the engine impl, the `saml:sp:` storage keys, `reconcile_saml_sps_for_realm`, `SamlServiceProviderYaml` and its validation
- [x] 2.5 Delete the IdP-only SAML library code: all of `logout.rs` (the SP-side SLO builders were never wired either), `build_idp_metadata`, `parse_authn_request`, the inbound Redirect decoder and the POST-binding page builder, the logout state keys, and the `UnknownSp` error
- [x] 2.6 Backup: stop exporting `saml_service_providers.ndjson`; make the importer skip it with a warning (`backup/export.rs`, `import.rs`, `types.rs`, `main.rs:5429`) **Changed during apply (follow-up):** the skip was removed again — Hearth has no deployments, so the importer treats the member as unknown (hard error); see design decision 6
- [x] 2.7 Update `docs/specs/SAML.md`, `federation.md`, `backup.md`, `security-hardening.md`, `error-codes.md`, `CONFIGURATION.md`, the hearth-yaml examples and README
- [x] 2.8 CHANGELOG `### Removed` entry for the SAML IdP side

## 3. SAML SP strict profile (PR 2)

- [x] 3.1 Red tests from `specs/saml-sp-profile`: DOCTYPE, two assertions, two signatures, and a wrapped-copy XSW case that names a different user
- [x] 3.2 Enforce the structural checks before signature verification. DOCTYPE and the one-assertion count already existed; added `check_signature_placement` (`saml/xml.rs`), called from `SamlSpService::complete_inner`
- [x] 3.3 Read the subject and attributes only from the element the verified reference identifies — already true: exactly one assertion in the document, and its ID must equal the verified ID. Covered by the XSW tests
- [x] 3.4 XSW corpus. **Changed during apply:** no maintained, vendorable corpus exists, so `tests/saml_sp.rs` generates XSW1–XSW8 (Somorovsky et al. 2012) from a real signed document; it runs in the normal CI suite
- [x] 3.5 CHANGELOG `### Security` entry

## 4. REST parity for the gRPC-only admin operations (PR 3, added during apply)

Sixteen admin operations existed only over gRPC (`docs/api/grpc-only.txt`; `ClientCredentials` is already `POST /token`). Removing gRPC without them would drop programmatic organization management, which B2B customers need. Owner decision 2026-10-01: port all of them before the removal.

- [x] 4.1 Map each gRPC handler's authorization steps (admin claim, realm binding, system-realm rules, admin privilege ceiling, suspension and YAML-managed refusals) and its tests
- [x] 4.2 Red tests through REST for organization CRUD (`/admin/organizations`, `/admin/organizations/{id}`), porting every authz assertion of the gRPC tests
- [x] 4.3 Implement organization CRUD over REST, reusing the engine and the shared ceiling helpers
- [x] 4.4 Red tests, then REST routes, for group roles, role members, direct user permissions, extra org roles, realm permissions and roles listing
- [x] 4.5 Red test, then REST route, for audit integrity verification
- [x] 4.6 Document every new route in `docs/api/openapi.supplement.yaml`, run `make openapi`, and empty `docs/api/grpc-only.txt` (only the unrelated `ClientCredentials` line remains; the file goes with gRPC in group 5). `tests/openapi.rs`'s gate that forbade `/admin/organizations` now requires every new route instead
- [x] 4.7 CHANGELOG `### Added` entry

## 5. Public gRPC (PR 4)

- [x] 5.1 Red tests: a single-node server listens only on the HTTP port; each `grpc_*` key and `security.grpc` stops startup; a 3-node cluster still elects a leader and replicates
- [x] 5.2 Delete `src/protocol/grpc/`, the startup wiring (`main.rs:1836`, `3248–3280`), the config keys, the `shaper.rs` gRPC interceptor and `examples/grpc-admin-flow`
- [x] 5.3 Drop `tonic-health`, `tonic-reflection` and the unused `tonic-types` from `Cargo.toml`. Keep `tonic`, `tonic-prost`, `prost`, `pbjson` and `pbjson-types`
- [x] 5.4 Remove the `service` blocks from `proto/hearth/{identity,rbac,events}/v1`. Regenerate `openapi.proto-derived.json` and diff `docs/api/openapi.json`. If the REST paths disappear, keep the `service` blocks as schema-only and document that in `PROTO.md` (design decision 3) — **Kept the `service` blocks** as the REST schema (design decision 3): `openapi.json` is merged from a committed file and `buf generate` output is unchanged, so removing them gained nothing. `build.rs` now generates no server or client stubs (`build_server(false)`, `build_client(false)`); `docs/specs/PROTO.md` documents this
- [x] 5.5 Delete the ~13 gRPC-only test files. Port any assertion that guards REST behaviour into a REST test first — 127 gRPC tests audited: 27 guarded shared behaviour and were ported to REST (new: `rest_sub_admin_bfla.rs`, `rest_audit_admin.rs`, `rest_org_suspension.rs`, `ga3_realm_trust_policy_rest.rs`, `ga3_realm_yaml_managed_rest.rs`, `tls_config_hardening.rs`; plus in-place REST ports in mixed files). The port of `grpc_org_suspension.rs` exposed a REST bug — `GET /admin/users/{id}/effective-permissions?org_id=` reported a suspended org's permissions — fixed by routing it (and `/v1/me/permissions`) through `active_org_context`
- [x] 5.6 Update `buf.gen.yaml`, the Makefile `proto-gen`/`proto-check` targets, `.githooks/pre-commit`, and the `proto-freshness`/`proto-governance` CI jobs to match — the protos are unchanged, so `buf.gen.yaml`, the `proto-*` targets, the pre-commit hook and the proto CI jobs need no change. `scripts/check-auth-discard.sh` now scans `src/protocol/http/admin/*.rs` instead of the deleted gRPC module
- [x] 5.7 Update `docs/specs/PROTO.md`, `docs/api/grpc-only.txt` (delete), `api-reference.md`, `admin-api.md`, `CONFIGURATION.md`, `ARCHITECTURE.md`, `clustering.md`
- [x] 5.8 CHANGELOG `### Removed` entry for public gRPC

## 6. MFA policy (PR 5)

**Changed during apply:** groups 7 and 8 run before this group. They delete sign-in paths (SMS OTP, adaptive MFA in the password grant, the password grant itself) that the resolver would otherwise have to cover. Two owner/apply decisions (2026-10-02): (1) the "required by default" lives where a server builds a realm's config — YAML conversion, the system realm at startup, the bootstrap dev realm — which record an explicit `mfa_required`; a realm created in-process with no value (tests only; `POST /admin/realms` is 405) reads as not required. Flipping the engine default instead broke 1,003 of 6,074 tests that never set the key. (2) `/admin/bootstrap` enrols TOTP for both dev admins, returns each secret once with the password, and mints its API tokens after verifying a code from that secret.

- [x] 6.1 Red tests from `specs/mfa-policy`: the default is required; the explicit opt-out is honoured; email OTP and magic link do not satisfy MFA; a passkey alone does; org tightening; org cannot loosen; the startup `WARN`; the console banner; an audit event on change
- [x] 6.2 Add `effective_mfa_requirement(...)` in the identity layer, and route every `mfa_required.unwrap_or(...)` site through it (`web/second_factor.rs:124`, `web/handlers.rs:2669`, `engine/oauth.rs:1389`, `engine/mod.rs:18971`, plus any others a search finds)
- [x] 6.3 Add the CI lint (clippy `disallowed-methods` or a `scripts/` check) that fails on a direct read of `mfa_required` outside the resolver, with a red self-test
- [x] 6.4 Split the email OTP proof from `MfaProof::Proved`, and make `satisfies_mfa_required` accept only WebAuthn, TOTP and recovery-code proofs
- [x] 6.5 Add `mfa_required` to organizations (storage, admin REST, console, SCIM-created orgs default `false`), and feed it to the resolver
- [x] 6.6 Add the startup `WARN`, the console warning banner (follow `docs/specs/THEME.md`), and the audit events
- [x] 6.7 Keep the production default under `--dev` (owner decision). Make `/admin/bootstrap` and the quick start in `CLAUDE.md` and README describe the enrolment step for the dev admin. Update `make dev`-based scripts (`make sdk-smoke-local`, UI smoke, `make seed`) that sign in as the dev admin
- [x] 6.8 A cluster test: the leader and a follower reach the same MFA decision for the same user
- [x] 6.9 CHANGELOG `### Changed` (default required, email OTP no longer MFA) and `### Added` (org MFA) entries

**Changed during apply (6.1–6.9):**
- Tests: `tests/mfa_policy.rs` (default, opt-out, startup listing, audit, system realm, bootstrap, strong factors, org tighten/no-loosen/audit/SCIM, the lint self-test, the `mfa_methods` rule), `tests/web_ui_admin.rs` (console banner), `tests/cluster_three_node_control_coherence.rs` (6.8), and web cases in `mfa_login_and_gate_regressions`, `mfa_otp_second_factor_login`, `required_action_mfa_proof`. The startup `WARN` text itself is not asserted; `realms_with_mfa_off` (which feeds it) is. The 6.8 cluster test passed on first run (the resolver reads replicated storage only).
- 6.2: the resolver is `IdentityEngine::effective_mfa_requirement(realm, user, client)`; `realm_requires_mfa(config)` is the realm-only input. `mfa_required_roles` now binds at `create_session` too (it was web-layer only); `conditional_mfa` was flipped accordingly. The realm requirement now also injects `ENROLL_MFA`, which lets a user with no qualifying factor enrol a passkey or TOTP — this is how a password + email OTP sign-in reaches a qualifying factor.
- 6.3: `scripts/check-mfa-resolver.sh` (`make mfa-resolver-check`, CI lint job, `ci-local-fast`). Marker `// mfa-resolver-ok: <reason>` on the line or the line above (rustfmt moves trailing comments). The config loader, reconcile, the backup importer and the admin settings editors are exempt.
- 6.4: new `MfaProof::EmailOtp` (satisfies neither policy, proves the held email-OTP factor) and `FirstFactor::VerifiedPasskey` (a passkey with UV, then an email OTP, keeps `ProvedWebAuthn`). Where MFA is required a held passkey is asked before email OTP, and after a UV-less passkey only TOTP can finish. Added a config rule: a realm that requires MFA must offer `totp` or `webauthn` in `mfa_methods`.
- 6.5: org REST `PATCH` now starts from the stored config, so a field the body omits is kept (before, `member_limit` alone reset the whole config).
- 6.6: the system realm always requires MFA (startup writes it, audited); the old HSEC-004 checks are gone.
- 6.7: found by a live run and fixed with tests: the inline TOTP form on the login page carried no CSRF token, so the first code was refused with 422; an unverified account reached forced enrolment and failed with 500 — it now gets the verify-your-email page first. The Playwright fixture signs in with TOTP (`tests/ui/fixtures/totp.ts`, `nextTotp` avoids the code bootstrap spent); `make ui-test-smoke` and `make sdk-smoke-local` pass on a fresh server. The load-test login plane still measures the Argon2id path; its sign-ins now stop at the second factor.

## 7. Risk scoring, adaptive MFA and SMS OTP (PR 6)

- [x] 7.1 Red tests: `security.risk_scorer` and `sms:` stop startup; the SMS routes and `/admin/users/{id}/device-fingerprints` answer `404`; refresh rotation works with no scorer; `mfa_methods: ["sms"]` is rejected (`tests/abuse_risk_and_sms_removed.rs`; it also carries the A-11 and A-49 IDs for the abuse coverage gate)
- [x] 7.2 Delete `src/abuse/risk_scorer.rs`, `src/identity/risk.rs`, `device_fp.rs`, `device_fingerprint.rs`, the realm `adaptive_mfa` and `risk_scorer_config` fields, the call at `engine/mod.rs:4132–4145`, the step-up recording (`engine/oauth.rs:1564`), the sweeper (`main.rs:2286`), the admin route and the `DeviceFingerprintsErased` audit action
- [x] 7.3 Delete `src/identity/sms/`, `src/protocol/web/sms_challenge.rs`, `RequiredAction::EnrollPhoneOtp` and its required-action code, the SMS config keys, `HEARTH_SMS_OTP_HMAC_KEY`, the realm `sms_otp_*` fields, the `sms_*` volume-shield settings, `check_outbound_sms`, and the SMS paths in `abuse/detector.rs` **Changed during apply:** (a) the OTP primitives in `sms/otp.rs` are shared by email OTP, so they moved to `src/identity/otp.rs`; (b) **follow-up:** the storage shims first added for old user records and audit events were removed again (no deployments, design decision 6); (c) the email OTP key no longer mixes in `HEARTH_SMS_OTP_HMAC_KEY`; it derives from the cookie secret only, like the login cookie it is bound to
- [x] 7.4 Delete the risk, device-fingerprint and SMS test files listed in the footprint survey. **Changed during apply:** tests of kept behaviour that used SMS as a vehicle were ported, not deleted: `tests/mfa_login_and_gate_regressions.rs` (from `sms_mfa_fail_closed.rs`), `tests/required_action_ra_cookie_forgery.rs`, `tests/abuse_challenge_store.rs` (A-16, A-48) and `tests/abuse_federation_state_binding.rs` (A-48); the `authorize_gate_parity.rs` resume tests now run through a required action
- [x] 7.5 Delete `docs/guides/sms-mfa-deployment.md`; update `required-actions.md`, `CONFIGURATION.md`, `ABUSE.md`, `privacy.md`, `concepts.md`
- [x] 7.6 CHANGELOG `### Removed` entries

## 8. ROPC password grant (PR 7)

- [x] 8.1 Red tests: `grant_type=password` answers `400 unsupported_grant_type` for a public and a confidential client; discovery `grant_types_supported` has no `password`; DCR refuses `password` in `grant_types`; a config client listing `password` stops startup with a named error **Changed during apply:** both token endpoints already refused the grant since HEA-1862, and config already refused it. `tests/ropc_removed.rs` adds a confidential client on both endpoints, discovery, and registration. It found two defects, both fixed: the realm token endpoint answered `{"error":"unsupported grant_type: password"}` (not the RFC code, and echoing input), and `POST /register` (and the engine) accepted `password` in `grant_types`
- [x] 8.2 Add a token helper for tests behind the `test-hooks` feature (or use the authorization-code flow via `TestHarness`), and move the 27 `password_grant_token` test calls in 6 files to it. Prove with `make test-no-dev-endpoints` that the helper is absent from a production build **Changed during apply:** `create_session` + `issue_tokens` are on the public trait, so the helper is `tests/common::user_token_pair`, in the test tree; no `test-hooks` code is needed and nothing reaches a production build. Only 7 test files called the method; ROPC-behaviour tests were deleted, token-acquisition ones moved to the helper
- [x] 8.3 Delete `password_grant_token`/`password_grant_token_inner`, `PasswordGrantRequest`, the `grant_type=password` dispatch in `src/protocol/http/oauth.rs`, the adaptive-MFA check and recording at `engine/oauth.rs:1401` and `1464`, and the ROPC grant-type gate **Changed during apply:** there was no `grant_type=password` dispatch left to delete. `PasswordGrantResponse` stays: the step-up MFA grant returns it
- [x] 8.4 Delete `tests/ropc_grant_type_gate.rs` and `tests/required_actions_ropc_bypass.rs`, after porting any assertion that guards a kept path **Changed during apply:** `ropc_grant_type_gate.rs` is kept: it is the HTTP refusal test this group's spec asks for; its opt-in test now proves a client cannot be registered or updated for `password`. `required_actions_ropc_bypass.rs` is deleted; the step-up grant's own required-action gate is tested in `login_paths_enforce_policy.rs`
- [x] 8.5 Update `OIDC.md`, `CONFIGURATION.md`, `api-reference.md`, `docs/api/openapi.json` and any guide that shows `grant_type=password` **Changed during apply:** the specs were already clean; fixed `concepts.md` and `examples/large-scale-demo/hearth-tier-miss.yaml`, which listed `password` and so could not boot
- [x] 8.6 CHANGELOG `### Removed` entry
- [x] 8.7 (Added during apply, owner decision 2026-10-02) Remove the step-up MFA grant (`urn:hearth:params:grant-type:step-up-mfa`): red test that both token endpoints answer `unsupported_grant_type`; delete the dispatch arms, `step_up_mfa_grant_token`, `StepUpMfaGrantRequest`, `PasswordGrantResponse`, the dead `StepUpChallengeRequired` error; port tests of kept behaviour; docs; CHANGELOG. Without ROPC nothing sends a client to it, it puts the user's password in the app, and it cannot use passkeys

## 9. JARM and the FAPI 2.0 profile (PR 8)

- [x] 9.1 Red tests: a DPoP-required client or agent with no `DPoP` proof is refused on each grant (auth code, client credentials, refresh, JWT bearer, device code) without any FAPI profile; discovery has no JARM or FAPI fields; `fapi_profile` and `profile: fapi2` stop startup; `response_mode=query.jwt` is refused as unsupported **Changed during apply:** `tests/fapi_jarm_removed.rs`. No agent-level DPoP-required setting exists, so the flag is client-level only; the other grants are covered in `tests/dpop_bound_client.rs` (task 9.6)
- [x] 9.2 Check whether `dpop.rs` enforces DPoP-required on its own. **Changed during apply:** it does not — no client or agent setting requires DPoP outside FAPI. Owner decision 2026-10-02: add the RFC 9449 §5.2 client metadata `dpop_bound_access_tokens` (hearth.yaml, admin API, dynamic registration) and enforce it in the gate that replaces `require_fapi_sender_constraint`. If any grant relied on `require_fapi_sender_constraint`, move that check into the DPoP path first
- [x] 9.3 Delete `require_fapi_sender_constraint` and its call sites, `FapiProfile`, `ClientProfile::Fapi2`, the FAPI authorize gate, the FAPI-only PAR checks, the secret refusals, `check_fapi2_client_keys`, `realm_enforces_fapi`/`refuse_rs256_under_fapi`, the FAPI DCR rules, `IdentityError::FapiViolation` **Changed during apply:** the gate is now `require_dpop_for_bound_client`, refusing with `InvalidDPopProof`. Also removed: `IdentityError::FapiViolation` and `PrivateKeyJwtRequired` (no producer left), and `via_par`, which only the FAPI PAR rule read
- [x] 9.4 Delete JARM: the `*.jwt` `ResponseMode` variants, `JarmClaims`/`JarmErrorClaims`, `new_jarm`/`jarm_jwt`, `sign_jarm_error_jwt`, `authorization_signed_response_alg`, and the JARM branches in `authorize_gate.rs` and `oauth_consent.rs` **Changed during apply:** `ResponseMode` is `query` | `fragment`; discovery `response_modes_supported` dropped the JARM modes
- [x] 9.5 Keep the client `jwks` field (used by `private_key_jwt` and JAR, design decision 9); delete only its "Required with `profile: fapi2`" doc line
- [ ] 9.6 Delete `fapi_conformance.rs`, `fapi2_conformance.rs`, `jarm.rs`, `fapi_client_auth.rs`, `client_secret_fapi_advanced_kdf.rs`, `engine/tests/fapi2_client_keys.rs`. Fix the ~30 incidental FAPI mentions in other tests
- [x] 9.7 Delete `docs/guides/fapi2.md`; update `OIDC.md`, `CONFIGURATION.md`, `security-model.md`, `backup.md`, `api-reference.md`, `AGENT_AUTH.md` line 4, README, `STATUS.md`
- [x] 9.8 CHANGELOG `### Removed` entries

## 10. LDAP and abuse extras (PR 9)

- [x] 10.1 Red tests: each removed abuse config key stops startup; signup still works without email reputation; login still works without the tarpit; the shaper, detector email shield, agent monitor, device approval and CAPTCHA tests stay green **Changed during apply:** `tests/abuse_extras_removed.rs` (carries A-17 for the coverage gate); signup and login keep their own suites
- [x] 10.2 Delete `src/identity/ldap/`, `pub mod ldap;`, `ldap3`, `tests/ldap_federation.rs`, the `ldap-integration` CI job, the `ldap` path filter and its required-summary entries **Changed during apply:** the LDAP module was never wired to config or login, so nothing else depended on it
- [x] 10.3 Delete `src/abuse/ip_reputation/` (and `maxminddb`), `email_reputation.rs` (and its call at `web/handlers.rs:5474`), `bot_signal.rs`, `tarpit.rs`
- [x] 10.4 Slim `src/abuse/runtime.rs` to the guards with kept users: pre-auth login checks, outbound email caps, `cidr_policy_denies`
- [x] 10.5 Update docs that mention LDAP or the removed abuse features (`federation.md`, README, `STATUS.md`, `VISION.md`, `TESTING.md`, `ABUSE.md`, both migrating-from guides)
- [x] 10.6 CHANGELOG `### Removed` entries

## 11. Pre-token webhook default (PR 10)

- [x] 11.1 Red tests from `specs/pre-token-webhook-failure`: the default fails closed on timeout; explicit `fail_open` still issues the token; reserved claims are dropped
- [x] 11.2 Change `#[default]` from `FailOpen` to `FailClosed` in `src/identity/types/realm.rs:455–457`
- [x] 11.3 CHANGELOG `### Changed` entry

**Changed during apply:** the reserved-claims test now also sends `aud` and `roles`; both were already dropped. The webhook has no YAML or admin-API surface (it is set in-process only), so the change is the type's `Default` and serde default; `docs/specs/CONFIGURATION.md` is updated.

## 12. SDKs (PR 11, may split per SDK)

- [x] 12.1 Port the Node-only features (Next.js helpers, discovery, flows, token, authorize) into `sdks/typescript` with their tests **Changed during apply:** ported by subagent into `HearthClient`, `Claims`, `middleware.ts` (`hearthMiddleware`, `hearthFastifyHook`, shared `authenticateRequest`) and `src/nextjs/` (subpath exports `./nextjs`, `./nextjs/edge`); TS tests 193 → 317. Node names kept where possible; `VerifiedToken` → `Claims`, `getHearthToken` → `getHearthClaims`; `generatePkce`, `EdgeToken` and the edge `requirePermission` dropped (existing TS equivalents). `mePermissions`/`svSnapshot`/`svDelta` now send `X-Realm-ID` (the Node SDK never did, and the server answers 400 without it)
- [x] 12.2 Delete `sdks/node`, `sdks/kotlin`, `sdks/rust`, their CI jobs (`sdk-node`, `sdk-kotlin`, `sdk-rust`) and required-summary entries, `sdk-publish-kotlin.yml`, `sdk-publish-rust.yml`, the semantic-release matrix entries, `.releaserc.json` files, Dependabot entries, `security.yml:332`, the Makefile `sdk-lint` lines, and the SDK guides **Changed during apply:** Dependabot's npm entry moved to `/sdks/typescript` rather than being dropped; the `rsa` OSV/SECURITY.md exception (Rust SDK lockfile only) removed; `scripts/check-sdk-conformance.sh` checked `rust` but never `php` and only warned on a missing SDK directory — it now checks the four supported SDKs, accepts PHP `...Exception` names (SDK.md §5), and fails on a missing directory
- [x] 12.3 **Changed during apply (owner decision, 2026-10-02):** the JOSE-library rewrite (old 12.3), the OpenAPI-generated admin clients (old 12.4) and the shared conformance harness (old 12.5) moved to the follow-up change `openspec/changes/sdk-standard-libraries/`, together with their three `sdk-support-contract` requirements. This task is done when that change exists and validates (`openspec validate sdk-standard-libraries`). Task 14.5 checks it is still open at release
- [x] 12.6 Update `docs/specs/SDK.md`, `SDK_SURFACE.md`, `sdk-spec.md`, `release-runbook.md`, `ops/RELEASE_VALIDATION.md`, `overview.md`, `getting-started.mdx`. **Changed during apply:** the Node guides became `sdks/typescript.md` (server-side section) and a new `sdks/typescript-nextjs.md`; also updated `permission-delivery.mdx`, `rbac.mdx`, `organizations.mdx`, `STATUS.md`, `VISION.md`, `ARCHITECTURE.md` and the docs-site navigation and landing page. The Rust and Kotlin tabs in `webhooks.mdx` stay: they are plain HMAC-check code with no SDK
- [x] 12.7 CHANGELOG `### Removed` (Kotlin, Rust, Node SDKs) and `### Changed` (TS SDK absorbs Node) entries

## 13. Vision and spec cleanup (PR 12)

- [x] 13.1 Delete the embedded-mode promise: `VISION.md` §6.2 and lines 314, 479, 581, 674; `TESTING.md:36, 236–304` (rewrite as "in-process harness"); `TEST_SCENARIOS.md:45`; `IMPLEMENTATION_ORDER.md:23`; `ARCHITECTURE.md:179`. Leave the token-embedded-permissions uses of "embedded" alone **Changed during apply:** VISION §6.2 now states the one deployment mode (server) and that the in-process harness is a test tool; `ARCHITECTURE.md:693` no longer says embedded mode may come later
- [x] 13.2 Rename `HarnessMode::InProcess` to `HarnessMode::InProcess` and `TestHarness::in_process` to `TestHarness::in_process` (mechanical) **Changed during apply:** also renamed the `embedded_with_*` constructors to `in_process_with_*` and the harness wording in test comments and `expect` messages; `Embedded*Engine` types keep their names (they are the engine). 6,095/6,095 tests pass
- [x] 13.3 Re-derive `docs/STATUS.md` from the tree after groups 2–10 (against `3e382f87`; every ✅ row names a path that exists)
- [x] 13.4 Add a note to `VERSIONING.md`: v3.0.0 removes features without a deprecation window, because there were no production users **Changed during apply:** also replaced the stale "gRPC API" section (public gRPC is gone; proto messages follow the REST rules) and dropped Kotlin/Node from the annotation list
- [x] 13.5 **Added during apply:** stale public-gRPC comments under `src/` rewritten (53 comments, 20 files); dead code the gRPC API alone used deleted (`AppState::with_shared_rate_limiter`, and the `From<pb::TokenRevocationRequest>` / `From<pb::TokenIntrospectionRequest>` conversions, which defaulted the authenticated client to `None`); `admin-api.md`, `organizations.mdx`, `SDK.md` and `SDK_SURFACE.md` corrected to the real `/admin/organizations` routes and fields (SDK support moved to `sdk-standard-libraries` task 3.2)

## 14. Release v3.0.0

- [ ] 14.1 Run `make test-detached` on the release candidate; the full suite is green
- [ ] 14.2 Compare per-module coverage before and after; the kept modules must not drop
- [ ] 14.3 Cut v3.0.0 with the release-cut procedure in `CLAUDE.md`, and update the README pins
- [ ] 14.4 Declare the feature freeze, and open the follow-up change for the confidence work (external conformance suites, invariant tests across entry points, mutation testing, pentest)
- [ ] 14.5 Before tagging, confirm `openspec/changes/sdk-standard-libraries/` is still an open change (not deleted, not archived unimplemented), and list it in the v3.0.0 release notes as the next SDK work
