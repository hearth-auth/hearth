## Context

On 2026-10-01 the owner decided to shrink Hearth to a trusted core before claiming production readiness for enterprise use. `proposal.md` gives the reasons. A read-only footprint survey of the code on `main` (`66e329f3`) found these facts, and the decisions below rely on them:

- LDAP has no operator surface. The only reference is `pub mod ldap;` in `src/identity/mod.rs:23`.
- Both SAML sides share most of the SAML code. The IdP-only parts are `idp.rs`, the IdP handlers in `src/protocol/web/saml.rs` (about lines 446–912), the SP registry, and the IdP SLO use of `logout.rs`.
- The REST layer depends on the proto-generated types. `pb::` appears in `http/oauth.rs`, `http/admin.rs`, `http/auth.rs` and others, and REST JSON goes through `proto_to_rest_json` with `pbjson`. The Raft transport has its own committed code in `src/cluster/generated/` and its own listener.
- The risk scorer is consulted in exactly one place: refresh rotation (`rotate_grant_family`, `engine/mod.rs:4132–4145`). Adaptive MFA (device fingerprints) runs only in the ROPC password grant (`engine/oauth.rs:1401`). Browser login uses neither.
- `abuse/shaper.rs` (the HTTP rate limiter), `detector.rs` (the outbound email volume shield), `agent_monitor.rs`, `device_approval.rs`, `challenge.rs` and `runtime.rs` all have kept dependants.
- `realm.config().mfa_required.unwrap_or(false)` is repeated in at least four places: `web/second_factor.rs:124`, `web/handlers.rs:2669`, `engine/oauth.rs:1389`, and `engine/mod.rs:18971` (which takes a parameter).
- TOTP, recovery codes, SMS and email OTP all set `MfaProof::Proved` (`handlers.rs:1010, 1084, 3110, 3470`).
- No organization-level MFA setting exists.
- The pre-token webhook `on_error` defaults to `FailOpen` (`types/realm.rs:455–457`).
- The Auth0 and Keycloak importers are reachable only through the `hearth migrate` CLI subcommand. They have no HTTP route.

## Goals / Non-Goals

**Goals:**
- Remove each listed feature completely: code, config keys, routes, discovery fields, tests, docs, CI jobs and dependencies.
- Make each removal fail loud. A removed config key stops startup with a message that names the key and the release that removed it.
- Fix the MFA policy in one place, so no call site can choose its own default.
- Ship everything in v3.0.0.

**Non-Goals:**
- Fixing Raft. It is kept as is and stays experimental. The Jepsen-driven work is a separate change.
- Replacing the proto types in the REST layer with handwritten DTOs.
- Moving the importers into a separate binary. They are already offline-only (see decision 7).
- The confidence work that follows the freeze (conformance suites, invariant tests, mutation testing, pentest).

## Decisions

### 1. One PR per removal group, in risk order
Order: SAML IdP → public gRPC → MFA policy, risk scoring and SMS (login-path branches) → FAPI/JARM → LDAP, abuse extras → SDKs → docs and the vision cleanup.
**Why:** each PR stays reviewable, and the biggest attack surface goes first. A revert stays small.
**Alternative:** one large PR. Rejected because nobody could review it, and the CodeQL "new alerts" check counts every touched file.

### 2. Removed config keys fail startup
The config structs already use `deny_unknown_fields`, so a deleted field turns into a generic "unknown field" error. We add a small table of removed keys (key path → removed-in version → replacement or "none"). The parse error is rewritten to name the removed feature.
**Why:** an operator who upgrades with `sms:` in `hearth.yaml` must learn that SMS is gone, not just that a field is unknown.
**Alternative:** ignore removed keys with a warning. Rejected: a silent no-op on a security setting is the fail-open class this project keeps fixing.

### 3. Keep `proto/` as the REST schema source; delete only the gRPC server
The REST layer serialises through the proto types, so `proto/hearth/{identity,rbac,events}/v1` stay as message definitions. The `service` blocks with their `google.api.http` annotations are removed. `docs/api/openapi.json` keeps being derived from them through `scripts/merge_openapi.py` until that pipeline is rewritten.
**Why:** rewriting the REST DTOs is large and has nothing to do with the attack surface. Without a listener, the proto messages expose nothing.
**Check:** the OpenAPI derivation currently reads the `google.api.http` annotations. If removing the services breaks it, keep the `service` blocks as schema-only (nothing compiles a server from them) and record that in `PROTO.md`. Decide this in the gRPC PR, using the generated diff.

### 4. One MFA policy resolver
Add one function, `effective_mfa_requirement(realm, org, client, user_roles) -> MfaRequirement`, in the identity layer. Every site that today calls `mfa_required.unwrap_or(false)` calls the resolver instead. A clippy `disallowed-methods` entry or a `scripts/` lint fails CI on a new direct read of `mfa_required`.
- **Default:** `required`, when neither the realm nor the global `auth.mfa_required` is set.
- **Org tightening:** a new organization field `mfa_required: bool` (default `false`). The result is the logical OR of realm, org, client and role requirements. An org can only add a requirement.
- **Qualifying factors:** `MfaProof::satisfies_mfa_required` accepts only proofs from WebAuthn, TOTP or a recovery code. Email OTP gets its own proof variant (`ProvedEmailOtp` or similar). It still works as a step in flows that ask for it, but it does not satisfy `mfa_required`.
- **Turning it off:** `auth.mfa_required: false` is accepted. Startup logs a `WARN` that names each realm with MFA off. The admin console shows a persistent warning banner on that realm. The audit log records every change of the effective value, including the change at startup reconcile.

**Why:** the "handler hand-rolls a shared guard" bug class appears in all three audits. One resolver plus a CI lint closes it structurally.

### 5. The SAML SP profile is enforced before signature verification
The parser rejects a document that has a DTD or a `DOCTYPE`, more than one `Assertion`, or more than one `ds:Signature` in the signed scope. It verifies the one signature, and then it reads attributes only from the element the signature references, found by ID through the verified reference. An external XSW corpus runs in CI.
**Why:** signature wrapping lives in the gap between "the signature is valid" and "the data I read is the data that was signed". The strict profile removes the ambiguity before any crypto runs.

### 6. No stored-data compatibility code
The export stops writing `saml_service_providers.ndjson`, and the importer treats it like any unknown member: a hard error. The same holds for storage fields, enum variants and audit actions of removed features: they are deleted, with no reader for older data.
**Why:** Hearth has no deployments (owner, 2026-10-02: "we have no users at all"), so a compatibility reader protects nothing and is code to maintain. Changed during apply; groups 2 and 7 first shipped such readers and a follow-up removed them.

### 7. The importers stay in the `hearth migrate` subcommand
The survey shows they are already offline-only: there is no HTTP route. A separate binary would add release work and remove no attack surface.
**Alternative:** a `hearth-migrate` crate in the workspace. Defer it until more importers exist and compile time matters.

### 8. Remove the ROPC grant, and give tests their own token helper
The ROPC grant goes, including its adaptive-MFA code. 27 test calls in 6 files use `password_grant_token` as a quick way to get a user token in-process. They switch to a token helper behind the existing `test-hooks` feature, or to the authorization-code flow through `TestHarness`. The helper MUST NOT compile into a production build. `make test-no-dev-endpoints` proves that.
**Why:** OAuth 2.1 drops ROPC. It hands the user's password to the client, it skips the browser MFA and required-action flows, and it already produced one bypass (`tests/required_actions_ropc_bypass.rs`).

### 9. Keep the client `jwks` field
`jwks` verifies `private_key_jwt` client assertions (`src/identity/client_auth.rs`) and signed request objects (`verify_jar`). Both features stay, so the field stays. Only its "Required with `profile: fapi2`" doc line goes.

### 10. SDKs: a rich API, borrowed crypto
Each supported SDK validates tokens through a widely used JOSE library that supports EdDSA/Ed25519: TS `jose`, Go `go-jose` or `jwx`, Python `joserfc` or `PyJWT[crypto]`, PHP `web-token/jwt-framework`. The admin client is generated from `docs/api/openapi.json`, and a handwritten ergonomic layer wraps it. Only the Hearth-specific parts are handwritten: DPoP proof creation, agent flows, and the session-version cache.
**Why:** the developer still writes very little code, and the risky code lives in libraries that thousands of projects already test.

## Risks / Trade-offs

- [The FAPI removal drops a call that some kept path relies on to require DPoP] → Before deleting `require_fapi_sender_constraint`, list every caller and check that client-level `dpop_bound_access_tokens` and agent-level DPoP-required are enforced by `dpop.rs` alone. A red test per caller comes first: device grant, auth-code exchange, client credentials, JWT bearer, refresh, step-up.
- [Removing `.jwt` response modes breaks web flows that share code with JARM (`authorize_gate.rs`, `oauth_consent.rs`, `sms_challenge.rs`)] → The plain `query`/`fragment`/`form_post` flows are each covered by an existing test, which must stay green.
- [Email OTP stops counting as MFA, so a dev realm that relies on it locks out password users] → Greenfield (no users). The bootstrap admin enrols TOTP or a passkey. The CHANGELOG entry says so plainly.
- [MFA required by default makes every new dev realm demand enrolment] → Owner decision (2026-10-01): `--dev` keeps the production default. `/admin/bootstrap` and the quick start describe the enrolment step.
- [Raft experimental and MFA default together: followers must agree on the resolver] → The resolver reads replicated config only. A cluster test asserts the same decision on leader and follower.
- [The deprecation policy in `VERSIONING.md` asks for a deprecation window before a breaking removal] → The owner has decided to remove outright, because there are zero users. The v3.0.0 CHANGELOG states this, and `VERSIONING.md` gets a one-line note on why this release has no deprecation window.
- [Deleting about 60 test files lowers the coverage figure] → Expected. Coverage on the remaining code must not fall. Compare per-module coverage before and after.

## Migration Plan

1. Land the PRs in the order from decision 1. Each must be green on `make check`, `make test-quality`, `make test-no-dev-endpoints` and `make ci-local-fast`.
2. Collect the CHANGELOG entries under `## [Unreleased]` → `### Removed` / `### Changed` / `### Security`.
3. Cut v3.0.0 with the normal release-cut procedure. Update the README pins.
4. Rollback: revert the offending PR. Every removal is code-only. Only the backup format changes, and decision 6 keeps v3 able to read old archives.

## Open Questions

None. The owner settled the ROPC, `jwks` and `--dev` questions on 2026-10-01.
