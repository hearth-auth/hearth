## Why

Three internal audit rounds each found new Critical or High bugs. Most of them sat on the joins between features: SAML × federation, MFA × alternate login paths, SCIM × authorization, cluster followers × caches. Hearth has about 267,000 lines in `src/` and 7 SDKs. That surface is too large to make trustworthy, and every feature multiplies the paths that each security invariant must hold on. Hearth has zero production users today, so shrinking it now costs nothing in migrations. Later, every removal would break someone.

This change shrinks Hearth to a **trusted core**. Then we freeze features and start the confidence work: external conformance suites, invariant tests across all entry points, mutation testing, an external pentest.

## What Changes

**Removals (all BREAKING; ship in v3.0.0):**
- **BREAKING** Remove LDAP / Active Directory federation (`src/identity/ldap/`, the `ldap3` crate, the `ldap-integration` CI job). It was never wired to an operator surface.
- **BREAKING** Remove the SAML **IdP side**: the `/ui/realms/{realm}/saml/{metadata,sso,sso/init,slo-idp}` routes, `realms.<name>.saml_service_providers`, the SP registry and its storage keys, and its backup file `saml_service_providers.ndjson`. The SAML **SP side** stays.
- **BREAKING** Remove JARM (`*.jwt` response modes, `authorization_signed_response_alg`) and the FAPI 2.0 profile (`fapi_profile`, client `profile: fapi2`, `require_fapi_sender_constraint`, the FAPI DCR rules). PAR, JAR, DPoP, PKCE and the device grant stay.
- **BREAKING** Remove SMS OTP: `src/identity/sms/`, `/ui/sms-challenge`, `ENROLL_PHONE_OTP`, `remove-phone`, `sms.*` config, `HEARTH_SMS_OTP_HMAC_KEY`, `mfa_methods: ["sms"]`.
- **BREAKING** Remove risk scoring and adaptive MFA: `security.risk_scorer.*`, the realm `adaptive_mfa` setting, device-fingerprint storage, its sweeper, and `/admin/users/{id}/device-fingerprints`.
- **BREAKING** Remove the public gRPC surface: `src/protocol/grpc/`, `server.grpc_port`, `server.grpc_bind_address`, `server.grpc_allow_plaintext`, `security.grpc.reflection_enabled`, `tonic-health`, `tonic-reflection`, `examples/grpc-admin-flow`. The internal Raft peer transport (`src/cluster/`, `proto/hearth/cluster/v1/`) stays. The `proto/` message types stay for now, because the REST layer serialises through them.
- **BREAKING** Remove the ROPC password grant (`grant_type=password`, `password_grant_token`). OAuth 2.1 drops it, and it was the source of a past required-actions bypass (`tests/required_actions_ropc_bypass.rs`).
- **BREAKING** Remove abuse extras with no kept dependants: IP reputation (`maxminddb`), email reputation, bot signals, login tarpit.
- **BREAKING** Stop supporting the Kotlin and Rust SDKs. Merge `@hearth-auth/node` into `@hearth-auth/sdk`. Supported SDKs: TypeScript, Go, Python, PHP.
- Remove the "embedded mode" (library / C ABI) promise from `VISION.md` and the specs. No code changes; the `Embedded*Engine` types are the server's own engine.

**Behaviour changes:**
- **BREAKING** MFA is required by default. A realm with no explicit `auth.mfa_required` requires MFA. An operator can set it to `false`. Startup then logs a strong warning, and the console shows a persistent warning on that realm. Every change of the setting is audited.
- **BREAKING** Email OTP no longer satisfies an MFA requirement. Passkeys (WebAuthn), TOTP and recovery codes do.
- **BREAKING** `--dev` keeps the production MFA default. The bootstrap dev admin must enrol TOTP or a passkey on first sign-in.
- **NEW** An organization can require MFA for its members, even when its realm does not. It can tighten the realm policy, never loosen it.
- **BREAKING** The SAML SP accepts only a strict profile: exactly one signature, no DTD, exactly one assertion, and data read only from the signed element.
- **BREAKING** The pre-token webhook defaults to `on_error: fail_closed`.
- SDKs use standard JOSE/OIDC libraries for token validation, and an admin client generated from OpenAPI. They expose a rich developer API on top. **Moved during apply:** this work is the follow-up change `sdk-standard-libraries`; this change ships only the supported SDK set.

## Capabilities

### New Capabilities
- `trusted-core-surface`: what Hearth exposes and what it no longer exposes. Removed routes answer 404, removed config keys fail startup with a clear error, and discovery no longer advertises removed features.
- `mfa-policy`: the MFA default, which factors satisfy it, organization-level tightening, and the warning and audit when MFA is turned off.
- `saml-sp-profile`: the strict profile the SAML SP accepts.
- `pre-token-webhook-failure`: the webhook's failure mode and its default.
- `sdk-support-contract`: the supported SDK set. (How SDKs validate tokens and call the admin API is added by the follow-up change `sdk-standard-libraries`.)

### Modified Capabilities
None. `openspec/specs/` has no archived specs yet.

## Impact

- **Code removed:** about 25,000–30,000 lines of `src/`, plus their tests. The largest parts are gRPC (4,302), FAPI/JARM, SMS (about 2,900), LDAP (2,309), the SAML IdP (about 1,500), abuse extras (about 3,100), and risk/device-fingerprint (about 1,150).
- **APIs:** HTTP routes, discovery fields, config keys and one admin route are removed (listed above). The REST JSON shapes do not change.
- **Dependencies dropped:** `ldap3`, `maxminddb`, `tonic-health`, `tonic-reflection`, the unused `tonic-types`.
- **Backups:** archives that contain `saml_service_providers.ndjson` must still import. The importer skips that file with a warning.
- **CI:** jobs `ldap-integration`, `sdk-kotlin`, `sdk-rust` and `sdk-node`, plus `sdk-publish-kotlin.yml` and `sdk-publish-rust.yml`, are removed. The required-summary `needs` lists change.
- **Docs:** many guides and specs; see the tasks.
- **Versioning:** under `VERSIONING.md` this is a major release, v3.0.0.
