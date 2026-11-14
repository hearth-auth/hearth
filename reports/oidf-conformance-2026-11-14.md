# OpenID Foundation conformance run — 2026-11-14

**Issue:** #639. Part of #652. **Previous run:** `reports/oidf-conformance-2026-11-08.md`.

**Suite:** OpenID Foundation conformance suite, tag `release-v5.3.4`, run on this host with
`scripts/conformance-oidf.sh` (`make conformance-oidf`). Hearth runs as `serve -c` with TLS and a
real KEK, never `--dev`. The image is the working tree of #856 (the per-client `require_pkce`
setting, #780), with no diagnostic change. All times are US Eastern (EST).

**Bottom line.**

| Plan | Result | Modules | Conditions (success / failure / warning) |
|---|---|---|---|
| Config OP (`oidcc-config-certification-test-plan`) | **PASS** | 1 warning (recorded) | 39 / 0 / 1 |
| Basic OP (`oidcc-basic-certification-test-plan`) | **PASS**: no failed condition; every warning and skip has a recorded decision | 19 passed, 7 warning, 4 review, 5 skipped | 1744 / 0 / 10 |
| Dynamic OP (`oidcc-dynamic-certification-test-plan`) | FAIL: known, not a goal (#784) | 15 failed, 1 passed, 3 review, 4 skipped | 506 / 23 / 1 |

`make conformance-oidf PLAN=config` plus `PLAN=basic` (started 2026-11-14 03:22 EST) exits 0:
the script finds no failed condition, and no warning or skip without a recorded decision. A run
of all three plans exits 1, because the Dynamic OP plan fails (section 3).

> **Hearth is NOT certified.** Do not describe it as "OpenID Certified", conformant, or as
> passing the OpenID conformance suite. A local run is not certification: certification needs
> an OpenID Foundation certification agreement, a submitted passing log and OIDF acceptance.

---

## 1. What changed since 2026-11-08

| Issue / PR | Change | Effect on the run |
|---|---|---|
| #780 (#856) | Per-client `require_pkce`, default `true`. The two static clients of `scripts/conformance-oidf/hearth.yaml` set `false` | The Basic OP plan runs to the end with the release code. The 2026-11-08 Basic OP numbers needed a diagnostic image with the PKCE check off |
| #781 (#827) | `/authorize` accepts `POST` (OIDC Core §3.1.2.1) | `oidcc-ensure-post-request-succeeds` passes |
| #782 (#830) | `auth_time` with `max_age`; `prompt=login` forces a new sign-in | `oidcc-max-age-1`, `oidcc-max-age-10000` and `oidcc-prompt-login` have no failed condition |
| #783 (#789) | A second use of a code revokes the tokens of the first exchange | The `oidcc-codereuse-30seconds` warning is gone |
| #785 (#790) | A client assertion without `client_id` is accepted (RFC 7521 §4.2) | Dynamic OP: not visible, the PKCE stop comes first (see 3) |

Basic OP: 6 failures on 2026-11-08 (diagnostic image), 0 now.

## 2. Modules for manual review

The suite marks a module REVIEW when a person must look at a screenshot, for example of an
error page or a sign-in page. These modules have no failed condition. A certification
submission needs the screenshots; a local run does not.

| Plan | Modules |
|---|---|
| Basic | `oidcc-ensure-registered-redirect-uri`, `oidcc-max-age-1`, `oidcc-prompt-login`, `oidcc-response-type-missing` |
| Dynamic | `oidcc-ensure-redirect-uri-in-authorization-request`, `oidcc-redirect-uri-query-mismatch`, `oidcc-redirect-uri-query-added` |

## 3. Dynamic OP: known failures

Owner decision on #784: Dynamic OP certification is not a goal. The release step runs the plan
for regressions only, not as a gate. These are the failures of this run; a failure that is not
in this list is a regression.

| Modules | Cause |
|---|---|
| `oidcc-server`, `oidcc-refresh-token`, `oidcc-idtoken-rs256`, `oidcc-userinfo-rs256`, `oidcc-redirect-uri-query-OK`, `oidcc-registration-logo-uri`, `oidcc-registration-policy-uri`, `oidcc-registration-tos-uri`, `oidcc-ensure-client-assertion-with-iss-aud-succeeds` | The suite registers its clients through dynamic registration and sends authorization requests without PKCE. A dynamically registered client always needs PKCE (spec `oidc-provider`, change `client-optional-pkce`), so Hearth answers `invalid_request` ("PKCE is required"). Each module stops there (`CheckIfAuthorizationEndpointError`) |
| `oidcc-discovery-endpoint-verification` | `response_types_supported` has `code` only, and `grant_types_supported` has no `implicit`. Hearth supports the code flow only |
| `oidcc-userinfo-rs256` (also) | UserInfo is JSON only; no `userinfo_signing_alg_values_supported` |
| `oidcc-registration-jwks-uri`, `oidcc-refresh-token-rp-key-rotation` | Client registration with `jwks_uri` is refused; Hearth takes inline `jwks` only |
| `oidcc-request-uri-unsigned`, `oidcc-request-uri-signed-rs256` | `request_uri` by reference is not supported |
| `oidcc-server-rotate-keys` | The test needs an operator to rotate the signing key while it waits |

The modules in the first row stop before the token endpoint. Other causes behind the PKCE stop,
such as the RS256 client assertions of the suite (Hearth accepts PS256, ES256 and EdDSA for
`private_key_jwt`), do not show in this run.

The 2026-11-08 suite exception in the `oidcc-registration-*-uri` modules
(`runInBackground called after runFinalisationTaskInBackground()`) did not occur. These modules
now stop at the PKCE refusal first.

To see every Dynamic OP module, raise the runner's stop limit; with the default (3), the plan
stops after the first three modules that do not finish:

```
OIDF_MAX_CONSECUTIVE_FAILURES=200 make conformance-oidf PLAN=dynamic
```

## 4. Warnings and their decisions

No change from the 2026-11-08 report, section 4, except that the `oidcc-codereuse-30seconds`
warning (#783) no longer occurs. Every warning of this run is in
`scripts/conformance-oidf/expected-warnings.json`.

| Plan | Module | Condition |
|---|---|---|
| Config, Dynamic | `oidcc-discovery-endpoint-verification` | `CheckForUnexpectedParametersInServerMetadata` (`resource_indicators_supported`) |
| Basic | `oidcc-server` | `EnsureIdTokenDoesNotContainNonRequestedClaims` (`token_type`, `tid`, `scope`) |
| Basic | `oidcc-scope-email`, `oidcc-alternate-happy-flow` | `EnsureIdTokenDoesNotContainEmailForScopeEmail` |
| Basic | `oidcc-scope-profile` | `VerifyScopesReturnedInUserInfoClaims` |
| Basic | `oidcc-claims-essential` | `EnsureUserInfoContainsName` |
| Basic | `oidcc-ensure-request-with-acr-values-succeeds` | `ValidateIdTokenACRClaimAgainstAcrValuesRequest` |
| Basic | `oidcc-userinfo-post-body` | `UserInfoEndpointWithAccessTokenInBodyNotSupported` |

## 5. Skipped modules

No change from the 2026-11-08 report, section 5. Every skip of this run is in
`scripts/conformance-oidf/expected-skips.json`.

## 6. How to run it

See the 2026-11-08 report, section 1, and `docs/release-runbook.md`.

## 7. Not in scope

The Implicit OP and Hybrid OP plans are not run: Hearth supports the code flow only.
