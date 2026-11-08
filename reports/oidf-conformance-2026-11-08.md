# OpenID Foundation conformance run — 2026-11-08

**OpenSpec change:** `trusted-core-confidence`, tasks 2.2 to 2.6. **Issue:** #639. Part of #652.

**Suite:** OpenID Foundation conformance suite, tag `release-v5.3.4`, run on this host with
`scripts/conformance-oidf.sh` (`make conformance-oidf`). Hearth runs as `serve -c` with TLS and a
real KEK, never `--dev`. All times are US Eastern (EST).

**Bottom line.**

| Plan | Result | Conditions (success / failure / warning) |
|---|---|---|
| Config OP (`oidcc-config-certification-test-plan`) | **PASS** | 39 / 0 / 1 |
| Basic OP (`oidcc-basic-certification-test-plan`) | **FAIL** — the plan stops at the PKCE requirement (see 3.1) | no export |
| Basic OP, PKCE check off (diagnostic image) | FAIL | 1708 / 6 / 11 |
| Dynamic OP, PKCE check off (diagnostic image) | FAIL | 554 / 23 / 2 |

> **Hearth is NOT certified.** Do not describe it as "OpenID Certified", conformant, or as
> passing the OpenID conformance suite. A local run is not certification: certification needs
> an OpenID Foundation certification agreement, a submitted passing log and OIDF acceptance.
> Only the Config OP plan passes.

The RS256 failure from the 2026-09-21 run is gone: `OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported`
passes, because a client can now ask for RS256 ID tokens (`id_token_signed_response_alg`).

---

## 1. How to run it

```
make conformance-oidf PLAN=config     # or basic, dynamic; no PLAN runs all three
make conformance-oidf-check           # the script's own guards and self-tests
```

The script builds the Hearth image, starts the Docker Compose project `hearth-oidf`, runs each
plan through the suite's own runner, exports the logs and checks them with
`scripts/conformance-oidf/check-export.py`. It exits non-zero when:

- any condition fails;
- a warning is not in `scripts/conformance-oidf/expected-warnings.json`, or the warning names a
  property or claim that the entry does not list;
- a module is SKIPPED and `scripts/conformance-oidf/expected-skips.json` does not list it, or a
  listed module does not skip;
- a plan does not export.

Each entry in those two files has a `decision` field. `render-plans.py` refuses an entry
without one, and refuses a skip that names a pattern instead of one module.

`OIDF_MAX_CONSECUTIVE_FAILURES` sets how many test modules can fail one after the other before
the runner stops a plan (the suite's default is 3). A diagnostic run sets it high to see every
module.

## 2. Fixes made from this run

Each fix has a red test first.

| PR | Fix | Suite modules |
|---|---|---|
| #778 | `prompt=none` with no session redirects with `login_required`; a request without PKCE gets an error redirect, not an error page | `oidcc-prompt-none-not-logged-in`, PKCE stop |
| #779 | Token endpoint error codes follow RFC 6749 §5.2 (`invalid_grant`, `invalid_client`), with `Cache-Control: no-store` and `Pragma: no-cache` | `oidcc-codereuse`, `oidcc-refresh-token` |
| #786 | `POST /userinfo` works as `GET` (OIDC Core §5.3.1); empty profile claims are left out (§5.3.2) | `oidcc-userinfo-post-header`, `oidcc-scope-profile` |
| #787 | Discovery states `request_parameter_supported`, `request_uri_parameter_supported: false` and the client assertion signing algorithms | `oidcc-discovery-endpoint-verification`, Dynamic OP |

The Basic OP diagnostic run went from 22 failures (before the fixes) to 6.

## 3. What still fails

### 3.1 PKCE is required (owner decision)

The spec `oidc-provider` requires PKCE (`S256`) on every authorization request. The Basic and
Dynamic OP plans send most requests without PKCE. Hearth now refuses them with an
`invalid_request` redirect, as RFC 6749 §4.1.2.1 says, but the suite counts each one as a failure
and stops the plan after three. The diagnostic image turns the PKCE check off to see the rest of
the plan. It is not a release image. Owner decision: #780.

### 3.2 Basic OP, with the PKCE check off

| Module | Cause | Issue |
|---|---|---|
| `oidcc-max-age-1`, `oidcc-max-age-10000` | The ID token has no `auth_time` when the request has `max_age` (OIDC Core §3.1.2.1) | #782 |
| `oidcc-prompt-login` | `prompt=login` does not force a new sign-in | #782 |
| `oidcc-ensure-post-request-succeeds` | `/authorize` accepts `GET` only; OIDC Core §3.1.2.1 says the OP MUST support `POST` too | #781 (owner decision) |

`oidcc-codereuse-30seconds` gives a warning: after a code is used twice, the access token from
the first exchange still works. RFC 6749 §4.1.2 says the server SHOULD revoke it. Issue: #783.

### 3.3 Dynamic OP, with the PKCE check off

Most Dynamic OP failures come from Hearth design choices. The owner decides if Dynamic OP
certification is a goal (#784):

- `response_types_supported` has `code` only; a dynamic OP must also list `id_token` and
  `id_token token`, and `grant_types_supported` must list `implicit`.
- Client registration with `jwks_uri` is refused; Hearth takes inline `jwks` only.
- UserInfo is JSON only; `oidcc-userinfo-rs256` needs signed UserInfo.
- `request_uri` by reference is not supported (`oidcc-request-uri-*`).
- The suite signs `private_key_jwt` client assertions with RS256; Hearth accepts PS256, ES256 and
  EdDSA only (FAPI 2.0 algorithm list). `oidcc-server`, `oidcc-refresh-token` and each other
  module that calls the token endpoint will fail on this. Today they fail one step earlier:
  the suite sends no `client_id` with its assertion, and Hearth refuses that (defect #785;
  RFC 7521 §4.2 makes `client_id` optional).
- `oidcc-server-rotate-keys` needs an operator to rotate the key while the test waits.
- `oidcc-registration-logo-uri`, `-policy-uri`, `-tos-uri` stop with a suite exception
  (`runInBackground called after runFinalisationTaskInBackground()`). This is not yet
  investigated; it can be a problem in the runner's browser overrides.

## 4. Warnings and their decisions

The full text of each decision is in `scripts/conformance-oidf/expected-warnings.json`.

| Plan | Module | Condition | Decision |
|---|---|---|---|
| Config, Dynamic | `oidcc-discovery-endpoint-verification` | `CheckForUnexpectedParametersInServerMetadata` (`resource_indicators_supported`) | KEEP. Design Open Question 1 stays open for the owner; the spec `agent-identity` requires the name |
| Basic | `oidcc-server` | `EnsureIdTokenDoesNotContainNonRequestedClaims` (`token_type`, `tid`, `scope`) | KEEP. `token_type` is the token-type guard; `tid` names the realm; `scope` is the granted scope |
| Basic | `oidcc-scope-email`, `oidcc-alternate-happy-flow` | `EnsureIdTokenDoesNotContainEmailForScopeEmail` | KEEP. `email` in the ID token saves a UserInfo call; OIDC Core §5.4 allows it |
| Basic | `oidcc-scope-profile` | `VerifyScopesReturnedInUserInfoClaims` | KEEP. Hearth stores no value for most profile claims; a claim with no value is left out |
| Basic | `oidcc-claims-essential` | `EnsureUserInfoContainsName` | KEEP. The `claims` request parameter (OIDC Core §5.5) is not supported |
| Basic | `oidcc-ensure-request-with-acr-values-succeeds` | `ValidateIdTokenACRClaimAgainstAcrValuesRequest` | KEEP. No `acr` claim; the ID token has `amr` |
| Basic | `oidcc-userinfo-post-body` | `UserInfoEndpointWithAccessTokenInBodyNotSupported` | KEEP. The token goes in the `Authorization` header only (RFC 6750 §2.2 is a MAY) |
| Basic | `oidcc-codereuse-30seconds` | `EnsureHttpStatusCodeIs4xx` | NOT recorded: a defect (#783), so the run stays red |

## 5. Skipped modules and their decisions

The full text is in `scripts/conformance-oidf/expected-skips.json`.

| Plan | Module | Decision |
|---|---|---|
| Basic | `oidcc-scope-address`, `oidcc-scope-phone`, `oidcc-scope-all` | ACCEPT. No address or phone claims |
| Basic, Dynamic | `oidcc-ensure-request-object-with-redirect-uri` | ACCEPT. Request objects must be signed |
| Basic | `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | ACCEPT. Request objects must be signed |
| Dynamic | `oidcc-idtoken-unsigned` | ACCEPT. Hearth never issues an unsigned token |
| Dynamic | `oidcc-registration-sector-uri`, `oidcc-registration-sector-bad` | ACCEPT. Public subject type only |

## 6. Release step

`docs/release-runbook.md` has the conformance step. The Config OP plan must pass before a
release. The Basic and Dynamic OP plans run for regressions: compare the failure list with
this report. Whether they become a release gate is an owner decision.

## 7. Not in scope

The Implicit OP and Hybrid OP plans are not run (design decision 2 of `trusted-core-confidence`:
Hearth supports the code flow only). SCIM and SAML have no certifying body's suite to run; see
the 2026-09-21 report.
