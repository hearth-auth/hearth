# Per-SDK JWT verify-or-decode-and-trust matrix

**Date:** 2026-09-09
**Branch:** `fix/production-readiness-audit-8-28-26-issues`
**Tasks:** production-readiness-remediation 23.4 (re-run of P28) and 23.17
**Audit citations:** §7.2, §8.1 item 4, §8.3
**Scope:** the seven SDKs under `sdks/` — `go`, `kotlin`, `node`, `php`, `python`, `rust`, `typescript`.
All paths below are relative to the repo root. Line numbers are as of the commit at the head of the
branch above (`3c13bcee`).

> **Method note.** The audit report's §4.x/§8.x prose is not present in this repository, so every claim
> below is proved from the SDK source rather than quoted from the audit. Where my count differs from
> the audit's, the discrepancy is called out explicitly in Findings.

---

## 1. Summary matrix

Two verification surfaces exist in most SDKs and they must be judged separately:

* **Verify path** — the `verifyToken` / `verify` / `VerifyToken` entry point that a caller invokes
  explicitly. This is the surface the SDK spec §2 describes.
* **Authorization path** — the shipped HTTP middleware / permission guard that a resource server mounts
  in front of its routes. This is what actually gates production traffic.

| SDK | Q1 — Verify or decode-and-trust? | Q2 — Algorithms accepted (`none`? symmetric?) | Q3 — JWKS fetch + cache; issuer/audience pinned? | Q4 — `exp` / `nbf` / `iss` | Q5 — TLS verification |
|---|---|---|---|---|---|
| **go** | **SPLIT — CRITICAL.** Verify path verifies Ed25519. Authorization path (`RequirePermission`, gin + echo guards) **decodes and trusts**; the helper's own comment says "The signature is NOT verified". | Verify path: `EdDSA` only, hard-rejected otherwise. No `none`, no symmetric. Decode path: **no `alg` check at all**. | Yes — `JwksCache` keyed by `kid`, `Cache-Control: max-age` honoured, capped 24 h, one re-fetch on miss. `iss` pinned to the discovered issuer; `aud` checked only when the caller passes one (variadic, default off). | `exp` yes; `iss` yes; **`nbf` never read** (`iat`-in-future is checked and reported as `TokenNotYetValidError`, which is a misnomer). | Default `net/http` client, TLS verification on. No `InsecureSkipVerify` anywhere. |
| **kotlin** | **SPLIT — CRITICAL.** `TokenVerifier.verify` verifies via Nimbus. `requirePermission(EMBEDDED)` **decodes and trusts**. | Verify path: `EdDSA` handled directly; anything else falls to a federation path wired only for `RS256`/`ES256`. `none` rejected by `SignedJWT.parse`. HS256 selects no key ⇒ reject. Decode path: **no `alg` check**. | Yes — `JwksClient` caches by `kid`, TTL clamped 5 min–24 h (default 1 h), merges old keys on refresh, one re-fetch on miss. `iss` pinned via `DefaultJWTClaimsVerifier` exact-match; `aud` pinned when `expectedAudience` set. | `exp` yes; `nbf` yes (Nimbus `DefaultJWTClaimsVerifier`); `iss` yes. Extra explicit `iat`-in-future check. | OkHttp default trust manager. No `X509TrustManager` override, no `allowAllHostnames`. |
| **node** | **VERIFIES.** Every gate consumes a `VerifiedToken` produced by `jwtVerify`. No decode-and-trust path in the SDK. | `["RS256","ES256","RS384","ES384","RS512","ES512","EdDSA"]` (express/fastify) and `["EdDSA","RS256","ES256","RS384","ES384","RS512","ES512"]` (Next.js edge). **No `none`, no HS\***. `jose` additionally refuses to use an OKP/RSA JWK as an HMAC key. | Yes — `createRemoteJWKSet` with `cacheMaxAge` capped 24 h plus an 80 %-of-TTL background refresh and re-fetch-once on `JWKSNoMatchingKey`. `issuer` always pinned; `audience` pinned only when configured (optional, default off). | `exp` yes; `nbf` yes (`jose` enforces both); `iss` yes. | Global `fetch` / undici defaults. No `rejectUnauthorized:false`, no `NODE_TLS_REJECT_UNAUTHORIZED`. |
| **php** | **VERIFIES.** Only path into `Claims` is `TokenVerifier::verify`; the PSR-15 and Laravel middleware both call it and 401 on failure. No embedded decode mode exists. | `EdDSA` only — hard reject with a typed exception otherwise. No `none`, no symmetric. Signature checked with `sodium_crypto_sign_verify_detached`. | Yes — `JwksClient` caches OKP/`Ed25519` keys by `kid`. `iss` pinned to the constructor's `$issuerUrl`; `aud` pinned when `$clientId` is non-null. | `exp` yes; `iss` yes; **`nbf` never read**. `iat` clock-skew check present. | Guzzle defaults (`verify => true`). No `CURLOPT_SSL_VERIFYPEER` override. |
| **python** | **SPLIT — CRITICAL.** `HearthClient.verify_token` verifies Ed25519. `RequirePermissionMiddleware` (ASGI), the Django middleware and the `@require_permission` decorator all route embedded mode to `_check_embedded`, which **decodes and trusts**. FastAPI's `HearthFastAPIDep` is the one adapter that verifies first. | Verify path: `EdDSA` only, hard reject. Decode path: **no `alg` check**. | Yes — `JwksCache` honours `Cache-Control: max-age` capped at 24 h, re-fetches once on miss, keys are `Ed25519PublicKey` objects only (`crv != "Ed25519"` skipped). `iss` pinned to `base_url` (or an explicit `issuer_url`); `aud` checked only when the caller passes `audience=`. | `exp` yes; `iss` yes; **`nbf` not checked on the verify path** (a separate opt-in `Claims.assert_valid()` helper checks it, and nothing in the verify path calls it). | `httpx.Client` defaults, TLS verification on. No `verify=False`. |
| **rust** | **SPLIT — CRITICAL.** `HearthClient::verify_token` verifies EdDSA via `jsonwebtoken`. `check_permission(Embedded)` → `has_permission` → `Claims::decode` **decodes and trusts**, and both the tower and actix middlewares gate on it. The actix middleware then stores the token in a struct literally named `VerifiedToken` even though nothing verified it. | Verify path: `Validation::new(Algorithm::EdDSA)` — `jsonwebtoken` rejects any other `alg`, including `none` and all HS\*. Decode path: **no `alg` check**. | Yes — `JwksCache` keyed by `kid`, TTL-driven, `DecodingKey::from_jwk`. `iss` pinned via `validation.set_issuer`; `aud` pinned when `client_id` is configured, otherwise `validate_aud = false`. | `exp` yes (jsonwebtoken, 5 s leeway); `iss` yes; **`nbf` not checked** — `Validation::validate_nbf` is left at its `false` default. | `reqwest::Client::builder()` with only a timeout. No `danger_accept_invalid_certs`. |
| **typescript** | **SPLIT — CRITICAL.** `JwksClient.verify` / `HearthClient.verifyToken` verify properly. `requirePermission(mode:"embedded")` **decodes and trusts** via `jose.decodeJwt`, and the README documents exactly that usage against a raw `accessToken`. `hearth.ts::safeDecode` is a second decode-and-trust helper (browser-side, lower severity). | Verify path: `["EdDSA","RS256","ES256","RS384","ES384"]`. **No `none`, no HS\***. Decode path: **no `alg` check**. | Yes — `JwksClient` caches a `createLocalJWKSet` for `ttl` (default 5 min), force-refresh on `JWKSNoMatchingKey`. `issuer` pinned when the caller passes it; `HearthClient.verifyToken` always passes `issuerUrl` and `clientId`. **`JwksClient.verify` called directly with no options pins neither `iss` nor `aud`.** | `exp` yes; `nbf` yes (`jose`); `iss` yes when supplied. | Global `fetch` with an `AbortSignal.timeout`. No TLS overrides. |

---

## 2. Evidence

### Q1 — verify vs. decode-and-trust

| SDK | Verifying entry point | Decode-and-trust entry point (if any) |
|---|---|---|
| go | `sdks/go/hearth/verify.go:90` `VerifyToken`; signature at `sdks/go/hearth/verify.go:141` (`ed25519.Verify`) | `sdks/go/hearth/client.go:204` `decodeClaims` — comment at `client.go:200-203`: *"The signature is NOT verified — the app trusts its own token."* Consumed by `sdks/go/hearth/middleware.go:121` (`ModeEmbedded` arm of `RequirePermission`), `sdks/go/hearth/client.go:234` `HasPermission`, `sdks/go/hearth/gin/middleware.go:157`, `sdks/go/hearth/echo/middleware.go:160` |
| kotlin | `sdks/kotlin/hearth-core/src/main/kotlin/io/hearth/sdk/TokenVerifier.kt:55` `verify`; EdDSA signature at `TokenVerifier.kt:117` (`Ed25519Verifier`) | `sdks/kotlin/hearth-core/src/main/kotlin/io/hearth/sdk/Middleware.kt:84-85` (`EMBEDDED` arm) → `Middleware.kt:147` `decodeLocalPermissions`; also `Middleware.kt:118` `checkRequiredAction` (comment at `Middleware.kt:115`: *"The signature is NOT verified here"*) |
| node | `sdks/node/src/jwks.ts:69` `verifyToken` (`jwtVerify` at `jwks.ts:79`); `sdks/node/src/nextjs/edge.ts:290` (`jwtVerify`) | **none** — `sdks/node/src/middleware.ts:97` `checkEmbedded` takes a `VerifiedToken`; `sdks/node/src/nextjs/edge.ts:184` `requirePermission` takes an already-verified `EdgeToken` |
| php | `sdks/php/src/TokenVerifier.php:57` `verify`; signature at `TokenVerifier.php:172` (`sodium_crypto_sign_verify_detached`); middleware at `sdks/php/src/Middleware/HearthMiddleware.php:96` | **none** |
| python | `sdks/python/src/hearth/client.py:477` `verify_token`; signature at `client.py:534` (`pub_key.verify`); FastAPI adapter verifies at `sdks/python/src/hearth/fastapi.py:185` | `sdks/python/src/hearth/middleware.py:71` `_check_embedded` → `sdks/python/src/hearth/claims.py:33` `Claims.decode` (*"Decode a JWT string without verifying its signature"*). Consumed by `sdks/python/src/hearth/middleware.py:228` (`RequirePermissionMiddleware._check`), `sdks/python/src/hearth/django.py:92` (`HearthDjangoMiddleware` + `@require_permission`) |
| rust | `sdks/rust/src/client.rs:278` `verify_token`; `jsonwebtoken::decode` at `client.rs:317` | `sdks/rust/src/client.rs:868` `has_permission` → `sdks/rust/src/client.rs:914` `decode_claims` → `sdks/rust/src/claims.rs:37` `Claims::decode` (*"Decode a JWT string without verifying its signature"*). Reached from `sdks/rust/src/client.rs:792` (`AccessTokenAuthorization::Embedded`), gated by `sdks/rust/src/middleware.rs:164` and `sdks/rust/src/actix.rs:180`; mislabelled `VerifiedToken` insert at `sdks/rust/src/actix.rs:187` |
| typescript | `sdks/typescript/src/jwks-client.ts:98` `verify` (`jwtVerify` at `jwks-client.ts:101`); `sdks/typescript/src/hearth-client.ts:315` `verifyToken` | `sdks/typescript/src/middleware.ts:54` (`"embedded"` arm of `requirePermission`, `jose.decodeJwt`); documented usage at `sdks/typescript/README.md:497-505`. Secondary: `sdks/typescript/src/hearth.ts:120` `safeDecode` (*"Signature is NOT verified"*), `sdks/typescript/src/client.ts:143` (callback handling, own token) |

### Q2 — accepted algorithms

| SDK | Evidence | `none` | HS\* / algorithm confusion |
|---|---|---|---|
| go | `sdks/go/hearth/verify.go:114` — `if header.Alg != "EdDSA"` reject | rejected | rejected |
| kotlin | `sdks/kotlin/hearth-core/.../TokenVerifier.kt:90` dispatch; `TokenVerifier.kt:142-143` `JWSVerificationKeySelector(RS256)` + `(ES256)` | rejected by `SignedJWT.parse` (Nimbus refuses `alg:none`) | HS256 selects zero keys ⇒ `BadJOSEException`; no OKP-as-HMAC-secret path |
| node | `sdks/node/src/jwks.ts:75`; `sdks/node/src/nextjs/edge.ts:295` | not in the allowlist ⇒ rejected | HS\* not in the allowlist; `jose` also refuses an asymmetric JWK as an HMAC key |
| php | `sdks/php/src/TokenVerifier.php:151` — `if ($alg !== 'EdDSA')` reject | rejected | rejected |
| python | `sdks/python/src/hearth/client.py:517` — `if alg != "EdDSA"` reject | rejected | rejected |
| rust | `sdks/rust/src/client.rs:302` — `Validation::new(Algorithm::EdDSA)` | rejected by `jsonwebtoken` | rejected |
| typescript | `sdks/typescript/src/jwks-client.ts:104` | not in the allowlist ⇒ rejected | HS\* not in the allowlist |

**Every decode-and-trust path listed under Q1 accepts any `alg` value, including `none`, because it never
looks at the header at all.** Algorithm confusion is not the exploit there — no signature is consulted.

### Q3 — JWKS fetch, cache, issuer and audience pinning

| SDK | JWKS cache | `iss` pinned | `aud` pinned |
|---|---|---|---|
| go | `sdks/go/hearth/jwks.go:32-70` (TTL from `Cache-Control`, 24 h cap, re-fetch once on miss); OKP guard at `jwks.go:154` | `sdks/go/hearth/verify.go:166` against `resolveIssuer()` | `sdks/go/hearth/verify.go:171-179` — only when the variadic `audience` arg is supplied |
| kotlin | `sdks/kotlin/hearth-core/.../JwksClient.kt:17-23,45-69` (5 min–24 h clamp, default 1 h, key merge) | `TokenVerifier.kt:196-199` exact-match `issuerUrl` | `TokenVerifier.kt:200-206` — only when `expectedAudience` is set |
| node | `sdks/node/src/jwks.ts:41-66` (24 h cap + 80 %-TTL background refresh); rotation re-fetch at `jwks.ts:93` | `sdks/node/src/jwks.ts:72` (always) | `sdks/node/src/jwks.ts:76-78` — only when `config.audience` non-empty (`sdks/node/src/config.ts:60-68`) |
| php | `sdks/php/src/JwksClient.php:15-60,106-150` (OKP/`Ed25519` only) | `sdks/php/src/TokenVerifier.php:75` | `sdks/php/src/TokenVerifier.php:78-80` — only when `$clientId !== null` |
| python | `sdks/python/src/hearth/jwks.py:26-63,116-123` (`Cache-Control` honoured, 24 h cap, re-fetch once) | `sdks/python/src/hearth/client.py:557-560` | `sdks/python/src/hearth/client.py:563-568` — only when `audience=` passed |
| rust | `sdks/rust/src/jwks_cache.rs:1-20`; wired at `sdks/rust/src/client.rs:127` | `sdks/rust/src/client.rs:306-307` `validation.set_issuer` | `sdks/rust/src/client.rs:309-313` — `validate_aud = false` when `client_id` is `None` |
| typescript | `sdks/typescript/src/jwks-client.ts:68-78` (TTL, default 5 min), force-refresh at `jwks-client.ts:115` | `sdks/typescript/src/jwks-client.ts:102` — **only when the caller passes `options.issuer`** | `sdks/typescript/src/jwks-client.ts:103` — only when `options.audience` passed. `HearthClient.verifyToken` (`hearth-client.ts:316-319`) always passes both |

### Q4 — `exp`, `nbf`, `iss`

| SDK | `exp` | `nbf` | `iss` |
|---|---|---|---|
| go | `verify.go:154` | **not checked** — `verify.go:183` checks `iat`-in-future and misreports it as `TokenNotYetValidError` | `verify.go:166` |
| kotlin | Nimbus `DefaultJWTClaimsVerifier` (`TokenVerifier.kt:194`) | checked by the same verifier | `TokenVerifier.kt:196` |
| node | `jose` (`jwks.ts:79`) | checked by `jose` | `jwks.ts:72` |
| php | `TokenVerifier.php:190-199` | **not checked** | `TokenVerifier.php:75` |
| python | `client.py:551-554` | **not checked on the verify path**; `sdks/python/src/hearth/claims.py:59-61` has an opt-in `assert_valid()` that nothing in `verify_token` calls | `client.py:557` |
| rust | `jsonwebtoken` (`client.rs:317`), 5 s leeway at `client.rs:303` | **not checked** — `Validation::validate_nbf` left at its `false` default | `client.rs:306` |
| typescript | `jose` (`jwks-client.ts:101`) | checked by `jose` | `jwks-client.ts:102` (when supplied) |

### Q5 — TLS certificate verification

No SDK disables TLS verification anywhere. A repo-wide sweep for `InsecureSkipVerify`, `verify=False`,
`danger_accept_invalid_certs`, `rejectUnauthorized`, `NODE_TLS_REJECT_UNAUTHORIZED`,
`CURLOPT_SSL_VERIFY*`, `X509TrustManager`, `allowAllHostnames` and `TrustAllCerts` across all seven SDKs
(excluding `node_modules`, `vendor`, `dist`, `target`, `.venv`, `build`) returned **zero hits**.

Client construction, all using library defaults with verification enabled:

* go — `sdks/go/hearth/client.go:96` (`&http.Client{}`), `sdks/go/hearth/jwks.go:54`
* kotlin — `sdks/kotlin/hearth-core/.../JwksClient.kt:37` (injected `OkHttpClient`, default trust manager)
* node / typescript — global `fetch` (`sdks/typescript/src/jwks-client.ts:166`)
* php — `sdks/php/src/HearthClient.php:79` (Guzzle, `verify` defaults to `true`)
* python — `sdks/python/src/hearth/client.py:69`, `sdks/python/src/hearth/jwks.py:45` (`httpx.Client`)
* rust — `sdks/rust/src/client.rs:123`, `sdks/rust/src/client.rs:172` (`reqwest::Client::builder()` with only a timeout)

One adjacent note, not a TLS defect: kotlin's `JwksClient` takes the `OkHttpClient` by injection
(`JwksClient.kt:37`), so an application that hands it a trust-all client defeats verification. That is a
caller responsibility, but it is the only place a Hearth SDK's TLS posture is not fixed by the SDK itself.

---

## 3. Findings, by severity

### CRITICAL-1 — Five SDKs gate authorization on an unverified JWT

**Affected: go, kotlin, python, rust, typescript. Not affected: node, php.**

Every one of these SDKs ships a permission guard whose default or documented `embedded` mode reads the
`permissions` claim straight out of the JWT payload with no signature check, no `alg` check, no `exp`
check, no `iss` check, and no JWKS lookup. In go, python and rust the guard *is* the HTTP middleware that
a resource server mounts in front of its routes:

* `sdks/go/hearth/middleware.go:121` — `RequirePermission(..., ModeEmbedded)` calls `decodeClaims` and
  calls `next` on a match. `sdks/go/hearth/gin/middleware.go:94` compounds it: `HearthMiddleware` only
  *extracts and stashes* the bearer token — it never verifies — and `RequirePermission` at
  `gin/middleware.go:157` then trusts the decoded claims. `echo` is identical (`echo/middleware.go:160`).
* `sdks/python/src/hearth/middleware.py:228` — `RequirePermissionMiddleware` (ASGI) in `embedded` mode.
  `sdks/python/src/hearth/django.py:92` — the Django middleware and the `@require_permission` decorator.
* `sdks/rust/src/middleware.rs:164` and `sdks/rust/src/actix.rs:180` — both delegate to
  `check_permission(Embedded)` → `has_permission` → `Claims::decode`. `actix.rs:187` then inserts the
  token into request extensions inside a newtype called `VerifiedToken`, which is actively misleading.
* `sdks/kotlin/.../Middleware.kt:84` — `requirePermission(EMBEDDED)`.
* `sdks/typescript/src/middleware.ts:54` — `requirePermission({mode:"embedded"})`, with
  `sdks/typescript/README.md:497-505` documenting it applied directly to a raw `accessToken`.

**Exploit.** An unauthenticated attacker mints `{"alg":"none"}.{"sub":"anyone","permissions":["admin.write"]}.`
with an empty signature and sends it as a Bearer token. Every guard above returns "allowed". No key
material, no interaction with Hearth, and no network call is required. `exp` is not consulted either, so
an expired or revoked token also passes indefinitely.

**Why this is not mitigated by design.** The obvious defence would be "embedded mode assumes the token was
already verified upstream." That defence does not hold here for three reasons:

1. The go gin/echo adapters ship the upstream middleware themselves (`HearthMiddleware`) and it does not
   verify — so wiring the SDK exactly as its own doc comment instructs
   (`gin/middleware.go:130-131`: *"HearthMiddleware must appear before RequirePermission"*) still yields
   a bypass.
2. The python ASGI/Django middlewares and the rust tower/actix layers are the outermost auth layer by
   construction; there is nothing upstream of them.
3. The typescript README's own embedded example passes a raw `accessToken` with no prior `verifyToken`
   call.

Node and PHP show the correct shape: node's `checkEmbedded` (`sdks/node/src/middleware.ts:97`) takes a
`VerifiedToken`, and PHP's PSR-15 middleware (`sdks/php/src/Middleware/HearthMiddleware.php:96`) always
calls `TokenVerifier::verify` first.

### HIGH-1 — `nbf` is not validated by four SDKs

`go`, `php`, `python` and `rust` never read `nbf` on the verify path (evidence in the Q4 table). Rust's is
a one-word omission: `Validation::validate_nbf` is left at its `false` default at
`sdks/rust/src/client.rs:302-303`. Python has a working `nbf` check at `claims.py:59-61` that
`verify_token` simply never calls. Go's `TokenNotYetValidError` is raised for a future `iat`, not `nbf`,
so the error type suggests coverage that does not exist. Hearth does not currently issue post-dated
tokens, which bounds the impact today, but this is a silent divergence from RFC 7519 §4.1.5 and from what
each SDK's own doc comment claims.

### MEDIUM-1 — Three SDKs (four code paths) accept RS256/ES256; the audit says four SDKs

The audit's "four SDKs accept RS256/ES256" does not reproduce. What I find is **three SDKs across four
verification call-sites**:

| # | SDK | File:line | Accepted list |
|---|---|---|---|
| 1 | node | `sdks/node/src/jwks.ts:75` | `RS256, ES256, RS384, ES384, RS512, ES512, EdDSA` |
| 2 | node | `sdks/node/src/nextjs/edge.ts:295` | `EdDSA, RS256, ES256, RS384, ES384, RS512, ES512` |
| 3 | typescript | `sdks/typescript/src/jwks-client.ts:104` | `EdDSA, RS256, ES256, RS384, ES384` |
| 4 | kotlin | `sdks/kotlin/hearth-core/.../TokenVerifier.kt:142-143` | `RS256`, `ES256` selectors on a federation fallback |

`go`, `php`, `python` and `rust` are `EdDSA`-only and hard-reject anything else. The audit's "four" is
most plausibly a count of these four *call-sites* read as four SDKs. If task 18.1 is scoped by SDK rather
than by call-site it will under-cover node, which has two.

Severity is medium, not high: Hearth only ever publishes OKP/`Ed25519` keys in its JWKS
(`sdks/go/hearth/jwks.go:154`, `sdks/php/src/JwksClient.php:149`,
`sdks/python/src/hearth/jwks.py:116` all skip non-`Ed25519` entries), so an RS256 token has no key to
match and fails closed today. The exposure is latent: if any RSA or EC key ever enters the JWKS — via
federation, a future migration, or a JWKS-hosting mistake — these four sites would accept a token signed
with it as though Hearth had issued it. Kotlin's federation path is explicitly documented as intended for
relaying third-party IdP tokens (`TokenVerifier.kt:134-137`), so removing it there needs a decision about
whether that use case is still supported; the node and typescript entries have no such justification.

### MEDIUM-2 — `typescript`'s `JwksClient.verify` pins neither `iss` nor `aud` when called directly

`sdks/typescript/src/jwks-client.ts:102-103` passes `options?.issuer` and `options?.audience` straight
through to `jose`, and `jose` skips the corresponding check when the value is `undefined`. `JwksClient` is
exported from the package root, so a caller who constructs it directly (rather than going through
`HearthClient.verifyToken`, which does pass both at `hearth-client.ts:316-319`) gets a signature-only
check. Any Hearth-issued token from any realm would then be accepted by any resource server sharing that
JWKS.

### LOW-1 — Browser-side decode helper in `typescript`

`sdks/typescript/src/hearth.ts:120` `safeDecode` decodes without verifying and backs the client-side
`hasPermission` predicates used by the React bindings. Using unverified claims to decide what UI to render
is conventional and not itself a vulnerability, but the helper is exported and nothing in its name or
signature stops a server-side caller from reaching for it. The doc comment at `hearth.ts:116-118` does say
the signature is not verified.

### LOW-2 — `aud` is optional in six of seven SDKs

Only when the caller supplies an audience (`client_id`, `clientId`, `expectedAudience`, `audience=`) is
`aud` checked at all; `go`, `python`, `rust`, `node`, `typescript` and `php` all silently skip the check
otherwise (Q3 table). This is a defensible default for a single-audience deployment but means the default
posture accepts a token minted for a different resource server in the same realm.

---

## 4. Answer to task 23.17

Task 23.17 asks for the same per-SDK verify/decode matrix as 23.4 (§8.3). It is section 1 above, with
supporting evidence in section 2. The headline for §8.3: **five of seven SDKs (go, kotlin, python, rust,
typescript) ship an authorization gate that decodes a JWT and trusts its `permissions` claim without any
signature verification. Two (node, php) do not.** No SDK disables TLS verification. No SDK's *verify* path
accepts `none` or a symmetric algorithm.
