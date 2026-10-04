## Context

`scope-trim-trusted-core` (design decision 10) set the direction: each SDK has a rich
developer API, but borrows its crypto and its admin plumbing. That change shipped only the
supported-set part (TypeScript, Go, Python, PHP; Node merged into TypeScript; Kotlin, Rust and
Node deleted). This change does the rest.

Current state, per SDK:

| SDK | Signature check today | JOSE library already a dependency | Admin client |
|-----|----------------------|-----------------------------------|--------------|
| TypeScript | `jose` `jwtVerify` over `createLocalJWKSet` | `jose` | handwritten `admin.ts` |
| Go | `ed25519.Verify` in `hearth/verify.go` | none | handwritten |
| Python | `Ed25519PublicKey.verify` in `client.py` | `pyjwt[crypto]` (unused for the check) | handwritten `admin.py` |
| PHP | `sodium_crypto_sign_verify_detached` in `TokenVerifier.php` | `lcobucci/jwt` (unused for the check) | handwritten `AdminClient.php` |

`docs/api/openapi.json` has 94 paths, 52 of them under `/admin`. It is derived from the proto
`google.api.http` annotations by `scripts/merge_openapi.py`.

## Goals / Non-Goals

**Goals:**
- No SDK contains signature-verification code. The JOSE library checks the signature, the
  algorithm allow-list (`EdDSA`; `RS256` only where the server can issue it for ID tokens), the
  key match by `kid`, and `exp`/`nbf`/`iss`/`aud`.
- Each admin client is generated, committed, and checked for staleness in CI.
- One scenario set, four SDK runners, one live server, one verdict per scenario per SDK.

**Non-Goals:**
- New SDK features. The developer-facing API stays as it is, apart from admin method names that
  follow the generated client.
- New SDK languages.
- Rewriting the server's OpenAPI derivation. Only gaps that block a generator are fixed.

## Decisions

### 1. JOSE libraries
- **TypeScript:** `jose` (already in use). Remove any remaining handwritten claim checks that
  `jwtVerify` options already cover.
- **Go:** `github.com/go-jose/go-jose/v4` (`jose` + `jwt` packages). Apache-2.0, supports
  EdDSA, widely used. Alternative `lestrrat-go/jwx` is larger than we need.
- **Python:** `PyJWT[crypto]` (already a dependency). `jwt.decode` with `algorithms=["EdDSA"]`
  and `PyJWK` keys. Alternative `joserfc` would add a dependency for no gain.
- **PHP:** `lcobucci/jwt` v5 (already a dependency), `Signer\Eddsa` plus the `SignedWith`,
  `IssuedBy`, `PermittedFor` and `StrictValidAt` constraints. Turning a JWK `x` value into a
  key is a base64url decode, not signature code. Alternative `web-token/jwt-framework` brings
  JWKS parsing but many packages.

**Why:** prefer the library each SDK already depends on; add one only for Go.

### 2. OpenAPI generators
Recommended, to confirm with a spike per SDK (Open Question 1):
- **TypeScript:** `openapi-typescript` (types) + `openapi-fetch` (a small typed fetch runtime).
- **Go:** `oapi-codegen` (client + types).
- **Python:** `openapi-python-client`.
- **PHP:** `jane-php/open-api-3`, or `openapi-generator` (`php` target) if Jane cannot read
  the spec.

The generated code is committed under each SDK (`generated/admin/`). A `make sdk-admin-gen`
target regenerates all four, and `make sdk-admin-check` fails when the result differs from
the committed code. The handwritten `AdminClient` keeps its constructor and auth handling and
calls the generated client.

### 3. Conformance harness
- Scenarios live in one language-neutral file, `sdks/conformance/scenarios.yaml`. Each
  scenario names an input (a token kind, or a flow) and the expected outcome (claims, or an
  error class from the SDK error taxonomy in `openspec/specs/sdk-support-contract/spec.md`).
- Each SDK has a small runner (`sdks/<sdk>/conformance/`) that reads the scenarios from a JSON
  file the driver writes, runs them through the public SDK API, and prints one JSON result per
  scenario.
- The driver (`scripts/sdk-conformance.sh`, extending `scripts/sdk-smoke-local.sh`) builds
  Hearth, boots `--dev`, bootstraps, mints the tokens (valid Ed25519, tampered payload, wrong
  `kid`, `alg:none`, expired, wrong audience, wrong issuer, required action pending), runs each
  runner, and diffs the results. A difference fails and names the SDK and the scenario.
- `scripts/check-sdk-conformance.sh` (the existing static check) stays.

## Risks / Trade-offs

- [`docs/api/openapi.json` has untyped or incomplete admin schemas, so a generator emits `any`
  or fails] → Spike first (task 1.x). Fix the derivation in the server before generating.
  Do not hand-edit generated code.
- [A JOSE library rejects something Hearth issues, e.g. a header the library does not know]
  → The red test for "Ed25519 token validates" uses a real server-issued token from the
  harness, not only a locally signed one.
- [Generated admin method names are worse than the handwritten ones] → The wrapper keeps the
  ergonomic names; generated names stay internal.
- [Harness flakiness from a live server] → One server per run, sequential runners, fixed
  clock skew allowances.

## Migration Plan

No users, no migration. One PR per SDK is fine; the harness PR comes last and gates them all.

## Open Questions

1. Generator choice per SDK — confirm with a spike that the generated client compiles and is
   typed for `/admin/users`, `/admin/clients` and `/admin/roles`.
2. Should the harness also cover the OAuth flows (client credentials, device flow), or only
   token validation in its first version? Recommendation: token validation plus client
   credentials first; device flow later.
