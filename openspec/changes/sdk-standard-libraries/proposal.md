## Why

`scope-trim-trusted-core` cut the SDK set to four: TypeScript, Go, Python and PHP. It kept the
cheap part (the Node port and the three deletions) and moved the rewrite work here, so the
server trim could ship first. The rewrite work is still needed:

- Three of the four SDKs verify token signatures with their own code. Go calls
  `crypto/ed25519` directly (`sdks/go/hearth/verify.go`), Python calls `cryptography`
  (`sdks/python/src/hearth/client.py`), and PHP calls `sodium_crypto_sign_verify_detached`
  (`sdks/php/src/TokenVerifier.php`). Python and PHP already depend on `pyjwt[crypto]` and
  `lcobucci/jwt`, but do not use them for the signature check. Only TypeScript verifies through
  `jose`. Handwritten verification is where `alg`, `kid`, `crit` and key-type mistakes hide.
- Each SDK's admin client is written by hand. Each one drifts from the server on its own, and
  nothing in CI notices.
- Each SDK has its own tests against its own mocks. Nothing proves that the four SDKs give the
  same answer for the same token or the same flow.

## What Changes

- Each of the four SDKs verifies signatures, JWKS keys and registered claims through a widely
  used JOSE library that supports EdDSA/Ed25519. The handwritten verification code is deleted.
- Each SDK's admin client is generated from `docs/api/openapi.json`. A thin handwritten layer
  wraps it. CI fails when a committed generated client is stale.
- One end-to-end conformance harness runs the same scenario set against all four SDKs, against
  a live Hearth server. It extends `make sdk-smoke-local`.
- `openspec/specs/sdk-support-contract/spec.md` and the SDK guides describe the libraries, the generated clients and the
  harness.
- **BREAKING** (SDK surface): the admin client method names and types follow the generated
  client. Hearth has no users, so there is no compatibility layer.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `sdk-support-contract`: adds the requirements for JOSE-library verification, OpenAPI-generated
  admin clients and the shared conformance harness. `scope-trim-trusted-core` creates this
  capability with the "Supported SDK set" requirement only; archive it before this change.

## Impact

- **Code:** `sdks/typescript`, `sdks/go`, `sdks/python`, `sdks/php`. No server code changes.
- **Dependencies:** Go gains a JOSE library (`go-jose` or `jwx`). Python uses `PyJWT[crypto]`
  (or `joserfc`) for verification. PHP uses `lcobucci/jwt` or `web-token/jwt-framework`. Each
  SDK gains an OpenAPI generator as a dev dependency.
- **CI:** a staleness check per SDK for the generated admin client, and the conformance
  harness job.
- **Server:** `docs/api/openapi.json` becomes a contract four generators consume. Gaps in it
  (missing schemas, untyped bodies) must be fixed in the server's OpenAPI derivation first.
