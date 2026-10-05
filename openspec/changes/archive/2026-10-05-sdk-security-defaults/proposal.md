## Why

`security-hardening` found five SDK gaps against the `sdk-support-contract` baseline. The `sdk-standard-libraries` rewrite did not close them. Several fixes change SDK APIs (async claim checks, instance methods, token storage), so they need their own change and must ship before the v3.0.0 release.

The owner also corrected the spec. It said to check `aud` against the client ID. That rule is for ID tokens (OIDC Core). An access token names the API that may accept it (RFC 9068 §4), and Hearth mints `aud` `hearth` unless the client names a resource. So the SDKs gain an `audience` option, with default `hearth`, and the check is always on.

The detail of each gap is kept in the draft repository security advisory `GHSA-hxcr-696v-vqw3` (maintainers only).

## What Changes

- All four SDKs: an `audience` option, default `hearth`, checked on every access token.
- TypeScript: refuse a token whose `iat` is in the future.
- TypeScript: the `createHearth` claim checks verify the signature. They become async.
- Python: `has_permission`, `has_role`, `in_group` and `in_org` verify the signature. They become instance methods.
- TypeScript: `createHearthAuth` stops keeping tokens in `localStorage`. It defaults to `sessionStorage`, takes a `storage` option and a key prefix, and removes the old keys once.
- The conformance harness gains the audience and future-`iat` scenarios.
- **BREAKING** (SDK API): the async TypeScript claim checks, the Python instance methods, and the TypeScript token getters moving onto the returned auth object. Hearth has no production users, so there is no deprecation path.
- `CHANGELOG.md`: `### Security` and `### Changed` entries per SDK.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `sdk-support-contract`: "JWT validation steps" (audience rule corrected, scenarios added), "Claim checks verify the token signature" and "Browser login flow" (scenarios added).

## Impact

- **Code:** `sdks/typescript/`, `sdks/go/`, `sdks/python/`, `sdks/php/`, `sdks/conformance/`, the SDK guides under `docs/guides/`.
- **Order:** after `sdk-standard-libraries`, whose delta touches other requirements of the same capability. Must land before the v3.0.0 cut.
