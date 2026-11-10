## Why

A browser application verifies Hearth's tokens with the TypeScript SDK (`createHearth({ issuerUrl })`). The SDK fetches `{issuerUrl}/.well-known/openid-configuration` and the `jwks_uri` it names, from the page's own origin. Hearth sends no `Access-Control-Allow-Origin` on those responses, so a browser refuses to give them to a page on another origin. Every role, permission and group check then reports `false`.

An SPA almost always runs on another origin than its identity provider (`app.example.com` and `auth.example.com`). The full-stack demo shows the defect: the token carries `roles: ["editor"]`, but the dashboard shows "no roles". A first real-world integration copies this demo.

## What Changes

- The public metadata documents answer a cross-origin `GET` with `Access-Control-Allow-Origin: *`:
  - discovery: `/.well-known/openid-configuration` and `/realms/{realm}/.well-known/openid-configuration`
  - the JWKS: `/.well-known/jwks.json`, `/jwks`, `/certs` and `/realms/{realm}/.well-known/jwks.json`
  - RFC 9728 protected-resource metadata: `/.well-known/oauth-protected-resource`
- These responses carry no `Access-Control-Allow-Credentials`, and no other route gets the header.

## Capabilities

### New Capabilities

### Modified Capabilities
- `oidc-provider`: ADDED requirement "Public metadata answers cross-origin reads".

## Impact

- `src/protocol/http/oauth.rs` (route layers on the metadata routes).
- `CHANGELOG.md`. No config, proto, storage or SDK change.
