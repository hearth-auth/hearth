## Why

The spec `oidc-provider` requires PKCE (`S256`) on every authorization request, with no opt-out. The OpenID Foundation Basic OP and Dynamic OP plans send no `code_challenge` in almost every test module, so Hearth refuses them and the plans stop (#639, #780). RFC 9700 §2.1.1 lets an authorization server accept a confidential OpenID Connect client without PKCE.

The owner decision on #780 (2026-11-11) is option 3: a per-client setting "require PKCE", default on. An admin can turn it off only for a confidential client. Public clients always need PKCE.

## What Changes

- A new client setting `require_pkce` (default `true`). It can be `false` only for a client that authenticates at the token endpoint (a client secret or `private_key_jwt`). `hearth.yaml` (`realms.<realm>.applications.<slug>.require_pkce`) and the admin API (create and `PATCH /admin/applications/{id}`) set it. Dynamic client registration cannot set it.
- An authorization request without `code_challenge` from a client with `require_pkce: false` is accepted. A request that carries `code_challenge` is checked as before (`S256` only).
- A token request with a `code_verifier` for a code that was issued without a `code_challenge` is refused with `invalid_grant` (PKCE downgrade protection, RFC 9700 §4.8.2).
- The config key `oidc.require_pkce_for_confidential_clients: false` stays refused: it was a global opt-out.

## Capabilities

### New Capabilities

### Modified Capabilities
- `oidc-provider`: MODIFIED requirement "PKCE with S256 is required for every client".

## Impact

- `src/identity/oidc.rs` (client field), `src/identity/engine/oauth.rs` (the authorize gates and the code exchange), `src/protocol/web/oauth_consent.rs` (the browser gate), `src/config/types.rs` and `src/config/validate.rs`, `src/identity/reconcile.rs`, `src/protocol/http/admin.rs`, `proto/hearth/identity/v1/oauth.proto` and the generated SDK types, `src/backup/import.rs`.
- `scripts/conformance-oidf/hearth.yaml`: the two static Basic OP clients set `require_pkce: false`.
- Docs: configuration reference, API reference, backup guide. `CHANGELOG.md`.
- No store format change: client records are JSON, and a record without the field reads as `require_pkce: true`.
