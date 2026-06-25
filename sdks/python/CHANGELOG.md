# Changelog

All notable changes to `hearth-python` are documented here.

## [Unreleased]

### Added
- **`generate_pkce_pair()`** — RFC 7636 S256 PKCE helper; returns a `PkcePair(code_verifier, code_challenge)` (HEA-1561).
- **`JwksCache`** — JWKS key cache with TTL, `Cache-Control: max-age` respect, 24-hour cap, and re-fetch on cache miss. Supports OKP/Ed25519 keys; silently skips unrecognised `kty` values per spec §2 (HEA-1561).
- **`HearthClient.verify_token(token, audience?, issuer_url?)`** — full Ed25519/EdDSA local signature verification backed by `JwksCache`; performs all five mandatory JWT validation steps (signature, exp, iss, aud, iat); returns typed `Claims` on success and typed §5 errors on failure. Does not delegate to introspection (HEA-1561 §7.1).
- **`HearthClient.client_credentials(scope?)`** — Client Credentials grant (RFC 6749 §4.4) for M2M authentication; `client_id` and `client_secret` are sent as `application/x-www-form-urlencoded` body fields (HEA-1561 §7.2).
- **`HearthClient.start_device_flow(scope?)`** — initiates Device Authorization Flow (RFC 8628); returns `DeviceAuthorizationResponse` with `device_code`, `user_code`, and `verification_uri` (HEA-1561 §7.2).
- **`HearthClient.poll_device_token(device_code)`** — single-probe device token poll; returns `None` on `authorization_pending`/`slow_down`; raises `TokenExpiredError` on `expired_token` (HEA-1561 §7.2).
- **`HearthClient.request_magic_link(email)`** — initiates passwordless magic-link email via `POST /v1/{realm}/auth/magic-link`; silently passes 202 responses (enumeration resistance); surfaces 429 as `HearthError` (HEA-1561 §7.2).
- **`HearthClient.sv_snapshot(access_token)`** — fetches full session-version snapshot from `GET /oauth/session-versions/snapshot` (HEA-1561).
- **`HearthClient.sv_delta(access_token, since)`** — fetches session-version deltas from `GET /oauth/session-versions?since=<seq>`; returns `None` on 204 (HEA-1561).
- **`DeviceAuthorizationResponse`**, **`SvDeltaEntry`**, **`SvDeltaResponse`**, **`SvSnapshotResponse`**, **`PkcePair`** Pydantic models / dataclasses added to public exports.
- `HearthClient` constructor now accepts `client_id`, `client_secret`, `jwks_ttl` keyword parameters.
- `TokenResponse.refresh_token` is now `Optional[str]` (client-credentials responses do not include a refresh token).

### Changed
- `HearthClient.has_permission`, `has_role`, `in_group`, `in_org` predicates now use `Claims.decode` internally instead of `pyjwt.decode`; behaviour is unchanged.
- **`cryptography>=41`** added as an explicit dependency (previously implicit via `pyjwt[crypto]`).

- **`client.check_permission(access_token, permission, **opts)`** — calls `POST /oauth/authorize`
  for a live per-request permission decision (decision mode). Fail-closed: any network or server
  error returns `CheckPermissionResponse(allowed=False)` rather than raising (HEA-926).
- **`client.introspect(access_token, client_id, **opts)`** — calls RFC 7662
  `POST /realms/{realm_id}/introspect`. Response includes a `mode` field that middleware
  MUST validate against the configured expected mode (HEA-926).
- **`RequirePermissionMiddleware`** — ASGI middleware (Starlette, FastAPI) that enforces
  a named permission using an explicit `mode`. Never auto-detects mode from JWT claim
  presence (HEA-926 design constraint).
- **`WsgiPermissionMiddleware`** — WSGI middleware (Flask, Django) with identical
  mode-awareness contract (HEA-926).
- **`AuthorizationModeMismatchError`** — raised when the introspection response echoes a
  mode that differs from the configured expectation; middleware maps this to a 403 denial.
- **`AccessTokenAuthorizationMode`** type alias (`Literal["embedded", "introspection", "decision"]`).
- **`IntrospectRequest`**, **`IntrospectResponse`**, **`CheckPermissionRequest`**,
  **`CheckPermissionResponse`** Pydantic models.

### Changed
- SDK brought into conformance with the [Hearth SDK Common Specification](../../docs/specs/SDK.md).
- All 9 required error types from spec §5 are now exported.
- Full Claims API (spec §4) implemented on verified token objects.
- JWKS caching follows the 5-rule contract from spec §2.
- README updated with installation, quickstart, and troubleshooting sections (spec §10).
