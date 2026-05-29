# Changelog

All notable changes to `hearth-python` are documented here.

## [Unreleased]

### Added
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
- SDK brought into conformance with the [Hearth SDK Common Specification](../../docs/sdk-spec.md).
- All 9 required error types from spec §5 are now exported.
- Full Claims API (spec §4) implemented on verified token objects.
- JWKS caching follows the 5-rule contract from spec §2.
- README updated with installation, quickstart, and troubleshooting sections (spec §10).
