## Context

SCIM 2.0 is mounted at `/scim/v2`. Every SCIM handler reads the realm from the `X-Realm-ID` header, through `scim::auth::authenticate` (or `authenticate_discovery` for the discovery endpoints). Two layers run before the handlers on that mount: the admin DPoP layer (`enforce_admin_dpop`) and the router-wide guards. The DPoP layer also reads the realm from `X-Realm-ID`.

The realm-path routes (`/realms/{realm_name}/token`, `/end_session`, …) are nested under `/realms/{realm_name}` and share the `realm_path_header_agreement` guard. That guard refuses a request whose `X-Realm-ID` disagrees with the path realm. `realm_end_session` resolves the realm by name in the handler and inserts `X-Realm-ID` into a copy of the headers before it calls the shared handler.

SCIM handlers build `meta.location` and `Location` from the fixed string `/scim/v2`.

## Goals / Non-Goals

**Goals:**

- One SCIM implementation, served at both bases.
- The realm path keeps every guard the header mount has: realm-status gate, credential check, rate limit, DPoP sender constraint, header agreement.
- URLs in responses use the base the client used.

**Non-Goals:**

- Absolute URLs. `meta.location` stays a path, as today.
- Removing `/scim/v2`.

## Decisions

### Set `X-Realm-ID` in a middleware, outside the DPoP layer

A middleware on the realm-path SCIM mount resolves `{realm_name}` and sets `X-Realm-ID` on the request. It runs after the agreement guard and before the DPoP layer.

Alternative: resolve in each handler, as `realm_end_session` does. Rejected. The DPoP layer runs before the handler and reads `X-Realm-ID`. Without the header it finds no realm and passes the request through. A DPoP-bound token would then replay as a plain Bearer on the realm path. The middleware also keeps the twelve SCIM handlers unchanged in their auth code.

The middleware answers `404` with a SCIM error body when the realm name is unknown. The agreement guard runs first and passes unknown realms through, so the `404` comes from the SCIM mount.

### The agreement guard reads the realm parameter by name

The guard extracted `Path<String>`. Under `/realms/{realm_name}/scim/v2/Users/{id}` the route has two parameters, and that extractor fails. The guard now reads the `realm_name` parameter by name. SCIM handlers that take `{id}` read it by name for the same reason.

### Base path from a request extension

The realm-path middleware stores the base path (`/realms/{name}/scim/v2`) in a request extension. A SCIM extractor reads it and falls back to `/scim/v2`. The name comes from the resolved realm, so it is the realm's canonical name. Realm names allow only ASCII letters, digits, `-` and `_`, so the name needs no URL encoding.

Alternative: derive the base from `OriginalUri` minus the nested path. Rejected: it depends on how `nest` rewrites the URI, and it would copy a percent-encoded name into the response.

### Remove the dead realm comparison in the admin-token fallback

`scim::auth::admin_jwt` compared `AdminAuth::realm_id` with the realm read from `X-Realm-ID`. `extract_admin_auth` reads `AdminAuth::realm_id` from the same header, so the comparison could never fail. The real binding is in `validate_token`: it refuses a token whose `tid` is not the requested realm. A test proves that an admin token of one realm gets `401` on another realm's path.

## Risks / Trade-offs

- [Two lookups of the realm per realm-path request: the agreement guard and the SCIM middleware] → Both are in-memory reads off the hot path.
- [The header mount and the realm mount could drift] → Both mounts use the same `scim::router()`. Only the outer middleware differs.
