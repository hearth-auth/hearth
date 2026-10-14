## Why

SCIM 2.0 is mounted only at `/scim/v2`, and the `X-Realm-ID` header selects the realm. An IdP such as Okta or Entra takes a SCIM base URL and a bearer token. Many IdPs cannot send a custom header, so they cannot provision into Hearth at all. Every other per-realm protocol surface already names its realm in the path, under `/realms/{realm_name}/`. The first real-world SCIM integration hit this gap.

## What Changes

- Mount SCIM 2.0 also at `/realms/{realm_name}/scim/v2`. The path selects the realm. The client sends no `X-Realm-ID`.
- Keep `/scim/v2` with `X-Realm-ID` working, unchanged.
- The realm-path mount accepts both SCIM credentials: the realm's provisioning token and an admin access token of that realm.
- A realm-path request whose `X-Realm-ID` names another realm is refused with `400` (`realm_mismatch`), as on every other realm-path route.
- An unknown realm name answers `404`.
- `meta.location` and the `Location` header use the base path the client used.
- The DPoP sender constraint on SCIM applies to the realm path as well.
- The SCIM provisioning guide recommends the realm path as the base URL.

## Capabilities

### New Capabilities

- `scim-provisioning`: the SCIM 2.0 provisioning surface. This change adds the requirement for the realm-path base URL.

### Modified Capabilities

None. No capability in `openspec/specs/` specifies SCIM routing. `ui-routing` covers only the admin console's `/ui/admin/realms/{realm_name}/…` URLs.

## Impact

- HTTP router: a second SCIM mount under `/realms/{realm_name}`.
- SCIM handlers: the base path for `meta.location` and `Location` comes from the request.
- OpenAPI supplement: the realm-path SCIM operations.
- Docs: `docs/guides/scim-provisioning.md`, `README.md`, the `hearth.yaml` example guides.
- No storage, config or SDK change.
