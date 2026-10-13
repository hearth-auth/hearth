## 1. Tests first (red)

- [x] 1.1 `tests/metadata_cross_origin.rs`: a `GET` with an `Origin` header to each metadata route (root and realm discovery, the four JWKS paths, protected-resource metadata) gets `Access-Control-Allow-Origin: *` and no `Access-Control-Allow-Credentials`; an unknown realm's discovery `404` gets it too.
- [x] 1.2 Same file: `/userinfo` and `/token` (without a registered origin) get no `Access-Control-Allow-Origin: *`.
- [x] 1.3 Run the file: the metadata cases fail (red).

## 2. Implementation

- [x] 2.1 A `map_response` route layer in `src/protocol/http/oauth.rs` on the metadata routes of `routes()` and `realm_routes()`.
- [x] 2.2 Run the new tests and the existing discovery and JWKS tests (green).

## 3. Close-out

- [x] 3.1 `CHANGELOG.md` `Fixed` entry.
- [ ] 3.2 Full-stack demo: the dashboard shows the user's roles (in the demo-repair PR).
- [x] 3.3 `make ci-local-fast`.
