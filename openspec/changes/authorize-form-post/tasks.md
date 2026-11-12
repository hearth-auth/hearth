## 1. Tests first (red)

- [x] 1.1 `tests/hea_2109_discovery_endpoint_routing.rs`: a form POST to `/authorize` and to `/realms/{realm}/authorize` answers `303` to the UI authorize page with the posted parameters, the same as a GET; a form POST with `charset` is still a form POST; a JSON POST without a Bearer token keeps its `401` JSON answer.
- [x] 1.2 Run the file: the form POST cases fail with `415` (red).

## 2. Implementation

- [x] 2.1 `AuthorizePost` extractor in `src/protocol/http/oauth.rs`: form body to the browser path, other bodies to the JSON API.
- [x] 2.2 One redirect helper for the GET and the form POST.
- [x] 2.3 Run the new tests and the existing authorize tests (green).

## 3. Close-out

- [x] 3.1 `CHANGELOG.md` `Fixed` entry.
- [ ] 3.2 OpenID Foundation run: `oidcc-ensure-post-request-succeeds` passes (next `make conformance-oidf` run).
