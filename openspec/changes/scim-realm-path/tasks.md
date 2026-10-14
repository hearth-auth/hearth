## 1. Tests first

- [x] 1.1 Write `tests/scim_realm_path.rs`: provisioning token and admin token through the realm path (`201`, user in the realm, `GET` of `meta.location`), disagreeing header (`400`), unknown realm (`404`), cross-realm credentials (`401`), the `/scim/v2` mount with the header, the user lifecycle and groups and discovery under the realm path. Run it and see it fail.
- [x] 1.2 Add `scim_realm_path_rejects_bound_token_replayed_as_plain_bearer` and `scim_realm_path_accepts_bound_token_with_a_valid_proof` to `tests/admin_dpop_sender_constraint.rs`. Run them and see them fail.
- [x] 1.3 Add the realm-path SCIM paths to `supplement_routes_present_in_merged_spec` in `tests/openapi.rs`. Run it and see it fail.

## 2. Routing

- [x] 2.1 Mount `scim::router()` under `/realms/{realm_name}/scim/v2`, with a middleware that resolves the realm and sets `X-Realm-ID` before the admin DPoP layer (tests 1.1, 1.2).
- [x] 2.2 Make `realm_path_header_agreement` read the `realm_name` parameter by name, and make the SCIM `{id}` handlers read `id` by name (test 1.1, lifecycle).

## 3. Response URLs

- [x] 3.1 Build `meta.location` and `Location` from the request's base path (test 1.1, `assert_created` and lifecycle).

## 4. Auth cleanup

- [x] 4.1 Remove the comparison of the header with itself in `scim::auth::admin_jwt` (test `an_admin_token_cannot_act_on_another_realm_through_its_path`).

## 5. Docs and contract

- [x] 5.1 Add the realm-path SCIM operations to `docs/api/openapi.supplement.yaml` and regenerate `docs/api/openapi.json` (test 1.3).
- [x] 5.2 Make the realm path the recommended base URL in `docs/guides/scim-provisioning.md`, and fix the SCIM base URL in `README.md` and the `hearth.yaml` example guides.
- [x] 5.3 Add a `CHANGELOG.md` entry under `## [Unreleased]` → `### Added`.
