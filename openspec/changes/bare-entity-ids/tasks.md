## 1. Tests first

- [x] 1.1 Unit tests in `src/core/types.rs`: every ID type's `Display` is the bare UUID, and `FromStr` accepts the bare and the prefixed forms. The same for `RoleId`, `GroupId` and `AssignmentId` `Display`.
- [x] 1.2 Unit tests for `TokenSubject`: `Display` for each kind, and `parse` of the bare, `user_`, `client_` and `agt_` forms and of bad text.
- [x] 1.3 Black-box test `tests/bare_entity_ids.rs`:
  - a user created through SCIM signs in, and the access token's `sub` equals the SCIM `id`; `sid` and `tid` are bare UUIDs
  - a `client_credentials` token's `sub` is `client_<uuid>`, and the client can introspect and revoke its own token
  - a token issued with the prefixed `sub` and `sid` passes `validate_token` and `/userinfo`
  - the back-channel logout token's `sub` and `sid` equal the ID token's
- [x] 1.4 Run them red.

## 2. Implementation

- [x] 2.1 Both ID macros write the bare UUID.
- [x] 2.2 Add `TokenSubject` in `src/core/`.
- [x] 2.3 Build client and agent token subjects with `TokenSubject`: `client_credentials` and JWT-bearer; `aat.rs` and `txn.rs`. A user's `sub` follows `UserId`'s `Display`.
- [x] 2.4 Replace the strict prefix parsers with `TokenSubject::parse` and `FromStr`: `parse_user_id_claim`, `parse_session_id_claim`, `refresh_tokens_for_resource`, `userinfo_inner`, `admin_bootstrap`.
- [x] 2.5 Compare client subjects with `TokenSubject::Client`: token exchange, revocation ownership, introspection ownership.
- [x] 2.6 The backup export writes the bare `realm_id`; the import accepts both forms.
- [x] 2.7 Run the tests green. Update the tests that state the prefixed format.

## 3. Go SDK v4

- [x] 3.1 Set `sdks/go/go.mod` to `.../sdks/go/v4` and update every import, `replace` line and doc reference.
- [x] 3.2 Run the release guard with `4.0.0`: it passes. `go build`, `go vet` and `go test` pass in `sdks/go` and in both examples.

## 4. Docs and close out

- [x] 4.1 Update the guides, SDK READMEs and examples that show prefixed IDs as Hearth output.
- [x] 4.2 `CHANGELOG.md` entry under `Changed` (**BREAKING**).
- [ ] 4.3 `make check` and `make test-detached`.
- [ ] 4.4 `make ci-local-fast`.
