## Why

One user has two IDs. The admin API, SCIM and the console show a user's bare UUID, but the user's access token carries `sub` = `user_<uuid>`. Token claims use an ID's `Display`, which adds a kind prefix (`user_`, `session_`, `realm_`, …). Serde and `as_uuid()` give the bare UUID, and nearly every other surface uses them. So an application that stores the SCIM `id` and later reads the token's `sub` cannot match them without code that strips the prefix. The first real-world integration hit this. Hearth has no users yet, so this is the right time to break the format once.

## What Changes

- **BREAKING:** every entity ID's `Display` writes the bare, lowercase UUID. This changes the token claims `sid`, `tid` and `oid`, the user `sub`, the logout token's `sub` and `sid`, the agent API's `agent_id`, the pre-token webhook IDs, audit record IDs and the backup manifest's `realm_id`.
- One token-subject type names the subject of every token Hearth issues:
  - a user: the bare UUID, equal to the user's `id` in the admin API and SCIM
  - an OAuth client (sessionless `client_credentials` and JWT-bearer tokens): `client_<uuid>`, as `client-authentication` requires
  - an agent: `agt_<uuid>`
- Every parser of an ID or a claim accepts the bare form and the prefixed forms that earlier releases issued. A token issued before the upgrade stays valid until it expires.
- **BREAKING:** delegation grants store the bare user UUID. A grant stored before the upgrade no longer shows in the user's list and cannot be revoked by the user. It expires on its own.
- **BREAKING** for Go importers: the SDKs move to v4 with the server, so the Go module path becomes `github.com/hearth-auth/hearth/sdks/go/v4`. The release guard from `sdk-go-module-major` refuses a v4 release without it.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `rbac-token-claims`: adds the requirement "Entity IDs are bare UUIDs", which fixes the token-subject forms.
- `rp-initiated-logout`: the logout token's `sub` and `sid` are the bare UUIDs that the ID token carries.
- `rbac-admin-api`: group membership takes bare member IDs and still accepts the prefixed forms.
- `agent-identity`: the agent API returns `agent_id` bare; an agent's token `sub` is `agt_<uuid>`.

## Impact

- `src/core/types.rs` and `src/rbac/types.rs` (the ID macros), a new token-subject type in `src/core/`.
- Token issuance in `src/identity/tokens.rs`, `engine/mod.rs`, `engine/oauth.rs`, `operator_token.rs`, `aat.rs` and `txn.rs`.
- Claim parsers in `src/identity/engine/`, `src/protocol/http/auth.rs`, `admin.rs`, `src/protocol/web/admin/rbac.rs` and `src/backup/`.
- Tests that state the prefixed format, the SDK docs and READMEs, and the guides that show prefixed IDs.
- `sdks/go/go.mod` and every Go import of the SDK, in the SDK, the examples and the docs.
- Not in this change: the approval capability token keeps its bare agent UUID `sub`. Only `validate_capability_token` reads it.
- Not in this change: the proto `go_package` options still name `github.com/hearthdb/...`. `buf breaking` (`FILE_SAME_GO_PACKAGE`) refuses a change to them, and no code imports the packages they name.
