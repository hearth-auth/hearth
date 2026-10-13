## Context

Two macros define the entity ID newtypes: `define_id_type!` in `src/core/types.rs` (`RealmId`, `UserId`, `SessionId`, `ClientId`, `OrganizationId`, `AgentId` and seven more) and `define_rbac_id!` in `src/rbac/types.rs` (`RoleId`, `GroupId`, `AssignmentId`). Each `Display` writes a kind prefix and the UUID. Serde writes the bare UUID, because each type is a newtype over `Uuid`. So a JSON body shows `"id": "<uuid>"`, and a token built with `to_string()` shows `"sub": "user_<uuid>"`.

The token `sub` names three kinds of subject today: a user (`user_<uuid>`), an OAuth client (`client_<uuid>`) and an agent (`agt_<uuid>`, built by hand in `aat.rs` and `txn.rs`). `client-authentication` requires the `client_<uuid>` form for a sessionless client token, because a client and a user can share no subject namespace.

## Goals / Non-Goals

**Goals:**
- One ID per entity on every surface: the bare UUID.
- A token `sub` that tells its subject's kind without a lookup, for clients and agents.
- Tokens issued before the upgrade stay valid until they expire.

**Non-Goals:**
- Migration of stored delegation grants. Hearth has no users.
- The capability-token caller binding (see below).
- The proto `go_package` options (see the proposal).

## Decisions

### `Display` writes the bare UUID; `FromStr` keeps the prefix optional

Both macros write `self.0` only. `FromStr` on `define_id_type!` already strips an optional prefix, so it accepts both forms. `define_rbac_id!` has no `FromStr`; the admin handlers strip `role_`, `group_` and `assign_` by hand, and they keep doing so.

The other choice was to keep `Display` and change each issuance site to `as_uuid()`. It leaves the trap in place: the next `to_string()` into a claim or a body brings the prefix back. With a bare `Display`, the prefix exists only where a type names it on purpose.

### A token-subject type in `core`

`TokenSubject { User(UserId), Client(ClientId), Agent(AgentId) }` in `src/core/` owns both directions:
- `Display`: user → bare UUID, client → `client_<uuid>`, agent → `agt_<uuid>`.
- `TokenSubject::parse(&str)`: a `client_` prefix names a client, an `agt_` prefix names an agent, and a `user_` prefix or a bare UUID names a user. Any other text is refused. It does not allocate, because `validate_token` calls it on the hot path.

Every client and agent issuance site builds `sub` from it. A user's `sub` is the `UserId`'s `Display`, which is the same text. Every site that compares a claim with a client's subject compares with `TokenSubject::Client(..)`, not with `ClientId`'s `Display`, which no longer carries the prefix. The strict `parse_user_id_claim` and `parse_session_id_claim` in `engine/mod.rs` call `TokenSubject::parse` and `SessionId::from_str`, so they accept both forms. A `client_` or `agt_` subject is still not a user: `parse_user_id_claim` refuses it, as it does today.

### The capability token keeps its bare agent UUID

The approval capability token carries `sub` = the bare agent UUID. Only `validate_capability_token` reads it, and it compares that `sub` with the caller's access-token `sub`. The token is not a general token, and `TokenSubject` does not apply to it. A separate defect is out of scope here: `POST /v1/tools/invoke` accepts a bearer only through `validate_token`, and no token that `validate_token` accepts has an agent as its `sub`. So no agent can present a capability token over HTTP today, with either ID format.

### Delegation grants store the bare user UUID

A grant stores `user_sub` from the subject token and indexes it under `dgrant:user:{user_sub}:…`. The list and revoke paths look it up with the user's `Display`, which is now bare. A grant stored before the upgrade has the prefixed key, so the user's list does not find it. Hearth has no users, so the change does not migrate stored grants, and the CHANGELOG says so.

### The Go module moves to `/v4` in the same change

The SDK releases read every commit, so this change's `!` makes the next Go SDK release v4.0.0. The release guard refuses a v4 release from a `/v3` module path, so the path changes here.

## Risks / Trade-offs

- **A site that compares a claim with an ID's `Display` changes meaning silently.** The compiler does not see it. Mitigation: the inventory lists every comparison (client `sub` in token exchange, revocation and introspection), and each one gets a test through the public API.
- **An integrator that strips `user_` from `sub` keeps working**, because a bare UUID has no prefix to strip. An integrator that adds `user_` to match the token breaks. Hearth has no users.
