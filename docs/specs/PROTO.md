# Hearth — Proto Authoring Guide

This document is the canonical reference for authoring `.proto` files in Hearth.
All proto changes are governed by `buf` — lint, format, and breaking-change checks
run in CI (`proto.yml`) and in the pre-commit hook. Read this before touching
anything under `proto/`.

## Tooling

| Command | What it does |
|---------|-------------|
| `make proto-lint` | Runs `buf lint` against `STANDARD` rules (fails if violations exist) |
| `make proto-format` | Runs `buf format -w` — rewrites files in-place |
| `make proto-format-check` | Runs `buf format --diff --exit-code` — CI gate, does not modify files |
| `make proto-breaking` | Checks backward-compatibility against `main` |
| `make proto-gen` | Regenerates TypeScript + Go + OpenAPI artifacts from proto sources |
| `make proto-check` | Regenerates and diffs — fails if committed artifacts are stale |

The pre-commit hook runs format → lint → generate automatically whenever
`.proto` files are staged, keeping commits atomic.

`buf` is **required** — install it before making any proto changes:

```bash
brew install bufbuild/buf/buf          # macOS
# or: https://buf.build/docs/installation
```

## File Organization

```
proto/
  buf.yaml          # workspace config, lint rules, breaking policy
  buf.gen.yaml      # codegen plugins (TS + Go + OpenAPI)
  buf.lock          # pinned dependency digests — commit this file
  hearth/
    identity/v1/    # identity service RPCs and types
    rbac/v1/        # RBAC service RPCs and types
    events/v1/      # audit event types
```

All proto files belong to the `hearth.<service>.v1` package. Do not introduce
new top-level packages without a discussion — the versioning suffix (`v1`) is
load-bearing for breaking-change detection.

## Package and File Naming

- Package: `hearth.<service>.v1` (all lowercase, dot-separated).
- File: `snake_case.proto`, placed under `hearth/<service>/v1/`.
- One proto file per logical service boundary.
- `go_package` option is **required** on every file:

```proto
option go_package = "github.com/hearthdb/hearth/sdks/go/generated/<service>/v1;<service>v1";
```

## RPC Naming

- Use `VerbNoun` for RPC names: `CreateUser`, `GetRealm`, `ListSessions`, `DeleteRole`.
- Avoid ambiguous verbs: prefer `Get` (single resource) / `List` (collection) over `Fetch`.
- `Update` means partial update (PATCH semantics). `Replace` means full replace (PUT).

### `google.api.http` Bindings

Every RPC that is exposed over HTTP MUST have a `google.api.http` annotation.
Use standard REST verbs:

| RPC intent | HTTP method | URL pattern |
|-----------|------------|-------------|
| Create resource | `POST` | `/v1/{parent}/resource` |
| Get single resource | `GET` | `/v1/{parent}/resource/{id}` |
| List resources | `GET` | `/v1/{parent}/resources` |
| Update resource | `PATCH` | `/v1/{parent}/resource/{id}` |
| Delete resource | `DELETE` | `/v1/{parent}/resource/{id}` |

Example:

```proto
rpc CreateUser(CreateUserRequest) returns (User) {
  option (google.api.http) = {
    post: "/v1/users"
    body: "*"
  };
}

rpc GetUser(GetUserRequest) returns (User) {
  option (google.api.http) = {
    get: "/v1/users/{id}"
  };
}
```

gRPC-only RPCs (no HTTP exposure) MAY omit the annotation — document the
intent in a comment above the RPC definition.

## Message Design

### Field Naming

- Field names are `snake_case` in proto; generated code follows target-language
  conventions automatically (`camelCase` in TypeScript/Go JSON output).
- Timestamps are `int64` microseconds since Unix epoch. Field name suffix: `_at`
  (e.g., `created_at`, `expires_at`).
- IDs are `string` (UUID or prefixed string like `usr_…`). Never use `int64` IDs.

### `json_name` for External Schemas

When a field must serialize to a specific JSON key to conform to an external
standard (SCIM, OpenID Connect, OAuth 2.0), add an explicit `[json_name = "..."]`
annotation. This overrides the default camelCase derivation:

```proto
// SCIM 2.0 §3.3 requires "userName" not "email".
string email = 1 [json_name = "userName"];

// OIDC Discovery §3 mandates underscore_case keys.
string issuer = 1 [json_name = "issuer"];
string jwks_uri = 2 [json_name = "jwks_uri"];
```

**Only add `json_name` when an external spec requires it.** Do not use it to
work around naming preferences — fix the field name instead.

### Optional Fields

Use `optional` for fields that may be absent in update requests:

```proto
message UpdateRealmRequest {
  optional string name = 1;
  optional RealmStatus status = 2;
}
```

`optional` on a scalar field generates a pointer (`*string` in Go, `string | undefined`
in TypeScript), enabling the caller to distinguish "not set" from the zero value.

### Enumerations

- Enum names: `UpperCamelCase`.
- Value names: `SCREAMING_SNAKE_CASE`, prefixed with the enum name.
- The zero value MUST be `UNSPECIFIED` (e.g., `USER_STATUS_UNSPECIFIED = 0`).

```proto
enum SessionLimitPolicy {
  SESSION_LIMIT_POLICY_UNSPECIFIED = 0;
  SESSION_LIMIT_POLICY_REJECT_NEW = 1;
  SESSION_LIMIT_POLICY_EVICT_OLDEST = 2;
}
```

> **Note:** `ENUM_VALUE_PREFIX` and `ENUM_ZERO_VALUE_SUFFIX` lint rules are
> grandfathered off for pre-existing violations (see `buf.yaml`). New enums
> MUST comply with both rules.

## Documentation Comments

All public messages, enums, and RPC methods MUST have a doc comment directly
above the definition. Comments go above the field for fields that need
explanation; omit them for self-evident fields.

```proto
// A user record within a realm.
message User {
  string id = 1;
  string email = 2;
  // Actions the user must complete before full access is granted.
  // Values: "VERIFY_EMAIL", "UPDATE_PASSWORD".
  repeated string required_actions = 9;
}
```

## Backward Compatibility

Hearth uses `FILE`-level breaking-change detection (configured in `buf.yaml`).
The following changes are **always breaking** and require CTO sign-off:

- Removing or renaming a field, message, enum, or RPC.
- Changing a field number.
- Changing a field type (including scalar ↔ message).
- Removing a `google.api.http` binding (breaks HTTP clients).

The following changes are **safe**:

- Adding a new field (with a new field number).
- Adding a new RPC.
- Adding a new enum value.
- Adding or updating a `google.api.http` binding on an existing RPC.
- Adding a comment.

## Pre-existing Lint Exceptions

The following rules are disabled in `buf.yaml` for pre-existing violations.
New code MUST NOT introduce new violations of these rules — they are tracked
for cleanup in [HEA-969](/HEA/issues/HEA-969):

| Rule | Reason grandfathered |
|------|---------------------|
| `RPC_REQUEST_RESPONSE_UNIQUE` | Services share resource types (`User`, `Realm`, `Role`) |
| `RPC_REQUEST_STANDARD_NAME` | `*Call` wrappers predate strict naming |
| `RPC_RESPONSE_STANDARD_NAME` | Resource types as response predate strict naming |
| `ENUM_VALUE_PREFIX` | `AccessTokenAuthorization` values predate prefix rule |
| `ENUM_ZERO_VALUE_SUFFIX` | `AccessTokenAuthorization` zero value predate suffix rule |

## Workflow Summary

```bash
# 1. Edit proto files
vim proto/hearth/identity/v1/identity.proto

# 2. Format in-place
make proto-format

# 3. Lint (must pass before committing)
make proto-lint

# 4. Regenerate SDK artifacts
make proto-gen

# 5. Verify no stale artifacts are committed
make proto-check

# 6. Commit — pre-commit hook repeats steps 2–4 automatically
git add proto/ sdks/typescript/src/generated sdks/go/generated
git commit -m "feat(proto): ..."
```
