# rbac-model Specification

## Purpose
Claims-based RBAC: roles, groups, permissions, the resolution algorithm, and the tenancy invariants of authorization. Permissions are resolved at token issuance and embedded in the token; authorization is not on the hot path.
## Requirements
### Requirement: Authorization is claims-based RBAC resolved at token issue
Hearth SHALL grant a user permissions only through roles: roles assigned to the user directly, and roles assigned to groups the user belongs to. Hearth SHALL resolve the effective permission set when it issues an access token and SHALL embed that set in the token as a claim. Clients read permissions from the token without a call to Hearth. Servers verify the token and authorize against the same claim.

#### Scenario: A role assigned to a user reaches the token
- **WHEN** an admin creates a role with `docs.edit`, assigns it to a user, and the user obtains an access token
- **THEN** the token's `permissions` claim contains `docs.edit`

#### Scenario: A role assigned to a group reaches its members
- **WHEN** a user is added to a group and a role is assigned to that group
- **THEN** resolution for that user includes the role's permissions

### Requirement: Resource-specific authorization stays in the application
Hearth SHALL answer only which roles, groups and permissions a user has. Hearth SHALL NOT decide whether a user may act on one specific resource given that resource's state. Ownership checks, quota enforcement and business rules belong to the application, which uses Hearth claims as one input.

#### Scenario: An application checks ownership of a document
- **WHEN** an application must decide whether Alice may edit one particular document
- **THEN** Hearth supplies Alice's claims, and the application makes the decision with its own data

### Requirement: No relationship-based or policy-engine authorization
Hearth SHALL NOT provide graph-structured ACLs, delegated sharing, or per-object grants. Hearth SHALL NOT ship a policy engine (Cedar, Rego, Polar). Applications MAY layer a policy engine on top of the claims. Teams that need relationship-based authorization pair Hearth with a dedicated service such as SpiceDB, OpenFGA or Cerbos.

#### Scenario: A per-object grant is needed
- **WHEN** an operator looks for a way to share one object with one user
- **THEN** Hearth offers no per-object grant, and the claims remain realm- or organization-wide

### Requirement: Permission changes take effect on the next token issue
A change to roles, groups or assignments SHALL reach a token at the next access-token issue or refresh. Hearth SHALL NOT push permission changes to connected clients in real time. Session revocation is the emergency mechanism: Hearth's own token validation SHALL refuse every token of a revoked session at once. A resource server that verifies an `embedded` token locally keeps accepting it until it expires. Operators choose the access-token TTL per security posture.

#### Scenario: A role is revoked
- **WHEN** an admin removes a role from a user who holds an unexpired access token
- **THEN** the existing token still carries the old permissions
- **AND** the next token issued for that user does not carry them

#### Scenario: A session is revoked
- **WHEN** an admin revokes a session while one of its access tokens is unexpired
- **THEN** Hearth refuses that token at its own endpoints from then on

### Requirement: Every RBAC entity belongs to exactly one realm
Every user, organization, group, role, role assignment and group membership SHALL live in exactly one realm. A permission is not a stored entity: it is a validated string, scoped to the realm through the token's `tid`. A role assignment binds a user or a group to a role, with a realm-level or organization-level scope. An organization is a B2B grouping inside a realm, with `owner`, `admin` and `member` membership shortcuts for role assignment.

#### Scenario: A role is looked up from another realm
- **WHEN** a role is created in realm A and looked up by ID in realm B
- **THEN** the lookup finds nothing

### Requirement: Roles compose through parent roles
A role MAY include one or more parent roles. A role's effective permission set SHALL be the union of its own permissions and the effective permission sets of its parents. Hearth SHALL reject a parent chain that forms a cycle with a `CycleDetected` error. A parent chain SHALL be at most 10 hops deep; a deeper chain SHALL be rejected with a `DepthExceeded` error. Duplicate permissions reached through several parents SHALL appear once.

#### Scenario: Transitive composition
- **WHEN** role `A` has parent `B` and `B` has parent `C`, and a user holds `A`
- **THEN** the user's permissions include every permission of `A`, `B` and `C`

#### Scenario: Multiple parents
- **WHEN** a role has two parents that both grant `docs.view`
- **THEN** the resolved set holds the union of both parents' permissions, with `docs.view` once

#### Scenario: Role cycle
- **WHEN** an admin makes `B` a parent of `A` while `A` is already a parent of `B`
- **THEN** the write is rejected with `CycleDetected`

#### Scenario: Role chain too deep
- **WHEN** a parent chain 11 roles deep is resolved
- **THEN** the operation fails with `DepthExceeded`

### Requirement: Groups nest and resolve transitively
A group MAY contain users, other groups, or both. Membership SHALL resolve transitively: when user U is a member of group A and group A is a member of group B, U is a member of B for resolution. Hearth SHALL detect group cycles and reject them with a `CycleDetected` error. Group nesting SHALL be at most 10 hops deep. A user SHALL belong transitively to at most 1000 groups. Exceeding the depth or the breadth bound SHALL fail with the corresponding error (`DepthExceeded` or `BreadthExceeded`).

#### Scenario: Three-level nesting
- **WHEN** a user is in `G1`, `G1` is in `G2`, and `G2` is in `G3`
- **THEN** resolution counts the user as a member of `G1`, `G2` and `G3`

#### Scenario: Group cycle
- **WHEN** `G1` is a member of `G2` and an admin adds `G2` as a member of `G1`
- **THEN** the operation fails with `CycleDetected`

#### Scenario: Group bounds exceeded
- **WHEN** a user's group graph is more than 10 levels deep, or reaches more than 1000 groups
- **THEN** resolution fails with the corresponding error

### Requirement: Permission strings are flat
A permission SHALL be an atomic string. The dotted notation is a readability convention, not a hierarchy: Hearth SHALL NOT grant one permission because another permission is a prefix of it. Each fully qualified name is an independent permission, at any nesting depth. Related permissions are grouped through roles or scope bundles, not through the name hierarchy.

#### Scenario: A shorter name grants nothing deeper
- **WHEN** a user holds `docs.edit` and `docs.read`
- **THEN** the user does not hold `docs.edit.comments` or `docs.versions.read`

### Requirement: Permission string grammar
Every permission SHALL match `^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+$` and be at most 128 characters long. A permission MUST contain at least one dot, so it has two or more non-empty segments. A segment may contain alphanumerics, underscore and hyphen. A permission MUST NOT contain `:` (reserved for scope bundles), whitespace, or the URL-reserved characters `/ ? # % & =`. Single-word names such as `admin` or `editor` SHALL be rejected. By convention, `system.*` names legitimately global permissions, `realm.*` realm administration, `org.*` organization-scoped permissions, and everything else is application-defined.

#### Scenario: A valid permission
- **WHEN** a role is created with `docs.read`
- **THEN** the permission is accepted

#### Scenario: Invalid permissions
- **WHEN** a role is created with `docs`, `docs:read`, `docs read`, `docs/read`, an empty string, or a 129-character string
- **THEN** each is rejected as an invalid permission

### Requirement: The `hearth.*` namespace is reserved
Permissions under `hearth.*` SHALL be grantable only by Hearth itself or by the roles seeded at realm bootstrap. An operator-defined role MUST NOT include a `hearth.*` permission; Hearth SHALL refuse such a role at creation and at update.

#### Scenario: An operator role claims a reserved permission
- **WHEN** an admin creates a role that lists `hearth.admin`
- **THEN** the API rejects the request with a reserved-namespace error

### Requirement: Assignments are realm-scoped or organization-scoped
Every role assignment SHALL carry a scope. A realm-scoped assignment SHALL apply whenever the user acts in the realm: its permissions appear in every access token for that user in that realm. An organization-scoped assignment SHALL apply only in that organization's context: its permissions appear only when the token is issued with an `oid` equal to the assignment's organization.

#### Scenario: A token without organization context
- **WHEN** a user holds an organization-scoped assignment and receives a token with no `oid`
- **THEN** the token carries none of that assignment's permissions

#### Scenario: A token in the matching organization
- **WHEN** the same user receives a token whose `oid` names the assignment's organization
- **THEN** the token carries that assignment's permissions

### Requirement: The resolution algorithm
Given a user, a realm, an optional organization and an optional requested OAuth scope, Hearth SHALL resolve the effective permission set as follows:

1. Collect the user's transitive groups by a cycle-detected breadth-first walk, bounded at depth 10 and breadth 1000.
2. Collect the role assignments of the user and of each of those groups. Keep every realm-scoped assignment. Keep an organization-scoped assignment only when its organization equals the requested organization.
3. Expand role composition by a depth-first walk with a visited set, bounded at depth 10.
4. Take the union of the permissions of every reached role.
5. When a scope is requested, intersect the union with the permissions the scope admits.

Cycle detection SHALL track visited groups and visited roles separately. Exceeding any bound SHALL return a structured error that names the entity and the limit.

#### Scenario: Worked example
- **WHEN** in realm `acme`, `leads` is a member of `engineers`, `alice` is a direct member of `leads`, role `docs.editor` grants `{docs.view, docs.edit}`, role `docs.admin` has parent `docs.editor` and grants `{docs.delete}`, and the realm-scoped assignments are `engineers → docs.editor` and `leads → docs.admin`
- **THEN** alice's groups resolve to `{leads, engineers}`, her roles to `{docs.admin, docs.editor}`
- **AND** with no requested scope her permissions are `{docs.view, docs.edit, docs.delete}`

#### Scenario: A requested scope narrows the set
- **WHEN** a user holds `org.read` and `docs.view`, and permissions are resolved with the seeded scope `org`
- **THEN** the resolved set is `{org.read}`

### Requirement: Token-size bounds
Hearth SHALL enforce these bounds when it issues a token:

| Bound | Value |
|-------|-------|
| Permissions per token | 100 |
| Role names per token | 50 |
| Group names per token | 50 |
| Serialized JWT claim bytes (`roles + groups + permissions`) | 8 KiB |
| Permission string length | 128 chars |

The tightest bound wins. Exceeding any bound at token-issue time SHALL fail issuance with a structured error that names the violating bound, its limit and the actual value. No oversize token SHALL be issued.

#### Scenario: Too many permissions
- **WHEN** a user's role assignments resolve to 127 permissions and a token is requested
- **THEN** issuance fails with an error that names `access_token_permissions_per_token`, the limit 100 and the actual value 127
- **AND** no token is issued

### Requirement: The resolved set lists each name once
The resolved set SHALL list each role name once, each group slug once, and each permission once, with permissions in sorted order.

#### Scenario: A permission reached twice
- **WHEN** two of a user's roles both grant `docs.view`
- **THEN** the resolved `permissions` list `docs.view` once

### Requirement: Resolution never crosses realms
Every RBAC operation SHALL require a realm. All RBAC state SHALL be stored under keys that embed the realm or are reachable only through a record that carries it, and every scan SHALL stay inside one realm's key space. Resolution in realm B SHALL ignore every role, group and assignment of realm A, even for the same user principal. Realms are hard isolation boundaries: Hearth SHALL NOT inherit permissions across realms.

#### Scenario: A cross-realm leak attempt
- **WHEN** a user holds roles and group memberships in realm A and permissions are resolved in realm B
- **THEN** none of realm A's roles, groups or permissions appear in the result

### Requirement: A token grants nothing outside its realm
A token issued in realm A MUST NOT grant any permission in realm B. Callers that verify tokens MUST validate the `tid` claim against the expected realm.

#### Scenario: A realm A token is presented to realm B
- **WHEN** a token issued in realm A is presented to an endpoint of realm B
- **THEN** the token is not accepted there

### Requirement: Cross-realm administration is explicit
An admin acting across realms MUST hold `hearth.admin` in a token targeted at the appropriate realm, and MUST target the realm explicitly on each request. The admin service MUST NOT perform implicit cross-realm writes.

#### Scenario: A realm admin writes to a peer realm
- **WHEN** an admin of realm A sends a write that targets realm B without a token targeted at realm B that holds `hearth.admin`
- **THEN** the write is refused and realm B is unchanged

### Requirement: Permission resolution is off the hot path
Hearth SHALL resolve permissions on the token-issue path, never on the hot read path. Reading a permission from a token's claims SHALL need no call to the RBAC engine.

#### Scenario: A resource server checks a permission
- **WHEN** a resource server checks `docs.edit` against an embedded-mode access token
- **THEN** it reads the decoded `permissions` claim and makes no call to Hearth

### Requirement: The resolution cache never serves a superseded graph
Hearth MAY memoize the unnarrowed permission set per realm, user and organization. Every mutation of a realm's RBAC graph (role grant or revoke, group member add or remove, direct permission grant or revoke) SHALL invalidate every cached entry of that realm, strictly after the durable storage write. A result computed while a mutation of the same realm was in flight SHALL NOT be cached. Scope narrowing SHALL be applied on every call, on top of the unnarrowed set. The cache SHALL hold at most 50,000 entries, split across 64 shards. When a shard exceeds its share, Hearth SHALL clear that whole shard rather than evict single entries.

#### Scenario: A role is revoked after a cached resolution
- **WHEN** a user's resolution is cached and an admin then revokes one of the user's roles
- **THEN** the next resolution for that user, after the revocation is durable, excludes that role's permissions

#### Scenario: A mutation races a resolution
- **WHEN** a resolution reads storage while a mutation of the same realm commits
- **THEN** that resolution's result is not stored as the current cached value

