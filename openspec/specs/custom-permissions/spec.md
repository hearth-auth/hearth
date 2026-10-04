# custom-permissions Specification

## Purpose
Custom permissions, OAuth scopes and scope bundles, configurable claim profiles, consent, and the registry that holds them.
## Requirements
### Requirement: The authorization vocabulary is authored per realm
Permissions, scope bundles (realm-level and protected-resource) and claim profiles SHALL be authored in `hearth.yaml`, under the realm they belong to (`realms.<id>`). The admin console and the admin API SHALL offer them read-only. Roles MAY be declared in `hearth.yaml` or created, edited and deleted at runtime through the admin API and the admin console. Each realm owns an independent vocabulary. A definition in one realm SHALL NOT apply in another realm. Runtime data is managed at runtime: role assignments, user extra permissions, additional organization roles, OAuth consents and group memberships.

#### Scenario: Two realms declare the same permission name
- **WHEN** realm `production` and realm `staging` both declare `docs.read`, with different roles granting it
- **THEN** each realm resolves `docs.read` only from its own roles, and a role in one realm never grants it in the other

#### Scenario: An admin opens the permissions page
- **WHEN** an admin opens the Permissions page of a realm
- **THEN** the page lists the realm's permissions with no control to create, edit or delete one

### Requirement: Scope strings are classified by their separator
The server SHALL classify every scope string syntactically, without a registry lookup:

| Kind | Rule |
|---|---|
| Permission | contains at least one `.` and no `:` |
| Scope bundle | contains at least one `:` and no `.` |
| OIDC standard scope | a bare word from the closed set `openid`, `profile`, `email`, `address`, `phone`, `offline_access` |

A bare word outside the OIDC set SHALL NOT be treated as an OIDC standard scope. Such a word is a name in the realm's scope mapping; every realm is seeded with the bare-word scopes `admin` and `org`.

#### Scenario: Each kind is recognised by its form
- **WHEN** a client requests `docs.read read:docs openid`
- **THEN** `docs.read` is treated as a permission, `read:docs` as a scope bundle, and `openid` as an OIDC standard scope

#### Scenario: A seeded bare-word scope
- **WHEN** a client requests `org`
- **THEN** `org` is not treated as an OIDC standard scope, and narrows by the realm's scope mapping for `org`

### Requirement: Scope bundle names have a fixed grammar
Every scope bundle name, realm-level or protected-resource, SHALL match `^[A-Za-z0-9_\-]+(:[A-Za-z0-9_\-]+)+$`: at least two non-empty segments, no `.`, and at most 128 characters. Config load SHALL reject a bundle whose name does not match.

#### Scenario: A bundle name with a dot
- **WHEN** a realm declares the scope bundle `read:docs.v2`
- **THEN** config load fails and names the bundle

#### Scenario: A bundle name without a colon
- **WHEN** a realm declares the scope bundle `readdocs`
- **THEN** config load fails and names the bundle

### Requirement: Extra permissions join the effective set when their scope matches
A user's extra permissions (direct grants outside any role) SHALL be added to the user's effective permission set at every token issuance, through the same resolution as role grants. A token SHALL carry one flat permission set, whatever the source of each grant. An extra permission granted at `Realm` scope SHALL apply to every token. An extra permission granted at `Org(X)` scope SHALL apply only when the token's `oid` is `X`:

| Grant scope | Token without `oid` | Token with `oid=X` | Token with `oid=Y` |
|---|---|---|---|
| `Realm` | applies | applies | applies |
| `Org(X)` | does not apply | applies | does not apply |

The same permission MAY be granted realm-wide and in any number of organizations at once. Each scope-distinct grant SHALL be kept separately, and one grant SHALL NOT overwrite another.

#### Scenario: An org-scoped extra outside its organization
- **WHEN** a user holds `billing.read` as an extra at `Org(X)` scope, and a token is issued with `oid=Y`
- **THEN** the token's effective set does not contain `billing.read`

#### Scenario: Realm and org grants of one permission
- **WHEN** an admin grants `docs.share` to a user at `Realm` scope and at `Org(X)` scope, then revokes the `Org(X)` grant
- **THEN** the `Realm` grant remains, and every token still carries `docs.share`

### Requirement: Roles declare the scope they may be assigned at
Every role SHALL have a `scope_kind` of `realm`, `organization` or `any`. A YAML role that omits `scope_kind` SHALL be `realm`. The admin console's organization member page SHALL list and offer only roles whose `scope_kind` is `organization` or `any`.

#### Scenario: A YAML role without a scope kind
- **WHEN** `hearth.yaml` declares a role with no `scope_kind`
- **THEN** the role's `scope_kind` is `realm`

#### Scenario: The organization member role picker
- **WHEN** an admin opens the role picker for an organization member
- **THEN** it offers the realm's `organization` and `any` roles, and no `realm` role

### Requirement: Additional organization roles are validated when added
An organization membership MAY carry additional roles, served over REST as `GET` and `POST /admin/organizations/{id}/members/{user_id}/roles` and `DELETE /admin/organizations/{id}/members/{user_id}/roles/{role_name}`. When an additional role is added, the server SHALL check, at call time and not at config load, that the name resolves to a role in the realm. Adding one SHALL emit `OrgMemberAdditionalRoleAdded`, and removing one SHALL emit `OrgMemberAdditionalRoleRemoved`, each with the actor, organization, user and role name. An additional role SHALL contribute its permissions only when the token's `oid` names that organization.

#### Scenario: An unknown role name
- **WHEN** an admin adds `no_such_role` as an additional role of a membership
- **THEN** the request is refused with `404`

#### Scenario: An additional role outside its organization
- **WHEN** a member of organization X holds the additional role `auditor`, and a token is issued with `oid=Y`
- **THEN** the token carries none of `auditor`'s permissions

### Requirement: The organization membership tier grants no RBAC permissions
The organization membership tier (`Member`, `Admin`, `Owner`) SHALL NOT grant RBAC permissions by itself. Organization-scoped RBAC authority SHALL come only from role assignments at `Org(X)` scope, additional organization roles and extra permissions at `Org(X)` scope. The seeded roles `org.member`, `org.admin` and `org.owner` are ordinary organization-scoped roles, assigned like any other.

#### Scenario: An owner without a role assignment
- **WHEN** a user is `Owner` of organization X, holds no role assignment at `Org(X)` scope, and a token is issued with `oid=X`
- **THEN** the token does not carry `org.billing`

#### Scenario: An assigned owner role
- **WHEN** a user holds `org.owner` at `Org(X)` scope, and a token is issued with `oid=X`
- **THEN** the token carries `org.billing`

### Requirement: User attributes are bounded
A user's attribute map SHALL satisfy these limits on every create, update and import, and a request that breaks one SHALL be refused:

| Bound | Value |
|---|---|
| Key | 1 to 64 bytes of ASCII letters, digits, `_`, `.` and `-` |
| Value | at most 1 KiB |
| Whole map (keys and values) | at most 16 KiB |

On create and update the map SHALL also hold at most 50 entries. The map SHALL serialize in a deterministic key order.

#### Scenario: A key with a space
- **WHEN** an admin sets the attribute `cost center` on a user
- **THEN** the request is refused

#### Scenario: A map over 16 KiB
- **WHEN** a user import carries attributes totalling more than 16 KiB
- **THEN** the import of that user is refused

### Requirement: Requested scopes must be declared by the client
When a client's `declared_scopes` is not empty, a requested scope that is not an OIDC standard scope and is not in `declared_scopes` SHALL fail with `invalid_scope`. OIDC standard scopes SHALL NOT need a declaration. A client with an empty `declared_scopes` MAY request any scope. The check SHALL run at the authorization endpoint and at the client-credentials, JWT-bearer and device-authorization grants. `declared_scopes` holds permission names, bundle names and OIDC standard scopes. Managed clients and clients created by Dynamic Client Registration follow the same rules for the same trust level.

#### Scenario: An undeclared bundle
- **WHEN** a client whose `declared_scopes` is `[read:docs, openid]` requests `write:docs`
- **THEN** the request fails with `invalid_scope`

#### Scenario: An undeclared OIDC scope
- **WHEN** a client whose `declared_scopes` is `[read:docs]` requests `openid read:docs`
- **THEN** `openid` is not refused for being undeclared

#### Scenario: A client with no declared scopes
- **WHEN** a client whose `declared_scopes` is empty requests `write:docs`
- **THEN** the scope is not refused for being undeclared

### Requirement: Third-party clients do not use raw permission scopes
A request from a `third_party` client for a raw permission scope (a `.`-form name) SHALL fail with `invalid_scope`. Third-party clients use scope bundles, which carry a curated `display_name` and `description` for the consent screen.

#### Scenario: A third-party client requests a permission
- **WHEN** a `third_party` client requests `scope=docs.read`
- **THEN** the request fails with `invalid_scope`

### Requirement: A scope is granted only when the user satisfies all of it
A scope bundle SHALL be granted only when the user's effective set contains every permission of the bundle. A raw permission scope SHALL be granted only when the user holds that permission. An OIDC standard scope SHALL always be granted. The token's `scope` SHALL list the granted scopes, space-delimited (RFC 6749 §3.3), and permission narrowing SHALL use the granted scopes only. When the request names at least one scope and no scope is grantable, the request SHALL fail with `invalid_scope`, for every trust level. A bundle named in `scope` is therefore always held in full, so `scope` and `permissions` never disagree.

#### Scenario: A bundle the user holds in part
- **WHEN** the bundle `read:docs` is `[docs.read, docs.list, docs.share]`, the user holds `docs.read` only, and a first-party client requests `read:docs docs.read`
- **THEN** the token's `scope` is `docs.read`, not `read:docs`, and its `permissions` is `[docs.read]`

#### Scenario: Nothing is grantable
- **WHEN** a client requests only bundles and permissions the user cannot satisfy
- **THEN** the request fails with `invalid_scope`

### Requirement: Ungrantable scopes are dropped for first-party and fatal for third-party clients
For a `first_party` client, the server SHALL issue the token with the grantable scopes only, so `scope` MAY be a strict subset of the request. For a `third_party` client, when any requested scope other than an OIDC standard scope is not grantable, the whole request SHALL fail with `invalid_scope`. OIDC standard scopes are exempt from this rule.

#### Scenario: A first-party partial grant
- **WHEN** a first-party client requests `read:docs write:docs`, and the user satisfies `read:docs` only
- **THEN** the token issues with `scope` `read:docs`

#### Scenario: A third-party partial grant
- **WHEN** a third-party client requests `openid read:docs write:docs`, and the user satisfies `read:docs` only
- **THEN** the request fails with `invalid_scope`, and no token issues

### Requirement: An empty scope request depends on the client's trust level
When a `first_party` client requests no scope, the token SHALL carry the user's full effective permission set, and an empty `scope`. When a `third_party` client requests no scope, the request SHALL fail with `invalid_scope`.

#### Scenario: A first-party client without scope
- **WHEN** a first-party client completes a grant with no `scope` parameter
- **THEN** the token's `permissions` is the user's full effective set

#### Scenario: A third-party client without scope
- **WHEN** a third-party client sends an authorization request with no `scope` parameter
- **THEN** the request fails with `invalid_scope`

### Requirement: The token audience selects the scope registry
The server SHALL decide which requested scopes are legal from the token's audience:

- An OIDC standard scope SHALL be legal under any audience.
- Without a `resource` parameter (the token is bound to Hearth itself), a `:`-bundle SHALL be legal only when the realm's top-level `scopes:` registry defines it. A protected resource's scopes SHALL NOT be legal.
- With `resource=<uri>` (RFC 8707), the legal scopes SHALL be exactly the OIDC standard scopes plus `protected_resources[<uri>].scopes`. The realm's `scopes:` registry SHALL NOT be consulted, as a primary source or as a fallback. A raw permission scope SHALL fail with `invalid_scope`.
- A scope missing from the selected registry SHALL fail with `invalid_scope`.

A realm bundle and a protected-resource bundle MAY share a name. They are distinct, because they are looked up under different audiences. Under a resource, a bundle SHALL be in both the client's `declared_scopes` and the resource's `scopes`.

| Context | OIDC standard | Raw permission | Realm bundle | Resource bundle |
|---|:-:|:-:|:-:|:-:|
| `first_party`, no `resource` | legal | legal if declared | legal if declared | not legal |
| `third_party`, no `resource` | legal | refused | legal if declared | not legal |
| any client, `resource=<uri>` | legal | `invalid_scope` | not consulted | legal if declared and registered under `<uri>` |

#### Scenario: A realm bundle requested under a resource
- **WHEN** a realm declares `read:docs` at the top level only, and a client requests `scope=read:docs` with `resource=https://mcp.acme.com`
- **THEN** the request fails with `invalid_scope`

#### Scenario: A resource bundle
- **WHEN** `protected_resources["https://mcp.acme.com"].scopes` declares `mcp:tools:invoke`, and a third-party client that declares it requests `openid mcp:tools:invoke` with that resource
- **THEN** both scopes are legal, and the realm's top-level `scopes:` block is not consulted

#### Scenario: A raw permission under a resource
- **WHEN** a first-party client requests `scope=mcp.tools.invoke` with `resource=https://mcp.acme.com`
- **THEN** the request fails with `invalid_scope`

### Requirement: Token claims keep fixed meanings
The server SHALL give the authorization claims these meanings under every claim profile:

| Claim | Meaning |
|---|---|
| `permissions` | Authoritative for fine-grained authorization. Always the flat, server-resolved effective set, after scope narrowing. |
| `scope` | The OAuth consent boundary (RFC 6749). |
| `oid` | Authoritative for tenant routing and data partitioning. Exactly the organization context Hearth resolved. |
| `roles`, `groups` | Informational. A mapper may override them. Never the authoritative check at an authorization boundary. |
| custom claims | Flattened into the top-level payload, as the realm's claim profile defines them. |

No mapper SHALL change the content of `permissions` or `oid`. The SDK helpers that read `roles` or `groups` are correct only under the default profile, or under a profile that keeps the `roles_from_assignments` and `groups_from_memberships` sources for them. Under the default profile, `roles` and `groups` reach first-party clients only.

#### Scenario: A realm overrides `roles`
- **WHEN** a realm maps `roles` with `role_subset` and prefix `customer.`
- **THEN** the token's `roles` holds only the user's role names that start with `customer.`, and its `permissions` and `oid` are unchanged

### Requirement: Claim profiles shape tokens with declarative mappings
A realm SHALL shape its tokens only through `realms.<id>.claims.mappings`, a list of declarative mappings. No expression language and no scripting SHALL be available. Each mapping names a target `claim`, a `source`, the targets it emits to (`include_in_access_token`, `include_in_id_token`, `include_in_userinfo`) and its release gates. The sources are:

| `source` | Value |
|---|---|
| `roles_from_assignments` | the user's role names |
| `groups_from_memberships` | the user's group names |
| `effective_permissions` | the effective permission set |
| `org_context` | the current organization context |
| `canonical_user_field` (with `field`) | a canonical user field |
| `user_attribute` (with `attribute`) | a key of the user's attribute map |
| `role_subset` (with `prefix`) | the user's role names that start with the prefix |
| `constant` (with `value`) | a fixed JSON value |
| `omit` | nothing: the claim is suppressed |

A claim whose winning mapping is `omit` SHALL be absent from the output. It SHALL NOT be emitted as `null` or as an empty value. A realm with no `claims:` block SHALL use the default profile.

#### Scenario: Suppressing a default claim
- **WHEN** a realm declares `{ claim: groups, source: omit }`
- **THEN** its tokens carry no `groups` key

#### Scenario: A constant claim
- **WHEN** a realm declares `{ claim: tier, source: constant, value: gold, first_party_only: true }`
- **THEN** a first-party client's access token carries `"tier": "gold"` at the top level

### Requirement: Canonical user fields and user attributes are separate sources
The `canonical_user_field` source SHALL read only the closed set of canonical user fields: `email`, `display_name`, `first_name`, `last_name`, `preferred_username`, `nickname`, `picture`, `website`, `gender`, `birthdate`, `locale`, `zoneinfo`, `phone_number`, `address`, `updated_at`. A realm SHALL NOT extend this set from YAML. `preferred_username` SHALL yield the user's email. The user record holds no value for `nickname`, `picture`, `website`, `gender`, `birthdate`, `locale`, `zoneinfo`, `phone_number` or `address`, so these fields SHALL yield nothing and the claim is omitted. The `user_attribute` source SHALL read only the user's attribute map, and SHALL NOT fall back to a canonical field. When the attribute key is missing, the claim SHALL be omitted, not emitted as `null`.

#### Scenario: A missing attribute
- **WHEN** a realm maps `department` from `user_attribute` `dept`, and a user has no `dept` attribute
- **THEN** that user's tokens carry no `department` claim

#### Scenario: No fallback to a canonical field
- **WHEN** a realm maps `email` from `user_attribute` `work_email`, and a user has no `work_email` attribute
- **THEN** the mapping yields nothing; it does not read the user's canonical `email`

### Requirement: A built-in default claim profile applies to every realm
Every realm SHALL start from this built-in profile. A realm's YAML mappings are layered over it.

| Claim | Source | Access token | ID token | UserInfo | Gate |
|---|---|:-:|:-:|:-:|---|
| `roles` | `roles_from_assignments` | yes | yes | no | `first_party_only: true` |
| `groups` | `groups_from_memberships` | yes | yes | no | `first_party_only: true` |
| `permissions` | `effective_permissions` | yes | no | no | `first_party_only: true` |
| `email` | `canonical_user_field` `email` | no | yes | yes | `required_scopes: [email]` |
| `name` | `canonical_user_field` `display_name` | no | yes | yes | `required_scopes: [profile]` |
| `given_name` | `canonical_user_field` `first_name` | no | yes | yes | `required_scopes: [profile]` |
| `family_name` | `canonical_user_field` `last_name` | no | yes | yes | `required_scopes: [profile]` |
| `picture`, `locale`, `zoneinfo` | `canonical_user_field`, same name | no | yes | yes | `required_scopes: [profile]` |
| `phone_number` | `canonical_user_field` `phone_number` | no | yes | yes | `required_scopes: [phone]` |
| `address` | `canonical_user_field` `address` | no | yes | yes | `required_scopes: [address]` |

So `roles`, `groups` and `permissions` SHALL be withheld from third-party clients by default, and SHALL NOT appear in `/userinfo` for any client. Because `permissions` is a Tier 1 name, no realm can release it to third-party clients. `oid` is emitted by core issuance, not by a mapping, and no mapping can override it. `email_verified` and `phone_number_verified` are emitted by core issuance from canonical user state. A realm that wants to release `roles` or `groups` to third-party clients overrides the mapping with explicit release gates.

#### Scenario: A third-party client under the default profile
- **WHEN** a third-party client is issued tokens in a realm with no `claims:` block
- **THEN** neither token carries `roles`, `groups` or `permissions`

#### Scenario: A first-party client under the default profile
- **WHEN** a first-party client is issued tokens in a realm with no `claims:` block
- **THEN** the access token carries `roles`, `groups` and `permissions`, and the ID token carries `roles` and `groups`

### Requirement: Mappings are evaluated per claim and token target with fallback
For each claim name `C` and each target `T` (`access_token`, `id_token`, `userinfo`), the server SHALL:

1. collect every mapping that targets `C` and includes `T`, in declaration order: the built-in defaults first, then the realm's YAML mappings;
2. walk that list from the last-declared mapping to the first;
3. emit `C` in `T` from the first mapping whose release gates all pass for the current client and granted scopes;
4. omit `C` from `T` when no mapping's gates pass.

When a YAML mapping's gates fail, evaluation SHALL fall back to the default mapping for the same claim. It SHALL NOT suppress the claim. Each target SHALL be evaluated independently, so a claim may come from different mappings in different targets.

#### Scenario: A per-client override with fallback
- **WHEN** a realm maps `{ claim: roles, source: role_subset, prefix: "customer.", allowed_clients: [customer-portal] }`
- **THEN** the `customer-portal` client receives the filtered `roles`, every other first-party client receives the default `roles`, and third-party clients receive no `roles`

#### Scenario: An override that leaves out a target
- **WHEN** a realm overrides `email` with `include_in_userinfo: false`
- **THEN** `/userinfo` still returns `email` from the default mapping when the `email` scope is granted

### Requirement: Release gates restrict which clients receive a claim
Each mapping SHALL carry three optional release gates. A claim SHALL be emitted only when all of them pass:

- `first_party_only: true`: the client's `trust_level` is `first_party`.
- `required_scopes: [...]`: the final granted scope set contains at least one listed scope.
- `allowed_clients: [...]`: the requesting client is one of the listed clients.

`required_scopes` SHALL be evaluated against the granted scopes (the token's `scope`), after scope resolution, and never against the raw request.

#### Scenario: A gated claim and a granted scope
- **WHEN** a claim is gated on `required_scopes: [read:docs]`, and the token's granted `scope` contains `read:docs`
- **THEN** the claim is emitted

#### Scenario: Gates combine with AND
- **WHEN** a mapping sets `first_party_only: true` and `allowed_clients: [ops-console]`, and a first-party client other than `ops-console` gets a token
- **THEN** that mapping does not emit the claim

### Requirement: `allowed_clients` names managed clients only
Every entry of `oauth_clients` in `hearth.yaml` SHALL carry a `slug`, unique within the realm. Each `allowed_clients` entry SHALL be the slug of a managed client: one authored under `realms.<id>.oauth_clients`. Config load SHALL reject an `allowed_clients` entry that names a client registered through Dynamic Client Registration, with an error that names the slug's track. The server SHALL resolve each slug to its client ID at registry load, and the gate SHALL compare client IDs, not slugs.

#### Scenario: A DCR slug in a gate
- **WHEN** a mapping lists in `allowed_clients` the slug of a client created by `POST /register`
- **THEN** config load fails and names that slug

#### Scenario: A registration that copies a managed client's name
- **WHEN** a gate lists `customer-portal`, and a dynamically registered client has a name or slug that reads `customer-portal`
- **THEN** that client does not pass the gate

### Requirement: Custom claims are first-party only unless released
When a YAML mapping omits `first_party_only`, it SHALL inherit the `first_party_only` value of the built-in mapping for the same claim. A mapping for a claim with no built-in mapping (a Tier 3 custom claim) that omits `first_party_only` SHALL get `first_party_only: true`, whatever other gates it sets. To release a custom claim to third-party clients, the operator SHALL set `first_party_only: false` explicitly, and SHOULD also gate it with `required_scopes` or `allowed_clients`.

#### Scenario: An ungated custom claim
- **WHEN** a realm declares `{ claim: department, source: user_attribute, attribute: dept }` with no gate
- **THEN** first-party clients receive `department`, and third-party clients do not

#### Scenario: An override of a built-in claim without the gate
- **WHEN** a realm overrides `roles` with `role_subset` and does not set `first_party_only`
- **THEN** the override is first-party only, like the built-in `roles` mapping

#### Scenario: An override of `email` without the gate
- **WHEN** a realm overrides `email` from an attribute and does not set `first_party_only`
- **THEN** third-party clients that are granted the `email` scope still receive `email`

### Requirement: Tier 1 claim names are reserved
Config load SHALL reject a mapping whose target is a Tier 1 claim name:

| Group | Names |
|---|---|
| JWT registered (RFC 7519) | `iss`, `aud`, `exp`, `nbf`, `iat`, `jti` |
| Identity | `sub`, `tid` |
| Authorization | `permissions`, `scope`, `sid` |
| Tenant routing | `oid` |
| OIDC flow | `nonce`, `auth_time`, `acr`, `amr`, `azp` |
| OIDC token-binding hashes | `at_hash`, `c_hash`, `s_hash` |
| OAuth client identity | `client_id` |
| Proof of possession (RFC 7800) | `cnf` |
| Delegation attestation (RFC 8693) | `act`, `actor` |
| Verification attestation | `email_verified`, `phone_number_verified` |

Core issuance SHALL write the Tier 1 claims after mapper evaluation, so a mapper value for a Tier 1 name never reaches a token. `act` and `actor` SHALL come only from the actual delegation flow. `email_verified` and `phone_number_verified` SHALL come only from canonical user state.

#### Scenario: A mapper targets `oid`
- **WHEN** a realm declares `{ claim: oid, source: constant, value: acme }`
- **THEN** config load fails and names the claim

#### Scenario: A mapper targets `email_verified`
- **WHEN** a realm maps `email_verified` to a constant `true`
- **THEN** config load fails and names the claim

#### Scenario: A mapper targets `permissions`
- **WHEN** a realm maps `permissions` with `first_party_only: false`
- **THEN** config load fails and names the claim

### Requirement: Non-reserved claim names are validated by tier
The validator SHALL accept a non-Tier-1 mapping target only when it is a Tier 2 name or a valid Tier 3 name, and SHALL refuse any other name at config load.

- **Tier 2 (overridable):** `roles`, `groups`, and the OIDC profile and contact claims `email`, `name`, `given_name`, `family_name`, `preferred_username`, `nickname`, `picture`, `website`, `gender`, `birthdate`, `locale`, `zoneinfo`, `updated_at`, `phone_number`, `address`. A mapping for one of these names overrides the default emission.
- **Tier 3 (custom):** either the short form `^[a-z][a-z0-9_]*$`, at most 64 characters, or the HTTPS-namespaced form `^https://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$`, at most 256 characters. An `http://` name SHALL be rejected. URN names (`urn:…`) are not supported.

#### Scenario: A short custom name
- **WHEN** a realm maps the claim `employee_id`
- **THEN** config load accepts it

#### Scenario: An HTTP namespace
- **WHEN** a realm maps the claim `http://acme.com/department`
- **THEN** config load fails and names the claim

#### Scenario: An HTTPS namespace
- **WHEN** a realm maps the claim `https://acme.com/department`
- **THEN** config load accepts it, and the token carries the claim under that exact name

### Requirement: UserInfo is produced from the claim profile
The `/userinfo` response SHALL be produced by evaluating the realm's claim profile for the `userinfo` target, so ID-token claims and UserInfo claims cannot drift apart. OIDC scope filtering SHALL apply on top of the mapper output: `scope=profile` releases profile claims, and `scope=email` releases email claims. An OIDC profile claim that the realm does not override SHALL come from the canonical user field.

#### Scenario: A realm overrides `name`
- **WHEN** a realm maps `name` from an attribute for both `id_token` and `userinfo`, and a client with the `profile` scope calls `/userinfo`
- **THEN** `/userinfo` returns the same `name` value as the ID token

### Requirement: Claim and scope work stays off the validation hot path
Claim-profile evaluation, scope resolution and registry lookups SHALL run at token issuance only. Token validation SHALL NOT evaluate them, and SHALL NOT gain an allocation or a lookup from them.

#### Scenario: A realm with a large claim profile
- **WHEN** a realm defines many claim mappings and scope bundles
- **THEN** validating one of its tokens does no claim-profile or registry work

### Requirement: Registry reload is lazy and non-destructive
The server SHALL load the permission registry (permissions, roles, scope bundles, protected resources and per-realm claim profiles) from YAML at startup, and SHALL swap it atomically on `SIGHUP`. A reload SHALL NOT delete runtime data, and SHALL NOT abort startup, when runtime data references a removed entry. Effective-permission resolution SHALL be the single enforcement point: a reference to a missing registry entry SHALL be skipped, so the missing permission is not granted. At startup the validator SHALL log a summary of orphaned references at `warn` level. The audit event `OrphanedReferenceSkipped` SHALL be emitted at most once per realm and reference per hour. Removing a claim mapping SHALL NOT invalidate tokens already issued; the next issuance uses the new shape.

#### Scenario: A permission removed from YAML
- **WHEN** a role in storage still references `docs.archive`, the operator removes `docs.archive` from `hearth.yaml` and reloads
- **THEN** the reload succeeds, tokens no longer carry `docs.archive`, and `OrphanedReferenceSkipped` is recorded once for that reference within the hour

### Requirement: Registry validation catches broken cross-references at load
Config load SHALL reject a registry in which a role or a scope bundle (realm-level or protected-resource) references a permission that the realm does not declare. It SHALL also apply the bundle-name grammar and the claim-name tiers. `hearth config validate [file]` SHALL run this validation without starting the server.

#### Scenario: A role references an undeclared permission
- **WHEN** a role lists `docs.purge`, and the realm does not declare `docs.purge`
- **THEN** config load fails and names the role and the permission

### Requirement: Maintenance commands manage the registry and its orphans
The CLI SHALL provide:

| Command | Effect |
|---|---|
| `hearth config validate [file]` | pre-flight validation: name grammar, claim-name tiers, cross-references |
| `hearth rbac orphans list [--realm <id>]` | list orphaned runtime data |
| `hearth rbac orphans purge [--realm <id>] [--dry-run]` | delete orphaned assignments and extras, with audit events |

#### Scenario: A dry-run purge
- **WHEN** an operator runs `hearth rbac orphans purge --realm <id> --dry-run`
- **THEN** the command reports what it would delete, and deletes nothing

### Requirement: Only third-party clients need consent
A `first_party` client SHALL NOT need consent. For a first-party client the server SHALL NOT store a consent row, SHALL NOT compute a digest, and SHALL NOT check one at `/authorize` or at a `refresh_token` grant. A first-party refresh SHALL re-resolve effective permissions against the current registry, and SHALL NOT fail with `consent_required`. A `third_party` client SHALL need consent the first time it asks for a scope set; afterwards the stored consent SHALL be checked against its digest.

#### Scenario: A first-party client loses a permission
- **WHEN** a user loses a permission, and a first-party client refreshes
- **THEN** the refresh succeeds with the narrower set

#### Scenario: A third-party client's first authorization
- **WHEN** a third-party client first asks a user for `read:docs`
- **THEN** the user sees the consent screen before a code is issued

### Requirement: Consent is bound to the organization context and the resource
A third-party consent SHALL be stored per realm, user, client, organization context and RFC 8707 resource. A consent row SHALL record the scopes as the client requested them, the digest, the organization the user was in, the resource (or none for Hearth itself as audience), when it was granted and who granted it. At `/authorize` and at a `refresh_token` grant, the server SHALL:

1. look up the row for the current organization context (`oid`) and the current resource;
2. when the user is in an organization and no row exists for it, fall back to the realm-level row only when the client sets `consent_spans_orgs: true`;
3. never fall back across resources: each protected resource is its own consent boundary;
4. on a miss, run the consent ceremony.

`consent_spans_orgs` SHALL default to `false`. It is a client capability flag, not a scope: it does not appear in `declared_scopes` and takes no part in scope resolution. A realm MAY restrict which clients may set it.

#### Scenario: Consent given in another organization
- **WHEN** a user consented to a client while in organization A, and the client's `consent_spans_orgs` is `false`, and the user now authorizes it in organization B
- **THEN** the consent screen is shown again

#### Scenario: Consent that spans organizations
- **WHEN** a client sets `consent_spans_orgs: true`, the user consented at realm level, and the user now authorizes it in organization B
- **THEN** the realm-level consent is used and no screen is shown

#### Scenario: A consent for another resource
- **WHEN** a user consented to a client for Hearth itself as audience, and the client now asks with `resource=https://mcp.acme.com`
- **THEN** the consent screen is shown for the new resource

### Requirement: The consent digest covers what the user agreed to disclose
At grant time the server SHALL compute a SHA-256 digest over:

1. the canonical resource: `_default` when there is none, otherwise the resource URI with a lower-cased scheme and host and a normalized path;
2. the sorted, de-duplicated permissions that the consented scopes resolve to;
3. the sorted set of `(claim, target)` pairs that the realm's claim profile would emit to this client, given its trust level, the granted scopes and the resource, serialized as `claim@target` strings.

The digest SHALL cover claim names and targets, not claim values. OIDC standard scopes SHALL contribute fixed sentinels. On every `/authorize` and every `refresh_token` grant the server SHALL recompute the digest against the current registry. On a mismatch, the stored consent SHALL be treated as absent: `/authorize` runs the consent ceremony again, and a refresh fails with `invalid_grant` and `error_description=consent_required`. No sweep SHALL run at YAML reload.

#### Scenario: A new mapper emits to the client
- **WHEN** the operator adds a mapper that releases `salary` to a third-party client that holds consent
- **THEN** the next `/authorize` for that client shows the consent screen again

#### Scenario: A claim moves to another target
- **WHEN** a claim the client received only in the ID token is changed to also emit to the access token and UserInfo
- **THEN** the stored consent no longer matches, and the user must consent again

### Requirement: Refresh re-checks consent against the current registry
A refresh for a third-party client SHALL re-run scope resolution and the digest check against the current registry, with these outcomes:

| Change since consent | Refresh outcome |
|---|---|
| A bundle's permission list changed | `invalid_grant` with `consent_required` |
| A bundle was deleted | `invalid_grant` with `consent_required` |
| The user lost a permission | succeeds, with the narrower set |
| The request names a different `resource` than the grant | succeeds; the new token keeps the grant's original resource |

A refresh request SHALL NOT switch `resource`. To use a new resource, the client runs `/authorize` again, which produces a separate consent row and a new grant family. A refresh token that references a removed scope or bundle SHALL fail on its next refresh with `invalid_grant`, and the consent for the removed scope SHALL be dropped at that point.

#### Scenario: A bundle is broadened
- **WHEN** an agent holds consent for `mcp:tools:invoke = [mcp.tools.invoke]`, and the operator redefines it as `[mcp.tools.invoke, mcp.tools.list]`
- **THEN** the agent's next refresh fails with `invalid_grant` and `consent_required`

#### Scenario: The user loses a role
- **WHEN** the operator removes the user's role, and the bundle definitions are unchanged
- **THEN** the refresh succeeds, and the new token carries the narrower permission set

#### Scenario: A refresh names another resource
- **WHEN** a grant was made for `resource=https://mcp.acme.com`, and the client refreshes with `resource=https://other.example.com`
- **THEN** the new access token's audience is still `https://mcp.acme.com`

### Requirement: Revoking an application removes all of its consent
Revoking an application SHALL delete every consent row for that realm, user and client: the realm-level row, every organization row and every per-resource row under each of them. Revocation SHALL NOT be selectable per organization or per resource. A user revokes from `/ui/account/applications` (`POST /ui/account/applications/{client_id}/revoke`), and over the API with `DELETE /oauth/consents/{client_id}`. An admin revokes from `/ui/admin/realms/{realm}/users/{id}/applications` (`POST /ui/admin/realms/{realm}/users/{id}/applications/{client_id}/revoke`), and over the API with `DELETE /admin/users/{id}/consents/{client_id}`, with the same effect. The server SHALL emit one `ClientConsentRevoked` audit event per deleted row, carrying the actor, the row's `context_oid`, and its `resource_uri` (`null` for a default-audience row).

#### Scenario: An app with rows in two organizations and two resources
- **WHEN** a user revokes a client that holds consent rows in organizations A and B, each for Hearth and for `https://mcp.acme.com`
- **THEN** all four rows are deleted, and four `ClientConsentRevoked` events are recorded with `actor = user`

### Requirement: Users see and revoke their connected applications
`/ui/account/applications` SHALL list the applications the signed-in user has granted, with each one's display name, granted-at time and granted scopes. It SHALL require only an account session, not an admin privilege. It SHALL offer a revoke control per application and one that revokes every application at once (`POST /ui/account/applications/revoke-all`). First-party clients may be absent from the list, because they store no consent.

#### Scenario: Listing a granted application
- **WHEN** a user who consented to AcmeNotes for `read:docs` opens `/ui/account/applications`
- **THEN** the page shows AcmeNotes with its granted-at time and the scope `read:docs`

#### Scenario: Revoking every application
- **WHEN** a user submits the revoke-all control
- **THEN** every consent the user granted is revoked

### Requirement: The admin console browses the RBAC vocabulary
The admin console SHALL have these RBAC pages for the selected realm:

| Page | Path | Content |
|---|---|---|
| Permissions | `/ui/admin/realms/{realm}/rbac/permissions` | Read-only. Each permission's name, description and the roles that grant it. An empty state when the realm declares none. |
| Roles | `/ui/admin/realms/{realm}/rbac/roles` | A list and a detail page, with create (`/new`), edit (`/{id}/edit`) and delete (`/{id}/delete`). |
| Groups | `/ui/admin/realms/{realm}/groups` | Create, edit and delete groups; add and remove members; assign and unassign roles. |
| Scopes | `/ui/admin/realms/{realm}/rbac/scopes` | Read-only. Each bundle's name, permissions and description. An empty state when the realm defines no bundle. |
| Debug | `/ui/admin/realms/{realm}/rbac/debug` | A Resolver tab (a user, optionally narrowed to an organization or a scope) and a Token preview tab. |

The Token preview (`GET /ui/admin/realms/{realm}/rbac/token-preview?user_id=<uuid>`) SHALL return, as JSON, the roles, groups and permissions that RBAC resolves for the user in the realm, with no client, scope or claim profile applied.

#### Scenario: A realm without scope bundles
- **WHEN** an admin opens the Scopes page of a realm with no `scopes:` block
- **THEN** the page shows an empty state

#### Scenario: Previewing a user's token
- **WHEN** an admin previews the token of a user who holds `docs.read` through a role
- **THEN** the JSON lists that role and `docs.read`

### Requirement: The user detail page manages a user's access
The admin user detail page SHALL show an Access card with four tabs:

- Roles: the user's role assignments, with controls to assign and unassign (runtime data);
- Extra Permissions: the user's extra permissions, with controls to grant and revoke (runtime data);
- Effective: a read-only flat list of the user's effective permissions;
- Attributes: a read-only table of the user's attributes.

The user's connected applications SHALL be listed at `/ui/admin/realms/{realm}/users/{id}/applications`, each with a revoke control.

#### Scenario: Granting an extra permission
- **WHEN** an admin grants `docs.share` as an extra permission on the user detail page
- **THEN** the Effective tab lists `docs.share`

### Requirement: Application pages show and edit trust level and declared scopes
The application detail page SHALL show the client's `trust_level` and `declared_scopes`. The application edit page SHALL let an admin change the `trust_level` (`first_party` or `third_party`) and the `declared_scopes` (a space-separated list).

#### Scenario: Making a client third-party
- **WHEN** an admin sets `trust_level` to `third_party` on the edit page and saves
- **THEN** the detail page shows the client as third-party

### Requirement: The realm claims page lists the realm's mappings
`/ui/admin/realms/{realm}/claims` SHALL show the claim mappings that the realm's `hearth.yaml` declares, read-only. For each mapping it SHALL show the target claim, the source, the access-token, ID-token and UserInfo flags, `first_party_only` and `required_scopes`. A realm with no `claims:` block SHALL show an empty list.

#### Scenario: A realm with one mapping
- **WHEN** a realm declares `{ claim: department, source: user_attribute, attribute: dept }`
- **THEN** the claims page lists `department` with its source and its `first_party_only` value

