## MODIFIED Requirements

### Requirement: A scope is granted only when the user satisfies all of it
A scope bundle SHALL be granted only when the user's effective set contains every permission of the bundle. A raw permission scope SHALL be granted only when the user holds that permission. An OIDC standard scope SHALL always be granted. The token's `scope` SHALL list the granted scopes, space-delimited (RFC 6749 §3.3), and permission narrowing SHALL use the granted scopes only. When the request names at least one scope and no scope is grantable, the request SHALL fail with `invalid_scope`, for every trust level. A bundle named in `scope` is therefore always held in full, so `scope` and `permissions` never disagree. When the request names only OIDC standard scopes, a `first_party` client SHALL receive the user's full effective set, and a `third_party` client SHALL receive no permissions, in the token, in introspection and in decision mode. When the request names a bundle or a raw permission and none is granted, `permissions` SHALL be empty.

#### Scenario: A bundle the user holds in part
- **WHEN** the bundle `read:docs` is `[docs.read, docs.list, docs.share]`, the user holds `docs.read` only, and a first-party client requests `read:docs docs.read`
- **THEN** the token's `scope` is `docs.read`, not `read:docs`, and its `permissions` is `[docs.read]`

#### Scenario: Nothing is grantable
- **WHEN** a client requests only bundles and permissions the user cannot satisfy
- **THEN** the request fails with `invalid_scope`

#### Scenario: Only OIDC scopes for a third-party client
- **WHEN** a third-party client asks for `openid profile` only
- **THEN** the token carries no permissions, and introspecting it returns no permissions

#### Scenario: Every requested bundle is dropped
- **WHEN** a first-party client asks for `openid read:docs`, and the user does not fully hold `read:docs`
- **THEN** the token's `scope` is `openid`, and its `permissions` is empty

#### Scenario: A bundle is granted only when fully held
- **WHEN** the bundle `read:docs` is `[docs.read, docs.list, docs.share]`, the user holds `docs.read` only, and a first-party client that declares `read:docs` and `docs.read` completes an authorization-code grant for `read:docs docs.read`
- **THEN** the token's `scope` does not contain `read:docs`

### Requirement: Ungrantable scopes are dropped for first-party and fatal for third-party clients
For a `first_party` client, the server SHALL issue the token with the grantable scopes only, so `scope` MAY be a strict subset of the request. For a `third_party` client, when any requested scope other than an OIDC standard scope is not grantable, the whole request SHALL fail with `invalid_scope`. OIDC standard scopes are exempt from this rule.

#### Scenario: A first-party partial grant
- **WHEN** a first-party client requests `read:docs write:docs`, and the user satisfies `read:docs` only
- **THEN** the token issues with `scope` `read:docs`

#### Scenario: A third-party partial grant
- **WHEN** a third-party client requests `openid read:docs write:docs`, and the user satisfies `read:docs` only
- **THEN** the request fails with `invalid_scope`, and no token issues

#### Scenario: A third-party client never gets an unsatisfiable bundle
- **WHEN** a third-party client that declares `read:docs` asks for `openid read:docs`, and the user holds only `docs.read` of `[docs.read, docs.list, docs.share]`
- **THEN** the authorization request fails with `invalid_scope`, and no code or token is issued

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

#### Scenario: Gates run on granted scopes only
- **WHEN** a mapping is gated on `required_scopes: [admin:bundle]`, a first-party client asks for `openid admin:bundle`, and the user holds only part of `admin:bundle`
- **THEN** the issued token's `scope` does not contain `admin:bundle`, and the gated claim is not emitted

### Requirement: The token audience selects the scope registry
The server SHALL decide which requested scopes are legal from the token's audience:

- An OIDC standard scope SHALL be legal under any audience.
- Without a `resource` parameter (the token is bound to Hearth itself), a `:`-bundle SHALL be legal only when the realm's top-level `scopes:` registry defines it. A protected resource's scopes SHALL NOT be legal.
- With `resource=<uri>` (RFC 8707), the legal scopes SHALL be exactly the OIDC standard scopes plus `protected_resources[<uri>].scopes`. The realm's `scopes:` registry SHALL NOT be consulted, as a primary source or as a fallback. A raw permission scope SHALL fail with `invalid_scope`.
- A scope missing from the selected registry SHALL fail with `invalid_scope`, for every trust level. The first-party drop rule applies to known scopes that the user cannot satisfy, not to unknown names.

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

#### Scenario: An unknown scope from a first-party client
- **WHEN** a first-party client asks for `openid nosuch:bundle`, and no registry defines `nosuch:bundle`
- **THEN** the request fails with `invalid_scope`

#### Scenario: Only resource bundles apply under a resource
- **WHEN** a realm declares `read:docs` only in its top-level `scopes:` block, `https://mcp.acme.com` is a registered protected resource, and a client that declares `read:docs` asks for `scope=read:docs` with `resource=https://mcp.acme.com`
- **THEN** the request fails with `invalid_scope`

### Requirement: `allowed_clients` names managed clients only
Every managed client (an entry of `applications` or `oauth_clients` in `hearth.yaml`) SHALL have a slug: its `slug` field, or its YAML key when the field is absent. Slugs SHALL be unique within the realm. Each `allowed_clients` entry SHALL be the slug of a managed client: one authored under `realms.<id>.oauth_clients`. Config load SHALL reject an `allowed_clients` entry that names a client registered through Dynamic Client Registration, with an error that names the slug's track. The server SHALL resolve each slug to its client ID at registry load, and the gate SHALL compare client IDs, not slugs.

#### Scenario: A DCR slug in a gate
- **WHEN** a mapping lists in `allowed_clients` the slug of a client created by `POST /register`
- **THEN** config load fails and names that slug

#### Scenario: A registration that copies a managed client's name
- **WHEN** a gate lists `customer-portal`, and a dynamically registered client has a name or slug that reads `customer-portal`
- **THEN** that client does not pass the gate

#### Scenario: Slug gates match managed clients only
- **WHEN** a mapping sets `allowed_clients: [customer-portal]`, and a client registered through `POST /register` with `client_name` `Customer Portal` gets a token
- **THEN** the gated claim is not emitted to that client

#### Scenario: Managed client slugs are unique
- **WHEN** `hearth.yaml` declares two clients in one realm with the same `slug`
- **THEN** config load fails and names the clients

#### Scenario: A client without a slug
- **WHEN** a client is declared under the key `customer-portal` with no `slug`, and a gate lists `customer-portal`
- **THEN** config load succeeds, and the gate matches that client

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

#### Scenario: Tier 1 names never come from mapper output
- **WHEN** a claim profile that was not checked at load maps `sub` to the constant `admin`, and a token is issued
- **THEN** the token's `sub` is the user's ID, and the payload carries `sub` once

### Requirement: Registry reload is lazy and non-destructive
The server SHALL load the permission registry (permissions, roles, scope bundles, protected resources and per-realm claim profiles) from YAML at startup, and SHALL swap it atomically on `SIGHUP`. A reload SHALL NOT delete runtime data, and SHALL NOT abort startup, when runtime data references a removed entry. Effective-permission resolution SHALL be the single enforcement point: a reference to a missing registry entry SHALL be skipped, so the missing permission is not granted. At startup the validator SHALL log a summary of orphaned references at `warn` level. The audit event `OrphanedReferenceSkipped` SHALL be emitted at most once per realm and reference per hour. Removing a claim mapping SHALL NOT invalidate tokens already issued; the next issuance uses the new shape.

#### Scenario: A permission removed from YAML
- **WHEN** a role in storage still references `docs.archive`, the operator removes `docs.archive` from `hearth.yaml` and reloads
- **THEN** the reload succeeds, tokens no longer carry `docs.archive`, and `OrphanedReferenceSkipped` is recorded once for that reference within the hour

#### Scenario: A skipped orphan reference is audited
- **WHEN** a member's additional organization role names a role that no longer exists, and two tokens are issued in that organization within an hour
- **THEN** `OrphanedReferenceSkipped` is recorded in the audit log exactly once

#### Scenario: An extra permission ends with its registry entry
- **WHEN** a user holds the extra permission `docs.archive`, and the operator removes `docs.archive` from `hearth.yaml` and reloads
- **THEN** new tokens for the user do not carry `docs.archive`

### Requirement: Consent is bound to the organization context and the resource
A third-party consent SHALL be stored per realm, user, client, organization context and RFC 8707 resource. A consent row SHALL record the scopes as granted, the disclosure set, the organization the user was in, the resource (or none for Hearth itself as audience), when it was granted, the ID of the user who granted it, and the surface it was granted on (`web` or `device`). A first-party client SHALL have no consent ceremony and no consent row. At `/authorize` and at a `refresh_token` grant, the server SHALL:

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

#### Scenario: Consent is scoped to the organization
- **WHEN** a user consented to a third-party client while in organization A, the client's `consent_spans_orgs` is `false`, and the user authorizes it in the browser while in organization B
- **THEN** the consent screen is shown

#### Scenario: Consent is scoped to the resource
- **WHEN** a user consented to a third-party client with no `resource`, and the client now asks in the browser for the same scopes with `resource=https://mcp.acme.com`
- **THEN** the consent screen is shown

### Requirement: The consent digest covers what the user agreed to disclose
At grant time the server SHALL store, on the consent row, the disclosure set:

1. the sorted, de-duplicated permissions that the consented scopes resolve to;
2. the sorted set of `(claim, target)` pairs that the realm's claim profile would emit to this client, given its trust level, the granted scopes and the resource, serialized as `claim@target` strings.

The set SHALL cover claim names and targets, not claim values. OIDC standard scopes SHALL contribute fixed sentinels. The row's resource is part of its key, so the set does not repeat it. On every `/authorize` and every `refresh_token` grant the server SHALL recompute the set against the current registry. The stored consent SHALL hold while the current set is a subset of the stored set. When the current set is not a subset, the stored consent SHALL be treated as absent: `/authorize` runs the consent ceremony again, and a refresh fails with `invalid_grant` and `error_description=consent_required`. A smaller set, for example after a mapper is removed, SHALL NOT ask for consent again. No sweep SHALL run at YAML reload.

#### Scenario: A removed mapper does not ask again
- **WHEN** a third-party client holds consent, and the operator removes a mapper that released a claim to it and reloads
- **THEN** the next `/authorize` for the same scopes shows no consent screen

#### Scenario: A new mapper emits to the client
- **WHEN** the operator adds a mapper that releases `salary` to a third-party client that holds consent
- **THEN** the next `/authorize` for that client shows the consent screen again

#### Scenario: A claim moves to another target
- **WHEN** a claim the client received only in the ID token is changed to also emit to the access token and UserInfo
- **THEN** the stored consent no longer matches, and the user must consent again

#### Scenario: A new mapper invalidates consent
- **WHEN** a third-party client holds consent, the operator adds a mapper with `first_party_only: false` that releases `salary` to it and reloads, and the user authorizes the client again for the same scopes
- **THEN** the consent screen is shown

### Requirement: Refresh re-checks consent against the current registry
A refresh for a third-party client SHALL re-run scope resolution and the digest check against the current registry, with these outcomes:

| Change since consent | Refresh outcome |
|---|---|
| A bundle's permission list changed | `invalid_grant` with `consent_required` |
| A bundle was deleted | `invalid_grant` with `consent_required` |
| The user lost a permission | succeeds, with the narrower set; a bundle no longer fully held drops out of `scope` |
| Nothing grantable remains | `invalid_grant` |
| The request names a different `resource` than the grant | `invalid_target` |

A refresh request SHALL NOT switch `resource`. An absent `resource`, or one equal in canonical form to the grant's resource, SHALL be accepted. To use a new resource, the client runs `/authorize` again, which produces a separate consent row and a new grant family. A refresh token that references a removed scope or bundle SHALL fail on its next refresh with `invalid_grant`, and the whole consent row SHALL be deleted at that point. A refresh for a first-party client SHALL re-run scope resolution with the same rules, with no consent step.

#### Scenario: A bundle is broadened
- **WHEN** an agent holds consent for `mcp:tools:invoke = [mcp.tools.invoke]`, and the operator redefines it as `[mcp.tools.invoke, mcp.tools.list]`
- **THEN** the agent's next refresh fails with `invalid_grant` and `consent_required`

#### Scenario: The user loses a role
- **WHEN** the operator removes the user's role, and the bundle definitions are unchanged
- **THEN** the refresh succeeds, and the new token carries the narrower permission set

#### Scenario: A refresh names another resource
- **WHEN** a grant was made for `resource=https://mcp.acme.com`, and the client refreshes with `resource=https://other.example.com`
- **THEN** the refresh fails with `invalid_target`, and no token issues

#### Scenario: A broadened bundle requires consent again
- **WHEN** a third-party client holds consent and a refresh token for `read:docs = [docs.read]`, and the operator redefines `read:docs` as `[docs.read, docs.list]` and reloads
- **THEN** the next refresh answers `400` with `error=invalid_grant` and `error_description=consent_required`

#### Scenario: A deleted bundle never widens a refreshed token
- **WHEN** a token was granted only `read:docs`, the operator deletes `read:docs` from `hearth.yaml` and reloads, and the client refreshes
- **THEN** the refresh fails with `invalid_grant`, and no new token carries a permission outside the old `read:docs`

### Requirement: Revoking an application removes all of its consent
Revoking an application SHALL delete every consent row for that realm, user and client: the realm-level row, every organization row and every per-resource row under each of them. Revocation SHALL NOT be selectable per organization or per resource. A user revokes from `/ui/account/applications` (`POST /ui/account/applications/{client_id}/revoke`), and over the API with `DELETE /oauth/consents/{client_id}`. An admin revokes from `/ui/admin/realms/{realm}/users/{id}/applications` (`POST /ui/admin/realms/{realm}/users/{id}/applications/{client_id}/revoke`), and over the API with `DELETE /admin/users/{id}/consents/{client_id}`, with the same effect. The server SHALL emit one `ClientConsentRevoked` audit event per deleted row, carrying the actor, the row's `context_oid`, and its `resource_uri` (`null` for a default-audience row).

#### Scenario: An app with rows in two organizations and two resources
- **WHEN** a user revokes a client that holds consent rows in organizations A and B, each for Hearth and for `https://mcp.acme.com`
- **THEN** all four rows are deleted, and four `ClientConsentRevoked` events are recorded with `actor = user`

#### Scenario: Revoking an application removes every consent row
- **WHEN** a user holds consent rows for one client at realm level, in organization A, and for `https://mcp.acme.com`, and revokes the client
- **THEN** no consent row for that client remains, and one `ClientConsentRevoked` event is recorded per deleted row
