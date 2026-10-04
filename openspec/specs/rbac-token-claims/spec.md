# rbac-token-claims Specification

## Purpose
The authorization claims in issued tokens: the claim schema, scope narrowing, permission-delivery modes, session-version (`sv`) revocation, and the permissions of delegated (`act`) tokens.
## Requirements
### Requirement: Access tokens carry identity and RBAC claims
An access token SHALL carry the claims `sub`, `iss`, `aud`, `exp`, `iat`, `sid`, `tid`, `token_type`, `jti` and `scope`, and, in `embedded` mode, `roles`, `groups` and `permissions`. Refresh tokens carry them where applicable. `tid` (the realm ID) SHALL always be present; every permission check is implicitly bound to it. `oid` (the organization ID) SHALL be present only when the token was issued in an organization context; its presence MAY enable organization-scoped role assignments. `roles` and `groups` SHALL carry names (role names and group slugs), not IDs; they are informational. `permissions` SHALL carry the resolved flat set, and it is the authoritative claim: client-side permission checks read exclusively from it. A `client_credentials` token has no user: it SHALL carry no `roles`, `groups` or `permissions`.

#### Scenario: A client-credentials token
- **WHEN** a machine client obtains a token with the `client_credentials` grant
- **THEN** the token carries no `roles`, `groups` or `permissions` claim

#### Scenario: A typical user token
- **WHEN** `alice` in realm `acme`, organization `acme-corp`, holds `docs.admin` (with parent `docs.editor`) through the groups `leads` and `engineers`, and obtains a token with `scope=openid profile docs`
- **THEN** the token carries `tid`, `oid`, `token_type: access`, `sid`, `jti`, `scope: "openid profile docs"`, `roles: ["docs.admin"]`, `groups: ["leads", "engineers"]` and `permissions: ["docs.view", "docs.edit", "docs.delete"]`

#### Scenario: A token issued outside an organization
- **WHEN** a token is issued with no organization context
- **THEN** it carries no `oid` claim

### Requirement: RBAC-bearing tokens are Ed25519-signed and realm-bound
Tokens MUST be signed with Ed25519, in every permission-delivery mode. A verifier MUST reject `alg: none` and symmetric algorithms. A token MUST carry the `iss`, `aud` and `tid` of the target realm. A verifier MUST NOT accept a token from another realm.

#### Scenario: An unsigned token
- **WHEN** a token with `alg: none` is presented
- **THEN** it is rejected

#### Scenario: A token from another realm
- **WHEN** a token whose `tid` names realm A is presented to realm B
- **THEN** it is rejected

### Requirement: An oversize claim set fails issuance
When the resolved claim set exceeds any token-size bound, token issuance SHALL fail with HTTP `413 Payload Too Large` and the body `{"error": "token too large", "error_code": "HEARTH_TOKEN_TOO_LARGE"}`. The access-token, ID-token and userinfo payloads SHALL each be checked against the same bounds. The internal error SHALL name the bound with its target as a prefix (`access_token_`, `id_token_` or `userinfo_`), followed by `permissions_per_token`, `roles_per_token`, `groups_per_token` or `claims_bytes_per_token`, with the limit and the actual value. Clients handle the error by requesting a narrower scope. Operators who see it persistently should audit the user's role assignments for over-broad roles.

#### Scenario: A user resolves to 127 permissions
- **WHEN** a token is requested for a user whose resolved set holds 127 permissions
- **THEN** the response is `413` with `error` `token too large` and `error_code` `HEARTH_TOKEN_TOO_LARGE`
- **AND** no token is issued

### Requirement: Issuance resolves RBAC before it signs
For every grant that issues a user token, the identity layer SHALL resolve the user's permissions through the RBAC engine (realm, user, session, organization and requested scope), then check the result against the token-size bounds, then build the claims, then sign the token. A token SHALL NOT be signed before its claim set passed the size check.

#### Scenario: Authenticate, assign, issue
- **WHEN** a user authenticates, an admin assigns the user a role, and the user obtains a token
- **THEN** the token's `permissions` claim grants the role's permissions

### Requirement: The granted scope narrows embedded permissions
`POST /token` SHALL accept the standard OAuth 2.0 `scope` parameter and pass it to resolution as the requested scope. A missing `scope` parameter SHALL mean no narrowing: the full resolved set is embedded. Every permission-bearing scope of the grant SHALL narrow: the effective set is intersected with the union of what the scopes admit. A raw permission scope (`docs.view`) admits that permission. A scope registered in the realm's scope registry with a permission list admits those permissions. OIDC standard scopes, and scopes the realm registry does not know (such as a protected resource's MCP scope), admit nothing and narrow nothing. A grant with no permission-bearing scope resolves to the full effective set, so an extra scope never buys more authority: `openid docs:read` resolves exactly as `docs:read`. The authorization-code exchange, every refresh rotation and the device grant SHALL apply this rule to an `embedded` token's `permissions`. The refresh token SHALL carry the grant's `scope`, so a token narrowed to a bundle stays narrowed after refresh.

#### Scenario: A scope narrows the token
- **WHEN** a user holds `docs.view`, `docs.edit` and `hearth.admin`, the realm registers the scope `docs:edit` with `docs.view` and `docs.edit`, and a token is requested with `scope=docs:edit`
- **THEN** the token's `permissions` are `["docs.view", "docs.edit"]`

#### Scenario: An OIDC scope does not widen a narrowed token
- **WHEN** a token is granted `openid docs:read`
- **THEN** its permissions equal those of a token granted `docs:read`

#### Scenario: Refresh keeps the narrowing
- **WHEN** a token narrowed to a bundle is refreshed
- **THEN** the new access token carries the same narrowed permissions

### Requirement: Every OAuth client has an access-token authorization mode
Every OAuth client SHALL carry an `access_token_authorization` field that decides which RBAC claims the issued token embeds and how resource servers obtain RBAC data:

| Mode | Enum value | RBAC claims in the JWT | Live RBAC call |
|------|------------|------------------------|----------------|
| `embedded` | `EMBEDDED` (default) | `roles`, `groups`, `permissions` | none |
| `introspection` | `INTROSPECTION` | none | `POST /realms/{realm}/introspect` |
| `decision` | `DECISION` | none | `POST /oauth/authorize` |

`embedded` MUST be the mode of every client whose `access_token_authorization` is omitted. An admin SHALL set the mode on the client record through the admin API, at registration (`POST /admin/applications`) or later (`PATCH /admin/applications/{id}`).

#### Scenario: A client registered without the field
- **WHEN** an admin registers a client and omits `access_token_authorization`
- **THEN** the client's mode is `embedded`

#### Scenario: A client switched to introspection
- **WHEN** an admin sends `PATCH /admin/applications/{id}` with `{ "access_token_authorization": "introspection" }`
- **THEN** later tokens for that client carry no `roles`, `groups` or `permissions` claims

### Requirement: Embedded mode resolves RBAC into the token
In `embedded` mode Hearth SHALL resolve RBAC at token issuance and embed the claim set in the JWT. Resource servers verify the signature locally and read claims from the token, with no network call at authorization time. Permission changes SHALL take effect at the next token refresh, bounded by `access_token_ttl`. The token-size bounds apply, and issuance SHALL fail when the resolved set exceeds them. Validating an `embedded` token SHALL need zero heap allocations, no syscalls and no network calls.

#### Scenario: A resource server authorizes an embedded token
- **WHEN** a resource server receives an `embedded` token that carries `docs.edit`
- **THEN** it verifies the Ed25519 signature with the realm's JWKS and authorizes from the `permissions` claim, with no call to Hearth

### Requirement: Introspection and decision tokens carry no RBAC claims
When a client is in `introspection` or `decision` mode, the issued JWT SHALL carry only identity claims (`sub`, `tid`, `sid`, `iss`, `exp`, `iat`, `jti`, `scope`). The `roles`, `groups` and `permissions` claims SHALL be omitted.

#### Scenario: A decision-mode client's token
- **WHEN** a user obtains a token through a client in `decision` mode
- **THEN** the token has no `roles`, `groups` or `permissions` claim

### Requirement: Introspection returns live RBAC to introspection-mode clients
`POST /realms/{realm_id}/introspect` SHALL accept the token in the `token` parameter, with an optional `token_type_hint`, and SHALL authenticate the client by HTTP Basic (`client_id:client_secret`) or by body fields. Hearth SHALL validate the token's signature, expiry and session liveness, then resolve RBAC live at introspection time. Hearth SHALL add `roles`, `groups`, `permissions` and `mode` to the RFC 7662 response only when the introspecting client itself has `access_token_authorization: introspection` or `decision`. An introspecting client in `embedded` mode SHALL receive a standard RFC 7662 response without those fields. An inactive token SHALL produce `{ "active": false }` with every other field omitted (RFC 7662 §2.2). The live `roles`, `groups` and `permissions` are the token's authority, not the user's.

#### Scenario: An introspection-mode resource server introspects an active token
- **WHEN** an `introspection`-mode client posts an active access token
- **THEN** the response holds `active: true`, `sub`, `client_id`, `scope`, `exp`, `iss`, `mode: "introspection"`, and the live `permissions`, `roles` and `groups`

#### Scenario: An embedded-mode client introspects
- **WHEN** an `embedded`-mode client introspects an active token
- **THEN** the response is a standard RFC 7662 response with no `permissions`, `roles` or `groups`

#### Scenario: An inactive token
- **WHEN** an expired or revoked token is introspected
- **THEN** the response is `{ "active": false }` and carries no other field

### Requirement: Introspection is restricted to the token's audience
A client SHALL introspect only a token explicitly bound to it (RFC 7662 §2). A member of the token's `aud` is named by its issued `client_id`. A client that introspects as the resource server of a protected resource named in the token's `aud` SHALL count as an `aud` member under every rule below.

- A token that carries an `azp` claim SHALL be introspectable only by the `azp` client or by a member of the token's `aud`.
- A token with no `azp` and `sid == "none"` (a `client_credentials` token) SHALL be introspectable only by the issuing client (`sub == client_id`) or by an explicit `aud` member.
- A user-session token with no `azp` SHALL be introspectable only by an `aud` member, by an active client in `introspection` or `decision` mode, by the client that an RFC 8693 exchanged token's outermost `act.sub` names, or by the client the token's grant family was issued to.

Every other case SHALL return `{ "active": false }`.

#### Scenario: Resource server A introspects a token for resource server B
- **WHEN** client A introspects a `client_credentials` token issued to client B whose `aud` does not name A
- **THEN** the response is `{ "active": false }`

#### Scenario: A bound token introspected by its authorized party
- **WHEN** the client named in a token's `azp` introspects that token
- **THEN** the token is reported according to its state

#### Scenario: An unrelated embedded-mode client introspects a user token
- **WHEN** an `embedded`-mode client that is not in the token's `aud` and did not receive the token's grant introspects a user-session token with no `azp`
- **THEN** the response is `{ "active": false }`

#### Scenario: The client that received the grant introspects its user token
- **WHEN** the client a user-session token's grant family was issued to introspects that token
- **THEN** the token is reported according to its state

### Requirement: The decision endpoint answers one permission per call
In `decision` mode, resource servers MUST call `POST /oauth/authorize` once per protected request. The request SHALL carry `Authorization: Bearer <access_token>`, `X-Realm-ID: <realm_uuid>`, `Content-Type: application/json`, and a JSON body with `permission` (required), `organization_id` (optional) and `resource` (optional, an RFC 8707 resource URI). The organization context SHALL be the token's own `oid`; without `oid`, only realm scope applies. `organization_id` MAY restate the token's `oid`; naming any other organization, or naming any organization for a token minted without `oid`, SHALL answer `{"allowed": false}`. When `resource` is present it MUST be named by the token's `aud`, compared in canonical form; otherwise the answer SHALL be `{"allowed": false}`. The token MUST pass every check that token validation applies, and the decision SHALL be taken against the token's live authority. Client-credential tokens have no user and SHALL always be denied. Every valid request SHALL get HTTP `200` with `{ "allowed": true }` or `{ "allowed": false }`. A request with no `permission` field SHALL get HTTP `400`.

#### Scenario: A held permission
- **WHEN** a valid user token whose live authority includes `docs.edit` asks for `docs.edit`
- **THEN** the response is `200` with `{ "allowed": true }`

#### Scenario: Another organization
- **WHEN** a token minted in organization A asks with `organization_id` naming organization B
- **THEN** the response is `200` with `{ "allowed": false }`

#### Scenario: A resource outside the audience
- **WHEN** a token minted for resource server A asks with a `resource` that its `aud` does not name
- **THEN** the response is `200` with `{ "allowed": false }`

#### Scenario: The permission field is missing
- **WHEN** the body has no `permission`
- **THEN** the response is `400`

### Requirement: The decision endpoint fails closed
Hearth MUST answer `{"allowed": false}`, never `{"allowed": true}`, when the signature is invalid, the token is expired, the session is revoked, the token is on the JTI blocklist, the token's `aud` names a removed protected resource, the token's `cnf.jkt` is blocked, `resource` is not in the token's `aud`, or the requested permission is not in the token's live authority. An internal resolution error SHALL also answer `200` with `{"allowed": false}`. The answer SHALL NOT distinguish between an invalid token, an expired session, a missing permission and an internal error.

#### Scenario: A revoked session
- **WHEN** a token whose session was revoked asks for a permission the user holds
- **THEN** the response is `200` with `{ "allowed": false }`

#### Scenario: A blocked DPoP key
- **WHEN** a token whose `cnf.jkt` is blocked asks for any permission
- **THEN** the response is `200` with `{ "allowed": false }`

### Requirement: The decision endpoint is an internal service endpoint
`POST /oauth/authorize` MUST be treated as an internal service endpoint. Operators MUST NOT expose it to the public internet or to browser clients. Resource servers SHOULD implement a circuit breaker or a timeout, so a Hearth slowdown cannot stall every protected request. On an HTTP `5xx`, resource servers SHOULD deny the request and SHOULD NOT retry in the hot path. On an HTTP `400`, resource servers deny the request and treat it as a client programming error.

#### Scenario: Hearth returns a server error
- **WHEN** a resource server receives `503` from `POST /oauth/authorize`
- **THEN** it denies the protected request without retrying in the request path

### Requirement: Live resolution answers for the token
Introspection, decision and `GET /v1/me/permissions` SHALL resolve RBAC live, and SHALL answer for the token, never for the user behind it. The live authority SHALL be what an `embedded` token issued to the same client for the same grant would carry, resolved at the time of the call:

1. The claim profile of the client the token was issued to applies. That client is named by the RFC 9068 `client_id` claim; a token without one is a Hearth first-party session token. Under the default claim profile, a third-party client's token SHALL resolve to no roles, groups or permissions unless the realm releases them to that client. A `client_id` that names an unknown client SHALL resolve to nothing.
2. Every permission-bearing scope of the token SHALL narrow, by the same rule that issuance applies.
3. A token that carries `act` (RFC 8693) SHALL be capped at the `permissions` it carries, and SHALL carry no roles or groups.

A client-credentials token has no user and SHALL resolve to nothing. Introspection, decision and `GET /v1/me/permissions` SHALL use the token's own `oid` as the organization context.

#### Scenario: A third-party client's token is introspected
- **WHEN** a token issued to a third-party client under the default claim profile is introspected by an `introspection`-mode client
- **THEN** `roles`, `groups` and `permissions` are empty
- **AND** `POST /oauth/authorize` with that token answers `{ "allowed": false }`

#### Scenario: A delegated token is checked live
- **WHEN** a delegated token carrying `permissions: ["docs.view"]` asks the decision endpoint for `docs.edit`, which the subject user holds
- **THEN** the answer is `{ "allowed": false }`

### Requirement: Resource-server obligations per mode
A resource server MUST follow the contract of the client's mode:

- All modes: verify the Ed25519 signature and the `iss`, `aud` and `tid` of the target realm.
- `embedded`: verify `exp`, `iat` and the signature on every request; accept that RBAC claims reflect the user's state at issuance and are stale after a role or group change until the next issuance; refresh the JWKS when signature verification fails.
- `introspection`: forward the bearer token in the `token` parameter; authenticate with `client_id` and `client_secret` by HTTP Basic on every call; treat `active: false` or any network error as a denial, and inspect no other field of an inactive response; authorize from the `permissions` field of the response. Introspection responses SHOULD NOT be cached, since caching defeats the freshness guarantee.
- `decision`: treat `allowed: false` as a denial whatever its cause; MUST NOT cache a decision across requests.

#### Scenario: An introspection call fails on the network
- **WHEN** an `introspection`-mode resource server cannot reach Hearth
- **THEN** it denies the request

#### Scenario: A signature does not verify
- **WHEN** an `embedded`-mode resource server fails to verify a token signature
- **THEN** it refreshes the realm's JWKS before it decides

### Requirement: Revocation propagation depends on the mode
Revoking a refresh token or a session SHALL NOT immediately invalidate access tokens already issued in `embedded` mode: their permissions persist until `access_token_ttl` expires (default 15 minutes). In `introspection` and `decision` modes, a revocation SHALL be reflected by the next `/introspect` or `/oauth/authorize` call, which re-checks session liveness. Operators who need tighter bounds in `embedded` mode configure a shorter `access_token_ttl` or enable session-version revocation.

#### Scenario: A session is revoked under each mode
- **WHEN** a user's session is revoked while an access token is outstanding
- **THEN** an `embedded` resource server keeps accepting the token until it expires
- **AND** the next introspection or decision call for that token denies it

### Requirement: Session-version claim and delta feed
Session-version (`sv`) revocation SHALL be opt-in per realm with `session_version.enabled: true`. While it is enabled, Hearth SHALL keep a monotonically increasing `u64` version per session and SHALL embed it in issued JWTs as the `sv` claim. Logout, admin revoke, password change and role or group change SHALL increment the version. Hearth SHALL publish changes as a compact delta feed at `GET /oauth/session-versions?since=<seq>`. A token without `sv` (issued before the feature was enabled, or while it is disabled) SHALL be validated by the existing path unchanged.

#### Scenario: A password change bumps the version
- **WHEN** a realm has `session_version.enabled: true` and a user changes password
- **THEN** the version of each of the user's sessions increases
- **AND** the change appears in `GET /oauth/session-versions?since=<seq>` for a `seq` before the change

#### Scenario: The feature is disabled
- **WHEN** a realm leaves `session_version.enabled` unset
- **THEN** issued tokens carry no `sv` claim and validate as before

### Requirement: Session-version freshness at resource servers
A resource server that uses `sv` SHALL keep a local `min_version[session_id]` cache, refreshed in the background by polling the delta feed, so validation adds one map lookup and no per-request network hop. The freshness window equals the poll interval: default 5 s, operator-configurable. When the cache is staler than `stale_threshold`, the resource server SHALL reject `sv`-bearing tokens rather than accept them silently; it MAY fall back to per-request introspection instead.

#### Scenario: The delta feed is unreachable
- **WHEN** a resource server's `sv` cache is older than `stale_threshold`
- **THEN** it rejects tokens that carry `sv`, or introspects them, and never accepts them unchecked

### Requirement: A delegated token carries the intersection of subject and actor permissions
When Hearth issues a delegated token by RFC 8693 token exchange (`urn:ietf:params:oauth:grant-type:token-exchange`), the token's `permissions` SHALL be the intersection of the subject token's `permissions` and the actor's `permissions`, as its scope is the intersection of subject, actor and requested scope. The delegated token's `roles` and `groups` SHALL be empty. An actor with no RBAC grants SHALL yield zero delegated permissions; operators grant the actor the permissions it legitimately needs. Resource servers keep reading the `permissions` claim.

#### Scenario: An agent exchanges an admin's token
- **WHEN** user Alice holds `{hearth.admin, docs.delete, billing.admin}`, agent Foo holds only `{tool.search_emails.invoke}`, and Foo exchanges Alice's access token
- **THEN** the delegated token carries `sub: alice` and `act: {sub: foo}`
- **AND** its `permissions` hold none of `hearth.admin`, `docs.delete` or `billing.admin`

#### Scenario: Permissions outside the actor's set
- **WHEN** an actor with permission set A exchanges a subject token with permission set B
- **THEN** no permission in B \ A is exercisable with the delegated token

