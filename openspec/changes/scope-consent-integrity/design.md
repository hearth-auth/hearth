## Context

A token's `scope` and `permissions` come from the scopes a client asks for. Consent records what a user agreed to show a third-party client. Today several issuance paths resolve scopes in their own way, and consent is always stored at realm level for Hearth as audience. This change gives every path one scope-resolution entry point, gives consent one key with the organization and the resource, and gives the browser flow an organization context, so that the key has something to bind to.

**Precedent.** The owner's rule for this change: Hearth's flow matches large identity providers (Auth0, Okta, Entra ID, Keycloak), and Hearth is stricter wherever they fall short of best practice.

| Question | Precedent | Hearth |
|---|---|---|
| Organization at sign-in | Auth0 `organization` parameter on `/authorize`; Keycloak `organization` scope | `organization` parameter (§1) |
| Unknown scope | Okta and Entra refuse with `invalid_scope`; Auth0 and Keycloak drop it | Refuse (§2) |
| Scope the user cannot fully satisfy | Auth0 RBAC grants `requested ∩ held` | Grant only fully held bundles (§2) |
| When consent is asked again | Auth0 asks again only for new scopes | Ask again only when disclosure grows (§5) |
| `resource` that differs from the grant | RFC 8707 §2.2: `invalid_target` | `invalid_target` (§2) |

## Goals / Non-Goals

**Goals:**
- One scope-resolution entry point, used by the browser consent gate, `/authorize`, PAR, the code exchange, the device grant, `client_credentials`, refresh and introspection.
- A scope that the registry does not know never reaches a token, and never widens one.
- Consent keyed by user, client, organization and resource, with one lookup.
- A consent that covers less than the client now receives is not reused.

**Non-Goals:**
- An organization picker in the login UI, and a client setting that requires an organization (Auth0 `organization_usage: require`). Both are possible follow-ups. Without the parameter, the flow stays in realm context.
- An organization context for the device grant. It stays in realm context.
- A path for an admin to grant consent on a user's behalf.

## Decisions

### 1. Organization context at `/authorize`

- `/authorize` accepts an optional `organization` parameter: an organization ID or slug in the realm. Every authorization surface accepts it: the browser query, JAR, PAR, and `/authorize` over JSON through a pushed `request_uri`.
- The server accepts it only when the organization is `Active` and the signed-in user has an active membership. Any other case (unknown, suspended, archived, not a member) is one refusal: an error redirect with `error=access_denied` and one fixed `error_description`. The refusal does not reveal which case applied.
- The authorization code stores the organization ID. The access token, the refresh token and the ID token carry it as `oid`.
- RBAC resolution uses that organization, so organization-scoped role assignments apply (`rbac-model`).
- Refresh carries `oid` forward (as today) and resolves RBAC in that organization. Today refresh resolves with no organization. Refresh re-checks the membership. When the organization is no longer `Active` or the user is no longer a member, the refresh fails with `invalid_grant`.

### 2. One scope-resolution entry point

A new engine function takes the realm, the user (none for `client_credentials`), the client, the requested scopes, the canonical resource and the organization. It returns the granted scopes, the permissions and the skipped orphans, or `invalid_scope`.

1. **Classify** each scope with `classify_scope_string`: OIDC standard, bundle, raw permission, or neither.
2. **Select the registry** from the audience (`custom-permissions` "The token audience selects the scope registry"). Under a `resource`, the legal scopes are the OIDC scopes plus that resource's bundles. Without one, they are the OIDC scopes, the realm's bundles and, for a first-party client, raw permissions.
3. **Refuse unknown names.** A scope that is neither OIDC, nor in the selected registry, nor (first-party, no resource) a raw permission, fails the request with `invalid_scope`, for every trust level. A raw permission does not need a registry record, because a realm created at runtime has none. A non-empty `declared_scopes` must hold every non-OIDC scope, for every trust level (baseline "Requested scopes must be declared by the client").
4. **Decide what is grantable.** An OIDC scope is always grantable. A bundle is grantable only when the user holds every permission in it. A raw permission is grantable only when the user holds it. A bundle with no permissions is refused at config load, so a vacuous bundle cannot exist.
5. **Apply the trust level.** A first-party client gets the grantable scopes, and the rest are dropped. A third-party client fails with `invalid_scope` when any non-OIDC scope is not grantable. When the request names at least one scope and none is grantable, it fails for every trust level.
6. **Compute permissions.**
   - When the request named a bundle or raw permission, `permissions` is the union of the granted ones. A dropped bundle contributes nothing, so a request whose bundles were all dropped carries no permissions.
   - When the request named only OIDC scopes, a first-party client gets the user's full effective set (the first-party app acts as the user). A third-party client gets no permissions: none in the token, and none through introspection or decision mode.
7. **Return orphans.** `rbac` returns the references that it skipped (see §4). It writes no audit itself.

Two modes:
- **Request** (`/authorize`, the browser gate, the device grant, `client_credentials`, the JWT-bearer grant): the trust-level rules of steps 5 and 6.
- **Reissue** (the code exchange, refresh, live resolution): scopes granted earlier are resolved again. A scope the user no longer fully holds drops out, for every trust level. A scope the registry no longer knows fails with `invalid_grant`. Live resolution treats that as no authority.

**Narrowing is recorded.** When a grant named a permission-bearing scope, the code and the refresh family record `scope_narrowed`. Re-issue keeps the narrowing even when every such scope has dropped out. Without it, a first-party grant for `openid read:docs`, stored as `openid`, would re-resolve to the user's full set.

**Size caps.** The per-token caps (100 permissions, 50 roles, 50 groups) apply to what a token carries, after narrowing, on the paths that mint a token. `/authorize` only decides what is grantable.

Where it runs:
- The browser consent gate resolves first, through `IdentityEngine::authorization_scopes`, so the consent check, the consent screen and the code see only grantable scopes. A refusal redirects with `error=invalid_scope`.
- `/authorize` resolves after the resource is known. The code stores the **granted** scopes.
- The device authorization request checks legality only (no user yet). The token request resolves with the approving user.
- `client_credentials` and the JWT-bearer grant resolve with no user: scopes must be legal for the audience, and the token carries no permissions (as today).
- The code exchange, refresh and live resolution (introspection, decision, `/v1/me/permissions`) re-issue.
- Claim release gates (`required_scopes`) read the granted scopes only.

**`resource` on the token endpoint:**
- `client_credentials`: a registered resource is applied (`Audience::with_resource`). An unregistered one fails with `invalid_target`.
- `authorization_code` and `refresh_token`: an absent `resource`, or one equal in canonical form to the code's or the family's resource, is accepted. Any other value fails with `invalid_target` (RFC 8707 §2.2).

### 3. Gates and config

- Every managed client has a slug: its `slug` field, or its YAML key when the field is absent. Before, a missing slug fell back to the client name, the same rule a dynamically registered client gets. Config load refuses a repeated slug and names the clients.
- Each `allowed_clients` entry must be the slug of a managed client in the same realm. Any other value fails config load and names the entry. A typo and a dynamically registered client's slug look the same at load, and both are refused. At registry load each slug resolves to a client ID. The gate compares client IDs.
- Issuance drops every realm mapping that targets a Tier 1 claim before it evaluates the profile, and drops any Tier 1 name from the result. The built-in `permissions` mapping, sourced from the resolved permissions, is the only profile source of a Tier 1 claim. Core writes the others. This holds even for a claim profile that config load did not check.
- Resolution skips a role or permission that `hearth.yaml` removed (archived). A permission with no registry record at all stays granted: a realm created at runtime has no YAML vocabulary, so its roles name unregistered permissions.

### 4. Registry hygiene

- `scope_permissions` returns `None` for a missing scope row, not an empty list.
- `reconcile_scopes` deletes a bundle that the YAML no longer defines.
- Resolution checks extra permissions and role permissions against the registry (`permission_active`). A permission that left the registry is skipped.
- Every skipped reference goes into `ResolvedPermissions` as an orphan. The `identity` layer writes `OrphanedReferenceSkipped` for it. A bounded per-node limiter, keyed by realm and reference, allows one event per hour. In a cluster, each node can write one event per hour for the same reference. A cluster-wide limit would put a Raft write on the token path.
- At startup the validator logs one `warn` summary of orphaned references.

### 5. Consent

**Key and lookup:**
- One `ConsentKey`: user, client, organization (none for realm context) and canonical resource (none for Hearth as audience).
- One lookup, used by the browser gate, `/authorize` and refresh:
  1. the exact row;
  2. then the realm-context row, only when the user is in an organization and the client sets `consent_spans_orgs: true`;
  3. never a row for another resource.
- The legacy `(user, client)` key and its read, merge and delete code are deleted. Hearth has no deployed data to migrate.
- Consent applies only to third-party clients. First-party clients have no consent ceremony and no consent check.

**Row:**
- The scopes as granted, the organization, the resource, `granted_at`, `updated_at`, `granted_by` (the signed-in user's ID) and `granted_via` (`web` or `device`).
- The **disclosure set**: the sorted, de-duplicated permissions that the granted scopes resolve to, plus the sorted `claim@target` pairs that the claim profile would emit to this client for those scopes and that resource. OIDC scopes add fixed sentinel entries.

**Check.** At the gate, at `/authorize` and at refresh, the server computes the current disclosure set. The consent holds while the current set is a subset of the stored set.
- A new mapper, a broadened bundle or a claim on a new target grows the set, so the user is asked again.
- A removed mapper or a narrowed bundle shrinks the set, so nothing changes. Issued tokens stay valid.

This replaces the scope-name digest. The row stores the set itself, so the subset test needs no hash.

**Refresh (third-party):**

| Change since consent | Outcome |
|---|---|
| The disclosure set grew | `invalid_grant`, `error_description=consent_required`, audit `ConsentRequiredOnRefresh` |
| A granted scope is no longer in the registry | `invalid_grant`, `error_description=consent_required`; the whole consent row is deleted |
| The user no longer fully holds a granted bundle | succeeds; the bundle drops out of `scope` |
| Nothing grantable remains | `invalid_grant` |
| The request names a different `resource` | `invalid_target` |

A first-party refresh re-resolves too, with the same scope rules and no consent step.

**Revoke.** Revoking an application deletes every row under `(user, client)`: all organizations and all resources. It writes one `ClientConsentRevoked` per row, with the real actor (the user, or the admin), the row's organization and its resource. It also revokes the matching grant families, as today.

### 6. Delivery

Three PRs, in order:
1. Registry hygiene and gates and config (§3, §4).
2. Scope resolution (§2).
3. Organization context and consent (§1, §5).

## Risks / Trade-offs

- **Refusing unknown scopes is stricter than Auth0 and Keycloak.** A client that sends a scope nobody defined gets `invalid_scope` instead of a quiet drop. Okta and Entra already do this, and it surfaces client bugs early.
- **A consent row holds its disclosure set.** The row grows with the number of permissions and claims. That is bounded by the registry size and read once per authorization.
- **Deleting a bundle from YAML ends every refresh family that holds it,** on the next refresh. The client sends the user through `/authorize` again. This is the intent of "a deleted bundle never widens a token".
- **The organization refusal is one generic error.** A client cannot tell "not a member" from "no such organization", by design.
- **Per-node orphan audit:** the same orphan can be audited once per node per hour.
