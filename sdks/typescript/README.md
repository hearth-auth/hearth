# Hearth TypeScript SDK

TypeScript client for the [Hearth](https://github.com/hearth-auth/hearth) identity API.

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/specs/SDK.md).

## Installation

```bash
npm install @hearth-auth/sdk
# or
yarn add @hearth-auth/sdk
# or
pnpm add @hearth-auth/sdk
```

**Peer dependencies:** both optional. React (`>=17 <20`) is needed only for the `HearthProvider` / `useHasPermission` hooks. Next.js (`>=14`) is needed only if you import `@hearth-auth/sdk/nextjs` or `@hearth-auth/sdk/nextjs/edge`.

| Import path | What it gives you |
|---|---|
| `@hearth-auth/sdk` | `HearthClient`, token verification, OAuth flows, Express/Fastify middleware, admin client, React hooks, browser auth |
| `@hearth-auth/sdk/nextjs` | `withHearthAuth` (Pages Router) and `getHearthClaims` (App Router Route Handlers) |
| `@hearth-auth/sdk/nextjs/edge` | `hearthEdgeMiddleware` for `middleware.ts` on the Edge Runtime |

---

## Quick start

```typescript
import { createHearth, HearthClient } from "@hearth-auth/sdk";

// Server-side client: discovery, token verification, OAuth flows
const client = new HearthClient({
  issuerUrl: "https://hearth.example.com",
  clientId: "<client-id>",
  clientSecret: "<client-secret>", // confidential clients only
  realmId: "<your-realm-id>",
});

const claims = await client.verifyToken(accessToken); // throws on a bad token
claims.subject();
claims.hasPermission("docs.write");

// RBAC facade — local, synchronous permission checks from the JWT
const hearth = createHearth({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
  getToken: () => localStorage.getItem("access_token"),
});
```

`HearthClient` reads every endpoint URL from `{issuerUrl}/.well-known/openid-configuration` on first use and caches it. `httpTimeout` (default 10 000 ms) applies to every request it makes. Call `client.invalidateCache()` to drop the cached discovery document, JWKS and introspection client.

`createHearth` gives you a zero-network RBAC facade that reads claims from the JWT in memory.

---

## Server-side login (authorization code with PKCE)

`beginLogin` builds the authorization URL with a fresh PKCE verifier and `state`. Keep both in your server-side session; on the callback, check `state` and call `completeLogin`.

```typescript
// GET /login
const { authorizationUrl, state, codeVerifier } = await client.beginLogin(
  "https://app.example.com/callback",
  "openid profile email", // default: "openid"
);
session.oauth = { state, codeVerifier };
res.redirect(authorizationUrl);

// GET /callback
const url = new URL(req.url, "https://app.example.com");
if (url.searchParams.get("state") !== session.oauth.state) throw new Error("state mismatch");
const tokens = await client.completeLogin(
  url.searchParams.get("code")!,
  session.oauth.codeVerifier,
  "https://app.example.com/callback",
);
// tokens.access_token, tokens.expires_in, tokens.refresh_token?, tokens.id_token?
```

`completeLogin(code, verifier, redirectUri)` is `exchangeCode(code, redirectUri, { codeVerifier })`. Call `exchangeCode` directly when you built the authorization URL yourself.

Both send `client_id` in the form body, plus `client_secret` when one is configured. A public client leaves `clientSecret` unset and relies on PKCE.

### Refreshing tokens

```typescript
const refreshed = await client.refreshTokens(tokens.refresh_token!);
// Store refreshed.refresh_token when present — Hearth rotates refresh tokens.
```

Pass a second argument to request a narrower scope.

### Other grants

| Method | Grant |
|---|---|
| `clientCredentials(scope?)` | Client credentials (RFC 6749 §4.4) |
| `startDeviceFlow(scope?)`, `pollDeviceToken(deviceCode, interval)` | Device authorization (RFC 8628) |
| `requestMagicLink(email)`, `exchangeMagicLink(token)` | Passwordless magic link (needs `realmId`) |

Every token-endpoint failure throws `OAuthFlowError` with `statusCode` and the OAuth `errorCode` (for example `invalid_grant`). A network failure or timeout has `statusCode` 0.

### Browser apps

A single-page app has no server session to hold the verifier. Use `createHearthAuth`, or build the flow from `generateCodeVerifier`, `generateCodeChallenge` and `buildAuthorizationUrl`.

---

## RBAC capabilities

All synchronous helpers decode the JWT returned by `getToken()` **locally** — no network call, no cache, no lock. When the token is absent or malformed, every predicate returns `false`.

```typescript
const hearth = createHearth({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
  getToken: () => sessionStorage.getItem("access_token"),
});
```

### `hasPermission(permission: string): boolean`

Returns `true` iff the JWT `permissions` claim contains `permission`. Use this for feature gates and API guards.

```typescript
if (hearth.hasPermission("docs.versions.read")) {
  renderVersionHistory();
}
```

### `hasRole(role: string): boolean`

Returns `true` iff the JWT `roles` claim contains `role`. Useful for UI personalization and coarse-grained access.

```typescript
if (hearth.hasRole("billing-admin")) {
  renderBillingPanel();
}
```

### `inGroup(group: string): boolean`

Returns `true` iff the JWT `groups` claim contains the group slug.

```typescript
if (hearth.inGroup("engineering")) {
  renderInternalToolingLink();
}
```

### `inOrg(org: string): boolean`

Returns `true` iff the JWT `oid` claim equals the given org ID.

```typescript
if (hearth.inOrg("org_acme")) {
  renderAcmeContent();
}
```

### `client.permissions(): Promise<MePermissionsResponse>`

Calls `GET /v1/me/permissions` and returns the **freshly-resolved** RBAC claim set from the server. Unlike the synchronous helpers above, this reflects any role/group assignments made since the JWT was issued.

```typescript
const { roles, groups, permissions } = await hearth.client.permissions();
```

Use `client.permissions()` when you need post-issuance accuracy (e.g., after an admin operation). For every other check, prefer the synchronous local helpers — they're faster and don't touch the network.

---

## React integration

The React hooks are exported from the main `@hearth-auth/sdk` package. No subpath import needed.

```tsx
import {
  createHearth,
  HearthProvider,
  useHasPermission,
  useHasRole,
  useInGroup,
  useInOrg,
} from "@hearth-auth/sdk";

// 1. Create the facade once at app startup
const hearth = createHearth({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
  getToken: () => localStorage.getItem("access_token"),
});

// 2. Mount the provider at the root of your React tree
function App() {
  return (
    <HearthProvider client={hearth}>
      <Router />
    </HearthProvider>
  );
}

// 3. Use hooks anywhere in the tree — no prop drilling
function NavBar() {
  const canEdit   = useHasPermission("docs.write");
  const isAdmin   = useHasRole("admin");
  const inEng     = useInGroup("engineering");
  const isAcme    = useInOrg("org_acme");

  return (
    <nav>
      {canEdit   && <a href="/editor">Editor</a>}
      {isAdmin   && <a href="/admin">Admin</a>}
      {inEng     && <a href="/internal">Internal tools</a>}
      {isAcme    && <a href="/acme">Acme portal</a>}
    </nav>
  );
}
```

All hooks return `false` when no `HearthProvider` is mounted, making them safe to call in tests without a provider.

---

## UserInfo and live permissions

`userinfo` calls the discovered `userinfo_endpoint`. It returns OIDC claims filtered by the granted scopes: `sub` is always present; `name` needs the `profile` scope; `email` and `email_verified` need `email`.

```typescript
const info = await client.userinfo(accessToken);
// info.sub, info.name?, info.email?, info.email_verified?, plus any other released claim
```

`mePermissions` calls `GET /v1/me/permissions` and returns the user's roles, groups and permissions as they are now on the server, including changes made after the token was issued. It needs `realmId`.

```typescript
const { roles, groups, permissions } = await client.mePermissions(accessToken);
```

### Session-version feed

`svSnapshot` and `svDelta` read the session-version feed (RFC HEA-930) that lets a resource server see session revocations without introspecting every token. Both need `realmId` and a service token with the `hearth.sv_feed` scope.

```typescript
const snap = await client.svSnapshot(serviceToken); // { current_seq, versions: { [sessionId]: minSv } }
const delta = await client.svDelta(serviceToken, snap.current_seq, 500); // null when nothing changed
```

`SessionVersionCache` runs this loop for you and checks a token's `sv` claim without a network call.

---

## JWKS and discovery

```typescript
// The discovery document (cached after the first call)
const discovery = await client.discover();

// Verify an access token: EdDSA signature against the realm JWKS, then exp,
// nbf, iss (must equal issuerUrl) and aud (must contain clientId, when set).
const claims = await client.verifyToken(accessToken);
claims.subject();          // sub
claims.scopes();           // scope split into an array
claims.requiredActions();  // required_actions, [] when absent
claims.raw();              // the whole payload, frozen
```

The JWKS is cached; on an unknown `kid` it is fetched again once before the token is refused. `client.jwksClient()` returns the underlying `JwksClient` if you need it directly.

---

## Admin API

`AdminClient` wraps the `/admin/*` endpoints. Construct it with a bearer token that carries the `hearth.admin` permission. Empty arguments throw `ConfigurationError`.

```typescript
import { AdminClient } from "@hearth-auth/sdk";

const admin = new AdminClient("https://hearth.example.com", "<realm-id>", accessToken);
```

Every list method takes `{ limit?, cursor? }` and returns `{ items, next_cursor }`. Pass `next_cursor` back as `cursor` until it is `null`. Every non-2xx response throws `HearthError` with `status` and `body` (parsed JSON, or the raw text when the body is not JSON).

### Users

```typescript
// Create a user
const user = await admin.createUser({
  email: "alice@example.com",
  displayName: "Alice",
});

// List users (paginated)
const page = await admin.listUsers({ limit: 50 });
// page.items: User[], page.next_cursor: string | null

// Get a user by ID
const user = await admin.getUser("<user-id>");

// Update a user
const updated = await admin.updateUser("<user-id>", {
  displayName: "Alice Smith",
  status: "USER_STATUS_ACTIVE", // the proto enum name; "active" is refused
});

// Delete a user
await admin.deleteUser("<user-id>");
```

### Realms

```typescript
// Realms are provisioned via hearth.yaml, not the admin API — there is no
// createRealm() or updateRealm() (the server returns 405).

// List realms (paginated)
const page = await admin.listRealms({ limit: 20 });

// Get a realm by ID
const realm = await admin.getRealm("<realm-id>");

// Delete a realm (cascades users, sessions, clients, assignments)
await admin.deleteRealm("<realm-id>");
```

### Clients, roles and groups

`createClient`, `getClient`, `updateClient`, `regenerateClientSecret`, `deleteClient`, `listClients`, and the same create/get/update/delete/list set for roles and groups.

### Organizations

```typescript
// Create an organization (slug is immutable after creation)
const org = await admin.createOrganization({
  slug: "acme",
  display_name: "Acme Corp",
  mfa_required: true, // members need MFA even where the realm does not
});

// List, get, update, delete
const page = await admin.listOrganizations({ limit: 50 });
const same = await admin.getOrganization(org.id);
await admin.updateOrganization(org.id, { status: "suspended" });
await admin.deleteOrganization(org.id);

// Extra org roles of one member (the user must already be a member)
await admin.addMemberRole(org.id, "<user-id>", "billing");
const roles = await admin.listMemberRoles(org.id, "<user-id>"); // ["billing"]
await admin.removeMemberRole(org.id, "<user-id>", "billing");
```

`Organization`, `CreateOrganizationParams` and `UpdateOrganizationParams` are exported types.

### Generated client

Routes and path parameters come from a client generated from Hearth's OpenAPI document (`src/generated/admin/schema.ts`, by `openapi-typescript`, called through `openapi-fetch`). Regenerate it with `make sdk-admin-gen` from the repository root; never edit it by hand.

---

## Error handling

Errors raised by the SDK itself extend `HearthSdkError`:

| Error | When |
|---|---|
| `ConfigurationError` | A required setting is missing (`clientId`, `realmId`, a discovery endpoint) |
| `DiscoveryError` | The discovery document cannot be fetched or is invalid |
| `JWKSFetchError` | The JWKS cannot be fetched |
| `TokenVerificationError` | Base class of every token failure below |
| `TokenExpiredError`, `TokenNotYetValidError` | `exp` / `nbf` outside the clock-skew window |
| `TokenInvalidError` | Bad signature, wrong algorithm, malformed JWT |
| `TokenIssuerError`, `TokenAudienceError` | `iss` / `aud` mismatch |
| `IntrospectionError` | The introspection request failed or returned non-JSON |
| `OAuthFlowError` | A token, userinfo, permissions or session-version request failed (`statusCode`, `errorCode`) |
| `AuthorizationModeMismatchError` | Introspection echoed a mode other than `expectedMode` |
| `RequiredActionError`, `SessionVersionRevokedError`, `SessionVersionCacheStaleError` | See their doc comments |

Any JWT-shaped string in an error message is replaced with `[redacted]`, so logging an error does not log a token.

`AdminClient` and `HearthApiClient` throw `HearthError` on a non-2xx response: `status` is the HTTP status code, `body` the parsed JSON (or raw text).

```typescript
import { HearthError, OAuthFlowError, TokenVerificationError } from "@hearth-auth/sdk";

try {
  await client.verifyToken(token);
} catch (err) {
  if (err instanceof TokenVerificationError) return res.status(401).end();
  throw err;
}
```

---

## Dev bootstrap (development only)

The bootstrap endpoint creates a realm, admin user, session, assigns the `realm.admin` role, and returns tokens. It is available only when Hearth is running with `--dev`. In production, it returns 404.

```typescript
import { AdminClient, HearthApiClient } from "@hearth-auth/sdk";

const { realm_id, user_id, access_token, refresh_token } =
  await HearthApiClient.bootstrap("http://127.0.0.1:8420");

// Use realm_id and access_token to make subsequent requests
const admin = new AdminClient("http://127.0.0.1:8420", realm_id, access_token);
```

---

## Type reference

```typescript
// HearthClientConfig — constructor argument for HearthClient
interface HearthClientConfig {
  issuerUrl: string;            // e.g. "https://hearth.example.com"; endpoints are discovered from it
  clientId?: string;            // needed for login flows, introspection; pins `aud` on verifyToken
  clientSecret?: string;        // confidential clients only
  realmId?: string;             // sent as X-Realm-ID; needed by authorize, mePermissions, sv feed, magic link
  httpTimeout?: number;         // ms, default 10 000
  jwksTtl?: number;             // ms, default 5 minutes
  introspectionEndpoint?: string;
  expectedMode?: "embedded" | "introspection" | "decision";
}

// HearthOptions — argument to createHearth()
interface HearthOptions {
  baseUrl: string;
  realmId: string;
  getToken: () => string | null | undefined; // called on every predicate check
}

// HearthFacade — returned by createHearth()
interface HearthFacade {
  hasPermission(permission: string): boolean;
  hasRole(role: string): boolean;
  inGroup(group: string): boolean;
  inOrg(org: string): boolean;
  client: { permissions(): Promise<MePermissionsResponse> };
}

// AuthorizeParams
interface AuthorizeParams {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  userId: string;
  responseType?: string;       // default: "code"
  codeChallenge?: string;      // S256 challenge; required for PKCE
  codeChallengeMethod?: string; // "S256"
  nonce?: string;              // echoed in the ID token
}

// TokenExchangeParams
interface TokenExchangeParams {
  clientId: string;
  code: string;
  redirectUri: string;
  codeVerifier?: string; // required when codeChallenge was sent on authorize
}

// TokenResponse
interface TokenResponse {
  access_token: string;
  token_type: string;      // "Bearer"
  expires_in: number;      // seconds
  refresh_token?: string;  // absent for client credentials
  id_token?: string;       // present when `openid` was granted
  scope?: string;
}

// LoginBeginResult — returned by beginLogin()
interface LoginBeginResult {
  authorizationUrl: string;
  state: string;
  codeVerifier: string;
}

// UserInfoResponse
interface UserInfoResponse {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  preferred_username?: string;
  [claim: string]: unknown;
}

// MePermissionsResponse — from GET /v1/me/permissions
interface MePermissionsResponse {
  roles: string[];
  groups: string[];
  permissions: string[];
  scope: string;
}

// User
interface User {
  id: string;
  email: string;
  display_name: string;
  status: string;
  created_at?: number; // Unix epoch seconds
  updated_at?: number;
}

// Realm
interface Realm {
  id: string;
  name: string;
  status: string;
  config: Record<string, unknown> | null;
  created_at?: number;
  updated_at?: number;
}

// OAuthClient — returned by registerClient()
interface OAuthClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  created_at?: number;
}

// PageResponse<T> — paginated list
interface PageResponse<T> {
  items: T[];
  next_cursor: string | null; // pass as cursor on the next request, or null if last page
}

// HearthError
class HearthError extends Error {
  status: number;   // HTTP status code
  body: unknown;    // parsed JSON error body
}
```


## Troubleshooting

**`DiscoveryError`** — verify `issuerUrl` is reachable and returns a valid `/.well-known/openid-configuration`.

**`JWKSFetchError`** — check network connectivity to the JWKS endpoint. The SDK retries once on a cache miss before returning this error.

**`TokenExpiredError`** — the token's `exp` claim is in the past. Refresh the token or re-authenticate.

**`TokenInvalidError`** — JWT signature does not match any key in the JWKS. If the server recently rotated keys the SDK will re-fetch once automatically; persistent failures indicate a key mismatch.

**`TokenAudienceError`** — the token's `aud` claim does not contain the configured audience. Verify `clientId` matches the audience your authorization server issues.

**`AuthorizationModeMismatchError`** — the server echoed an `access_token_authorization` mode
that differs from the SDK's `expectedMode` config or the `mode` passed to `requirePermission`.
Verify the `OAuthClient` admin setting matches the resource server's SDK configuration.

See [docs/specs/SDK.md](../../docs/specs/SDK.md) Section 5 for the full error taxonomy.

---

## Permission delivery modes (HEA-922/923)

Hearth supports three modes for delivering RBAC data to resource servers. Pick one when
registering the OAuth client; the SDK validates you stay consistent.

### Embedded (default)

RBAC claims (`permissions`, `roles`, `groups`) are embedded in the JWT at issuance. The
checker verifies the token first — EdDSA signature against the realm's JWKS, plus `exp`,
`nbf`, `iss` and (when `clientId` is set) `aud` — and only then reads the claim. The JWKS
is cached, so after the first request there is no network traffic per check.

A token that does not verify returns `false`; the checker never trusts an unverified
payload.

```typescript
import { HearthClient, requirePermission } from "@hearth-auth/sdk";

const client = new HearthClient({
  issuerUrl: "https://auth.example.com",
  clientId: "<your-client-id>", // enables `aud` pinning
});

const check = requirePermission("docs.write", { mode: "embedded", client });

// Verifies the token, then reads its permissions claim.
const allowed = await check(accessToken);
```

> **Security note.** Before v1.1 this checker called `decodeJwt` and trusted whatever the
> payload said, so an `alg: none` token carrying `permissions: ["admin.write"]` was
> accepted. If you pinned an older version, upgrade.

### Decision (per-request server check)

JWT carries only identity claims. The SDK calls `POST /oauth/authorize` on every check.
Fail-closed: any network or server error returns `false`.

```typescript
import { HearthClient, requirePermission } from "@hearth-auth/sdk";

const client = new HearthClient({
  issuerUrl: "https://auth.example.com",
  realmId: "<realm-id>",
});

// Low-level: call authorize() directly
const allowed = await client.authorize(accessToken, "docs.write");

// Middleware factory
const check = requirePermission("docs.write", { mode: "decision", client });
const allowed2 = await check(accessToken);
```

### Introspection (live RBAC via /introspect)

JWT carries only identity claims. The SDK calls `POST /introspect` and reads live RBAC from
the response. Throws `AuthorizationModeMismatchError` when the server echoes a mode that
differs from what the middleware expects.

```typescript
import { HearthClient, requirePermission } from "@hearth-auth/sdk";

const client = new HearthClient({
  issuerUrl: "https://auth.example.com",
  clientId: "<client-id>",
  clientSecret: "<client-secret>",
  // optional: validate the server echoes the expected mode
  expectedMode: "introspection",
});

const check = requirePermission("docs.write", { mode: "introspection", client });
const allowed = await check(accessToken);
```

> **Design constraint**: the SDK MUST NOT silently fall back from one mode to another based on
> whether `permissions` is present in the JWT. The `mode` must always be set explicitly.
> Absence of a `permissions` claim in `embedded` mode means the user has no permissions, not
> that the SDK should try a network call.

---

## Server middleware (Express and Fastify)

`hearthMiddleware` and `hearthFastifyHook` verify the bearer token on each request, apply optional scope, role and permission guards, and attach the verified `Claims`. Both take the same options:

| Option | Meaning |
|---|---|
| `client` | The `HearthClient` to verify with. Create one per process so the JWKS cache is shared. |
| `mode` | `"embedded"`, `"introspection"` or `"decision"`. Default: `client.expectedMode`, then `"embedded"`. |
| `required` | Default `true`. When `false`, a request with no token or a token that does not verify goes through without claims. |
| `requiredScope`, `requiredRole` | Checked against the verified JWT in every mode. |
| `requiredPermission` | Checked per `mode` (see below). |
| `organizationId`, `resource` | Sent with the decision-mode `POST /oauth/authorize` call. |

```typescript
import express from "express";
import { HearthClient, hearthMiddleware } from "@hearth-auth/sdk";

const client = new HearthClient({ issuerUrl: "https://hearth.example.com", clientId: "my-api" });
const app = express();

app.get("/docs", hearthMiddleware({ client, requiredPermission: "docs.read" }), (req, res) => {
  res.json({ sub: req.hearthClaims!.subject() });
});
```

```typescript
import Fastify from "fastify";
import { hearthFastifyHook } from "@hearth-auth/sdk";

const app = Fastify();
app.addHook("onRequest", hearthFastifyHook({ client, requiredRole: "editor" }));
// request.hearthClaims is set in route handlers
```

Responses:

| Situation | Status |
|---|---|
| No bearer token (with `required`), or the token does not verify | 401 |
| `token_type` is `required_action` (even when `required` is `false`) | 401 |
| Introspection mode: the token is no longer active | 401 |
| Missing scope, role or permission; decision mode denied; introspection failed or echoed another mode | 403 |

Every 401 carries `WWW-Authenticate: Bearer realm="hearth"`. Bodies are JSON: `{ "error": "unauthorized" | "forbidden", "error_description": "..." }`.

How `requiredPermission` is checked:

- **embedded** — from the `permissions` claim of the verified JWT. No network call. A token without the claim has no permissions; the middleware never falls back to another mode.
- **introspection** — from the live `permissions` returned by `POST /introspect`. Needs `clientId` and `clientSecret` on the client.
- **decision** — `POST /oauth/authorize` decides; the JWT claim is ignored. Needs `realmId` on the client.

A client that cannot serve the mode makes the factory throw `ConfigurationError` at startup, not on the first request.

For another framework, call `authenticateRequest(authorizationHeader, options)`. It returns `{ ok: true, claims }` or `{ ok: false, status, headers, body }` for you to send.

---

## Next.js

### Pages Router API routes

```typescript
// pages/api/profile.ts
import { withHearthAuth } from "@hearth-auth/sdk/nextjs";
import { hearth } from "../../lib/hearth"; // a module-scope HearthClient

export default withHearthAuth(
  (req, res) => {
    res.json({ sub: req.hearthClaims!.subject() });
  },
  { client: hearth, requiredPermission: "profile.read" },
);
```

`withHearthAuth` takes the same options as `hearthMiddleware`. On a 401 or 403 the handler is not called.

### App Router Route Handlers

```typescript
// app/api/profile/route.ts
import { NextResponse } from "next/server";
import { getHearthClaims } from "@hearth-auth/sdk/nextjs";
import { hearth } from "@/lib/hearth";

export async function GET(request: Request) {
  const claims = await getHearthClaims(request, hearth);
  if (!claims) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  return NextResponse.json({ sub: claims.subject() });
}
```

`getHearthClaims` returns `null` when there is no bearer token, the token does not verify, or it is a `required_action` token.

### `middleware.ts` (Edge Runtime)

```typescript
// middleware.ts
import { NextResponse, type NextRequest } from "next/server";
import { HearthClient } from "@hearth-auth/sdk";
import { hearthEdgeMiddleware } from "@hearth-auth/sdk/nextjs/edge";

const guard = hearthEdgeMiddleware({
  client: new HearthClient({ issuerUrl: process.env.HEARTH_ISSUER_URL! }),
  requiredScope: "api",
});

export async function middleware(request: NextRequest) {
  return (await guard(request)) ?? NextResponse.next();
}

export const config = { matcher: ["/api/:path*"] };
```

The guard resolves to `undefined` when the request may proceed, or to a 401/403 JSON `Response`. It uses only `fetch` and Web Crypto, so it runs on the Edge Runtime. Create it at module scope so the discovery document and JWKS stay cached for the life of the isolate.

---

## Agent Authentication (M5)

Hearth supports AI agent identity and authorization via a set of REST endpoints and OAuth extensions. Enable with `agent_auth.capabilities.identity = true` (plus `advanced = true` for AATs and transaction tokens) in your `hearth.yaml`.

### Agent CRUD + API keys

```typescript
const client = new HearthClient({ baseUrl, realmId });

// Create an agent
const agent = await client.post("/v1/agents", {
  realm_id: realmId,
  display_name: "my-agent",
  capabilities: ["urn:hearth:capability:docs:read"],
});

// Issue an API key (long-lived bearer token for the agent)
const { api_key } = await client.post(`/v1/agents/${agent.agent_id}/credentials/keys`, {
  description: "production key",
});
```

### DPoP-bound tokens (RFC 9449)

Bind an access token to an EC key pair so it cannot be replayed by a token thief:

```typescript
import { generateKeyPairSync, sign, createHash, randomUUID } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const pub = publicKey.export({ format: "jwk" });

// JWK thumbprint per RFC 7638 (lex-sorted required members)
const canonical = JSON.stringify({ crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y });
const thumbprint = createHash("sha256").update(canonical).digest("base64url");

function makeDPopProof(htm: string, htu: string, nonce?: string): string {
  const header = { alg: "ES256", jwk: { crv: "EC", kty: "EC", x: pub.x, y: pub.y }, typ: "dpop+jwt" };
  const claims: Record<string, unknown> = {
    htm, htu, iat: Math.floor(Date.now() / 1000), jti: randomUUID(),
  };
  if (nonce) claims.nonce = nonce;
  const b64u = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const input = `${b64u(header)}.${b64u(claims)}`;
  const sig = sign("SHA256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${input}.${sig.toString("base64url")}`;
}

// 1st request — server always returns DPoP-Nonce
const resp1 = await fetch(tokenUrl, { method: "POST", headers: { DPoP: makeDPopProof("POST", tokenUrl) }, body });
const nonce = resp1.headers.get("dpop-nonce")!;

// 2nd request — include nonce; receive AT with cnf.jkt binding
const resp2 = await fetch(tokenUrl, { method: "POST", headers: { DPoP: makeDPopProof("POST", tokenUrl, nonce) }, body });
const { access_token } = await resp2.json();
// Decoded AT claims will contain: cnf: { jkt: "<thumbprint>" }
```

### RFC 8693 Token Exchange (OBO / act chain)

```typescript
const body = new URLSearchParams({
  grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
  subject_token: subjectToken,
  subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
  requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
  scope: "openid",
});
const resp = await fetch(`${baseUrl}/token`, { method: "POST", body, headers: { Authorization: `Basic ${creds}` } });
const { access_token } = await resp.json();
// Exchanged token contains: act: { sub: "<actor-client-id>" }  (RFC 8693 §4.1)
```

### Attenuating Authorization Tokens — AATs (Phase D)

```typescript
// Issue a root AAT for an agent
const rootAat = await client.post("/v1/aats", {
  realm_id: realmId,
  agent_id: agentId,
  tools: [
    { tool_name: "read_docs", constraints: null },
    { tool_name: "search_files", constraints: null },
  ],
  expires_in_secs: 3600,
});

// Derive a child AAT with narrowed scope (child tools ⊆ parent tools)
const childAat = await client.post("/v1/aats/derive", {
  realm_id: realmId,
  parent_token: rootAat.token,
  tools: [{ tool_name: "read_docs", constraints: null }],
  expires_in_secs: 300,
});
```

### Transaction tokens (single-use A2A, 60s TTL)

```typescript
// Issue a single-use transaction token binding agent-a → agent-b
const txn = await client.post("/v1/transaction-tokens", {
  realm_id: realmId,
  requesting_agent_id: agentAId,
  target_agent_id: agentBId,
  txn_id: `txn-${crypto.randomUUID()}`,
});

// Consume (single-use — second call returns 409)
await client.post("/v1/transaction-tokens/consume", {
  realm_id: realmId,
  token: txn.token,
});
```

### Draft-standard tracking

The following IETF drafts underpin the agent-auth surface. The designated owner for re-checking draft advancement is **[@therecluse26](https://github.com/therecluse26)** (CTO). When a draft advances to RFC or a new revision ships, open a follow-up issue on [HEA-1409](/HEA/issues/HEA-1409).

| Draft | Hearth feature | Check when |
|-------|----------------|-----------|
| `draft-oauth-ai-agents-on-behalf-of-user-02` | OBO `on_behalf_of` claim | New revision or RFC publication |
| `draft-niyikiza-oauth-attenuating-agent-tokens` | AAT engine (`/v1/aats`) | New revision or RFC publication |
| `draft-oauth-transaction-tokens-for-agents` | Transaction tokens (`/v1/transaction-tokens`) | New revision or RFC publication |
| `draft-prakash-aip` | Agent identity model, Agent Card | New revision or RFC publication |
| OpenID SSF/CAEP | DPoP JKT blocklist + risk signals | When CAEP SSF spec stabilizes |
