# Hearth TypeScript SDK

TypeScript client for the [Hearth](https://github.com/hearth-auth/hearth) identity API.

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/specs/SDK.md).

## Installation

```bash
npm install @hearth/sdk
# or
yarn add @hearth/sdk
# or
pnpm add @hearth/sdk
```

**Peer dependencies:** React (`>=17 <20`) is optional. Only required for the `HearthProvider` / `useHasPermission` hooks.

---

## Quick start

```typescript
import { createHearth, HearthClient } from "@hearth/sdk";

// Low-level HTTP client — auth flows, token exchange, admin ops
const client = new HearthClient({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
});

// RBAC facade — local, synchronous permission checks from the JWT
const hearth = createHearth({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
  getToken: () => localStorage.getItem("access_token"),
});
```

`HearthClient` is for server-side or client-side HTTP operations (token exchange, admin CRUD, JWKS). `createHearth` gives you a zero-network RBAC facade that reads claims from the JWT in memory.

---

## Auth code flow (with PKCE)

PKCE is the secure default for every OAuth authorization code flow — required for public clients, recommended for confidential clients.

```typescript
import { HearthClient } from "@hearth/sdk";
import { createHash, randomBytes } from "crypto"; // Node.js built-in

const client = new HearthClient({
  baseUrl: "https://hearth.example.com",
  realmId: "<your-realm-id>",
});

// 1. Generate PKCE verifier and challenge
const codeVerifier = randomBytes(32).toString("hex"); // 64 unreserved chars
const codeChallenge = createHash("sha256")
  .update(codeVerifier)
  .digest("base64url"); // base64url, no padding

// 2. Start the authorization request
const { code } = await client.authorize({
  clientId: "<client-id>",
  redirectUri: "https://app.example.com/callback",
  scope: "openid profile email",
  state: randomBytes(16).toString("hex"), // CSRF token
  userId: "<authenticated-user-uuid>",    // resolved user on your backend
  codeChallenge,
  codeChallengeMethod: "S256",
});

// 3. Exchange the code for tokens
const tokens = await client.exchangeCode({
  clientId: "<client-id>",
  code,
  redirectUri: "https://app.example.com/callback",
  codeVerifier,
});

// tokens.access_token  — short-lived JWT (check tokens.expires_in)
// tokens.id_token      — OIDC identity token
// tokens.refresh_token — rotate with refreshTokens()

// 4. Refresh before expiry
const refreshed = await client.refreshTokens("<client-id>", tokens.refresh_token);
```

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

The React hooks are exported from the main `@hearth/sdk` package. No subpath import needed.

```tsx
import {
  createHearth,
  HearthProvider,
  useHasPermission,
  useHasRole,
  useInGroup,
  useInOrg,
} from "@hearth/sdk";

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

## UserInfo endpoint

Returns OIDC claims filtered by the granted scopes. `sub` is always present; `name` requires `profile` scope; `email` and `email_verified` require `email` scope.

```typescript
const info = await client.userinfo(accessToken);
// info.sub            — stable user identifier
// info.name           — display name (if profile scope granted)
// info.email          — email address (if email scope granted)
// info.email_verified — boolean (if email scope granted)
```

---

## JWKS and discovery

```typescript
// Retrieve the realm's public signing keys (for local JWT verification)
const jwks = await client.jwks();
// jwks.keys — array of JWK entries (kty, crv, x, kid, use, alg)

// Retrieve the OIDC discovery document
const discovery = await client.discovery();
// Standard OIDC Core 1.0 metadata
```

Use the JWKS with a library like `jose` to verify access tokens on your backend:

```typescript
import { createRemoteJWKSet, jwtVerify } from "jose";

const JWKS = createRemoteJWKSet(
  new URL("https://hearth.example.com/jwks"),
);

const { payload } = await jwtVerify(accessToken, JWKS, {
  issuer: "https://hearth.example.com",
  audience: "<client-id>",
});
```

---

## Admin API

`AdminClient` wraps the `/admin/*` endpoints. Obtain one from any `HearthClient` instance using a bearer token that carries the `hearth.admin` permission.

```typescript
const admin = client.admin(accessToken);
```

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
  status: "active",
});

// Delete a user
await admin.deleteUser("<user-id>");
```

### Realms

```typescript
// Create a realm
const realm = await admin.createRealm({ name: "acme-corp" });

// List realms (paginated)
const page = await admin.listRealms({ limit: 20 });
// page.items: Realm[], page.next_cursor: string | null

// Get a realm by ID
const realm = await admin.getRealm("<realm-id>");

// Update a realm
const updated = await admin.updateRealm("<realm-id>", {
  status: "suspended",
});

// Delete a realm (cascades users, sessions, clients, assignments)
await admin.deleteRealm("<realm-id>");
```

---

## Error handling

All methods throw `HearthError` on non-2xx responses.

```typescript
import { HearthClient, HearthError } from "@hearth/sdk";

try {
  const tokens = await client.exchangeCode({ ... });
} catch (err) {
  if (err instanceof HearthError) {
    console.error(`HTTP ${err.status}:`, err.body);
  } else {
    throw err;
  }
}
```

`HearthError.status` is the HTTP status code. `HearthError.body` is the parsed JSON response body (or the raw string if parsing fails).

---

## Dev bootstrap (development only)

The bootstrap endpoint creates a realm, admin user, session, assigns the `realm.admin` role, and returns tokens. It is available only when Hearth is running with `--dev`. In production, it returns 404.

```typescript
import { HearthClient } from "@hearth/sdk";

const { realm_id, user_id, access_token, refresh_token } =
  await HearthClient.bootstrap("http://127.0.0.1:8420");

// Use realm_id and access_token to make subsequent requests
const client = new HearthClient({
  baseUrl: "http://127.0.0.1:8420",
  realmId: realm_id,
});
const admin = client.admin(access_token);
```

---

## Type reference

```typescript
// HearthClientConfig — constructor argument for HearthClient
interface HearthClientConfig {
  baseUrl: string;   // Hearth server base URL, e.g. "https://hearth.example.com"
  realmId: string;   // Realm UUID to scope all requests to
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
  id_token: string;
  token_type: string;   // "Bearer"
  expires_in: number;   // seconds
  refresh_token: string;
}

// UserInfoResponse
interface UserInfoResponse {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
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

RBAC claims (`permissions`, `roles`, `groups`) are embedded in the JWT at issuance. Zero
network traffic on every request — stateless and fastest.

```typescript
import { requirePermission } from "@hearth/sdk";

const check = requirePermission("docs.write", {
  mode: "embedded",
  client: new HearthClient({ issuerUrl: "https://auth.example.com" }),
});

// returns true/false synchronously from the JWT; no network call
const allowed = await check(accessToken);
```

### Decision (per-request server check)

JWT carries only identity claims. The SDK calls `POST /oauth/authorize` on every check.
Fail-closed: any network or server error returns `false`.

```typescript
import { HearthClient, requirePermission } from "@hearth/sdk";

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
import { HearthClient, requirePermission } from "@hearth/sdk";

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
