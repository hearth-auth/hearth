---
title: TypeScript SDK quickstart
sidebar_label: TypeScript
description: Add Hearth authentication and RBAC to a TypeScript app in under 5 minutes. Covers browser PKCE, React hooks, token verification, server-side OAuth flows, and Express and Fastify middleware.
---

# TypeScript SDK quickstart

Get your first protected route in under 5 minutes using `@hearth-auth/sdk`.

## Install

```bash
npm install @hearth-auth/sdk
# or: yarn add @hearth-auth/sdk  |  pnpm add @hearth-auth/sdk
```

**Peer dependencies:** both optional. React 17–19 is needed only for the
`HearthProvider` and hooks. Next.js 14 or later is needed only for
`@hearth-auth/sdk/nextjs` and `@hearth-auth/sdk/nextjs/edge`. The `HearthClient`
and `createHearth` factory work in any TypeScript environment.

One package covers the browser and the server:

| Import path | What it gives you |
|---|---|
| `@hearth-auth/sdk` | `HearthClient`, token verification, OAuth flows, Express and Fastify middleware, admin client, React hooks, browser auth |
| `@hearth-auth/sdk/nextjs` | `withHearthAuth` (Pages Router) and `getHearthClaims` (App Router Route Handlers) |
| `@hearth-auth/sdk/nextjs/edge` | `hearthEdgeMiddleware` for `middleware.ts` on the Edge Runtime |

For Next.js, see the [Next.js guide](./typescript-nextjs.md).

## Start Hearth locally

```bash
# from the hearth repo root
make dev
# → binds http://127.0.0.1:8420

curl -X POST http://127.0.0.1:8420/admin/bootstrap
# → { "realm_id": "…", "access_token": "…" }
```

`--dev` starts Hearth with in-memory storage and a built-in mailcatcher at
`http://127.0.0.1:8420/dev/mail`.

## Register an OAuth client

```bash
export REALM_ID=<realm_id>
export TOKEN=<access_token>

curl -X POST "http://127.0.0.1:8420/admin/realms/$REALM_ID/clients" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "my-app",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
# → { "client_id": "…" }
```

## Initialize the client

`HearthClient` takes the server base URL plus an optional `realmId` (UUID) and OAuth client credentials:

```typescript
import { HearthClient } from "@hearth-auth/sdk";

const client = new HearthClient({
  issuerUrl: "http://127.0.0.1:8420",  // server base URL — NOT a realm-scoped URL
  realmId: "<realm_id>",               // optional — required for magic-link and decision mode
  clientId: "<client_id>",             // optional — required for flows needing a client identity
  clientSecret: "<client_secret>",     // optional — required for confidential client flows
});
```

All endpoint URLs are auto-discovered from `{issuerUrl}/.well-known/openid-configuration` on first use. The `realmId` is sent as `X-Realm-ID` on endpoints that need it; for OAuth flows like `clientCredentials()` and `startDeviceFlow()`, the realm is resolved from `client_id` on the server side — no `realmId` needed.

## Authenticate with PKCE

PKCE is mandatory for all public clients (browser apps, mobile apps) and
recommended for confidential clients.

### Step 1 — Start the login redirect

```typescript
import { HearthApiClient, startLogin } from "@hearth-auth/sdk";

const client = new HearthApiClient({
  baseUrl: "http://127.0.0.1:8420",
  realmId: "<realm_id>",
});

// startLogin discovers the authorization endpoint, generates the PKCE verifier
// and S256 challenge, and builds the redirect URL — no manual crypto needed.
const { url, state, codeVerifier } = await startLogin(client, {
  clientId: "<client_id>",
  redirectUri: "http://localhost:3000/callback",
  scope: "openid profile email",
});

// Persist for the callback
sessionStorage.setItem("pkce_verifier", codeVerifier);
sessionStorage.setItem("oauth_state", state);

window.location.href = url;
```

### Step 2 — Exchange the code

After the user authenticates, Hearth redirects to your `redirect_uri` with
`?code=…&state=…`. Verify state and exchange the code:

```typescript
import { HearthApiClient } from "@hearth-auth/sdk";

const client = new HearthApiClient({
  baseUrl: "http://127.0.0.1:8420",
  realmId: "<realm_id>",
});

// Verify state before exchanging the code
if (new URLSearchParams(window.location.search).get("state") !== sessionStorage.getItem("oauth_state")) {
  throw new Error("state mismatch");
}

const tokens = await client.handleCallback({
  callbackUrl: window.location.href,
  clientId: "<client_id>",
  redirectUri: "http://localhost:3000/callback",
  codeVerifier: sessionStorage.getItem("pkce_verifier")!,
});

// tokens.access_token   — short-lived JWT
// tokens.id_token       — OIDC identity claims
// tokens.refresh_token  — rotate with refreshTokens()
// tokens.expires_in     — seconds until access token expires
```

### Step 3 — Refresh before expiry

```typescript
const refreshed = await client.refreshTokens("<client_id>", tokens.refresh_token);
```

## RBAC checks

### React hooks

Mount `HearthProvider` once at the root of your React tree and use hooks
anywhere in the component tree. Permission checks are **synchronous and
zero-network** — they decode the JWT in memory.

```tsx
import {
  createHearth,
  createHearthAuth,
  HearthApiClient,
  HearthProvider,
  useHasPermission,
  useHasRole,
  useInGroup,
} from "@hearth-auth/sdk";

// Initialize once at app startup — handles PKCE, in-memory token storage, and silent refresh.
// Never store access tokens in localStorage or sessionStorage — see /docs/guides/browser-spa-tokens
const apiClient = new HearthApiClient({ baseUrl: "http://127.0.0.1:8420", realmId: "<realm_id>" });
const auth = createHearthAuth(apiClient, {
  clientId:    "<client_id>",
  redirectUri: "http://localhost:3000/callback",
});

const hearth = createHearth({
  baseUrl: "http://127.0.0.1:8420",
  realmId: "<realm_id>",
  getToken: () => auth.getAccessToken(), // in-memory — never localStorage or sessionStorage
});

function App() {
  return (
    <HearthProvider client={hearth}>
      <NavBar />
    </HearthProvider>
  );
}

function NavBar() {
  const canPublish = useHasPermission("docs.publish");
  const isAdmin    = useHasRole("admin");
  const inEng      = useInGroup("engineering");

  return (
    <nav>
      {canPublish && <a href="/publish">Publish</a>}
      {isAdmin    && <a href="/admin">Admin</a>}
      {inEng      && <a href="/internal">Internal tools</a>}
    </nav>
  );
}
```

### Non-React (synchronous facade)

```typescript
import { createHearth, createHearthAuth, HearthApiClient } from "@hearth-auth/sdk";

const apiClient = new HearthApiClient({ baseUrl: "http://127.0.0.1:8420", realmId: "<realm_id>" });
const auth = createHearthAuth(apiClient, {
  clientId:    "<client_id>",
  redirectUri: "http://localhost:3000/callback",
});

const hearth = createHearth({
  baseUrl: "http://127.0.0.1:8420",
  realmId: "<realm_id>",
  getToken: () => auth.getAccessToken(), // in-memory — never localStorage or sessionStorage
});

if (hearth.hasPermission("invoices.write")) {
  renderInvoiceForm();
}
```

### Live permission check (post-issuance)

The synchronous helpers reflect only claims baked in at token issuance. For
post-issuance accuracy — e.g., after an admin grants a new role — call:

```typescript
const { roles, groups, permissions } = await hearth.client.permissions();
```

This hits `GET /v1/me/permissions` and returns the freshly-resolved RBAC set.

## Verify tokens

Use `HearthClient.verifyToken()` to perform full Ed25519/EdDSA local signature
verification without a network call beyond the initial JWKS fetch:

```typescript
import { HearthClient, TokenExpiredError, TokenInvalidError } from "@hearth-auth/sdk";

const client = new HearthClient({
  issuerUrl: "http://127.0.0.1:8420",
  clientId: "<client_id>",
});

try {
  const claims = await client.verifyToken(accessToken);
  // claims.subject()        — JWT `sub`, stable user UUID
  // claims.hasRole("admin") — reads `roles` claim (local, no network)
  // claims.hasPermission("docs.write") — reads `permissions` claim
  // claims.inGroup("engineering")      — reads `groups` claim
} catch (err) {
  if (err instanceof TokenExpiredError) {
    // 401 — ask client to refresh
  } else if (err instanceof TokenInvalidError) {
    // 401 — reject the request
  }
}
```

`verifyToken()` caches JWKS keys by `kid`, re-fetches once on a key miss
(transparent key rotation), and validates signature, `exp`, `iss`, `aud`, and
`iat` in that order. It never falls back to introspection.

:::note[`iss` validation and `issuerUrl`]
`verifyToken()` checks that the token's `iss` claim exactly matches `issuerUrl`. System tokens (admin bootstrap) carry `iss = <baseUrl>`. User/client tokens issued by a realm carry `iss = <baseUrl>/realms/<realm-slug>`. Configure `issuerUrl` to match the issuer your tokens actually contain, or set `expectedMode: "introspection"` to skip local `iss` validation.
:::

## Machine-to-machine (client credentials)

For service-to-service calls where your server acts as its own principal:

```typescript
const client = new HearthClient({
  issuerUrl: "http://127.0.0.1:8420",
  clientId: "<service-client-id>",
  clientSecret: "<service-client-secret>",
});

const tokens = await client.clientCredentials("read:users");
// tokens.access_token — short-lived M2M JWT
// tokens.expires_in   — seconds until expiry
```

Credentials are sent as `application/x-www-form-urlencoded` body fields. The
token endpoint is discovered from the OIDC discovery document.

## Device authorization flow

For CLI tools or headless servers that need interactive user approval:

```typescript
const resp = await client.startDeviceFlow("openid");
// resp.user_code          — display this to the user (e.g. "WDJB-MJHT")
// resp.verification_uri   — URL the user visits to approve
console.log(`Visit ${resp.verification_uri} and enter code: ${resp.user_code}`);

// Poll until the user approves (or the device code expires)
let tokens;
while (true) {
  try {
    tokens = await client.pollDeviceToken(resp.device_code, resp.interval);
    break; // approved
  } catch (err) {
    if (err instanceof TokenExpiredError) {
      throw new Error("device code expired before the user approved");
    }
    throw err;
  }
  await new Promise((r) => setTimeout(r, resp.interval * 1000));
}
```

`pollDeviceToken` handles `authorization_pending` and `slow_down` transparently
and throws `TokenExpiredError` when the device code expires.

## Magic-link (passwordless) initiation

Send a single-use login link to a user's email address:

```typescript
await client.requestMagicLink("user@example.com");
// Always resolves — Hearth returns 202 whether or not the email is registered
// (enumeration resistance). The user clicks the link to complete authentication.
```

HTTP 429 is surfaced as `OAuthFlowError`.

## Server-side (Node.js)

On a Node.js server, `HearthClient` handles the OAuth callback, verifies incoming bearer
tokens, and protects Express and Fastify routes. Create one `HearthClient` per process so the
discovery document and JWKS cache are shared. Requires Node.js 18 or later.

### Login with PKCE on the server

`beginLogin` builds the authorization URL with a fresh PKCE verifier and `state`. Keep both in
your server-side session. On the callback, check `state`, then call `completeLogin`.

```typescript
import express from "express";
import { HearthClient } from "@hearth-auth/sdk";

const app = express();
const client = new HearthClient({
  issuerUrl: "https://hearth.example.com",
  clientId: process.env.HEARTH_CLIENT_ID,
  clientSecret: process.env.HEARTH_CLIENT_SECRET, // confidential clients only
});

app.get("/login", async (req, res) => {
  const { authorizationUrl, state, codeVerifier } = await client.beginLogin(
    "https://myapp.example.com/callback",
    "openid profile email", // default: "openid"
  );
  req.session.oauth = { state, codeVerifier };
  res.redirect(authorizationUrl);
});

app.get("/callback", async (req, res) => {
  if (req.query.state !== req.session.oauth.state) {
    return res.status(400).send("state mismatch");
  }
  const tokens = await client.completeLogin(
    req.query.code as string,
    req.session.oauth.codeVerifier,
    "https://myapp.example.com/callback",
  );
  // tokens.access_token, tokens.expires_in, tokens.refresh_token?, tokens.id_token?
  res.json({ access_token: tokens.access_token });
});
```

`completeLogin(code, verifier, redirectUri)` is the same as
`exchangeCode(code, redirectUri, { codeVerifier })`. Call `exchangeCode` directly when you
built the authorization URL yourself. Both send `client_id` in the form body, plus
`client_secret` when one is configured. A public client leaves `clientSecret` unset and
relies on PKCE.

Refresh tokens with `refreshTokens`. Hearth rotates refresh tokens, so store the new one:

```typescript
const refreshed = await client.refreshTokens(tokens.refresh_token!);
// Pass a second argument to request a narrower scope.
```

:::tip[Where should the access token live?]
If your frontend is a browser SPA, consider the **Backend for Frontend (BFF)** pattern: your
server completes the OAuth callback, keeps the access and refresh tokens server-side, and gives
the browser an `HttpOnly; Secure; SameSite=Strict` session cookie. The browser never sees a
token. See [Browser SPA Token Handling](../browser-spa-tokens.md) for the trade-offs.
:::

### Express and Fastify middleware

`hearthMiddleware` (Express) and `hearthFastifyHook` (Fastify) verify the bearer token on each
request, apply optional scope, role and permission guards, and attach the verified `Claims`
as `hearthClaims`.

```typescript
import express from "express";
import { HearthClient, hearthMiddleware } from "@hearth-auth/sdk";

const client = new HearthClient({
  issuerUrl: "https://hearth.example.com",
  clientId: "my-api", // pins the `aud` claim
});
const app = express();

// Verify every request in embedded mode (JWKS only, no extra network call)
app.use(hearthMiddleware({ client, mode: "embedded" }));

app.get("/me", (req, res) => {
  res.json({ sub: req.hearthClaims!.subject() });
});

// Require a permission on one route
app.post("/docs", hearthMiddleware({ client, requiredPermission: "docs.write" }), docsHandler);
```

```typescript
import Fastify from "fastify";
import { HearthClient, hearthFastifyHook } from "@hearth-auth/sdk";

const client = new HearthClient({ issuerUrl: "https://hearth.example.com", clientId: "my-api" });
const app = Fastify();

app.addHook("onRequest", hearthFastifyHook({ client, requiredRole: "editor" }));

app.get("/docs", async (request) => {
  return { sub: request.hearthClaims!.subject() };
});
```

Both take the same options:

| Option | Meaning |
|---|---|
| `client` | The `HearthClient` to verify with. |
| `mode` | `"embedded"`, `"introspection"` or `"decision"`. Default: `client.expectedMode`, then `"embedded"`. |
| `required` | Default `true`. When `false`, a request with no token or a token that does not verify goes through without claims. |
| `requiredScope`, `requiredRole` | Checked against the verified JWT in every mode. |
| `requiredPermission` | Checked per `mode` (see below). |
| `organizationId`, `resource` | Sent with the decision-mode `POST /oauth/authorize` call. |

Responses:

| Situation | Status |
|---|---|
| No bearer token (with `required`), or the token does not verify | 401 |
| `token_type` is `required_action` (even when `required` is `false`) | 401 |
| Introspection mode: the token is no longer active | 401 |
| Missing scope, role or permission; decision mode denied; introspection failed or echoed another mode | 403 |

Every 401 carries `WWW-Authenticate: Bearer realm="hearth"`. Bodies are JSON:
`{ "error": "unauthorized" | "forbidden", "error_description": "..." }`. The route handler is
not called on a 401 or 403.

For another framework, call `authenticateRequest(authorizationHeader, options)`. It returns
`{ ok: true, claims }` or `{ ok: false, status, headers, body }` for you to send.

### Permission delivery modes

Hearth delivers permissions in one of three modes, set by `access_token_authorization` on the
registered OAuth client. The SDK never picks the mode from whether the JWT has a
`permissions` claim: set `mode` explicitly.

| Mode | How `requiredPermission` is checked | When to use |
|------|-------------|-------------|
| `embedded` (default) | From the `permissions` claim of the verified JWT. No network call. | Most services |
| `introspection` | From the live `permissions` returned by `POST /introspect`. Needs `clientId` and `clientSecret`. | You want live permissions without a per-permission decision call |
| `decision` | `POST /oauth/authorize` decides; the JWT claim is ignored. Needs `realmId`. Any failure is a denial. | Role changes must take effect at once |

A client that cannot serve the chosen mode makes the middleware factory throw
`ConfigurationError` at startup, not on the first request.

To introspect a token yourself:

```typescript
const client = new HearthClient({
  issuerUrl: "https://hearth.example.com",
  clientId: "<resource-server-client-id>",
  clientSecret: "<secret>",
  expectedMode: "introspection", // throws AuthorizationModeMismatchError on another echoed mode
});

const result = await client.introspect(rawToken);
if (!result.active) {
  // reject
}
// result.permissions, result.roles, result.groups
```

### UserInfo, live permissions and the session-version feed

```typescript
// OIDC claims released by the granted scopes (sub is always present)
const info = await client.userinfo(accessToken);

// Roles, groups and permissions as they are now on the server (needs realmId)
const { roles, groups, permissions } = await client.mePermissions(accessToken);

// Session-version feed (needs realmId and a service token with the hearth.sv_feed scope)
const snap = await client.svSnapshot(serviceToken);
const delta = await client.svDelta(serviceToken, snap.current_seq, 500); // null when nothing changed
```

`SessionVersionCache` runs the snapshot and delta loop for you and checks a token's `sv` claim
without a network call. Call `client.invalidateCache()` to drop the cached discovery document,
JWKS and introspection client.

### Admin API

`AdminClient` wraps the `/admin/*` endpoints. Use a bearer token that carries the
`hearth.admin` permission.

```typescript
import { AdminClient } from "@hearth-auth/sdk";

const admin = new AdminClient("https://hearth.example.com", "<realm-id>", adminToken);

const user = await admin.createUser({ email: "alice@example.com", displayName: "Alice" });
const page = await admin.listUsers({ limit: 50 });
// page.items: User[], page.next_cursor: string | null
await admin.deleteUser(user.id);
```

A non-2xx response throws `HearthError` with `status` and `body`.

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

`AdminClient` and `HearthApiClient` throw `HearthError` on a non-2xx response, with `status`
and `body`. Any JWT-shaped string in an error message is replaced with `[redacted]`.

```typescript
import {
  HearthClient,
  OAuthFlowError,
  TokenExpiredError,
  TokenVerificationError,
} from "@hearth-auth/sdk";

try {
  const claims = await client.verifyToken(accessToken);
  if (claims.tokenType() === "required_action") {
    // Defensive: Hearth issues no required-action token, but refuse one if presented.
    // claims.requiredActions() lists the pending actions.
  }
} catch (err) {
  if (err instanceof TokenExpiredError) {
    // 401 — ask the client to refresh
  } else if (err instanceof TokenVerificationError) {
    // 401 — any other token failure (signature, issuer, audience, ...)
  } else {
    throw err; // JWKSFetchError, DiscoveryError: not the caller's fault
  }
}

try {
  await client.clientCredentials();
} catch (err) {
  if (err instanceof OAuthFlowError) {
    console.error(`OAuth error HTTP ${err.statusCode}: ${err.errorCode}`);
  }
}
```

The middleware in [Server-side (Node.js)](#server-side-nodejs) answers 401 to a
`required_action` token for you.

## Runnable example

A complete Next.js 14 (App Router) example lives at
[`examples/typescript-nextjs/`](https://github.com/hearth-auth/hearth/tree/main/examples/typescript-nextjs).
It covers the full PKCE flow, Edge middleware route protection, and React RBAC
hooks — all runnable with `npm run dev`.

## Next steps

- [Next.js guide](./typescript-nextjs.md) — Edge Runtime middleware, App Router and Pages Router
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Admin API guide](/docs/admin-api) — managing users and clients programmatically
- [TypeScript type reference](https://github.com/hearth-auth/hearth/blob/main/sdks/typescript/README.md) — full interface list
