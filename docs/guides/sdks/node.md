---
title: Node.js SDK quickstart
sidebar_label: Node.js
description: Verify Hearth tokens and enforce RBAC in a Node.js server in under 5 minutes. Covers Express and Fastify middleware, JWKS caching, and the Admin API.
---

# Node.js SDK quickstart

Add token verification and permission checks to a Node.js server in under 5 minutes using `@hearth-auth/node`.

:::note[Node.js vs TypeScript SDK]
This is the **server-side** SDK. Use it to handle the OAuth callback route, verify incoming Bearer tokens, protect Express/Fastify routes, and call the Admin API.

For **browser or React** — `HearthProvider`, `useHasPermission` hooks, and browser-hosted PKCE — use the [TypeScript SDK](./typescript.md) instead.
:::

## Install

```bash
npm install @hearth-auth/node
# or: yarn add @hearth-auth/node  |  pnpm add @hearth-auth/node
```

| SDK | Node.js | Hearth server |
|-----|---------|---------------|
| 1.0.x | ≥ 18.0 | ≥ 1.0.0 |

Ships `jose` as a direct dependency — no peer deps required.

## Auth code flow with PKCE

For Node.js servers that handle the OAuth callback (Express, Fastify, Next.js API routes), use `beginLogin` / `completeLogin`:

```typescript
import { HearthClient } from "@hearth-auth/node";

const client = new HearthClient({
  issuer_url:    "https://hearth.example.com",
  client_id:     process.env.HEARTH_CLIENT_ID,
  client_secret: process.env.HEARTH_CLIENT_SECRET,
});

// Login route — generate PKCE and build the authorization URL
app.get("/login", async (req, res) => {
  const { authorizationUrl, state, codeVerifier } = await client.beginLogin(
    "https://myapp.example.com/callback",
    "openid profile email",
  );
  // Persist state + codeVerifier in your session (one line you own)
  req.session.oauthState   = state;
  req.session.codeVerifier = codeVerifier;
  res.redirect(authorizationUrl);
});

// Callback route — exchange the code for tokens
app.get("/callback", async (req, res) => {
  if (req.query.state !== req.session.oauthState) {
    return res.status(400).send("state mismatch");
  }
  const tokens = await client.completeLogin(
    req.query.code as string,
    req.session.codeVerifier,
    "https://myapp.example.com/callback",
  );
  // tokens.access_token, tokens.refresh_token, tokens.expires_in
});
```

:::tip[PKCE in the browser?]
If your PKCE flow runs in the browser (React SPA, Next.js client components), use the [TypeScript SDK](./typescript.md) `startLogin()` instead. Your Node.js server then only needs `verifyToken()` on incoming Bearer tokens.
:::

:::tip[Where should the access token live?]
If your frontend is a browser SPA, consider the **Backend for Frontend (BFF)** pattern: your Node.js server completes the OAuth callback, stores the access and refresh tokens server-side, and issues the browser an `HttpOnly; Secure; SameSite=Strict` session cookie. The browser never sees a token at all.

This is the most XSS-resistant architecture for SPAs. See [Browser SPA Token Handling](../browser-spa-tokens.md) for a full comparison of storage options and the BFF flow diagram.
:::

## Verify tokens

```typescript
import { HearthClient, TokenExpiredError, TokenInvalidError } from "@hearth-auth/node";

const client = new HearthClient({
  issuer_url: "https://hearth.example.com",
  client_id: process.env.HEARTH_CLIENT_ID,        // validates JWT `aud` claim
  client_secret: process.env.HEARTH_CLIENT_SECRET, // required for introspection/decision mode
});

// On each incoming request:
try {
  const token = await client.verifyToken(rawBearerToken);

  token.subject();               // JWT `sub` — stable user UUID
  token.hasPermission("docs.write");  // reads `permissions` claim (local, no network)
  token.hasRole("admin");        // reads `roles` claim
  token.inGroup("engineering");  // reads `groups` claim
  token.inOrg("org_acme");       // reads `oid` claim
} catch (err) {
  if (err instanceof TokenExpiredError) {
    // 401 — ask client to refresh
  } else if (err instanceof TokenInvalidError) {
    // 401 — reject the request
  }
}
```

`HearthClient` auto-discovers all endpoint URLs from `{issuer_url}/.well-known/openid-configuration` on first use. JWKS keys are cached by `kid`; on a cache miss the SDK re-fetches once before failing (handles transparent key rotation).

:::tip[Audience validation]
Always supply `client_id`. Without it the SDK cannot compare the JWT `aud` claim, which opens the server to token-confusion attacks (RFC 7519 §4.1.3). Omit only for pure gateways that intentionally accept tokens for any client.
:::

## Express middleware

```typescript
import express from "express";
import { hearthMiddleware } from "@hearth-auth/node";

const app = express();

// Protect all routes — embedded mode (JWKS only, no extra network call)
app.use(
  hearthMiddleware({
    issuer_url: "https://hearth.example.com",
    expectedMode: "embedded",
  })
);

// Access the verified token downstream
app.get("/me", (req, res) => {
  res.json({ sub: req.hearthToken?.subject() });
});

// Require a specific permission on a single route
app.post(
  "/docs",
  hearthMiddleware({
    issuer_url: "https://hearth.example.com",
    expectedMode: "embedded",
    requiredPermission: "docs.write",
  }),
  docsHandler
);
```

The middleware responds `401 Unauthorized` (`WWW-Authenticate: Bearer realm="hearth"`) on missing or invalid tokens, and `403 Forbidden` on permission failures. It never calls `next` on auth failure.

## Fastify hook

```typescript
import Fastify from "fastify";
import { hearthFastifyHook } from "@hearth-auth/node";

const app = Fastify();

app.addHook(
  "preHandler",
  hearthFastifyHook({
    issuer_url: "https://hearth.example.com",
    expectedMode: "embedded",
    requiredPermission: "docs.write",
  })
);

app.get("/docs", async (request, reply) => {
  return { sub: request.hearthToken?.subject() };
});
```

## Permission delivery modes

Hearth supports three modes controlled by the `access_token_authorization` field on the registered OAuth client. The Node.js SDK exposes all three explicitly — **it never auto-detects the mode from JWT claim presence**.

| Mode | How it works | When to use |
|------|-------------|-------------|
| `embedded` (default) | Permissions baked into the JWT at issuance. Zero network calls on the hot path. | Most services — fast and scalable |
| `decision` | Live per-request `POST /oauth/authorize`. Fail-closed on errors. | When you need post-issuance accuracy (e.g., role changes take effect immediately) |
| `introspection` | `POST /realms/{id}/introspect` (RFC 7662). Echoed `mode` is validated. | Stateless resource servers that delegate trust to the authorization server |

### Introspection mode

```typescript
import { HearthClient } from "@hearth-auth/node";

const client = new HearthClient({
  issuer_url: "https://hearth.example.com",
  client_id: "<resource-server-client-id>",
  client_secret: "<secret>",
});

const result = await client.introspect(rawToken);
if (!result.active) {
  // reject
}
// result.permissions, result.roles, result.groups
```

## Machine-to-machine (client credentials)

For services that authenticate as their own principal:

```typescript
import { HearthClient } from "@hearth-auth/node";

const client = new HearthClient({
  issuer_url: "https://hearth.example.com",
  client_id: process.env.HEARTH_CLIENT_ID,
  client_secret: process.env.HEARTH_CLIENT_SECRET,
});

const tokens = await client.clientCredentials("read:reports");
// tokens.access_token, tokens.expires_in
```

## Device authorization flow

For CLI tools or headless processes that need interactive user approval:

```typescript
const resp = await client.startDeviceFlow("openid");
console.log(`Visit ${resp.verification_uri}\nEnter code: ${resp.user_code}`);

let tokens;
while (true) {
  try {
    tokens = await client.pollDeviceToken(resp.device_code, resp.interval);
    break;
  } catch (err) {
    if (err instanceof TokenExpiredError) {
      throw new Error("device code expired");
    }
    throw err;
  }
  await new Promise((r) => setTimeout(r, resp.interval * 1000));
}
```

## Magic-link (passwordless) initiation

```typescript
await client.requestMagicLink("user@example.com");
// Always resolves — Hearth returns 202 whether or not the email is registered
```

HTTP 429 is surfaced as `OAuthFlowError`.

## Admin API

```typescript
import { AdminClient } from "@hearth-auth/node";

const admin = new AdminClient({
  base_url: "https://hearth.example.com",
  realm_id: "<realm-id>",
  access_token: adminToken, // must carry hearth.admin permission
});

const user = await admin.createUser({ email: "alice@example.com", display_name: "Alice" });
const page = await admin.listUsers({ limit: 50 });
// page.items: User[], page.next_cursor: string | null
await admin.deleteUser(user.id);
```

## Error types

All SDK errors extend `HearthError`:

| Error | When thrown |
|-------|-------------|
| `TokenExpiredError` | `exp` claim is in the past — ask client to refresh |
| `TokenInvalidError` | Signature invalid or malformed JWT |
| `TokenIssuerError` | `iss` mismatch |
| `TokenAudienceError` | `aud` does not contain `client_id` |
| `RequiredActionError` | Token type is `required_action` — user must complete pending actions |
| `IntrospectionError` | Introspection endpoint unreachable or returned error |
| `AuthorizationModeError` | Server echoed a mode different from `expectedMode` |
| `ConfigurationError` | Missing required config (e.g. `client_secret` for introspection) |

```typescript
import { HearthClient, RequiredActionError, TokenExpiredError } from "@hearth-auth/node";

try {
  const token = await client.verifyToken(rawToken);
} catch (err) {
  if (err instanceof RequiredActionError) {
    // Token valid but user must complete: err.requiredActions (string[])
    // Redirect to err.redirectUri if present
  } else if (err instanceof TokenExpiredError) {
    // 401 — ask client to refresh
  }
}
```

## Next steps

- [TypeScript SDK](./typescript.md) — browser PKCE flow, React hooks, and the counterpart to this server SDK
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Admin API guide](/docs/admin-api) — managing users and clients programmatically
- [Node.js type reference](https://github.com/hearth-auth/hearth/blob/main/sdks/node/README.md) — full API surface
