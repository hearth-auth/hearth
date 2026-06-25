---
title: Node.js SDK quickstart
sidebar_label: Node.js
description: Verify Hearth tokens and enforce RBAC in a Node.js server in under 5 minutes. Covers Express and Fastify middleware, JWKS caching, and the Admin API.
---

# Node.js SDK quickstart

Add token verification and permission checks to a Node.js server in under 5 minutes using `@hearth-auth/node`.

:::note[Node.js vs TypeScript SDK]
This is the **server-side** SDK. Use it to verify incoming Bearer tokens, protect Express/Fastify routes, and call the Admin API.

If you need a **browser or React** integration — PKCE authorization-code flow, `HearthProvider`, or `useHasPermission` hooks — use the [TypeScript SDK](./typescript.md) instead.
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

The Node.js SDK is a **resource-server** library — it verifies tokens issued by the browser-side PKCE flow. It does not initiate the authorization redirect.

The authorization-code + PKCE flow lives in the browser client (TypeScript SDK or any OIDC library). Your Node.js server receives the resulting access token in the `Authorization: Bearer` header and calls `verifyToken`:

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
