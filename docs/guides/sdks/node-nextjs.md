---
title: Authenticate a Next.js app with Hearth
sidebar_label: Next.js
description: >
  Protect Next.js routes with Hearth tokens using the dedicated Next.js adapter.
  Covers Edge Runtime middleware, App Router Route Handlers, and Pages Router API routes.
---

# Authenticate a Next.js app with Hearth

This guide is for **Next.js developers** who want to protect routes and API handlers with Hearth tokens. The `@hearth-auth/node` package ships a dedicated Next.js adapter with separate entry points for the Edge Runtime and the Node.js runtime — no separate package to install.

:::note[Node.js SDK vs TypeScript SDK]
This page covers the **server-side** Next.js adapter. For **browser client components** — `HearthProvider`, `useHasPermission` hooks, and browser-hosted PKCE — see the [TypeScript SDK](./typescript.md).
:::

## Install

```bash
npm install @hearth-auth/node
# or: yarn add @hearth-auth/node  |  pnpm add @hearth-auth/node
```

## Which entry point to use

| Context | Import path | Key export |
|---------|-------------|------------|
| `middleware.ts` (Edge Runtime) | `@hearth-auth/node/nextjs/edge` | `hearthEdgeMiddleware()` |
| App Router Route Handlers | `@hearth-auth/node/nextjs` | `getHearthToken()` |
| Pages Router API routes | `@hearth-auth/node/nextjs` | `withHearthAuth()` |

The edge entry point uses only Web Crypto (`globalThis.crypto`) — safe in the V8 Isolate Edge Runtime. The Node.js runtime helpers use the full Node.js crypto stack.

:::caution[Option naming differs between entry points]
The **edge** entry point uses camelCase option names (`issuerUrl`, `jwksUri`).
The **Node.js** entry point uses snake_case (`issuer_url`, `client_id`) from `HearthConfig`.
Mixing them will cause TypeScript errors at compile time.
:::

---

## Edge Runtime middleware (`middleware.ts`)

Next.js `middleware.ts` runs in the Edge Runtime. Use `hearthEdgeMiddleware` from the edge-specific entry point to protect routes without a full Node.js runtime.

```typescript
// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { hearthEdgeMiddleware } from "@hearth-auth/node/nextjs/edge";

const guard = hearthEdgeMiddleware({
  issuerUrl: process.env.HEARTH_ISSUER_URL!,
  jwksUri:   `${process.env.HEARTH_ISSUER_URL}/.well-known/jwks.json`,
});

export async function middleware(request: NextRequest) {
  const result = await guard(request);
  if (result) return result; // 401 or 403 Response — return directly
  return NextResponse.next();
}

// Apply only to /api routes
export const config = { matcher: ["/api/:path*"] };
```

`hearthEdgeMiddleware` returns:
- `undefined` — token is valid; call `NextResponse.next()` to continue.
- `Response` (401 or 403) — token is missing, invalid, or lacks the required scope/role/permission; return it directly to the client.

:::note[Why explicit `jwksUri`?]
The Edge Runtime adapter skips OIDC discovery to avoid an extra network round-trip on every invocation. The JWKS URI is always `<issuer-url>/.well-known/jwks.json` for a standard Hearth install. Find the exact value in `https://<hearth-host>/.well-known/openid-configuration` → `jwks_uri`.
:::

### Scope, role, and permission guards at the edge

```typescript
// middleware.ts — require a permission on admin routes
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { hearthEdgeMiddleware } from "@hearth-auth/node/nextjs/edge";

const guard = hearthEdgeMiddleware({
  issuerUrl:          process.env.HEARTH_ISSUER_URL!,
  jwksUri:            `${process.env.HEARTH_ISSUER_URL}/.well-known/jwks.json`,
  requiredPermission: "admin:write",
});

export async function middleware(request: NextRequest) {
  const result = await guard(request);
  if (result) return result;
  return NextResponse.next();
}

export const config = { matcher: ["/admin/:path*"] };
```

For per-handler permission logic, use the composable `requirePermission` guard:

```typescript
import { requirePermission } from "@hearth-auth/node/nextjs/edge";
import type { EdgeToken } from "@hearth-auth/node/nextjs/edge";

const isAdmin = requirePermission("admin:write");

// In a Route Handler or Server Action:
if (!isAdmin(token)) {
  return new Response(null, { status: 403 });
}
```

### All edge middleware options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `issuerUrl` | `string` | **required** | Must match the `iss` claim in tokens |
| `jwksUri` | `string` | **required** | JWKS endpoint URL |
| `audience` | `string \| string[]` | — | Expected `aud` claim; omit to skip audience check |
| `required` | `boolean` | `true` | Return 401 when no Bearer token is present |
| `requiredScope` | `string` | — | Return 403 if scope is absent |
| `requiredRole` | `string` | — | Return 403 if role is absent |
| `requiredPermission` | `string` | — | Return 403 if permission is absent |
| `clockSkewSeconds` | `number` | `60` | Clock tolerance for `exp`/`nbf` |
| `jwksCacheTtlMs` | `number` | `600000` (10 min) | JWKS key cache TTL |

---

## App Router Route Handlers

Use `getHearthToken` inside a Route Handler (`app/api/*/route.ts`). It reads `Authorization: Bearer <token>`, verifies the JWT, and returns a typed `VerifiedToken` — or `null` if the token is missing or invalid.

```typescript
// app/api/profile/route.ts
import { NextRequest, NextResponse } from "next/server";
import { getHearthToken } from "@hearth-auth/node/nextjs";

// Define the config outside the handler so the JWKS cache is shared across requests
const hearthConfig = {
  issuer_url: process.env.HEARTH_ISSUER_URL!,
  client_id:  process.env.HEARTH_CLIENT_ID!,
};

export async function GET(request: NextRequest) {
  const token = await getHearthToken(request, hearthConfig);
  if (!token) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  return NextResponse.json({
    sub:    token.subject(),
    scopes: token.scopes(),
  });
}
```

### Checking permissions in a Route Handler

```typescript
// app/api/documents/route.ts
import { NextRequest, NextResponse } from "next/server";
import { getHearthToken } from "@hearth-auth/node/nextjs";

const hearthConfig = {
  issuer_url: process.env.HEARTH_ISSUER_URL!,
  client_id:  process.env.HEARTH_CLIENT_ID!,
};

export async function POST(request: NextRequest) {
  const token = await getHearthToken(request, hearthConfig);
  if (!token) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  if (!token.hasPermission("docs:write")) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  // handle the request ...
  return NextResponse.json({ created: true });
}
```

---

## Pages Router API routes

Use `withHearthAuth` to wrap a Pages Router handler (`pages/api/*.ts`). It verifies the `Authorization: Bearer` token, attaches it to `req.hearthToken`, and calls the inner handler only on success.

```typescript
// pages/api/profile.ts
import type { NextApiRequest, NextApiResponse } from "next";
import { withHearthAuth } from "@hearth-auth/node/nextjs";

export default withHearthAuth(
  (req, res) => {
    // req.hearthToken is always set here — withHearthAuth never reaches the handler on auth failure
    res.json({ sub: req.hearthToken!.subject() });
  },
  {
    issuer_url: process.env.HEARTH_ISSUER_URL!,
    client_id:  process.env.HEARTH_CLIENT_ID!,
  },
);
```

`withHearthAuth` returns:
- `401 Unauthorized` (`WWW-Authenticate: Bearer realm="hearth"`) — token missing or invalid.
- `403 Forbidden` — token valid but `requiredPermission`, `requiredScope`, or `requiredRole` not met.

The inner handler is not invoked on either failure.

### Require a permission on a Pages Router route

```typescript
// pages/api/documents.ts
import type { NextApiRequest, NextApiResponse } from "next";
import { withHearthAuth } from "@hearth-auth/node/nextjs";

export default withHearthAuth(
  (req, res) => {
    res.json({ ok: true });
  },
  {
    issuer_url:         process.env.HEARTH_ISSUER_URL!,
    client_id:          process.env.HEARTH_CLIENT_ID!,
    requiredPermission: "docs:write",
  },
);
```

---

## OAuth login flow (PKCE)

The Next.js adapter does not include a built-in login page. Use `HearthClient` from `@hearth-auth/node` to handle the OAuth 2.0 + PKCE flow in your API routes.

:::warning[Store tokens in httpOnly cookies, not `localStorage`]
`localStorage` and `sessionStorage` are readable by any JavaScript on the page. An XSS vulnerability exposes any token stored there. Use `httpOnly` cookies (inaccessible to JS) or server-side sessions instead.
:::

```typescript
// pages/api/login.ts — initiate PKCE flow
import type { NextApiRequest, NextApiResponse } from "next";
import { HearthClient } from "@hearth-auth/node";

const client = new HearthClient({
  issuer_url:    process.env.HEARTH_ISSUER_URL!,
  client_id:     process.env.HEARTH_CLIENT_ID!,
  client_secret: process.env.HEARTH_CLIENT_SECRET!,
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { authorizationUrl, state, codeVerifier } = await client.beginLogin(
    `${process.env.NEXT_PUBLIC_BASE_URL}/api/callback`,
    "openid profile email",
  );
  // Persist state + codeVerifier in httpOnly cookies — never in localStorage
  res.setHeader("Set-Cookie", [
    `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/`,
    `code_verifier=${codeVerifier}; HttpOnly; Secure; SameSite=Lax; Path=/`,
  ]);
  res.redirect(302, authorizationUrl);
}
```

```typescript
// pages/api/callback.ts — exchange code for tokens
import type { NextApiRequest, NextApiResponse } from "next";
import { HearthClient } from "@hearth-auth/node";

const client = new HearthClient({
  issuer_url:    process.env.HEARTH_ISSUER_URL!,
  client_id:     process.env.HEARTH_CLIENT_ID!,
  client_secret: process.env.HEARTH_CLIENT_SECRET!,
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { oauth_state, code_verifier } = req.cookies;
  if (req.query.state !== oauth_state) {
    return res.status(400).json({ error: "state mismatch" });
  }
  const tokens = await client.completeLogin(
    req.query.code as string,
    code_verifier!,
    `${process.env.NEXT_PUBLIC_BASE_URL}/api/callback`,
  );
  // Store the access token in an httpOnly cookie for subsequent API calls
  res.setHeader("Set-Cookie",
    `access_token=${tokens.access_token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${tokens.expires_in}`,
  );
  res.redirect(302, "/dashboard");
}
```

---

## Required-action tokens

If a user has a pending required action (e.g. email verification, MFA enrollment), their access token has `token_type: "required_action"`. Both `hearthEdgeMiddleware` and `withHearthAuth` automatically return `401` on required-action tokens. When using `getHearthToken`, check explicitly:

```typescript
export async function GET(request: NextRequest) {
  const token = await getHearthToken(request, hearthConfig);
  if (!token) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  if (token.tokenType() === "required_action") {
    return NextResponse.json(
      { error: "action_required", required_actions: token.requiredActions() },
      { status: 401 },
    );
  }
  // proceed with normal handler ...
}
```

---

## Environment variables

| Variable | Used in | Description |
|----------|---------|-------------|
| `HEARTH_ISSUER_URL` | All | Hearth base URL — e.g. `https://hearth.example.com` |
| `HEARTH_CLIENT_ID` | Node.js runtime helpers | OAuth client ID registered in Hearth |
| `HEARTH_CLIENT_SECRET` | Login / callback flow | Client secret — **never** prefix with `NEXT_PUBLIC_` |
| `NEXT_PUBLIC_BASE_URL` | Login / callback flow | Public base URL for building the redirect URI |

---

## Next steps

- [Node.js SDK](./node.md) — `hearthMiddleware` for Express, `hearthFastifyHook` for Fastify, and the full client API
- [TypeScript SDK](./typescript.md) — browser PKCE flow and React hooks for Next.js client components
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Permission delivery modes](./node.md#permission-delivery-modes) — embedded, introspection, and decision mode details
