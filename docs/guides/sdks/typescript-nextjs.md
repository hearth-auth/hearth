---
title: Authenticate a Next.js app with Hearth
sidebar_label: Next.js
description: >
  Protect Next.js routes with Hearth tokens using the TypeScript SDK's Next.js helpers.
  Covers Edge Runtime middleware, App Router Route Handlers, Pages Router API routes, and the server-side login flow.
---

# Authenticate a Next.js app with Hearth

This guide is for **Next.js developers** who want to protect routes and API handlers with
Hearth tokens. The `@hearth-auth/sdk` package has two Next.js entry points: one for the Edge
Runtime and one for the Node.js runtime. There is no separate package to install.

:::note[Server side and browser side]
This page covers the server side of a Next.js app. For **client components** —
`HearthProvider`, `useHasPermission` and browser PKCE — see the
[TypeScript SDK guide](./typescript.md).
:::

## Install

```bash
npm install @hearth-auth/sdk
# or: yarn add @hearth-auth/sdk  |  pnpm add @hearth-auth/sdk
```

Next.js 14 or later is an optional peer dependency, needed only for these entry points.

## Which entry point to use

| Context | Import path | Export |
|---------|-------------|------------|
| `middleware.ts` (Edge Runtime) | `@hearth-auth/sdk/nextjs/edge` | `hearthEdgeMiddleware()` |
| App Router Route Handlers | `@hearth-auth/sdk/nextjs` | `getHearthClaims()` |
| Pages Router API routes | `@hearth-auth/sdk/nextjs` | `withHearthAuth()` |

All three verify tokens with a `HearthClient` from `@hearth-auth/sdk`. Create it once at
module scope so the discovery document and JWKS stay cached:

```typescript
// lib/hearth.ts
import { HearthClient } from "@hearth-auth/sdk";

export const hearth = new HearthClient({
  issuerUrl: process.env.HEARTH_ISSUER_URL!,
  clientId: process.env.HEARTH_CLIENT_ID, // pins the `aud` claim
});
```

`HearthClient` reads every endpoint URL, including the JWKS URI, from
`{issuerUrl}/.well-known/openid-configuration`. You do not configure the JWKS URI,
audience or clock skew separately.

---

## Edge Runtime middleware (`middleware.ts`)

Next.js `middleware.ts` runs on the Edge Runtime. `hearthEdgeMiddleware` uses only `fetch`
and Web Crypto, so it runs there.

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

The guard resolves to:

- `undefined` — the request may proceed; return `NextResponse.next()`.
- a 401 or 403 JSON `Response` — return it as is.

Create the guard at module scope so the client's caches live as long as the isolate.

### Options

`hearthEdgeMiddleware`, `withHearthAuth` and the Express `hearthMiddleware` take the same
options:

| Option | Meaning |
|---|---|
| `client` | **Required.** The `HearthClient` to verify with. |
| `mode` | `"embedded"`, `"introspection"` or `"decision"`. Default: `client.expectedMode`, then `"embedded"`. |
| `required` | Default `true`. When `false`, a request with no token or a token that does not verify goes through. |
| `requiredScope` | Answer 403 unless the token's `scope` contains this value. |
| `requiredRole` | Answer 403 unless the token's `roles` claim contains this value. |
| `requiredPermission` | Answer 403 unless the token holder has this permission (checked per `mode`). |
| `organizationId`, `resource` | Sent with the decision-mode `POST /oauth/authorize` call. |

A client that cannot serve the mode makes the factory throw `ConfigurationError` at startup.
See [Permission delivery modes](./typescript.md#permission-delivery-modes) for how each mode
checks `requiredPermission`.

To require a permission on admin routes:

```typescript
// middleware.ts
import { NextResponse, type NextRequest } from "next/server";
import { HearthClient } from "@hearth-auth/sdk";
import { hearthEdgeMiddleware } from "@hearth-auth/sdk/nextjs/edge";

const guard = hearthEdgeMiddleware({
  client: new HearthClient({
    issuerUrl: process.env.HEARTH_ISSUER_URL!,
    clientId: process.env.HEARTH_CLIENT_ID,
  }),
  requiredPermission: "admin.write",
});

export async function middleware(request: NextRequest) {
  return (await guard(request)) ?? NextResponse.next();
}

export const config = { matcher: ["/admin/:path*"] };
```

---

## App Router Route Handlers

`getHearthClaims(request, client)` reads `Authorization: Bearer <token>`, verifies the JWT,
and returns the verified `Claims`. It returns `null` when there is no bearer token, the token
does not verify, or it is a `required_action` token.

```typescript
// app/api/profile/route.ts
import { NextResponse } from "next/server";
import { getHearthClaims } from "@hearth-auth/sdk/nextjs";
import { hearth } from "@/lib/hearth";

export async function GET(request: Request) {
  const claims = await getHearthClaims(request, hearth);
  if (!claims) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  return NextResponse.json({ sub: claims.subject(), scopes: claims.scopes() });
}
```

### Checking permissions in a Route Handler

```typescript
// app/api/documents/route.ts
import { NextResponse } from "next/server";
import { getHearthClaims } from "@hearth-auth/sdk/nextjs";
import { hearth } from "@/lib/hearth";

export async function POST(request: Request) {
  const claims = await getHearthClaims(request, hearth);
  if (!claims) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  if (!claims.hasPermission("docs.write")) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  // handle the request ...
  return NextResponse.json({ created: true });
}
```

`claims.hasPermission` reads the `permissions` claim of the verified JWT (embedded mode).

---

## Pages Router API routes

`withHearthAuth` wraps a Pages Router handler (`pages/api/*.ts`). It verifies the bearer
token, applies the guards in its options, sets `req.hearthClaims`, and calls the handler.

```typescript
// pages/api/documents.ts
import { withHearthAuth } from "@hearth-auth/sdk/nextjs";
import { hearth } from "../../lib/hearth";

export default withHearthAuth(
  (req, res) => {
    // req.hearthClaims is set: the handler runs only after the token verified
    res.json({ sub: req.hearthClaims!.subject() });
  },
  { client: hearth, requiredPermission: "docs.write" },
);
```

`withHearthAuth` answers:

- `401 Unauthorized` (`WWW-Authenticate: Bearer realm="hearth"`) — the token is missing, does
  not verify, or is a `required_action` token.
- `403 Forbidden` — the token verified but `requiredScope`, `requiredRole` or
  `requiredPermission` is not met.

The handler is not called on either failure.

---

## OAuth login flow (PKCE)

The SDK has no built-in login page. Use `HearthClient.beginLogin` and `completeLogin` in two
Route Handlers. Keep `state` and the PKCE verifier in `HttpOnly` cookies.

:::warning[Store tokens in `HttpOnly` cookies, not `localStorage`]
`localStorage` and `sessionStorage` are readable by any JavaScript on the page. An XSS bug
exposes any token stored there. Use `HttpOnly` cookies or server-side sessions.
:::

```typescript
// lib/hearth-login.ts — a confidential client, used only on the server
import { HearthClient } from "@hearth-auth/sdk";

export const loginClient = new HearthClient({
  issuerUrl: process.env.HEARTH_ISSUER_URL!,
  clientId: process.env.HEARTH_CLIENT_ID!,
  clientSecret: process.env.HEARTH_CLIENT_SECRET!,
});

export const redirectUri = `${process.env.NEXT_PUBLIC_BASE_URL}/api/auth/callback`;
```

```typescript
// app/api/auth/login/route.ts
import { NextResponse } from "next/server";
import { loginClient, redirectUri } from "@/lib/hearth-login";

const cookie = { httpOnly: true, secure: true, sameSite: "lax", path: "/" } as const;

export async function GET() {
  const { authorizationUrl, state, codeVerifier } = await loginClient.beginLogin(
    redirectUri,
    "openid profile email",
  );
  const response = NextResponse.redirect(authorizationUrl);
  response.cookies.set("oauth_state", state, cookie);
  response.cookies.set("code_verifier", codeVerifier, cookie);
  return response;
}
```

```typescript
// app/api/auth/callback/route.ts
import { NextResponse, type NextRequest } from "next/server";
import { loginClient, redirectUri } from "@/lib/hearth-login";

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const state = request.cookies.get("oauth_state")?.value;
  const verifier = request.cookies.get("code_verifier")?.value;
  if (!state || !verifier || searchParams.get("state") !== state) {
    return NextResponse.json({ error: "state mismatch" }, { status: 400 });
  }
  const tokens = await loginClient.completeLogin(
    searchParams.get("code")!,
    verifier,
    redirectUri,
  );
  const response = NextResponse.redirect(new URL("/dashboard", request.url));
  response.cookies.set("access_token", tokens.access_token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: tokens.expires_in,
  });
  response.cookies.delete("oauth_state");
  response.cookies.delete("code_verifier");
  return response;
}
```

Refresh with `loginClient.refreshTokens(refreshToken)`. Hearth rotates refresh tokens, so
store the new one when it is present.

---

## Required-action tokens

Hearth never issues a token to a user with pending required actions (for example email
verification or MFA enrolment). A browser login runs them at `/required-action/{ACTION}`
before any code is issued, and a REST login answers `400 required_actions_pending`. As a
defence, all three helpers refuse a token with `token_type: "required_action"`:
`hearthEdgeMiddleware` and `withHearthAuth` answer 401, and `getHearthClaims` returns `null`.

---

## Environment variables

| Variable | Used in | Description |
|----------|---------|-------------|
| `HEARTH_ISSUER_URL` | All | Hearth base URL, for example `https://hearth.example.com` |
| `HEARTH_CLIENT_ID` | Token verification, login | OAuth client ID registered in Hearth |
| `HEARTH_CLIENT_SECRET` | Login and callback | Client secret. **Never** prefix it with `NEXT_PUBLIC_` |
| `NEXT_PUBLIC_BASE_URL` | Login and callback | Public base URL, used to build the redirect URI |

---

## Runnable example

A complete Next.js 14 (App Router) example lives at
[`examples/typescript-nextjs/`](https://github.com/hearth-auth/hearth/tree/main/examples/typescript-nextjs).

## Next steps

- [TypeScript SDK guide](./typescript.md) — Express and Fastify middleware, server-side OAuth
  flows, browser PKCE and React hooks
- [Permission delivery modes](./typescript.md#permission-delivery-modes) — embedded,
  introspection and decision modes
- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
