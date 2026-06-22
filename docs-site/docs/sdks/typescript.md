---
id: typescript
title: TypeScript SDK quickstart
sidebar_label: TypeScript
description: Add Hearth authentication and RBAC to a TypeScript app in under 5 minutes.
---

# TypeScript SDK quickstart

Get your first protected route in under 5 minutes using `@hearth-auth/sdk`.

## Install

```bash
npm install @hearth-auth/sdk
# or: yarn add @hearth-auth/sdk  |  pnpm add @hearth-auth/sdk
```

**Peer dependency:** React 17–19 is required only if you use the `HearthProvider`
and hooks. The `HearthClient` and `createHearth` factory work in any TypeScript
environment.

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

```typescript
import { HearthClient } from "@hearth-auth/sdk";

const client = new HearthClient({
  baseUrl: "http://127.0.0.1:8420",
  realmId: "<realm_id>",
});
```

## Authenticate with PKCE

PKCE is mandatory for all public clients (browser apps, mobile apps) and
recommended for confidential clients.

### Step 1 — Build the authorization URL

```typescript
import { createHash, randomBytes } from "crypto";

const codeVerifier = randomBytes(32).toString("hex");
const codeChallenge = createHash("sha256")
  .update(codeVerifier)
  .digest("base64url");
const state = randomBytes(16).toString("hex"); // CSRF token

// Fetch Hearth's OIDC discovery document
const discovery = await client.discovery();

// Build the URL and redirect the browser to it
const authUrl = new URL(discovery.authorization_endpoint);
authUrl.searchParams.set("response_type", "code");
authUrl.searchParams.set("client_id", "<client_id>");
authUrl.searchParams.set("redirect_uri", "http://localhost:3000/callback");
authUrl.searchParams.set("scope", "openid profile email");
authUrl.searchParams.set("state", state);
authUrl.searchParams.set("code_challenge", codeChallenge);
authUrl.searchParams.set("code_challenge_method", "S256");

window.location.href = authUrl.toString();
```

Store `codeVerifier` and `state` in `sessionStorage` or an HTTP-only cookie
for use in the callback.

### Step 2 — Exchange the code

After the user authenticates, Hearth redirects to your `redirect_uri` with
`?code=…&state=…`. Verify state and exchange the code:

```typescript
const params = new URLSearchParams(window.location.search);
const code = params.get("code")!;
// verify params.get("state") === savedState before proceeding

const tokens = await client.exchangeCode({
  clientId: "<client_id>",
  code,
  redirectUri: "http://localhost:3000/callback",
  codeVerifier, // retrieved from storage
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
  HearthProvider,
  useHasPermission,
  useHasRole,
  useInGroup,
} from "@hearth-auth/sdk";

const hearth = createHearth({
  baseUrl: "http://127.0.0.1:8420",
  realmId: "<realm_id>",
  getToken: () => localStorage.getItem("access_token"),
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
import { createHearth } from "@hearth-auth/sdk";

const hearth = createHearth({
  baseUrl: "http://127.0.0.1:8420",
  realmId: "<realm_id>",
  getToken: () => sessionStorage.getItem("access_token"),
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

## Verify tokens on the server

Use [`jose`](https://github.com/panva/jose) and Hearth's JWKS endpoint to
verify tokens in Node.js without an SDK round-trip:

```typescript
import { createRemoteJWKSet, jwtVerify } from "jose";

const JWKS = createRemoteJWKSet(
  new URL("http://127.0.0.1:8420/realms/<realm_id>/jwks"),
);

const { payload } = await jwtVerify(accessToken, JWKS, {
  issuer: "http://127.0.0.1:8420",
  audience: "<client_id>",
});
// payload.sub — stable user identifier
// payload.permissions — string[]
// payload.roles       — string[]
// payload.groups      — string[]
```

`createRemoteJWKSet` caches keys and re-fetches on a key miss, so server key
rotation is handled automatically.

## Error handling

All `HearthClient` methods throw `HearthError` on non-2xx responses.

```typescript
import { HearthClient, HearthError } from "@hearth-auth/sdk";

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

## Runnable example

A complete Next.js 14 (App Router) example lives at
[`examples/typescript-nextjs/`](https://github.com/hearth-auth/hearth/tree/main/examples/typescript-nextjs).
It covers the full PKCE flow, Edge middleware route protection, and React RBAC
hooks — all runnable with `npm run dev`.

## Next steps

- [RBAC guide](../rbac.md) — roles, groups, permissions, and JWT claim structure
- [Admin API guide](../admin-api.md) — managing users and clients programmatically
- [TypeScript type reference](https://github.com/hearth-auth/hearth/blob/main/sdks/typescript/README.md) — full interface list
