---
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

## Error handling

All `HearthClient` methods throw typed errors:

```typescript
import {
  HearthClient,
  ConfigurationError,
  TokenExpiredError,
  TokenInvalidError,
  TokenIssuerError,
  OAuthFlowError,
  RequiredActionError,
} from "@hearth-auth/sdk";

try {
  const claims = await client.verifyToken(accessToken);
} catch (err) {
  if (err instanceof RequiredActionError) {
    // Token is valid but user must complete: err.requiredActions (string[])
    // Redirect to err.redirectUri if present
  } else if (err instanceof TokenExpiredError) {
    // 401 — ask client to refresh
  } else if (err instanceof TokenIssuerError) {
    // 401 — token from wrong realm
  } else if (err instanceof TokenInvalidError) {
    // 401 — bad signature or malformed JWT
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

## Runnable example

A complete Next.js 14 (App Router) example lives at
[`examples/typescript-nextjs/`](https://github.com/hearth-auth/hearth/tree/main/examples/typescript-nextjs).
It covers the full PKCE flow, Edge middleware route protection, and React RBAC
hooks — all runnable with `npm run dev`.

## Next steps

- [RBAC guide](/docs/rbac) — roles, groups, permissions, and JWT claim structure
- [Admin API guide](/docs/admin-api) — managing users and clients programmatically
- [TypeScript type reference](https://github.com/hearth-auth/hearth/blob/main/sdks/typescript/README.md) — full interface list
