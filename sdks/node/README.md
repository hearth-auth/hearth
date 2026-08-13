# Hearth Node.js SDK

> **SDK Specification:** This SDK must conform to the [Hearth SDK Common Specification](../../docs/specs/SDK.md).

Server-side Node.js client for [Hearth](https://github.com/hearth-auth/hearth). Covers JWT verification, token introspection, Express/Fastify middleware, and the Admin API.

**Use this SDK when:** you are building a Node.js server that must verify Hearth-issued tokens or enforce permission checks on incoming requests.

**Use [`@hearth-auth/sdk`](../typescript/README.md) instead when:** you need a browser/React integration, PKCE authorization-code flow, or React hooks (`useHasPermission`, `HearthProvider`).

---

## Installation

```bash
npm install @hearth-auth/node
# or
yarn add @hearth-auth/node
# or
pnpm add @hearth-auth/node
```

| SDK version | Minimum Node.js | Minimum Hearth server |
|-------------|-----------------|----------------------|
| 1.0.x       | 18.0.0          | 1.0.0                |

**Peer dependencies:** none. The SDK ships `jose` as a direct dependency for JWKS verification.

---

## Quick start

```typescript
import { HearthClient } from "@hearth-auth/node";

const client = new HearthClient({
  issuer_url: "https://hearth.example.com",
  client_id: process.env.HEARTH_CLIENT_ID,      // required for audience validation
  client_secret: process.env.HEARTH_CLIENT_SECRET, // required for introspection/Decision mode
});

// Verify an incoming Bearer token (JWKS-based, local, no network on cache hit)
const token = await client.verifyToken(rawToken);
// use your logger — avoid logging sub/email to stdout (PII in container logs)
console.log("Has permission:", token.hasPermission("docs.write"));
```

`HearthClient` auto-discovers all endpoint URLs from `{issuer_url}/.well-known/openid-configuration` on first use.

---

## Token verification

> **Audience validation:** always supply `client_id`. Without it the SDK has no audience to
> compare the JWT `aud` claim against, leaving the server open to token-confusion attacks
> (RFC 7519 §4.1.3). Omit `client_id` only when this server intentionally accepts tokens
> issued for any client (e.g. a pure gateway that delegates authz downstream).

```typescript
import { HearthClient, TokenExpiredError, TokenInvalidError } from "@hearth-auth/node";

const client = new HearthClient({
  issuer_url: "https://hearth.example.com",
  client_id: process.env.HEARTH_CLIENT_ID, // enables JWT `aud` validation
});

try {
  const token = await client.verifyToken(rawToken);
  // token is a VerifiedToken — typed access to all claims
  token.subject();                           // JWT `sub`
  token.issuer();                            // JWT `iss`
  token.expiry();                            // Date | null
  token.hasRole("admin");                    // reads `roles` claim
  token.hasPermission("docs.write");         // reads `permissions` claim
  token.inGroup("engineering");              // reads `groups` claim
  token.inOrg("org_acme");                   // reads `oid` claim
} catch (err) {
  if (err instanceof TokenExpiredError) {
    // 401 — ask client to refresh
  } else if (err instanceof TokenInvalidError) {
    // 401 — reject the request
  }
}
```

JWKS keys are cached by `kid`. On a cache miss the SDK re-fetches the JWKS once before
failing — this handles transparent key rotation. Call `client.invalidateCache()` after
receiving a `401` from a downstream service to force a re-fetch.

---

## Express middleware

```typescript
import express from "express";
import { hearthMiddleware } from "@hearth-auth/node";

const app = express();

// Protect all routes — embedded mode (JWKS only, no network per request)
app.use(
  hearthMiddleware({
    issuer_url: "https://hearth.example.com",
    expectedMode: "embedded",
  })
);

// Access the verified token downstream via req.hearthToken
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

The middleware responds `401 Unauthorized` with `WWW-Authenticate: Bearer realm="hearth"` on
missing or invalid tokens, and `403 Forbidden` on scope/role/permission failures. It never
calls `next` on auth failure.

---

## Fastify hook

```typescript
import Fastify from "fastify";
import { hearthFastifyHook } from "@hearth-auth/node";

const app = Fastify();

app.addHook(
  "onRequest",
  hearthFastifyHook({
    issuer_url: "https://hearth.example.com",
    expectedMode: "embedded",
    requiredRole: "admin",
  })
);
```

The hook calls `reply.code(401).send(...)` on missing or invalid tokens and
`reply.code(403).send(...)` on permission failures. It always calls `reply.hijack()` on
failure so no downstream handler runs. It never resolves to `next` on auth failure.

---

## Permission delivery modes

Hearth supports three modes for how RBAC data reaches your resource server. The mode must
match the `access_token_authorization` setting on the registered OAuth client.

| Mode | Strategy | Network per request |
|------|----------|-------------------|
| `embedded` (default) | RBAC claims baked into JWT at issuance; verify via JWKS | None |
| `introspection` | Call `POST /introspect`; server re-resolves live RBAC | 1 |
| `decision` | Call `POST /oauth/authorize`; server returns `allowed` | 1 |

> **Design constraint:** the SDK never infers mode from whether `permissions` is present in
> the token. Declare `expectedMode` explicitly; absence of `permissions` in `embedded` mode
> means the user has no permissions, not that a different mode should be tried.

### Introspection mode

```typescript
import { HearthClient } from "@hearth-auth/node";

const client = new HearthClient({
  issuer_url: "https://hearth.example.com",
  client_id: "<resource-server-client-id>",
  client_secret: process.env.RS_SECRET,
});

const result = await client.introspect(rawToken);
if (result.active) {
  console.log("Live permissions:", result.extra?.permissions);
}
```

Or via middleware:

```typescript
app.use(
  hearthMiddleware({
    issuer_url: "https://hearth.example.com",
    client_id: "<resource-server-client-id>",
    client_secret: process.env.RS_SECRET,
    expectedMode: "introspection",
    requiredPermission: "docs.write",
  })
);
```

### Decision mode

```typescript
const result = await client.authorize(rawToken, "docs.write");
if (result.allowed) {
  // proceed
}
```

Decision mode is fail-closed: network errors return `{ allowed: false }`.

---

## Token introspection (RFC 7662)

```typescript
const result = await client.introspect(rawToken);
// result.active         — boolean
// result.sub            — string (when active)
// result.exp, iat, iss  — standard claims
// result.scope          — space-delimited string
// result.extra          — all non-standard claims (includes roles, permissions, groups)
```

Introspection results are **never cached** — per RFC 7662, token state can change at any time.

Introspection mode is fail-closed: network errors or non-2xx responses from the introspection
endpoint cause the middleware to respond `401 Unauthorized`. The request is never forwarded to
the route handler on an indeterminate result.

---

## Admin API

```typescript
import { AdminClient } from "@hearth-auth/node";

const admin = new AdminClient({
  base_url: "https://hearth.example.com",
  realm_id: "<realm-id>",
  access_token: adminToken, // must carry hearth.admin permission
});

// Users
const user = await admin.createUser({ email: "alice@example.com", display_name: "Alice" });
const page = await admin.listUsers({ limit: 50 });
// page.items: User[], page.next_cursor: string | null
await admin.deleteUser(user.id);

// Realms are provisioned via hearth.yaml, not the admin API — there is no
// createRealm() (the server returns 405). Only read paths are exposed.
const realm = await admin.getRealm("<realm-id>");
```

---

## Error types

All SDK errors extend `HearthError`. Import typed errors for precise handling:

| Error | When thrown |
|-------|-------------|
| `ConfigurationError` | Missing required config (e.g. `client_secret` needed for introspection) |
| `DiscoveryError` | OIDC discovery endpoint unreachable or returned invalid JSON |
| `JWKSFetchError` | JWKS endpoint unreachable or returned invalid response |
| `TokenExpiredError` | `exp` claim is in the past |
| `TokenNotYetValidError` | `nbf` claim is in the future |
| `TokenInvalidError` | Signature invalid, malformed JWT |
| `TokenIssuerError` | `iss` mismatch |
| `TokenAudienceError` | `aud` does not contain expected audience |
| `IntrospectionError` | Introspection endpoint unreachable or returned error |
| `RequiredActionError` | Token `token_type` is `"required_action"` |
| `AuthorizationModeError` | Server echoed a mode that differs from `expectedMode` |
| `AdminHttpError` | Admin API returned non-2xx |

```typescript
import { HearthClient, TokenExpiredError, RequiredActionError } from "@hearth-auth/node";

const client = new HearthClient({
  issuer_url: "https://hearth.example.com",
  client_id: process.env.HEARTH_CLIENT_ID,
});

try {
  const token = await client.verifyToken(rawToken);
} catch (err) {
  if (err instanceof RequiredActionError) {
    // Token is valid but requires user to complete actions before using the API
    console.log("Pending actions:", err.requiredActions); // string[]
    // Redirect to err.redirectUri if present
  } else if (err instanceof TokenExpiredError) {
    // Ask client to refresh
  }
}
```

---

## Troubleshooting

**`DiscoveryError`** — verify `issuer_url` is reachable and returns a valid `/.well-known/openid-configuration`.

**`JWKSFetchError`** — check network connectivity to the JWKS endpoint. The SDK re-fetches
once on a cache miss before returning this error.

**`TokenExpiredError`** — the token's `exp` claim is in the past. Ask the client to refresh.

**`TokenInvalidError`** — JWT signature does not match any key in the JWKS. If the server
recently rotated keys, call `client.invalidateCache()` and retry once.

**`TokenAudienceError`** — the token's `aud` claim does not contain the configured audience.
Verify `client_id` matches what your authorization server issues.

**`AuthorizationModeError`** — the server echoed a mode different from `expectedMode`. Verify
the `access_token_authorization` setting on the registered OAuth client matches your SDK config.

**`ConfigurationError: client_secret required`** — Introspection and Decision modes require
`client_secret`. Pass it in the `HearthClient` constructor.

See [docs/specs/SDK.md](../../docs/specs/SDK.md) Section 5 for the full error taxonomy.
