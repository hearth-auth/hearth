# @hearth/node

Node.js/TypeScript SDK for [Hearth](https://github.com/hearthauth/hearth) — JWKS-backed JWT verification, token introspection, and Express/Fastify middleware.

## Server compatibility

| `@hearth/node` | Minimum Hearth server |
|----------------|-----------------------|
| 1.x            | 1.0.0                 |

Features used: OIDC discovery (`.well-known/openid-configuration`), JWKS endpoint, RFC 7662 token introspection.

## Install

```bash
npm install @hearth/node
```

## Quick start — Express middleware

```ts
import express from "express";
import { hearthMiddleware } from "@hearth/node";

const app = express();

app.use(
  hearthMiddleware({
    issuer: "https://your-hearth-instance.example.com",
    clientId: "my-api",
    audience: "my-api",
  })
);

app.get("/me", (req, res) => {
  res.json({ sub: req.auth?.sub });
});
```

## JWKS verification

```ts
import { JwksClient } from "@hearth/node";

const client = new JwksClient({
  issuer: "https://your-hearth-instance.example.com",
  audience: "my-api",
});

const { payload } = await client.verify(token);
console.log(payload.sub);
```

## Token introspection

```ts
import { IntrospectionClient } from "@hearth/node";

const intro = new IntrospectionClient({
  introspectionEndpoint: "https://your-hearth-instance.example.com/oauth/introspect",
  clientId: "my-api",
  clientSecret: "secret",
});

const result = await intro.introspect(token);
if (!result.active) throw new Error("Token revoked or expired");
```

## Fastify

```ts
import Fastify from "fastify";
import { hearthFastifyPlugin } from "@hearth/node";

const app = Fastify();

app.addHook("preHandler", hearthFastifyPlugin({
  issuer: "https://your-hearth-instance.example.com",
  clientId: "my-api",
}));
```

## Observability endpoints

```ts
import express from "express";
import { HearthObservability } from "@hearth/node";

const app = express();
const obs = new HearthObservability({
  readinessChecks: [
    async () => ({ name: "db", ok: true }),
  ],
});

app.get("/metrics", obs.metricsHandler());
app.get("/healthz", obs.healthzHandler());
app.get("/readyz", obs.readyzHandler());

// Record domain metrics from your handlers/services.
obs.recordAuthAttempt(true);
obs.recordTokenIssuance(true);
obs.setActiveSessions(42);
obs.observeHttpRequest(0.021, { method: "POST", route: "/oauth/token", status: 200 });
obs.observeDbQuery(0.003, { operation: "find_session", status: "ok" });
```

## Webhook signature verification

```ts
import { WebhookVerifier } from "@hearth/node";

const verifier = new WebhookVerifier({ secret: process.env.HEARTH_WEBHOOK_SECRET! });

const rawBody = JSON.stringify(req.body);
verifier.verify(rawBody, req.headers as Record<string, string | string[] | undefined>);
```

By default the verifier checks:

- `x-hearth-signature` HMAC-SHA256 header (`sha256=<hex>`)
- optional `x-hearth-timestamp` freshness (300 second tolerance)

## API

### `JwksClient`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `issuer` | `string` | required | Hearth server base URL |
| `jwksUri` | `string` | auto-discovered | Override JWKS URI |
| `audience` | `string \| string[]` | none | Expected token audience(s) |
| `cacheTtlMs` | `number` | `600_000` (10 min) | JWKS cache TTL |

- `verify(token, options?)` — verify JWT signature and claims, returns `{ payload, header }`
- `resetCache()` — force JWKS re-fetch on next verification

### `IntrospectionClient`

- `introspect(token, hint?)` — call introspection endpoint, returns RFC 7662 response
- `isActive(token)` — shorthand returning boolean active state

### `hearthMiddleware(options)`

Express 4/5 compatible middleware. Attaches verified claims to `req.auth`. Returns 401 on missing/invalid token (`required: true` by default).

### `hearthFastifyPlugin(options)`

Fastify `preHandler` hook. Attaches verified claims to `request.auth`.

### `WebhookVerifier`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secret` | `string` | required | HMAC secret used to sign webhook payloads |
| `signatureHeader` | `string` | `x-hearth-signature` | Header carrying signature(s) |
| `timestampHeader` | `string` | `x-hearth-timestamp` | Optional unix timestamp header |
| `toleranceSeconds` | `number` | `300` | Timestamp freshness window; set `0` to disable |
| `signaturePrefix` | `string` | `sha256=` | Signature prefix in header entries |

- `verify(body, headers, now?)` — throws `WebhookVerificationError` when invalid

## Troubleshooting

### `JwksFetchError: Failed to fetch JWKS`

The SDK cannot reach the JWKS endpoint derived from your `issuer_url`. Verify:
- `issuer_url` is reachable from your server (not a browser-only URL)
- No firewall or egress policy blocks outbound HTTPS to the Hearth instance
- The Hearth server is running and healthy (check `/healthz`)

### `DiscoveryError: OIDC discovery failed`

Auto-discovery failed fetching `{issuer_url}/.well-known/openid-configuration`. Check that:
- `issuer_url` does not include a trailing path (use `https://auth.example.com`, not `https://auth.example.com/oauth`)
- The Hearth server version is ≥ 1.0.0 (older versions may not expose the discovery endpoint)

### `TokenExpiredError: Token has expired`

The JWT `exp` claim is in the past. Either:
- The client did not refresh the token before expiry — ensure your client calls `refresh_token` flows
- Your server clock is drifted; `jwks_ttl` / clock skew tolerance can be widened via `HearthClient` config (default: 60s)

### `TokenClaimsError: iss mismatch` / `aud mismatch`

- **`iss`**: The token's `iss` claim does not match `issuer_url`. Confirm you're pointing at the correct Hearth instance.
- **`aud`**: The token's `aud` claim does not include `client_id`. Ensure the Hearth client is configured with the correct audience.

### `TokenVerificationError: No matching key found in JWKS`

The signing key in the JWT header (`kid`) is not in the current JWKS. This usually means a key rotation just occurred. The SDK re-fetches JWKS on 401 automatically, but if you see this in a non-middleware context call `client.verifyToken()` — it will re-fetch and retry. If the error persists, confirm the Hearth server is serving the correct JWKS.

### `MiddlewareError: Authorization header missing or malformed`

The `Authorization` header is absent or not in `Bearer <token>` format. The middleware returns `401` automatically. On the client side, ensure the header is set:
```
Authorization: Bearer <access_token>
```

### `IntrospectionError: Introspection request failed`

The introspection endpoint returned a non-200 response. Check:
- `client_id` and `client_secret` are correct for the Hearth client
- The Hearth client has introspection enabled in its configuration
- Network connectivity between your server and the Hearth introspection endpoint
