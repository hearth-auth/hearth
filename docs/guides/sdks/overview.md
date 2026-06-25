---
title: SDKs
sidebar_label: Overview
description: Official Hearth client SDKs for TypeScript and Go — auth code + PKCE, zero-network RBAC checks, and the Admin API.
---

# Hearth SDKs

Hearth ships official client SDKs for integrating authentication and RBAC into your application. Every SDK covers the same core contract: **auth code + PKCE flow**, zero-network RBAC checks decoded from the JWT, transparent token refresh, and the Hearth Admin API.

| Language | Package | Min version |
|----------|---------|-------------|
| [TypeScript / React](./typescript.md) | `@hearth-auth/sdk` (npm) | Node 18 · React 17–19 |
| [Go](./go.md) | `github.com/hearth-auth/hearth/sdks/go` | Go 1.21 |

## Quickstarts

- **[TypeScript / React](./typescript.md)** — browser SPAs, Next.js App Router, React hooks, Node.js server-side verification
- **[Go](./go.md)** — Go services, Gin middleware, `net/http`

## Common patterns

All SDKs expose the same surface:

| Pattern | TypeScript | Go |
|---------|-----------|-----|
| Auth code + PKCE | `client.exchangeCode(…)` | `client.ExchangeCode(ctx, …)` |
| Zero-network role check | `hearth.hasRole("admin")` | `client.HasRole(token, "admin")` |
| Zero-network permission check | `hearth.hasPermission("invoices.write")` | `client.HasPermission(token, "invoices.write")` |
| Group membership | `hearth.inGroup("engineering")` | `client.InGroup(token, "engineering")` |
| Live permission refresh | `hearth.client.permissions()` | `client.Permissions(ctx, token)` |
| Token refresh | `client.refreshTokens(clientId, refreshToken)` | `client.RefreshTokens(ctx, clientId, refreshToken)` |
| Admin API | `client.Admin(token).CreateUser(…)` | `admin.CreateUser(ctx, …)` |

:::note[PKCE is mandatory for public clients]
All public clients (browser SPAs, mobile apps) must use PKCE. Hearth rejects authorization requests without `code_challenge`. See each SDK quickstart for a copy-paste implementation.
:::

## Token verification without an SDK

If you prefer not to use an SDK wrapper, verify tokens directly against Hearth's JWKS endpoint:

```bash
# JWKS endpoint for your realm
GET /realms/<realm_id>/jwks
```

Hearth signs tokens with **Ed25519** (`alg: EdDSA`). Use any JWKS-aware library — `jose` (Node/TypeScript), `lestrrat-go/jwx` (Go), `python-jose` (Python), `Auth0/java-jwt` (JVM). See [§ Verify tokens on the server](./typescript.md#verify-tokens-on-the-server) in the TypeScript quickstart for a full example.

## Migrating from Keycloak?

The [SDK migration guide](./migration-from-keycloak.md) covers the concept mapping, Keycloak realm export + `hearth migrate keycloak` CLI, and side-by-side SDK swap (Keycloak JS Adapter → `@hearth-auth/sdk`, gocloak → Hearth Go SDK).

For the full operator migration (data directory layout, post-migration checklist, gap analysis), see [Migrating from Keycloak](/docs/migrating-from-keycloak).
