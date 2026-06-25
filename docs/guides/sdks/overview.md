---
title: SDKs
sidebar_label: Overview
description: Official Hearth client SDKs — TypeScript, Node.js, Go, Python, Rust, PHP, and Kotlin (coming soon).
---

# Hearth SDKs

Hearth ships official client SDKs for integrating authentication and RBAC into your application. Every GA SDK implements the same contract: **auth code + PKCE flow**, zero-network RBAC checks decoded from the JWT, transparent token refresh, and the Hearth Admin API.

## SDK catalogue

| Language / Runtime | Package | Install | Status |
|--------------------|---------|---------|--------|
| [TypeScript / React](./typescript.md) | `@hearth-auth/sdk` | `npm install @hearth-auth/sdk` | GA |
| [Node.js (server)](./node.md) | `@hearth-auth/node` | `npm install @hearth-auth/node` | GA |
| [Go](./go.md) | `github.com/hearth-auth/hearth/sdks/go` | `go get github.com/hearth-auth/hearth/sdks/go` | GA |
| [Python](./python.md) | `hearth-sdk` | `pip install hearth-sdk` | GA |
| [Rust](./rust.md) | `hearth-sdk` (git) | see [install instructions](./rust.md#install) | GA |
| [PHP](./php.md) | `hearth-auth/php-sdk` | `composer require hearth-auth/php-sdk:^1.0` | GA |
| Kotlin / JVM | `io.hearth-auth:hearth-sdk` | — | **Coming soon** |

:::note[Kotlin / JVM — not yet released]
The Kotlin SDK is under active development and will target JVM 17+, Ktor, and Spring WebFlux. No install instructions or standalone page are available until GA.
:::

## TypeScript vs Node.js — which should I use?

Both packages are published under `@hearth-auth/*` but serve different roles:

| | TypeScript (`@hearth-auth/sdk`) | Node.js (`@hearth-auth/node`) |
|--|--|--|
| **Use for** | Browser SPAs, React apps, Next.js | Node.js servers that verify incoming tokens |
| **PKCE flow** | ✓ — full authorization-code + PKCE | ✗ — resource-server only |
| **React hooks** | ✓ `useHasPermission`, `HearthProvider` | ✗ |
| **Middleware** | ✗ | ✓ Express, Fastify |
| **Min runtime** | Node 18 / any browser | Node 18 |

A typical full-stack setup uses **both**: the TypeScript SDK in the browser to run the PKCE flow and get tokens, and the Node.js SDK on the server to verify those tokens on every API request.

## Common patterns

All SDKs expose the same surface (method names vary by language convention):

| Pattern | TypeScript | Node.js | Go | Python | Rust | PHP |
|---------|-----------|---------|-----|--------|------|-----|
| Auth code + PKCE | `client.exchangeCode()` | — (resource-server) | `client.ExchangeCode()` | `client.exchange_code()` | `client.exchange_code()` | `$hearth->exchangeCode()` |
| Verify token | — | `client.verifyToken()` | JWKS + `jwt.Parse()` | `client.verify_token()` | `client.has_permission()` | `$hearth->verify()` |
| Role check (local) | `hearth.hasRole()` | `token.hasRole()` | `client.HasRole()` | `claims.has_role()` | `client.has_role()` | `$claims->hasRole()` |
| Permission check (local) | `hearth.hasPermission()` | `token.hasPermission()` | `client.HasPermission()` | `claims.has_permission()` | `client.has_permission()` | `$claims->hasPermission()` |
| Group check (local) | `hearth.inGroup()` | `token.inGroup()` | `client.InGroup()` | `claims.in_group()` | `client.in_group()` | `$claims->inGroup()` |
| Live permission refresh | `hearth.client.permissions()` | — | `client.Permissions()` | `client.check_permission()` | `client.check_permission()` | via introspect mode |
| Token refresh | `client.refreshTokens()` | — | `client.RefreshTokens()` | httpx + `/token` | `client.refresh_tokens()` | `$hearth->refreshTokens()` |

:::note[PKCE is mandatory for public clients]
All public clients (browser SPAs, mobile apps) must use PKCE. Hearth rejects authorization requests without `code_challenge`. Each SDK quickstart includes a copy-paste implementation.
:::

## Token verification without an SDK

If you prefer not to use an SDK, verify tokens directly against Hearth's JWKS endpoint using any JWKS-aware library:

```bash
GET /realms/<realm_id>/jwks
```

Hearth signs all tokens with **Ed25519** (`alg: EdDSA`). Compatible libraries: `jose` (Node/TypeScript), `lestrrat-go/jwx` (Go), `python-jose` (Python), `Auth0/java-jwt` (JVM). See [§ Verify tokens on the server](./typescript.md#verify-tokens-on-the-server) in the TypeScript quickstart for a full example.

## Migrating from Keycloak?

The [SDK migration guide](./migration-from-keycloak.md) covers concept mapping, the `hearth migrate keycloak` CLI, and side-by-side code comparisons for TypeScript and Go. For the full operator migration see [Migrating from Keycloak](/docs/migrating-from-keycloak).
