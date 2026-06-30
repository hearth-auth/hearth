---
title: SDKs
sidebar_label: Overview
description: Official Hearth client SDKs — TypeScript, Node.js, Go, Python, Rust, PHP, and Kotlin.
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
| [Kotlin / JVM](./kotlin.md) | `io.hearth-auth:hearth-sdk` | see [install instructions](./kotlin.md#install) | GA |

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

All SDKs expose the same surface (method names vary by language convention). See the [full symbol-name mapping table](../../specs/SDK.md#25-per-sdk-symbol-name-mapping) for a complete SDK-by-SDK reference, including platform exceptions.

| Pattern | TypeScript | Node.js | Go | Python | Rust | PHP | Kotlin |
|---------|-----------|---------|-----|--------|------|-----|--------|
| Auth code + PKCE — begin | `startLogin()` | `client.beginLogin()` | `client.BeginLogin()` | `client.begin_login()` | `client.begin_login().await` | `$client->beginLogin()` | `client.beginLogin()` |
| Auth code + PKCE — complete | — (browser flow) | `client.completeLogin()` | `client.CompleteLogin()` | `client.complete_login()` | `client.complete_login().await` | `$client->completeLogin()` | `client.completeLogin()` |
| Verify token (EdDSA) | `client.verifyToken()` | `client.verifyToken()` | `client.VerifyToken()` | `client.verify_token()` | `client.verify_token().await` | `$client->verifyToken()` | `client.verifyToken()` |
| M2M (client credentials) | `client.clientCredentials()` | `client.clientCredentials()` | `client.ClientCredentials()` | `client.client_credentials()` | `client.client_credentials().await` | `$client->clientCredentials()` | `client.clientCredentials()` |
| Device flow — start | `client.startDeviceFlow()` | `client.startDeviceFlow()` | `client.StartDeviceFlow()` | `client.start_device_flow()` | `client.start_device_flow().await` | `$client->startDeviceFlow()` | `client.deviceAuthorization()` ⚠ |
| Device flow — poll | `client.pollDeviceToken()` | `client.pollDeviceToken()` | `client.PollDeviceToken()` ⚠ | `client.poll_device_token()` | `client.poll_device_token().await` | `$client->pollDeviceToken()` | `client.pollDeviceToken()` ⚠ |
| Magic-link initiation | `client.requestMagicLink()` | `client.requestMagicLink()` | `client.RequestMagicLink()` | `client.request_magic_link()` | `client.initiate_magic_link().await` ⚠ | `$client->requestMagicLink()` | — ⚠ |
| Role check (local) | `claims.hasRole()` | `token.hasRole()` | `client.HasRole()` | `claims.has_role()` | `HearthClient::has_role()` | `$claims->hasRole()` | `client.hasRole()` |
| Permission check (local) | `claims.hasPermission()` | `token.hasPermission()` | `client.HasPermission()` | `claims.has_permission()` | `HearthClient::has_permission()` | `$claims->hasPermission()` | `client.hasPermission()` |
| Group check (local) | `claims.inGroup()` | `token.inGroup()` | `client.InGroup()` | `claims.in_group()` | `HearthClient::in_group()` | `$claims->inGroup()` | `client.hasRole()` → `inGroup` |
| Token refresh | `client.refreshTokens()` | — | `client.RefreshTokens()` | `client.refresh_tokens()` | `client.refresh_tokens().await` | `$client->refreshToken()` | `client.refreshTokens()` |

> ⚠ marks a [platform exception](../../specs/SDK.md#platform-exceptions). Read the linked spec section before using these methods.

:::note[PKCE is mandatory for public clients]
All public clients (browser SPAs, mobile apps) must use PKCE. Hearth rejects authorization requests without `code_challenge`. Each SDK quickstart includes a copy-paste implementation.
:::

## Token verification without an SDK

Every GA SDK exposes `verifyToken()` (or the language-idiomatic equivalent — see the table above). Prefer `verifyToken()` over manual JWKS calls: it performs all five mandatory validation steps in the correct order, caches keys, re-fetches on rotation, and returns typed errors.

If you need to verify tokens from a language or framework that has no Hearth SDK, call the JWKS endpoint directly:

```bash
GET /realms/<realm_id>/jwks
```

Hearth signs all tokens with **Ed25519** (`alg: EdDSA`, `kty: OKP`). Your parser **must** support OKP keys — parsers that only handle EC or RSA keys will fail to load Hearth's JWKS. Compatible JWKS libraries: `jose` (Node/TypeScript), `lestrrat-go/jwx` (Go), `python-jose` (Python), `Auth0/java-jwt` (JVM).

## Migrating from Keycloak?

The [SDK migration guide](./migration-from-keycloak.md) covers concept mapping, the `hearth migrate keycloak` CLI, and side-by-side code comparisons for TypeScript and Go. For the full operator migration see [Migrating from Keycloak](/docs/migrating-from-keycloak).
