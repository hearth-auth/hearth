---
title: SDKs
sidebar_label: Overview
description: Official Hearth client SDKs — TypeScript, Go, Python, and PHP.
---

# Hearth SDKs

Hearth ships four official client SDKs — TypeScript, Go, Python and PHP — for integrating authentication and RBAC into your application. Every SDK implements the same contract: **auth code + PKCE flow**, zero-network RBAC checks decoded from the JWT, transparent token refresh, and the Hearth Admin API.

## SDK catalogue

Registry status was checked on 2026-09-28. Not every SDK is installable from its registry, and
the published versions lag the source on `main` — check the registry before pinning a version.

| Language / Runtime | Package | Install | Registry status |
|--------------------|---------|---------|-----------------|
| [TypeScript (browser, React, Node.js, Next.js)](./typescript.md) | `@hearth-auth/sdk` | `npm install @hearth-auth/sdk` | npm — **1.6.2** |
| [Go](./go.mdx) | `github.com/hearth-auth/hearth/sdks/go` | `go get github.com/hearth-auth/hearth/sdks/go` | Go module proxy — **v1.6.11** |
| [Python](./python.mdx) | `hearth-sdk` | `pip install hearth-sdk` | PyPI — **1.6.8** |
| [PHP](./php.mdx) | `hearth-auth/php-sdk` | `composer require hearth-auth/php-sdk:dev-main` | Packagist — **`dev-main` only**; no tagged release, so `^1.0` does not resolve |

## One TypeScript package for browser and server

`@hearth-auth/sdk` covers both sides of a JavaScript app:

| Side | What you use |
|--|--|
| **Browser and React** | `startLogin()` / `createHearthAuth()` for PKCE, `HearthProvider` and `useHasPermission` hooks |
| **Node.js server** | `HearthClient` (`beginLogin`, `completeLogin`, `verifyToken`), Express `hearthMiddleware`, Fastify `hearthFastifyHook` |
| **Next.js** | `@hearth-auth/sdk/nextjs` (`withHearthAuth`, `getHearthClaims`) and `@hearth-auth/sdk/nextjs/edge` (`hearthEdgeMiddleware`) |

It needs Node.js 18 or later on the server. The former `@hearth-auth/node` package is
retired: its features are in `@hearth-auth/sdk`. See the
[TypeScript guide](./typescript.md#server-side-nodejs) and the
[Next.js guide](./typescript-nextjs.md).

## Common patterns

All SDKs expose the same surface (method names vary by language convention). See the [full symbol-name mapping table](https://github.com/hearth-auth/hearth/blob/main/openspec/specs/sdk-support-contract/spec.md) for a complete SDK-by-SDK reference, including platform exceptions.

| Pattern | TypeScript | Go | Python | PHP |
|---------|-----------|-----|--------|-----|
| Auth code + PKCE — begin | `startLogin()` (browser), `client.beginLogin()` (server) | `client.BeginLogin()` | `client.begin_login()` | `$client->beginLogin()` |
| Auth code + PKCE — complete | `client.completeLogin()` | `client.CompleteLogin()` | `client.complete_login()` | `$client->completeLogin()` |
| Verify token (EdDSA) | `client.verifyToken()` | `client.VerifyToken()` | `client.verify_token()` | `$client->verifyToken()` |
| Expected access-token audience (default `"hearth"`) | `new HearthClient({ audience })` | `hearth.WithAudience()` | `HearthClient(…, audience=…)` | `new HearthClient(…, audience: …)` |
| M2M (client credentials) | `client.clientCredentials()` | `client.ClientCredentials()` | `client.client_credentials()` | `$client->clientCredentials()` |
| Device flow — start | `client.startDeviceFlow()` | `client.StartDeviceFlow()` | `client.start_device_flow()` | `$client->startDeviceFlow()` |
| Device flow — poll | `client.pollDeviceToken()` | `client.PollDeviceToken()` ⚠ | `client.poll_device_token()` | `$client->pollDeviceToken()` |
| Magic-link initiation | `client.requestMagicLink()` | `client.RequestMagicLink()` | `client.request_magic_link()` | `$client->requestMagicLink()` |
| Role check (from verified claims) | `claims.hasRole()` | `claims.HasRole()` | `claims.hasRole()` | `$claims->hasRole()` |
| Permission check (from verified claims) | `claims.hasPermission()` | `claims.HasPermission()` | `claims.hasPermission()` | `$claims->hasPermission()` |
| Group check (from verified claims) | `claims.inGroup()` | `claims.InGroup()` | `claims.in_group()` | `$claims->inGroup()` |
| Check on a raw token (verifies it first) | `await hearth.hasPermission()` (`createHearth`) | `client.HasPermission(ctx, token, …)` | `client.has_permission(token, …)` | — |
| Token refresh | `client.refreshTokens()` | `client.RefreshTokens()` | `client.refresh_tokens()` | `$client->refreshToken()` |

> ⚠ marks a [platform exception](https://github.com/hearth-auth/hearth/blob/main/openspec/specs/sdk-support-contract/spec.md). Read the linked spec section before using these methods.

:::note[PKCE is mandatory for public clients]
All public clients (browser SPAs, mobile apps) must use PKCE. Hearth rejects authorization requests without `code_challenge`. Each SDK quickstart includes a copy-paste implementation.
:::

## Token verification without an SDK

Every GA SDK exposes `verifyToken()` (or the language-idiomatic equivalent — see the table above). Prefer `verifyToken()` over manual JWKS calls: it runs the six mandatory validation steps through a standard JOSE library with one 5 s clock-skew allowance, always checks `aud` against the configured audience (default `hearth`, the audience Hearth mints when a client names no resource; an API registered as a protected resource sets its resource URI; the client ID is not the audience), caches keys, re-fetches on rotation, and returns typed errors. A shared conformance harness (`make sdk-conformance`) proves all four SDKs give the same answer for the same token.

If you need to verify tokens from a language or framework that has no Hearth SDK, call the JWKS endpoint directly:

```bash
GET /realms/<realm>/.well-known/jwks.json
```

(The realm's discovery document, `/realms/<realm>/.well-known/openid-configuration`, names it as `jwks_uri`.)

Hearth signs every access token with **Ed25519** (`alg: EdDSA`, `kty: OKP`). Your parser **must** support OKP keys — parsers that only handle EC or RSA keys will fail to load Hearth's JWKS. Use a JOSE library with EdDSA support, as the SDKs do: `jose` (Node/TypeScript), `github.com/go-jose/go-jose/v4` (Go), `PyJWT[crypto]` (Python), `lcobucci/jwt` v5 (PHP). Allow `EdDSA` only, check `iss`, `aud` and `exp`, and do not write your own signature check.

The JWKS can also carry an `RSA` key with `alg: RS256`: it signs **ID tokens** only, for clients registered with `id_token_signed_response_alg: RS256` (the OpenID Connect default, and what Dynamic Client Registration gives a client that omits the parameter). The SDKs' `verifyToken` verifies access tokens and keeps refusing RS256 even though that key is published — an ID token must never pass as a bearer token.

## Migrating from Keycloak?

The [SDK migration guide](./migration-from-keycloak.md) covers concept mapping, the `hearth migrate keycloak` CLI, and side-by-side code comparisons for TypeScript and Go. For the full operator migration see [Migrating from Keycloak](/docs/migrating-from-keycloak).
