## Context

`routes()` and `realm_routes()` in `src/protocol/http/oauth.rs` serve discovery, the JWKS and the protected-resource metadata. Hearth has no global CORS layer. Only `/token` answers CORS, with an origin allowlist per client (`cors_origins`), because it takes a POST from a browser.

The TypeScript SDK fetches discovery and the JWKS with plain `fetch(url)`: a GET with no custom header. That is a CORS "simple request", so the browser sends no preflight and needs only `Access-Control-Allow-Origin` on the response.

## Goals / Non-Goals

**Goals:**
- A page on any origin can read the discovery document, the JWKS and the protected-resource metadata.

**Non-Goals:**
- CORS for `/userinfo`, `/introspect` or other endpoints that take a credential.
- A preflight (`OPTIONS`) answer on the metadata routes: the SDK sends simple requests only.
- The A2A agent card (`/.well-known/agent.json`).

## Decisions

1. **`*`, not a reflected origin or an allowlist.** The documents are public, the same for every caller, and read without credentials. `*` with no `Access-Control-Allow-Credentials` lets no page send cookies or read anything that depends on them (Fetch: a credentialed request fails against `*`). An allowlist would make a realm list every SPA origin to let it read a public key. OpenID providers such as Keycloak, Auth0 and Okta send `*` on these documents.
2. **A route layer on the metadata routes only.** `axum::middleware::map_response` adds the header on those routes, so a new route does not get it by accident. The layer covers every response of those routes, including an unknown realm's `404`, so a page can read the error too.
3. **No `Vary: Origin`.** The response does not depend on `Origin`.

## Risks / Trade-offs

- [A page on any origin reads the realm's public keys and endpoints] → Anyone can already read them with any HTTP client; CORS only protects data that depends on the browser's credentials.
