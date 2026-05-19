# Getting started with Hearth

Hearth is an OAuth 2.0 / OpenID Connect authorization server. This guide walks through integrating Hearth into a new or existing application.

## 1. Prerequisites

- A running Hearth instance (self-hosted or managed)
- An OAuth client registered in the Hearth admin console
- Your `issuer URL` (e.g. `https://auth.example.com`)

## 2. Install the SDK

**Go**
```bash
go get github.com/hearthauth/hearth-go/pkg
```

**Node.js / TypeScript**
```bash
npm install @hearth/node
```

**Python**
```bash
pip install hearth
```

**Browser SPA** (PKCE flows and silent token refresh)
```bash
npm install @hearth/browser
```

## 3. Register your client

In the Hearth admin console, create a client with:

| Setting | Server-side app | Browser SPA |
|---------|----------------|-------------|
| Client type | `confidential` | `public` |
| Grant type | `authorization_code`, `client_credentials` | `authorization_code` with PKCE |
| Redirect URIs | Your callback route | Your SPA origin + callback path |

For SPAs, Hearth automatically enforces PKCE (`code_challenge_method: S256`). The client secret is not issued.

## 4. Protect an API route

The Hearth server SDKs verify JWTs from `Authorization: Bearer <token>` headers. All tokens are delivered as JSON by Hearth's `/oauth/token` endpoint (RFC 6749 compliant) and presented to your API as Bearer tokens.

**Go (net/http)**
```go
import hearth "github.com/hearthauth/hearth-go/pkg"

client := hearth.NewClient(hearth.Config{
    Issuer:   "https://auth.example.com",
    Audience: "my-api",
})

mux.Handle("GET /api/me", client.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    token, _ := hearth.TokenFromContext(r.Context())
    // use token.Subject(), token.PrivateClaims(), etc.
})))
```

**Node.js (Express)**
```ts
import { hearthMiddleware } from "@hearth/node";

app.use(hearthMiddleware({
    issuer: "https://auth.example.com",
    audience: "my-api",
}));

app.get("/api/me", (req, res) => {
    res.json({ sub: req.auth?.sub });
});
```

## 5. Check roles and permissions

Hearth embeds roles and permissions in the JWT payload. Read them from the verified token:

```go
// Go
claims := token.PrivateClaims()
roles, _ := claims["roles"].([]interface{})
```

```ts
// Node.js
const roles = (req.auth?.roles as string[]) ?? [];
const canWrite = roles.includes("editor");
```

## 6. Token refresh

Access tokens are short-lived (default: 15 minutes). Use refresh tokens to maintain sessions without re-prompting the user.

**Browser SPA** — use `@hearth/browser` which handles silent refresh automatically:

```ts
import { createHearthClient } from "@hearth/browser";

const hearth = createHearthClient({
    issuer: "https://auth.example.com",
    clientId: "my-spa",
    redirectUri: `${location.origin}/callback`,
});

// Login redirects to Hearth and back
await hearth.loginWithRedirect();

// Access token, refreshed automatically on expiry
const token = await hearth.getAccessToken();
```

**Server-side apps** — call the token endpoint directly:

```bash
curl -X POST https://auth.example.com/oauth/token \
  -d grant_type=refresh_token \
  -d refresh_token=<refresh_token> \
  -d client_id=<client_id> \
  -d client_secret=<client_secret>
```

## 7. Token delivery for browser SPAs

### How Hearth delivers tokens

Hearth's `/oauth/token` endpoint delivers all tokens (access, refresh, ID) in a **JSON response body** per RFC 6749:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "oqMBuqmSe7GUV8...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

By default Hearth uses JSON delivery. Optionally, you can configure a client to use **native cookie delivery** — Hearth then sets the access and refresh tokens as HttpOnly cookies directly on the `/oauth/token` response, so the tokens never touch JavaScript memory.

### Where to store tokens in a browser SPA

Choosing a storage location is a security decision with real tradeoffs:

| Storage | XSS risk | CSRF risk | Persistence | Notes |
|---------|----------|-----------|-------------|-------|
| `localStorage` | **High** — any script on the page can read it | None | Tab + across sessions | Not recommended for access tokens |
| `sessionStorage` | **High** — same as above | None | Tab only | Slightly better than localStorage; still JS-accessible |
| In-memory (closure/variable) | **Low** — lost on page refresh | None | Current page load only | **Recommended** for bearer-mode SPAs |
| HttpOnly cookie (native, `token_delivery: cookie`) | **None** — inaccessible to JavaScript | Low (mitigated by `SameSite=Strict`) | Configurable | **Recommended** for highest XSS protection |
| HttpOnly cookie (via BFF) | **None** | Low (mitigated by `SameSite`) | Configurable | Alternative: own server proxies token exchange |

### Recommended pattern for SPAs: PKCE + in-memory

For most SPAs, the recommended approach is:

1. Perform the OAuth authorization code + PKCE flow using `@hearth/browser`
2. Store the **access token in memory only** (never in `localStorage`)
3. Store the **refresh token in an HttpOnly cookie** (set by your server or the `@hearth/browser` silent refresh mechanism)
4. On page reload, use the refresh token to silently re-acquire an access token

`@hearth/browser` implements this pattern out of the box:

```ts
const hearth = createHearthClient({
    issuer: "https://auth.example.com",
    clientId: "my-spa",
    redirectUri: `${location.origin}/callback`,
    // Access tokens are held in memory automatically; no localStorage
});
```

### Advanced: Backend-For-Frontend (BFF) pattern

For applications with the strictest XSS requirements, the BFF pattern eliminates token storage in the browser entirely:

```
Browser SPA
    │  browser-session cookie (HttpOnly, Secure, SameSite=Strict)
    ▼
BFF Server (your domain, e.g. api.example.com)
    │  exchanges cookie for bearer token internally
    │  Authorization: Bearer <access_token>
    ▼
Resource API (Hearth-protected)
```

In this pattern:
- The BFF performs the OAuth authorization code + PKCE flow on behalf of the SPA
- The BFF receives the JSON token response from Hearth
- The BFF issues an **HttpOnly; Secure; SameSite=Strict** session cookie to the browser
- All API calls go through the BFF, which injects the bearer token server-side
- The browser JavaScript never sees any OAuth token

Cookie flags to use in the BFF:

```
Set-Cookie: session=<session_id>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
```

| Flag | Purpose |
|------|---------|
| `HttpOnly` | Blocks JavaScript access — the primary XSS defense |
| `Secure` | Transmit only over HTTPS |
| `SameSite=Strict` | Blocks cross-site request forgery for state-changing actions |
| `Path=/` | Scope cookie to your entire domain |

### Admin console cookie behavior

The Hearth admin UI (`/ui/*`) uses its own session cookies for the built-in admin console:

- `hearth_ui_session`: `HttpOnly; SameSite=Lax` — admin session token
- `hearth_ui_csrf`: CSRF double-submit cookie

These cookies are scoped to the admin console only and are **not available to OAuth clients or third-party SPAs**. The `SameSite=Lax` setting (rather than `Strict`) is intentional — it allows the admin console to receive cookies after a top-level navigation redirect from Hearth's own OAuth flow, which `Strict` would block.

### Native HttpOnly cookie delivery (`token_delivery: cookie`)

Hearth supports delivering access and refresh tokens as HttpOnly cookies directly from the `/oauth/token` endpoint. The cookie name is `hearth_access_token`. This eliminates JavaScript token storage entirely without requiring a BFF proxy.

**1. Server configuration** — set `token_delivery: cookie` on the OAuth client in `hearth.yaml`:

```yaml
clients:
  - client_id: my-spa
    client_type: public
    token_delivery: cookie   # 'bearer' (default) or 'cookie'
    token_cookie_flags:
      secure: true
      same_site: Strict
      max_age: 3600
```

**2. Browser SDK** — pass `token_delivery: "cookie"` to `createHearthClient`. The SDK stores only session metadata (expiry and ID token claims) — no access or refresh token is held in JS:

```ts
import { createHearthClient } from "@hearth/browser";

const hearth = createHearthClient({
    issuer_url: "https://auth.example.com",
    client_id: "my-spa",
    redirect_uri: `${location.origin}/callback`,
    token_delivery: "cookie",   // tokens arrive as HttpOnly cookies
});

await hearth.loginWithRedirect();
// Silent refresh works without a JS-accessible refresh token —
// the browser sends the HttpOnly refresh cookie automatically.
const token = await hearth.getAccessToken();
```

**3. Resource server (Node.js)** — enable `acceptCookieToken` so the middleware accepts the `hearth_access_token` cookie when no `Authorization: Bearer` header is present:

```ts
import { hearthMiddleware } from "@hearth/node";

app.use(hearthMiddleware({
    issuer: "https://auth.example.com",
    audience: "my-api",
    acceptCookieToken: true,  // fallback to hearth_access_token cookie
}));
```

**3. Resource server (Go)** — use `MiddlewareWithOptions` with `AcceptCookieToken: true`:

```go
mux.Handle("GET /api/me", client.MiddlewareWithOptions(
    http.HandlerFunc(myHandler),
    hearth.MiddlewareOptions{AcceptCookieToken: true},
))
```

`Authorization: Bearer` always takes priority over the cookie, so server-to-server calls using bearer tokens continue to work without any change.

**Cookie flags set by Hearth in cookie mode:**

| Flag | Value | Purpose |
|------|-------|---------|
| `HttpOnly` | always | Blocks JavaScript access |
| `Secure` | configurable (default: `true`) | HTTPS only |
| `SameSite` | configurable (default: `Strict`) | CSRF protection |
| `Path` | `/` | Scoped to entire origin |
| `Max-Age` | configurable | Session lifetime |

## 8. Webhook verification

Hearth sends signed webhook events for user and session lifecycle. Verify signatures before processing:

```go
// Go
verifier := hearth.NewWebhookVerifier(hearth.WebhookVerifierConfig{
    Secret: os.Getenv("HEARTH_WEBHOOK_SECRET"),
})

body, _ := io.ReadAll(r.Body)
_, err := verifier.Verify(body, r.Header, time.Now())
```

```ts
// Node.js
import { WebhookVerifier } from "@hearth/node";
const verifier = new WebhookVerifier({ secret: process.env.HEARTH_WEBHOOK_SECRET! });
verifier.verify(rawBody, req.headers);
```

## 9. Observability

Each SDK ships observability helpers that expose Prometheus metrics and health endpoints:

```go
// Go
obs := hearth.NewHearthObservability(
    hearth.ReadinessCheck(func() hearth.ReadinessCheckResult {
        return hearth.ReadinessCheckResult{Name: "db", OK: true}
    }),
)
http.HandleFunc("/metrics", obs.MetricsHandler())
http.HandleFunc("/healthz", obs.HealthzHandler())
```

See the SDK-specific READMEs for full observability API documentation.

## Next steps

- [Go SDK reference](../../sdks/go/README.md)
- [Node.js SDK reference](../../sdks/node/README.md)
- [Python SDK reference](../../sdks/python/README.md)
- [Browser SDK reference](../../sdks/browser/README.md)
- [DPoP sender-constraint assessment](../spikes/HEA-520-dpop-assessment.md)
