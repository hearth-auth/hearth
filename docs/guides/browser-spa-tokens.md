# Browser / SPA Token Handling

**Who this is for:** developers building browser-side Single Page Applications (SPAs) that receive OAuth tokens from Hearth and need to decide where to store them and how to protect them.

**DIATAXIS mode:** explanation. This page explains trade-offs — it does not walk through a step-by-step flow. For the PKCE authorization-code flow itself, see [Getting Started](getting-started.mdx).

---

## How Hearth delivers tokens to SPAs

All Hearth token endpoints (`/token`, `/realms/{name}/token`) return tokens in the JSON response body — the standard RFC 6749 format:

```json
{
  "access_token":  "eyJ...",
  "token_type":    "Bearer",
  "expires_in":    900,
  "refresh_token": "eyJ...",
  "id_token":      "eyJ..."
}
```

No `Set-Cookie` header is emitted. You receive the tokens and are responsible for how they are stored and transported.

---

## Token storage options

Every storage location in the browser involves a trade-off between **XSS risk** (can injected JavaScript read the token?) and **CSRF risk** (can a cross-origin page trigger a request that includes the token?):

| Location | XSS risk | CSRF risk | Verdict |
|---|---|---|---|
| `localStorage` | **High** — any injected script reads it | None | **Avoid** — persists across tabs and browser restarts, so a single XSS bug exposes the token until it is revoked. `createHearthAuth` uses it only when you set `storage: "localStorage"` |
| `sessionStorage` | **High** — same as localStorage within the tab | None | **Refresh token only, when there is no BFF** — scoped to one tab and cleared when it closes, but still readable by injected scripts. The `createHearthAuth` default for the refresh token, ID token and PKCE state |
| JavaScript variable (in-memory) | Low — injected script must be active in the same execution context | None | **OK for access tokens** — lost on page reload, short-lived by design |
| `HttpOnly` cookie (set by a BFF server) | None — JS cannot read `HttpOnly` cookies | Mitigated by `SameSite=Strict` | **Best for refresh tokens** — requires a server-side component |

**Rule of thumb:** access tokens are short-lived (default: 15 minutes in Hearth), so keeping them in memory is acceptable. Refresh tokens are long-lived credentials — treat them with the same care as passwords.

---

## Recommended SPA pattern: PKCE + in-memory access token

Use the PKCE Authorization Code flow (the TypeScript `createHearthAuth` browser facade wraps this for you). After the token exchange:

- **Access token**: keep in a module-scoped JavaScript variable. Never write it to `localStorage` or `sessionStorage`. On page reload, silently re-acquire it with the refresh token or a `prompt=none` silent redirect.
- **Refresh token**: keep it in `sessionStorage` (the `createHearthAuth` default), so the session survives a page reload and the login redirect while staying scoped to one tab. Hearth rotates refresh tokens on every use, so a copied token stops working the moment the legitimate client refreshes, and presenting a rotated-out token revokes the entire grant family and its session. Note what rotation does *not* buy you: if the thief redeems the stolen token before the legitimate client does, the thief gets the live chain and the legitimate client's next refresh is the presentation that trips detection. Rotation bounds the damage and guarantees you find out; it does not decide who wins the race.

The `createHearthAuth` browser facade from `@hearth-auth/sdk` implements this pattern and handles PKCE, token storage, scheduled silent refresh, and RP-initiated logout:

```ts
import { HearthApiClient, createHearthAuth } from '@hearth-auth/sdk';

const apiClient = new HearthApiClient({ baseUrl: 'https://auth.example.com', realmId: '<realm-id>' });

const auth = createHearthAuth(apiClient, {
  clientId:    '<client-id>',
  redirectUri: 'https://myapp.example.com/callback',
  hearthUrl:   'https://auth.example.com',
  realmSlug:   '<realm-name>',
});

// On login button click
await auth.startLogin();                         // redirects browser to Hearth login page

// In your /callback route handler
await auth.handleCallback(code, state);          // exchanges code, stores tokens, schedules refresh

// On API requests
const token = auth.getAccessToken();             // returns the in-memory access token (null if not logged in)

// On logout
await auth.logout();                             // clears tokens, redirects to Hearth end-session endpoint
```

`auth.getAccessToken()` returns the access token, which is held in memory only. `auth.getRefreshToken()` and `auth.getIdToken()` read the configured store: `sessionStorage` by default, under keys prefixed `hearth_` (`storageKeyPrefix` changes the prefix). The PKCE verifier and `state` of a login in flight are kept there too. `auth.isAuthenticated()` and `auth.clearTokens()` complete the set.

The `storage` option picks the store:

| `storage` | Behaviour |
|---|---|
| `"sessionStorage"` (default) | Scoped to one tab; cleared when the tab closes |
| `"localStorage"` | Survives the tab closing; shared by every tab of the origin |
| `"memory"` | Nothing is written to Web Storage. Lost on reload and does not survive the login redirect, so use it only with a flow that stays on the page |
| a `{ getItem, setItem, removeItem }` object | Your own store |

At creation, `createHearthAuth` removes `hearth_refresh_token` and `hearth_id_token` from `localStorage` unless `localStorage` is the configured store. If you want stricter XSS isolation, the BFF pattern below eliminates browser-side token storage entirely.

---

## Backend for Frontend (BFF) pattern

In the BFF pattern, your SPA delegates all token handling to a server-side component you own. The browser never receives OAuth tokens directly.

```
Browser SPA  ──POST /api/auth/callback──►  Your BFF server
                                            │
                                            ├─► POST /token to Hearth (gets access + refresh tokens)
                                            │   Stores refresh_token server-side (never sent to browser)
                                            │
             ◄── Set-Cookie: sid=...; HttpOnly; Secure; SameSite=Strict ──┘

Browser SPA  ──API requests (cookie auto-attached)──►  Your BFF server
                                                         │
                                                         └─► Forwards access token to backend API
```

Your BFF issues its own `HttpOnly; Secure; SameSite=Strict` session cookie. The access token exists only in your server's memory (or a short-lived server-side store). You are responsible for building and securing the BFF — Hearth's role is the authorization server only.

Use `SameSite=Strict` for your BFF cookie because the SPA and BFF share an origin; this prevents CSRF entirely without needing a CSRF token.

---

## What the Hearth admin UI uses internally

Hearth's built-in admin console (`/ui/*`) uses the same principles, implemented with two cookies:

| Cookie | Flags | Purpose |
|---|---|---|
| `hearth_ui_session` | `HttpOnly; Path=/ui; SameSite=Lax` | Binds session and realm; JS cannot read it |
| `hearth_ui_csrf` | `Path=/ui; SameSite=Lax` | JS-readable CSRF token; echoed on every mutation |

`SameSite=Lax` (not `Strict`) is deliberate: `Strict` would drop the cookie on the redirect back from the login page, breaking the flow. For your own BFF cookie, `SameSite=Strict` is safe because your SPA and BFF share an origin.

**These cookies are for the admin console only — they are not available to your OAuth clients.**

---

## Current implementation boundaries

Hearth does not offer a built-in mode that delivers `/token` responses as `HttpOnly` cookies. If you need Hearth to issue tokens directly into cookies, implement the BFF pattern in your own application server.

---

## Related guides

| Topic | Guide |
|---|---|
| First authenticated request (PKCE flow, SDK quickstart) | [Getting Started](getting-started.mdx) |
| Roles, groups, and the permissions claim | [RBAC guide](rbac.md) |
| Session revocation and silent refresh | [Session version revocation](session-version-revocation.md) |
