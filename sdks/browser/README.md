# @hearth/browser

Browser SDK for [Hearth](https://github.com/hearthauth/hearth) — PKCE authorization code flow, silent token refresh, and logout helpers.

## Server compatibility

| `@hearth/browser` | Minimum Hearth server |
|-------------------|-----------------------|
| 1.x               | 1.0.0                 |

Features used: OIDC discovery (`.well-known/openid-configuration`), authorization endpoint, token endpoint, end-session endpoint, RFC 7662 token introspection, JWKS endpoint.

## Install

```bash
npm install @hearth/browser
```

## Quick start

```ts
import { HearthClient } from "@hearth/browser";

const auth = new HearthClient({
  issuer: "https://your-hearth-instance.example.com",
  clientId: "my-spa",
  redirectUri: window.location.origin + "/callback",
  scopes: ["openid", "profile", "email"],
});

// Login — redirects to Hearth, then back to redirectUri
await auth.login();

// On your /callback page:
const tokens = await auth.handleCallback();
console.log(tokens.accessToken);

// Get tokens (auto-refreshes if near expiry)
const current = await auth.getTokens();

// Logout (clears session + RP-initiated logout)
await auth.logout({ redirectUri: window.location.origin });
```

## WebAuthn / passkeys

The SDK exports browser helpers for WebAuthn ceremonies. Your server generates the challenge/options and verifies the returned credential payload.

```ts
import { startRegistration, startAuthentication } from "@hearth/browser";

const registration = await startRegistration(registrationOptionsFromServer);
await fetch("/webauthn/register/finish", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(registration),
});

const authentication = await startAuthentication(authenticationOptionsFromServer);
await fetch("/webauthn/authenticate/finish", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(authentication),
});
```

## End-user account console APIs

`HearthClient` includes account-management methods that map directly to a self-service UI:

- `getProfile()` / `updateProfile(...)`
- `changePassword(...)`
- `listSessions()` / `revokeSession(sessionId)` / `revokeOtherSessions()`
- `listMfaDevices()` / `removeMfaDevice(deviceId)`
- `createDataExport()` / `getDataExport(exportId)` / `downloadDataExport(exportId)`

```ts
const auth = new HearthClient({
  issuer: "https://your-hearth-instance.example.com",
  clientId: "my-spa",
  redirectUri: window.location.origin + "/callback",
  // Optional: override paths if your deployment uses different routes
  accountApiBaseUrl: "https://your-hearth-instance.example.com",
  accountEndpoints: {
    profile: "/account/profile",
    sessions: "/account/sessions",
    mfaDevices: "/account/mfa/devices",
  },
});

const profile = await auth.getProfile();
await auth.updateProfile({ givenName: "Ada", familyName: "Lovelace" });
await auth.changePassword({ currentPassword: "old", newPassword: "new" });
const sessions = await auth.listSessions();
if (sessions.length > 1) await auth.revokeOtherSessions();
```

### Route helper for account console UIs

Use `createAccountConsoleRoute` to wire route loaders and action handlers without duplicating API glue:

```ts
import { HearthClient, createAccountConsoleRoute } from "@hearth/browser";

const auth = new HearthClient({
  issuer: "https://your-hearth-instance.example.com",
  clientId: "my-spa",
  redirectUri: window.location.origin + "/callback",
});

const accountRoute = createAccountConsoleRoute(auth);

// Example route loader
const data = await accountRoute.load();
// data.profile, data.sessions, data.mfaDevices

// Example action handlers
await accountRoute.actions.updateProfile({ givenName: "Ada" });
await accountRoute.actions.changePassword({
  currentPassword: "old-password",
  newPassword: "new-password",
});
await accountRoute.actions.revokeOtherSessions();
```

## Token storage

Tokens default to `sessionStorage`. To use in-memory storage (e.g. for iframes):

```ts
import { HearthClient, memoryStorageAdapter } from "@hearth/browser";

const auth = new HearthClient({
  issuer: "...",
  clientId: "...",
  redirectUri: "...",
  storage: memoryStorageAdapter(),
});
```

## API

### `new HearthClient(config)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `issuer` | `string` | required | Hearth server base URL |
| `clientId` | `string` | required | OAuth 2.0 client ID |
| `redirectUri` | `string` | required | Callback URL registered on the client |
| `scopes` | `string[]` | `["openid","profile","email"]` | OAuth scopes |
| `storage` | `TokenStorage` | `sessionStorageAdapter` | Token persistence adapter |
| `accountApiBaseUrl` | `string` | `issuer` | Base URL for self-service account APIs |
| `accountEndpoints` | `Partial<AccountEndpoints>` | built-in defaults | Override account endpoint templates |
| `onTokenChange` | `(tokens \| null) => void` | no-op | Called on token update or logout |

### Methods

- `login()` — redirect to authorization endpoint with PKCE challenge
- `handleCallback(url?)` — exchange authorization code for tokens
- `getTokens()` — return current tokens, refreshing if within 60s of expiry
- `refresh()` — force token refresh using refresh_token
- `logout(options?)` — clear session and redirect to end_session_endpoint
- `getIdTokenClaims()` — decode ID token payload (client-side only, no verification)
- `getDiscovery()` — fetch/return cached OIDC discovery document
- `getProfile()` / `updateProfile(payload)` — read and update end-user profile
- `changePassword(payload)` — rotate end-user password
- `listSessions()` / `revokeSession(sessionId)` / `revokeOtherSessions()` — session management
- `listMfaDevices()` / `removeMfaDevice(deviceId)` — MFA device management
- `createDataExport()` / `getDataExport(exportId)` / `downloadDataExport(exportId)` — user data export
- `createAccountConsoleRoute(client)` — route loader/actions wrapper for account console UIs
- `startRegistration(options, signal?)` — WebAuthn registration helper returning JSON-safe credential data
- `startAuthentication(options, signal?)` — WebAuthn authentication helper returning JSON-safe credential data

## Security notes

- PKCE `code_verifier` is generated using `crypto.getRandomValues` (32 bytes, ~256 bits entropy)
- `code_challenge` uses SHA-256 (`S256` method per RFC 7636)
- State parameter is validated on callback to prevent CSRF
- ID token claims decoded client-side are **not cryptographically verified** — always verify tokens server-side for authorization decisions

## Troubleshooting

### Login redirect does not return / callback fails

- Confirm `redirectUri` exactly matches the URI registered for this client on the Hearth server (case-sensitive, including trailing slash)
- Check that the Hearth server is reachable from the browser network (no CORS or DNS issues)
- Inspect the browser's network tab for the authorization redirect — the `error` query param on the redirect-back URL often contains the exact rejection reason

### `DiscoveryError: OIDC discovery failed`

Auto-discovery fetches `{issuer_url}/.well-known/openid-configuration` on first use. Check that:
- `issuer_url` does not include a trailing path (use `https://auth.example.com`, not `https://auth.example.com/oauth`)
- CORS headers on the Hearth server allow the browser origin making the request
- The Hearth server version is ≥ 1.0.0

### `TokenExpiredError` during `getTokens()` or `silentRefresh()`

The access token expired and the refresh token is also expired (or absent). The user must re-authenticate:
```ts
try {
  const tokens = await auth.getTokens();
} catch (e) {
  if (e instanceof TokenExpiredError) await auth.login();
}
```

### `TokenVerificationError: No matching key found in JWKS`

The JWKS key used to sign the token is not in the current local cache. Key rotation is likely. The SDK re-fetches JWKS on the next `verifyToken()` call automatically. If the error persists after one retry, confirm the Hearth server is serving up-to-date JWKS.

### `TokenClaimsError: iss mismatch` / `aud mismatch`

- **`iss`**: Token `iss` does not equal `issuer_url`. Ensure you're targeting the correct Hearth instance.
- **`aud`**: Token `aud` does not include `client_id`. Confirm the Hearth client is configured to issue tokens with the expected audience.

### Tokens not persisted across page loads

The default storage is `sessionStorage`, which is cleared when the browser tab closes. To persist across tabs and reloads use `localStorage`:
```ts
import { HearthClient, localStorageAdapter } from "@hearth/browser";
const auth = new HearthClient({ ..., storage: localStorageAdapter() });
```
Note: `localStorage` tokens are readable by any same-origin JavaScript. Only use this if your app has no XSS risk.

### Cross-tab token sync not working

`BroadcastChannel` is used for cross-tab sync. It requires pages to share the same origin. If you're testing on `file://` URLs or different ports, `BroadcastChannel` will not fire — use a proper dev server.

### `IntrospectionError: Introspection request failed`

Introspection calls from the browser require the Hearth server to allow CORS from your origin. Confirm:
- `client_id` has introspection enabled in its Hearth configuration
- The Hearth server CORS policy includes your browser origin
