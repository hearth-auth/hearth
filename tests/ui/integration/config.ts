/**
 * Shared coordinates for the reference-integration Playwright suite (HEA-2056).
 *
 * These tests drive the real `examples/full-stack-demo/` SPA against a real
 * Hearth + Go backend. The three tiers are booted by `run-integration.sh`
 * (which reuses the demo's own `demo.sh`), but every value here also has a
 * sensible default so a bare `--project=integration` run works against a stack
 * that is already up (e.g. one started manually via `demo.sh`).
 *
 * The demo realm id is NOT hard-coded — it is assigned at bootstrap time and
 * resolved dynamically via the admin API (see `api.ts#resolveDemoRealmId`).
 */

/** Hearth identity server. Use `localhost` (not 127.0.0.1) so the browser origin
 *  matches the issuer and the registered `localhost:5173/callback` redirect_uri. */
export const HEARTH_URL = process.env.HEARTH_URL ?? 'http://localhost:8420';

/** Vite dev server hosting the demo SPA. MUST be `localhost` — the OIDC client's
 *  registered redirect_uri is `http://localhost:5173/callback`; navigating via
 *  127.0.0.1 would make `window.location.origin` mismatch and fail redirect_uri
 *  validation. */
export const FRONTEND_URL = process.env.DEMO_FRONTEND_URL ?? 'http://localhost:5173';

/** Go resource server (the demo backend). The SPA calls it directly (no proxy),
 *  so its responses are interceptable in-page. */
export const BACKEND_URL = process.env.DEMO_BACKEND_URL ?? 'http://localhost:8421';

/** Realm slug configured in `examples/full-stack-demo/hearth.yaml`. */
export const REALM_SLUG = process.env.DEMO_REALM_SLUG ?? 'demo';

/** Public (PKCE) OAuth client id seeded by the demo config. */
export const CLIENT_ID =
  process.env.DEMO_CLIENT_ID ?? 'f7057d27-61fd-555e-b2af-ba8edd112237';

/** Seed users from `hearth.yaml` — all share this password. */
export const DEMO_PASSWORD = process.env.DEMO_PASSWORD ?? 'HearthTest123!';

export const VIEWER = { email: 'viewer@hearth.test', role: 'viewer' } as const;
export const EDITOR = { email: 'editor@hearth.test', role: 'editor' } as const;
export const ADMIN = { email: 'admin@hearth.test', role: 'admin' } as const;

/** The demo SPA's callback route (relative to FRONTEND_URL). */
export const CALLBACK_PATH = '/callback';
