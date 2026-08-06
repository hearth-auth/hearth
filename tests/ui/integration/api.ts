/**
 * Server-side control-plane helpers for the integration suite (HEA-2056).
 *
 * These talk to Hearth's admin + OAuth APIs directly (no browser) to set up
 * and perturb state: resolve the demo realm id, revoke tokens, rotate the
 * realm signing key, and probe userinfo / the resource server. They are the
 * "attacker/operator" side of each flow — the SPA is the system under test's
 * client.
 */

import { HEARTH_URL, BACKEND_URL, REALM_SLUG, CLIENT_ID } from './config';

export interface AdminSession {
  token: string;
  /** System realm id — required as `X-Realm-ID` on admin API calls. */
  systemRealmId: string;
}

/** Returns an admin session for use by control-plane helpers.
 *
 *  When the stack was booted by run-integration.sh the admin token is available
 *  as HEARTH_ADMIN_TOKEN / HEARTH_SYSTEM_REALM_ID (written by demo.sh after its
 *  first-call bootstrap).  Those env vars are consumed here directly so this
 *  function never re-calls POST /admin/bootstrap — which would 401 because the
 *  realm already exists after demo.sh ran.
 *
 *  Without those env vars (standalone test run against a fresh instance) the
 *  unauthenticated bootstrap call is valid only on the very first call. */
export async function bootstrapAdmin(): Promise<AdminSession> {
  const envToken = process.env['HEARTH_ADMIN_TOKEN'];
  const envRealmId = process.env['HEARTH_SYSTEM_REALM_ID'];
  if (envToken && envRealmId) {
    return { token: envToken, systemRealmId: envRealmId };
  }
  const resp = await fetch(`${HEARTH_URL}/admin/bootstrap`, { method: 'POST' });
  if (!resp.ok) throw new Error(`bootstrap failed: HTTP ${resp.status}`);
  const body = (await resp.json()) as { access_token: string; realm_id: string };
  return { token: body.access_token, systemRealmId: body.realm_id };
}

/** Resolves the demo realm's UUID via the admin realms list. */
export async function resolveDemoRealmId(admin: AdminSession): Promise<string> {
  const resp = await fetch(`${HEARTH_URL}/admin/realms`, {
    headers: {
      Authorization: `Bearer ${admin.token}`,
      'X-Realm-ID': admin.systemRealmId,
    },
  });
  if (!resp.ok) throw new Error(`list realms failed: HTTP ${resp.status}`);
  const body = (await resp.json()) as { items: Array<{ id: string; name: string }> };
  const demo = body.items.find((r) => r.name === REALM_SLUG);
  if (!demo) throw new Error(`demo realm "${REALM_SLUG}" not found in ${JSON.stringify(body.items.map((r) => r.name))}`);
  return demo.id;
}

/** Revokes a token via the realm's RFC 7009 revocation endpoint. The public
 *  client authenticates with just its `client_id`. Returns the HTTP status. */
export async function revokeToken(token: string): Promise<number> {
  const resp = await fetch(`${HEARTH_URL}/realms/${REALM_SLUG}/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, client_id: CLIENT_ID }),
  });
  return resp.status;
}

/** Calls the realm userinfo endpoint with a bearer token. Returns the status —
 *  200 for a live token, 401 once revoked. Hearth enforces revocation here;
 *  this is the control-plane assertion for flow 4. */
export async function userinfoStatus(token: string): Promise<number> {
  const resp = await fetch(`${HEARTH_URL}/realms/${REALM_SLUG}/userinfo`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return resp.status;
}

/** Returns the set of key ids currently published in the realm JWKS. */
export async function jwksKids(): Promise<string[]> {
  const resp = await fetch(`${HEARTH_URL}/realms/${REALM_SLUG}/.well-known/jwks.json`);
  if (!resp.ok) throw new Error(`jwks fetch failed: HTTP ${resp.status}`);
  const body = (await resp.json()) as { keys: Array<{ kid: string }> };
  return body.keys.map((k) => k.kid);
}

/** Rotates the demo realm's Ed25519 signing key via the admin API. The old key
 *  stays valid during the config grace period; new tokens are signed with a new
 *  kid, forcing the backend's JWKS cache to miss and re-fetch (flow 5). */
export async function rotateSigningKey(admin: AdminSession, demoRealmId: string): Promise<void> {
  const resp = await fetch(`${HEARTH_URL}/admin/realms/${demoRealmId}/rotate-signing-key`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${admin.token}`,
      'X-Realm-ID': demoRealmId,
    },
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`rotate-signing-key failed: HTTP ${resp.status} ${text}`);
  }
}

/** Calls the Go resource server with a bearer token. Returns the HTTP status.
 *  `path` defaults to a route any authenticated user may hit (`/api/notes`). */
export async function backendStatus(token: string | null, path = '/api/notes'): Promise<number> {
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const resp = await fetch(`${BACKEND_URL}${path}`, { headers });
  return resp.status;
}
