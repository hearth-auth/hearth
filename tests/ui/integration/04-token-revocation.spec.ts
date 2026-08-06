/**
 * Flow 4 — Token revocation propagates.
 *
 * After revoking the session/token at Hearth, the SPA must not silently keep a
 * working session, and Hearth's own control plane must reject the token.
 *
 * What the demo architecture actually enforces (verified end-to-end here):
 *   • Control plane — Hearth `/userinfo` rejects a revoked access token (401).
 *   • SPA plane     — on next load the SDK's silent refresh (App.tsx) fails
 *                     against the revoked refresh token, clears tokens, and the
 *                     user is bounced to the login screen.
 *
 * Resource-server revocation (HEA-2094, was a KNOWN GAP under HEA-2056): the Go
 * backend now layers RFC 7662 introspection on top of its JWKS signature check
 * (`middleware/revocation.go`), with a short-TTL cache so introspection is not a
 * per-request round-trip. A revoked-but-unexpired access token is therefore
 * refused at `/api/notes` (within the cache TTL). The third test below asserts
 * that behavior directly — the former `test.fail` annotation is gone.
 */

import { test, expect } from '@playwright/test';
import { EDITOR } from './config';
import { loginViaSpa, readStoredTokens } from './ui';
import { revokeToken, userinfoStatus, backendStatus } from './api';

test.describe('Flow 4 — token revocation propagates', () => {
  test('Hearth rejects a revoked access token at the control plane', async ({ page }) => {
    const { accessToken } = await loginViaSpa(page, EDITOR.email);

    // Live before revocation.
    expect(await userinfoStatus(accessToken)).toBe(200);

    // Revoke, then the same token is rejected by Hearth.
    expect(await revokeToken(accessToken)).toBe(200);
    expect(await userinfoStatus(accessToken)).toBe(401);
  });

  test('revoking the session logs the SPA out on next load', async ({ page }) => {
    await loginViaSpa(page, EDITOR.email);
    const stored = await readStoredTokens(page);
    expect(stored.refresh).toBeTruthy();

    // Revoke the refresh token that backs the SPA's silent session restore.
    expect(await revokeToken(stored.refresh as string)).toBe(200);

    // Reload — App.tsx tries to restore the session via refreshAccessToken();
    // with the refresh token revoked it fails, clears tokens, and shows Login.
    await page.reload();
    await expect(page.getByRole('button', { name: 'Sign in with Hearth' })).toBeVisible();
  });

  test('resource server rejects a revoked access token (introspection)', async ({ page }) => {
    // HEA-2094: the demo backend now layers RFC 7662 introspection on top of its
    // JWKS signature check (middleware/revocation.go), so a revoked-but-unexpired
    // access token is refused at /api/notes — no longer a KNOWN GAP.
    const { accessToken } = await loginViaSpa(page, EDITOR.email);

    // Live: the resource server accepts the token (and caches the "active"
    // introspection verdict for its short TTL).
    expect(await backendStatus(accessToken, '/api/notes')).toBe(200);

    // Revoke the access token at Hearth (kills the backing session).
    expect(await revokeToken(accessToken)).toBe(200);

    // The resource server introspects and rejects the revoked token. The backend
    // caches introspection verdicts for a short TTL (INTROSPECT_CACHE_TTL,
    // default 3s), so the previously-cached "active" verdict lingers until it
    // expires — this IS the latency/consistency tradeoff the cache buys. Poll
    // until the revocation propagates rather than asserting on the first request.
    await expect
      .poll(() => backendStatus(accessToken, '/api/notes'), {
        timeout: 15_000,
        intervals: [250, 500, 1000, 1000],
        message: 'resource server should reject the revoked token within the introspection cache TTL',
      })
      .toBe(401);
  });
});
