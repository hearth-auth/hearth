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
 * KNOWN GAP (HEA-2056 finding, encoded as `test.fail`): the Go resource server
 * (`middleware/auth.go`) validates the JWT signature only — it does NOT
 * introspect or check revocation — so a revoked-but-unexpired access token is
 * still accepted on `/api/notes`. That is a demo-app limitation, not a test bug;
 * fixing it requires editing demo backend source (introspection), which this
 * issue explicitly scopes out. The expected-fail test flips to a hard failure
 * the moment the backend starts enforcing revocation, prompting its removal.
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

  test('KNOWN GAP: resource server should reject a revoked access token', async ({ page }) => {
    // Expected-fail: demo backend does signature-only validation (no introspection).
    test.fail(true, 'demo Go backend validates signature only — no revocation check (HEA-2056 finding)');

    const { accessToken } = await loginViaSpa(page, EDITOR.email);
    expect(await backendStatus(accessToken, '/api/notes')).toBe(200); // warm: accepted while live
    expect(await revokeToken(accessToken)).toBe(200);

    // Desired behavior: the resource server rejects the revoked token.
    // Currently returns 200 (signature still valid) → this assertion fails →
    // the expected-fail annotation keeps the suite green while tracking the gap.
    expect(await backendStatus(accessToken, '/api/notes')).toBe(401);
  });
});
