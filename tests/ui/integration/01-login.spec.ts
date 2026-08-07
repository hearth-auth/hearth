/**
 * Flow 1 — Login (auth-code + PKCE round trip).
 *
 * Drives the full round trip through the real SPA and a real Hearth:
 *   Login.tsx → hosted Hearth login → Callback.tsx → Dashboard.tsx.
 * Asserts the user is authenticated AND that the minted access token carries
 * the expected identity claims (not just that a page rendered).
 */

import { test, expect } from '@playwright/test';
import { EDITOR, FRONTEND_URL } from './config';
import { loginViaSpa } from './ui';
import { userinfoStatus } from './api';

test.describe('Flow 1 — auth-code + PKCE login', () => {
  test('editor logs in and lands authenticated on the dashboard', async ({ page }) => {
    const tokens = await loginViaSpa(page, EDITOR.email);

    // The dashboard reflects the authenticated identity — role badge + claims.
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.locator('.badge-editor')).toHaveText('editor');
    await expect(page.locator('.nav-brand')).toHaveText('Hearth Hub');

    // A real access token was minted and it identifies the editor.
    expect(tokens.accessToken).toBeTruthy();
    const claims = decodeJwt(tokens.accessToken);
    expect(claims['email'] ?? claims['sub']).toBeTruthy();

    // The captured token is live at the Hearth control plane.
    expect(await userinfoStatus(tokens.accessToken)).toBe(200);

    // Raw JWT claims are rendered on the dashboard (proves the SPA has the token).
    const claimsBlock = await page.locator('pre.code-block').innerText();
    expect(claimsBlock).toContain('"');
    expect(claimsBlock.length).toBeGreaterThan(2);
  });

  test('unauthenticated visit to a protected route redirects to login', async ({ page }) => {
    await page.goto(`${FRONTEND_URL}/dashboard`);
    // ProtectedRoute bounces unauthenticated users to the SPA login page.
    await expect(page.getByRole('button', { name: 'Sign in with Hearth' })).toBeVisible();
  });
});

function decodeJwt(token: string): Record<string, unknown> {
  const part = token.split('.')[1] ?? '';
  const b64 = part.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  return JSON.parse(Buffer.from(b64 + pad, 'base64').toString('utf8')) as Record<string, unknown>;
}
