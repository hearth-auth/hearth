/**
 * Flow 6 — Silent refresh keeps the SPA logged in.
 *
 * The SPA holds the access token in memory only; the refresh token persists in
 * localStorage. When the access token is gone (here: dropped by a page reload,
 * exactly as it would be when it expires), the SDK silently exchanges the
 * refresh token for a fresh access token (App.tsx restore path) and the user
 * stays authenticated without re-entering credentials.
 */

import { test, expect } from '@playwright/test';
import { EDITOR, FRONTEND_URL } from './config';
import { loginViaSpa, captureTokenDuring } from './ui';
import { decodeClaims } from './jwt';
import { userinfoStatus } from './api';

test.describe('Flow 6 — silent refresh at expiry', () => {
  test('SPA silently refreshes and stays logged in after losing its access token', async ({ page }) => {
    const first = await loginViaSpa(page, EDITOR.email);

    // Reload drops the in-memory access token (models expiry). App.tsx restores
    // the session by exchanging the stored refresh token for a new access token.
    const refreshed = await captureTokenDuring(page, async () => {
      await page.reload();
    });

    // A genuine refresh occurred and produced a NEW, live access token.
    expect(refreshed).not.toBeNull();
    const newToken = (refreshed as { accessToken: string }).accessToken;
    expect(newToken).toBeTruthy();
    expect(newToken).not.toBe(first.accessToken);
    expect(await userinfoStatus(newToken)).toBe(200);
    expect(decodeClaims(newToken)['sub']).toBeTruthy();

    // The user remains authenticated — Dashboard renders, no bounce to Login.
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();

    // And protected navigation continues to work post-refresh. Click the real
    // nav link rather than calling page.goto: a second full load would race the
    // SDK's localStorage write of the freshly rotated refresh token. Clicking
    // is also what a user actually does, and it exercises React Router.
    await page.getByRole('link', { name: 'Notes' }).click();
    await expect(page.getByRole('heading', { name: 'Notes' })).toBeVisible();
  });
});
