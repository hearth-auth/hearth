/**
 * Flow 5 — JWKS rotation mid-session.
 *
 * Hearth rotates the realm's Ed25519 signing key (old key enters a grace
 * period). The Go backend caches the JWKS and only re-fetches on a key-miss
 * (`middleware/auth.go`). After rotation the SPA obtains a token signed with the
 * NEW kid; the backend's cached keyset misses, triggers a single re-fetch, and
 * MUST recover (accept the new token) rather than hard-fail.
 *
 * This is the regression guard for the JWKS-cache re-fetch path: if a change
 * broke the re-fetch, the new-key token would 401 and this test would fail.
 */

import { test, expect } from '@playwright/test';
import { EDITOR } from './config';
import { loginViaSpa, captureTokenDuring } from './ui';
import { bootstrapAdmin, resolveDemoRealmId, rotateSigningKey, jwksKids, backendStatus } from './api';
import { decodeHeader } from './jwt';

test.describe('Flow 5 — JWKS rotation mid-session', () => {
  test('backend re-fetches JWKS and recovers after a signing-key rotation', async ({ page }) => {
    const { accessToken: oldToken } = await loginViaSpa(page, EDITOR.email);
    const oldKid = decodeHeader(oldToken)['kid'] as string;
    expect(oldKid).toBeTruthy();

    // Warm the backend's JWKS cache with the pre-rotation key.
    expect(await backendStatus(oldToken, '/api/notes')).toBe(200);
    const kidsBefore = await jwksKids();
    expect(kidsBefore).toContain(oldKid);

    // Rotate the realm signing key.
    const admin = await bootstrapAdmin();
    const demoRealmId = await resolveDemoRealmId(admin);
    await rotateSigningKey(admin, demoRealmId);

    // JWKS now advertises a new key id (the old one lingers during grace).
    const kidsAfter = await jwksKids();
    const newKids = kidsAfter.filter((k) => !kidsBefore.includes(k));
    expect(newKids.length).toBeGreaterThan(0);

    // Force the SPA to mint a token signed with the NEW key via silent refresh.
    const refreshed = await captureTokenDuring(page, async () => {
      await page.reload();
    });
    expect(refreshed).not.toBeNull();
    const newKid = decodeHeader((refreshed as { accessToken: string }).accessToken)['kid'] as string;
    expect(newKid).toBeTruthy();
    expect(newKid).not.toBe(oldKid);

    // The backend's cached keyset misses on newKid, re-fetches, and recovers.
    expect(await backendStatus((refreshed as { accessToken: string }).accessToken, '/api/notes')).toBe(200);

    // And the SPA is still authenticated after the rotation.
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  });
});
