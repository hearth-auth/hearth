/**
 * Flow 3 — Permission enforcement on BOTH planes.
 *
 * A non-admin (viewer) must be denied admin capability in two independent
 * places, and the test asserts both — UI hiding alone is NOT enforcement:
 *
 *   (a) UI plane   — the `Admin` nav link (RoleGate / isAdmin) is absent, and
 *                    navigating straight to `/admin` bounces the viewer back to
 *                    `/dashboard` (Admin.tsx `<Navigate>`).
 *   (b) API plane  — the Go backend's `middleware/rbac.go` returns 403 for the
 *                    viewer's token on the admin route `handlers/admin.go`
 *                    (`GET /admin/users`), while an admin's token gets 200.
 *
 * The viewer also must not be able to create notes (content.write) — the
 * backend returns 403 on `POST /api/notes` regardless of any UI gating.
 */

import { test, expect } from '@playwright/test';
import { VIEWER, ADMIN, FRONTEND_URL } from './config';
import { loginViaSpa } from './ui';
import { backendStatus } from './api';

test.describe('Flow 3 — permission enforcement (UI + API planes)', () => {
  test('viewer is denied admin UI and gets 403 from the backend admin route', async ({ page }) => {
    const { accessToken } = await loginViaSpa(page, VIEWER.email);

    // ── UI plane ──────────────────────────────────────────────────────────
    // No Admin nav link for a non-admin.
    await expect(page.getByRole('link', { name: 'Admin' })).toHaveCount(0);
    // The viewer role badge is present; admin is not.
    await expect(page.locator('.badge-viewer')).toHaveText('viewer');
    await expect(page.locator('.badge-admin')).toHaveCount(0);

    // Direct navigation to /admin is bounced back to /dashboard (client guard).
    // This is a real user action — typing the URL, or following a bookmark —
    // so it must go through page.goto and actually load the SPA. It regressed
    // once when the Vite dev proxy shadowed /admin (HEA-2086); keep it as a
    // full navigation so that collision cannot come back unnoticed.
    await page.goto(`${FRONTEND_URL}/admin`);
    await expect(page).toHaveURL(`${FRONTEND_URL}/dashboard`);

    // ── API plane (the real enforcement) ─────────────────────────────────
    // The backend rejects the viewer's token on the admin route with 403 —
    // this is what makes it enforcement rather than cosmetic hiding.
    expect(await backendStatus(accessToken, '/admin/users')).toBe(403);

    // And on the write route: viewers lack content.write.
    const writeStatus = await postNote(accessToken);
    expect(writeStatus).toBe(403);

    // Sanity: the viewer CAN read notes (any authenticated user).
    expect(await backendStatus(accessToken, '/api/notes')).toBe(200);
  });

  test('admin sees the Admin tab and the backend returns 200 on the admin route', async ({ page }) => {
    const { accessToken } = await loginViaSpa(page, ADMIN.email);

    // UI plane — admin nav link present and the Admin page renders.
    await expect(page.getByRole('link', { name: 'Admin' })).toBeVisible();
    await page.getByRole('link', { name: 'Admin' }).click();
    await expect(page).toHaveURL(`${FRONTEND_URL}/admin`);
    await expect(page.getByRole('heading', { name: 'Admin — Users' })).toBeVisible();

    // API plane — same route the viewer got 403 on now returns 200.
    expect(await backendStatus(accessToken, '/admin/users')).toBe(200);
  });
});

/** POSTs a note to the backend with the given token; returns the HTTP status. */
async function postNote(token: string): Promise<number> {
  const { BACKEND_URL } = await import('./config');
  const resp = await fetch(`${BACKEND_URL}/api/notes`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'viewer-should-not-write', content: 'x' }),
  });
  return resp.status;
}
