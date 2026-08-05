/**
 * Browser-driver helpers for the integration suite (HEA-2056).
 *
 * `loginViaSpa` drives the *real* auth-code + PKCE round trip through the demo
 * SPA: Login → hosted Hearth login form → Callback → Dashboard. It captures the
 * tokens minted during the exchange so control-plane assertions (revoke,
 * rotate) can operate on the exact credential the SPA holds.
 */

import { expect, type Page } from '@playwright/test';
import { FRONTEND_URL, REALM_SLUG, DEMO_PASSWORD } from './config';

export interface CapturedTokens {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
}

/** Matches the realm token endpoint regardless of whether the SPA reaches it
 *  directly (:8420) or through the Vite proxy (:5173). */
function isTokenResponse(url: string): boolean {
  return url.includes(`/realms/${REALM_SLUG}/token`);
}

/**
 * Performs a full interactive login through the demo SPA and returns the tokens
 * the SPA received. Asserts the user lands on the authenticated Dashboard.
 */
export async function loginViaSpa(
  page: Page,
  email: string,
  password: string = DEMO_PASSWORD,
): Promise<CapturedTokens> {
  // Arm the token-response capture before anything navigates.
  const tokenResponse = page.waitForResponse(
    (r) => isTokenResponse(r.url()) && r.request().method() === 'POST',
    { timeout: 20_000 },
  );

  await page.goto(`${FRONTEND_URL}/`);
  await expect(page.getByRole('heading', { name: 'Hearth Hub' })).toBeVisible();

  // Kick off startLogin() — the browser navigates to Hearth's hosted login page.
  await page.getByRole('button', { name: 'Sign in with Hearth' }).click();

  // Hosted login form (served by Hearth on :8420 under /ui/realms/<realm>/…).
  await page.waitForURL(/\/ui\/realms\/[^/]+\/(oauth\/authorize|login)/, { timeout: 20_000 });
  await fillLoginForm(page, email, password);

  // Back through /callback → token exchange → client-side nav to /dashboard.
  // Wait on the rendered heading rather than the URL: the SPA fires several
  // quick redirects (login 303 → /callback → pushState /dashboard) and a
  // waitForURL races them (net::ERR_ABORTED / frame detached). A locator
  // tolerates the intermediate navigations.
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 20_000 });
  await expect(page).toHaveURL(`${FRONTEND_URL}/dashboard`);

  const resp = await tokenResponse;
  const body = (await resp.json()) as {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
  };
  return {
    accessToken: body.access_token,
    refreshToken: body.refresh_token,
    idToken: body.id_token,
  };
}

/** Fills and submits Hearth's hosted email/password login form.
 *
 *  The hosted login page starts a conditional-UI WebAuthn ("passkey") mediation
 *  on load and DISABLES the password submit button until it resolves. In
 *  headless Chromium (no authenticator) that never resolves, so clicking the
 *  button is a no-op. We submit the form programmatically via requestSubmit(),
 *  which fires the native submit regardless of the button's disabled state. */
export async function fillLoginForm(page: Page, email: string, password: string): Promise<void> {
  const emailField = page.locator('input[name="email"]');
  await emailField.waitFor({ state: 'visible', timeout: 15_000 });
  await emailField.fill(email);
  await page.fill('input[name="password"]', password);
  // Resolve the exact form from the password field, re-enable its submit button
  // (passkey.js disabled it), and submit programmatically.
  await page.locator('input[name="password"]').evaluate((el) => {
    const form = (el as HTMLInputElement).closest('form');
    if (!form) throw new Error('password field has no enclosing form');
    const btn = form.querySelector<HTMLButtonElement>('button[type="submit"]');
    if (btn) btn.disabled = false;
    form.requestSubmit(btn ?? undefined);
  });
}

/**
 * Runs `action` (e.g. a page reload) and captures the tokens from the
 * `POST …/token` response it triggers. Returns null if no successful token
 * response was observed (e.g. the refresh was rejected).
 */
export async function captureTokenDuring(
  page: Page,
  action: () => Promise<void>,
): Promise<CapturedTokens | null> {
  const pending = page
    .waitForResponse(
      (r) => isTokenResponse(r.url()) && r.request().method() === 'POST',
      { timeout: 20_000 },
    )
    .catch(() => null);
  await action();
  const resp = await pending;
  if (!resp || !resp.ok()) return null;
  const body = (await resp.json()) as {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
  };
  return { accessToken: body.access_token, refreshToken: body.refresh_token, idToken: body.id_token };
}

/**
 * Reads the SDK's persisted refresh/id tokens from the SPA's localStorage.
 * The access token lives in memory only and is captured from the token
 * response instead (see {@link loginViaSpa}).
 */
export async function readStoredTokens(page: Page): Promise<{ refresh: string | null; id: string | null }> {
  return page.evaluate(() => ({
    refresh: window.localStorage.getItem('hearth_refresh_token'),
    id: window.localStorage.getItem('hearth_id_token'),
  }));
}
