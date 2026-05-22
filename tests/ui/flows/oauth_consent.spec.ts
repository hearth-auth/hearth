/**
 * OAuth 2.0 authorization-code + consent flow (HEA-663).
 *
 * Drives the browser-facing consent UI end-to-end:
 *   GET /ui/oauth/authorize
 *     → redirect to /ui/oauth/consent
 *     → POST /ui/oauth/consent (approve or deny)
 *     → 302 to redirect_uri with ?code= or ?error=access_denied
 *
 * The seeded test-app client (redirect_uri = https://example.com/callback)
 * is intercepted via page.route() so the external redirect never fires but
 * its URL (including the authorization code) is still captured.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { test, expect } from '@playwright/test';
import type { SeedFixtures } from '../fixtures/seed';
import { loadCredentials } from '../helpers/actions';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const AUTH_DIR = path.join(__dirname, '..', '.auth');
const CALLBACK_ORIGIN = 'https://example.com';
const REDIRECT_URI = `${CALLBACK_ORIGIN}/callback`;

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  if (!fs.existsSync(p)) throw new Error(`seed.json not found at ${p}. Run globalSetup first.`);
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

/** Revoke stored consent for the realm-user so the next authorize always shows the consent page.
 *  Hearth does not implement prompt=consent, so we must clear the record via the admin API. */
async function revokeConsent(clientId: string): Promise<void> {
  const creds = loadCredentials();
  await fetch(`${BASE_URL}/admin/users/${creds.user_id}/consents/${clientId}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${creds.access_token}`,
      'X-Realm-ID': creds.realm_id,
    },
  });
}

/** Generate a PKCE code_verifier + S256 code_challenge pair. */
function pkce(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function buildAuthorizeUrl(clientId: string, challenge: string, state: string): URL {
  const u = new URL(`${BASE_URL}/ui/oauth/authorize`);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('redirect_uri', REDIRECT_URI);
  u.searchParams.set('scope', 'openid profile');
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  return u;
}

// ---------------------------------------------------------------------------
// Consent page renders
// ---------------------------------------------------------------------------

// Run consent tests serially to prevent parallel consent-state races.
test.describe.serial('OAuth consent — page renders', () => {
  test.beforeEach(async () => {
    const seed = loadSeed();
    await revokeConsent(seed.appClientId);
  });

  test('authorize redirects to consent page with client name visible', async ({ browser }) => {
    const seed = loadSeed();
    const { challenge } = pkce();
    const state = crypto.randomBytes(8).toString('hex');

    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'realm-user.json') });
    const page = await ctx.newPage();

    // Intercept the callback so the external redirect never fires
    await page.route((url) => url.href.startsWith(CALLBACK_ORIGIN), async (route) => { await route.abort(); });

    await page.goto(buildAuthorizeUrl(seed.appClientId, challenge, state).toString(), {
      waitUntil: 'domcontentloaded',
    });

    await expect(page).toHaveURL(/\/oauth\/consent/);

    // Application name must be visible on the consent page
    await expect(page.locator('body')).toContainText('test-app');

    // The form must be present
    await expect(page.locator('[data-testid="consent-form"]')).toBeVisible();

    await ctx.close();
  });

  test('consent page shows approve and deny buttons', async ({ browser }) => {
    const seed = loadSeed();
    const { challenge } = pkce();
    const state = crypto.randomBytes(8).toString('hex');

    // force re-prompt so we always see the consent page
    const u = buildAuthorizeUrl(seed.appClientId, challenge, state);
    u.searchParams.set('prompt', 'consent');

    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'realm-user.json') });
    const page = await ctx.newPage();
    await page.route((url) => url.href.startsWith(CALLBACK_ORIGIN), async (route) => { await route.abort(); });

    await page.goto(u.toString(), { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/oauth\/consent/);

    await expect(page.locator('[data-testid="approve-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="deny-button"]')).toBeVisible();

    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Approve → authorization code returned
// ---------------------------------------------------------------------------

test.describe.serial('OAuth consent — approve', () => {
  test.beforeEach(async () => {
    const seed = loadSeed();
    await revokeConsent(seed.appClientId);
  });

  test('approve redirects to redirect_uri with authorization code and correct state', async ({
    browser,
  }) => {
    const seed = loadSeed();
    const { challenge } = pkce();
    const state = crypto.randomBytes(16).toString('hex');

    const u = buildAuthorizeUrl(seed.appClientId, challenge, state);
    u.searchParams.set('prompt', 'consent');

    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'realm-user.json') });
    const page = await ctx.newPage();

    // Abort navigation to callback so the browser stays on a local page
    await page.route((url) => url.href.startsWith(CALLBACK_ORIGIN), async (route) => { await route.abort(); });

    // Capture the redirect Location from the server's consent POST response.
    // This fires before the browser follows the redirect, giving us the full
    // callback URL including code and state without needing to intercept the
    // navigation to the external domain.
    const consentResponsePromise = page.waitForResponse(
      (resp) => resp.url().includes('/oauth/consent') && resp.request().method() === 'POST',
      { timeout: 30000 },
    );

    await page.goto(u.toString(), { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/oauth\/consent/);

    await page.click('[data-testid="approve-button"]');
    const consentResponse = await consentResponsePromise;
    const location = consentResponse.headers()['location'];
    expect(location, 'Expected redirect Location header on consent POST response').toBeTruthy();
    const capturedCallbackUrl = new URL(location);

    expect(
      capturedCallbackUrl.searchParams.get('code'),
      'Expected authorization code in redirect',
    ).toBeTruthy();
    expect(capturedCallbackUrl.searchParams.get('state')).toBe(state);
    expect(capturedCallbackUrl.searchParams.get('error')).toBeNull();

    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Deny → access_denied error
// ---------------------------------------------------------------------------

test.describe.serial('OAuth consent — deny', () => {
  test.beforeEach(async () => {
    const seed = loadSeed();
    await revokeConsent(seed.appClientId);
  });

  test('deny redirects to redirect_uri with error=access_denied', async ({ browser }) => {
    const seed = loadSeed();
    const { challenge } = pkce();
    const state = crypto.randomBytes(16).toString('hex');

    const u = buildAuthorizeUrl(seed.appClientId, challenge, state);
    u.searchParams.set('prompt', 'consent');

    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'realm-user.json') });
    const page = await ctx.newPage();

    await page.route((url) => url.href.startsWith(CALLBACK_ORIGIN), async (route) => { await route.abort(); });

    const consentResponsePromise = page.waitForResponse(
      (resp) => resp.url().includes('/oauth/consent') && resp.request().method() === 'POST',
      { timeout: 30000 },
    );

    await page.goto(u.toString(), { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/oauth\/consent/);

    await page.click('[data-testid="deny-button"]');
    const consentResponse = await consentResponsePromise;
    const location = consentResponse.headers()['location'];
    expect(location, 'Expected redirect Location header on consent POST response').toBeTruthy();
    const capturedCallbackUrl = new URL(location);

    expect(capturedCallbackUrl.searchParams.get('error')).toBe('access_denied');
    expect(capturedCallbackUrl.searchParams.get('state')).toBe(state);
    expect(capturedCallbackUrl.searchParams.get('code')).toBeNull();

    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Unauthenticated → redirected to login
// ---------------------------------------------------------------------------

test.describe('OAuth consent — unauthenticated', () => {
  test('unauthenticated authorize request redirects to login', async ({ browser }) => {
    const seed = loadSeed();
    const { challenge } = pkce();
    const state = crypto.randomBytes(8).toString('hex');

    // No storageState — anonymous browser context
    const ctx = await browser.newContext();
    const page = await ctx.newPage();

    await page.goto(buildAuthorizeUrl(seed.appClientId, challenge, state).toString(), {
      waitUntil: 'domcontentloaded',
    });

    // Should be redirected to a login page, not the consent page
    expect(page.url()).not.toContain('/oauth/consent');
    expect(page.url()).toMatch(/login/);

    await ctx.close();
  });
});
