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

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const AUTH_DIR = path.join(__dirname, '..', '.auth');
const CALLBACK_ORIGIN = 'https://example.com';
const REDIRECT_URI = `${CALLBACK_ORIGIN}/callback`;

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  if (!fs.existsSync(p)) throw new Error(`seed.json not found at ${p}. Run globalSetup first.`);
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
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

test.describe('OAuth consent — page renders', () => {
  test('authorize redirects to consent page with client name visible', async ({ browser }) => {
    const seed = loadSeed();
    const { challenge } = pkce();
    const state = crypto.randomBytes(8).toString('hex');

    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    // Intercept the callback so the external redirect never fires
    await page.route(`${CALLBACK_ORIGIN}/**`, (route) => route.abort());

    await page.goto(buildAuthorizeUrl(seed.appClientId, challenge, state).toString(), {
      waitUntil: 'domcontentloaded',
    });

    // Must end up on the consent interstitial (server may skip it if a consent
    // record already exists; use prompt=consent to force the page on repeat runs)
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

    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();
    await page.route(`${CALLBACK_ORIGIN}/**`, (route) => route.abort());

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

test.describe('OAuth consent — approve', () => {
  test('approve redirects to redirect_uri with authorization code and correct state', async ({
    browser,
  }) => {
    const seed = loadSeed();
    const { challenge } = pkce();
    const state = crypto.randomBytes(16).toString('hex');

    const u = buildAuthorizeUrl(seed.appClientId, challenge, state);
    u.searchParams.set('prompt', 'consent');

    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    // Capture the callback URL before the browser tries to navigate there
    let capturedCallbackUrl: URL | null = null;
    await page.route(`${CALLBACK_ORIGIN}/**`, (route) => {
      capturedCallbackUrl = new URL(route.request().url());
      route.abort();
    });

    await page.goto(u.toString(), { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/oauth\/consent/);

    // Submit approval and wait for the intercept to fire
    const [callbackRequest] = await Promise.all([
      page.waitForRequest((req) => req.url().startsWith(CALLBACK_ORIGIN)),
      page.click('[data-testid="approve-button"]'),
    ]);

    expect(capturedCallbackUrl, 'Redirect to callback URI was not intercepted').not.toBeNull();
    expect(
      capturedCallbackUrl!.searchParams.get('code'),
      'Expected authorization code in redirect',
    ).toBeTruthy();
    expect(capturedCallbackUrl!.searchParams.get('state')).toBe(state);
    expect(capturedCallbackUrl!.searchParams.get('error')).toBeNull();

    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Deny → access_denied error
// ---------------------------------------------------------------------------

test.describe('OAuth consent — deny', () => {
  test('deny redirects to redirect_uri with error=access_denied', async ({ browser }) => {
    const seed = loadSeed();
    const { challenge } = pkce();
    const state = crypto.randomBytes(16).toString('hex');

    const u = buildAuthorizeUrl(seed.appClientId, challenge, state);
    u.searchParams.set('prompt', 'consent');

    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    let capturedCallbackUrl: URL | null = null;
    await page.route(`${CALLBACK_ORIGIN}/**`, (route) => {
      capturedCallbackUrl = new URL(route.request().url());
      route.abort();
    });

    await page.goto(u.toString(), { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/oauth\/consent/);

    await Promise.all([
      page.waitForRequest((req) => req.url().startsWith(CALLBACK_ORIGIN)),
      page.click('[data-testid="deny-button"]'),
    ]);

    expect(capturedCallbackUrl, 'Redirect to callback URI was not intercepted').not.toBeNull();
    expect(capturedCallbackUrl!.searchParams.get('error')).toBe('access_denied');
    expect(capturedCallbackUrl!.searchParams.get('state')).toBe(state);
    expect(capturedCallbackUrl!.searchParams.get('code')).toBeNull();

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
