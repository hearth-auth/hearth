/**
 * OAuth 2.0 Device Authorization Grant flow (HEA-663).
 *
 * RFC 8628 end-to-end:
 *   1. API: POST /oauth/device_authorization → device_code + user_code
 *   2. Browser: GET /ui/device → enter user_code → POST /ui/device (approve)
 *   3. API: POST /oauth/token with device_code → access_token
 *
 * The approval step requires a logged-in user session (admin session used here).
 * The token poll loop retries until the device code is exchanged (up to 10 s).
 */

import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import { newInstrumentedPage, assertPageClean } from '../helpers/assertions';
import type { SeedFixtures } from '../fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const AUTH_DIR = path.join(__dirname, '..', '.auth');

const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  if (!fs.existsSync(p)) throw new Error(`seed.json not found at ${p}. Run globalSetup first.`);
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

interface DeviceAuthResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

/** POST /realms/{realm}/device_authorization — initiates a device grant. */
async function startDeviceAuth(clientId: string, realmName: string): Promise<DeviceAuthResponse> {
  const resp = await fetch(`${BASE_URL}/realms/${realmName}/device_authorization`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: clientId }),
  });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`device_authorization failed: HTTP ${resp.status} — ${body}`);
  }
  return resp.json() as Promise<DeviceAuthResponse>;
}

/** Poll POST /realms/{realm}/token until approved or timeout. Returns access_token. */
async function pollDeviceToken(
  clientId: string,
  deviceCode: string,
  realmName: string,
  intervalMs: number,
  maxWaitMs = 10_000,
): Promise<string> {
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, intervalMs));
    const resp = await fetch(`${BASE_URL}/realms/${realmName}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: DEVICE_GRANT,
        device_code: deviceCode,
        client_id: clientId,
      }),
    });
    if (resp.ok) {
      const body = (await resp.json()) as { access_token?: string };
      if (body.access_token) return body.access_token;
    }
    // 400 with authorization_pending is expected while user hasn't approved yet
    const err = (await resp.json().catch(() => ({}))) as { error?: string };
    if (err.error && err.error !== 'authorization_pending' && err.error !== 'slow_down') {
      throw new Error(`Token poll failed with error: ${err.error}`);
    }
  }
  throw new Error(`Device code was not approved within ${maxWaitMs} ms`);
}

// ---------------------------------------------------------------------------
// Device approval page renders
// ---------------------------------------------------------------------------

test.describe('Device auth — approval page', () => {
  test('GET /ui/device renders user-code entry form', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await newInstrumentedPage(ctx);

    await page.goto(`${BASE_URL}/ui/device`, { waitUntil: 'domcontentloaded' });

    await expect(page.locator('input[name="user_code"]')).toBeVisible();
    await expect(page.locator('#main button[type="submit"]')).toBeVisible();

    assertPageClean(page);
    await ctx.close();
  });

  test('unauthenticated visit to /ui/device redirects to login', async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await newInstrumentedPage(ctx);

    await page.goto(`${BASE_URL}/ui/device`, { waitUntil: 'domcontentloaded' });

    expect(page.url()).not.toContain('/device');
    expect(page.url()).toMatch(/login/);

    assertPageClean(page);
    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Full device authorization flow
// ---------------------------------------------------------------------------

test.describe('Device auth — full flow', () => {
  test('device_authorization → user approves → token issued', async ({ browser }) => {
    // Device approval uses the realm-scoped user session (system-realm admin
    // cannot approve dev-realm device codes — session.realm_id mismatch).
    const realmUserState = path.join(AUTH_DIR, 'realm-user.json');
    test.skip(
      !fs.existsSync(realmUserState),
      'realm-user.json not found — setupRealmUserAuth skipped (no dev-realm user)',
    );

    const seed = loadSeed();

    // Step 1: initiate device grant via API
    const deviceAuth = await startDeviceAuth(seed.appClientId, seed.realmName);

    expect(deviceAuth.device_code, 'Expected device_code').toBeTruthy();
    expect(deviceAuth.user_code, 'Expected user_code').toBeTruthy();
    expect(deviceAuth.verification_uri, 'Expected verification_uri').toBeTruthy();
    // user_code is 8 chars per the Hearth implementation
    expect(deviceAuth.user_code.replace(/-/g, '')).toHaveLength(8);

    // Step 2: browser approval — must use the realm-scoped session so that
    // device_approve_submit resolves session.realm_id == dev-realm.
    const ctx = await browser.newContext({ storageState: realmUserState });
    const page = await newInstrumentedPage(ctx);

    await page.goto(`${BASE_URL}/ui/device`, { waitUntil: 'domcontentloaded' });
    await expect(page.locator('input[name="user_code"]')).toBeVisible();

    await page.fill('input[name="user_code"]', deviceAuth.user_code);
    await Promise.all([
      // Successful approval redirects to /ui/device?flash=approved (handlers.rs).
      page.waitForURL(/\/ui\/device\?flash=approved/, { timeout: 15_000 }),
      page.click('#main button[type="submit"]'),
    ]);

    // Assert the specific success flash renders — not merely a non-empty body,
    // which an error page would also satisfy.
    await expect(page.locator('#main')).toContainText('Device approved successfully', {
      timeout: 10_000,
    });

    assertPageClean(page);
    await ctx.close();

    // Step 3: poll for the token — should succeed now that the user approved
    const accessToken = await pollDeviceToken(
      seed.appClientId,
      deviceAuth.device_code,
      seed.realmName,
      (deviceAuth.interval ?? 1) * 1_000,
    );

    // Validate the token structure — a JWS compact serialization has three
    // non-empty base64url segments (header.payload.signature). "toBeTruthy" alone
    // would accept any non-empty string.
    expect(accessToken, 'Expected access_token after device approval').toBeTruthy();
    const segments = accessToken.split('.');
    expect(segments, 'access_token must be a 3-part JWS').toHaveLength(3);
    expect(segments.every((s) => /^[A-Za-z0-9_-]+$/.test(s))).toBe(true);
  });

  test('device_authorization response includes required RFC 8628 fields', async () => {
    const seed = loadSeed();
    const deviceAuth = await startDeviceAuth(seed.appClientId, seed.realmName);

    expect(typeof deviceAuth.device_code).toBe('string');
    expect(typeof deviceAuth.user_code).toBe('string');
    expect(typeof deviceAuth.verification_uri).toBe('string');
    expect(typeof deviceAuth.expires_in).toBe('number');
    expect(deviceAuth.expires_in).toBeGreaterThan(0);
    expect(deviceAuth.verification_uri).toMatch(/\/device/);
  });

  test('polling before approval returns authorization_pending', async () => {
    const seed = loadSeed();
    const deviceAuth = await startDeviceAuth(seed.appClientId, seed.realmName);

    const resp = await fetch(`${BASE_URL}/realms/${seed.realmName}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: DEVICE_GRANT,
        device_code: deviceAuth.device_code,
        client_id: seed.appClientId,
      }),
    });

    expect(resp.status).toBe(400);
    const body = (await resp.json()) as { error: string };
    expect(body.error).toBe('authorization_pending');
  });
});
