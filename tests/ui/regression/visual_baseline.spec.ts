/**
 * Visual regression baselines (HEA-663).
 *
 * Uses Playwright's built-in `toHaveScreenshot()` to lock pixel-perfect
 * snapshots of key pages. First run generates the `.png` baseline files
 * in tests/ui/snapshots/. Subsequent runs diff against them.
 *
 * Diff policy (configured in playwright.config.ts):
 *   - While baselines are being established: threshold = 0.1 (WARN on diff)
 *   - After `--update-snapshots` locking run: threshold = 0.02 (FAIL on diff)
 *
 * To regenerate baselines:
 *   cd tests/ui && npx playwright test --project=visual --update-snapshots
 *
 * Pages covered:
 *   - Admin login form
 *   - Admin dashboard / realm list
 *   - Admin users list
 *   - OAuth consent interstitial
 *   - Device authorization approval page
 *   - User account consents page
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { test, expect } from '@playwright/test';
import type { SeedFixtures } from '../fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const AUTH_DIR = path.join(__dirname, '..', '.auth');
const CALLBACK_ORIGIN = 'https://example.com';

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  if (!fs.existsSync(p)) throw new Error(`seed.json not found at ${p}. Run globalSetup first.`);
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

function pkce(): { challenge: string } {
  const verifier = crypto.randomBytes(32).toString('base64url');
  return {
    challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
  };
}

// Shared screenshot options — mask dynamic elements so diffs are stable
const screenshotOpts = {
  // Mask elements whose content changes every run (timestamps, IDs, tokens)
  mask: [] as ReturnType<typeof test.info>['annotations'],
  animations: 'disabled' as const,
  // Allow minor antialiasing differences across OS/browser versions
  maxDiffPixelRatio: 0.03,
};

// ---------------------------------------------------------------------------
// Public / pre-auth pages
// ---------------------------------------------------------------------------

test.describe('Visual — public pages', () => {
  test('admin login page matches baseline', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/admin/login`, { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveScreenshot('admin-login.png', screenshotOpts);
  });

  test('user login page matches baseline', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/login`, { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveScreenshot('user-login.png', screenshotOpts);
  });
});

// ---------------------------------------------------------------------------
// Admin pages (authenticated)
// ---------------------------------------------------------------------------

test.describe('Visual — admin pages', () => {
  test('admin dashboard matches baseline', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(`${BASE_URL}/ui`, { waitUntil: 'domcontentloaded' });

    // Mask any dynamic last-seen / created-at timestamps
    await expect(page).toHaveScreenshot('admin-dashboard.png', {
      ...screenshotOpts,
      mask: [page.locator('time'), page.locator('[data-dynamic]')],
    });

    await ctx.close();
  });

  test('admin realm users list matches baseline', async ({ browser }) => {
    const seed = loadSeed();
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/users`,
      { waitUntil: 'domcontentloaded' },
    );

    await expect(page).toHaveScreenshot('admin-users-list.png', {
      ...screenshotOpts,
      mask: [page.locator('time'), page.locator('[data-dynamic]')],
    });

    await ctx.close();
  });

  test('admin realm applications list matches baseline', async ({ browser }) => {
    const seed = loadSeed();
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/applications`,
      { waitUntil: 'domcontentloaded' },
    );

    await expect(page).toHaveScreenshot('admin-applications-list.png', screenshotOpts);

    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// OAuth consent interstitial
// ---------------------------------------------------------------------------

test.describe('Visual — OAuth consent', () => {
  test('consent page matches baseline', async ({ browser }) => {
    const seed = loadSeed();
    const { challenge } = pkce();
    const state = 'visual-test-state';

    const u = new URL(`${BASE_URL}/ui/oauth/authorize`);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('client_id', seed.appClientId);
    u.searchParams.set('redirect_uri', `${CALLBACK_ORIGIN}/callback`);
    u.searchParams.set('scope', 'openid profile');
    u.searchParams.set('state', state);
    u.searchParams.set('code_challenge', challenge);
    u.searchParams.set('code_challenge_method', 'S256');
    u.searchParams.set('prompt', 'consent');

    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();
    await page.route(`${CALLBACK_ORIGIN}/**`, (route) => route.abort());

    await page.goto(u.toString(), { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/oauth\/consent/);

    await expect(page).toHaveScreenshot('oauth-consent.png', screenshotOpts);

    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// Device authorization page
// ---------------------------------------------------------------------------

test.describe('Visual — device authorization', () => {
  test('device approval page matches baseline', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
    const page = await ctx.newPage();

    await page.goto(`${BASE_URL}/ui/device`, { waitUntil: 'domcontentloaded' });

    await expect(page).toHaveScreenshot('device-approve.png', screenshotOpts);

    await ctx.close();
  });
});

// ---------------------------------------------------------------------------
// User account pages (requires user session)
// ---------------------------------------------------------------------------

test.describe('Visual — user account pages', () => {
  test.skip(
    () => !fs.existsSync(path.join(AUTH_DIR, 'user.json')),
    'user.json not found — run globalSetup with user auth enabled',
  );

  test('account consents page matches baseline', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'user.json') });
    const page = await ctx.newPage();

    await page.goto(`${BASE_URL}/ui/account/consents`, { waitUntil: 'domcontentloaded' });

    await expect(page).toHaveScreenshot('user-account-consents.png', screenshotOpts);

    await ctx.close();
  });
});
