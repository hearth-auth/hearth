import * as fs from 'fs';
import * as path from 'path';
import { chromium } from '@playwright/test';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

// The repo root is 3 levels up from tests/ui/fixtures/
const REPO_ROOT = path.resolve(__dirname, '../../..');
const DEV_DATA_DIR =
  process.env.HEARTH_DEV_DATA_DIR ?? path.join(REPO_ROOT, 'data', 'dev');
const AUTH_DIR = path.join(__dirname, '..', '.auth');

// Fixed credentials used for every test run — stable across restarts once set up
export const ADMIN_EMAIL = 'admin@hearth.test';
export const ADMIN_PASSWORD = 'HearthTest123!';

// Regular (non-admin) user credentials for user-portal session tests
export const USER_EMAIL = ADMIN_EMAIL;
export const USER_PASSWORD = ADMIN_PASSWORD;

// Dev-realm user credentials (set by bootstrap handler for UI test access)
export const DEV_REALM_NAME = 'dev-realm';
export const DEV_REALM_USER_EMAIL = 'admin@dev.local';
export const DEV_REALM_USER_PASSWORD = 'HearthDev123!';

/**
 * Performs first-time admin setup if the setup token is present, then logs in
 * via the browser form at /ui/admin/login and saves storageState to
 * .auth/admin.json so tests can reuse the session without re-authenticating.
 */
export async function setupAdminAuth(): Promise<void> {
  fs.mkdirSync(AUTH_DIR, { recursive: true });

  // Attempt one-time setup if the token file still exists (fresh dev server)
  const tokenPath = path.join(DEV_DATA_DIR, '.setup_token');
  if (fs.existsSync(tokenPath)) {
    const token = fs.readFileSync(tokenPath, 'utf-8').trim();
    try {
      const setupResp = await fetch(`${BASE_URL}/ui/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token,
          admin_email: ADMIN_EMAIL,
          admin_display_name: 'Test Admin',
          admin_password: ADMIN_PASSWORD,
        }),
        redirect: 'manual',
      });
      // 303 = success redirect; 4xx = already configured or invalid token — both OK
      if (
        setupResp.status !== 303 &&
        setupResp.status !== 302 &&
        setupResp.status >= 500
      ) {
        throw new Error(
          `Setup failed unexpectedly: HTTP ${setupResp.status}`,
        );
      }
    } catch (err) {
      if (!(err instanceof Error && err.message.includes('fetch'))) throw err;
      // Network-level error — likely server not ready yet
      throw err;
    }
  }

  // Browser login — captures the session cookies as storageState
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_EXECUTABLE_PATH || undefined,
  });
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(`${BASE_URL}/ui/admin/login`);
  await page.fill('input[name="email"]', ADMIN_EMAIL);
  await page.fill('input[name="password"]', ADMIN_PASSWORD);

  await Promise.all([
    // Wait for a successful post-login redirect to /ui (the admin dashboard area).
    // Using a positive match avoids accidentally resolving on /required-action,
    // /mfa-enroll-required, or /ui/setup/sent — all of which are non-/login URLs
    // but do NOT carry a hearth_ui_session cookie.
    page.waitForURL((url) => url.pathname.startsWith('/ui') && !url.pathname.includes('/login') && !url.pathname.includes('/setup') && !url.pathname.includes('/required-action') && !url.pathname.includes('/mfa'), { timeout: 15_000 }),
    page.click('button[type="submit"]'),
  ]);

  const finalUrl = page.url();
  console.log(`[setupAdminAuth] post-login URL: ${finalUrl}`);

  await context.storageState({ path: path.join(AUTH_DIR, 'admin.json') });
  await browser.close();

  // Verify the session cookie was actually issued.
  const savedState = JSON.parse(fs.readFileSync(path.join(AUTH_DIR, 'admin.json'), 'utf-8')) as { cookies: Array<{name: string}> };
  const hasSession = savedState.cookies.some((c) => c.name === 'hearth_ui_session');
  if (!hasSession) {
    throw new Error(
      `[setupAdminAuth] admin login succeeded (landed at ${finalUrl}) but ` +
      `no hearth_ui_session cookie was issued. Check server logs for session creation errors.`,
    );
  }
  console.log(`[setupAdminAuth] session cookie present — admin.json is valid`);
}

/**
 * Logs in as the dev-realm user at /ui/realms/dev-realm/login and saves
 * storageState to .auth/realm-user.json. This session is required for
 * user-facing OAuth consent and device-approval flows that target the dev-realm.
 *
 * Falls back silently when setup fails so that tests can skip gracefully.
 */
export async function setupRealmUserAuth(): Promise<void> {
  fs.mkdirSync(AUTH_DIR, { recursive: true });

  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_EXECUTABLE_PATH || undefined,
  });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    await page.goto(
      `${BASE_URL}/ui/realms/${DEV_REALM_NAME}/login`,
      { waitUntil: 'domcontentloaded', timeout: 10_000 },
    );

    if ((await page.locator('input[name="email"]').count()) === 0) {
      console.warn('[setupRealmUserAuth] realm login form not found — skipping realm-user.json');
      return;
    }

    await page.fill('input[name="email"]', DEV_REALM_USER_EMAIL, { timeout: 5_000 });
    await page.fill('input[name="password"]', DEV_REALM_USER_PASSWORD, { timeout: 5_000 });

    await Promise.all([
      page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    await context.storageState({ path: path.join(AUTH_DIR, 'realm-user.json') });
  } catch (err) {
    console.warn(`[setupRealmUserAuth] could not establish realm user session: ${err}`);
  } finally {
    await browser.close();
  }
}

/**
 * Logs in as a regular (non-admin) user via the user-portal login form at
 * /ui/login and saves storageState to .auth/user.json. This session is used
 * for crawling and testing user-facing pages (/ui/account/*, /ui/device, etc.).
 *
 * Falls back silently (no user.json written) when the login fails so that
 * tests which depend on user.json can skip themselves rather than crash the
 * entire globalSetup.
 */
export async function setupUserAuth(): Promise<void> {
  fs.mkdirSync(AUTH_DIR, { recursive: true });

  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_EXECUTABLE_PATH || undefined,
  });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    await page.goto(`${BASE_URL}/ui/login`, { waitUntil: 'domcontentloaded', timeout: 10_000 });

    // Bare /ui/login returns 400 in multi-realm mode (no default realm) — the URL
    // still ends with /login but the page has no login form.  Detect by checking
    // for the email field; skip rather than waiting for a 5 s timeout.
    if (!page.url().includes('/login') || (await page.locator('input[name="email"]').count()) === 0) {
      console.warn('[setupUserAuth] /ui/login has no login form — skipping user.json');
      return;
    }

    await page.fill('input[name="email"]', USER_EMAIL, { timeout: 5_000 });
    await page.fill('input[name="password"]', USER_PASSWORD, { timeout: 5_000 });

    await Promise.all([
      page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    await context.storageState({ path: path.join(AUTH_DIR, 'user.json') });
  } catch (err) {
    console.warn(`[setupUserAuth] could not establish user session: ${err}`);
  } finally {
    await browser.close();
  }
}
