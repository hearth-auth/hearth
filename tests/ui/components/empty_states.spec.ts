import { test, expect, type Browser } from '@playwright/test';
import { AUTH_DIR } from '../helpers/actions';
import { instrumentPage, assertPageClean } from '../helpers/assertions';
import * as path from 'path';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

test.use({ storageState: path.join(AUTH_DIR, 'admin.json') });

/**
 * Creates a fresh realm via the onboarding wizard UI and returns its name.
 *
 * POST /admin/realms is intentionally disabled (realms are managed via
 * hearth.yaml in production). The wizard form at /ui/admin/onboarding/realm
 * is the correct runtime path for realm creation and works regardless of
 * whether other realms already exist.
 */
async function createEmptyRealm(browser: Browser, suffix: string): Promise<string> {
  const realmName = `ui-empty-${suffix}`;
  const ctx = await browser.newContext({ storageState: path.join(AUTH_DIR, 'admin.json') });
  const page = await ctx.newPage();

  // Fetch CSRF token from an authenticated page (it's session-bound).
  await page.goto(`${BASE_URL}/ui/admin/realms`, { waitUntil: 'domcontentloaded' });
  const csrf = await page.$eval(
    'meta[name="csrf"]',
    (el: Element) => (el as HTMLMetaElement).content ?? '',
  );

  // Submit the realm creation wizard form. The server creates the realm and
  // redirects to step 2 (/ui/admin/onboarding/app?realm=...).
  // ctx.request shares the browser context cookies, so the session is intact.
  const resp = await ctx.request.post(`${BASE_URL}/ui/admin/onboarding/realm`, {
    form: {
      _csrf: csrf,
      realm_name: realmName,
      display_name: realmName,
      theme: 'ember',
    },
  });

  await ctx.close();

  if (!resp.ok()) {
    const body = await resp.text();
    throw new Error(`Failed to create realm ${realmName}: HTTP ${resp.status()} — ${body.slice(0, 200)}`);
  }

  return realmName;
}

test.describe('Empty state partials', () => {
  let emptyRealm: string;

  test.beforeAll(async ({ browser }) => {
    emptyRealm = await createEmptyRealm(browser, Date.now().toString());
  });

  test.beforeEach(async ({ page }) => {
    instrumentPage(page);
  });

  test.afterEach(async ({ page }) => {
    assertPageClean(page);
  });

  test('users list shows _empty.html partial when realm has no users', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/admin/realms/${emptyRealm}/users`);

    // _empty.html renders "No users yet"
    await expect(page.locator('#main')).toContainText('No users yet', { timeout: 10_000 });
    // And offers a create action — not a blank page
    await expect(page.locator('a[href*="/users/new"], a[href*="/users/invite"]').first()).toBeVisible();
  });

  test('applications list shows _empty.html partial when realm has no apps', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/admin/realms/${emptyRealm}/applications`);

    // _empty.html renders "No applications yet"
    await expect(page.locator('#main')).toContainText('No applications yet', { timeout: 10_000 });
    // And offers a "create first" CTA — not a blank page
    await expect(
      page.locator(`a[href="/ui/admin/realms/${emptyRealm}/applications/new"]`).first(),
    ).toBeVisible();
  });

  test('organizations list shows _empty.html partial when realm has no orgs', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/admin/realms/${emptyRealm}/organizations`);

    // _empty.html renders "No organizations yet"
    await expect(page.locator('#main')).toContainText('No organizations yet', { timeout: 10_000 });
    await expect(
      page.locator(`a[href="/ui/admin/realms/${emptyRealm}/organizations/new"]`).first(),
    ).toBeVisible();
  });

  test('groups list shows empty state when realm has no groups', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/admin/realms/${emptyRealm}/groups`);

    // list.html empty branch renders "No groups yet"
    await expect(page.locator('#main')).toContainText('No groups yet', { timeout: 10_000 });
    await expect(
      page.locator(`a[href="/ui/admin/realms/${emptyRealm}/groups/new"]`).first(),
    ).toBeVisible();
  });
});
