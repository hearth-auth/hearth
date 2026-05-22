import { test, expect } from '@playwright/test';
import { AUTH_DIR, loadCredentials } from '../helpers/actions';
import * as path from 'path';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

test.use({ storageState: path.join(AUTH_DIR, 'admin.json') });

/** Creates a fresh realm via API and returns its name. The realm starts empty
 *  (no users, apps, or groups), making it ideal for empty-state verification. */
async function createEmptyRealm(suffix: string): Promise<string> {
  const creds = loadCredentials();
  const name = `ui-empty-${suffix}`;
  const resp = await fetch(`${BASE_URL}/admin/realms`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${creds.access_token}`,
      'X-Realm-ID': creds.realm_id,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ name }),
  });
  if (!resp.ok && resp.status !== 409) {
    throw new Error(`Failed to create realm ${name}: HTTP ${resp.status}`);
  }
  return name;
}

test.describe('Empty state partials', () => {
  let emptyRealm: string;

  test.beforeAll(async () => {
    emptyRealm = await createEmptyRealm(Date.now().toString());
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

    // _empty.html content is visible
    const main = page.locator('#main');
    await expect(main).not.toBeEmpty();
    // Page has meaningful content (not a blank body)
    const text = await main.innerText();
    expect(text.trim().length).toBeGreaterThan(10);
  });

  test('organizations list shows _empty.html partial when realm has no orgs', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/admin/realms/${emptyRealm}/organizations`);

    const main = page.locator('#main');
    await expect(main).not.toBeEmpty();
    const text = await main.innerText();
    expect(text.trim().length).toBeGreaterThan(10);
  });

  test('groups list shows empty state when realm has no groups', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/admin/realms/${emptyRealm}/groups`);

    const main = page.locator('#main');
    await expect(main).not.toBeEmpty();
    const text = await main.innerText();
    expect(text.trim().length).toBeGreaterThan(10);
  });
});
