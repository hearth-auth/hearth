import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import { AUTH_DIR, DESTRUCTIVE, loadCredentials } from '../helpers/actions';
import type { SeedFixtures } from '../fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

test.use({ storageState: path.join(AUTH_DIR, 'admin.json') });

test.describe('Admin users list', () => {
  test('users list page loads and shows seeded user', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(`${BASE_URL}/ui/admin/realms/${seed.realmName}/users`);

    await expect(page.locator('h1')).toContainText('Users');
    // The table or empty-state renders — page is not blank
    const bodyText = await page.locator('#main').innerText();
    expect(bodyText.length).toBeGreaterThan(10);
  });

  test('create user form renders with required fields', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(`${BASE_URL}/ui/admin/realms/${seed.realmName}/users/new`);

    await expect(page.locator('h1')).toContainText('Create user');
    await expect(page.locator('input[name="email"]')).toBeVisible();
    await expect(page.locator('input[name="first_name"]')).toBeVisible();
    await expect(page.locator('input[name="last_name"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('create user form submits and redirects to user detail', async ({ page }) => {
    const seed = loadSeed();
    const uniqueEmail = `ui-create-test-${Date.now()}@example.com`;

    await page.goto(`${BASE_URL}/ui/admin/realms/${seed.realmName}/users/new`);
    await page.fill('input[name="email"]', uniqueEmail);
    await page.fill('input[name="first_name"]', 'UI');
    await page.fill('input[name="last_name"]', 'Test');
    await page.fill('input[name="password"]', 'UITestPassword!42');

    await Promise.all([
      page.waitForURL(/\/users\/[^/]+$/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    // Landed on the new user's detail page
    await expect(page.locator('#main')).toContainText(uniqueEmail);
  });

  // Runs in the sequential destructive project — safe to mutate shared state.
  test(`delete user ${DESTRUCTIVE}`, async ({ page }) => {
    const seed = loadSeed();
    const creds = loadCredentials();

    // Create a throwaway user via API so we don't destroy seeded fixtures
    const uniqueEmail = `ui-delete-target-${Date.now()}@example.com`;
    const resp = await fetch(`${BASE_URL}/admin/users`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${creds.access_token}`,
        'X-Realm-ID': creds.realm_id,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email: uniqueEmail, display_name: 'Delete Target' }),
    });
    if (!resp.ok) throw new Error(`Seed user creation failed: HTTP ${resp.status}`);
    const created = (await resp.json()) as { id: string };

    // Navigate to the user's detail page and trigger deletion via the Danger tab
    await page.goto(
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/users/${created.id}?tab=danger`,
    );

    // The delete button / confirmation form should be present on the Danger tab
    const deleteButton = page.locator('button', { hasText: /Delete user/i }).first();
    await expect(deleteButton).toBeVisible();
    await deleteButton.click();

    // Confirm by typing the user's email in the confirmation input
    const confirmInput = page.locator('input[type="text"]').last();
    await confirmInput.fill(uniqueEmail);

    await Promise.all([
      page.waitForURL(/\/users$/, { timeout: 15_000 }),
      page.locator('button[type="submit"]').filter({ hasText: /Delete permanently/i }).click(),
    ]);

    // Redirected to the users list; deleted user is no longer present
    await expect(page).toHaveURL(/\/users$/);
  });
});
