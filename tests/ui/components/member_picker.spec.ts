import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import { AUTH_DIR } from '../helpers/actions';
import type { SeedFixtures } from '../fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

test.use({ storageState: path.join(AUTH_DIR, 'admin.json') });

test.describe('Member picker component (group detail — members tab)', () => {
  test.beforeEach(async ({ page }) => {
    const seed = loadSeed();
    if (!seed.groupId) test.skip();
    await page.goto(
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/groups/${seed.groupId}?tab=members`,
    );
    await expect(page.locator('#member-picker-results')).toBeVisible();
  });

  test('search input triggers HTMX request and results populate', async ({ page }) => {
    const seed = loadSeed();

    // Wait for the HTMX GET triggered by typing in the search input
    const [response] = await Promise.all([
      page.waitForResponse(
        (r) =>
          r.url().includes('/members/picker') &&
          r.url().includes('q=') &&
          r.status() === 200,
        { timeout: 10_000 },
      ),
      page.fill('#member_search', 'test'),
    ]);

    expect(response.status()).toBe(200);

    // Container is swapped with the HTMX response — must be non-empty
    await expect(page.locator('#member-picker-results')).not.toBeEmpty();

    // Response body is an HTML partial, not a full page
    const body = await response.text();
    expect(body).not.toContain('<html');
  });

  test('empty search query loads the full paginated picker', async ({ page }) => {
    // Clear any prior input
    await page.fill('#member_search', '');

    // The container should still show users (or the "all already members" message)
    await expect(page.locator('#member-picker-results')).not.toBeEmpty();
  });

  test('clicking Add in picker results adds member to the group list', async ({ page }) => {
    const seed = loadSeed();

    // Search for the seeded test user to ensure there's at least one result
    await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes('/members/picker') && r.url().includes('q=') && r.status() === 200,
        { timeout: 10_000 },
      ),
      page.fill('#member_search', 'test'),
    ]);

    const addButton = page.locator('#member-picker-results button[type="submit"]').first();

    if ((await addButton.count()) === 0) {
      // User is already a member — picker shows "All realm users are already members"
      test.skip();
      return;
    }

    // Submit the add-member form and wait for the full page reload
    await Promise.all([
      page.waitForURL(
        (url) => url.href.includes(`/groups/${seed.groupId}`),
        { timeout: 15_000 },
      ),
      addButton.click(),
    ]);

    // Members table now has at least one row (not just the "No members yet" message)
    await expect(page.locator('table tbody tr td[colspan]')).not.toBeVisible();
  });
});
