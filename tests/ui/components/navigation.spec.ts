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

test.describe('Sidebar navigation', () => {
  test('sidebar renders with main nav links', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui`);

    const nav = page.locator('nav[aria-label="Admin"]');
    await expect(nav).toBeVisible();

    // Core nav links present
    await expect(nav.locator('a[href="/ui"]')).toBeVisible();
    await expect(nav.locator('a[href="/ui/account"]')).toBeVisible();
    await expect(nav.locator('a[href="/ui/admin/realms"]')).toBeVisible();
    await expect(nav.locator('a[href="/ui/admin/settings"]')).toBeVisible();
  });

  test('dashboard link is marked active on the dashboard page', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui`);

    const dashLink = page.locator('nav[aria-label="Admin"] a[href="/ui"]');
    await expect(dashLink).toHaveAttribute('aria-current', 'page');
  });

  test('account link is marked active on the account page', async ({ page }) => {
    await page.goto(`${BASE_URL}/ui/account`);

    const accountLink = page.locator('nav[aria-label="Admin"] a[href="/ui/account"]');
    await expect(accountLink).toHaveAttribute('aria-current', 'page');
  });

  test('realm pill appears in top bar on realm-scoped pages', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(`${BASE_URL}/ui/admin/realms/${seed.realmName}/users`);

    // The Alpine-rendered realm pill shows the current realm name
    const pill = page.locator('header').getByText(seed.realmName);
    await expect(pill).toBeVisible({ timeout: 10_000 });
  });

  test('realm tree expands to show sub-pages for the current realm', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(`${BASE_URL}/ui/admin/realms/${seed.realmName}/users`);

    const nav = page.locator('nav[aria-label="Admin"]');
    // Wait for AlpineJS to render the realm nav from /ui/admin/api/nav/realms
    await expect(nav.getByText(seed.realmName)).toBeVisible({ timeout: 10_000 });

    // At least one sub-page link visible under the expanded realm
    const subLink = nav.locator('a[href*="/realms/"][href*="/users"]');
    await expect(subLink).toBeVisible({ timeout: 5_000 });
  });
});
