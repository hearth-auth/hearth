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

test.describe('Admin applications', () => {
  test('applications list page loads', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(`${BASE_URL}/ui/admin/realms/${seed.realmName}/applications`);

    await expect(page.locator('h1')).toContainText('Applications');
    const bodyText = await page.locator('#main').innerText();
    expect(bodyText.length).toBeGreaterThan(10);
  });

  test('create application form renders with required fields', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(`${BASE_URL}/ui/admin/realms/${seed.realmName}/applications/new`);

    await expect(page.locator('h1')).toContainText('Register application');
    await expect(page.locator('input[name="client_name"]')).toBeVisible();
    await expect(page.locator('textarea[name="redirect_uris"]')).toBeVisible();
    // Grant type checkboxes
    await expect(page.locator('input[name="grant_authorization_code"]')).toBeVisible();
    await expect(page.locator('input[name="grant_client_credentials"]')).toBeVisible();
    // Submit
    await expect(page.locator('#main button[type="submit"]')).toBeVisible();
  });

  test('application detail page loads for seeded app', async ({ page }) => {
    const seed = loadSeed();
    if (!seed.appClientId) {
      test.skip();
      return;
    }
    await page.goto(
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/applications/${seed.appClientId}`,
    );

    // Detail page renders client ID and an edit link
    await expect(page.locator('#main')).toContainText(seed.appClientId);
    await expect(page.locator('a[href*="/edit"]')).toBeVisible();
  });
});
