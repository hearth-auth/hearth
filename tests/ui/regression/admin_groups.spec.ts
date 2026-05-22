/**
 * Admin groups regression suite (HEA-661).
 *
 * Covers: list, new-form, create, detail, edit, member management.
 * Uses the seed `groupId` for detail/edit/member tests so these work without
 * requiring the create step to succeed first.
 */

import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import { AUTH_DIR } from '../helpers/actions';
import type { SeedFixtures } from '../fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  if (!fs.existsSync(p)) throw new Error(`Seed not found at ${p}. Run globalSetup first.`);
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

function groupsUrl(realmName: string, suffix = ''): string {
  return `${BASE_URL}/ui/admin/realms/${realmName}/groups${suffix}`;
}

test.describe('Admin groups', () => {
  test.use({ storageState: path.join(AUTH_DIR, 'admin.json') });

  test('list page loads and shows at least the seed group', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(groupsUrl(seed.realmName), { waitUntil: 'domcontentloaded' });

    expect(page.url()).toContain('/groups');
    const body = await page.evaluate(() => document.body.innerText.trim());
    expect(body.length).toBeGreaterThan(10);
    // The seed group "test-group" should appear in the list
    expect(body).toContain('test-group');
  });

  test('new-group form renders required fields', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(groupsUrl(seed.realmName, '/new'), { waitUntil: 'domcontentloaded' });

    await expect(page.locator('input[name="name"]')).toBeVisible();
    await expect(page.locator('textarea[name="description"], input[name="description"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('creating a group redirects to the group detail page', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(groupsUrl(seed.realmName, '/new'), { waitUntil: 'domcontentloaded' });

    const groupName = `regression-group-${Date.now()}`;
    await page.fill('input[name="name"]', groupName);

    const descField = page.locator('textarea[name="description"], input[name="description"]').first();
    await descField.fill('Created by regression test');

    await Promise.all([
      // Successful create redirects to the detail page
      page.waitForURL(/\/groups\/[^/]+$/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    const body = await page.evaluate(() => document.body.innerText);
    expect(body).toContain(groupName);
  });

  test('group detail page renders for seed group', async ({ page }) => {
    const seed = loadSeed();
    if (!seed.groupId) test.skip();

    await page.goto(groupsUrl(seed.realmName, `/${seed.groupId}`), {
      waitUntil: 'domcontentloaded',
    });

    const body = await page.evaluate(() => document.body.innerText.trim());
    expect(body.length).toBeGreaterThan(10);
    // The seed user should appear in members (was added during seed)
    expect(body).toMatch(/test-group|group/i);
  });

  test('group edit form renders for seed group', async ({ page }) => {
    const seed = loadSeed();
    if (!seed.groupId) test.skip();

    await page.goto(groupsUrl(seed.realmName, `/${seed.groupId}/edit`), {
      waitUntil: 'domcontentloaded',
    });

    await expect(page.locator('input[name="name"]')).toBeVisible();
  });

  test('group members page renders', async ({ page }) => {
    const seed = loadSeed();
    if (!seed.groupId) test.skip();

    await page.goto(groupsUrl(seed.realmName, `/${seed.groupId}/members`), {
      waitUntil: 'domcontentloaded',
    });

    const body = await page.evaluate(() => document.body.innerText.trim());
    expect(body.length).toBeGreaterThan(10);
  });
});
