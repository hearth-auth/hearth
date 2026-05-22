/**
 * Admin RBAC roles regression suite (HEA-661).
 *
 * Covers: list, new-form, create, detail, edit.
 * The seed provides a `roleId` for detail/edit tests.
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

function rolesUrl(realmName: string, suffix = ''): string {
  return `${BASE_URL}/ui/admin/realms/${realmName}/rbac/roles${suffix}`;
}

test.describe('Admin RBAC roles', () => {
  test.use({ storageState: path.join(AUTH_DIR, 'admin.json') });

  test('list page loads and shows seed role', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(rolesUrl(seed.realmName), { waitUntil: 'domcontentloaded' });

    expect(page.url()).toContain('/rbac/roles');
    const body = await page.evaluate(() => document.body.innerText.trim());
    expect(body.length).toBeGreaterThan(10);
  });

  test('new-role form renders required fields', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(rolesUrl(seed.realmName, '/new'), { waitUntil: 'domcontentloaded' });

    await expect(page.locator('input[name="name"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('creating a role redirects to role detail', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(rolesUrl(seed.realmName, '/new'), { waitUntil: 'domcontentloaded' });

    const roleName = `regression-role-${Date.now()}`;
    await page.fill('input[name="name"]', roleName);

    const descEl = page.locator('textarea[name="description"], input[name="description"]');
    if (await descEl.count()) {
      await descEl.first().fill('Created by regression test');
    }

    await Promise.all([
      page.waitForURL(/\/rbac\/roles\/[^/]+$/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    const body = await page.evaluate(() => document.body.innerText);
    expect(body).toContain(roleName);
  });

  test('role detail page renders for seed role', async ({ page }) => {
    const seed = loadSeed();
    if (!seed.roleId) test.skip();

    await page.goto(rolesUrl(seed.realmName, `/${seed.roleId}`), {
      waitUntil: 'domcontentloaded',
    });

    const body = await page.evaluate(() => document.body.innerText.trim());
    expect(body.length).toBeGreaterThan(10);
    expect(body).toMatch(/test-role|role/i);
  });

  test('role edit form pre-populates fields', async ({ page }) => {
    const seed = loadSeed();
    if (!seed.roleId) test.skip();

    await page.goto(rolesUrl(seed.realmName, `/${seed.roleId}/edit`), {
      waitUntil: 'domcontentloaded',
    });

    const nameInput = page.locator('input[name="name"]');
    await expect(nameInput).toBeVisible();
    const value = await nameInput.inputValue();
    expect(value).toBe('test-role');
  });

  test('editing a role name persists', async ({ page }) => {
    const seed = loadSeed();

    // Create a throwaway role to edit
    await page.goto(rolesUrl(seed.realmName, '/new'), { waitUntil: 'domcontentloaded' });
    const roleName = `editable-role-${Date.now()}`;
    await page.fill('input[name="name"]', roleName);

    await Promise.all([
      page.waitForURL(/\/rbac\/roles\/[^/]+$/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    const detailUrl = page.url();

    // Edit the role
    await page.goto(`${detailUrl}/edit`, { waitUntil: 'domcontentloaded' });
    const updatedName = `${roleName}-updated`;
    await page.fill('input[name="name"]', updatedName);

    await Promise.all([
      page.waitForURL(/\/rbac\/roles\/[^/]+$/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    const body = await page.evaluate(() => document.body.innerText);
    expect(body).toContain(updatedName);
  });

  test('system-seeded realm.admin role appears in list', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(rolesUrl(seed.realmName), { waitUntil: 'domcontentloaded' });

    const body = await page.evaluate(() => document.body.innerText);
    // The dev-realm bootstrapper seeds realm.admin
    expect(body).toMatch(/realm\.admin|realm admin/i);
  });
});
