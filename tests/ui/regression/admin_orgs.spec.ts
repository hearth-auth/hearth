/**
 * Admin organizations regression suite (HEA-661).
 *
 * Covers: list, new-form, create, detail, edit, member management.
 * Creates an org inline (no seed fixture) since the REST API has no /admin/organizations route.
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

function orgsUrl(realmName: string, suffix = ''): string {
  return `${BASE_URL}/ui/admin/realms/${realmName}/organizations${suffix}`;
}

test.describe('Admin organizations', () => {
  test.use({ storageState: path.join(AUTH_DIR, 'admin.json') });

  test('list page loads', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(orgsUrl(seed.realmName), { waitUntil: 'domcontentloaded' });

    expect(page.url()).toContain('/organizations');
    const body = await page.evaluate(() => document.body.innerText.trim());
    expect(body.length).toBeGreaterThan(10);
  });

  test('new-org form renders required fields', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(orgsUrl(seed.realmName, '/new'), { waitUntil: 'domcontentloaded' });

    await expect(page.locator('input[name="name"]')).toBeVisible();
    await expect(page.locator('input[name="slug"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('creating an org redirects to org detail and shows the org name', async ({ page }) => {
    const seed = loadSeed();
    await page.goto(orgsUrl(seed.realmName, '/new'), { waitUntil: 'domcontentloaded' });

    const orgName = `Regression Org ${Date.now()}`;
    const slug = `regression-org-${Date.now()}`;

    await page.fill('input[name="name"]', orgName);
    await page.fill('input[name="slug"]', slug);

    await Promise.all([
      page.waitForURL(/\/organizations\/[^/]+$/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    const body = await page.evaluate(() => document.body.innerText);
    expect(body).toContain(orgName);
  });

  test('created org detail page shows members tab', async ({ page }) => {
    const seed = loadSeed();

    // Create a fresh org to inspect
    await page.goto(orgsUrl(seed.realmName, '/new'), { waitUntil: 'domcontentloaded' });

    const slug = `member-test-${Date.now()}`;
    await page.fill('input[name="name"]', `Member Test Org ${Date.now()}`);
    await page.fill('input[name="slug"]', slug);

    await Promise.all([
      page.waitForURL(/\/organizations\/[^/]+$/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    // The detail page should have a link to /members
    const membersLink = page.locator('a[href*="members"]');
    await expect(membersLink.first()).toBeVisible();
  });

  test('org members page is reachable from detail', async ({ page }) => {
    const seed = loadSeed();

    await page.goto(orgsUrl(seed.realmName, '/new'), { waitUntil: 'domcontentloaded' });
    const slug = `members-page-${Date.now()}`;
    await page.fill('input[name="name"]', `Members Page Org ${Date.now()}`);
    await page.fill('input[name="slug"]', slug);

    await Promise.all([
      page.waitForURL(/\/organizations\/[^/]+$/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    // Navigate to members sub-page via URL manipulation
    const orgUrl = page.url();
    await page.goto(`${orgUrl}/members`, { waitUntil: 'domcontentloaded' });

    expect(page.url()).toContain('/members');
    const body = await page.evaluate(() => document.body.innerText.trim());
    expect(body.length).toBeGreaterThan(10);
  });

  test('org edit form renders and can update org name', async ({ page }) => {
    const seed = loadSeed();

    // Create org
    await page.goto(orgsUrl(seed.realmName, '/new'), { waitUntil: 'domcontentloaded' });
    const slug = `edit-test-${Date.now()}`;
    const originalName = `Edit Test Org ${Date.now()}`;
    await page.fill('input[name="name"]', originalName);
    await page.fill('input[name="slug"]', slug);

    await Promise.all([
      page.waitForURL(/\/organizations\/[^/]+$/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    const detailUrl = page.url();

    // Edit org
    await page.goto(`${detailUrl}/edit`, { waitUntil: 'domcontentloaded' });
    await expect(page.locator('input[name="name"]')).toBeVisible();

    const updatedName = `${originalName} (updated)`;
    await page.fill('input[name="name"]', updatedName);

    await Promise.all([
      page.waitForURL(/\/organizations\/[^/]+$/, { timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    const body = await page.evaluate(() => document.body.innerText);
    expect(body).toContain(updatedName);
  });
});
