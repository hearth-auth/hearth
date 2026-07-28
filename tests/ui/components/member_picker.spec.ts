import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import { AUTH_DIR } from '../helpers/actions';
import { instrumentPage, assertPageClean } from '../helpers/assertions';
import type { SeedFixtures } from '../fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

test.use({ storageState: path.join(AUTH_DIR, 'admin.json') });

test.describe('Member picker component (group detail — members tab)', () => {
  test.beforeEach(async ({ page }) => {
    instrumentPage(page);
    const seed = loadSeed();
    // seedTestData always creates test-group, so a missing groupId is a seeding
    // failure — fail loudly instead of silently skipping (which would hide the
    // broken setup as a green CI run).
    if (!seed.groupId) {
      throw new Error(
        'seed.groupId is empty — group seeding failed in fixtures/seed.ts. ' +
          'The member-picker tests cannot run without a seeded group.',
      );
    }
    await page.goto(
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/groups/${seed.groupId}?tab=members`,
    );
    await expect(page.locator('#member-picker-results')).toBeVisible();
  });

  test.afterEach(async ({ page }) => {
    assertPageClean(page);
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
    // First type a query so clearing it actually fires the "input changed" HTMX
    // trigger (an already-empty field would emit no change event).
    await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes('/members/picker') && r.url().includes('q=test') && r.status() === 200,
        { timeout: 10_000 },
      ),
      page.fill('#member_search', 'test'),
    ]);

    // Now clear the field and wait for the empty-query HTMX response to swap the
    // container — asserting the freshly-rendered state, not a stale pre-render.
    const [emptyResp] = await Promise.all([
      page.waitForResponse(
        (r) =>
          r.url().includes('/members/picker') &&
          new URL(r.url()).searchParams.get('q') === '' &&
          r.status() === 200,
        { timeout: 10_000 },
      ),
      page.fill('#member_search', ''),
    ]);

    expect(emptyResp.status()).toBe(200);
    // The container shows either candidate users or the "all already members" copy.
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

    // Target the first candidate row's form so we can read the user's identity
    // before adding them, then assert that same identity lands in the table.
    const firstRow = page.locator('#member-picker-results form').first();

    if ((await firstRow.count()) === 0) {
      // Legitimate runtime state: every realm user is already a member, so the
      // picker shows "All realm users are already members" and there is nothing
      // to add. Skip with a descriptive reason rather than a silent skip.
      test.skip(true, 'No addable candidates — all realm users are already group members');
      return;
    }

    // Capture the candidate's email (unique per user) from the picker row.
    const addedEmail = (
      await firstRow.locator('.text-ht-content-muted').first().innerText()
    ).trim();
    expect(addedEmail, 'Expected to read the candidate user email from the picker row').toBeTruthy();

    // Submit the add-member form and wait for the full page reload
    await Promise.all([
      page.waitForURL(
        (url) => url.href.includes(`/groups/${seed.groupId}`),
        { timeout: 15_000 },
      ),
      firstRow.locator('button[type="submit"]').click(),
    ]);

    // The specific user we added must now appear in the members table — asserting
    // presence of the added row, not merely the absence of the empty-state row.
    await expect(page.locator('table tbody')).toContainText(addedEmail, { timeout: 10_000 });
  });
});
