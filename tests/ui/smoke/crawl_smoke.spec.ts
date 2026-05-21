import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import { crawl } from '../helpers/crawler';
import type { SeedFixtures } from '../fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const AUTH_DIR = path.join(__dirname, '..', '.auth');
const REPORTS_DIR = path.join(__dirname, '..', 'reports');

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  if (!fs.existsSync(p)) {
    throw new Error(`Seed file not found at ${p}. Ensure globalSetup ran successfully.`);
  }
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

test.describe('Admin crawler smoke', () => {
  test('crawls all admin-reachable pages without errors', async ({ browser }) => {
    const seed = loadSeed();
    const context = await browser.newContext({
      storageState: path.join(AUTH_DIR, 'admin.json'),
    });

    // Core entry points — the crawler discovers further pages from these
    const entryPoints: string[] = [
      `${BASE_URL}/ui`,
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/users`,
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/applications`,
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/groups`,
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/organizations`,
      `${BASE_URL}/ui/admin/realms/${seed.realmName}/audit`,
      `${BASE_URL}/ui/admin/settings`,
    ];

    // Seed IDs give us concrete detail pages (not just lists)
    if (seed.userId) {
      entryPoints.push(
        `${BASE_URL}/ui/admin/realms/${seed.realmName}/users/${seed.userId}`,
      );
    }
    if (seed.appClientId) {
      entryPoints.push(
        `${BASE_URL}/ui/admin/realms/${seed.realmName}/applications/${seed.appClientId}`,
      );
    }
    if (seed.groupId) {
      entryPoints.push(
        `${BASE_URL}/ui/admin/realms/${seed.realmName}/groups/${seed.groupId}`,
      );
    }

    const manifest = await crawl(
      context,
      entryPoints,
      path.join(REPORTS_DIR, 'crawl-manifest.json'),
    );

    await context.close();

    const failures = manifest.visited.filter((r) => r.status === 'fail');
    expect(
      failures,
      `${failures.length} page(s) failed:\n${JSON.stringify(failures, null, 2)}`,
    ).toHaveLength(0);

    expect(manifest.visited.length, 'Expected at least one page to be visited').toBeGreaterThan(0);
  });
});

test.describe('Public pages smoke', () => {
  test('pre-auth pages are accessible and non-empty', async ({ browser }) => {
    // No storageState — simulates an unauthenticated visitor
    const context = await browser.newContext();

    const manifest = await crawl(
      context,
      [
        `${BASE_URL}/ui/admin/login`,
        `${BASE_URL}/ui/login`,
      ],
      path.join(REPORTS_DIR, 'crawl-manifest-public.json'),
    );

    await context.close();

    const failures = manifest.visited.filter((r) => r.status === 'fail');
    expect(
      failures,
      `${failures.length} public page(s) failed:\n${JSON.stringify(failures, null, 2)}`,
    ).toHaveLength(0);
  });
});
