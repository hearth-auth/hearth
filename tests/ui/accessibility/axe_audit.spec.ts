import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { AUTH_DIR } from '../helpers/actions';
import type { SeedFixtures } from '../fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const REPORTS_DIR = path.join(__dirname, '..', 'reports');

function loadSeed(): SeedFixtures {
  const p = path.join(AUTH_DIR, 'seed.json');
  if (!fs.existsSync(p)) {
    throw new Error(`Seed not found at ${p}. Did globalSetup run?`);
  }
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as SeedFixtures;
}

/** Critical and serious violations block CI; moderate/minor are advisory. */
const BLOCKING_IMPACTS = new Set(['critical', 'serious']);

interface ViolationSummary {
  id: string;
  impact: string | null;
  description: string;
  nodes: number;
}

function summarize(v: { id: string; impact?: string | null; description: string; nodes: unknown[] }): ViolationSummary {
  return { id: v.id, impact: v.impact ?? null, description: v.description, nodes: v.nodes.length };
}

function saveAxeReport(label: string, results: unknown): void {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  fs.writeFileSync(path.join(REPORTS_DIR, `axe-${label}.json`), JSON.stringify(results, null, 2));
}

// ── Authenticated admin pages ─────────────────────────────────────────────────

// Static list — URLs are resolved inside each test body after globalSetup has run.
const ADMIN_SECTIONS = ['users', 'applications', 'groups', 'organizations', 'audit'] as const;

test.describe('Accessibility audit — admin sections', () => {
  for (const section of ADMIN_SECTIONS) {
    test(`admin/${section} — no critical/serious violations`, async ({ browser }) => {
      const seed = loadSeed();
      const context = await browser.newContext({
        storageState: path.join(AUTH_DIR, 'admin.json'),
      });
      const page = await context.newPage();

      await page.goto(`${BASE_URL}/ui/admin/realms/${seed.realmName}/${section}`);
      await page.waitForLoadState('domcontentloaded');

      const results = await new AxeBuilder({ page }).analyze();

      const blocking = results.violations.filter((v) => BLOCKING_IMPACTS.has(v.impact ?? ''));
      const advisory = results.violations.filter((v) => !BLOCKING_IMPACTS.has(v.impact ?? ''));

      if (advisory.length > 0) {
        console.warn(
          `[a11y:admin/${section}] ${advisory.length} minor/moderate violation(s) (advisory):`,
          advisory.map(summarize),
        );
      }

      saveAxeReport(`admin-${section}`, results);
      await context.close();

      expect(
        blocking.map(summarize),
        `Critical/serious a11y violations on /ui/admin/realms/…/${section}`,
      ).toHaveLength(0);
    });
  }

  test('admin/settings — no critical/serious violations', async ({ browser }) => {
    const context = await browser.newContext({
      storageState: path.join(AUTH_DIR, 'admin.json'),
    });
    const page = await context.newPage();

    await page.goto(`${BASE_URL}/ui/admin/settings`);
    await page.waitForLoadState('domcontentloaded');

    const results = await new AxeBuilder({ page }).analyze();

    const blocking = results.violations.filter((v) => BLOCKING_IMPACTS.has(v.impact ?? ''));
    const advisory = results.violations.filter((v) => !BLOCKING_IMPACTS.has(v.impact ?? ''));

    if (advisory.length > 0) {
      console.warn(
        `[a11y:admin/settings] ${advisory.length} minor/moderate violation(s) (advisory):`,
        advisory.map(summarize),
      );
    }

    saveAxeReport('admin-settings', results);
    await context.close();

    expect(
      blocking.map(summarize),
      'Critical/serious a11y violations on /ui/admin/settings',
    ).toHaveLength(0);
  });
});

// ── Public / pre-auth pages ───────────────────────────────────────────────────

const PUBLIC_PAGES = [
  { label: 'admin-login', path: '/ui/admin/login' },
  { label: 'user-login', path: '/ui/login' },
] as const;

test.describe('Accessibility audit — public pages', () => {
  for (const { label, path: pagePath } of PUBLIC_PAGES) {
    test(`${label} — no critical/serious violations`, async ({ page }) => {
      await page.goto(`${BASE_URL}${pagePath}`);
      await page.waitForLoadState('domcontentloaded');

      const results = await new AxeBuilder({ page }).analyze();

      const blocking = results.violations.filter((v) => BLOCKING_IMPACTS.has(v.impact ?? ''));
      const advisory = results.violations.filter((v) => !BLOCKING_IMPACTS.has(v.impact ?? ''));

      if (advisory.length > 0) {
        console.warn(
          `[a11y:${label}] ${advisory.length} minor/moderate violation(s) (advisory):`,
          advisory.map(summarize),
        );
      }

      saveAxeReport(label, results);

      expect(
        blocking.map(summarize),
        `Critical/serious a11y violations on ${pagePath}`,
      ).toHaveLength(0);
    });
  }
});
