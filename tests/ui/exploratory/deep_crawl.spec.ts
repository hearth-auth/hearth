/**
 * Exploratory deep crawl — non-blocking.
 *
 * Extends the smoke crawl with:
 *   - Pagination link discovery (href containing `?page=`)
 *   - Form inventory per page (elements logged, not submitted)
 *   - Issues written to reports/deep-crawl-gaps.txt for artifact upload
 *
 * The test always passes structurally (expects at least one page visited).
 * The CI job uses `continue-on-error: true` so failures are visible but
 * do not block the gate. Review the artifact to address gaps.
 */

import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import type { BrowserContext, Response } from '@playwright/test';
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

interface DeepCrawlResult {
  url: string;
  status: 'pass' | 'fail';
  title?: string;
  forms?: number;
  error?: string;
}

interface DeepCrawlManifest {
  baseUrl: string;
  startedAt: string;
  finishedAt: string;
  pagesVisited: number;
  failures: number;
  totalForms: number;
  visited: DeepCrawlResult[];
}

// Patterns skipped by the deep crawl (same safety policy as smoke)
const SKIP_PATTERNS = [
  /\/logout/,
  /\/delete/,
  /\/revoke/,
  /\/disable/,
  /\/remove/,
  /\/reset(?!-password$)/,
  /\/export/,
  /\/import/,
  /\/backup/,
  /\/passkey-(?:begin|complete)/,
  /\/dev\/mail/,
  /\/metrics/,
  /\.(?:txt|csv|json)$/,
];

function shouldSkip(url: string): boolean {
  if (!url.startsWith(BASE_URL) && !url.startsWith('/')) return true;
  return SKIP_PATTERNS.some((p) => p.test(url));
}

function toAbsolute(href: string): string {
  return href.startsWith('http') ? href : `${BASE_URL}${href}`;
}

/** For the deep crawl we preserve query params to follow pagination. */
function dedupKey(url: string): string {
  // Strip fragment only; keep query string so ?page=2 counts as distinct
  return url.split('#')[0];
}

async function deepCrawl(
  context: BrowserContext,
  entryPoints: string[],
  manifestPath: string,
): Promise<DeepCrawlManifest> {
  const visited = new Set<string>();
  const queue: string[] = entryPoints.map(toAbsolute);
  const results: DeepCrawlResult[] = [];
  const startedAt = new Date().toISOString();

  while (queue.length > 0) {
    const url = queue.shift()!;
    const key = dedupKey(url);
    if (visited.has(key)) continue;
    visited.add(key);

    const page = await context.newPage();
    const failedResponses: Response[] = [];
    page.on('response', (r) => {
      if (r.status() >= 500) failedResponses.push(r);
    });

    try {
      const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15_000 });

      if (!resp || resp.status() >= 400) {
        results.push({ url, status: 'fail', error: `HTTP ${resp?.status() ?? 'no response'}` });
        await page.close();
        continue;
      }

      const title = await page.title();

      // Count forms for coverage inventory
      const forms = await page.locator('form').count();

      results.push({ url, status: 'pass', title, forms });

      // Collect standard navigation links (same-origin, no query strip)
      const navLinks = (await page.evaluate((base) => {
        return Array.from(
          document.querySelectorAll<HTMLAnchorElement>('a[href]:not([data-crawl-skip])'),
        )
          .map((a) => a.getAttribute('href') ?? '')
          .filter((h) => h.startsWith('/') || h.startsWith(base));
      }, BASE_URL)) as string[];

      // Collect pagination-specific links (?page=N)
      const paginationLinks = (await page.evaluate((base) => {
        return Array.from(
          document.querySelectorAll<HTMLAnchorElement>('a[href*="?page="], a[href*="&page="]'),
        )
          .map((a) => a.getAttribute('href') ?? '')
          .filter((h) => h.startsWith('/') || h.startsWith(base));
      }, BASE_URL)) as string[];

      for (const link of [...navLinks, ...paginationLinks]) {
        const abs = toAbsolute(link);
        const k = dedupKey(abs);
        if (!visited.has(k) && !queue.includes(k) && !shouldSkip(abs)) {
          queue.push(abs);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      results.push({ url, status: 'fail', error: msg });

      try {
        const screenshotDir = path.join(path.dirname(manifestPath), 'screenshots-deep');
        fs.mkdirSync(screenshotDir, { recursive: true });
        const safe = key.replace(/[^a-z0-9]/gi, '_').slice(0, 80);
        await page.screenshot({ path: path.join(screenshotDir, `${safe}.png`), fullPage: false });
      } catch {
        // Screenshot failure is non-fatal
      }
    } finally {
      await page.close();
    }
  }

  const totalForms = results.reduce((sum, r) => sum + (r.forms ?? 0), 0);
  const manifest: DeepCrawlManifest = {
    baseUrl: BASE_URL,
    startedAt,
    finishedAt: new Date().toISOString(),
    pagesVisited: results.length,
    failures: results.filter((r) => r.status === 'fail').length,
    totalForms,
    visited: results,
  };

  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  return manifest;
}

// ── Test ──────────────────────────────────────────────────────────────────────

test.describe('Exploratory deep crawl', () => {
  test(
    'discovers all pages including pagination — non-blocking',
    async ({ browser }) => {
      const seed = loadSeed();
      const context = await browser.newContext({
        storageState: path.join(AUTH_DIR, 'admin.json'),
      });

      const entryPoints = [
        `${BASE_URL}/ui`,
        `${BASE_URL}/ui/admin/realms/${seed.realmName}/users`,
        `${BASE_URL}/ui/admin/realms/${seed.realmName}/applications`,
        `${BASE_URL}/ui/admin/realms/${seed.realmName}/groups`,
        `${BASE_URL}/ui/admin/realms/${seed.realmName}/organizations`,
        `${BASE_URL}/ui/admin/realms/${seed.realmName}/audit`,
        `${BASE_URL}/ui/admin/settings`,
      ];

      // Add detail pages when seed IDs are present
      if (seed.userId) {
        entryPoints.push(`${BASE_URL}/ui/admin/realms/${seed.realmName}/users/${seed.userId}`);
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

      const manifestPath = path.join(REPORTS_DIR, 'deep-crawl-manifest.json');
      const manifest = await deepCrawl(context, entryPoints, manifestPath);

      await context.close();

      // Write gaps file — uploaded as CI artifact regardless of result
      const failures = manifest.visited.filter((r) => r.status === 'fail');
      const gapsPath = path.join(REPORTS_DIR, 'deep-crawl-gaps.txt');
      fs.mkdirSync(REPORTS_DIR, { recursive: true });
      fs.writeFileSync(
        gapsPath,
        failures.length === 0
          ? '# No gaps found\n'
          : failures.map((f) => `FAIL ${f.url}: ${f.error ?? 'unknown'}`).join('\n') + '\n',
      );

      if (failures.length > 0) {
        console.warn(
          `[deep-crawl] ${failures.length} page(s) with issues (non-blocking — see deep-crawl-gaps.txt):`,
          failures.map((f) => `${f.url}: ${f.error}`),
        );
      }

      console.info(
        `[deep-crawl] visited=${manifest.pagesVisited} failures=${manifest.failures} forms=${manifest.totalForms}`,
      );

      // Structural check only — deep crawl is always non-blocking on content failures
      expect(manifest.pagesVisited, 'Expected at least one page to be visited').toBeGreaterThan(0);
    },
  );
});
