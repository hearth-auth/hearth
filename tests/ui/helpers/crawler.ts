import * as fs from 'fs';
import * as path from 'path';
import type { BrowserContext, ConsoleMessage, Response } from '@playwright/test';
import {
  assertNoFailedRequests,
  assertPageNonEmpty,
} from './assertions';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

// Hard cap so a deeply-linked admin panel never causes a timeout.
const MAX_PAGES = 150;

export interface CrawlResult {
  url: string;
  status: 'pass' | 'fail';
  title?: string;
  error?: string;
}

export interface CrawlManifest {
  baseUrl: string;
  startedAt: string;
  finishedAt: string;
  pagesVisited: number;
  failures: number;
  visited: CrawlResult[];
}

// URL patterns that map to destructive or non-navigable actions
const SKIP_PATTERNS = [
  /\/logout/,
  /\/delete/,
  /\/revoke/,
  /\/disable/,
  /\/remove/,
  /\/reset(?!-password$)/,  // keep /reset-password, skip generic /reset
  /\/export/,
  /\/import/,
  /\/backup/,
  /\/passkey-(?:begin|complete)/,
  /\/dev\/mail/,
  /\/metrics/,
  /\.(?:txt|csv|json)$/,
];

function shouldSkip(url: string): boolean {
  // Skip non-origin and protocol links
  if (!url.startsWith(BASE_URL) && !url.startsWith('/')) return true;
  return SKIP_PATTERNS.some((p) => p.test(url));
}

function toAbsolute(href: string): string {
  return href.startsWith('http') ? href : `${BASE_URL}${href}`;
}

/** Strip query/hash for dedup purposes */
function dedup(url: string): string {
  return url.split(/[?#]/)[0];
}

/**
 * Breadth-first link crawler. Visits each discovered page once, runs smoke
 * assertions, and collects same-origin links for further crawling.
 *
 * Reuses a single browser page across all navigations to avoid per-URL tab
 * creation overhead. Response and console listeners are attached and removed
 * per navigation so each URL gets a clean collector.
 *
 * Links marked `data-crawl-skip` are excluded via CSS selector on collection.
 * Emits a crawl-manifest.json at `manifestPath` when done.
 */
export async function crawl(
  context: BrowserContext,
  entryPoints: string[],
  manifestPath: string,
): Promise<CrawlManifest> {
  const visited = new Set<string>();
  const queue: string[] = entryPoints.map(toAbsolute);
  const results: CrawlResult[] = [];
  const startedAt = new Date().toISOString();

  // Single reused page — avoids browser-tab creation overhead on every URL.
  let page = await context.newPage();

  while (queue.length > 0 && results.length < MAX_PAGES) {
    const url = queue.shift()!;
    const key = dedup(url);
    if (visited.has(key)) continue;
    visited.add(key);

    // Fresh per-navigation collectors, attached and removed explicitly.
    const failedResponses: Response[] = [];
    const consoleErrors: string[] = [];

    const onResponse = (r: Response) => failedResponses.push(r);
    const onConsole = (msg: ConsoleMessage) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    };

    page.on('response', onResponse);
    page.on('console', onConsole);

    try {
      const resp = await page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout: 10_000,
      });

      if (!resp || resp.status() >= 400) {
        results.push({
          url,
          status: 'fail',
          error: `HTTP ${resp?.status() ?? 'no response'}`,
        });
        continue;
      }

      await assertPageNonEmpty(page);
      if (consoleErrors.length > 0) {
        throw new Error(`Console errors on ${url}:\n${consoleErrors.join('\n')}`);
      }
      assertNoFailedRequests(failedResponses, url);

      const title = await page.title();
      results.push({ url, status: 'pass', title });

      // Collect same-origin links, excluding data-crawl-skip anchors
      const links = (await page.evaluate((base) => {
        return Array.from(
          document.querySelectorAll<HTMLAnchorElement>(
            'a[href]:not([data-crawl-skip])',
          ),
        )
          .map((a) => a.getAttribute('href') ?? '')
          .filter((h) => h.startsWith('/') || h.startsWith(base));
      }, BASE_URL)) as string[];

      for (const link of links) {
        const abs = toAbsolute(link);
        const k = dedup(abs);
        if (!visited.has(k) && !queue.includes(k) && !shouldSkip(abs)) {
          queue.push(abs);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      results.push({ url, status: 'fail', error: msg });

      // Screenshot on failure for diagnosis
      try {
        const screenshotDir = path.join(path.dirname(manifestPath), 'screenshots');
        fs.mkdirSync(screenshotDir, { recursive: true });
        const safe = key.replace(/[^a-z0-9]/gi, '_').slice(0, 80);
        await page.screenshot({
          path: path.join(screenshotDir, `${safe}.png`),
          fullPage: false,
        });
      } catch {
        // Screenshot failure is non-fatal
      }

      // If the page is in a crashed/unusable state, replace it so subsequent
      // URLs still get a working page.
      if (msg.includes('crashed') || msg.includes('Target closed')) {
        try { await page.close(); } catch { /* already closed */ }
        page = await context.newPage();
        continue; // handlers already removed by the page being replaced
      }
    } finally {
      page.off('response', onResponse);
      page.off('console', onConsole);
    }
  }

  await page.close();

  const manifest: CrawlManifest = {
    baseUrl: BASE_URL,
    startedAt,
    finishedAt: new Date().toISOString(),
    pagesVisited: results.length,
    failures: results.filter((r) => r.status === 'fail').length,
    visited: results,
  };

  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  return manifest;
}
