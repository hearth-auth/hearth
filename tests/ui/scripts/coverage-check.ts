/**
 * Diffs crawl-manifest.json against declared-routes.json and emits
 * reports/coverage-gaps.txt for routes not visited during the smoke crawl.
 *
 * Non-blocking: exits 0 even when gaps are found (gaps are a warning, not a failure).
 * Run: npx tsx scripts/coverage-check.ts
 */

import * as fs from 'fs';
import * as path from 'path';

const REPORTS_DIR = path.join(__dirname, '..', 'reports');
const MANIFEST_PATH = path.join(REPORTS_DIR, 'crawl-manifest.json');
const DECLARED_PATH = path.join(REPORTS_DIR, 'declared-routes.json');
const GAPS_PATH = path.join(REPORTS_DIR, 'coverage-gaps.txt');

interface CrawlResult {
  url: string;
  status: 'pass' | 'fail';
}
interface CrawlManifest {
  visited: CrawlResult[];
}

function missingInputs(): boolean {
  if (!fs.existsSync(MANIFEST_PATH)) {
    console.warn(`Missing ${MANIFEST_PATH} — run 'make ui-test-smoke' first`);
    return true;
  }
  if (!fs.existsSync(DECLARED_PATH)) {
    console.warn(`Missing ${DECLARED_PATH} — run 'make ui-coverage-check' after extracting routes`);
    return true;
  }
  return false;
}

if (missingInputs()) process.exit(0);

const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf-8')) as CrawlManifest;
const declared = JSON.parse(fs.readFileSync(DECLARED_PATH, 'utf-8')) as string[];

// Normalise visited URLs: strip the /ui prefix (routes in mod.rs don't include it)
// and strip query/fragment
const visitedPaths = new Set(
  manifest.visited.map((v) => {
    try {
      const p = new URL(v.url).pathname;
      // Strip /ui prefix — routes in mod.rs are registered relative to /ui
      return p.replace(/^\/ui/, '') || '/';
    } catch {
      return v.url;
    }
  }),
);

// A declared route is "covered" if the visited set contains an exact match or
// a more-specific path that starts with it (handles list-vs-detail).
const gaps = declared.filter(
  (r) =>
    !visitedPaths.has(r) &&
    ![...visitedPaths].some((v) => v.startsWith(r + '/')),
);

if (gaps.length > 0) {
  fs.writeFileSync(GAPS_PATH, gaps.join('\n') + '\n');
  console.warn(`⚠ Coverage gaps (${gaps.length}) — written to ${GAPS_PATH}`);
  gaps.forEach((g) => console.warn(`  ${g}`));
} else {
  console.log('✓ No coverage gaps found.');
  if (fs.existsSync(GAPS_PATH)) fs.unlinkSync(GAPS_PATH);
}
