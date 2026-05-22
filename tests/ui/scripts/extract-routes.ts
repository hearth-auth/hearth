/**
 * Parses src/protocol/web/mod.rs for axum::routing::get(...) route registrations
 * and emits a JSON list of declared GET paths to reports/declared-routes.json.
 *
 * Run: npx tsx scripts/extract-routes.ts
 */

import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const WEB_MOD_RS = path.join(REPO_ROOT, 'src', 'protocol', 'web', 'mod.rs');
const OUT_DIR = path.join(__dirname, '..', 'reports');
const OUT_PATH = path.join(OUT_DIR, 'declared-routes.json');

function extractGetRoutes(src: string): string[] {
  // Match .route("PATH", axum::routing::get( patterns — the path string is
  // always the first argument, immediately followed by a routing method call.
  const re =
    /\.route\(\s*"([^"]+)"\s*,\s*axum::routing::get\s*\(/g;
  const routes = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    routes.add(m[1]);
  }
  return [...routes].sort();
}

const src = fs.readFileSync(WEB_MOD_RS, 'utf-8');
const routes = extractGetRoutes(src);

fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(OUT_PATH, JSON.stringify(routes, null, 2));

console.log(`Extracted ${routes.length} GET routes → ${OUT_PATH}`);
routes.forEach((r) => console.log(`  ${r}`));
