// Writes the ids of the first IDS_COUNT users of realm 1, one per line, to
// IDS_OUT: the working set of the #913 cold read (admin user lookup over
// 100,000 and 1M users), which stress.js reads with ADMIN_IDS_FILE. It pages
// through the product's admin user list (the adapter's listUsers, as
// stress.js's setup does for ADMIN_IDS), so it works for every product.
//
// Env: lib.js variables, IDS_COUNT (required), IDS_OUT (required).
import { adminContext, adminSession, env, hosts, product, realms, send } from './lib.js';

const want = parseInt(__ENV.IDS_COUNT || '0', 10);
if (!(want > 0)) throw new Error('IDS_COUNT must be a positive integer');
if (!__ENV.IDS_OUT) throw new Error('IDS_OUT is required');

export const options = {
  hosts,
  setupTimeout: '60m',
  scenarios: { ids: { executor: 'shared-iterations', vus: 1, iterations: 1 } },
};

export function setup() {
  const r = realms[0];
  const admin = adminSession(r);
  const a = { token: admin.access, realmId: adminContext(admin.access).realmId };
  const ids = [];
  let cursor = null;
  const started = Date.now();
  while (ids.length < want) {
    const res = send(product.listUsers(env, r, a, cursor), { tags: { phase: 'setup' } });
    if (res.status !== 200) throw new Error(`list users answered ${res.status} after ${ids.length} ids`);
    const page = product.userPage(res, cursor);
    for (const id of page.ids) if (ids.length < want) ids.push(id);
    cursor = page.next;
    if (!cursor) break;
  }
  if (ids.length < want) throw new Error(`the realm lists ${ids.length} users, fewer than ${want}`);
  return { ids, seconds: (Date.now() - started) / 1000 };
}

export default function () {}

export function handleSummary(data) {
  const d = data.setup_data || { ids: [], seconds: 0 };
  return {
    stdout: `${JSON.stringify({ ids: d.ids.length, seconds: d.seconds })}\n`,
    [__ENV.IDS_OUT]: `${d.ids.join('\n')}\n`,
  };
}
