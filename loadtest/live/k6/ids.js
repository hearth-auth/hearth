// The working set of the #913 cold read (admin user lookup over 100,000 and
// 1M users), which stress.js reads with ADMIN_IDS_FILE, and the seed's check
// that the admin API serves it. One job per run, by the environment:
//
//   IDS_OUT=<file>    list: writes the ids of the first IDS_COUNT users of
//                     realm 1, one per line, paging through the product's
//                     admin user list (the adapter's listUsers, as stress.js's
//                     setup does for ADMIN_IDS). compare.sh lists Hearth's and
//                     Ory's this way (their admin APIs page by cursor); the
//                     other products' ids come from their store, in their admin
//                     API's order (<product>.sh ids), as their offset paging
//                     through 1M users takes from about 45 min (Keycloak, 2
//                     vCPUs) to more than a day (Authentik).
//   IDS_CHECK=<file>  check: looks up each id of the file (one per line)
//                     through the admin API with the cold read's own request
//                     (the adapter's adminUser) and fails unless every lookup
//                     answers 200: the seed's "usable" rule, the same for every
//                     product (compare.sh hands it the first and every 1,000th
//                     of the 1M ids).
//
// Env: lib.js variables, and IDS_COUNT and IDS_OUT, or IDS_CHECK.
import { adminContext, adminSession, env, hosts, product, realms, send } from './lib.js';

const checkFile = __ENV.IDS_CHECK || '';
const toCheck = checkFile ? open(checkFile).split('\n').filter((l) => l !== '') : null;
const want = parseInt(__ENV.IDS_COUNT || '0', 10);
if (toCheck === null) {
  if (!(want > 0)) throw new Error('IDS_COUNT must be a positive integer');
  if (!__ENV.IDS_OUT) throw new Error('IDS_OUT (list) or IDS_CHECK (check) is required');
} else if (toCheck.length === 0) {
  throw new Error(`no user ids in ${checkFile}`);
}

export const options = {
  hosts,
  setupTimeout: '60m',
  scenarios: { ids: { executor: 'shared-iterations', vus: 1, iterations: 1 } },
};

function list(r, a) {
  const ids = [];
  let cursor = null;
  while (ids.length < want) {
    const res = send(product.listUsers(env, r, a, cursor), { tags: { phase: 'setup' } });
    if (res.status !== 200) throw new Error(`list users answered ${res.status} after ${ids.length} ids`);
    const page = product.userPage(res, cursor);
    for (const id of page.ids) if (ids.length < want) ids.push(id);
    cursor = page.next;
    if (!cursor) break;
  }
  if (ids.length < want) throw new Error(`the realm lists ${ids.length} users, fewer than ${want}`);
  return ids;
}

function check(r, a) {
  toCheck.forEach((id, i) => {
    const res = send(product.adminUser(env, r, a, id), { tags: { phase: 'setup' } });
    if (res.status !== 200) {
      throw new Error(`the admin API answered ${res.status} for id ${i + 1} of ${toCheck.length} (${id})`);
    }
  });
  return toCheck.length;
}

export function setup() {
  const r = realms[0];
  const admin = adminSession(r);
  const a = { token: admin.access, realmId: adminContext(admin.access).realmId };
  const started = Date.now();
  if (toCheck !== null) return { checked: check(r, a), seconds: (Date.now() - started) / 1000 };
  return { ids: list(r, a), seconds: (Date.now() - started) / 1000 };
}

export default function () {}

export function handleSummary(data) {
  const d = data.setup_data || {};
  if (toCheck !== null) {
    return { stdout: `${JSON.stringify({ checked: d.checked || 0, seconds: d.seconds || 0 })}\n` };
  }
  const ids = d.ids || [];
  return {
    stdout: `${JSON.stringify({ ids: ids.length, seconds: d.seconds || 0 })}\n`,
    [__ENV.IDS_OUT]: `${ids.join('\n')}\n`,
  };
}
