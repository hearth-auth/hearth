// One-off preparation of a fresh server, as the realm admin:
//
//   1. The `api` client's secret is regenerated. A secret declared in
//      hearth.yaml is stored as an Argon2id hash, which every introspection
//      would pay for; a regenerated secret is checked with one SHA-256. Its
//      mode (access_token_authorization: introspection) is declared in
//      hearth.yaml: Hearth refuses to change it at runtime (409).
//   2. Password-less users are imported through POST /admin/users/import, in
//      batches, to grow the store: emails bulk<index>@<host> for index in
//      [IMPORT_FROM, IMPORT_TO). Re-importing an existing email fails that
//      entry and changes nothing, so a range can be re-run.
//
// Step 1 runs when PREPARE_CLIENTS=1. The new secret is written to
// $PREPARE_OUT (JSON): `api_secret` (realm 1) and `api_secrets`, every realm's
// secret by its generator.env variable. Import progress goes to the summary.
//
// Several realms (STRESS_REALMS > 1): step 1 runs in every realm. The import
// splits the users [IMPORT_ALL_FROM, IMPORT_ALL_TO) (default: this job's
// range) evenly over the realms in order, in contiguous blocks; with 1M users
// and 10 realms, realm 1 gets bulk00000000..bulk00099999. cloud.sh import sets
// IMPORT_ALL_* to its whole range, so the split is the same on every generator.
//
// Env: lib.js variables, plus IMPORT_FROM (0), IMPORT_TO (0 = no import),
// IMPORT_ALL_FROM, IMPORT_ALL_TO, IMPORT_BATCH (5000, server maximum 10000),
// IMPORT_VUS (4), PREPARE_OUT.
import http from 'k6/http';
import exec from 'k6/execution';
import { Counter } from 'k6/metrics';
import { adminHeaders, adminSession, claims, env, hosts, realms } from './lib.js';
import { importBatches, realmBounds } from './realms.js';

const from = parseInt(__ENV.IMPORT_FROM || '0', 10);
const to = parseInt(__ENV.IMPORT_TO || '0', 10);
const batch = parseInt(__ENV.IMPORT_BATCH || '5000', 10);
const importVus = parseInt(__ENV.IMPORT_VUS || '4', 10);
const bounds = realms.length > 1
  ? realmBounds(
    parseInt(__ENV.IMPORT_ALL_FROM || String(from), 10),
    parseInt(__ENV.IMPORT_ALL_TO || String(to), 10),
    realms.length,
  )
  : null;
const plan = to > from ? importBatches(from, to, batch, bounds) : [];
const batches = plan.length;

const imported = new Counter('users_imported');
const importFailed = new Counter('users_import_failed');
const batchFailed = new Counter('import_batches_failed');

export const options = {
  hosts,
  setupTimeout: '5m',
  scenarios: batches > 0
    ? {
        import: {
          executor: 'shared-iterations',
          vus: Math.min(importVus, batches),
          iterations: batches,
          maxDuration: '55m',
        },
      }
    : {
        // k6 needs one scenario; this one does nothing.
        idle: { executor: 'shared-iterations', vus: 1, iterations: 1 },
      },
};

export function setup() {
  const admins = [];
  const apiSecrets = {};
  for (const r of realms) {
    const admin = adminSession(r);
    const realmId = claims(admin.access).tid.replace(/^realm_/, '');
    admins.push({ token: admin.access, realmId });
    if (__ENV.PREPARE_CLIENTS === '1') {
      const regen = http.post(
        `${env.base}/admin/applications/${r.apiClientId}/regenerate-secret`,
        null,
        { headers: adminHeaders(admin.access, realmId), timeout: '60s' },
      );
      if (regen.status !== 200) {
        const where = realms.length > 1 ? ` in realm ${r.name}` : '';
        throw new Error(`regenerate-secret${where} answered ${regen.status}: ${regen.body}`);
      }
      apiSecrets[r.secretVar] = regen.json().client_secret;
    }
  }
  return {
    admins,
    realmId: admins[0].realmId,
    apiSecret: apiSecrets[realms[0].secretVar] || null,
    apiSecrets: __ENV.PREPARE_CLIENTS === '1' ? apiSecrets : null,
  };
}

export default function (data) {
  if (batches === 0) return;
  const { start, end, realm } = plan[exec.scenario.iterationInTest];
  const admin = data.admins[realm];
  const users = [];
  for (let i = start; i < end; i++) {
    users.push({
      email: `bulk${String(i).padStart(8, '0')}@${env.host}`,
      display_name: `Bulk ${i}`,
    });
  }
  const res = http.post(`${env.base}/admin/users/import`, JSON.stringify({ users }), {
    headers: adminHeaders(admin.token, admin.realmId),
    timeout: '300s',
    tags: { name: 'import' },
  });
  if (res.status !== 200) {
    batchFailed.add(1);
    importFailed.add(users.length);
    const where = realms.length > 1 ? ` (realm ${realms[realm].name})` : '';
    console.error(`import batch ${start}..${end}${where} answered ${res.status}`);
    return;
  }
  const body = res.json();
  imported.add(body.imported);
  importFailed.add(body.failed);
}

export function handleSummary(data) {
  const out = {};
  const m = (name) => (data.metrics[name] ? data.metrics[name].values.count : 0);
  const result = {
    api_secret: data.setup_data ? data.setup_data.apiSecret : null,
    api_secrets: data.setup_data ? data.setup_data.apiSecrets : null,
    realm_id: data.setup_data ? data.setup_data.realmId : null,
    import_from: from,
    import_to: to,
    users_imported: m('users_imported'),
    users_import_failed: m('users_import_failed'),
    import_batches_failed: m('import_batches_failed'),
    duration_s: data.state.testRunDurationMs / 1000,
  };
  if (__ENV.PREPARE_OUT) out[__ENV.PREPARE_OUT] = JSON.stringify(result, null, 2);
  const shown = Object.assign({}, result, {
    api_secret: result.api_secret ? '<written>' : null,
    api_secrets: result.api_secrets ? Object.keys(result.api_secrets) : null,
  });
  out.stdout = `${JSON.stringify(shown, null, 2)}\n`;
  return out;
}
