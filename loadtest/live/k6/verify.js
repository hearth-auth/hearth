// Durability check after a crash or restart: every user that a create_user
// ramp saw acknowledged (201) must still exist. Reads the "ACK <id>" lines
// that stress.js wrote to its console output, then GETs each id.
//
//   missing  404: an acknowledged write was lost. Must be 0.
//   errors   any other failure: the check could not decide; re-run it.
//
// Env (besides lib.js): ACK_FILE (k6 --console-output of the create_user
// ramp), VERIFY_VUS (16), VERIFY_OUT (result JSON).
import http from 'k6/http';
import exec from 'k6/execution';
import { SharedArray } from 'k6/data';
import { Counter } from 'k6/metrics';
import { adminHeaders, adminSession, claims, env, hosts, TIMEOUT } from './lib.js';

const ids = new SharedArray('acked', () => {
  const text = open(__ENV.ACK_FILE);
  const out = [];
  const re = /ACK ([0-9a-f-]{36})/g;
  let m;
  while ((m = re.exec(text)) !== null) out.push(m[1]);
  return out;
});

const found = new Counter('verify_found');
const missing = new Counter('verify_missing');
const errors = new Counter('verify_errors');

export const options = {
  hosts,
  scenarios: {
    verify: {
      executor: 'shared-iterations',
      vus: Math.max(1, Math.min(parseInt(__ENV.VERIFY_VUS || '16', 10), ids.length)),
      iterations: Math.max(1, ids.length),
      maxDuration: '50m',
    },
  },
  thresholds: {
    verify_missing: ['count==0'],
    verify_errors: ['count==0'],
  },
};

export function setup() {
  const admin = adminSession();
  return { token: admin.access, realmId: claims(admin.access).tid.replace(/^realm_/, '') };
}

export default function (data) {
  if (ids.length === 0) return;
  const id = ids[exec.scenario.iterationInTest];
  const res = http.get(`${env.base}/admin/users/${id}`, {
    headers: adminHeaders(data.token, data.realmId),
    timeout: TIMEOUT,
    tags: { name: 'verify' },
  });
  if (res.status === 200) {
    found.add(1);
  } else if (res.status === 404) {
    missing.add(1);
    console.error(`MISSING ${id}`);
  } else {
    errors.add(1);
  }
}

export function handleSummary(data) {
  const c = (name) => (data.metrics[name] ? data.metrics[name].values.count : 0);
  const result = {
    acknowledged: ids.length,
    found: c('verify_found'),
    missing: c('verify_missing'),
    errors: c('verify_errors'),
  };
  const text = `${JSON.stringify(result, null, 2)}\n`;
  const out = { stdout: text };
  if (__ENV.VERIFY_OUT) out[__ENV.VERIFY_OUT] = text;
  return out;
}
