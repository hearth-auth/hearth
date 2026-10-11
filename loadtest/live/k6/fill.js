// Grows the store with password-less users through POST /admin/users, one
// user per request, FILL_VUS requests in flight. Each generator takes its own
// range [FILL_FROM, FILL_TO), so several generators never collide.
//
// This replaces prepare.js's bulk import for large stores: the bulk import
// endpoint handles one user at a time and stayed near 270 users/s whatever
// the batch size or concurrency, while single creates ran at 800/s.
//
// Env (besides lib.js): FILL_FROM, FILL_TO, FILL_VUS (64), FILL_OUT (result JSON).
import http from 'k6/http';
import exec from 'k6/execution';
import { Counter } from 'k6/metrics';
import { adminHeaders, adminSession, claims, env, hosts, TIMEOUT } from './lib.js';

const from = parseInt(__ENV.FILL_FROM, 10);
const to = parseInt(__ENV.FILL_TO, 10);
if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
  throw new Error('FILL_FROM and FILL_TO are required, with FILL_FROM < FILL_TO');
}

const created = new Counter('fill_created');
const exists = new Counter('fill_exists');
const failed = new Counter('fill_failed');

export const options = {
  hosts,
  scenarios: {
    fill: {
      executor: 'shared-iterations',
      vus: parseInt(__ENV.FILL_VUS || '64', 10),
      iterations: to - from,
      maxDuration: '3h',
    },
  },
  // A threshold per class makes k6 keep a sub-metric for each in the summary.
  thresholds: {
    'fill_failed{cls:400}': ['count>=0'],
    'fill_failed{cls:429}': ['count>=0'],
    'fill_failed{cls:500}': ['count>=0'],
    'fill_failed{cls:503}': ['count>=0'],
    'fill_failed{cls:e1050}': ['count>=0'],
  },
};

export function setup() {
  const admin = adminSession();
  return {
    token: admin.access,
    realmId: claims(admin.access).tid.replace(/^realm_/, ''),
    startedAt: Date.now(),
  };
}

export default function (data) {
  const n = from + exec.scenario.iterationInTest;
  const email = `fill${String(n).padStart(8, '0')}@${env.host}`;
  const res = http.post(
    `${env.base}/admin/users`,
    JSON.stringify({ email, display_name: `Fill ${n}` }),
    { headers: adminHeaders(data.token, data.realmId), timeout: TIMEOUT, tags: { name: 'fill' } },
  );
  if (res.status === 201) {
    created.add(1);
  } else if (res.status === 409) {
    // A re-run over a range already filled.
    exists.add(1);
  } else {
    // By class: the HTTP status, or k6's transport error code.
    failed.add(1, { cls: res.status > 0 ? String(res.status) : `e${res.error_code}` });
  }
}

export function handleSummary(data) {
  const c = (name) => (data.metrics[name] ? data.metrics[name].values.count : 0);
  const failClasses = {};
  for (const [key, m] of Object.entries(data.metrics)) {
    const match = key.match(/^fill_failed\{cls:(.+)\}$/);
    if (match) failClasses[match[1]] = m.values.count;
  }
  const durationS = data.state.testRunDurationMs / 1000;
  const result = {
    from,
    to,
    created: c('fill_created'),
    already_existed: c('fill_exists'),
    failed: c('fill_failed'),
    fail_classes: failClasses,
    duration_s: durationS,
    created_per_s: c('fill_created') / durationS,
  };
  const text = `${JSON.stringify(result, null, 2)}\n`;
  const out = { stdout: text };
  if (__ENV.FILL_OUT) out[__ENV.FILL_OUT] = text;
  return out;
}
