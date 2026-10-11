// Open-loop stress ramp against one production-mode Hearth server.
//
// The generator offers a fixed arrival rate that steps up until Hearth
// fails: k6's ramping-arrival-rate executor starts each iteration on
// schedule, whether or not earlier ones have finished. A slow server
// therefore cannot slow the offered load down (no coordinated omission).
// When every VU is busy, k6 drops the iteration and counts it in
// `dropped_iterations`; the analysis reports that as load the generator
// could not deliver.
//
// One iteration is one journey:
//   introspect    POST /realms/<r>/introspect as the `api` resource server
//   userinfo      GET  /realms/<r>/userinfo with a user access token
//   refresh       POST /realms/<r>/token grant_type=refresh_token (rotation)
//   login         hosted login form + authorization code + PKCE (4 requests,
//                 one Argon2id password check)
//   admin_lookup  GET  /admin/users/<id> as the realm admin
//   create_user   POST /admin/users as the realm admin (one durable write);
//                 each acknowledged user is logged as "ACK <id>" for verify.js
//   mix           a weighted mix of the above, from MIX
//
// Every iteration is tagged with its step (`step`) and whether the step was
// ramping up or holding (`phase`), so the analysis can use hold periods only.
//
// Env (besides lib.js): JOURNEY, START_RATE, STEP_RATE, STEPS, HOLD_S (60),
// RAMP_S (5), VUS (1000), POOL (sessions to sign in for the token pool,
// default VUS), ADMIN_IDS (user ids to sample, 1000), MIX
// ("refresh:65,login:15,userinfo:15,admin_lookup:5"), ABORT_FAIL_RATIO (0.5),
// RUN_ID (a label for created users), START_AT (epoch seconds: with several
// generators, each waits after its setup until this moment, so their ramps
// start together), CHAIN_REFRESHES (0: after this many refreshes, a VU signs
// in again and starts a new chain, so a soak keeps making new token families;
// 0 = never), PRESENT (pool: the tokens userinfo and introspect present;
// see userToken()).
//
// Tokens never expire under a run: each VU replaces a token when 10 to 25 % of
// its lifetime is left (a fraction each VU draws once), by a sign-in tagged
// name=renew. A ramp ends before its tokens get near their expiry, so this does
// not change ramps.
import { sleep } from 'k6';
import http from 'k6/http';
import exec from 'k6/execution';
import { Counter, Rate, Trend } from 'k6/metrics';
import {
  adminHeaders,
  adminSession,
  apiBasic,
  claims,
  env,
  hosts,
  signIn,
  signInMany,
  TIMEOUT,
  userEmail,
} from './lib.js';

const JOURNEYS = ['introspect', 'userinfo', 'refresh', 'login', 'admin_lookup', 'create_user'];
const journey = __ENV.JOURNEY;
if (!JOURNEYS.includes(journey) && journey !== 'mix') {
  throw new Error(`JOURNEY must be one of ${JOURNEYS.join(', ')}, mix`);
}

const startRate = num('START_RATE');
const stepRate = num('STEP_RATE');
const steps = num('STEPS');
const holdS = num('HOLD_S', 60);
const rampS = num('RAMP_S', 5);
const vus = num('VUS', 1000);
// Refresh needs one chain per VU; the other token journeys share 50 sessions.
const pool = num('POOL', (__ENV.JOURNEY === 'refresh' || __ENV.JOURNEY === 'mix') ? vus : 50);
const setupParallel = num('SETUP_PARALLEL', 4);
const adminIds = num('ADMIN_IDS', 1000);
const abortRatio = parseFloat(__ENV.ABORT_FAIL_RATIO || '0.5');
const runId = __ENV.RUN_ID || `${Date.now()}`;
const stepS = rampS + holdS;
const chainRefreshes = num('CHAIN_REFRESHES', 0);
const present = __ENV.PRESENT || 'pool';
if (!['pool', 'chain'].includes(present)) throw new Error('PRESENT must be pool or chain');
// Init code runs once per VU, so each VU draws its own fraction and the VUs
// do not all sign in again at the same moment.
const renewFraction = 0.1 + Math.random() * 0.15;

function num(name, dflt) {
  const raw = __ENV[name];
  if (raw === undefined || raw === '') {
    if (dflt === undefined) throw new Error(`environment variable ${name} is required`);
    return dflt;
  }
  const v = parseInt(raw, 10);
  if (!Number.isFinite(v) || v < 0) throw new Error(`${name} must be a non-negative integer`);
  return v;
}

const mix = (__ENV.MIX || 'refresh:65,login:15,userinfo:15,admin_lookup:5')
  .split(',')
  .map((p) => {
    const [name, w] = p.split(':');
    if (!JOURNEYS.includes(name)) throw new Error(`MIX names unknown journey ${name}`);
    return { name, weight: parseFloat(w) };
  });
const mixTotal = mix.reduce((s, m) => s + m.weight, 0);
const needsTokens = (j) => ['introspect', 'userinfo', 'refresh'].includes(j);
const uses = journey === 'mix' ? mix.map((m) => m.name) : [journey];

// One journey's latency: the sum of its requests' durations, in ms.
const journeyMs = new Trend('journey_ms', true);
// 1 when the journey succeeded, 0 when it failed.
const journeyOk = new Rate('journey_ok');
// Failed journeys by class (HTTP status, or k6's transport error code).
const journeyFail = new Counter('journey_fail');
// Refresh chains restarted by a fresh sign-in after an unknown outcome.
const relogins = new Counter('refresh_relogins');
// Refresh chains restarted by a fresh sign-in after CHAIN_REFRESHES refreshes.
const rotations = new Counter('chain_rotations');
// Sign-ins that replace a token before it expires.
const renewals = new Counter('token_renewals');

function stages() {
  const out = [];
  for (let i = 0; i < steps; i++) {
    const target = startRate + i * stepRate;
    out.push({ duration: `${rampS}s`, target });
    out.push({ duration: `${holdS}s`, target });
  }
  return out;
}

export const options = {
  hosts,
  setupTimeout: '45m',
  // Per-request rows go to the CSV output; keep the end-of-test summary
  // small and exact.
  summaryTrendStats: ['count', 'min', 'med', 'p(90)', 'p(99)', 'p(99.9)', 'max'],
  scenarios: {
    stress: {
      executor: 'ramping-arrival-rate',
      startRate,
      timeUnit: '1s',
      preAllocatedVUs: vus,
      maxVUs: vus,
      stages: stages(),
      gracefulStop: '15s',
    },
  },
};

export function setup() {
  const admin = adminSession();
  const realmId = claims(admin.access).tid.replace(/^realm_/, '');
  const data = {
    admin: admin.access,
    adminLife: life(admin.access),
    realmId,
    sessions: [],
    userIds: [],
  };

  if (uses.some(needsTokens)) {
    if (uses.includes('refresh') && pool < vus) {
      throw new Error('POOL must be >= VUS: each VU owns one refresh chain');
    }
    const emails = [];
    for (let i = 0; i < pool; i++) emails.push(userEmail((i % env.loginUsers) + 1));
    const r = signInMany(emails, env.userPassword, setupParallel);
    // A few users may stay shed by the KDF gate. A refresh VU without a
    // session signs in at its first iteration (counted as a relogin).
    if (r.sessions.length < Math.ceil(pool * 0.9)) {
      throw new Error(`token pool: ${r.failed} of ${pool} sign-ins failed`);
    }
    data.sessions = r.sessions.map((s) => Object.assign(life(s.access), s));
  }
  if (uses.includes('admin_lookup')) {
    let cursor = null;
    while (data.userIds.length < adminIds) {
      const url = `${env.base}/admin/users?limit=200${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
      const res = http.get(url, { headers: adminHeaders(admin.access, realmId), tags: { phase: 'setup' } });
      if (res.status !== 200) throw new Error(`list users answered ${res.status}`);
      const body = res.json();
      for (const u of body.items) data.userIds.push(u.id);
      cursor = body.next_cursor || body.cursor || null;
      if (!cursor || body.items.length === 0) break;
    }
    if (data.userIds.length === 0) throw new Error('no users to look up');
  }
  if (uses.includes('introspect') && !env.apiSecret) {
    throw new Error('STRESS_API_SECRET is required for introspect (run prepare.js first)');
  }
  if (__ENV.START_AT) {
    const waitMs = parseInt(__ENV.START_AT, 10) * 1000 - Date.now();
    if (waitMs > 0) {
      sleep(waitMs / 1000);
    } else {
      console.warn(`START_AT passed ${-waitMs} ms before setup ended; starting now`);
    }
  }
  data.startedAt = Date.now();
  return data;
}

// VU-local state: this VU's session ({ refresh, access, iat, exp, refreshes },
// or 'relogin' when it must sign in again), its own admin token once setup()'s
// nears expiry ({ access, iat, exp }), and a window of recent outcomes.
let chain = null;
let admin = null;
const recent = [];

// A token's issue and expiry times (epoch seconds), from its claims.
function life(jwt) {
  const c = claims(jwt);
  return { iat: c.iat, exp: c.exp };
}

// True when this VU must replace a token with these times.
function due(t) {
  return Date.now() / 1000 >= t.exp - (t.exp - t.iat) * renewFraction;
}

// A VU session from a sign-in, or 'relogin' when the sign-in failed.
function session(s) {
  if (!s.ok) return 'relogin';
  return Object.assign({ refresh: s.refresh, access: s.access, refreshes: 0 }, life(s.access));
}

// Signs this VU's own user in; `name` tags the requests (they are not a journey).
function signInOwn(name) {
  return signIn(userEmail(1 + (exec.vu.idInTest % env.loginUsers)), env.userPassword, { name });
}

// This VU's session, or null when the VU must sign in again. The first call
// takes the VU's own session from the pool. A session whose access token
// nears expiry is replaced by a fresh sign-in.
function ownSession(data) {
  if (chain === null) {
    chain =
      exec.vu.idInTest <= data.sessions.length
        ? Object.assign({ refreshes: 0 }, data.sessions[exec.vu.idInTest - 1])
        : 'relogin';
  }
  if (chain !== 'relogin' && due(chain)) {
    renewals.add(1);
    chain = session(signInOwn('renew'));
  }
  return chain === 'relogin' ? null : chain;
}

// The access token a userinfo or introspect journey presents.
//   PRESENT=pool   the pool's tokens in turn (the same few hundred all run)
//   PRESENT=chain  this VU's newest token, as a real client presents it: a new
//                  one after each refresh, so the server's token cache fills
// A pool token near its expiry gives way to this VU's own session.
function userToken(data) {
  if (present === 'pool') {
    const s = pickSession(data);
    if (!due(s)) return s.access;
  }
  const own = ownSession(data);
  return own ? own.access : pickSession(data).access;
}

// The realm admin's token. setup()'s expires after the access-token lifetime,
// so near its expiry each VU signs the admin in for itself.
function adminToken(data) {
  if (!due(data.adminLife)) return data.admin;
  if (admin === null || due(admin)) {
    renewals.add(1);
    const s = signIn(env.adminEmail, env.adminPassword, { name: 'renew' });
    if (s.ok) admin = Object.assign({ access: s.access }, life(s.access));
  }
  return admin ? admin.access : data.admin;
}

function tagIteration() {
  const elapsed = (Date.now() - exec.scenario.startTime) / 1000;
  const step = Math.min(steps - 1, Math.floor(elapsed / stepS));
  const phase = elapsed - step * stepS < rampS ? 'ramp' : 'hold';
  exec.vu.metrics.tags.step = String(step);
  exec.vu.metrics.tags.phase = phase;
}

// A failure's class: the HTTP status when the server answered, else k6's
// transport error code (k6 also sets error_code = 1000 + status for HTTP
// errors, so the status comes first).
function fail(res) {
  if (!res) return 'none';
  if (res.status > 0) return String(res.status);
  return `e${res.error_code}`;
}

function record(name, ok, ms, cls) {
  const tags = { journey: name };
  journeyMs.add(ms, tags);
  journeyOk.add(ok ? 1 : 0, tags);
  if (!ok) journeyFail.add(1, Object.assign({ cls }, tags));
  recent.push(ok ? 0 : 1);
  if (recent.length > 200) recent.shift();
  if (recent.length === 200) {
    const failed = recent.reduce((s, x) => s + x, 0) / recent.length;
    if (failed > abortRatio) {
      exec.test.abort(`failure ratio ${failed.toFixed(2)} over this VU's last 200 journeys`);
    }
  }
}

function pickSession(data) {
  return data.sessions[exec.scenario.iterationInTest % data.sessions.length];
}

function introspect(data) {
  const res = http.post(
    `${env.base}/realms/${env.realm}/introspect`,
    { token: userToken(data) },
    { headers: { Authorization: apiBasic(env.apiSecret) }, timeout: TIMEOUT, tags: { name: 'introspect' } },
  );
  const ok = res.status === 200 && res.json('active') === true;
  record('introspect', ok, res.timings.duration, ok ? null : res.status === 200 ? 'inactive' : fail(res));
}

function userinfo(data) {
  const res = http.get(`${env.base}/realms/${env.realm}/userinfo`, {
    headers: { Authorization: `Bearer ${userToken(data)}` },
    timeout: TIMEOUT,
    tags: { name: 'userinfo' },
  });
  record('userinfo', res.status === 200, res.timings.duration, fail(res));
}

function refresh(data) {
  const own = ownSession(data);
  if (own === null) {
    relogins.add(1);
    chain = session(signInOwn('relogin'));
    return;
  }
  if (chainRefreshes > 0 && own.refreshes >= chainRefreshes) {
    rotations.add(1);
    chain = session(signInOwn('rotate'));
    return;
  }
  const res = http.post(
    `${env.base}/realms/${env.realm}/token`,
    { grant_type: 'refresh_token', refresh_token: own.refresh, client_id: env.appClientId },
    { timeout: TIMEOUT, tags: { name: 'refresh' } },
  );
  const ok = res.status === 200;
  record('refresh', ok, res.timings.duration, fail(res));
  if (ok) {
    const b = res.json();
    chain = Object.assign(
      { refresh: b.refresh_token, access: b.access_token, refreshes: own.refreshes + 1 },
      life(b.access_token),
    );
  } else if (res.status === 429 || res.status === 503 || (res.status >= 400 && res.status < 500)) {
    // 429/503: refused before rotation, so the token is still valid.
    // 4xx: the token is spent or revoked; start a new chain.
    if (res.status !== 429 && res.status !== 503) chain = 'relogin';
  } else {
    // Timeout or 5xx: the rotation may have happened. Reusing the old token
    // would revoke the family, so start a new chain.
    chain = 'relogin';
  }
}

function login() {
  const user = 1 + Math.floor(Math.random() * env.loginUsers);
  const s = signIn(userEmail(user), env.userPassword);
  const cls = s.ok ? null : `${s.failedStep}:${s.status > 0 ? s.status : `e${s.errorCode}`}`;
  record('login', s.ok, s.durationMs, cls);
}

function adminLookup(data) {
  const id = data.userIds[exec.scenario.iterationInTest % data.userIds.length];
  const res = http.get(`${env.base}/admin/users/${id}`, {
    headers: adminHeaders(adminToken(data), data.realmId),
    timeout: TIMEOUT,
    tags: { name: 'admin_lookup' },
  });
  record('admin_lookup', res.status === 200, res.timings.duration, fail(res));
}

function createUser(data) {
  const email = `c-${runId}-${exec.vu.idInTest}-${exec.vu.iterationInInstance}@${env.host}`;
  const res = http.post(
    `${env.base}/admin/users`,
    JSON.stringify({ email, display_name: 'Stress created' }),
    { headers: adminHeaders(adminToken(data), data.realmId), timeout: TIMEOUT, tags: { name: 'create_user' } },
  );
  const ok = res.status === 201;
  record('create_user', ok, res.timings.duration, fail(res));
  if (ok) console.log(`ACK ${res.json('id')}`);
}

const run = {
  introspect,
  userinfo,
  refresh,
  login,
  admin_lookup: adminLookup,
  create_user: createUser,
};

function pickMix() {
  let x = Math.random() * mixTotal;
  for (const m of mix) {
    x -= m.weight;
    if (x <= 0) return m.name;
  }
  return mix[mix.length - 1].name;
}

export default function (data) {
  // cloud.sh waits for this line to time a kill -9 from the scenario start.
  if (exec.scenario.iterationInTest === 0) console.log('STRESS_STARTED');
  tagIteration();
  const name = journey === 'mix' ? pickMix() : journey;
  run[name](data);
}

export function handleSummary(data) {
  const summary = `${JSON.stringify(summaryObject(data), null, 2)}\n`;
  const out = { stdout: summary };
  // The analysis reads started_at from this file to place sampler rows and
  // dropped iterations in their steps.
  if (__ENV.SUMMARY_OUT) out[__ENV.SUMMARY_OUT] = summary;
  return out;
}

function summaryObject(data) {
  const m = data.metrics;
  const v = (name, key) => (m[name] ? m[name].values[key] : undefined);
  return {
    journey,
    started_at: data.setup_data ? data.setup_data.startedAt : null,
    journeys: (v('journey_ok', 'passes') || 0) + (v('journey_ok', 'fails') || 0),
    ok_rate: v('journey_ok', 'rate'),
    p50_ms: v('journey_ms', 'med'),
    p99_ms: v('journey_ms', 'p(99)'),
    dropped_iterations: v('dropped_iterations', 'count') || 0,
    relogins: v('refresh_relogins', 'count') || 0,
    chain_rotations: v('chain_rotations', 'count') || 0,
    token_renewals: v('token_renewals', 'count') || 0,
  };
}
