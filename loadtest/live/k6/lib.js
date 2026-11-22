// Shared helpers for the live stress scripts: configuration from the
// environment, sign-in through the product's own login page plus
// authorization code + PKCE (Hearth has no password grant), and the admin API.
//
// PRODUCT (default hearth) picks the product adapter (products/index.js): the
// endpoints, the login page's steps and the admin API of the server under
// test. Everything else here is the same for every product (#913).
//
// The generator reaches the server by name; `options.hosts` maps that name to
// the server's address, and SSL_CERT_FILE makes k6 trust the run's CA.
//
// A run may span several realms (gen-config.sh REALMS): `realms` lists them,
// from STRESS_REALM, STRESS_APP_CLIENT_ID, STRESS_API_CLIENT_ID and
// STRESS_API_SECRET (realm 1) and the same names with `_<k>` (realm k), for
// STRESS_REALMS realms (default 1; see realms.js). The helpers below take a
// realm and default to realm 1.
import http from 'k6/http';
import { sleep } from 'k6';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';
import { realmsFromEnv } from './realms.js';
import { productFor } from './products/index.js';

/** The product adapter of the server under test (PRODUCT). */
export const product = productFor(__ENV.PRODUCT);

/** The run's realms; realm 1 first. */
export const realms = realmsFromEnv(__ENV);

export const env = {
  base: req('STRESS_BASE'),
  host: req('STRESS_HOST'),
  serverIp: req('STRESS_SERVER_IP'),
  redirectUri: req('STRESS_REDIRECT_URI'),
  loginUsers: parseInt(req('STRESS_LOGIN_USERS'), 10),
  userPassword: req('STRESS_USER_PASSWORD'),
  adminEmail: req('STRESS_ADMIN_EMAIL'),
  adminPassword: req('STRESS_ADMIN_PASSWORD'),
};

function req(name) {
  const v = __ENV[name];
  if (v === undefined || v === '') {
    throw new Error(`environment variable ${name} is required`);
  }
  return v;
}

/** k6 `hosts` option: the server name resolves to the server's address. */
export const hosts = { [env.host]: env.serverIp };

/** Request timeout. A request that takes longer counts as failed. */
export const TIMEOUT = __ENV.STRESS_TIMEOUT || '10s';

/** The email of login user `i` (1-based), as gen-config.sh declares them. */
export function userEmail(i) {
  return `user${String(i).padStart(6, '0')}@${env.host}`;
}

function b64url(bytes) {
  return encoding.b64encode(bytes, 'rawurl');
}

/**
 * A new sign-in flow: the user, a PKCE pair, a state and the scope. An admin
 * sign-in adds the product's admin scope (product.adminScope), if it has one.
 */
function newFlow(email, password, admin) {
  const verifier = b64url(crypto.randomBytes(32));
  return {
    email,
    password,
    scope: admin && product.adminScope ? `openid ${product.adminScope}` : 'openid',
    verifier,
    challenge: crypto.sha256(verifier, 'base64rawurl'),
    state: b64url(crypto.randomBytes(12)),
  };
}

function stepParams(jar, name, tags, headers) {
  const p = {
    jar,
    redirects: 0,
    timeout: TIMEOUT,
    tags: Object.assign({ name }, tags || {}),
  };
  if (headers) p.headers = headers;
  return p;
}

/**
 * Sends a request an adapter built (`{ method, url, body, headers }`) with
 * k6 params `params`; the spec's headers go first.
 */
export function send(spec, params) {
  const p = Object.assign({}, params || {});
  if (spec.headers) p.headers = Object.assign({}, spec.headers, p.headers || {});
  return http.request(spec.method, spec.url, spec.body === undefined ? null : spec.body, p);
}

/** One login step of flow `f` as an http.batch entry. */
function batchEntry(step, r, f, tags) {
  const spec = step.request(env, r, f);
  return [spec.method, spec.url, spec.body === undefined ? null : spec.body,
    stepParams(f.jar, step.name, tags, spec.headers)];
}

/**
 * Signs `email` in to realm `r` through the product's login page and the code
 * flow (product.loginSteps); `admin` for the realm admin. Returns `{ ok, access, refresh, durationMs,
 * failedStep, status, errorCode }`. `durationMs` is the sum of the steps'
 * request durations.
 */
export function signIn(email, password, tags, r = realms[0], admin = false) {
  const f = newFlow(email, password, admin);
  f.jar = new http.CookieJar();
  let duration = 0;
  for (const step of product.loginSteps) {
    const res = send(step.request(env, r, f), stepParams(f.jar, step.name, tags));
    duration += res.timings.duration;
    if (!step.accept(res, f)) {
      return {
        ok: false,
        failedStep: step.name,
        status: res.status,
        errorCode: res.error_code,
        durationMs: duration,
      };
    }
  }
  return { ok: true, access: f.access, refresh: f.refresh, durationMs: duration };
}

/**
 * Signs many users in to realm `r`, `parallel` at a time, with http.batch per
 * step. Used by setup() to build the token pool; not a measured journey.
 * Returns the sessions that worked and the number that failed.
 */
export function signInMany(emails, password, parallel, r = realms[0]) {
  // A small server sheds concurrent password checks with 503 (the KDF gate):
  // retry the users that failed, a few rounds, with a pause between rounds.
  const sessions = [];
  let pending = emails;
  for (let round = 0; round < 6 && pending.length > 0; round++) {
    if (round > 0) sleep(1 + round);
    const pass = signInPass(pending, password, parallel, r);
    for (const s of pass.sessions) sessions.push(s);
    pending = pass.retry;
  }
  return { sessions, failed: pending.length };
}

function signInPass(emails, password, parallel, r) {
  const sessions = [];
  const retry = [];
  const t = { phase: 'setup' };
  for (let i = 0; i < emails.length; i += parallel) {
    let live = emails.slice(i, i + parallel).map((email) => {
      const f = newFlow(email, password);
      f.jar = new http.CookieJar();
      return f;
    });
    // Each step runs for the flows still live; a flow whose step fails is retried.
    for (const step of product.loginSteps) {
      if (live.length === 0) break;
      const res = http.batch(live.map((f) => batchEntry(step, r, f, t)));
      const next = [];
      live.forEach((f, j) => (step.accept(res[j], f) ? next.push(f) : retry.push(f.email)));
      live = next;
    }
    for (const f of live) sessions.push({ access: f.access, refresh: f.refresh });
  }
  return { sessions, retry };
}

/** The claims of a JWT, unverified (the generator only reads them). */
export function claims(jwt) {
  return JSON.parse(encoding.b64decode(jwt.split('.')[1], 'rawurl', 's'));
}

/** Signs realm `r`'s admin in; `tags` tag its requests. */
export function adminSignIn(tags, r = realms[0]) {
  return signIn(env.adminEmail, env.adminPassword, tags, r, true);
}

/** Signs realm `r`'s admin in. Throws when it fails: nothing works without it. */
export function adminSession(r = realms[0]) {
  const s = adminSignIn({ phase: 'setup' }, r);
  if (!s.ok) {
    const where = realms.length > 1 ? ` in realm ${r.name}` : '';
    throw new Error(`admin sign-in${where} failed at ${s.failedStep} (status ${s.status})`);
  }
  return s;
}

/**
 * The product's admin context ({ token, realmId }) for an admin access token:
 * what the adapter's admin requests take.
 */
export function adminContext(token) {
  return product.admin(token, claims(token));
}

/** Headers for the product's admin API as the realm admin. */
export function adminHeaders(adminToken, realmId) {
  return product.adminHeaders({ token: adminToken, realmId });
}

/** Basic auth header for realm `r`'s confidential `api` client. */
export function apiBasic(r = realms[0]) {
  return `Basic ${encoding.b64encode(`${r.apiClientId}:${r.apiSecret}`)}`;
}
