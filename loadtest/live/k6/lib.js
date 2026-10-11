// Shared helpers for the live stress scripts: configuration from the
// environment, sign-in through the hosted login form plus authorization code
// + PKCE (Hearth has no password grant), and the admin API.
//
// The generator reaches the server by name; `options.hosts` maps that name to
// the server's address, and SSL_CERT_FILE makes k6 trust the run's CA.
import http from 'k6/http';
import { sleep } from 'k6';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';

export const env = {
  base: req('STRESS_BASE'),
  host: req('STRESS_HOST'),
  serverIp: req('STRESS_SERVER_IP'),
  realm: req('STRESS_REALM'),
  redirectUri: req('STRESS_REDIRECT_URI'),
  appClientId: req('STRESS_APP_CLIENT_ID'),
  apiClientId: req('STRESS_API_CLIENT_ID'),
  apiSecret: __ENV.STRESS_API_SECRET || '',
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

function randomBytes(n) {
  return crypto.randomBytes(n);
}

function pkce() {
  const verifier = b64url(randomBytes(32));
  const challenge = crypto.sha256(verifier, 'base64rawurl');
  return { verifier, challenge };
}

function hidden(body, name) {
  const m = new RegExp(`name="${name}" value="([^"]*)"`).exec(body || '');
  return m ? m[1] : null;
}

function query(params) {
  return Object.keys(params)
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
    .join('&');
}

function redirectParams(location) {
  const q = (location || '').split('?')[1] || '';
  const out = {};
  for (const pair of q.split('&')) {
    if (!pair) continue;
    const [k, v] = pair.split('=');
    out[decodeURIComponent(k)] = decodeURIComponent((v || '').replace(/\+/g, ' '));
  }
  return out;
}

function stepParams(jar, name, tags) {
  return {
    jar,
    redirects: 0,
    timeout: TIMEOUT,
    tags: Object.assign({ name }, tags || {}),
  };
}

/**
 * The four requests of one sign-in, as plain request descriptions, so a
 * caller can run them one at a time (signIn) or as batches (signInMany).
 */
const loginUrl = () => `${env.base}/ui/realms/${env.realm}/login`;
const authorizeUrl = () => `${env.base}/ui/realms/${env.realm}/oauth/authorize`;
const tokenUrl = () => `${env.base}/realms/${env.realm}/token`;

/**
 * Signs `email` in through the login form and the code flow. Returns
 * `{ ok, access, refresh, durationMs, failedStep, status }`. `durationMs` is
 * the sum of the four requests' durations.
 */
export function signIn(email, password, tags) {
  const jar = new http.CookieJar();
  let duration = 0;
  const fail = (step, res) => ({
    ok: false,
    failedStep: step,
    status: res ? res.status : 0,
    errorCode: res ? res.error_code : 0,
    durationMs: duration,
  });

  const page = http.get(loginUrl(), stepParams(jar, 'login_page', tags));
  duration += page.timings.duration;
  if (page.status !== 200) return fail('login_page', page);

  const posted = http.post(
    loginUrl(),
    { _csrf: hidden(page.body, '_csrf') || '', email, password },
    stepParams(jar, 'login_submit', tags),
  );
  duration += posted.timings.duration;
  if (posted.status !== 303) return fail('login_submit', posted);

  const { verifier, challenge } = pkce();
  const state = b64url(randomBytes(12));
  const authz = http.get(
    `${authorizeUrl()}?${query({
      response_type: 'code',
      client_id: env.appClientId,
      redirect_uri: env.redirectUri,
      state,
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })}`,
    stepParams(jar, 'authorize', tags),
  );
  duration += authz.timings.duration;
  if (authz.status !== 303) return fail('authorize', authz);
  const p = redirectParams(authz.headers.Location || authz.headers.location);
  if (!p.code || p.state !== state) return fail('authorize', authz);

  const token = http.post(
    tokenUrl(),
    {
      grant_type: 'authorization_code',
      code: p.code,
      redirect_uri: env.redirectUri,
      client_id: env.appClientId,
      code_verifier: verifier,
    },
    stepParams(jar, 'code_exchange', tags),
  );
  duration += token.timings.duration;
  if (token.status !== 200) return fail('code_exchange', token);
  const body = token.json();
  return {
    ok: true,
    access: body.access_token,
    refresh: body.refresh_token,
    durationMs: duration,
  };
}

/**
 * Signs many users in, `parallel` at a time, with http.batch per step. Used by
 * setup() to build the token pool; not a measured journey. Returns the
 * sessions that worked and the number that failed.
 */
export function signInMany(emails, password, parallel) {
  // A small server sheds concurrent password checks with 503 (the KDF gate):
  // retry the users that failed, a few rounds, with a pause between rounds.
  const sessions = [];
  let pending = emails;
  for (let round = 0; round < 6 && pending.length > 0; round++) {
    if (round > 0) sleep(1 + round);
    const r = signInPass(pending, password, parallel);
    for (const s of r.sessions) sessions.push(s);
    pending = r.retry;
  }
  return { sessions, failed: pending.length };
}

function signInPass(emails, password, parallel) {
  const sessions = [];
  const retry = [];
  for (let i = 0; i < emails.length; i += parallel) {
    const chunk = emails.slice(i, i + parallel);
    const flows = chunk.map((email) => ({ email, jar: new http.CookieJar() }));
    const t = { phase: 'setup' };

    const pages = http.batch(
      flows.map((f) => ['GET', loginUrl(), null, stepParams(f.jar, 'login_page', t)]),
    );
    const posts = http.batch(
      flows.map((f, j) => [
        'POST',
        loginUrl(),
        { _csrf: hidden(pages[j].body, '_csrf') || '', email: f.email, password },
        stepParams(f.jar, 'login_submit', t),
      ]),
    );
    flows.forEach((f) => {
      const k = pkce();
      f.verifier = k.verifier;
      f.challenge = k.challenge;
      f.state = b64url(randomBytes(12));
    });
    const authzs = http.batch(
      flows.map((f, j) => [
        'GET',
        `${authorizeUrl()}?${query({
          response_type: 'code',
          client_id: env.appClientId,
          redirect_uri: env.redirectUri,
          state: f.state,
          scope: 'openid',
          code_challenge: f.challenge,
          code_challenge_method: 'S256',
        })}`,
        null,
        stepParams(f.jar, 'authorize', t),
      ]),
    );
    const live = [];
    flows.forEach((f, j) => {
      const a = authzs[j];
      const p = redirectParams(a.headers.Location || a.headers.location);
      if (posts[j].status === 303 && a.status === 303 && p.code && p.state === f.state) {
        f.code = p.code;
        live.push(f);
      } else {
        retry.push(f.email);
      }
    });
    if (live.length === 0) continue;
    const tokens = http.batch(
      live.map((f) => [
        'POST',
        tokenUrl(),
        {
          grant_type: 'authorization_code',
          code: f.code,
          redirect_uri: env.redirectUri,
          client_id: env.appClientId,
          code_verifier: f.verifier,
        },
        stepParams(f.jar, 'code_exchange', t),
      ]),
    );
    tokens.forEach((r, j) => {
      if (r.status === 200) {
        const b = r.json();
        sessions.push({ access: b.access_token, refresh: b.refresh_token });
      } else {
        retry.push(live[j].email);
      }
    });
  }
  return { sessions, retry };
}

/** The claims of a JWT, unverified (the generator only reads them). */
export function claims(jwt) {
  return JSON.parse(encoding.b64decode(jwt.split('.')[1], 'rawurl', 's'));
}

/** Signs the realm admin in. Throws when it fails: nothing works without it. */
export function adminSession() {
  const s = signIn(env.adminEmail, env.adminPassword, { phase: 'setup' });
  if (!s.ok) {
    throw new Error(`admin sign-in failed at ${s.failedStep} (status ${s.status})`);
  }
  return s;
}

/** Headers for the admin API as the realm admin. */
export function adminHeaders(adminToken, realmId) {
  return {
    Authorization: `Bearer ${adminToken}`,
    'X-Realm-ID': realmId,
    'Content-Type': 'application/json',
  };
}

/** Basic auth header for the confidential `api` client. */
export function apiBasic(secret) {
  return `Basic ${encoding.b64encode(`${env.apiClientId}:${secret}`)}`;
}
