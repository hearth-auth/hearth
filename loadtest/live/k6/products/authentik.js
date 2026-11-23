// The Authentik adapter (#913): the same journeys as Hearth through
// Authentik's own endpoints and its flow executor. Pure request builders
// without k6 modules, so node tests them (test_products.mjs). The providers,
// the service account and the users come from loadtest/compare/authentik
// (authentik.sh, realm.py and the seed).
//
//   login       GET the authorization endpoint (302 to the flow interface of
//               the default authentication flow), GET the interface (the page
//               a browser loads; its script then drives the flow executor
//               API), GET the executor (the identification challenge), POST
//               the email (302 back to the executor), GET it (the password
//               challenge), POST the password (302), GET the executor twice
//               (the MFA stage passes, as the user has no authenticator; then
//               the user login stage answers with the redirect back to the
//               authorization endpoint), GET that (302 to the redirect URI with
//               the code; the implicit-consent flow shows no page), exchange
//               the code with PKCE: 10 requests, one PBKDF2-SHA256 password
//               check. The scope adds offline_access: Authentik issues a
//               refresh token only for it.
//   refresh     refresh_token grant of the public `app` provider (Authentik
//               rotates the refresh token and refuses a used one)
//   client credentials  the confidential `api` provider with a service
//               account's app password (client_secret = base64(username:app
//               password), Authentik's machine-to-machine guide; realm.py)
//   userinfo    GET the userinfo endpoint
//   introspect  RFC 7662 introspection as the confidential `api` provider (the
//               app provider names it as a federated provider, realm.py)
//   admin       the core users API (/api/v3/core/users/) with an access token
//               of akadmin with the goauthentik.io/api scope, signed in through
//               the same login flow as the users
//
// Authentik's access tokens are JWTs (RS256); the harness takes their
// lifetime from the token response's expires_in, as for every product.
import { authorizeQuery, codeExchange, header, json, takeCode, takeTokens } from './common.js';

const oauth = (c) => `${c.base}/application/o`;
const users = (c) => `${c.base}/api/v3/core/users/`;
// A page of listUsers; the users API pages by page number.
const PAGE = 200;
// The flow interface's prefix, in the authorization endpoint's redirect.
const FLOW_UI = '/if/flow/';

const JSON_HEADERS = { Accept: 'application/json', 'Content-Type': 'application/json' };

function adminHeaders(a) {
  return { Authorization: `Bearer ${a.token}`, 'Content-Type': 'application/json' };
}

/**
 * True when the authorization endpoint sent the browser to a flow's
 * interface (`/if/flow/<slug>/?<query>`). Sets `f.flowPage` (that URL, on the
 * server), `f.executor`: the flow executor's URL that the interface calls,
 * with the interface's query as `query` (Authentik's flow executor guide), and
 * `f.executorPath`, the executor's path, where its redirects go.
 */
export function takeFlow(res, f, base) {
  if (res.status !== 302) return false;
  const loc = header(res, 'Location') || '';
  const m = /^\/if\/flow\/([a-z0-9-]+)\/\?(.+)$/.exec(loc);
  if (!m) return false;
  f.flowPage = `${base}${FLOW_UI}${m[1]}/?${m[2]}`;
  f.executorPath = `/api/v3/flows/executor/${m[1]}/?`;
  f.executor = `${base}${f.executorPath}query=${encodeURIComponent(m[2])}`;
  return true;
}

/** True when `res` is the challenge `component` of the flow executor. */
export function challenge(res, component) {
  if (res.status !== 200) return false;
  const b = json(res);
  return b !== null && b.component === component;
}

/** True when the executor answered with the redirect back to itself (the flow's next stage). */
function backToExecutor(res, f) {
  if (res.status !== 302) return false;
  return (header(res, 'Location') || '').startsWith(f.executorPath);
}

/**
 * True when the flow ended with its redirect (`xak-flow-redirect`) back to the
 * authorization endpoint. Sets `f.next` (the `to` URL, on the server).
 */
export function takeRedirect(res, f, base) {
  if (!challenge(res, 'xak-flow-redirect')) return false;
  const to = json(res).to || '';
  if (!to.startsWith('/application/o/authorize/?')) return false;
  f.next = `${base}${to}`;
  return true;
}

const executorGet = (c, r, f) => ({ method: 'GET', url: f.executor, headers: { Accept: 'application/json' } });

export const authentik = {
  name: 'authentik',

  loginSteps: [
    {
      name: 'authorize',
      request: (c, r, f) => {
        // The redirects of the flow are relative: they stay on this server.
        f.base = c.base;
        return {
          method: 'GET',
          url: `${oauth(c)}/authorize/?${authorizeQuery(
            Object.assign({}, f, { scope: `${f.scope || 'openid'} offline_access` }),
            r.appClientId,
            c.redirectUri,
          )}`,
        };
      },
      accept: (res, f) => takeFlow(res, f, f.base),
    },
    {
      // The flow interface: the page whose script runs the flow.
      name: 'flow_page',
      request: (c, r, f) => ({ method: 'GET', url: f.flowPage }),
      accept: (res) => res.status === 200,
    },
    {
      name: 'identification',
      request: executorGet,
      accept: (res) => challenge(res, 'ak-stage-identification'),
    },
    {
      name: 'identify',
      request: (c, r, f) => ({
        method: 'POST',
        url: f.executor,
        body: JSON.stringify({ component: 'ak-stage-identification', uid_field: f.email }),
        headers: JSON_HEADERS,
      }),
      accept: backToExecutor,
    },
    {
      name: 'password_challenge',
      request: executorGet,
      accept: (res) => challenge(res, 'ak-stage-password'),
    },
    {
      name: 'password',
      request: (c, r, f) => ({
        method: 'POST',
        url: f.executor,
        body: JSON.stringify({ component: 'ak-stage-password', password: f.password }),
        headers: JSON_HEADERS,
      }),
      // A refused password answers 200 with the password challenge again.
      accept: backToExecutor,
    },
    {
      // The MFA validation stage passes (no authenticator) and moves on.
      name: 'mfa_stage',
      request: executorGet,
      accept: backToExecutor,
    },
    {
      name: 'login_stage',
      request: executorGet,
      accept: (res, f) => takeRedirect(res, f, f.base),
    },
    {
      // The implicit-consent flow: straight to the redirect URI with the code.
      name: 'authorize_code',
      request: (c, r, f) => ({ method: 'GET', url: f.next }),
      accept: (res, f) => takeCode(res, f, 302),
    },
    {
      name: 'code_exchange',
      request: (c, r, f) => codeExchange(`${oauth(c)}/token/`, f, r.appClientId, c.redirectUri),
      accept: takeTokens,
    },
  ],

  refresh: (c, r, refreshToken) => ({
    method: 'POST',
    url: `${oauth(c)}/token/`,
    body: { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: r.appClientId },
  }),

  // `basic` carries the api provider's client id and base64(username:app
  // password) as the secret (STRESS_CC_*, realm.py).
  clientCredentials: (c, r, basic) => ({
    method: 'POST',
    url: `${oauth(c)}/token/`,
    body: { grant_type: 'client_credentials' },
    headers: { Authorization: basic },
  }),

  userinfo: (c, r, token) => ({
    method: 'GET',
    url: `${oauth(c)}/userinfo/`,
    headers: { Authorization: `Bearer ${token}` },
  }),

  introspect: (c, r, token, basic) => ({
    method: 'POST',
    url: `${oauth(c)}/introspect/`,
    body: { token },
    headers: { Authorization: basic },
  }),

  // The API takes an OAuth access token with the goauthentik.io/api scope
  // (Authentik's API authentication guide): the admin signs in with it, the
  // users without it.
  adminScope: 'goauthentik.io/api',
  admin: (token) => ({ token, realmId: null }),
  adminHeaders,

  adminUser: (c, r, a, id) => ({
    method: 'GET',
    url: `${users(c)}${id}/`,
    headers: adminHeaders(a),
  }),

  // `cursor` is the page number (null for the first).
  listUsers: (c, r, a, cursor) => ({
    method: 'GET',
    url: `${users(c)}?ordering=username&page=${cursor || 1}&page_size=${PAGE}`
      + '&include_groups=false&include_roles=false',
    headers: adminHeaders(a),
  }),
  userPage: (res) => {
    const b = json(res);
    const next = b.pagination && b.pagination.next;
    return { ids: b.results.map((u) => String(u.pk)), next: next ? String(next) : null };
  },

  // Like Hearth's create: no password (Authentik stores an unusable one) and
  // no email (the users API sends none; authentik.sh tasks counts them).
  createUser: (c, r, a, email) => ({
    method: 'POST',
    url: users(c),
    body: JSON.stringify({ username: email, name: 'Stress created', email, is_active: true }),
    headers: adminHeaders(a),
  }),
  // 201 with the user; its id is the integer `pk`.
  createdId: (res) => {
    if (res.status !== 201) return null;
    const b = json(res);
    return b && b.pk !== undefined ? String(b.pk) : null;
  },

  // Authentik's seed does not go through prepare.js: authentik.sh seed
  // applies blueprints outside the worker's queue, so that the import queues
  // no task per user (loadtest/compare/README.md).
  importUsers: () => {
    throw new Error('Authentik is seeded with loadtest/compare/authentik/authentik.sh seed, not prepare.js');
  },
  imported: () => null,

  // The api provider's secret is generated when the realm is made (realm.py).
  regenerateSecret: null,
  newSecret: null,
};
