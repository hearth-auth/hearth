// The Ory adapter (#913): Ory Hydra (OAuth 2.0 and OpenID Connect) with Ory
// Kratos (the users) and Ory's reference login and consent UI, the same
// journeys as Hearth through their own endpoints. Pure request builders
// without k6 modules, so node tests them (test_products.mjs). The clients and
// users come from loadtest/compare/ory (ory.sh, realm.py and the seed).
//
// One host, five TLS listeners (compose.yaml): STRESS_BASE is Hydra's public
// port; the others are on the same name.
//
//   login       GET Hydra's authorization endpoint (302 to the UI's login page
//               with a login_challenge), GET it (303 to Kratos's browser login
//               flow), GET that (303 to the UI's login page with the flow), GET
//               the login page (200 with the form), POST the form to Kratos (303
//               back to Hydra with a login_verifier: Kratos accepted Hydra's
//               login request), GET that (302 to the UI's consent page), GET the
//               consent page (302 back to Hydra with a consent_verifier: the
//               client has skip_consent), GET that (303 to the redirect URI with
//               the code), exchange the code with PKCE: 9 requests, one Argon2id
//               password check. The scope adds offline_access: Hydra issues a
//               refresh token only for it.
//   refresh     refresh_token grant of the public `app` client (Hydra rotates
//               refresh tokens, refuses a reused one and revokes its family; it
//               also revokes the access token of the refresh token used; the
//               comparison runs with PRESENT=chain, loadtest/compare/README.md)
//   client credentials  the confidential `api` client (client_secret_basic)
//   userinfo    GET /userinfo on Hydra's public port
//   introspect  POST /admin/oauth2/introspect on Hydra's admin port, which
//               takes no client authentication (Ory: keep the port off the
//               public network)
//   admin       Kratos's admin identities API on its admin port, which has no
//               authentication of its own (same advice); the realm admin still
//               signs in, as for the other products, but its token is not sent
//
// Hydra issues JWT access tokens here (hydra.yaml: its default is opaque), as
// Zitadel's run does: the harness reads `iat` and `exp` from them.
import { authorizeQuery, codeExchange, header, json, takeCode, takeTokens } from './common.js';

// The ports of compose.yaml; STRESS_BASE carries Hydra's public one.
const HYDRA_ADMIN = 4445;
const KRATOS_PUBLIC = 4433;
const KRATOS_ADMIN = 4434;
const UI = 4455;
// A page of listUsers; Kratos pages by keyset (page_token).
const PAGE = 200;
const SCHEMA_ID = 'default';

/** The URL of the same host as `c.base` on `port`. */
export function at(c, port) {
  const m = /^(https?:\/\/[^/:]+)(?::[0-9]+)?/.exec(c.base);
  if (!m) throw new Error(`STRESS_BASE is not an http(s) URL: ${c.base}`);
  return `${m[1]}:${port}`;
}

/**
 * True when `res` redirects (302 or 303) to a URL that starts with `prefix`
 * and whose query has `param`. Sets `f.next` to that URL.
 */
export function redirectsTo(res, f, prefix, param) {
  if (res.status !== 302 && res.status !== 303) return false;
  const loc = header(res, 'Location') || '';
  if (!loc.startsWith(prefix)) return false;
  if (param && !new RegExp(`[?&]${param}=[^&]`).test(loc)) return false;
  f.next = loc;
  return true;
}

/** The action of the login form (Ory Elements, `data-testid="login-flow"`), or null. */
export function loginAction(body) {
  const form = /<form\b[^>]*\bdata-testid="login-flow"[^>]*>/.exec(body || '');
  if (!form) return null;
  const action = /\baction="([^"]*)"/.exec(form[0]);
  return action ? action[1].replace(/&amp;/g, '&') : null;
}

/** The value of the `<input>` named `name` in a page, whatever the order of its attributes. */
export function inputValue(body, name) {
  const re = new RegExp(`<input\\b[^>]*\\bname="${name}"[^>]*>`);
  const input = re.exec(body || '');
  if (!input) return null;
  const value = /\bvalue="([^"]*)"/.exec(input[0]);
  return value ? value[1] : null;
}

/** The page_token of the `rel="next"` link of a Kratos list answer, or null. */
export function nextPageToken(link) {
  for (const part of (link || '').split(',')) {
    if (!/rel="next"/.test(part)) continue;
    const m = /[?&]page_token=([^&>]+)/.exec(part);
    if (m) return decodeURIComponent(m[1]);
  }
  return null;
}

function adminHeaders() {
  return { 'Content-Type': 'application/json' };
}

/**
 * A Kratos createIdentityBody: the email is the password identifier and is
 * already verified, so no verification message is ever due. `hash` (the
 * seed's unusable Argon2id hash, realm.py unusable_hash) makes a password
 * credential that no password matches; without it the user has no password.
 */
function identity(email, first, last, hash) {
  const body = {
    schema_id: SCHEMA_ID,
    traits: { email, name: { first, last } },
    state: 'active',
    verifiable_addresses: [{ value: email, via: 'email', verified: true, status: 'completed' }],
  };
  if (hash) body.credentials = { password: { config: { hashed_password: hash } } };
  return body;
}

const tokenUrl = (c) => `${c.base}/oauth2/token`;
const identities = (c) => `${at(c, KRATOS_ADMIN)}/admin/identities`;

/**
 * The flow's origins, kept on the flow by the first step: each step checks
 * that the server sent the browser where Ory's flow goes next.
 */
function origins(c, f) {
  f.hydra = c.base;
  f.ui = at(c, UI);
  f.kratos = at(c, KRATOS_PUBLIC);
}

// A step that follows the previous step's redirect (`f.next`).
const follow = (c, r, f) => ({ method: 'GET', url: f.next });

export const ory = {
  name: 'ory',

  loginSteps: [
    {
      name: 'authorize',
      request: (c, r, f) => {
        origins(c, f);
        return {
          method: 'GET',
          url: `${c.base}/oauth2/auth?${authorizeQuery(
            Object.assign({}, f, { scope: `${f.scope || 'openid'} offline_access` }),
            r.appClientId,
            c.redirectUri,
          )}`,
        };
      },
      // To the UI's login page with Hydra's login challenge.
      accept: (res, f) => redirectsTo(res, f, `${f.ui}/login?`, 'login_challenge'),
    },
    {
      // The UI starts a Kratos browser login flow for the challenge.
      name: 'login_challenge',
      request: follow,
      accept: (res, f) => redirectsTo(res, f, `${f.kratos}/self-service/login/browser?`, 'login_challenge'),
    },
    {
      // Kratos makes the flow (and its CSRF cookie) and sends the browser to the UI.
      name: 'login_flow',
      request: follow,
      accept: (res, f) => redirectsTo(res, f, `${f.ui}/login?`, 'flow'),
    },
    {
      name: 'login_page',
      request: follow,
      accept: (res, f) => {
        f.action = loginAction(res.body);
        f.csrf = inputValue(res.body, 'csrf_token');
        return res.status === 200 && f.action !== null && f.csrf !== null
          && f.action.startsWith(`${f.kratos}/self-service/login?`);
      },
    },
    {
      name: 'login_submit',
      request: (c, r, f) => ({
        method: 'POST',
        url: f.action,
        body: { csrf_token: f.csrf, identifier: f.email, password: f.password, method: 'password' },
      }),
      // Back to Hydra with the login verifier; a refused password goes back
      // to the UI's login page instead.
      accept: (res, f) => redirectsTo(res, f, `${f.hydra}/oauth2/auth?`, 'login_verifier'),
    },
    {
      name: 'login_verifier',
      request: follow,
      accept: (res, f) => redirectsTo(res, f, `${f.ui}/consent?`, 'consent_challenge'),
    },
    {
      // skip_consent: the UI accepts the consent request at once.
      name: 'consent',
      request: follow,
      accept: (res, f) => redirectsTo(res, f, `${f.hydra}/oauth2/auth?`, 'consent_verifier'),
    },
    {
      name: 'consent_verifier',
      request: follow,
      accept: (res, f) => takeCode(res, f, 303),
    },
    {
      name: 'code_exchange',
      request: (c, r, f) => codeExchange(tokenUrl(c), f, r.appClientId, c.redirectUri),
      accept: takeTokens,
    },
  ],

  refresh: (c, r, refreshToken) => ({
    method: 'POST',
    url: tokenUrl(c),
    body: { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: r.appClientId },
  }),

  clientCredentials: (c, r, basic) => ({
    method: 'POST',
    url: tokenUrl(c),
    body: { grant_type: 'client_credentials' },
    headers: { Authorization: basic },
  }),

  userinfo: (c, r, token) => ({
    method: 'GET',
    url: `${c.base}/userinfo`,
    headers: { Authorization: `Bearer ${token}` },
  }),

  // Hydra's admin port takes no client authentication: `basic` is not sent.
  introspect: (c, r, token) => ({
    method: 'POST',
    url: `${at(c, HYDRA_ADMIN)}/admin/oauth2/introspect`,
    body: { token },
  }),

  // Kratos's admin API is the realm's; no scope, no realm id.
  admin: (token) => ({ token, realmId: null }),
  adminHeaders,

  adminUser: (c, r, a, id) => ({
    method: 'GET',
    url: `${identities(c)}/${id}`,
    headers: adminHeaders(),
  }),

  // `cursor` is the page token of the page (null for the first).
  listUsers: (c, r, a, cursor) => ({
    method: 'GET',
    url: `${identities(c)}?page_size=${PAGE}${cursor ? `&page_token=${encodeURIComponent(cursor)}` : ''}`,
    headers: adminHeaders(),
  }),
  userPage: (res) => {
    const items = json(res);
    return {
      ids: items.map((u) => u.id),
      next: items.length < PAGE ? null : nextPageToken(header(res, 'Link')),
    };
  },

  // Like Hearth's create: no password and no email (the address is verified,
  // and Kratos's admin API sends nothing; ory.sh messages counts).
  createUser: (c, r, a, email) => ({
    method: 'POST',
    url: identities(c),
    body: JSON.stringify(identity(email, 'Stress', 'created')),
    headers: adminHeaders(),
  }),
  // 201 with the identity.
  createdId: (res) => {
    if (res.status !== 201) return null;
    const b = json(res);
    return b && b.id ? b.id : null;
  },

  // The bulk path: PATCH /admin/identities (batchPatchIdentities, Kratos's
  // import of many identities; at most 1,000 per request). Each user gets the
  // run's unusable hash (identity()). Kratos writes a batch in one
  // transaction and reports each identity; an existing user fails and is
  // counted as failed, as Hearth's import counts a duplicate.
  importUsers: (c, r, a, batch) => {
    if (!c.bulkPasswordHash) {
      throw new Error('STRESS_BULK_PASSWORD_HASH is required to seed Ory (realm.py)');
    }
    return {
      method: 'PATCH',
      url: identities(c),
      body: JSON.stringify({
        identities: batch.map((u) => ({ create: identity(u.email, 'Bulk', String(u.index), c.bulkPasswordHash) })),
      }),
      headers: adminHeaders(),
    };
  },
  imported: (res) => {
    if (res.status !== 200) return null;
    const b = json(res);
    if (!b) return null;
    const items = b.identities || [];
    const ok = items.filter((i) => i.action === 'create' && i.identity).length;
    return { imported: ok, failed: items.length - ok };
  },

  // The api client's secret is generated when the realm is made (realm.py).
  regenerateSecret: null,
  newSecret: null,
};
