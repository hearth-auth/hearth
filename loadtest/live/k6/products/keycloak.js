// The Keycloak adapter (#913): the same journeys as Hearth through Keycloak's
// own endpoints and login page. Pure request builders without k6 modules, so
// node tests them (test_products.mjs). The realm, its clients and its users
// come from loadtest/compare/keycloak (realm.py and the seed).
//
//   login       GET the authorization endpoint (it renders Keycloak's login
//               page), POST the page's form (302 to the redirect URI with the
//               code), exchange the code with PKCE: 3 requests, one Argon2id
//               password check
//   refresh     refresh_token grant of the public `app` client
//   userinfo    GET the userinfo endpoint
//   introspect  RFC 7662 introspection as the confidential `api` client
//   admin       the admin REST API (/admin/realms/<realm>/users) with a token of
//               the realm's admin user (realm-management realm-admin role),
//               signed in through the same login page as the users
import {
  authorizeQuery,
  codeExchange,
  header,
  json,
  takeCode,
  takeTokens,
} from './common.js';

const oidc = (c, r) => `${c.base}/realms/${r.name}/protocol/openid-connect`;
const users = (c, r) => `${c.base}/admin/realms/${r.name}/users`;
// A page of listUsers: Keycloak pages by offset (`first`) and size (`max`).
const PAGE = 200;

/** HTML entities that Keycloak's templates escape in an attribute value. */
function unescapeHtml(s) {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

/**
 * The action URL of the login form (`<form id="kc-form-login" … action="…">`)
 * in Keycloak's login page, or null when the page has none.
 */
export function loginAction(body) {
  const form = /<form\b[^>]*\bid="kc-form-login"[^>]*>/.exec(body || '');
  if (!form) return null;
  const action = /\baction="([^"]*)"/.exec(form[0]);
  return action ? unescapeHtml(action[1]) : null;
}

function adminHeaders(a) {
  return { Authorization: `Bearer ${a.token}`, 'Content-Type': 'application/json' };
}

/** A user representation for the admin API: the email is also the username. */
function userRep(email, first, last) {
  return { username: email, email, firstName: first, lastName: last, enabled: true, emailVerified: true };
}

export const keycloak = {
  name: 'keycloak',

  loginSteps: [
    {
      name: 'login_page',
      request: (c, r, f) => ({
        method: 'GET',
        url: `${oidc(c, r)}/auth?${authorizeQuery(f, r.appClientId, c.redirectUri)}`,
      }),
      accept: (res, f) => {
        f.action = loginAction(res.body);
        return res.status === 200 && f.action !== null;
      },
    },
    {
      name: 'login_submit',
      request: (c, r, f) => ({
        method: 'POST',
        url: f.action,
        body: { username: f.email, password: f.password, credentialId: '' },
      }),
      // A refused password answers 200 with the form again.
      accept: (res, f) => takeCode(res, f, 302),
    },
    {
      name: 'code_exchange',
      request: (c, r, f) => codeExchange(`${oidc(c, r)}/token`, f, r.appClientId, c.redirectUri),
      accept: takeTokens,
    },
  ],

  refresh: (c, r, refreshToken) => ({
    method: 'POST',
    url: `${oidc(c, r)}/token`,
    body: { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: r.appClientId },
  }),

  clientCredentials: (c, r, basic) => ({
    method: 'POST',
    url: `${oidc(c, r)}/token`,
    body: { grant_type: 'client_credentials' },
    headers: { Authorization: basic },
  }),

  userinfo: (c, r, token) => ({
    method: 'GET',
    url: `${oidc(c, r)}/userinfo`,
    headers: { Authorization: `Bearer ${token}` },
  }),

  introspect: (c, r, token, basic) => ({
    method: 'POST',
    url: `${oidc(c, r)}/token/introspect`,
    body: { token },
    headers: { Authorization: basic },
  }),

  // The admin REST API takes only tokens with its audience and scope: the
  // admin signs in with the built-in kc-admin-api client scope (optional on
  // the app client), the users without it. The realm comes from the URL.
  adminScope: 'kc-admin-api',
  admin: (token) => ({ token, realmId: null }),
  adminHeaders,

  adminUser: (c, r, a, id) => ({
    method: 'GET',
    url: `${users(c, r)}/${id}`,
    headers: adminHeaders(a),
  }),

  // `cursor` is the offset of the page (null for the first).
  listUsers: (c, r, a, cursor) => ({
    method: 'GET',
    url: `${users(c, r)}?briefRepresentation=true&first=${cursor || 0}&max=${PAGE}`,
    headers: adminHeaders(a),
  }),
  userPage: (res, cursor) => {
    const items = json(res);
    const offset = parseInt(cursor || '0', 10);
    return {
      ids: items.map((u) => u.id),
      next: items.length < PAGE ? null : String(offset + items.length),
    };
  },

  createUser: (c, r, a, email) => ({
    method: 'POST',
    url: users(c, r),
    body: JSON.stringify(userRep(email, 'Stress', 'created')),
    headers: adminHeaders(a),
  }),
  // 201 with `Location: …/users/<id>`.
  createdId: (res) => {
    if (res.status !== 201) return null;
    const m = /\/users\/([0-9a-f-]{36})$/.exec(header(res, 'Location') || '');
    return m ? m[1] : null;
  },

  // The bulk path: partialImport (server_admin guide, "Importing a realm from
  // an exported JSON file"), one transaction per batch. An existing user is
  // skipped and counted as failed, as Hearth's import counts a duplicate.
  importUsers: (c, r, a, batch) => ({
    method: 'POST',
    url: `${c.base}/admin/realms/${r.name}/partialImport`,
    body: JSON.stringify({
      ifResourceExists: 'SKIP',
      users: batch.map((u) => userRep(u.email, 'Bulk', String(u.index))),
    }),
    headers: adminHeaders(a),
  }),
  imported: (res) => {
    if (res.status !== 200) return null;
    const b = json(res);
    return { imported: b.added, failed: b.skipped + b.overwritten };
  },

  // The api client's secret is set when the realm is made (realm.py).
  regenerateSecret: null,
  newSecret: null,
};
