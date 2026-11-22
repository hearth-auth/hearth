// The Hearth adapter: the reference product of the comparison (#913) and the
// product of every #647 round. Pure request builders without k6 modules, so
// node tests them (test_products.mjs); lib.js and stress.js send the requests.
//
// Every builder takes `c` (lib.js `env`: base URL, host, redirect URI) and `r`
// (a realm of realms.js) and returns `{ method, url, body, headers }`; an
// object body is sent form-encoded, a string as is.
import { authorizeQuery, codeExchange, header, hidden, json, takeCode, takeTokens } from './common.js';

const tokenUrl = (c, r) => `${c.base}/realms/${r.name}/token`;
const loginUrl = (c, r) => `${c.base}/ui/realms/${r.name}/login`;

/**
 * A sign-in form POST that succeeded. It answers a continue page (`200` with
 * `Refresh: 0;url=…`), not a `303` (form-action-safe-sign-in); a refused
 * sign-in answers `200` with the form and no `Refresh` header.
 */
function signedIn(res) {
  const refresh = header(res, 'Refresh') || '';
  return res.status === 200 && refresh.startsWith('0;url=');
}

/** Headers for the admin API as the realm admin `a` ({ token, realmId }). */
function adminHeaders(a) {
  return {
    Authorization: `Bearer ${a.token}`,
    'X-Realm-ID': a.realmId,
    'Content-Type': 'application/json',
  };
}

export const hearth = {
  name: 'hearth',

  // Sign-in: the hosted login form, then authorization code + PKCE. Each step
  // builds its request from the flow `f` ({ email, password, verifier,
  // challenge, state }) and says whether its response succeeded, keeping what
  // the next step needs in `f`.
  loginSteps: [
    {
      name: 'login_page',
      request: (c, r) => ({ method: 'GET', url: loginUrl(c, r) }),
      accept: (res, f) => {
        f.csrf = hidden(res.body, '_csrf') || '';
        return res.status === 200;
      },
    },
    {
      name: 'login_submit',
      request: (c, r, f) => ({
        method: 'POST',
        url: loginUrl(c, r),
        body: { _csrf: f.csrf, email: f.email, password: f.password },
      }),
      accept: (res) => signedIn(res),
    },
    {
      name: 'authorize',
      request: (c, r, f) => ({
        method: 'GET',
        url: `${c.base}/ui/realms/${r.name}/oauth/authorize?${authorizeQuery(f, r.appClientId, c.redirectUri)}`,
      }),
      accept: (res, f) => takeCode(res, f, 303),
    },
    {
      name: 'code_exchange',
      request: (c, r, f) => codeExchange(tokenUrl(c, r), f, r.appClientId, c.redirectUri),
      accept: takeTokens,
    },
  ],

  refresh: (c, r, refreshToken) => ({
    method: 'POST',
    url: tokenUrl(c, r),
    body: { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: r.appClientId },
  }),

  clientCredentials: (c, r, basic) => ({
    method: 'POST',
    url: tokenUrl(c, r),
    body: { grant_type: 'client_credentials' },
    headers: { Authorization: basic },
  }),

  userinfo: (c, r, token) => ({
    method: 'GET',
    url: `${c.base}/realms/${r.name}/userinfo`,
    headers: { Authorization: `Bearer ${token}` },
  }),

  introspect: (c, r, token, basic) => ({
    method: 'POST',
    url: `${c.base}/realms/${r.name}/introspect`,
    body: { token },
    headers: { Authorization: basic },
  }),

  /** The admin context from the admin's token claims: Hearth's admin API wants the realm id. */
  admin: (token, claims) => ({ token, realmId: claims.tid.replace(/^realm_/, '') }),
  adminHeaders,

  adminUser: (c, r, a, id) => ({
    method: 'GET',
    url: `${c.base}/admin/users/${id}`,
    headers: adminHeaders(a),
  }),

  // A page of the realm's users. `cursor` is null for the first page.
  listUsers: (c, r, a, cursor) => ({
    method: 'GET',
    url: `${c.base}/admin/users?limit=200${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
    headers: adminHeaders(a),
  }),
  // { ids, next } of the listUsers response for `cursor`; next is null after the last page.
  userPage: (res) => {
    const b = json(res);
    const next = b.next_cursor || b.cursor || null;
    return { ids: b.items.map((u) => u.id), next: b.items.length === 0 ? null : next };
  },

  createUser: (c, r, a, email) => ({
    method: 'POST',
    url: `${c.base}/admin/users`,
    body: JSON.stringify({ email, display_name: 'Stress created' }),
    headers: adminHeaders(a),
  }),
  // The new user's id, or null when the create failed.
  createdId: (res) => (res.status === 201 ? json(res).id : null),

  // Password-less users through the bulk path: `users` is [{ email, name, index }].
  importUsers: (c, r, a, users) => ({
    method: 'POST',
    url: `${c.base}/admin/users/import`,
    body: JSON.stringify({
      users: users.map((u) => ({ email: u.email, display_name: u.name })),
    }),
    headers: adminHeaders(a),
  }),
  // { imported, failed } of an import response, or null when it failed as a whole.
  imported: (res) => {
    if (res.status !== 200) return null;
    const b = json(res);
    return { imported: b.imported, failed: b.failed };
  },

  // prepare.js PREPARE_CLIENTS=1: a new secret for the api client, so
  // introspection checks a SHA-256 digest instead of an Argon2id hash.
  regenerateSecret: (c, r, a) => ({
    method: 'POST',
    url: `${c.base}/admin/applications/${r.apiClientId}/regenerate-secret`,
    body: null,
    headers: adminHeaders(a),
  }),
  newSecret: (res) => (res.status === 200 ? json(res).client_secret : null),
};
