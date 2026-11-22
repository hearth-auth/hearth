// The Zitadel adapter (#913): the same journeys as Hearth through Zitadel's
// own endpoints and its hosted login page (login UI v1, served by Zitadel
// itself). Pure request builders without k6 modules, so node tests them
// (test_products.mjs). The realm (the first instance and its organization),
// its clients and its users come from loadtest/compare/zitadel (zitadel.sh,
// instance.py and the seed).
//
//   login       GET the authorization endpoint (302 to the login page), GET
//               the login page, POST the login name (200 with the password
//               page), POST the password (302 to the authorization callback),
//               GET the callback (302 to the redirect URI with the code),
//               exchange the code with PKCE: 6 requests, one Argon2id password
//               check. The scope adds offline_access: Zitadel issues a refresh
//               token only for it.
//   refresh     refresh_token grant of the public `app` client (Zitadel
//               rotates refresh tokens and refuses a reused one; it also
//               revokes the access token of the refresh token used; the
//               comparison runs with PRESENT=chain, loadtest/compare/README.md)
//   client credentials  the service account `cc` (STRESS_CC_*): in Zitadel an
//               API application cannot take that grant
//   userinfo    GET /oidc/v1/userinfo
//   introspect  RFC 7662 introspection as the `api` API application (basic
//               auth); the users' tokens carry its project in `aud`
//   admin       the user API v2 with a token of the realm admin (the first
//               instance's admin, IAM_OWNER), signed in through the same login
//               page with the Zitadel API audience scope
import { authorizeQuery, codeExchange, header, hidden, json, takeCode, takeTokens } from './common.js';

const tokenUrl = (c) => `${c.base}/oauth/v2/token`;
// A page of listUsers: the user API v2 pages by offset and limit.
const PAGE = 200;
// The admin's scopes besides openid: the Zitadel API audience (the APIs refuse
// tokens without it) and the organization claims (the admin context).
const ADMIN_SCOPE = 'urn:zitadel:iam:org:project:id:zitadel:aud urn:zitadel:iam:user:resourceowner';
const ORG_ID = 'urn:zitadel:iam:user:resourceowner:id';
const ORG_NAME = 'urn:zitadel:iam:user:resourceowner:name';
// The hidden field of the login pages' CSRF token (gorilla/csrf).
const CSRF = 'gorilla.csrf.Token';
// Zitadel refuses a client credentials request without a scope. `profile`
// gets an access token only, as Hearth and Keycloak answer; with `openid`
// Zitadel would also sign an ID token.
const CC_SCOPE = 'profile';

/** True when a login page `body` has a form that posts to `path`. */
export function formPostsTo(body, path) {
  return new RegExp(`<form\\b[^>]*\\baction="${path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`).test(body || '');
}

function adminHeaders(a) {
  return { Authorization: `Bearer ${a.token}`, 'Content-Type': 'application/json' };
}

/**
 * A human of the import (DataHumanUser): the email is also the username;
 * Zitadel picks the id. `hash` is the run's unusable Argon2id hash
 * (STRESS_BULK_PASSWORD_HASH, instance.py): no password matches it, and
 * without it Zitadel would give each user an initialization code and email.
 */
function importHuman(email, first, last, hash) {
  return {
    user: {
      userName: email,
      profile: { firstName: first, lastName: last },
      email: { email, isEmailVerified: true },
      hashedPassword: { value: hash },
      passwordChangeRequired: false,
    },
  };
}

export const zitadel = {
  name: 'zitadel',

  loginSteps: [
    {
      name: 'authorize',
      request: (c, r, f) => ({
        method: 'GET',
        url: `${c.base}/oauth/v2/authorize?${authorizeQuery(
          Object.assign({}, f, { scope: `${f.scope || 'openid'} offline_access` }),
          r.appClientId,
          c.redirectUri,
        )}`,
      }),
      // 302 to /ui/login/login?authRequestID=<id>.
      accept: (res, f) => {
        const m = /[?&]authRequestID=([0-9]+)/.exec(header(res, 'Location') || '');
        if (res.status !== 302 || !m) return false;
        f.authRequest = m[1];
        return true;
      },
    },
    {
      name: 'login_page',
      request: (c, r, f) => ({ method: 'GET', url: `${c.base}/ui/login/login?authRequestID=${f.authRequest}` }),
      accept: (res, f) => {
        f.csrf = hidden(res.body, CSRF);
        return res.status === 200 && f.csrf !== null && formPostsTo(res.body, '/ui/login/loginname');
      },
    },
    {
      name: 'login_name',
      request: (c, r, f) => ({
        method: 'POST',
        url: `${c.base}/ui/login/loginname`,
        body: { [CSRF]: f.csrf, authRequestID: f.authRequest, loginName: f.email },
      }),
      // 200 with the password page; an unknown user gets the login name page again.
      accept: (res, f) => {
        f.csrf = hidden(res.body, CSRF);
        return res.status === 200 && f.csrf !== null && formPostsTo(res.body, '/ui/login/password');
      },
    },
    {
      name: 'login_password',
      request: (c, r, f) => ({
        method: 'POST',
        url: `${c.base}/ui/login/password`,
        body: { [CSRF]: f.csrf, authRequestID: f.authRequest, loginName: f.email, password: f.password },
      }),
      // 302 to the authorization callback; a refused password answers 200 with the form.
      accept: (res, f) => {
        const loc = header(res, 'Location') || '';
        if (res.status !== 302 || !/\/oauth\/v2\/authorize\/callback\?id=/.test(loc)) return false;
        f.callback = loc;
        return true;
      },
    },
    {
      name: 'callback',
      // Zitadel answers an absolute URL; a relative one is on the same server.
      request: (c, r, f) => ({
        method: 'GET',
        url: f.callback.startsWith('/') ? `${c.base}${f.callback}` : f.callback,
      }),
      accept: (res, f) => takeCode(res, f, 302),
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
    body: { grant_type: 'client_credentials', scope: CC_SCOPE },
    headers: { Authorization: basic },
  }),

  userinfo: (c, r, token) => ({
    method: 'GET',
    url: `${c.base}/oidc/v1/userinfo`,
    headers: { Authorization: `Bearer ${token}` },
  }),

  introspect: (c, r, token, basic) => ({
    method: 'POST',
    url: `${c.base}/oauth/v2/introspect`,
    body: { token },
    headers: { Authorization: basic },
  }),

  adminScope: ADMIN_SCOPE,
  /** The admin context from the admin's token claims: the organization's id and name. */
  admin: (token, claims) => ({ token, realmId: claims[ORG_ID], orgName: claims[ORG_NAME] }),
  adminHeaders,

  adminUser: (c, r, a, id) => ({
    method: 'GET',
    url: `${c.base}/v2/users/${id}`,
    headers: adminHeaders(a),
  }),

  // `cursor` is the offset of the page (null for the first). Human users only:
  // the realm's service accounts are not users of the journeys.
  listUsers: (c, r, a, cursor) => ({
    method: 'POST',
    url: `${c.base}/v2/users`,
    body: JSON.stringify({
      query: { offset: String(cursor || 0), limit: PAGE, asc: true },
      queries: [{ typeQuery: { type: 'TYPE_HUMAN' } }],
    }),
    headers: adminHeaders(a),
  }),
  userPage: (res, cursor) => {
    const items = json(res).result || [];
    const offset = parseInt(cursor || '0', 10);
    return {
      ids: items.map((u) => u.userId),
      next: items.length < PAGE ? null : String(offset + items.length),
    };
  },

  // Like Hearth's create: no password and no email. The user API v2 adds no
  // initialization code (unlike the v1 import, see importHuman), and a
  // verified email gets no email code, so no email is sent.
  createUser: (c, r, a, email) => ({
    method: 'POST',
    url: `${c.base}/v2/users/human`,
    body: JSON.stringify({
      username: email,
      organization: { orgId: a.realmId },
      profile: { givenName: 'Stress', familyName: 'created' },
      email: { email, isVerified: true },
    }),
    headers: adminHeaders(a),
  }),
  // 200 with { userId }.
  createdId: (res) => {
    if (res.status !== 200) return null;
    const b = json(res);
    return b && b.userId ? b.userId : null;
  },

  // The bulk path: POST /admin/v1/import (AdminService.ImportData, the
  // migration guide's "bulk import"), into the existing organization; each
  // user gets the run's unusable hash (importHuman). The
  // import first tries to create the organization and reports that it exists
  // (an `errors` entry of type "org"); each user is its own command. An
  // existing user fails and is counted as failed, as Hearth's import counts a
  // duplicate.
  importUsers: (c, r, a, batch) => {
    if (!c.bulkPasswordHash) {
      throw new Error('STRESS_BULK_PASSWORD_HASH is required to seed Zitadel (instance.py)');
    }
    return {
      method: 'POST',
      url: `${c.base}/admin/v1/import`,
      body: JSON.stringify({
        dataOrgs: {
          orgs: [{
            orgId: a.realmId,
            org: { name: a.orgName },
            humanUsers: batch.map((u) => importHuman(u.email, 'Bulk', String(u.index), c.bulkPasswordHash)),
          }],
        },
        timeout: '5m',
      }),
      headers: adminHeaders(a),
    };
  },
  imported: (res) => {
    if (res.status !== 200) return null;
    const b = json(res);
    if (!b) return null;
    const orgs = (b.success && b.success.orgs) || [];
    return {
      imported: orgs.reduce((n, o) => n + (o.humanUserIds || []).length, 0),
      failed: (b.errors || []).filter((e) => e.type === 'human_user').length,
    };
  },

  // The api application's secret and the service account's are generated
  // when the realm is made (instance.py).
  regenerateSecret: null,
  newSecret: null,
};
