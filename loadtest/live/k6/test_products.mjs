// Tests for the product adapters (products/, #913): the requests each one
// builds and how it reads the answers, including each login page's steps.
// The adapters have no k6 imports, so node runs them.
//
// The Hearth cases pin the requests stress.js and lib.js sent before the
// adapters existed: Hearth is the reference, and its ramps must not change.
//
// Usage: node loadtest/live/k6/test_products.mjs
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';

// k6 loads the adapters as ES modules. A copy with a `"type": "module"`
// package.json makes node do the same, whatever its version.
const dir = mkdtempSync(join(tmpdir(), 'products-'));
cpSync(new URL('./products/', import.meta.url), dir, { recursive: true });
writeFileSync(join(dir, 'package.json'), '{"type": "module"}\n');
const load = (f) => import(pathToFileURL(join(dir, f)).href);
const { PRODUCTS, productFor } = await load('index.js');
const common = await load('common.js');
const { loginAction } = await load('keycloak.js');
const { formPostsTo } = await load('zitadel.js');
const oryHelpers = await load('ory.js');
rmSync(dir, { recursive: true, force: true });
const { hearth, keycloak, ory, zitadel } = PRODUCTS;

const c = {
  base: 'https://server.stress.test:8443',
  host: 'server.stress.test',
  redirectUri: 'https://app.stress.test/callback',
};
const r = { name: 'stress', appClientId: 'app-id', apiClientId: 'api-id', apiSecret: 's' };
const flow = () => ({
  email: 'user000001@server.stress.test',
  password: 'pw',
  verifier: 'ver',
  challenge: 'chal',
  state: 'st',
});
const res = (status, headers = {}, body = '') => ({ status, headers, body });
const tokens = res(200, {}, JSON.stringify({ access_token: 'at', refresh_token: 'rt' }));

// Runs `p`'s login steps for flow `f`; `answer(step, spec)` plays the server.
// Returns the failed step's name, or null when every step was accepted.
function runLogin(p, f, answer) {
  for (const step of p.loginSteps) {
    const spec = step.request(c, r, f);
    if (!step.accept(answer(step.name, spec), f)) return step.name;
  }
  return null;
}

test('PRODUCT picks the adapter; hearth when unset', () => {
  assert.equal(productFor(undefined), hearth);
  assert.equal(productFor(''), hearth);
  assert.equal(productFor('keycloak'), keycloak);
  assert.equal(productFor('zitadel'), zitadel);
  assert.equal(productFor('ory'), ory);
  assert.throws(() => productFor('fusionauth'), /PRODUCT must be one of hearth, keycloak/);
});

test('every adapter supplies every operation', () => {
  const ops = ['refresh', 'clientCredentials', 'userinfo', 'introspect', 'admin', 'adminHeaders',
    'adminUser', 'listUsers', 'userPage', 'createUser', 'createdId', 'importUsers', 'imported'];
  for (const p of Object.values(PRODUCTS)) {
    for (const op of ops) assert.equal(typeof p[op], 'function', `${p.name}.${op}`);
    assert.ok(p.loginSteps.length > 0);
    assert.equal(p.loginSteps.at(-1).name, 'code_exchange', p.name);
  }
});

test('common: redirect parameters, headers in any case, JSON', () => {
  assert.deepEqual(common.redirectParams('https://a/cb?code=x%2By&state=a+b'), { code: 'x+y', state: 'a b' });
  assert.deepEqual(common.redirectParams(undefined), {});
  assert.equal(common.header(res(200, { location: '/x' }), 'Location'), '/x');
  assert.equal(common.header(res(200, {}), 'Location'), undefined);
  assert.equal(common.json(res(200, {}, 'not json')), null);
});

test('hearth: the login requests are the ones lib.js sent', () => {
  const f = flow();
  const seen = [];
  const failed = runLogin(hearth, f, (name, spec) => {
    seen.push([name, spec]);
    if (name === 'login_page') return res(200, {}, '<input name="_csrf" value="tok">');
    if (name === 'login_submit') return res(200, { Refresh: '0;url=/next' });
    if (name === 'authorize') return res(303, { Location: `${c.redirectUri}?code=cd&state=st` });
    return tokens;
  });
  assert.equal(failed, null);
  assert.equal(f.access, 'at');
  assert.equal(f.refresh, 'rt');
  assert.deepEqual(seen, [
    ['login_page', { method: 'GET', url: `${c.base}/ui/realms/stress/login` }],
    ['login_submit', {
      method: 'POST',
      url: `${c.base}/ui/realms/stress/login`,
      body: { _csrf: 'tok', email: f.email, password: 'pw' },
    }],
    ['authorize', {
      method: 'GET',
      url: `${c.base}/ui/realms/stress/oauth/authorize?response_type=code&client_id=app-id`
        + `&redirect_uri=${encodeURIComponent(c.redirectUri)}&state=st&scope=openid`
        + '&code_challenge=chal&code_challenge_method=S256',
    }],
    ['code_exchange', {
      method: 'POST',
      url: `${c.base}/realms/stress/token`,
      body: {
        grant_type: 'authorization_code',
        code: 'cd',
        redirect_uri: c.redirectUri,
        client_id: 'app-id',
        code_verifier: 'ver',
      },
    }],
  ]);
});

test('hearth: a refused sign-in, a wrong state and a missing token fail their step', () => {
  const page = res(200, {}, '');
  assert.equal(runLogin(hearth, flow(), (n) => (n === 'login_page' ? res(503) : null)), 'login_page');
  // A refused password answers the form again: 200 without Refresh.
  assert.equal(runLogin(hearth, flow(), (n) => (n === 'login_page' ? page : res(200))), 'login_submit');
  assert.equal(
    runLogin(hearth, flow(), (n) => {
      if (n === 'login_page') return page;
      if (n === 'login_submit') return res(200, { refresh: '0;url=/x' });
      return res(303, { location: `${c.redirectUri}?code=cd&state=other` });
    }),
    'authorize',
  );
  assert.equal(
    runLogin(hearth, flow(), (n) => {
      if (n === 'login_page') return page;
      if (n === 'login_submit') return res(200, { Refresh: '0;url=/x' });
      if (n === 'authorize') return res(303, { Location: `${c.redirectUri}?code=cd&state=st` });
      return res(200, {}, '{}');
    }),
    'code_exchange',
  );
});

test('hearth: the journey and admin requests are the ones stress.js and prepare.js sent', () => {
  const a = hearth.admin('adm', { tid: 'realm_1234' });
  const h = { Authorization: 'Bearer adm', 'X-Realm-ID': '1234', 'Content-Type': 'application/json' };
  assert.deepEqual(a, { token: 'adm', realmId: '1234' });
  assert.deepEqual(hearth.adminHeaders(a), h);
  assert.deepEqual(hearth.refresh(c, r, 'rt'), {
    method: 'POST',
    url: `${c.base}/realms/stress/token`,
    body: { grant_type: 'refresh_token', refresh_token: 'rt', client_id: 'app-id' },
  });
  assert.deepEqual(hearth.introspect(c, r, 'at', 'Basic x'), {
    method: 'POST',
    url: `${c.base}/realms/stress/introspect`,
    body: { token: 'at' },
    headers: { Authorization: 'Basic x' },
  });
  assert.deepEqual(hearth.clientCredentials(c, r, 'Basic x'), {
    method: 'POST',
    url: `${c.base}/realms/stress/token`,
    body: { grant_type: 'client_credentials' },
    headers: { Authorization: 'Basic x' },
  });
  assert.deepEqual(hearth.userinfo(c, r, 'at'), {
    method: 'GET',
    url: `${c.base}/realms/stress/userinfo`,
    headers: { Authorization: 'Bearer at' },
  });
  assert.deepEqual(hearth.adminUser(c, r, a, 'u1'), { method: 'GET', url: `${c.base}/admin/users/u1`, headers: h });
  assert.equal(hearth.listUsers(c, r, a, null).url, `${c.base}/admin/users?limit=200`);
  assert.equal(hearth.listUsers(c, r, a, 'a/b').url, `${c.base}/admin/users?limit=200&cursor=a%2Fb`);
  assert.deepEqual(hearth.createUser(c, r, a, 'e@x'), {
    method: 'POST',
    url: `${c.base}/admin/users`,
    body: JSON.stringify({ email: 'e@x', display_name: 'Stress created' }),
    headers: h,
  });
  assert.deepEqual(hearth.importUsers(c, r, a, [{ email: 'bulk00000007@x', name: 'Bulk 7', index: 7 }]), {
    method: 'POST',
    url: `${c.base}/admin/users/import`,
    body: JSON.stringify({ users: [{ email: 'bulk00000007@x', display_name: 'Bulk 7' }] }),
    headers: h,
  });
  assert.deepEqual(hearth.regenerateSecret(c, r, a), {
    method: 'POST',
    url: `${c.base}/admin/applications/api-id/regenerate-secret`,
    body: null,
    headers: h,
  });
});

test('hearth: reads pages, created users, imports and secrets', () => {
  const page = (body) => hearth.userPage(res(200, {}, JSON.stringify(body)), null);
  assert.deepEqual(page({ items: [{ id: 'a' }, { id: 'b' }], next_cursor: 'n' }), { ids: ['a', 'b'], next: 'n' });
  assert.deepEqual(page({ items: [{ id: 'a' }], cursor: 'm' }), { ids: ['a'], next: 'm' });
  assert.deepEqual(page({ items: [{ id: 'a' }] }), { ids: ['a'], next: null });
  assert.deepEqual(page({ items: [], next_cursor: 'n' }), { ids: [], next: null });
  assert.equal(hearth.createdId(res(201, {}, '{"id":"u1"}')), 'u1');
  assert.equal(hearth.createdId(res(409, {}, '{}')), null);
  assert.deepEqual(hearth.imported(res(200, {}, '{"imported":4,"failed":1}')), { imported: 4, failed: 1 });
  assert.equal(hearth.imported(res(413)), null);
  assert.equal(hearth.newSecret(res(200, {}, '{"client_secret":"new"}')), 'new');
  assert.equal(hearth.newSecret(res(409)), null);
});

// The login form of Keycloak's keycloak.v2 theme, cut down: the attributes in
// their order, with the action's `&` escaped as the template writes it.
const kcPage = `<html><body><div>
<form id="kc-form-login" class="pf-v5-c-form" onsubmit="login.disabled = true; return true;"
  action="https://server.stress.test:8443/realms/stress/login-actions/authenticate?session_code=sc&amp;execution=ex&amp;client_id=app-id&amp;tab_id=tb&amp;client_data=cd" method="post" novalidate="novalidate">
<input id="username" name="username" value="" type="text">
</form></div></body></html>`;

test('keycloak: the login form action, unescaped', () => {
  assert.equal(
    loginAction(kcPage),
    'https://server.stress.test:8443/realms/stress/login-actions/authenticate?session_code=sc&execution=ex&client_id=app-id&tab_id=tb&client_data=cd',
  );
  // An escaped entity is unescaped once only.
  assert.equal(loginAction('<form id="kc-form-login" action="/a?x=&amp;lt;"></form>'), '/a?x=&lt;');
  assert.equal(loginAction('<form id="other" action="/x"></form>'), null);
  assert.equal(loginAction(''), null);
  assert.equal(loginAction(undefined), null);
});

test('keycloak: login through its own page with PKCE', () => {
  const f = flow();
  const seen = [];
  const failed = runLogin(keycloak, f, (name, spec) => {
    seen.push([name, spec]);
    if (name === 'login_page') return res(200, {}, kcPage);
    if (name === 'login_submit') return res(302, { Location: `${c.redirectUri}?state=st&session_state=x&iss=y&code=cd` });
    return tokens;
  });
  assert.equal(failed, null);
  assert.equal(f.access, 'at');
  const oidc = `${c.base}/realms/stress/protocol/openid-connect`;
  assert.deepEqual(seen, [
    ['login_page', {
      method: 'GET',
      url: `${oidc}/auth?response_type=code&client_id=app-id`
        + `&redirect_uri=${encodeURIComponent(c.redirectUri)}&state=st&scope=openid`
        + '&code_challenge=chal&code_challenge_method=S256',
    }],
    ['login_submit', {
      method: 'POST',
      url: loginAction(kcPage),
      body: { username: f.email, password: 'pw', credentialId: '' },
    }],
    ['code_exchange', {
      method: 'POST',
      url: `${oidc}/token`,
      body: {
        grant_type: 'authorization_code',
        code: 'cd',
        redirect_uri: c.redirectUri,
        client_id: 'app-id',
        code_verifier: 'ver',
      },
    }],
  ]);
});

test('the admin scope: Keycloak asks for kc-admin-api, Hearth for openid only', () => {
  // lib.js sets f.scope to `openid <adminScope>` for an admin sign-in, when
  // the product has an admin scope.
  assert.equal(hearth.adminScope, undefined);
  assert.equal(keycloak.adminScope, 'kc-admin-api');
  const f = Object.assign(flow(), { scope: 'openid kc-admin-api' });
  const url = keycloak.loginSteps[0].request(c, r, f).url;
  assert.match(url, /&scope=openid%20kc-admin-api&/);
  assert.match(keycloak.loginSteps[0].request(c, r, flow()).url, /&scope=openid&/);
});

test('keycloak: a page without the form, a refused password and a wrong state fail their step', () => {
  assert.equal(runLogin(keycloak, flow(), () => res(200, {}, '<html>error</html>')), 'login_page');
  assert.equal(runLogin(keycloak, flow(), (n) => (n === 'login_page' ? res(503, {}, kcPage) : null)), 'login_page');
  // A refused password answers 200 with the form again.
  assert.equal(runLogin(keycloak, flow(), (n) => res(200, {}, kcPage)), 'login_submit');
  assert.equal(
    runLogin(keycloak, flow(), (n) => (n === 'login_page' ? res(200, {}, kcPage)
      : res(302, { Location: `${c.redirectUri}?state=other&code=cd` }))),
    'login_submit',
  );
});

test('keycloak: journey and admin requests', () => {
  const oidc = `${c.base}/realms/stress/protocol/openid-connect`;
  const a = keycloak.admin('adm', {});
  const h = { Authorization: 'Bearer adm', 'Content-Type': 'application/json' };
  assert.deepEqual(keycloak.adminHeaders(a), h);
  assert.deepEqual(keycloak.refresh(c, r, 'rt').body, { grant_type: 'refresh_token', refresh_token: 'rt', client_id: 'app-id' });
  assert.equal(keycloak.refresh(c, r, 'rt').url, `${oidc}/token`);
  assert.deepEqual(keycloak.clientCredentials(c, r, 'Basic x'), {
    method: 'POST',
    url: `${oidc}/token`,
    body: { grant_type: 'client_credentials' },
    headers: { Authorization: 'Basic x' },
  });
  assert.deepEqual(keycloak.introspect(c, r, 'at', 'Basic x'), {
    method: 'POST',
    url: `${oidc}/token/introspect`,
    body: { token: 'at' },
    headers: { Authorization: 'Basic x' },
  });
  assert.equal(keycloak.userinfo(c, r, 'at').url, `${oidc}/userinfo`);
  assert.deepEqual(keycloak.adminUser(c, r, a, 'u1'), {
    method: 'GET',
    url: `${c.base}/admin/realms/stress/users/u1`,
    headers: h,
  });
  assert.equal(
    keycloak.listUsers(c, r, a, null).url,
    `${c.base}/admin/realms/stress/users?briefRepresentation=true&first=0&max=200`,
  );
  assert.equal(
    keycloak.listUsers(c, r, a, '400').url,
    `${c.base}/admin/realms/stress/users?briefRepresentation=true&first=400&max=200`,
  );
  const created = keycloak.createUser(c, r, a, 'e@x');
  assert.equal(created.url, `${c.base}/admin/realms/stress/users`);
  assert.deepEqual(JSON.parse(created.body), {
    username: 'e@x', email: 'e@x', firstName: 'Stress', lastName: 'created', enabled: true, emailVerified: true,
  });
  const imp = keycloak.importUsers(c, r, a, [{ email: 'bulk00000007@x', name: 'Bulk 7', index: 7 }]);
  assert.equal(imp.url, `${c.base}/admin/realms/stress/partialImport`);
  assert.deepEqual(JSON.parse(imp.body), {
    ifResourceExists: 'SKIP',
    users: [{
      username: 'bulk00000007@x', email: 'bulk00000007@x', firstName: 'Bulk', lastName: '7', enabled: true, emailVerified: true,
    }],
  });
  assert.equal(keycloak.regenerateSecret, null);
});

test('keycloak: reads pages by offset, created ids from Location, import counts', () => {
  const ids = (n) => JSON.stringify(Array.from({ length: n }, (_, i) => ({ id: `u${i}` })));
  const full = keycloak.userPage(res(200, {}, ids(200)), '400');
  assert.equal(full.ids.length, 200);
  assert.equal(full.next, '600');
  assert.equal(keycloak.userPage(res(200, {}, ids(200)), null).next, '200');
  assert.deepEqual(keycloak.userPage(res(200, {}, ids(3)), '200'), { ids: ['u0', 'u1', 'u2'], next: null });
  const id = '0b8f5a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
  assert.equal(keycloak.createdId(res(201, { Location: `${c.base}/admin/realms/stress/users/${id}` })), id);
  assert.equal(keycloak.createdId(res(201, {})), null);
  assert.equal(keycloak.createdId(res(409, { Location: `/users/${id}` })), null);
  assert.deepEqual(
    keycloak.imported(res(200, {}, '{"added":3,"skipped":2,"overwritten":0,"results":[]}')),
    { imported: 3, failed: 2 },
  );
  assert.equal(keycloak.imported(res(500)), null);
});

// Zitadel's login UI v1, as v4.20.5 renders it (attributes in its order).
const ztNamePage = '<form action="/ui/login/loginname" method="POST">'
  + '<input type="hidden" name="gorilla.csrf.Token" value="csrf1">'
  + '<input type="hidden" name="authRequestID" value="4007" />'
  + '<input class="lgn-input" type="text" id="loginName" name="loginName" value="" required></form>';
const ztPasswordPage = '<form action="/ui/login/password" method="POST">'
  + '<input type="hidden" name="gorilla.csrf.Token" value="csrf2">'
  + '<input type="hidden" name="authRequestID" value="4007" />'
  + '<input type="password" id="password" name="password" required></form>';
const ztCallback = `${c.base}/oauth/v2/authorize/callback?id=4007`;

// Plays Zitadel for a sign-in that succeeds; `over` replaces a step's answer.
function ztAnswer(over = {}) {
  return (name) => {
    if (name in over) return over[name];
    if (name === 'authorize') return res(302, { Location: '/ui/login/login?authRequestID=4007' });
    if (name === 'login_page') return res(200, {}, ztNamePage);
    if (name === 'login_name') return res(200, {}, ztPasswordPage);
    if (name === 'login_password') return res(302, { Location: ztCallback });
    if (name === 'callback') return res(302, { Location: `${c.redirectUri}?code=cd&state=st` });
    return tokens;
  };
}

test('zitadel: login through its own pages (login UI v1) with PKCE', () => {
  const f = flow();
  const seen = [];
  const answer = ztAnswer();
  const failed = runLogin(zitadel, f, (name, spec) => {
    seen.push([name, spec]);
    return answer(name);
  });
  assert.equal(failed, null);
  assert.equal(f.access, 'at');
  assert.equal(f.refresh, 'rt');
  assert.deepEqual(seen, [
    ['authorize', {
      method: 'GET',
      // offline_access: Zitadel issues a refresh token only for it.
      url: `${c.base}/oauth/v2/authorize?response_type=code&client_id=app-id`
        + `&redirect_uri=${encodeURIComponent(c.redirectUri)}&state=st&scope=openid%20offline_access`
        + '&code_challenge=chal&code_challenge_method=S256',
    }],
    ['login_page', { method: 'GET', url: `${c.base}/ui/login/login?authRequestID=4007` }],
    ['login_name', {
      method: 'POST',
      url: `${c.base}/ui/login/loginname`,
      body: { 'gorilla.csrf.Token': 'csrf1', authRequestID: '4007', loginName: f.email },
    }],
    ['login_password', {
      method: 'POST',
      url: `${c.base}/ui/login/password`,
      // Each page has its own CSRF token.
      body: { 'gorilla.csrf.Token': 'csrf2', authRequestID: '4007', loginName: f.email, password: 'pw' },
    }],
    ['callback', { method: 'GET', url: ztCallback }],
    ['code_exchange', {
      method: 'POST',
      url: `${c.base}/oauth/v2/token`,
      body: {
        grant_type: 'authorization_code',
        code: 'cd',
        redirect_uri: c.redirectUri,
        client_id: 'app-id',
        code_verifier: 'ver',
      },
    }],
  ]);
  // The flow's scope is left as lib.js made it.
  assert.equal(f.scope, undefined);
});

test('zitadel: the admin asks for the API audience; its organization comes from the environment', () => {
  assert.equal(zitadel.adminScope, 'urn:zitadel:iam:org:project:id:zitadel:aud');
  const f = Object.assign(flow(), { scope: `openid ${zitadel.adminScope}` });
  assert.match(
    zitadel.loginSteps[0].request(c, r, f).url,
    /&scope=openid%20urn%3Azitadel%3Aiam%3Aorg%3Aproject%3Aid%3Azitadel%3Aaud%20offline_access&/,
  );
  // Opaque tokens: no claims; instance.py writes the organization to generator.env.
  const zc = Object.assign({}, c, { orgId: '4006', orgName: 'stress' });
  assert.deepEqual(zitadel.admin('adm', null, zc), { token: 'adm', realmId: '4006', orgName: 'stress' });
  assert.throws(() => zitadel.admin('adm', null, c), /STRESS_ORG_ID and STRESS_ORG_NAME are required/);
  // Only Hearth's admin context comes from its access token's claims.
  assert.equal(hearth.adminClaims, true);
  for (const p of [keycloak, zitadel, ory]) assert.equal(p.adminClaims, undefined);
});

test('zitadel: a missing form, an unknown user, a refused password and a wrong state fail their step', () => {
  assert.equal(runLogin(zitadel, flow(), ztAnswer({ authorize: res(400, {}, 'invalid_request') })), 'authorize');
  assert.equal(runLogin(zitadel, flow(), ztAnswer({ authorize: res(302, { Location: '/ui/login/login' }) })), 'authorize');
  assert.equal(runLogin(zitadel, flow(), ztAnswer({ login_page: res(200, {}, '<html>error</html>') })), 'login_page');
  // An unknown login name answers the login name page again.
  assert.equal(runLogin(zitadel, flow(), ztAnswer({ login_name: res(200, {}, ztNamePage) })), 'login_name');
  // A refused password answers 200 with the password page again.
  assert.equal(runLogin(zitadel, flow(), ztAnswer({ login_password: res(200, {}, ztPasswordPage) })), 'login_password');
  assert.equal(
    runLogin(zitadel, flow(), ztAnswer({ login_password: res(302, { Location: '/ui/login/mfa/prompt' }) })),
    'login_password',
  );
  assert.equal(
    runLogin(zitadel, flow(), ztAnswer({ callback: res(302, { Location: `${c.redirectUri}?code=cd&state=other` }) })),
    'callback',
  );
  assert.equal(runLogin(zitadel, flow(), ztAnswer({ code_exchange: res(400, {}, '{"error":"invalid_grant"}') })), 'code_exchange');
});

test('zitadel: a relative callback location stays on the server', () => {
  const f = flow();
  const seen = [];
  const answer = ztAnswer({ login_password: res(302, { Location: '/oauth/v2/authorize/callback?id=4007' }) });
  runLogin(zitadel, f, (name, spec) => {
    seen.push([name, spec.url]);
    return answer(name);
  });
  assert.deepEqual(seen.find(([n]) => n === 'callback'), ['callback', ztCallback]);
});

test('zitadel: formPostsTo matches a form by its action only', () => {
  assert.equal(formPostsTo(ztNamePage, '/ui/login/loginname'), true);
  assert.equal(formPostsTo(ztNamePage, '/ui/login/password'), false);
  assert.equal(formPostsTo('<a href="/ui/login/password">', '/ui/login/password'), false);
  assert.equal(formPostsTo(undefined, '/ui/login/password'), false);
});

test('zitadel: journey and admin requests', () => {
  const a = { token: 'adm', realmId: '4006', orgName: 'stress' };
  const h = { Authorization: 'Bearer adm', 'Content-Type': 'application/json' };
  assert.deepEqual(zitadel.adminHeaders(a), h);
  assert.deepEqual(zitadel.refresh(c, r, 'rt'), {
    method: 'POST',
    url: `${c.base}/oauth/v2/token`,
    body: { grant_type: 'refresh_token', refresh_token: 'rt', client_id: 'app-id' },
  });
  // Zitadel refuses the grant without a scope; `profile` answers an access token only.
  assert.deepEqual(zitadel.clientCredentials(c, r, 'Basic x'), {
    method: 'POST',
    url: `${c.base}/oauth/v2/token`,
    body: { grant_type: 'client_credentials', scope: 'profile' },
    headers: { Authorization: 'Basic x' },
  });
  assert.deepEqual(zitadel.introspect(c, r, 'at', 'Basic x'), {
    method: 'POST',
    url: `${c.base}/oauth/v2/introspect`,
    body: { token: 'at' },
    headers: { Authorization: 'Basic x' },
  });
  assert.deepEqual(zitadel.userinfo(c, r, 'at'), {
    method: 'GET',
    url: `${c.base}/oidc/v1/userinfo`,
    headers: { Authorization: 'Bearer at' },
  });
  assert.deepEqual(zitadel.adminUser(c, r, a, '4008'), { method: 'GET', url: `${c.base}/v2/users/4008`, headers: h });
  const list = zitadel.listUsers(c, r, a, null);
  assert.equal(list.method, 'POST');
  assert.equal(list.url, `${c.base}/v2/users`);
  assert.deepEqual(JSON.parse(list.body), {
    query: { offset: '0', limit: 200, asc: true },
    queries: [{ typeQuery: { type: 'TYPE_HUMAN' } }],
  });
  assert.equal(JSON.parse(zitadel.listUsers(c, r, a, '400').body).query.offset, '400');
  const created = zitadel.createUser(c, r, a, 'e@x');
  assert.equal(created.url, `${c.base}/v2/users/human`);
  assert.deepEqual(JSON.parse(created.body), {
    username: 'e@x',
    organization: { orgId: '4006' },
    profile: { givenName: 'Stress', familyName: 'created' },
    email: { email: 'e@x', isVerified: true },
  });
  const hash = '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnZXN0';
  const zc = Object.assign({}, c, { bulkPasswordHash: hash });
  const imp = zitadel.importUsers(zc, r, a, [{ email: 'bulk00000007@x', name: 'Bulk 7', index: 7 }]);
  assert.equal(imp.url, `${c.base}/admin/v1/import`);
  assert.deepEqual(JSON.parse(imp.body), {
    dataOrgs: {
      orgs: [{
        orgId: '4006',
        org: { name: 'stress' },
        humanUsers: [{
          user: {
            userName: 'bulk00000007@x',
            profile: { firstName: 'Bulk', lastName: '7' },
            email: { email: 'bulk00000007@x', isEmailVerified: true },
            // Without a password or hash Zitadel gives each user an init code and email.
            hashedPassword: { value: hash },
            passwordChangeRequired: false,
          },
        }],
      }],
    },
    timeout: '5m',
  });
  // Without the run's hash the seed stops instead of making users in their initial state.
  assert.throws(() => zitadel.importUsers(c, r, a, []), /STRESS_BULK_PASSWORD_HASH is required/);
  assert.equal(zitadel.regenerateSecret, null);
});

test('zitadel: reads pages by offset, created ids, import counts', () => {
  const page = (n) => JSON.stringify({
    details: { totalResult: '1003' },
    result: Array.from({ length: n }, (_, i) => ({ userId: `4${i}` })),
  });
  const full = zitadel.userPage(res(200, {}, page(200)), '400');
  assert.equal(full.ids.length, 200);
  assert.equal(full.next, '600');
  assert.equal(zitadel.userPage(res(200, {}, page(200)), null).next, '200');
  assert.deepEqual(zitadel.userPage(res(200, {}, page(2)), '200'), { ids: ['40', '41'], next: null });
  // An empty last page has no `result` at all.
  assert.deepEqual(zitadel.userPage(res(200, {}, '{"details":{}}'), '1000'), { ids: [], next: null });
  assert.equal(zitadel.createdId(res(200, {}, '{"userId":"4009","details":{}}')), '4009');
  assert.equal(zitadel.createdId(res(200, {}, '{}')), null);
  assert.equal(zitadel.createdId(res(409, {}, '{"userId":"4009"}')), null);
  // The existing organization is reported as an error; it is not a failed user.
  const answer = {
    errors: [
      { type: 'org', id: '4006', message: 'ID=V2-zzz Message=Errors.Org.AlreadyExists' },
      { type: 'human_user', id: '', message: 'Errors.User.AlreadyExists' },
    ],
    success: { orgs: [{ orgId: '4006', humanUserIds: ['41', '42'] }] },
  };
  assert.deepEqual(zitadel.imported(res(200, {}, JSON.stringify(answer))), { imported: 2, failed: 1 });
  assert.deepEqual(zitadel.imported(res(200, {}, '{"success":{"orgs":[{"orgId":"4006"}]}}')), { imported: 0, failed: 0 });
  assert.equal(zitadel.imported(res(504, {}, 'timeout')), null);
});

// Ory: Hydra's public port is c.base; the UI, Kratos and the admin ports are
// on the same host.
const oUi = 'https://server.stress.test:4455';
const oKratos = 'https://server.stress.test:4433';
const oFlowAction = `${oKratos}/self-service/login?flow=f1`;
// The login page as the reference UI renders it (Ory Elements): the CSRF
// input has attributes between its name and its value.
const oLoginPage = `<form class="ory_elements__form" action="${oFlowAction}" method="POST" data-testid="login-flow">`
  + '<input data-testid="node/input/csrf_token" name="csrf_token" type="hidden" autoComplete="" required="" value="csrf1"/>'
  + '<input class="x" id=":R1:" name="identifier" type="text" autoComplete="username" required="" value=""/>'
  + '<button type="submit" name="method" value="password"></button></form>';
const oVerifier = (kind) => `${c.base}/oauth2/auth?client_id=app-id&state=st&${kind}_verifier=v1`;

// Plays Ory for a sign-in that succeeds; `over` replaces a step's answer.
function oryAnswer(over = {}) {
  return (name) => {
    if (name in over) return over[name];
    const to = (status, location) => res(status, { Location: location });
    if (name === 'authorize') return to(302, `${oUi}/login?login_challenge=lc1`);
    if (name === 'login_challenge') {
      return to(303, `${oKratos}/self-service/login/browser?aal=&refresh=&return_to=&organization=&via=&login_challenge=lc1`);
    }
    if (name === 'login_flow') return to(303, `${oUi}/login?flow=f1`);
    if (name === 'login_page') return res(200, {}, oLoginPage);
    if (name === 'login_submit') return to(303, oVerifier('login'));
    if (name === 'login_verifier') return to(302, `${oUi}/consent?consent_challenge=cc1`);
    if (name === 'consent') return to(302, oVerifier('consent'));
    if (name === 'consent_verifier') return to(303, `${c.redirectUri}?code=cd&scope=openid+offline_access&state=st`);
    return res(200, {}, JSON.stringify({ access_token: 'at', refresh_token: 'ory_rt_x' }));
  };
}

test('ory: login through Hydra, the reference UI and Kratos with PKCE', () => {
  const f = flow();
  const seen = [];
  const answer = oryAnswer();
  const failed = runLogin(ory, f, (name, spec) => {
    seen.push([name, spec]);
    return answer(name);
  });
  assert.equal(failed, null);
  assert.equal(f.access, 'at');
  assert.equal(f.refresh, 'ory_rt_x');
  assert.deepEqual(seen, [
    ['authorize', {
      method: 'GET',
      // offline_access: Hydra issues a refresh token only for it.
      url: `${c.base}/oauth2/auth?response_type=code&client_id=app-id`
        + `&redirect_uri=${encodeURIComponent(c.redirectUri)}&state=st&scope=openid%20offline_access`
        + '&code_challenge=chal&code_challenge_method=S256',
    }],
    ['login_challenge', { method: 'GET', url: `${oUi}/login?login_challenge=lc1` }],
    ['login_flow', {
      method: 'GET',
      url: `${oKratos}/self-service/login/browser?aal=&refresh=&return_to=&organization=&via=&login_challenge=lc1`,
    }],
    ['login_page', { method: 'GET', url: `${oUi}/login?flow=f1` }],
    ['login_submit', {
      method: 'POST',
      url: oFlowAction,
      body: { csrf_token: 'csrf1', identifier: f.email, password: 'pw', method: 'password' },
    }],
    ['login_verifier', { method: 'GET', url: oVerifier('login') }],
    ['consent', { method: 'GET', url: `${oUi}/consent?consent_challenge=cc1` }],
    ['consent_verifier', { method: 'GET', url: oVerifier('consent') }],
    ['code_exchange', {
      method: 'POST',
      url: `${c.base}/oauth2/token`,
      body: {
        grant_type: 'authorization_code',
        code: 'cd',
        redirect_uri: c.redirectUri,
        client_id: 'app-id',
        code_verifier: 'ver',
      },
    }],
  ]);
  // The flow's scope is left as lib.js made it; Ory has no admin scope.
  assert.equal(f.scope, undefined);
  assert.equal(ory.adminScope, undefined);
});

test('ory: a refused password, a page without the form, a redirect elsewhere and a wrong state fail their step', () => {
  const fails = (over) => runLogin(ory, flow(), oryAnswer(over));
  assert.equal(fails({ authorize: res(400, {}, 'invalid_request') }), 'authorize');
  // Hydra's error page instead of the login page.
  assert.equal(fails({ authorize: res(302, { Location: `${oUi}/error?error=invalid_client` }) }), 'authorize');
  assert.equal(fails({ authorize: res(302, { Location: `https://evil.test:4455/login?login_challenge=lc1` }) }), 'authorize');
  assert.equal(fails({ login_challenge: res(500, {}, 'error') }), 'login_challenge');
  assert.equal(fails({ login_flow: res(303, { Location: `${oUi}/error?id=e1` }) }), 'login_flow');
  assert.equal(fails({ login_page: res(200, {}, '<html>error</html>') }), 'login_page');
  assert.equal(fails({ login_page: res(200, {}, oLoginPage.replace(/name="csrf_token"/, 'name="other"')) }), 'login_page');
  assert.equal(
    fails({ login_page: res(200, {}, oLoginPage.replace(oFlowAction, 'https://evil.test/self-service/login?flow=f1')) }),
    'login_page',
  );
  // Kratos sends a refused password back to the UI's login page.
  assert.equal(fails({ login_submit: res(303, { Location: `${oUi}/login?flow=f1` }) }), 'login_submit');
  assert.equal(fails({ login_verifier: res(302, { Location: `${oUi}/error?error=x` }) }), 'login_verifier');
  // A consent page shown (no skip_consent) is not a redirect.
  assert.equal(fails({ consent: res(200, {}, '<form action="consent">') }), 'consent');
  assert.equal(
    fails({ consent_verifier: res(303, { Location: `${c.redirectUri}?code=cd&state=other` }) }),
    'consent_verifier',
  );
  assert.equal(fails({ code_exchange: res(400, {}, '{"error":"invalid_grant"}') }), 'code_exchange');
});

test('ory: helpers for ports, redirects, the login form and Kratos page links', () => {
  assert.equal(oryHelpers.at(c, 4445), 'https://server.stress.test:4445');
  assert.equal(oryHelpers.at({ base: 'https://h.test' }, 4434), 'https://h.test:4434');
  assert.throws(() => oryHelpers.at({ base: 'h.test' }, 1), /not an http\(s\) URL/);
  const f = {};
  assert.equal(oryHelpers.redirectsTo(res(302, { location: `${oUi}/x?a=1&p=2` }), f, `${oUi}/x?`, 'p'), true);
  assert.equal(f.next, `${oUi}/x?a=1&p=2`);
  // The parameter must be there and have a value.
  assert.equal(oryHelpers.redirectsTo(res(302, { Location: `${oUi}/x?p=` }), {}, `${oUi}/x?`, 'p'), false);
  assert.equal(oryHelpers.redirectsTo(res(302, { Location: `${oUi}/x?xp=1` }), {}, `${oUi}/x?`, 'p'), false);
  assert.equal(oryHelpers.redirectsTo(res(200, { Location: `${oUi}/x?p=1` }), {}, `${oUi}/x?`, 'p'), false);
  assert.equal(oryHelpers.loginAction(oLoginPage), oFlowAction);
  assert.equal(oryHelpers.loginAction('<form action="/a&amp;b" data-testid="login-flow">'), '/a&b');
  assert.equal(oryHelpers.loginAction('<form action="/other">'), null);
  assert.equal(oryHelpers.inputValue(oLoginPage, 'csrf_token'), 'csrf1');
  assert.equal(oryHelpers.inputValue(oLoginPage, 'missing'), null);
  const link = '</admin/identities?page_size=200&page_token=00000000-0000-0000-0000-000000000000>; rel="first",'
    + '</admin/identities?page_size=200&page_token=00dc35ee-7949-460b-a2b7-40a9cecbab18>; rel="next"';
  assert.equal(oryHelpers.nextPageToken(link), '00dc35ee-7949-460b-a2b7-40a9cecbab18');
  assert.equal(oryHelpers.nextPageToken(link.split(',')[0]), null);
  assert.equal(oryHelpers.nextPageToken(undefined), null);
});

test('ory: journey and admin requests', () => {
  const a = ory.admin('adm', null);
  assert.deepEqual(a, { token: 'adm', realmId: null });
  // Kratos's admin API has no authentication of its own: no token is sent.
  const h = { 'Content-Type': 'application/json' };
  assert.deepEqual(ory.adminHeaders(a), h);
  assert.deepEqual(ory.refresh(c, r, 'rt'), {
    method: 'POST',
    url: `${c.base}/oauth2/token`,
    body: { grant_type: 'refresh_token', refresh_token: 'rt', client_id: 'app-id' },
  });
  assert.deepEqual(ory.clientCredentials(c, r, 'Basic x'), {
    method: 'POST',
    url: `${c.base}/oauth2/token`,
    body: { grant_type: 'client_credentials' },
    headers: { Authorization: 'Basic x' },
  });
  // Hydra's admin port: no client authentication.
  assert.deepEqual(ory.introspect(c, r, 'at', 'Basic x'), {
    method: 'POST',
    url: 'https://server.stress.test:4445/admin/oauth2/introspect',
    body: { token: 'at' },
  });
  assert.deepEqual(ory.userinfo(c, r, 'at'), {
    method: 'GET',
    url: `${c.base}/userinfo`,
    headers: { Authorization: 'Bearer at' },
  });
  const ids = 'https://server.stress.test:4434/admin/identities';
  assert.deepEqual(ory.adminUser(c, r, a, 'u1'), { method: 'GET', url: `${ids}/u1`, headers: h });
  assert.deepEqual(ory.listUsers(c, r, a, null), { method: 'GET', url: `${ids}?page_size=200`, headers: h });
  assert.equal(ory.listUsers(c, r, a, 'u 9').url, `${ids}?page_size=200&page_token=u%209`);
  const created = ory.createUser(c, r, a, 'e@x');
  assert.equal(created.method, 'POST');
  assert.equal(created.url, ids);
  // No credentials: like Hearth's create, the user has no password.
  assert.deepEqual(JSON.parse(created.body), {
    schema_id: 'default',
    traits: { email: 'e@x', name: { first: 'Stress', last: 'created' } },
    state: 'active',
    verifiable_addresses: [{ value: 'e@x', via: 'email', verified: true, status: 'completed' }],
  });
  const hash = '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGlnZXN0';
  const oc = Object.assign({}, c, { bulkPasswordHash: hash });
  const imp = ory.importUsers(oc, r, a, [{ email: 'bulk00000007@x', name: 'Bulk 7', index: 7 }]);
  assert.equal(imp.method, 'PATCH');
  assert.equal(imp.url, ids);
  assert.deepEqual(JSON.parse(imp.body), {
    identities: [{
      create: {
        schema_id: 'default',
        traits: { email: 'bulk00000007@x', name: { first: 'Bulk', last: '7' } },
        state: 'active',
        verifiable_addresses: [{ value: 'bulk00000007@x', via: 'email', verified: true, status: 'completed' }],
        // The run's unusable hash, never a plaintext password.
        credentials: { password: { config: { hashed_password: hash } } },
      },
    }],
  });
  assert.throws(() => ory.importUsers(c, r, a, []), /STRESS_BULK_PASSWORD_HASH is required/);
  assert.equal(ory.regenerateSecret, null);
});

test('ory: reads pages by page token, created ids, import counts', () => {
  const link = '</admin/identities?page_size=200&page_token=p2>; rel="next"';
  const items = (n) => JSON.stringify(Array.from({ length: n }, (_, i) => ({ id: `u${i}` })));
  const full = ory.userPage(res(200, { Link: link }, items(200)), null);
  assert.equal(full.ids.length, 200);
  assert.equal(full.next, 'p2');
  // A short page is the last, whatever its links say.
  assert.deepEqual(ory.userPage(res(200, { Link: link }, items(2)), 'p2'), { ids: ['u0', 'u1'], next: null });
  assert.deepEqual(ory.userPage(res(200, {}, items(200)), 'p2').next, null);
  assert.equal(ory.createdId(res(201, {}, '{"id":"u9","traits":{}}')), 'u9');
  assert.equal(ory.createdId(res(201, {}, '{}')), null);
  assert.equal(ory.createdId(res(409, {}, '{"id":"u9"}')), null);
  const answer = {
    identities: [
      { action: 'create', identity: 'u1' },
      { action: 'create', identity: 'u2' },
      { action: 'error', error: { code: 409, message: 'conflict' } },
    ],
  };
  assert.deepEqual(ory.imported(res(200, {}, JSON.stringify(answer))), { imported: 2, failed: 1 });
  assert.equal(ory.imported(res(400, {}, '{"error":{}}')), null);
});

test('token lifetimes come from expires_in (RFC 6749 section 5.1) for every product', () => {
  // takeTokens keeps expires_in from the token response, whatever the token's format.
  const f = {};
  assert.equal(common.takeTokens(res(200, {}, '{"access_token":"opaque","refresh_token":"b","expires_in":3599}'), f), true);
  assert.deepEqual(f, { access: 'opaque', refresh: 'b', expiresIn: 3599 });
  const g = {};
  assert.equal(common.takeTokens(res(200, {}, '{"access_token":"a"}'), g), true);
  assert.equal(g.expiresIn, undefined);
  // Received at now, lives expires_in seconds.
  assert.deepEqual(common.tokenLife(3600, 5000), { iat: 5000, exp: 8600 });
  assert.deepEqual(common.tokenLife(299.5, 10), { iat: 10, exp: 309.5 });
  // A missing or bad expires_in fails loudly; no lifetime is guessed.
  for (const bad of [undefined, null, 0, -1, '3600', NaN, Infinity, {}, true]) {
    assert.throws(() => common.tokenLife(bad, 5000), /the token response has no valid expires_in/, String(bad));
  }
  assert.throws(() => common.tokenLife('3600', 5000), /\("3600"\)/);
});
