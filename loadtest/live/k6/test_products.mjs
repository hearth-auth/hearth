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
rmSync(dir, { recursive: true, force: true });
const { hearth, keycloak } = PRODUCTS;

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
