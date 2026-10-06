import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { bootstrap, Credentials, BootstrapDeps } from './bootstrap';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

interface Call {
  url: string;
  init: RequestInit;
}

/** Builds a minimal Response-like object for the injected fetch. */
function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

function headerValue(init: RequestInit, name: string): string | undefined {
  const h = (init.headers ?? {}) as Record<string, string>;
  return h[name];
}

const FRESH: Credentials = {
  realm_id: 'realm-1',
  user_id: 'user-1',
  access_token: 'fresh-access',
  refresh_token: 'fresh-refresh',
};

/** Harness: records calls, drives injected responses, captures cache writes. */
function harness(responders: Array<(c: Call) => Response>, cached: Credentials | null) {
  const calls: Call[] = [];
  let written: Credentials | null = null;
  let idx = 0;
  const deps: BootstrapDeps = {
    fetchFn: (async (url: string, init: RequestInit = {}) => {
      const call = { url, init };
      calls.push(call);
      const responder = responders[idx++];
      if (!responder) throw new Error(`unexpected fetch #${idx}: ${url}`);
      return responder(call);
    }) as unknown as typeof fetch,
    readCache: () => cached,
    writeCache: (c: Credentials) => {
      written = c;
    },
  };
  return { calls, deps, getWritten: () => written };
}

test('fresh realm: unauthenticated bootstrap succeeds and caches creds', async () => {
  const h = harness([() => jsonResponse(200, FRESH)], null);
  const creds = await bootstrap(h.deps);

  assert.equal(creds.access_token, 'fresh-access');
  assert.equal(h.getWritten()?.access_token, 'fresh-access');
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].url, `${BASE_URL}/admin/bootstrap`);
  // No cached creds → no Authorization header.
  assert.equal(headerValue(h.calls[0].init, 'Authorization'), undefined);
});

test('existing realm, valid cached token: re-bootstrap with Bearer succeeds, no refresh', async () => {
  const cached: Credentials = { ...FRESH, access_token: 'cached-access', refresh_token: 'cached-refresh' };
  const h = harness([() => jsonResponse(200, FRESH)], cached);
  const creds = await bootstrap(h.deps);

  assert.equal(creds.access_token, 'fresh-access');
  assert.equal(h.calls.length, 1, 'refresh must not be called when cached token is valid');
  assert.equal(headerValue(h.calls[0].init, 'Authorization'), 'Bearer cached-access');
});

test('existing realm, expired token: 401 triggers refresh then retry with fresh Bearer', async () => {
  const cached: Credentials = { ...FRESH, access_token: 'stale-access', refresh_token: 'good-refresh' };
  const refreshed = { access_token: 'refreshed-access', refresh_token: 'refreshed-refresh' };
  const h = harness(
    [
      () => jsonResponse(401, { error: 'missing authorization header' }),
      () => jsonResponse(200, refreshed),
      () => jsonResponse(200, { ...FRESH, access_token: 'rebootstrap-access' }),
    ],
    cached,
  );
  const creds = await bootstrap(h.deps);

  assert.equal(creds.access_token, 'rebootstrap-access');
  assert.equal(h.calls.length, 3);

  // Call 2 = clientless session refresh at /token.
  const refreshCall = h.calls[1];
  assert.equal(refreshCall.url, `${BASE_URL}/token`);
  assert.equal(headerValue(refreshCall.init, 'X-Realm-ID'), 'realm-1');
  const refreshBody = JSON.parse(refreshCall.init.body as string) as Record<string, string>;
  assert.equal(refreshBody.grant_type, 'refresh_token');
  assert.equal(refreshBody.refresh_token, 'good-refresh');
  assert.equal(refreshBody.client_id, '', 'clientless refresh: client_id must be empty');
  assert.equal(headerValue(refreshCall.init, 'Authorization'), undefined);

  // Call 3 = re-bootstrap carrying the refreshed access token.
  assert.equal(headerValue(h.calls[2].init, 'Authorization'), 'Bearer refreshed-access');
  assert.equal(h.getWritten()?.access_token, 'rebootstrap-access');
});

const DEV_CREDS: Credentials = {
  realm_id: 'realm-1',
  user_id: 'user-1',
  access_token: 'dev-console-access',
  refresh_token: 'dev-console-refresh',
  totp_secret: 'REALMSECRET',
  admin_totp_secret: 'ADMINSECRET',
};

test('401 with no cache: falls back to the dev console credentials', async () => {
  // The accounts were set up by a visit to /dev, so there is no first
  // bootstrap response to have cached.
  const h = harness(
    [
      () => jsonResponse(401, { error: 'missing authorization header' }),
      () => jsonResponse(200, DEV_CREDS),
    ],
    null,
  );
  const creds = await bootstrap(h.deps);
  assert.equal(h.calls[1].url, `${BASE_URL}/dev/credentials`);
  assert.equal(creds.access_token, 'dev-console-access');
  assert.equal(creds.admin_totp_secret, 'ADMINSECRET');
  assert.equal(h.getWritten()?.totp_secret, 'REALMSECRET');
});

test('401 then refresh fails: falls back to the dev console credentials', async () => {
  const cached: Credentials = { ...FRESH, access_token: 'stale', refresh_token: 'expired-refresh' };
  const h = harness(
    [
      () => jsonResponse(401, { error: 'missing authorization header' }),
      () => jsonResponse(400, { error: 'invalid_grant' }),
      () => jsonResponse(200, DEV_CREDS),
    ],
    cached,
  );
  const creds = await bootstrap(h.deps);
  assert.equal(h.calls[2].url, `${BASE_URL}/dev/credentials`);
  assert.equal(creds.access_token, 'dev-console-access');
});

test('401 and no dev console either: throws a clear error', async () => {
  const h = harness(
    [
      () => jsonResponse(401, { error: 'missing authorization header' }),
      () => jsonResponse(404, {}),
    ],
    null,
  );
  await assert.rejects(bootstrap(h.deps), /make dev-reset/);
});

test('re-bootstrap keeps the cached TOTP secrets the server returns only once', async () => {
  const cached: Credentials = {
    ...FRESH,
    access_token: 'cached-access',
    totp_secret: 'DEVREALMSECRET',
    admin_totp_secret: 'SYSTEMSECRET',
  };
  const h = harness([() => jsonResponse(200, { ...FRESH, totp_secret: '', admin_totp_secret: '' })], cached);
  const creds = await bootstrap(h.deps);

  assert.equal(creds.totp_secret, 'DEVREALMSECRET');
  assert.equal(creds.admin_totp_secret, 'SYSTEMSECRET');
  assert.equal(h.getWritten()?.admin_totp_secret, 'SYSTEMSECRET');
});

test('first bootstrap caches the TOTP secrets it returns', async () => {
  const h = harness(
    [() => jsonResponse(200, { ...FRESH, totp_secret: 'NEWDEV', admin_totp_secret: 'NEWSYS' })],
    null,
  );
  const creds = await bootstrap(h.deps);
  assert.equal(creds.totp_secret, 'NEWDEV');
  assert.equal(h.getWritten()?.admin_totp_secret, 'NEWSYS');
});
