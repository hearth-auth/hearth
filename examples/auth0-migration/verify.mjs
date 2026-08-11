#!/usr/bin/env node
// verify.mjs — Smoke-verifies a successful Auth0 → Hearth migration.
//
// Reads environment variables set by run.sh:
//   BASE              — Hearth base URL, e.g. http://127.0.0.1:8431
//   MIGRATED_REALM_ID — UUID of the imported realm (parsed from migration output)
//
// Exit 0 on success; non-zero on any failure.
//
// Zero external dependencies — uses only Node built-in fetch (Node 18+).
//
// Note on the login step: Hearth does not implement the ROPC
// (`grant_type=password`) grant — it was removed in HEA-1862 and is offered at
// no token endpoint, exactly as the migration guide states. Alice's migrated
// bcrypt credential is therefore exercised through the interactive login form,
// the same `verify_password` path a real browser drives, plus a negative
// control asserting a wrong password is refused.

const BASE = process.env.BASE ?? 'http://127.0.0.1:8431';
const REALM_ID = process.env.MIGRATED_REALM_ID;
const REALM_NAME = 'acme-corp';
const ALICE_EMAIL = 'alice@acme-corp.test';
const ALICE_PASSWORD = 'TestMigration1!';

// ── Helpers ───────────────────────────────────────────────────────────────────

let failures = 0;

function pass(label) {
  console.log(`  ✓ ${label}`);
}

function fail(label, detail = '') {
  console.error(`  ✗ ${label}${detail ? ': ' + detail : ''}`);
  failures++;
}

function assert(condition, label, detail = '') {
  if (condition) {
    pass(label);
  } else {
    fail(label, detail);
  }
}

async function get(path, headers = {}) {
  const res = await fetch(`${BASE}${path}`, { headers });
  return res;
}

async function postJson(path, body, headers = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return res;
}

/// Reads the `hearth_ui_csrf` double-submit token from a response's cookies.
/// Production mode fails closed without it; dev mode bypasses the check, but we
/// always send it so this script behaves identically under both.
function csrfFromSetCookie(res) {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const m = /(?:^|;\s*)hearth_ui_csrf=([^;]+)/.exec(c);
    if (m) return m[1];
  }
  return null;
}

function sessionCookiePresent(res) {
  return (res.headers.getSetCookie?.() ?? []).some((c) =>
    c.startsWith('hearth_ui_session='),
  );
}

/// Submits the realm-scoped login form with redirects disabled so the 303 and
/// its Set-Cookie are directly observable.
async function submitLogin(password) {
  const page = await get(`/ui/realms/${REALM_NAME}/login`);
  if (!page.ok) {
    return { error: `login page GET ${page.status}` };
  }
  const csrf = csrfFromSetCookie(page) ?? '';
  const res = await fetch(`${BASE}/ui/realms/${REALM_NAME}/login`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: `hearth_ui_csrf=${csrf}`,
    },
    body: new URLSearchParams({ email: ALICE_EMAIL, password, _csrf: csrf }),
  });
  return { res };
}

// ── Preflight ─────────────────────────────────────────────────────────────────

if (!REALM_ID) {
  console.error('ERROR: MIGRATED_REALM_ID environment variable is not set.');
  console.error('       run.sh should set this automatically. See README.md.');
  process.exit(1);
}

console.log(`\nverify.mjs — Hearth Auth0 migration smoke test`);
console.log(`  base:     ${BASE}`);
console.log(`  realm:    ${REALM_NAME}  (${REALM_ID})\n`);

// ── Step 1: Health check ──────────────────────────────────────────────────────

console.log('▸ step 1 — /health');
{
  const res = await get('/health');
  assert(res.ok, 'health endpoint returns 200', `status ${res.status}`);
}

// ── Step 2: OIDC discovery ────────────────────────────────────────────────────

console.log('▸ step 2 — OIDC discovery document');
let discoveryDoc;
{
  const res = await get(`/realms/${REALM_NAME}/.well-known/openid-configuration`);
  // A migrated realm whose name index was never written is present in storage
  // and listed by GET /admin/realms, yet 404s on every user-facing route
  // (HEA-2143) — so this doubles as the "realm is reachable by name" check.
  assert(
    res.ok,
    'discovery document returns 200',
    `status ${res.status} — realm is not routable by its name`,
  );
  if (res.ok) {
    discoveryDoc = await res.json();
    assert(
      typeof discoveryDoc.issuer === 'string' && discoveryDoc.issuer.length > 0,
      'discovery doc has issuer claim',
      JSON.stringify(discoveryDoc.issuer),
    );
    assert(
      typeof discoveryDoc.token_endpoint === 'string',
      'discovery doc has token_endpoint',
    );
    assert(
      typeof discoveryDoc.jwks_uri === 'string',
      'discovery doc has jwks_uri',
    );
  }
}

// ── Step 3: JWKS — Ed25519 key ────────────────────────────────────────────────

console.log('▸ step 3 — JWKS (Ed25519 key present)');
{
  const res = await get(`/realms/${REALM_NAME}/.well-known/jwks.json`);
  assert(res.ok, 'JWKS endpoint returns 200', `status ${res.status}`);
  if (res.ok) {
    const jwks = await res.json();
    assert(Array.isArray(jwks.keys) && jwks.keys.length > 0, 'JWKS has at least one key');
    const key = jwks.keys[0];
    assert(key.kty === 'OKP', 'key type is OKP (asymmetric)', `got kty=${key.kty}`);
    assert(key.crv === 'Ed25519', 'curve is Ed25519', `got crv=${key.crv}`);
  }
}

// ── Step 4: Interactive login as migrated user (alice) ────────────────────────

console.log('▸ step 4 — browser login as migrated user alice');
let aliceLoggedIn = false;
{
  // alice@acme-corp.test was imported with a bcrypt credential (TestMigration1!).
  // UserStatus::Active — can log in immediately without a password reset.
  const { res, error } = await submitLogin(ALICE_PASSWORD);
  if (error) {
    fail('alice login', error);
  } else if (res.status !== 303 || !sessionCookiePresent(res)) {
    const body = await res.text().catch(() => '');
    fail('alice login', `expected 303 + session cookie, got HTTP ${res.status}`);
    console.error('\n  NOTE: If the login failed with 401, the bcrypt hash in');
    console.error('  sample-bundle.json may not match the password "TestMigration1!".');
    console.error(`  See README.md § Troubleshooting for details. ${body.slice(0, 200)}\n`);
  } else {
    aliceLoggedIn = true;
    pass('alice@acme-corp.test logged in successfully (migrated bcrypt hash verified)');
  }

  // Negative control — without this, a server that accepted any password would
  // still pass every other check in this file.
  const bad = await submitLogin('definitely-not-the-password');
  assert(
    !bad.error && bad.res.status !== 303 && !sessionCookiePresent(bad.res),
    'wrong password is rejected',
    `status ${bad.res?.status}`,
  );
}

// ── Step 5: /v1/me/permissions — alice should have the "admin" role ───────────
//
// Step 4 proved the credential; this needs a Bearer token to read the RBAC
// claim set. A migrated realm has no admin credentials of its own and admin
// tokens only validate under the realm named in X-Realm-ID, so we resolve
// alice's id with the dev-only /dev/probe-user and mint a token with the
// dev-only /dev/seed-token.

console.log('▸ step 5 — /v1/me/permissions (alice has admin role)');
if (aliceLoggedIn) {
  const probe = await get(
    `/dev/probe-user?realm_id=${REALM_ID}&email=${encodeURIComponent(ALICE_EMAIL)}`,
  );
  const { user_id } = probe.ok ? await probe.json() : {};
  if (!user_id) {
    fail('resolve alice user id', `probe-user HTTP ${probe.status} (is the server in --dev mode?)`);
  } else {
    const tokRes = await postJson('/dev/seed-token', { user_id }, { 'X-Realm-ID': REALM_ID });
    const aliceToken = tokRes.ok ? (await tokRes.json()).access_token : null;
    if (!aliceToken) {
      fail('mint access token for alice', `HTTP ${tokRes.status}`);
    } else {
      const res = await get('/v1/me/permissions', {
        Authorization: `Bearer ${aliceToken}`,
        'X-Realm-ID': REALM_ID,
      });
      if (!res.ok) {
        fail('/v1/me/permissions', `HTTP ${res.status}`);
      } else {
        const perms = await res.json();
        assert(
          Array.isArray(perms.roles) && perms.roles.includes('admin'),
          'alice has "admin" role',
          `actual roles: [${(perms.roles ?? []).join(', ')}]`,
        );
        pass(`effective roles: [${(perms.roles ?? []).join(', ')}]`);
        if ((perms.permissions ?? []).length > 0) {
          pass(`effective permissions (${perms.permissions.length}): ${perms.permissions.slice(0, 3).join(', ')}${perms.permissions.length > 3 ? ', …' : ''}`);
        }
      }
    }
  }
} else {
  fail('/v1/me/permissions skipped — alice login failed');
}

// ── Step 6: Verify the migrated realm is visible to admin APIs ───────────────

console.log('▸ step 6 — admin bootstrap + migrated realm visible');
{
  // Bootstrap creates the system admin realm; the migrated realm is separate.
  const bootRes = await postJson('/admin/bootstrap', {});
  const boot = bootRes.ok ? await bootRes.json() : null;

  if (!boot?.system_access_token) {
    fail('admin bootstrap', `HTTP ${bootRes.status}`);
  } else {
    pass('admin bootstrap succeeded');

    // List all realms and confirm our migrated realm is present. Admin routes
    // require X-Realm-ID, and the bearer must validate under THAT realm — so
    // the system token is paired with the system realm id here.
    const realmsRes = await get('/admin/realms', {
      Authorization: `Bearer ${boot.system_access_token}`,
      'X-Realm-ID': boot.system_realm_id,
    });
    if (realmsRes.ok) {
      const realmsData = await realmsRes.json();
      const items = realmsData.items ?? [];
      const found = items.some(
        (r) => r.name === REALM_NAME || r.id === REALM_ID,
      );
      assert(found, `migrated realm "${REALM_NAME}" is listed in /admin/realms`);
    } else {
      fail('/admin/realms', `HTTP ${realmsRes.status}`);
    }
  }
}

// ── Result ────────────────────────────────────────────────────────────────────

console.log('');
if (failures === 0) {
  console.log('▸ all checks passed — migration verified ✓');
  process.exit(0);
} else {
  console.error(`▸ ${failures} check(s) failed`);
  process.exit(1);
}
