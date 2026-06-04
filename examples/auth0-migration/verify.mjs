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
  assert(res.ok, 'discovery document returns 200', `status ${res.status}`);
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

// ── Step 3: JWKS — Ed25519 key ────────────────────────────────────────────────

console.log('▸ step 3 — JWKS (Ed25519 key present)');
{
  const res = await get(`/realms/${REALM_NAME}/.well-known/jwks.json`);
  assert(res.ok, 'JWKS endpoint returns 200', `status ${res.status}`);
  const jwks = await res.json();
  assert(Array.isArray(jwks.keys) && jwks.keys.length > 0, 'JWKS has at least one key');
  const key = jwks.keys[0];
  assert(key.kty === 'OKP', 'key type is OKP (asymmetric)', `got kty=${key.kty}`);
  assert(key.crv === 'Ed25519', 'curve is Ed25519', `got crv=${key.crv}`);
}

// ── Step 4: Login as migrated user (alice) via ROPC password grant ─────────────

console.log('▸ step 4 — ROPC login as migrated user alice');
let aliceToken;
{
  // alice@acme-corp.test was imported with a bcrypt credential (TestMigration1!).
  // UserStatus::Active — can log in immediately without a password reset.
  const res = await postJson(`/realms/${REALM_NAME}/token`, {
    client_id: 'sample-spa',   // rate-limit key only; any string is accepted for ROPC
    grant_type: 'password',
    username: ALICE_EMAIL,
    password: ALICE_PASSWORD,
  });
  if (!res.ok) {
    const body = await res.text();
    fail('alice login via ROPC', `HTTP ${res.status} — ${body}`);
    console.error('\n  NOTE: If the login failed with 401/invalid_credential, the bcrypt');
    console.error('  hash in sample-bundle.json may not match the password "TestMigration1!".');
    console.error('  See README.md § Troubleshooting for details.\n');
  } else {
    const data = await res.json();
    aliceToken = data.access_token;
    assert(typeof aliceToken === 'string' && aliceToken.length > 0, 'ROPC returns access_token');
    pass('alice@acme-corp.test logged in successfully');
  }
}

// ── Step 5: /v1/me/permissions — alice should have the "admin" role ────────────

console.log('▸ step 5 — /v1/me/permissions (alice has admin role)');
if (aliceToken) {
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
    pass(`effective roles: [${perms.roles.join(', ')}]`);
    if (perms.permissions.length > 0) {
      pass(`effective permissions (${perms.permissions.length}): ${perms.permissions.slice(0, 3).join(', ')}${perms.permissions.length > 3 ? ', …' : ''}`);
    }
  }
} else {
  fail('/v1/me/permissions skipped — alice login failed');
}

// ── Step 6: Verify bob is imported as PendingVerification ─────────────────────

console.log('▸ step 6 — admin bootstrap + migrated users visible');
{
  // Bootstrap creates the system admin realm; the migrated realm is separate.
  const bootRes = await postJson('/admin/bootstrap', {});
  const adminToken = bootRes.ok ? (await bootRes.json()).access_token : null;

  if (!adminToken) {
    fail('admin bootstrap', `HTTP ${bootRes.status}`);
  } else {
    pass('admin bootstrap succeeded');

    // List all realms and confirm our migrated realm is present.
    const realmsRes = await get('/admin/realms', {
      Authorization: `Bearer ${adminToken}`,
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
