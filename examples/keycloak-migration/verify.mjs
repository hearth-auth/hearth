// End-to-end verification of a Keycloak-to-Hearth migration.
//
// Assumes Hearth is already running on HTTP 8420 with a data directory that
// was pre-populated by `hearth migrate keycloak --file sample-export.json`.
// `run.sh` handles the full setup for you.
//
// Checks performed:
//   1. The migrated realm is reachable by NAME (`/realms/acme/...`), not just
//      present in storage.
//   2. Browser login succeeds for a user whose PBKDF2-SHA256 credential was
//      imported from the Keycloak export (alice@acme.test / hunter2), and
//      FAILS for a wrong password.
//   3. /v1/me/permissions returns the expected roles (admin, member).
//   4. /.well-known/jwks.json for the realm contains at least one key.
//
// Why not a password grant? Hearth removed the ROPC (`grant_type=password`)
// grant in HEA-1862 — it is not offered at any token endpoint, matching the
// migration guide. The imported credential is instead exercised through the
// interactive login form, which runs the same `verify_password` path a real
// user's browser would. That is a strictly stronger check than the old ROPC
// step: it also asserts a WRONG password is rejected, so a server that
// accepted anything could no longer pass this script.
//
// Exits 0 on success, 1 on any assertion failure.

const BASE       = "http://127.0.0.1:8420";
const REALM_NAME = "acme";
// Realm UUID from sample-export.json "id" field — preserved verbatim by the importer.
const REALM_ID   = "550e8400-e29b-41d4-a716-446655440000";

// alice's credential is a real PBKDF2-SHA256 hash of "hunter2" baked into
// sample-export.json.  The importer converts it to PHC format so Hearth
// can verify it natively without any Keycloak-specific code at login time.
const TEST_EMAIL    = "alice@acme.test";
const TEST_PASSWORD = "hunter2";
const EXPECTED_ROLES = ["admin", "member"];

function assert(cond, msg) {
  if (!cond) {
    console.error(`\x1b[1;31m✖ FAIL\x1b[0m ${msg}`);
    process.exit(1);
  }
}

function log(section, msg) {
  process.stdout.write(`\n\x1b[1;36m▸ ${section}\x1b[0m\n${msg}\n`);
}

/// Reads the `hearth_ui_csrf` double-submit token from a Set-Cookie header set.
/// Production mode fails closed without it; dev mode bypasses the check, but we
/// always send it so this script behaves identically under both.
function csrfFromSetCookie(resp) {
  const raw = resp.headers.getSetCookie?.() ?? [];
  for (const c of raw) {
    const m = /(?:^|;\s*)hearth_ui_csrf=([^;]+)/.exec(c);
    if (m) return m[1];
  }
  return null;
}

function sessionCookiePresent(resp) {
  return (resp.headers.getSetCookie?.() ?? []).some((c) =>
    c.startsWith("hearth_ui_session="),
  );
}

/// Submits the realm-scoped login form. Returns the raw response with redirects
/// disabled so we can inspect the 303 + Set-Cookie directly.
async function submitLogin(password) {
  const pageResp = await fetch(`${BASE}/ui/realms/${REALM_NAME}/login`);
  assert(
    pageResp.ok,
    `login page GET failed (${pageResp.status}) — is the realm reachable by name?`,
  );
  const csrf = csrfFromSetCookie(pageResp) ?? "";

  const form = new URLSearchParams({
    email: TEST_EMAIL,
    password,
    _csrf: csrf,
  });
  return fetch(`${BASE}/ui/realms/${REALM_NAME}/login`, {
    method: "POST",
    redirect: "manual",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Cookie": `hearth_ui_csrf=${csrf}`,
    },
    body: form,
  });
}

async function main() {
  // ── 1. The migrated realm is reachable by name ──────────────────────────
  //
  // An imported realm whose name index was never written still shows up in
  // `GET /admin/realms`, but every user-facing route 404s. Check the public
  // surface, not the admin listing (HEA-2143).
  log("routing", `GET /realms/${REALM_NAME}/.well-known/openid-configuration`);
  const discoResp = await fetch(
    `${BASE}/realms/${REALM_NAME}/.well-known/openid-configuration`,
  );
  assert(
    discoResp.ok,
    `realm "${REALM_NAME}" is not routable by name (${discoResp.status}) — ` +
      `the migration wrote the realm record but not its name index`,
  );
  const disco = await discoResp.json();
  console.log(`  issuer = ${disco.issuer}`);

  // ── 2. Browser login with the migrated credential ───────────────────────
  log("login", `interactive login for ${TEST_EMAIL} (migrated PBKDF2 hash)`);
  const loginResp = await submitLogin(TEST_PASSWORD);
  if (loginResp.status !== 303) {
    const body = await loginResp.text().catch(() => "(no body)");
    assert(
      false,
      `login expected 303, got ${loginResp.status}: ${body.slice(0, 400)}`,
    );
  }
  assert(
    sessionCookiePresent(loginResp),
    "login returned 303 but set no hearth_ui_session cookie",
  );
  console.log(`  303 → ${loginResp.headers.get("location")}  (session established)`);

  // Negative control: the same form with a wrong password must NOT succeed.
  // Without this, a server that accepted any password would pass every other
  // check in this script.
  log("login", "negative control — wrong password must be rejected");
  const badResp = await submitLogin("definitely-not-the-password");
  assert(
    badResp.status !== 303 && !sessionCookiePresent(badResp),
    `wrong password was accepted (status ${badResp.status}) — credential ` +
      `verification is not actually running`,
  );
  console.log(`  rejected with ${badResp.status}`);

  // ── 3. Roles via /v1/me/permissions ────────────────────────────────────
  //
  // The login above proves the credential; this step needs a Bearer token to
  // read the RBAC claim set. `POST /dev/seed-token` (dev-only) mints one for a
  // known user id, which we resolve with the dev-only `/dev/probe-user` probe —
  // a migrated realm has no admin credentials of its own.
  log("permissions", "GET /v1/me/permissions");
  const probeResp = await fetch(
    `${BASE}/dev/probe-user?realm_id=${REALM_ID}&email=${encodeURIComponent(TEST_EMAIL)}`,
  );
  assert(probeResp.ok, `probe-user failed (${probeResp.status}) — is the server in --dev mode?`);
  const { user_id } = await probeResp.json();
  assert(
    typeof user_id === "string" && user_id.length > 0,
    `${TEST_EMAIL} was not found in the migrated realm`,
  );

  const tokenResp = await fetch(`${BASE}/dev/seed-token`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Realm-ID": REALM_ID },
    body: JSON.stringify({ user_id }),
  });
  if (!tokenResp.ok) {
    const body = await tokenResp.text().catch(() => "(no body)");
    assert(false, `seed-token failed (${tokenResp.status}): ${body}`);
  }
  const { access_token } = await tokenResp.json();
  assert(
    typeof access_token === "string" && access_token.length > 0,
    "access_token missing from seed-token response",
  );
  console.log(`  access_token = <${access_token.length} chars>`);

  const permResp = await fetch(`${BASE}/v1/me/permissions`, {
    headers: {
      "Authorization": `Bearer ${access_token}`,
      "x-realm-id":    REALM_ID,
    },
  });
  if (!permResp.ok) {
    const body = await permResp.text().catch(() => "(no body)");
    assert(false, `permissions request failed (${permResp.status}): ${body}`);
  }
  const { roles, permissions } = await permResp.json();
  console.log(`  roles       = ${(roles ?? []).join(", ")}`);
  console.log(`  permissions = ${(permissions ?? []).join(", ")}`);

  for (const expected of EXPECTED_ROLES) {
    assert(
      Array.isArray(roles) && roles.includes(expected),
      `expected role "${expected}" — got [${(roles ?? []).join(", ")}]`,
    );
  }

  // ── 4. JWKS ─────────────────────────────────────────────────────────────
  log("jwks", `GET /realms/${REALM_NAME}/.well-known/jwks.json`);
  const jwksResp = await fetch(
    `${BASE}/realms/${REALM_NAME}/.well-known/jwks.json`,
  );
  assert(jwksResp.ok, `JWKS request failed (${jwksResp.status})`);
  const jwks = await jwksResp.json();
  assert(
    Array.isArray(jwks.keys) && jwks.keys.length > 0,
    "JWKS has no keys — realm signing key was not generated during migration",
  );
  console.log(`  key count = ${jwks.keys.length}`);
  console.log(`  key ids   = ${jwks.keys.map((k) => k.kid ?? "(none)").join(", ")}`);

  log("done", "All checks passed. Migration verified.");
}

main().catch((e) => {
  console.error(`\n\x1b[1;31m✖ verify.mjs failed:\x1b[0m`, e?.message ?? e);
  process.exit(1);
});
