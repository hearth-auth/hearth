// End-to-end verification of a Keycloak-to-Hearth migration.
//
// Assumes Hearth is already running on HTTP 8420 with a data directory that
// was pre-populated by `hearth migrate keycloak --file sample-export.json`.
// `run.sh` handles the full setup for you.
//
// Checks performed:
//   1. Password grant succeeds for a user whose PBKDF2-SHA256 credential
//      was imported from the Keycloak export (alice@acme.test / hunter2).
//   2. /v1/me/permissions returns the expected roles (admin, member).
//   3. /.well-known/jwks.json for the realm contains at least one key.
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

// acme-web client UUID from the sample export — used as client_id for the
// password grant (Hearth uses it only for rate-limit accounting; it is not
// validated for the ROPC grant type).
const CLIENT_ID = "33333333-3333-4333-8333-333333333333";

function assert(cond, msg) {
  if (!cond) {
    console.error(`\x1b[1;31m✖ FAIL\x1b[0m ${msg}`);
    process.exit(1);
  }
}

function log(section, msg) {
  process.stdout.write(`\n\x1b[1;36m▸ ${section}\x1b[0m\n${msg}\n`);
}

async function main() {
  // ── 1. Password grant ───────────────────────────────────────────────────
  log("login", `password grant for ${TEST_EMAIL}`);
  const tokenResp = await fetch(`${BASE}/realms/${REALM_NAME}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "password",
      username:   TEST_EMAIL,
      password:   TEST_PASSWORD,
      client_id:  CLIENT_ID,
    }),
  });
  if (!tokenResp.ok) {
    const body = await tokenResp.text().catch(() => "(no body)");
    assert(false, `token grant failed (${tokenResp.status}): ${body}`);
  }
  const tokenBody = await tokenResp.json();
  const { access_token } = tokenBody;
  assert(
    typeof access_token === "string" && access_token.length > 0,
    "access_token missing from token response",
  );
  console.log(`  access_token = <${access_token.length} chars>`);

  // ── 2. Roles via /v1/me/permissions ────────────────────────────────────
  log("permissions", "GET /v1/me/permissions");
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
  console.log(`  roles       = ${roles.join(", ")}`);
  console.log(`  permissions = ${permissions.join(", ")}`);

  for (const expected of EXPECTED_ROLES) {
    assert(
      Array.isArray(roles) && roles.includes(expected),
      `expected role "${expected}" — got [${(roles ?? []).join(", ")}]`,
    );
  }

  // ── 3. JWKS ─────────────────────────────────────────────────────────────
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
