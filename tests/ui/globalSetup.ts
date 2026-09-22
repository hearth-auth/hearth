import { bootstrap } from './fixtures/bootstrap';
import { setupAdminAuth, setupUserAuth, setupRealmUserAuth } from './fixtures/auth';
import { seedTestData } from './fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

/**
 * The `integration` project (HEA-2056) boots and seeds its own full stack via
 * `run-integration.sh` and does not depend on the admin/dev-realm auth this
 * setup prepares for the other projects. Skip the heavy setup for it — both
 * when the runner sets the flag and when the only selected project is
 * `integration` (so a bare `--project=integration` invocation works too).
 */
function integrationOnly(): boolean {
  if (process.env.HEARTH_SKIP_GLOBAL_SETUP) return true;
  const argv = process.argv.join(' ');
  return /--project[= ]integration(\s|$)/.test(argv) && !/--project[= ](?!integration)/.test(argv);
}

export default async function globalSetup(): Promise<void> {
  if (integrationOnly()) {
    console.log('[globalSetup] integration-only run — skipping admin/dev-realm setup.');
    return;
  }

  console.log('[globalSetup] bootstrapping API credentials...');
  const creds = await bootstrap();

  console.log('[globalSetup] setting up admin UI auth...');
  await setupAdminAuth();

  console.log('[globalSetup] setting up user portal auth...');
  await setupUserAuth();

  console.log('[globalSetup] setting up realm user auth...');
  await setupRealmUserAuth();

  console.log('[globalSetup] seeding test data...');
  const seed = await seedTestData(creds);

  // Ensure the seed app has consent + device_code grant regardless of how it
  // was originally created (seed is cached — creation grant_types may be stale).
  //
  // Audit 2026-08-28 §4.12#19: this call used `method: 'PUT'`. The route is
  // registered as PATCH (src/protocol/http/admin.rs), so every run got 405 and
  // neither `require_consent` nor the device_code grant was ever applied — the
  // two things flows/oauth_consent.spec.ts and flows/device_auth.spec.ts need
  // from it. The response was not checked, so the setup reported success and
  // the run exited 0 with those flows exercising an app that lacked both.
  //
  // The status is now asserted: a setup step that cannot do its job must stop
  // the run, not hand the suite a fixture it silently failed to build.
  console.log('[globalSetup] patching test-app require_consent + grant_types...');
  const patch = await fetch(`${BASE_URL}/admin/applications/${seed.appClientId}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${creds.access_token}`,
      'X-Realm-ID': creds.realm_id,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      require_consent: true,
      grant_types: [
        'authorization_code',
        'urn:ietf:params:oauth:grant-type:device_code',
      ],
    }),
  });
  if (!patch.ok) {
    throw new Error(
      `[globalSetup] PATCH /admin/applications/${seed.appClientId} failed: ` +
        `${patch.status} ${patch.statusText} — ${await patch.text()}`,
    );
  }

  console.log('[globalSetup] done.');
}
