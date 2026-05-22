import { bootstrap } from './fixtures/bootstrap';
import { setupAdminAuth, setupUserAuth, setupRealmUserAuth } from './fixtures/auth';
import { seedTestData } from './fixtures/seed';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';

export default async function globalSetup(): Promise<void> {
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
  console.log('[globalSetup] patching test-app require_consent + grant_types...');
  await fetch(`${BASE_URL}/admin/applications/${seed.appClientId}`, {
    method: 'PUT',
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

  console.log('[globalSetup] done.');
}
