import { bootstrap } from './fixtures/bootstrap';
import { setupAdminAuth } from './fixtures/auth';
import { seedTestData } from './fixtures/seed';

export default async function globalSetup(): Promise<void> {
  console.log('[globalSetup] bootstrapping API credentials...');
  const creds = await bootstrap();

  console.log('[globalSetup] setting up admin UI auth...');
  await setupAdminAuth();

  console.log('[globalSetup] seeding test data...');
  await seedTestData(creds);

  console.log('[globalSetup] done.');
}
