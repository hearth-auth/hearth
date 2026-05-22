import * as fs from 'fs';
import * as path from 'path';
import { Credentials } from './bootstrap';

const BASE_URL = process.env.HEARTH_URL ?? 'http://127.0.0.1:8420';
const SEED_PATH = path.join(__dirname, '..', '.auth', 'seed.json');

export interface SeedFixtures {
  realmId: string;
  /** Human-readable realm name — used to build /ui/admin/realms/{name}/... URLs */
  realmName: string;
  userId: string;
  appClientId: string;
  groupId: string;
  /** Custom RBAC role ID (name: "test-role") for regression tests. */
  roleId: string;
}

/**
 * Creates test realm/user/app/group via the admin REST API using the dev-realm
 * access token from bootstrap. Results are cached in .auth/seed.json so that
 * subsequent runs skip re-creation (idempotent).
 */
export async function seedTestData(creds: Credentials): Promise<SeedFixtures> {
  // If seed exists and is for the same realm, skip re-seeding
  if (fs.existsSync(SEED_PATH)) {
    const cached = JSON.parse(fs.readFileSync(SEED_PATH, 'utf-8')) as SeedFixtures;
    if (cached.realmId === creds.realm_id) {
      return cached;
    }
  }

  const headers: Record<string, string> = {
    Authorization: `Bearer ${creds.access_token}`,
    'X-Realm-ID': creds.realm_id,
    'Content-Type': 'application/json',
  };

  // Create test@example.com user
  const userId = await createOrSkip(
    `${BASE_URL}/admin/users`,
    headers,
    { email: 'test@example.com', display_name: 'Test User' },
    (body: Record<string, unknown>) => body['id'] as string,
  );

  // Create test-app OAuth client
  const appClientId = await createOrSkip(
    `${BASE_URL}/admin/applications`,
    headers,
    {
      client_name: 'test-app',
      redirect_uris: ['https://example.com/callback'],
      grant_types: ['authorization_code'],
    },
    (body: Record<string, unknown>) => body['client_id'] as string,
  );

  // Create test-group
  const groupId = await createOrSkip(
    `${BASE_URL}/admin/groups`,
    headers,
    { name: 'test-group', slug: 'test-group', description: 'Smoke-test group' },
    (body: Record<string, unknown>) => body['id'] as string,
  );

  // Add test user to group (ignore 409 = already a member)
  if (groupId && userId) {
    await fetch(`${BASE_URL}/admin/groups/${groupId}/members`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ user_id: userId }),
    });
  }

  // Create custom RBAC role for regression tests
  const roleId = await createOrSkip(
    `${BASE_URL}/admin/roles`,
    headers,
    { name: 'test-role', description: 'Regression-test role' },
    (body: Record<string, unknown>) => body['id'] as string,
  );

  const fixtures: SeedFixtures = {
    realmId: creds.realm_id,
    realmName: 'dev-realm',
    userId,
    appClientId,
    groupId,
    roleId,
  };

  fs.writeFileSync(SEED_PATH, JSON.stringify(fixtures, null, 2));
  return fixtures;
}

async function createOrSkip<T>(
  url: string,
  headers: Record<string, string>,
  body: unknown,
  extractId: (parsed: Record<string, unknown>) => T,
): Promise<T> {
  const resp = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });

  if (resp.ok) {
    return extractId((await resp.json()) as Record<string, unknown>);
  }
  if (resp.status === 409) {
    // Already exists — return empty string; crawl will still visit the list page
    return '' as unknown as T;
  }
  if (resp.status === 401) {
    // Stale bootstrap token — warn and degrade gracefully; smoke suite list pages still work
    console.warn(`[seed] 401 on POST ${url} — bootstrap token is stale. Restart 'make dev' to get fresh tokens.`);
    return '' as unknown as T;
  }
  throw new Error(`Seed POST ${url} failed: HTTP ${resp.status} — ${await resp.text()}`);
}
