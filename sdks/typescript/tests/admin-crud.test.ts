import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ensureBinary, startServer, stopServer, type TestServer } from "./helpers.js";

describe("TypeScript SDK: Admin CRUD", () => {
  let server: TestServer;

  beforeAll(async () => {
    ensureBinary();
    server = await startServer();
  });

  afterAll(() => {
    if (server) stopServer(server);
  });

  it("performs full CRUD on users and realms via the admin API", async () => {
    const admin = server.client.admin(server.bootstrap.access_token);

    // === User CRUD ===

    // Create
    const user = await admin.createUser({
      email: "crud-test@test.local",
      displayName: "CRUD Test User",
    });
    expect(user.id).toBeTruthy();
    expect(user.email).toBe("crud-test@test.local");
    expect(user.display_name).toBe("CRUD Test User");
    expect(user.status).toBe("USER_STATUS_ACTIVE");

    // Read
    const fetched = await admin.getUser(user.id);
    expect(fetched.id).toBe(user.id);
    expect(fetched.email).toBe("crud-test@test.local");

    // Update
    const updated = await admin.updateUser(user.id, {
      displayName: "Updated Name",
    });
    expect(updated.display_name).toBe("Updated Name");
    expect(updated.email).toBe("crud-test@test.local");

    // List
    const page = await admin.listUsers({ limit: 10 });
    expect(page.items.length).toBeGreaterThanOrEqual(1);
    const found = page.items.find((u) => u.id === user.id);
    expect(found).toBeTruthy();
    expect(found!.display_name).toBe("Updated Name");

    // Delete
    await admin.deleteUser(user.id);

    // Verify deleted — should 404
    try {
      await admin.getUser(user.id);
      expect.fail("should have thrown");
    } catch (e: unknown) {
      expect((e as { status: number }).status).toBe(404);
    }

    // === Realm read paths ===
    //
    // Realms are provisioned via hearth.yaml, not the admin API: POST and
    // PATCH /admin/realms return 405 ("Realms are managed via hearth.yaml").
    // The SDK exposes only the read paths, so exercise those against the
    // realm the dev server bootstrapped.

    // List
    const realmPage = await admin.listRealms({ limit: 10 });
    expect(realmPage.items.length).toBeGreaterThanOrEqual(1);

    // Read the bootstrapped realm by ID
    const fetchedRealm = await admin.getRealm(server.bootstrap.realm_id);
    expect(fetchedRealm.id).toBe(server.bootstrap.realm_id);
  });
});
