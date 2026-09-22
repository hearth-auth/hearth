import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ensureBinary, startServer, stopServer, type TestServer } from "./helpers.js";

describe("TypeScript SDK: Auth Code Flow", () => {
  let server: TestServer;

  beforeAll(async () => {
    ensureBinary();
    server = await startServer();
  });

  afterAll(() => {
    if (server) stopServer(server);
  });

  it("completes a full auth code flow: authorize → exchange → userinfo → refresh", async () => {
    const { client, bootstrap } = server;

    // 1. Register an OAuth client. Registration is an admin operation and
    // answers 401 without a bearer token.
    const oauthClient = await client.registerClient(
      {
        clientName: "test-app",
        redirectUris: ["http://localhost:3000/callback"],
      },
      bootstrap.access_token,
    );
    expect(oauthClient.client_id).toBeTruthy();

    // 2. Create a user for the flow
    const admin = client.admin(bootstrap.access_token);
    const user = await admin.createUser({
      email: "alice@test.local",
      displayName: "Alice Test",
    });
    expect(user.id).toBeTruthy();

    // 3. Authorize — get an auth code. Selecting the subject with `userId`
    // rather than a session is an admin act, so it needs the bearer token too.
    const authResp = await client.authorize(
      {
        clientId: oauthClient.client_id,
        redirectUri: "http://localhost:3000/callback",
        scope: "openid profile email",
        state: "test-state-123",
        userId: user.id,
      },
      bootstrap.access_token,
    );
    expect(authResp.code).toBeTruthy();
    expect(authResp.state).toBe("test-state-123");

    // 4. Exchange code for tokens
    const tokens = await client.exchangeCode({
      clientId: oauthClient.client_id,
      code: authResp.code,
      redirectUri: "http://localhost:3000/callback",
    });
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.expires_in).toBeGreaterThan(0);

    // 5. Validate — call userinfo with the access token
    const userinfo = await client.userinfo(tokens.access_token);
    expect(userinfo.sub).toContain(user.id);

    // 6. Refresh — exchange the refresh token for new tokens
    const refreshed = await client.refreshTokens(
      oauthClient.client_id,
      tokens.refresh_token,
    );
    expect(refreshed.access_token).toBeTruthy();
    expect(refreshed.refresh_token).toBeTruthy();
    // New access token should be different from original
    expect(refreshed.access_token).not.toBe(tokens.access_token);

    // 7. Verify the new access token works
    const userinfo2 = await client.userinfo(refreshed.access_token);
    expect(userinfo2.sub).toContain(user.id);
  });
});
