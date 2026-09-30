import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { HearthApiClient } from "../src/client.js";

function lastRequestBody(): Record<string, unknown> {
  const call = vi.mocked(fetch).mock.calls.at(-1);
  expect(call).toBeDefined();
  const init = call![1] as RequestInit;
  return JSON.parse(init.body as string) as Record<string, unknown>;
}

describe("HearthApiClient.registerClient", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({ client_id: "c1", client_name: "app", redirect_uris: [], grant_types: [] }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends the trust level as the proto enum name", async () => {
    const client = new HearthApiClient({ baseUrl: "http://hearth.test", realmId: "r1" });
    await client.registerClient(
      { clientName: "app", redirectUris: ["http://app.test/cb"], trustLevel: "first_party" },
      "admin-token",
    );
    expect(lastRequestBody().trust_level).toBe("CLIENT_TRUST_LEVEL_FIRST_PARTY");
  });

  it("maps third_party to its proto enum name", async () => {
    const client = new HearthApiClient({ baseUrl: "http://hearth.test", realmId: "r1" });
    await client.registerClient(
      { clientName: "app", redirectUris: ["http://app.test/cb"], trustLevel: "third_party" },
      "admin-token",
    );
    expect(lastRequestBody().trust_level).toBe("CLIENT_TRUST_LEVEL_THIRD_PARTY");
  });

  it("omits trust_level when none is given, so the server default applies", async () => {
    const client = new HearthApiClient({ baseUrl: "http://hearth.test", realmId: "r1" });
    await client.registerClient(
      { clientName: "app", redirectUris: ["http://app.test/cb"] },
      "admin-token",
    );
    expect(Object.keys(lastRequestBody())).not.toContain("trust_level");
  });

  it("requests a generated secret and returns it from the create response", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          client_id: "c1",
          client_name: "svc",
          redirect_uris: [],
          grant_types: ["client_credentials"],
          client_secret: "generated-once",
        }),
        { status: 201, headers: { "Content-Type": "application/json" } },
      ),
    );
    const client = new HearthApiClient({ baseUrl: "http://hearth.test", realmId: "r1" });
    const created = await client.registerClient(
      {
        clientName: "svc",
        redirectUris: ["https://svc.test/cb"],
        tokenEndpointAuthMethod: "client_secret_basic",
      },
      "admin-token",
    );
    expect(lastRequestBody().token_endpoint_auth_method).toBe("client_secret_basic");
    expect(created.client_secret).toBe("generated-once");
  });

  it("omits token_endpoint_auth_method when none is given", async () => {
    const client = new HearthApiClient({ baseUrl: "http://hearth.test", realmId: "r1" });
    await client.registerClient(
      { clientName: "app", redirectUris: ["http://app.test/cb"] },
      "admin-token",
    );
    expect(Object.keys(lastRequestBody())).not.toContain("token_endpoint_auth_method");
  });
});
