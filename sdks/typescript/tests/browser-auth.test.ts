// @vitest-environment jsdom
/**
 * createHearthAuth token storage. Spec: sdk-support-contract, "Browser login
 * flow" — scenarios "Custom storage" and "The refresh token is not kept in
 * `localStorage`".
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { HearthApiClient } from "../src/client.js";
import { createHearthAuth, type AuthConfig, type TokenStorage } from "../src/browser-auth.js";
import type { TokenResponse } from "../src/types.js";

const TOKENS: TokenResponse = {
  access_token: "access-1",
  token_type: "Bearer",
  expires_in: 3600,
  refresh_token: "refresh-1",
  id_token: "id-1",
} as TokenResponse;

/** The HearthApiClient surface createHearthAuth uses, answered from memory. */
function stubClient(): HearthApiClient {
  return {
    discovery: vi.fn(async () => ({
      authorization_endpoint: "https://hearth.example.com/realms/demo/authorize",
      end_session_endpoint: "https://hearth.example.com/realms/demo/end_session",
    })),
    handleCallback: vi.fn(async () => TOKENS),
    refreshTokens: vi.fn(async () => ({ ...TOKENS, access_token: "access-2" })),
  } as unknown as HearthApiClient;
}

const CONFIG: AuthConfig = {
  clientId: "spa",
  redirectUri: "https://app.example.com/callback",
  hearthUrl: "https://hearth.example.com",
  realmSlug: "demo",
};

/** A Map-backed custom store that records every key written. */
function memoryStore(): TokenStorage & { data: Map<string, string>; written: string[] } {
  const data = new Map<string, string>();
  const written: string[] = [];
  return {
    data,
    written,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => {
      written.push(k);
      data.set(k, v);
    },
    removeItem: (k) => {
      data.delete(k);
    },
  };
}

/** Run startLogin then handleCallback with the state startLogin stored. */
async function signIn(auth: ReturnType<typeof createHearthAuth>, readState: () => string | null) {
  await auth.startLogin();
  await auth.handleCallback("code-1", readState() ?? "");
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("createHearthAuth — default storage", () => {
  it("keeps no token in localStorage; its state lives in sessionStorage", async () => {
    const auth = createHearthAuth(stubClient(), CONFIG);
    await signIn(auth, () => sessionStorage.getItem("hearth_oauth_state"));

    expect(localStorage.length).toBe(0);
    expect(sessionStorage.getItem("hearth_refresh_token")).toBe("refresh-1");
    expect(sessionStorage.getItem("hearth_id_token")).toBe("id-1");
    expect(auth.getAccessToken()).toBe("access-1");
    expect(auth.getRefreshToken()).toBe("refresh-1");
    expect(auth.getIdToken()).toBe("id-1");
    expect(auth.isAuthenticated()).toBe(true);
  });

  it("removes the tokens an older SDK left in localStorage", () => {
    localStorage.setItem("hearth_refresh_token", "old-refresh");
    localStorage.setItem("hearth_id_token", "old-id");
    localStorage.setItem("unrelated", "keep");

    createHearthAuth(stubClient(), CONFIG);

    expect(localStorage.getItem("hearth_refresh_token")).toBeNull();
    expect(localStorage.getItem("hearth_id_token")).toBeNull();
    expect(localStorage.getItem("unrelated")).toBe("keep");
  });

  it("clearTokens empties the store", async () => {
    const auth = createHearthAuth(stubClient(), CONFIG);
    await signIn(auth, () => sessionStorage.getItem("hearth_oauth_state"));
    auth.clearTokens();
    expect(auth.getAccessToken()).toBeNull();
    expect(auth.getRefreshToken()).toBeNull();
    expect(sessionStorage.getItem("hearth_refresh_token")).toBeNull();
    expect(auth.isAuthenticated()).toBe(false);
  });
});

describe("createHearthAuth — storage option", () => {
  it("keeps its state in a custom store under the configured prefix", async () => {
    const store = memoryStore();
    const auth = createHearthAuth(stubClient(), {
      ...CONFIG,
      storage: store,
      storageKeyPrefix: "myapp_",
    });
    await signIn(auth, () => store.getItem("myapp_oauth_state"));

    expect(store.written.length).toBeGreaterThan(0);
    expect(store.written.every((k) => k.startsWith("myapp_"))).toBe(true);
    expect(store.getItem("myapp_refresh_token")).toBe("refresh-1");
    expect(sessionStorage.length).toBe(0);
    expect(localStorage.length).toBe(0);
    expect(auth.getRefreshToken()).toBe("refresh-1");
  });

  it('"memory" writes nothing to web storage', async () => {
    const auth = createHearthAuth(stubClient(), { ...CONFIG, storage: "memory" });
    await auth.startLogin();
    // The state lives in the instance; read it back the way the app would see
    // it on the callback: through the same auth object.
    expect(sessionStorage.length).toBe(0);
    expect(localStorage.length).toBe(0);
  });

  it('"localStorage" is an explicit opt-in and keeps its own keys at init', async () => {
    const auth = createHearthAuth(stubClient(), { ...CONFIG, storage: "localStorage" });
    await signIn(auth, () => localStorage.getItem("hearth_oauth_state"));
    expect(localStorage.getItem("hearth_refresh_token")).toBe("refresh-1");
    expect(sessionStorage.length).toBe(0);

    const again = createHearthAuth(stubClient(), { ...CONFIG, storage: "localStorage" });
    expect(again.getRefreshToken()).toBe("refresh-1");
  });

  it("refuses a state mismatch", async () => {
    const auth = createHearthAuth(stubClient(), CONFIG);
    await auth.startLogin();
    await expect(auth.handleCallback("code-1", "forged-state")).rejects.toThrow(/state/i);
  });
});

describe("createHearthAuth — token getters live on the auth object", () => {
  it("keeps separate instances apart", async () => {
    const a = memoryStore();
    const b = memoryStore();
    const authA = createHearthAuth(stubClient(), { ...CONFIG, storage: a });
    const authB = createHearthAuth(stubClient(), { ...CONFIG, storage: b });
    await signIn(authA, () => a.getItem("hearth_oauth_state"));

    expect(authA.getAccessToken()).toBe("access-1");
    expect(authB.getAccessToken()).toBeNull();
    expect(authB.getRefreshToken()).toBeNull();
  });

  it("refreshAccessToken uses the stored refresh token", async () => {
    const client = stubClient();
    const auth = createHearthAuth(client, CONFIG);
    await signIn(auth, () => sessionStorage.getItem("hearth_oauth_state"));
    await auth.refreshAccessToken();
    expect(client.refreshTokens).toHaveBeenCalledWith("spa", "refresh-1");
    expect(auth.getAccessToken()).toBe("access-2");
  });
});
