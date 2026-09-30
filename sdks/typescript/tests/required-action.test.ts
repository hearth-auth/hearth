/**
 * Unit tests for RequiredActionError (spec §5) and handleCallback (spec §7).
 * Tests are written before implementation (TDD).
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { RequiredActionError } from "../src/errors.js";
import { HearthApiClient } from "../src/client.js";

// ── RequiredActionError ────────────────────────────────────────────────────

describe("RequiredActionError", () => {
  it("is a subclass of Error", () => {
    const err = new RequiredActionError(["VERIFY_EMAIL"]);
    expect(err).toBeInstanceOf(Error);
  });

  it("exposes requiredActions array", () => {
    const err = new RequiredActionError(["VERIFY_EMAIL", "UPDATE_PASSWORD"]);
    expect(err.requiredActions).toEqual(["VERIFY_EMAIL", "UPDATE_PASSWORD"]);
  });

  it("has a human-readable message", () => {
    const err = new RequiredActionError(["VERIFY_EMAIL"]);
    expect(err.message).toBeTruthy();
    expect(typeof err.message).toBe("string");
  });

  it("has name 'RequiredActionError'", () => {
    const err = new RequiredActionError(["VERIFY_EMAIL"]);
    expect(err.name).toBe("RequiredActionError");
  });

  it("works with empty required actions list", () => {
    const err = new RequiredActionError([]);
    expect(err.requiredActions).toEqual([]);
  });
});

// ── handleCallback() ───────────────────────────────────────────────────────

/** Build a minimal JWT with the given payload. */
function forgeJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" }), "utf8").toString(
    "base64url",
  );
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = Buffer.from("fake-sig").toString("base64url");
  return `${header}.${body}.${sig}`;
}

function makeClient(): HearthApiClient {
  return new HearthApiClient({
    baseUrl: "https://auth.example.com",
    realmId: "realm_test",
  });
}

describe("HearthApiClient.handleCallback()", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns token response when token_type is 'access'", async () => {
    const accessJwt = forgeJwt({
      sub: "user_1",
      token_type: "access",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const mockResponse = {
      access_token: accessJwt,
      id_token: "id_token_value",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "refresh_token_value",
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(mockResponse), { status: 200 }),
    );

    const client = makeClient();
    const result = await client.handleCallback({
      callbackUrl: "https://app.example.com/callback?code=abc123&state=xyz",
      clientId: "client_1",
      redirectUri: "https://app.example.com/callback",
    });
    expect(result.access_token).toBe(accessJwt);
    expect(result.token_type).toBe("Bearer");
  });

  it("performs no required-action detection: the server resolves pending actions before it issues a code", async () => {
    // Hearth runs pending required actions at /required-action/{ACTION}
    // during /authorize, so a callback always carries an ordinary code and the
    // exchange yields an ordinary access token. There is no callback
    // parameter or token type to detect.
    const accessJwt = forgeJwt({ sub: "user_1", token_type: "access" });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: accessJwt,
          id_token: "",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "rt",
        }),
        { status: 200 },
      ),
    );

    const client = makeClient();
    const result = await client.handleCallback({
      callbackUrl: "https://app.example.com/callback?code=abc123&state=xyz",
      clientId: "client_1",
      redirectUri: "https://app.example.com/callback",
    });
    expect(result.access_token).toBe(accessJwt);
  });

  it("passes codeVerifier to the token exchange when provided", async () => {
    const accessJwt = forgeJwt({ sub: "user_1", token_type: "access" });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: accessJwt,
          id_token: "",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "rt",
        }),
        { status: 200 },
      ),
    );

    const client = makeClient();
    await client.handleCallback({
      callbackUrl: "https://app.example.com/callback?code=abc123",
      clientId: "client_1",
      redirectUri: "https://app.example.com/callback",
      codeVerifier: "pkce_verifier_value",
    });

    const body = JSON.parse(fetchSpy.mock.calls[0][1]?.body as string);
    expect(body.code_verifier).toBe("pkce_verifier_value");
  });
});
