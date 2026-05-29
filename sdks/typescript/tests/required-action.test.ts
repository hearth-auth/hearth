/**
 * Unit tests for RequiredActionError (spec §5) and handleCallback
 * required-action detection (spec §7).
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

  it("redirectUri is undefined when not provided", () => {
    const err = new RequiredActionError(["VERIFY_EMAIL"]);
    expect(err.redirectUri).toBeUndefined();
  });

  it("accepts an optional redirectUri", () => {
    const err = new RequiredActionError(
      ["VERIFY_EMAIL"],
      "https://auth.example.com/ui/required-actions/verify-email",
    );
    expect(err.redirectUri).toBe(
      "https://auth.example.com/ui/required-actions/verify-email",
    );
  });

  it("works with empty required actions list", () => {
    const err = new RequiredActionError([]);
    expect(err.requiredActions).toEqual([]);
  });
});

// ── handleCallback() ───────────────────────────────────────────────────────

/** Build a minimal JWT with the given payload. */
function forgeJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "EdDSA", typ: "JWT" }),
    "utf8",
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url",
  );
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

  it("throws RequiredActionError when JWT token_type is 'required_action'", async () => {
    const requiredActionJwt = forgeJwt({
      sub: "user_1",
      token_type: "required_action",
      required_actions: ["VERIFY_EMAIL", "UPDATE_PASSWORD"],
      exp: Math.floor(Date.now() / 1000) + 300,
    });
    const mockResponse = {
      access_token: requiredActionJwt,
      id_token: "id_token_value",
      token_type: "Bearer",
      expires_in: 300,
      refresh_token: "",
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(mockResponse), { status: 200 }),
    );

    const client = makeClient();
    await expect(
      client.handleCallback({
        callbackUrl: "https://app.example.com/callback?code=abc123",
        clientId: "client_1",
        redirectUri: "https://app.example.com/callback",
      }),
    ).rejects.toBeInstanceOf(RequiredActionError);
  });

  it("populates requiredActions from JWT required_actions claim", async () => {
    const requiredActionJwt = forgeJwt({
      sub: "user_1",
      token_type: "required_action",
      required_actions: ["VERIFY_EMAIL", "UPDATE_PASSWORD"],
      exp: Math.floor(Date.now() / 1000) + 300,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: requiredActionJwt,
          id_token: "",
          token_type: "Bearer",
          expires_in: 300,
          refresh_token: "",
        }),
        { status: 200 },
      ),
    );

    const client = makeClient();
    try {
      await client.handleCallback({
        callbackUrl: "https://app.example.com/callback?code=abc123",
        clientId: "client_1",
        redirectUri: "https://app.example.com/callback",
      });
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RequiredActionError);
      expect((err as RequiredActionError).requiredActions).toEqual([
        "VERIFY_EMAIL",
        "UPDATE_PASSWORD",
      ]);
    }
  });

  it("throws RequiredActionError with redirectUri from required_action_redirect_uri param", async () => {
    const normalJwt = forgeJwt({
      sub: "user_1",
      token_type: "access",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: normalJwt,
          id_token: "",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "rt",
        }),
        { status: 200 },
      ),
    );

    const client = makeClient();
    const redirectUri = "https://auth.example.com/ui/required-actions/verify-email";
    const callbackUrl = `https://app.example.com/callback?code=abc123&required_action_redirect_uri=${encodeURIComponent(redirectUri)}`;

    try {
      await client.handleCallback({
        callbackUrl,
        clientId: "client_1",
        redirectUri: "https://app.example.com/callback",
      });
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RequiredActionError);
      expect((err as RequiredActionError).redirectUri).toBe(redirectUri);
    }
  });

  it("token_type=required_action sets redirectUri from JWT if required_action_redirect_uri also in URL", async () => {
    const redirectUri = "https://auth.example.com/ui/actions";
    const requiredActionJwt = forgeJwt({
      sub: "user_1",
      token_type: "required_action",
      required_actions: ["VERIFY_EMAIL"],
      exp: Math.floor(Date.now() / 1000) + 300,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: requiredActionJwt,
          id_token: "",
          token_type: "Bearer",
          expires_in: 300,
          refresh_token: "",
        }),
        { status: 200 },
      ),
    );

    const callbackUrl = `https://app.example.com/callback?code=abc123&required_action_redirect_uri=${encodeURIComponent(redirectUri)}`;
    const client = makeClient();
    try {
      await client.handleCallback({
        callbackUrl,
        clientId: "client_1",
        redirectUri: "https://app.example.com/callback",
      });
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RequiredActionError);
      expect((err as RequiredActionError).requiredActions).toEqual(["VERIFY_EMAIL"]);
      expect((err as RequiredActionError).redirectUri).toBe(redirectUri);
    }
  });

  it("passes codeVerifier to the token exchange when provided", async () => {
    const accessJwt = forgeJwt({ sub: "user_1", token_type: "access" });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
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
