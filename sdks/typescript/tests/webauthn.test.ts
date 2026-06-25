/**
 * Unit tests for WebAuthn passkey ceremony helpers on HearthApiClient (C-21).
 * Tests are written before implementation (TDD).
 *
 * The browser SDK is the natural home for WebAuthn: the begin/complete calls
 * here return/consume the options that `navigator.credentials.create()` and
 * `navigator.credentials.get()` produce. These tests mock `fetch` and assert
 * the wire contract (endpoint, method, bearer header, body shape) matches the
 * Go/Python/Rust SDKs.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { HearthApiClient } from "../src/client.js";

function makeClient(): HearthApiClient {
  return new HearthApiClient({
    baseUrl: "https://auth.example.com",
    realmId: "realm_test",
  });
}

function mockFetch(body: unknown, status = 200) {
  return vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(new Response(JSON.stringify(body), { status }));
}

function lastCall(): [string, RequestInit] {
  return vi.mocked(fetch).mock.calls[0] as unknown as [string, RequestInit];
}

describe("HearthApiClient WebAuthn helpers (C-21)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── Registration begin ──────────────────────────────────────────────────
  it("startWebAuthnRegistration POSTs to /webauthn/register/begin with bearer", async () => {
    const begin = {
      challenge: "chal-1",
      rp_id: "auth.example.com",
      rp_name: "Hearth",
      user_id: "user_1",
      user_name: "alice",
      user_display_name: "Alice",
      attestation: "none",
      timeout: 60000,
    };
    mockFetch(begin);
    const client = makeClient();

    const res = await client.startWebAuthnRegistration("bearer-token");

    const [url, init] = lastCall();
    expect(url).toBe("https://auth.example.com/webauthn/register/begin");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe(
      "Bearer bearer-token",
    );
    expect((init.headers as Record<string, string>)["X-Realm-ID"]).toBe("realm_test");
    expect(res.challenge).toBe("chal-1");
    expect(res.rp_id).toBe("auth.example.com");
  });

  // ── Registration complete ───────────────────────────────────────────────
  it("finishWebAuthnRegistration POSTs attestation with bearer and returns credential", async () => {
    mockFetch({ credential_id: "cred-1", algorithm: -8, discoverable: true });
    const client = makeClient();

    const res = await client.finishWebAuthnRegistration("bearer-token", {
      client_data_json: "cdj",
      attestation_object: "att",
      origin: "https://app.example.com",
      discoverable: true,
    });

    const [url, init] = lastCall();
    expect(url).toBe("https://auth.example.com/webauthn/register/complete");
    expect((init.headers as Record<string, string>).Authorization).toBe(
      "Bearer bearer-token",
    );
    const body = JSON.parse(init.body as string);
    expect(body.client_data_json).toBe("cdj");
    expect(body.attestation_object).toBe("att");
    expect(res.credential_id).toBe("cred-1");
  });

  // ── Authentication begin (discoverable / resident key) ──────────────────
  it("startWebAuthnAuthentication POSTs to /webauthn/auth/begin without bearer when no userId", async () => {
    mockFetch({
      challenge: "chal-2",
      rp_id: "auth.example.com",
      allow_credentials: [],
      user_verification: "preferred",
      timeout: 60000,
    });
    const client = makeClient();

    const res = await client.startWebAuthnAuthentication();

    const [url, init] = lastCall();
    expect(url).toBe("https://auth.example.com/webauthn/auth/begin");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
    const body = JSON.parse(init.body as string);
    expect(body.user_id).toBeUndefined();
    expect(res.challenge).toBe("chal-2");
  });

  it("startWebAuthnAuthentication includes user_id when provided", async () => {
    mockFetch({
      challenge: "chal-3",
      rp_id: "auth.example.com",
      allow_credentials: [{ id: "cred-1", type: "public-key" }],
      user_verification: "required",
      timeout: 60000,
    });
    const client = makeClient();

    await client.startWebAuthnAuthentication("user_42");

    const [, init] = lastCall();
    const body = JSON.parse(init.body as string);
    expect(body.user_id).toBe("user_42");
  });

  // ── Authentication complete → tokens ────────────────────────────────────
  it("finishWebAuthnAuthentication POSTs assertion and returns a TokenResponse", async () => {
    mockFetch({
      access_token: "at",
      id_token: "it",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "rt",
    });
    const client = makeClient();

    const res = await client.finishWebAuthnAuthentication({
      credential_id: "cred-1",
      client_data_json: "cdj",
      authenticator_data: "ad",
      signature: "sig",
      origin: "https://app.example.com",
    });

    const [url, init] = lastCall();
    expect(url).toBe("https://auth.example.com/webauthn/auth/complete");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.credential_id).toBe("cred-1");
    expect(body.signature).toBe("sig");
    expect(res.access_token).toBe("at");
    expect(res.token_type).toBe("Bearer");
  });
});
