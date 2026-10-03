/**
 * RFC 7662 — IntrospectionClient error mapping and request shape (ported from
 * the Node SDK's introspect tests).
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { IntrospectionClient } from "../src/introspection-client.js";
import { HearthClient } from "../src/hearth-client.js";
import { IntrospectionError } from "../src/errors.js";

const ENDPOINT = "https://auth.example.com/introspect";

function makeClient(): IntrospectionClient {
  return new IntrospectionClient({
    introspectionEndpoint: ENDPOINT,
    clientId: "client1",
    clientSecret: "secret1",
  });
}

function stub(response: Response | Error) {
  const spy = vi.fn(() =>
    response instanceof Error ? Promise.reject(response) : Promise.resolve(response),
  );
  vi.stubGlobal("fetch", spy);
  return spy;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("IntrospectionClient.introspect()", () => {
  it("POSTs the token with HTTP Basic client credentials", async () => {
    const spy = stub(new Response(JSON.stringify({ active: true, sub: "u1" })));
    const result = await makeClient().introspect("tok");
    const [url, init] = spy.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(ENDPOINT);
    expect(new Headers(init.headers).get("Authorization")).toBe(`Basic ${btoa("client1:secret1")}`);
    expect(new URLSearchParams(String(init.body)).get("token")).toBe("tok");
    expect(result.active).toBe(true);
    expect(result.sub).toBe("u1");
  });

  it("passes token_type_hint when provided", async () => {
    const spy = stub(new Response(JSON.stringify({ active: true })));
    await makeClient().introspect("tok", "refresh_token");
    const init = (spy.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(new URLSearchParams(String(init.body)).get("token_type_hint")).toBe("refresh_token");
  });

  it("omits token_type_hint when not provided", async () => {
    const spy = stub(new Response(JSON.stringify({ active: true })));
    await makeClient().introspect("tok");
    const init = (spy.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(new URLSearchParams(String(init.body)).has("token_type_hint")).toBe(false);
  });

  it("throws IntrospectionError on a non-2xx response", async () => {
    stub(new Response("nope", { status: 401 }));
    await expect(makeClient().introspect("tok")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("throws IntrospectionError on a network failure, keeping the cause", async () => {
    const cause = new TypeError("ECONNREFUSED");
    stub(cause);
    const err = await makeClient()
      .introspect("tok")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IntrospectionError);
    expect((err as IntrospectionError).cause).toBe(cause);
  });

  it("throws IntrospectionError when the response is not JSON", async () => {
    stub(new Response("<html>", { status: 200 }));
    await expect(makeClient().introspect("tok")).rejects.toBeInstanceOf(IntrospectionError);
  });
});

describe("HearthClient.introspect() token type hint", () => {
  it("forwards tokenTypeHint to the introspection endpoint", async () => {
    const spy = vi.fn((url: string) =>
      Promise.resolve(
        new Response(
          JSON.stringify(
            String(url).includes("openid-configuration")
              ? {
                  issuer: "https://auth.example.com",
                  jwks_uri: "https://auth.example.com/jwks",
                  introspection_endpoint: ENDPOINT,
                }
              : { active: true },
          ),
        ),
      ),
    );
    vi.stubGlobal("fetch", spy);
    const client = new HearthClient({
      issuerUrl: "https://auth.example.com",
      clientId: "c",
      clientSecret: "s",
    });
    await client.introspect("tok", "access_token");
    const init = (spy.mock.calls[1] as unknown as [string, RequestInit])[1];
    expect(new URLSearchParams(String(init.body)).get("token_type_hint")).toBe("access_token");
  });
});
