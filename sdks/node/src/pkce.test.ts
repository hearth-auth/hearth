/** §PKCE — generatePkce() tests (TDD — written before implementation). */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { generatePkce } from "./pkce.js";

describe("generatePkce", () => {
  it("returns a PkcePair with verifier, challenge, and method S256", () => {
    const pair = generatePkce();
    expect(typeof pair.verifier).toBe("string");
    expect(typeof pair.challenge).toBe("string");
    expect(pair.method).toBe("S256");
  });

  it("verifier is 43 Base64url characters (32 bytes, no padding)", () => {
    const { verifier } = generatePkce();
    expect(verifier).toHaveLength(43);
  });

  it("verifier contains only Base64url-safe characters", () => {
    const { verifier } = generatePkce();
    expect(verifier).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it("verifier has no padding characters", () => {
    const { verifier } = generatePkce();
    expect(verifier).not.toContain("=");
  });

  it("challenge is BASE64URL(SHA256(verifier)) with no padding", () => {
    const { verifier, challenge } = generatePkce();
    const expected = createHash("sha256").update(verifier).digest("base64url");
    expect(challenge).toBe(expected);
    expect(challenge).not.toContain("=");
  });

  it("challenge is 43 Base64url characters (SHA-256 = 32 bytes → 43 chars)", () => {
    const { challenge } = generatePkce();
    expect(challenge).toHaveLength(43);
  });

  it("successive calls produce unique pairs (CSPRNG)", () => {
    const p1 = generatePkce();
    const p2 = generatePkce();
    expect(p1.verifier).not.toBe(p2.verifier);
    expect(p1.challenge).not.toBe(p2.challenge);
  });

  it("method is always 'S256'", () => {
    for (let i = 0; i < 5; i++) {
      expect(generatePkce().method).toBe("S256");
    }
  });
});
