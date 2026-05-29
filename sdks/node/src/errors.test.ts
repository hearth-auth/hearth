import { describe, it, expect } from "vitest";
import {
  HearthError,
  ConfigurationError,
  DiscoveryError,
  JWKSFetchError,
  TokenVerificationError,
  TokenExpiredError,
  TokenNotYetValidError,
  TokenInvalidError,
  TokenIssuerError,
  TokenAudienceError,
  TokenClaimsError,
  IntrospectionError,
  MiddlewareError,
  RequiredActionError,
} from "./errors.js";

describe("HearthError taxonomy", () => {
  it("all error classes extend HearthError", () => {
    const classes = [
      ConfigurationError,
      DiscoveryError,
      JWKSFetchError,
      TokenVerificationError,
      TokenClaimsError,
      IntrospectionError,
      MiddlewareError,
      TokenInvalidError,
      TokenIssuerError,
      TokenAudienceError,
    ];
    for (const Cls of classes) {
      const err = new (Cls as new (m: string) => HearthError)("test");
      expect(err).toBeInstanceOf(HearthError);
      expect(err).toBeInstanceOf(Cls);
      expect(err.name).toBe(Cls.name);
    }
  });

  it("TokenExpiredError extends TokenVerificationError", () => {
    const err = new TokenExpiredError(new Date());
    expect(err).toBeInstanceOf(HearthError);
    expect(err).toBeInstanceOf(TokenVerificationError);
    expect(err).toBeInstanceOf(TokenExpiredError);
  });

  it("TokenNotYetValidError extends TokenVerificationError", () => {
    const d = new Date("2099-01-01T00:00:00Z");
    const err = new TokenNotYetValidError(d);
    expect(err).toBeInstanceOf(HearthError);
    expect(err).toBeInstanceOf(TokenVerificationError);
    expect(err).toBeInstanceOf(TokenNotYetValidError);
    expect(err.message).toContain("2099-01-01T00:00:00.000Z");
    expect(err.name).toBe("TokenNotYetValidError");
  });

  it("TokenInvalidError extends TokenVerificationError", () => {
    const err = new TokenInvalidError("bad signature");
    expect(err).toBeInstanceOf(TokenVerificationError);
    expect(err.name).toBe("TokenInvalidError");
  });

  it("TokenIssuerError extends TokenVerificationError", () => {
    const err = new TokenIssuerError("https://wrong.example.com");
    expect(err).toBeInstanceOf(TokenVerificationError);
    expect(err.name).toBe("TokenIssuerError");
    expect(err.message).toContain("https://wrong.example.com");
  });

  it("TokenAudienceError extends TokenVerificationError", () => {
    const err = new TokenAudienceError("my-client");
    expect(err).toBeInstanceOf(TokenVerificationError);
    expect(err.name).toBe("TokenAudienceError");
    expect(err.message).toContain("my-client");
  });

  it("RequiredActionError exposes requiredActions and optional redirectUri", () => {
    const err = new RequiredActionError(["VERIFY_EMAIL", "UPDATE_PASSWORD"]);
    expect(err).toBeInstanceOf(HearthError);
    expect(err.name).toBe("RequiredActionError");
    expect(err.requiredActions).toEqual(["VERIFY_EMAIL", "UPDATE_PASSWORD"]);
    expect(err.redirectUri).toBeUndefined();
  });

  it("RequiredActionError accepts optional redirectUri", () => {
    const err = new RequiredActionError(["VERIFY_EMAIL"], "https://auth.example.com/ui/required-actions");
    expect(err.requiredActions).toEqual(["VERIFY_EMAIL"]);
    expect(err.redirectUri).toBe("https://auth.example.com/ui/required-actions");
  });

  it("supports cause chaining", () => {
    const cause = new Error("original");
    const err = new DiscoveryError("wrapped", { cause });
    expect(err.cause).toBe(cause);
  });

  it("sanitizes JWT-like strings from messages", () => {
    const fakeJwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123";
    const err = new HearthError(`Token was: ${fakeJwt}`);
    expect(err.message).not.toContain(fakeJwt);
    expect(err.message).toContain("[redacted]");
  });

  it("TokenExpiredError formats expiry date in message", () => {
    const date = new Date("2024-01-01T00:00:00Z");
    const err = new TokenExpiredError(date);
    expect(err.message).toContain("2024-01-01T00:00:00.000Z");
  });

  it("TokenVerificationError is instance of TokenVerificationError via TokenExpiredError", () => {
    const err = new TokenExpiredError(new Date());
    expect(err).toBeInstanceOf(TokenVerificationError);
  });
});
