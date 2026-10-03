/**
 * Spec §5 — error taxonomy (ported from the Node SDK's errors tests).
 */

import { describe, it, expect } from "vitest";
import {
  AuthorizationModeMismatchError,
  ConfigurationError,
  DiscoveryError,
  HearthSdkError,
  IntrospectionError,
  JWKSFetchError,
  RequiredActionError,
  TokenAudienceError,
  TokenExpiredError,
  TokenInvalidError,
  TokenIssuerError,
  TokenNotYetValidError,
  TokenVerificationError,
} from "../src/errors.js";

describe("error taxonomy", () => {
  it("every error class extends HearthSdkError and is named after itself", () => {
    const errors: Array<[HearthSdkError, string]> = [
      [new ConfigurationError("x"), "ConfigurationError"],
      [new DiscoveryError("x"), "DiscoveryError"],
      [new JWKSFetchError("x"), "JWKSFetchError"],
      [new IntrospectionError("x"), "IntrospectionError"],
      [new TokenVerificationError("x"), "TokenVerificationError"],
      [new TokenInvalidError("x"), "TokenInvalidError"],
      [new TokenIssuerError("a", "b"), "TokenIssuerError"],
      [new TokenAudienceError("a", ["b"]), "TokenAudienceError"],
      [new RequiredActionError([]), "RequiredActionError"],
    ];
    for (const [err, name] of errors) {
      expect(err).toBeInstanceOf(HearthSdkError);
      expect(err).toBeInstanceOf(Error);
      expect(err.name).toBe(name);
    }
  });

  it("every token verification failure extends TokenVerificationError", () => {
    const failures = [
      new TokenExpiredError(new Date()),
      new TokenNotYetValidError(new Date()),
      new TokenInvalidError("bad signature"),
      new TokenIssuerError("https://expected", "https://wrong"),
      new TokenAudienceError("my-client", ["other"]),
    ];
    for (const err of failures) {
      expect(err).toBeInstanceOf(TokenVerificationError);
      expect(err).toBeInstanceOf(HearthSdkError);
    }
  });

  it("TokenExpiredError and TokenNotYetValidError format the date", () => {
    expect(new TokenExpiredError(new Date("2024-01-01T00:00:00Z")).message).toContain(
      "2024-01-01T00:00:00.000Z",
    );
    expect(new TokenNotYetValidError(new Date("2099-01-01T00:00:00Z")).message).toContain(
      "2099-01-01T00:00:00.000Z",
    );
  });

  it("RequiredActionError exposes requiredActions", () => {
    const err = new RequiredActionError(["VERIFY_EMAIL", "UPDATE_PASSWORD"]);
    expect(err.requiredActions).toEqual(["VERIFY_EMAIL", "UPDATE_PASSWORD"]);
  });

  it("AuthorizationModeMismatchError carries expected and actual modes", () => {
    const err = new AuthorizationModeMismatchError("introspection", "embedded");
    expect(err.expected).toBe("introspection");
    expect(err.actual).toBe("embedded");
    expect(err.message).toMatch(/introspection/);
    expect(err.message).toMatch(/embedded/);
  });

  it("keeps the cause", () => {
    const cause = new Error("original");
    expect(new DiscoveryError("wrapped", cause).cause).toBe(cause);
    expect(new IntrospectionError("wrapped", cause).cause).toBe(cause);
  });

  it("redacts JWT-shaped strings from messages", () => {
    const jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c2VyMSJ9.c2lnbmF0dXJl";
    const err = new HearthSdkError(`Token was: ${jwt} (end)`);
    expect(err.message).not.toContain(jwt);
    expect(err.message).toBe("Token was: [redacted] (end)");
    expect(new TokenInvalidError(`bad ${jwt}`).message).toBe("bad [redacted]");
  });

  it("leaves two-segment and non-JWT text alone", () => {
    expect(new HearthSdkError("eyJabc.def only").message).toBe("eyJabc.def only");
    expect(new HearthSdkError("plain message").message).toBe("plain message");
  });

  it("redaction is linear on adversarial input", () => {
    const evil = "eyJ".repeat(50_000) + ".";
    const start = Date.now();
    new HearthSdkError(evil);
    expect(Date.now() - start).toBeLessThan(1000);
  });
});
