/**
 * Spec §5 — Hearth SDK error hierarchy.
 *
 * All SDK-specific errors extend HearthSdkError so callers can catch
 * the entire category with a single `instanceof HearthSdkError` check.
 */

/** Base class for all Hearth SDK errors. */
export class HearthSdkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

/** Thrown when the client is misconfigured (missing baseUrl, realmId, etc.). */
export class ConfigurationError extends HearthSdkError {
  constructor(message: string) {
    super(message);
  }
}

/** Thrown when the OIDC discovery document cannot be fetched or parsed. */
export class DiscoveryError extends HearthSdkError {
  constructor(
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
  }
}

/** Thrown when fetching or parsing the JWKS document fails. */
export class JWKSFetchError extends HearthSdkError {
  constructor(
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
  }
}

/** Thrown when a token's `exp` claim is in the past. */
export class TokenExpiredError extends HearthSdkError {
  constructor(
    public readonly expiredAt: Date,
    message = `Token expired at ${expiredAt.toISOString()}`,
  ) {
    super(message);
  }
}

/** Thrown when a token's `nbf` claim is in the future. */
export class TokenNotYetValidError extends HearthSdkError {
  constructor(
    public readonly notBefore: Date,
    message = `Token not yet valid until ${notBefore.toISOString()}`,
  ) {
    super(message);
  }
}

/** Thrown when a token fails signature or structural validation. */
export class TokenInvalidError extends HearthSdkError {
  constructor(message: string) {
    super(message);
  }
}

/** Thrown when the token's `iss` claim does not match the expected issuer. */
export class TokenIssuerError extends HearthSdkError {
  constructor(
    public readonly expected: string,
    public readonly actual: string,
    message = `Token issuer mismatch: expected "${expected}", got "${actual}"`,
  ) {
    super(message);
  }
}

/** Thrown when the token's `aud` claim does not include the expected audience. */
export class TokenAudienceError extends HearthSdkError {
  constructor(
    public readonly expected: string,
    public readonly actual: string[],
    message = `Token audience mismatch: expected "${expected}", got [${actual.join(", ")}]`,
  ) {
    super(message);
  }
}

/** Thrown when a token introspection request fails or returns inactive. */
export class IntrospectionError extends HearthSdkError {
  constructor(
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
  }
}

/**
 * Thrown when the `mode` field echoed in an introspection response does not
 * match the SDK's configured `expectedMode`.
 *
 * Per HEA-923 design constraint: mode must be validated explicitly; the SDK
 * MUST NOT silently tolerate a server returning a different mode than the one
 * configured for the resource server.
 */
export class AuthorizationModeMismatchError extends HearthSdkError {
  constructor(
    public readonly expected: string,
    public readonly actual: string,
    message = `Authorization mode mismatch: expected "${expected}", got "${actual}"`,
  ) {
    super(message);
  }
}

/**
 * Thrown when a token's `sv` claim is below the minimum accepted session
 * version for the session (RFC HEA-930 § 8).
 *
 * Resource servers should translate this into an HTTP 401 response.
 */
export class SessionVersionRevokedError extends HearthSdkError {
  constructor(
    public readonly sessionId: string,
    public readonly tokenSv: bigint,
    public readonly minSv: bigint,
    message = `Session version revoked: sid=${sessionId}, sv=${tokenSv} < min=${minSv}`,
  ) {
    super(message);
  }
}

/**
 * Thrown when the session-version cache has not been refreshed within
 * `staleThresholdMs` (RFC HEA-930 § 8.1).
 *
 * When `onStale` is `"reject"`, resource servers should translate this into
 * an HTTP 401 response with `error=session_version_cache_stale`.
 * When `onStale` is `"introspect"`, catch this error and fall back to the
 * introspection endpoint.
 */
export class SessionVersionCacheStaleError extends HearthSdkError {
  constructor(
    /** Cache age in milliseconds, or -1 if the cache has never been seeded. */
    public readonly ageMs: number,
    public readonly onStale: "reject" | "introspect" = "reject",
    message = `Session version cache stale: age=${ageMs < 0 ? "never seeded" : `${ageMs}ms`}`,
  ) {
    super(message);
  }
}
