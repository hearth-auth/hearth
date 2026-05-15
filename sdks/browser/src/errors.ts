/** §5 — Hearth browser SDK error taxonomy. */

const REDACTED = "[redacted]";

function sanitize(value: string): string {
  return value.replace(/[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/g, REDACTED);
}

/** Base class for all @hearth/browser errors. */
export class HearthError extends Error {
  readonly cause?: unknown;

  constructor(message: string, options?: { cause?: unknown }) {
    super(sanitize(message));
    this.name = this.constructor.name;
    if (options?.cause !== undefined) {
      this.cause = options.cause;
    }
  }
}

/** Thrown when the client is misconfigured. */
export class ConfigurationError extends HearthError {}

/** Thrown when OIDC discovery fails. */
export class DiscoveryError extends HearthError {}

/** Thrown when fetching or parsing the JWKS document fails. */
export class JwksFetchError extends HearthError {}

/** Thrown when token signature verification fails or the token is structurally invalid. */
export class TokenVerificationError extends HearthError {}

/** Thrown when token `exp` is in the past beyond clock skew tolerance. */
export class TokenExpiredError extends TokenVerificationError {
  constructor(expiredAt: Date, options?: { cause?: unknown }) {
    super(`Token expired at ${expiredAt.toISOString()}`, options);
  }
}

/** Thrown when a required claim is missing, wrong type, or fails validation. */
export class TokenClaimsError extends TokenVerificationError {}

/** Thrown when the introspection request fails. */
export class IntrospectionError extends HearthError {}

/** Thrown when auth flow state is corrupted or PKCE fails. */
export class MiddlewareError extends HearthError {}
