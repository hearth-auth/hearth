/**
 * Spec §5 — Hearth SDK error hierarchy.
 *
 * All SDK-specific errors extend HearthSdkError so callers can catch
 * the entire category with a single `instanceof HearthSdkError` check.
 */

const REDACTED = "[redacted]";

/** True for the base64url alphabet: `A-Z a-z 0-9 _ -`. */
function isB64UrlCode(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 95 ||
    code === 45
  );
}

/**
 * Replace JWT-shaped substrings (`eyJ<seg>.<seg>.<seg>`) with `[redacted]`, so a
 * token that ends up in an error message is not written to logs.
 *
 * A single linear scan: a backtracking regex would be open to ReDoS on input
 * such as `"eyJeyJeyJ…"`.
 */
function redactTokens(value: string): string {
  let out = "";
  let i = 0;
  while (i < value.length) {
    if (value.startsWith("eyJ", i)) {
      const start = i;
      i += 3;
      while (i < value.length && isB64UrlCode(value.charCodeAt(i))) i++;
      if (value[i] === ".") {
        const dot1 = i++;
        const seg2Start = i;
        while (i < value.length && isB64UrlCode(value.charCodeAt(i))) i++;
        if (i > seg2Start && value[i] === ".") {
          i++;
          while (i < value.length && isB64UrlCode(value.charCodeAt(i))) i++;
          out += REDACTED;
          continue;
        }
        // Two segments only: not a JWT. Emit through the first dot and rescan.
        out += value.slice(start, dot1 + 1);
        i = dot1 + 1;
        continue;
      }
      out += value.slice(start, i);
      continue;
    }
    out += value[i++];
  }
  return out;
}

/**
 * Base class for all Hearth SDK errors.
 *
 * JWT-shaped substrings in the message are replaced with `[redacted]`.
 */
export class HearthSdkError extends Error {
  constructor(message: string) {
    super(redactTokens(message));
    this.name = this.constructor.name;
  }
}

/**
 * Base class for every token verification failure: expired, not yet valid,
 * bad signature or structure, wrong issuer, wrong audience. Catch this to
 * handle all of them at once.
 */
export class TokenVerificationError extends HearthSdkError {
  constructor(message: string) {
    super(message);
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
export class TokenExpiredError extends TokenVerificationError {
  constructor(
    public readonly expiredAt: Date,
    message = `Token expired at ${expiredAt.toISOString()}`,
  ) {
    super(message);
  }
}

/** Thrown when a token's `nbf` claim is in the future. */
export class TokenNotYetValidError extends TokenVerificationError {
  constructor(
    public readonly notBefore: Date,
    message = `Token not yet valid until ${notBefore.toISOString()}`,
  ) {
    super(message);
  }
}

/** Thrown when a token fails signature or structural validation. */
export class TokenInvalidError extends TokenVerificationError {
  constructor(message: string) {
    super(message);
  }
}

/** Thrown when the token's `iss` claim does not match the expected issuer. */
export class TokenIssuerError extends TokenVerificationError {
  constructor(
    public readonly expected: string,
    public readonly actual: string,
    message = `Token issuer mismatch: expected "${expected}", got "${actual}"`,
  ) {
    super(message);
  }
}

/** Thrown when the token's `aud` claim does not include the expected audience. */
export class TokenAudienceError extends TokenVerificationError {
  constructor(
    public readonly expected: string,
    public readonly actual: string[],
    message = `Token audience mismatch: expected "${expected}", got [${actual.join(", ")}]`,
  ) {
    super(message);
  }
}

/**
 * Thrown when a token has `token_type === "required_action"`: the subject must
 * complete pending actions before the token can be used for general API
 * access (spec §5). The browser SDK exports it for the shared error taxonomy;
 * Hearth itself resolves pending actions during `/authorize`, so
 * `handleCallback()` never receives such a token.
 */
export class RequiredActionError extends HearthSdkError {
  constructor(
    /** Pending action names (e.g. `["VERIFY_EMAIL"]`). */
    public readonly requiredActions: string[],
    message = `Required actions pending: ${requiredActions.join(", ")}`,
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
 * Thrown when an OAuth 2.0 token-endpoint request (code exchange, client credentials,
 * device flow, magic-link, etc.) returns a non-2xx HTTP response.
 */
export class OAuthFlowError extends HearthSdkError {
  constructor(
    /** HTTP status code returned by the server; 0 for network-level failures. */
    public readonly statusCode: number,
    /** OAuth error code from the response body, or a summary message. */
    public readonly errorCode: string,
    message = `OAuth flow error ${statusCode}: ${errorCode}`,
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
