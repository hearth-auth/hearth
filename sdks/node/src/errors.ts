/** §5 — Hearth Node SDK error taxonomy. */

const REDACTED = "[redacted]";

// Charcode ranges for base64url alphabet — used by sanitize() to avoid a backtracking regex.
function isB64UrlCode(code: number): boolean {
  return (code >= 65 && code <= 90)   // A-Z
    || (code >= 97 && code <= 122)    // a-z
    || (code >= 48 && code <= 57)     // 0-9
    || code === 95                    // _
    || code === 45;                   // -
}

function sanitize(value: string): string {
  // Linear O(n) scan — redacts JWT-shaped tokens (eyJ<seg>.<seg>.<seg>) without a
  // backtracking regex (which is ReDoS-vulnerable on crafted inputs like "eyJeyJeyJ…").
  let out = "";
  let i = 0;
  while (i < value.length) {
    if (value[i] === "e" && value[i + 1] === "y" && value[i + 2] === "J") {
      const start = i;
      i += 3;
      while (i < value.length && isB64UrlCode(value.charCodeAt(i))) i++;
      if (i < value.length && value[i] === ".") {
        const dot1 = i++;
        const seg2Start = i;
        while (i < value.length && isB64UrlCode(value.charCodeAt(i))) i++;
        if (i > seg2Start && i < value.length && value[i] === ".") {
          i++;
          while (i < value.length && isB64UrlCode(value.charCodeAt(i))) i++;
          out += REDACTED;
          continue;
        }
        // Two-segment prefix — not a JWT; emit up to and including the dot, re-scan remainder.
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

/** Base class for all @hearth/node errors. Messages are sanitized to remove tokens/secrets. */
export class HearthError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(sanitize(message), options);
    this.name = this.constructor.name;
    if (Error.captureStackTrace) Error.captureStackTrace(this, this.constructor);
  }
}

/** Thrown when the HearthClient is misconfigured (missing required fields, invalid URLs). */
export class ConfigurationError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when OIDC discovery (/.well-known/openid-configuration) fails. */
export class DiscoveryError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when fetching or parsing the JWKS document fails. */
export class JWKSFetchError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when token signature verification fails or the token is structurally invalid. */
export class TokenVerificationError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when token `exp` claim is in the past (beyond clock skew tolerance). */
export class TokenExpiredError extends TokenVerificationError {
  constructor(expiredAt: Date, options?: { cause?: unknown }) {
    super(`Token expired at ${expiredAt.toISOString()}`, options);
  }
}

/** Thrown when token `nbf` claim is in the future (beyond clock skew tolerance). */
export class TokenNotYetValidError extends TokenVerificationError {
  constructor(notBefore: Date, options?: { cause?: unknown }) {
    super(`Token not valid until ${notBefore.toISOString()}`, options);
  }
}

/** Thrown when token signature is invalid, the JWT is malformed, or the algorithm does not match. */
export class TokenInvalidError extends TokenVerificationError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when the `iss` claim does not match the configured issuer URL. */
export class TokenIssuerError extends TokenVerificationError {
  constructor(actualIssuer: string, options?: { cause?: unknown }) {
    super(`Token issuer "${actualIssuer}" does not match configured issuer`, options);
  }
}

/** Thrown when the `aud` claim does not contain the expected audience. */
export class TokenAudienceError extends TokenVerificationError {
  constructor(expectedAudience: string, options?: { cause?: unknown }) {
    super(`Token audience does not contain expected value "${expectedAudience}"`, options);
  }
}

/** Thrown when a required claim is missing, wrong type, or fails validation (iss, aud, iat). */
export class TokenClaimsError extends TokenVerificationError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown when the introspection request fails or returns an unexpected response. */
export class IntrospectionError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Thrown by Express/Fastify middleware when configuration is invalid or setup fails. */
export class MiddlewareError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/**
 * Thrown when the introspection response echoes an `access_token_authorization` mode
 * that does not match the SDK's configured `expectedMode`.
 */
export class AuthorizationModeError extends HearthError {
  readonly expected: string;
  readonly actual: string;

  constructor(expected: string, actual: string, options?: { cause?: unknown }) {
    super(`Expected authorization mode "${expected}" but server echoed "${actual}"`, options);
    this.expected = expected;
    this.actual = actual;
  }
}

/** Thrown when the `POST /oauth/authorize` request cannot be made (misconfiguration). */
export class AuthorizeError extends HearthError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/**
 * Thrown when a token with `token_type === "required_action"` is presented as a regular access
 * token, or when the server returns `error_code: "HEARTH_REQUIRED_ACTIONS_PENDING"`.
 */
export class RequiredActionError extends HearthError {
  /** Pending action names from the token's `required_actions` claim. */
  readonly requiredActions: string[];
  /** Optional URL to the Hearth interstitial page for completing required actions. */
  readonly redirectUri: string | undefined;

  constructor(requiredActions: string[], redirectUri?: string, options?: { cause?: unknown }) {
    super(
      `Token requires completion of required actions: ${requiredActions.join(", ") || "(none)"}`,
      options,
    );
    this.requiredActions = requiredActions;
    this.redirectUri = redirectUri;
  }
}

/**
 * Typed HTTP error for AdminClient operations that return 4xx/5xx responses
 * not covered by the standard error taxonomy.
 */
export class AdminHttpError extends HearthError {
  readonly status: number;

  constructor(status: number, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.status = status;
  }
}
