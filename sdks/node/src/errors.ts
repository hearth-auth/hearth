/** §5 — Hearth Node SDK error taxonomy. */

const REDACTED = "[redacted]";

function sanitize(value: string): string {
  // Redact JWTs: header must start with eyJ (base64url of '{'), and we require all three segments.
  // This avoids false-positive redaction of domain names like "wrong.example.com".
  return value.replace(/eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/g, REDACTED);
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
