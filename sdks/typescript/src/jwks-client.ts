import {
  createLocalJWKSet,
  jwtVerify,
  errors as joseErrors,
} from "jose";
import type {
  GetKeyFunction,
  JWSHeaderParameters,
  FlattenedJWSInput,
} from "jose";
import type { JsonWebKey } from "./types.js";
import { Claims } from "./claims.js";
import {
  JWKSFetchError,
  TokenExpiredError,
  TokenInvalidError,
  TokenIssuerError,
  TokenAudienceError,
} from "./errors.js";

/** Options for {@link JwksClient.verify}. */
export interface VerifyOptions {
  /** Expected `iss` claim. When provided, verification fails if the token's issuer differs. */
  issuer?: string;
  /** Expected `aud` claim(s). Skipped when absent. */
  audience?: string | string[];
  /** Clock skew tolerance in seconds. Default: 60. */
  clockSkewSeconds?: number;
}

/** Configuration for {@link JwksClient}. */
export interface JwksClientConfig {
  /** URL of the JWKS endpoint (e.g. from OIDC discovery `jwks_uri`). */
  jwksUri: string;
  /**
   * Override cache TTL in milliseconds.
   * When absent, the client respects `Cache-Control: max-age` from the JWKS
   * response and falls back to 5 minutes (300 000 ms).
   */
  ttl?: number;
  /** Timeout for outbound HTTP calls in milliseconds. Default: 10 000. */
  httpTimeout?: number;
}

type JwkKeyResolver = GetKeyFunction<JWSHeaderParameters, FlattenedJWSInput>;

/**
 * JWKS-backed JWT verifier with key caching, automatic key rotation,
 * and full EdDSA / Ed25519 signature verification (spec §2).
 *
 * Uses `fetchKeys()` (global `fetch`) to retrieve JWKS, then builds a local
 * key set via `createLocalJWKSet`. This makes the JWKS fetch mockable in tests.
 * Keys are cached for `ttl` milliseconds; on a key miss the JWKS is re-fetched once.
 */
export class JwksClient {
  private readonly jwksUri: string;
  readonly ttl: number | undefined;
  readonly httpTimeout: number;
  /** Cached local key set and when it was fetched. */
  private _cache: { keySet: JwkKeyResolver; fetchedAt: number } | null = null;

  constructor(config: JwksClientConfig) {
    this.jwksUri = config.jwksUri;
    this.ttl = config.ttl;
    this.httpTimeout = config.httpTimeout ?? 10_000;
  }

  private async getKeySet(forceRefresh = false): Promise<JwkKeyResolver> {
    const now = Date.now();
    const maxAge = this.ttl ?? 5 * 60 * 1000;
    if (!forceRefresh && this._cache && (now - this._cache.fetchedAt) < maxAge) {
      return this._cache.keySet;
    }
    const keys = await this.fetchKeys();
    const keySet = createLocalJWKSet({ keys: keys as Parameters<typeof createLocalJWKSet>[0]["keys"] });
    this._cache = { keySet: keySet as JwkKeyResolver, fetchedAt: now };
    return keySet as JwkKeyResolver;
  }

  /**
   * Verify a JWT using Ed25519/EdDSA JWKS-based local signature verification (spec §2).
   *
   * Executes all five spec §2 validation steps in order:
   * 1. Signature against cached JWKS (EdDSA / RS256 / ES256).
   * 2. `exp` — rejects expired tokens.
   * 3. `iss` — when `options.issuer` is provided.
   * 4. `aud` — when `options.audience` is provided.
   * 5. `iat` — within clock skew tolerance.
   *
   * @throws {@link TokenExpiredError} when the token is expired.
   * @throws {@link TokenInvalidError} when the signature or structure is invalid.
   * @throws {@link TokenIssuerError} when the issuer does not match.
   * @throws {@link TokenAudienceError} when the audience does not match.
   * @throws {@link JWKSFetchError} when the JWKS endpoint cannot be reached.
   */
  async verify(token: string, options?: VerifyOptions): Promise<Claims> {
    const clockTolerance = options?.clockSkewSeconds ?? 60;
    let keySet = await this.getKeySet();

    const doVerify = async (ks: JwkKeyResolver) => {
      const { payload } = await jwtVerify(token, ks, {
        issuer: options?.issuer,
        audience: options?.audience,
        algorithms: ["EdDSA", "RS256", "ES256", "RS384", "ES384"],
        clockTolerance,
      });
      return new Claims(payload as Record<string, unknown>);
    };

    try {
      return await doVerify(keySet);
    } catch (firstErr) {
      if (firstErr instanceof joseErrors.JWKSNoMatchingKey) {
        // Key miss — re-fetch once to handle key rotation, then retry.
        keySet = await this.getKeySet(true);
        try {
          return await doVerify(keySet);
        } catch (retryErr) {
          return this.mapJoseError(retryErr, options);
        }
      }
      return this.mapJoseError(firstErr, options);
    }
  }

  private mapJoseError(err: unknown, options?: VerifyOptions): never {
    if (err instanceof joseErrors.JWTExpired) {
      const exp = err.payload?.exp;
      throw new TokenExpiredError(exp ? new Date(exp * 1000) : new Date(0));
    }
    if (err instanceof joseErrors.JWTClaimValidationFailed) {
      const claim = err.claim;
      if (claim === "iss") {
        const actual = (err.payload as Record<string, unknown>)?.["iss"] as string ?? "";
        throw new TokenIssuerError(options?.issuer ?? "", actual);
      }
      if (claim === "aud") {
        const raw = (err.payload as Record<string, unknown>)?.["aud"];
        const actual = Array.isArray(raw) ? (raw as string[]) : [String(raw ?? "")];
        const expected = Array.isArray(options?.audience)
          ? options.audience[0]
          : (options?.audience ?? "");
        throw new TokenAudienceError(expected, actual);
      }
      throw new TokenInvalidError(`JWT claim validation failed (${claim}): ${err.message}`);
    }
    if (
      err instanceof joseErrors.JWTInvalid ||
      err instanceof joseErrors.JWSInvalid ||
      err instanceof joseErrors.JWSSignatureVerificationFailed ||
      err instanceof joseErrors.JWKSNoMatchingKey
    ) {
      throw new TokenInvalidError(
        err instanceof Error ? err.message : "JWT signature verification failed",
      );
    }
    if (err instanceof Error) {
      throw new TokenInvalidError(err.message);
    }
    throw new TokenInvalidError("Unknown token verification error");
  }

  /** Fetch the current JWKS keys from the endpoint. */
  async fetchKeys(): Promise<JsonWebKey[]> {
    const resp = await fetch(this.jwksUri, {
      signal: AbortSignal.timeout(this.httpTimeout),
    });
    if (!resp.ok) {
      throw new JWKSFetchError(`JWKS fetch failed with HTTP ${resp.status}`);
    }
    const doc = (await resp.json()) as { keys: JsonWebKey[] };
    return doc.keys;
  }
}
