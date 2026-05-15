/** §2 — JWKS-backed token verification with cache and background refresh. */

import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from "jose";
import type {
  JWTVerifyOptions,
  RemoteJWKSetOptions,
  JWSHeaderParameters,
  FlattenedJWSInput,
  GetKeyFunction,
} from "jose";
import { JwksFetchError, TokenVerificationError, TokenExpiredError, TokenClaimsError } from "./errors.js";
import { VerifiedToken } from "./verified-token.js";
import type { OIDCDiscovery } from "./tokens.js";

type JwkKeyArg = GetKeyFunction<JWSHeaderParameters, FlattenedJWSInput>;

export type JwkSetFactory = (jwksUri: string, ttlMs: number) => JwkKeyArg;

const JWKS_TTL_DEFAULT_MS = 5 * 60 * 1000;
const JWKS_TTL_MAX_MS = 24 * 60 * 60 * 1000;
const CLOCK_SKEW_DEFAULT_S = 60;

export interface JwksVerifierConfig {
  issuer_url: string;
  jwks_ttl?: number;
  clock_skew_seconds?: number;
  audience?: string | string[];
}

export class JwksVerifier {
  private readonly config: Required<Omit<JwksVerifierConfig, "audience">> & { audience: string[] };
  private remoteJwkSet: JwkKeyArg | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly jwkSetFactory: JwkSetFactory;

  constructor(
    config: JwksVerifierConfig,
    private readonly getDiscovery: () => Promise<OIDCDiscovery>,
    jwkSetFactory?: JwkSetFactory,
  ) {
    const jwks_ttl = Math.min(config.jwks_ttl ?? JWKS_TTL_DEFAULT_MS, JWKS_TTL_MAX_MS);
    const audience = config.audience
      ? Array.isArray(config.audience) ? config.audience : [config.audience]
      : [];

    this.config = {
      issuer_url: config.issuer_url.replace(/\/$/, ""),
      jwks_ttl,
      clock_skew_seconds: config.clock_skew_seconds ?? CLOCK_SKEW_DEFAULT_S,
      audience,
    };

    this.jwkSetFactory = jwkSetFactory ?? ((uri, ttl) =>
      createRemoteJWKSet(new URL(uri), {
        cacheMaxAge: ttl,
        cooldownDuration: 30_000,
      } as RemoteJWKSetOptions) as unknown as JwkKeyArg
    );
  }

  private async buildJwkSet(): Promise<JwkKeyArg> {
    let jwksUri: string;
    try {
      const doc = await this.getDiscovery();
      jwksUri = (doc as OIDCDiscovery & { jwks_uri?: string }).jwks_uri ?? "";
      if (!jwksUri) throw new JwksFetchError("No jwks_uri in discovery document");
    } catch (err) {
      if (err instanceof JwksFetchError) throw err;
      throw new JwksFetchError("Failed to discover JWKS URI", { cause: err });
    }

    const cacheMaxAge = this.config.jwks_ttl;
    const jwkSet = this.jwkSetFactory(jwksUri, cacheMaxAge);
    this.scheduleBackgroundRefresh(cacheMaxAge);
    return jwkSet;
  }

  private scheduleBackgroundRefresh(ttlMs: number): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    const delay = Math.max(ttlMs * 0.8, 60_000);
    this.refreshTimer = setTimeout(() => {
      this.remoteJwkSet = null;
      this.getJwkSet().catch(() => undefined);
    }, delay);
  }

  private async getJwkSet(): Promise<JwkKeyArg> {
    if (!this.remoteJwkSet) {
      this.remoteJwkSet = await this.buildJwkSet();
    }
    return this.remoteJwkSet;
  }

  /** Verify a JWT. Supports RS256 and ES256. */
  async verifyToken(token: string): Promise<VerifiedToken> {
    const jwkSet = await this.getJwkSet();

    const verifyOptions: JWTVerifyOptions = {
      issuer: this.config.issuer_url,
      clockTolerance: this.config.clock_skew_seconds,
      algorithms: ["RS256", "ES256", "RS384", "ES384", "RS512", "ES512"],
    };
    if (this.config.audience.length > 0) {
      verifyOptions.audience = this.config.audience;
    }

    try {
      const result = await jwtVerify(token, jwkSet, verifyOptions);
      return new VerifiedToken(result.payload, result.protectedHeader as Record<string, unknown>);
    } catch (err) {
      if (err instanceof joseErrors.JWTExpired) {
        const expiredAt = err.payload?.exp ? new Date(err.payload.exp * 1000) : new Date(0);
        throw new TokenExpiredError(expiredAt, { cause: err });
      }
      if (
        err instanceof joseErrors.JWKSNoMatchingKey ||
        err instanceof joseErrors.JWKSMultipleMatchingKeys
      ) {
        this.remoteJwkSet = null;
        const freshSet = await this.getJwkSet().catch((e) => {
          throw new JwksFetchError("JWKS re-fetch after key miss failed", { cause: e });
        });
        try {
          const result = await jwtVerify(token, freshSet, verifyOptions);
          return new VerifiedToken(result.payload, result.protectedHeader as Record<string, unknown>);
        } catch (retryErr) {
          throw new TokenVerificationError("Token verification failed after JWKS refresh", {
            cause: retryErr,
          });
        }
      }
      if (
        err instanceof joseErrors.JWTClaimValidationFailed ||
        err instanceof joseErrors.JWTInvalid
      ) {
        throw new TokenClaimsError(
          `Token claim validation failed: ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        );
      }
      throw new TokenVerificationError(
        `Token verification failed: ${err instanceof Error ? err.message : "unknown error"}`,
        { cause: err },
      );
    }
  }

  /** Evict JWKS cache (e.g. on 401 from resource server). */
  invalidateCache(): void {
    this.remoteJwkSet = null;
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }
}
