/** §3 — Token introspection per RFC 7662. */

import { IntrospectionError } from "./errors.js";
import type { ResolvedConfig } from "./config.js";
import type { OidcDiscovery } from "./discovery.js";
import type { AccessTokenAuthorizationMode } from "./token.js";

/** RFC 7662 introspection response — required fields per spec §3. */
export interface IntrospectionResult {
  active: boolean;
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  scope?: string;
  /**
   * Access-token authorization mode echoed from the server (HEA-922).
   * Present when the introspecting client has a non-Embedded mode configured.
   */
  mode?: AccessTokenAuthorizationMode;
  /** Live permissions — populated for Introspection/Decision mode clients. */
  permissions?: string[];
  /** Live roles — populated for Introspection/Decision mode clients. */
  roles?: string[];
  /** Live group slugs — populated for Introspection/Decision mode clients. */
  groups?: string[];
  /** Catch-all for non-standard claims returned by the server. */
  extra: Record<string, unknown>;
}

export class IntrospectionClient {
  private readonly credentials: string;

  constructor(
    private readonly config: ResolvedConfig,
    private readonly getDiscovery: () => Promise<OidcDiscovery>,
  ) {
    this.credentials = Buffer.from(
      `${config.client_id}:${config.client_secret}`,
    ).toString("base64");
  }

  private async getIntrospectionEndpoint(): Promise<string> {
    if (this.config.introspection_endpoint) return this.config.introspection_endpoint;
    const doc = await this.getDiscovery();
    if (!doc.introspection_endpoint) {
      throw new IntrospectionError(
        "Introspection endpoint not found in OIDC discovery document and no override configured",
      );
    }
    return doc.introspection_endpoint;
  }

  /** Introspect a token per RFC 7662. */
  async introspect(token: string, tokenTypeHint?: "access_token" | "refresh_token"): Promise<IntrospectionResult> {
    const endpoint = await this.getIntrospectionEndpoint();

    const body = new URLSearchParams({ token });
    if (tokenTypeHint) body.set("token_type_hint", tokenTypeHint);

    let res: Response;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.config.http_timeout);
      res = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${this.credentials}`,
        },
        body,
        signal: controller.signal,
      });
      clearTimeout(timer);
    } catch (err) {
      throw new IntrospectionError("Introspection request failed", { cause: err });
    }

    if (!res.ok) {
      throw new IntrospectionError(`Introspection endpoint returned HTTP ${res.status}`);
    }

    let raw: Record<string, unknown>;
    try {
      raw = await res.json() as Record<string, unknown>;
    } catch (err) {
      throw new IntrospectionError("Introspection response is not valid JSON", { cause: err });
    }

    const { active, sub, iss, aud, exp, iat, scope, mode, permissions, roles, groups, ...rest } = raw;
    return {
      active: Boolean(active),
      sub: typeof sub === "string" ? sub : undefined,
      iss: typeof iss === "string" ? iss : undefined,
      aud: typeof aud === "string" || Array.isArray(aud) ? aud as string | string[] : undefined,
      exp: typeof exp === "number" ? exp : undefined,
      iat: typeof iat === "number" ? iat : undefined,
      scope: typeof scope === "string" ? scope : undefined,
      mode: typeof mode === "string" ? mode as AccessTokenAuthorizationMode : undefined,
      permissions: Array.isArray(permissions) ? permissions.filter((p): p is string => typeof p === "string") : undefined,
      roles: Array.isArray(roles) ? roles.filter((r): r is string => typeof r === "string") : undefined,
      groups: Array.isArray(groups) ? groups.filter((g): g is string => typeof g === "string") : undefined,
      extra: rest,
    };
  }
}
