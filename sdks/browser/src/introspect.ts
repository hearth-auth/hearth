/** §3 — Token introspection per RFC 7662. */

import { IntrospectionError } from "./errors.js";
import type { OIDCDiscovery } from "./tokens.js";

/** RFC 7662 introspection result. */
export interface IntrospectionResult {
  active: boolean;
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  scope?: string;
  /** Non-standard claims returned by the server. */
  extra: Record<string, unknown>;
}

export class IntrospectionClient {
  constructor(
    private readonly clientId: string,
    private readonly getDiscovery: () => Promise<OIDCDiscovery>,
    private readonly httpTimeout: number = 10_000,
  ) {}

  private async getEndpoint(): Promise<string> {
    const doc = await this.getDiscovery();
    if (!doc.introspection_endpoint) {
      throw new IntrospectionError(
        "introspection_endpoint not found in OIDC discovery document",
      );
    }
    return doc.introspection_endpoint;
  }

  async introspect(token: string, tokenTypeHint?: "access_token" | "refresh_token"): Promise<IntrospectionResult> {
    const endpoint = await this.getEndpoint();
    const body = new URLSearchParams({ token, client_id: this.clientId });
    if (tokenTypeHint) body.set("token_type_hint", tokenTypeHint);

    let res: Response;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.httpTimeout);
      res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
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

    const { active, sub, iss, aud, exp, iat, scope, ...rest } = raw;
    return {
      active: Boolean(active),
      sub: typeof sub === "string" ? sub : undefined,
      iss: typeof iss === "string" ? iss : undefined,
      aud: typeof aud === "string" || Array.isArray(aud) ? (aud as string | string[]) : undefined,
      exp: typeof exp === "number" ? exp : undefined,
      iat: typeof iat === "number" ? iat : undefined,
      scope: typeof scope === "string" ? scope : undefined,
      extra: rest,
    };
  }
}
