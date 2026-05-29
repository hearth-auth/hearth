/** §7 — AuthorizeClient: per-request permission decisions via POST /oauth/authorize. */

import { AuthorizeError } from "./errors.js";
import type { ResolvedConfig } from "./config.js";

export interface AuthorizeOptions {
  /** Optional org-scoped permission check. */
  organization_id?: string;
  /** Optional RFC 8707 resource URI for audience-scoped checks. */
  resource?: string;
}

export interface AuthorizeResult {
  /** Whether the token holder has the requested permission. */
  allowed: boolean;
}

/**
 * Calls `POST /oauth/authorize` to make a per-request permission decision.
 *
 * This client is fail-closed: network errors and non-OK responses return
 * `{ allowed: false }` rather than throwing, so middleware cannot accidentally
 * grant access on infrastructure failures.
 *
 * Misconfiguration (no endpoint) throws `AuthorizeError` before any network call.
 */
export class AuthorizeClient {
  private readonly endpoint: string | null;
  private readonly realmId: string | null;
  private readonly timeout: number;

  constructor(config: ResolvedConfig) {
    this.endpoint = config.authorize_endpoint ?? `${config.issuer_url}/oauth/authorize`;
    // If authorize_endpoint was explicitly set to null (no issuer_url fallback possible),
    // keep null so decide() can throw a typed error.
    if (config.authorize_endpoint === null && !config.issuer_url) {
      this.endpoint = null;
    }
    this.realmId = config.realm_id;
    this.timeout = config.http_timeout;
  }

  /**
   * Check whether the bearer token holder has `permission`.
   *
   * Fail-closed: returns `{ allowed: false }` on any network or server error.
   * Throws `AuthorizeError` only when the endpoint is not configured.
   */
  async decide(token: string, permission: string, opts?: AuthorizeOptions): Promise<AuthorizeResult> {
    if (!this.endpoint) {
      throw new AuthorizeError(
        "authorize_endpoint is not configured and issuer_url is unavailable",
      );
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
    };
    if (this.realmId) headers["X-Realm-ID"] = this.realmId;

    const body: Record<string, string> = { permission };
    if (opts?.organization_id) body["organization_id"] = opts.organization_id;
    if (opts?.resource) body["resource"] = opts.resource;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);
      const res = await fetch(this.endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!res.ok) return { allowed: false };

      const json = await res.json() as Record<string, unknown>;
      return { allowed: json["allowed"] === true };
    } catch {
      // Fail-closed: any network error → deny
      return { allowed: false };
    }
  }
}
