import { decodeJwt } from "jose";
import { AuthorizationModeMismatchError } from "./errors.js";
import type { HearthClient } from "./hearth-client.js";
import type { AccessTokenAuthorizationMode, AuthorizePermissionOptions } from "./types.js";

/** Options for {@link requirePermission}. */
export interface RequirePermissionOptions extends AuthorizePermissionOptions {
  /**
   * Which permission delivery mode the resource server expects.
   *
   * MUST be set explicitly — the middleware MUST NOT auto-detect the mode from
   * JWT claim presence. Absence of a `permissions` claim in the token does not
   * change behavior (per HEA-923 design constraint).
   */
  mode: AccessTokenAuthorizationMode;
  /** HearthClient instance used for network calls in decision/introspection modes. */
  client: HearthClient;
}

/**
 * A synchronous-or-async gate that returns `true` iff the token holder has
 * the given permission under the configured mode.
 */
export type PermissionChecker = (token: string) => Promise<boolean>;

/**
 * Returns a mode-aware permission checker for the given `permission`.
 *
 * Behaviour by mode:
 * - **embedded** — decodes the JWT locally and checks the `permissions` claim.
 *   No network traffic. Returns `false` when the claim is absent; DOES NOT
 *   fall back to network (design constraint: absence of claims ≠ switch mode).
 * - **decision** — calls `client.authorize(token, permission, opts)` which
 *   POSTs to `POST /oauth/authorize`. Fail-closed on network/server errors.
 * - **introspection** — calls `client.introspectionClient().introspect(token)`,
 *   validates the echoed `mode` field if present, then checks the returned
 *   `permissions` array. Throws {@link AuthorizationModeMismatchError} if the
 *   server echoes a mode that differs from `opts.mode`.
 *
 * @param permission - The permission string to check (e.g. `"docs.write"`).
 * @param opts - Mode, client reference, and optional scoping parameters.
 */
export function requirePermission(
  permission: string,
  opts: RequirePermissionOptions,
): PermissionChecker {
  const { mode, client, organizationId, resource } = opts;

  switch (mode) {
    case "embedded":
      return async (token: string): Promise<boolean> => {
        let claims: Record<string, unknown> | null = null;
        try {
          claims = decodeJwt(token) as Record<string, unknown>;
        } catch {
          return false;
        }
        const perms = claims["permissions"];
        return Array.isArray(perms) && perms.includes(permission);
      };

    case "decision":
      return async (token: string): Promise<boolean> =>
        client.authorize(token, permission, { organizationId, resource });

    case "introspection":
      return async (token: string): Promise<boolean> => {
        const ic = await client.introspectionClient();
        const result = await ic.introspect(token);

        // Validate mode echo when present — catches misconfigured deployments.
        if (result.mode !== undefined && result.mode !== "introspection") {
          throw new AuthorizationModeMismatchError("introspection", String(result.mode));
        }

        if (!result.active) return false;
        return (
          Array.isArray(result.permissions) && result.permissions.includes(permission)
        );
      };
  }
}
