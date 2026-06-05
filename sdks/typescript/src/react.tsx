import * as React from "react";
import type { HearthFacade } from "./hearth.js";
import type { Claims } from "./claims.js";

/**
 * React context carrying a {@link HearthFacade} down the tree.
 *
 * The default value is `null`; the hooks treat a `null` context as
 * unauthenticated and return `false`.
 */
export const HearthContext = React.createContext<HearthFacade | null>(null);

/** Props for {@link HearthProvider}. */
export interface HearthProviderProps {
  client: HearthFacade;
  children: React.ReactNode;
}

/**
 * Provides a {@link HearthFacade} to descendants via {@link HearthContext}.
 *
 * Wrap your React tree once with this after calling `createHearth(...)`.
 */
export function HearthProvider(props: HearthProviderProps): React.ReactElement {
  return React.createElement(
    HearthContext.Provider,
    { value: props.client },
    props.children,
  );
}

/**
 * Returns `true` iff the nearest {@link HearthProvider} client reports
 * the permission as present in the JWT claim set. Returns `false`
 * when no provider is mounted.
 */
export function useHasPermission(permission: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.hasPermission(permission);
}

/** Returns `true` iff the JWT `roles` claim contains `role`. */
export function useHasRole(role: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.hasRole(role);
}

/** Returns `true` iff the JWT `groups` claim contains `group`. */
export function useInGroup(group: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.inGroup(group);
}

/** Returns `true` iff the JWT `oid` claim equals `org`. */
export function useInOrg(org: string): boolean {
  const client = React.useContext(HearthContext);
  return client !== null && client.inOrg(org);
}

/**
 * Returns the typed {@link Claims} from the current access token, or `null`
 * when unauthenticated or no {@link HearthProvider} is mounted.
 *
 * Subscribes to token-change events (e.g. silent refresh) so the component
 * re-renders automatically when the token is replaced — avoiding the latent
 * bug of manually decoded claims going stale after refresh.
 */
export function useClaims(): Claims | null {
  const client = React.useContext(HearthContext);
  const [claims, setClaims] = React.useState<Claims | null>(
    () => client?.getClaims() ?? null,
  );

  React.useEffect(() => {
    if (!client) {
      setClaims(null);
      return;
    }
    setClaims(client.getClaims());
    return client.subscribe(() => {
      setClaims(client.getClaims());
    });
  }, [client]);

  return claims;
}

/** Common user identity fields extracted from the JWT for convenience. */
export interface UserProfile {
  /** The `sub` (subject) claim — typically a stable user ID. */
  sub: string;
  /** The `name` claim, or an empty string when absent. */
  name: string;
  /** The `email` claim, or an empty string when absent. */
  email: string;
  /** The `email_verified` claim. */
  emailVerified: boolean;
  /** The `picture` claim (avatar URL), or null when absent. */
  picture: string | null;
}

/**
 * Returns common user identity fields from the current access token, or
 * `null` when unauthenticated. Re-renders on token refresh via
 * {@link useClaims}.
 */
export function useUser(): UserProfile | null {
  const claims = useClaims();
  if (!claims) return null;
  return {
    sub: claims.subject(),
    name: String(claims.get("name") ?? ""),
    email: String(claims.get("email") ?? ""),
    emailVerified: Boolean(claims.get("email_verified")),
    picture:
      typeof claims.get("picture") === "string"
        ? (claims.get("picture") as string)
        : null,
  };
}
