import * as React from "react";
import type { HearthFacade } from "./hearth.js";

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
  return React.createElement(HearthContext.Provider, { value: props.client }, props.children);
}

/**
 * Runs one facade check after each render and returns its last result.
 * `false` until the first check resolves, and whenever a check rejects or no
 * provider is mounted: the facade verifies the token asynchronously, and an
 * unverified answer is never `true`.
 */
function useCheck(check: (client: HearthFacade) => Promise<boolean>): boolean {
  const client = React.useContext(HearthContext);
  const [held, setHeld] = React.useState(false);
  // No dependency list: the token can change between renders without any
  // prop changing, so the check runs again after every render. Setting the
  // same value again does not re-render.
  React.useEffect(() => {
    if (client === null) {
      setHeld(false);
      return;
    }
    let current = true;
    check(client).then(
      (result) => {
        if (current) setHeld(result);
      },
      () => {
        if (current) setHeld(false);
      },
    );
    return () => {
      current = false;
    };
  });
  return client !== null && held;
}

/**
 * Returns `true` once the nearest {@link HearthProvider} client has verified
 * the token and found the permission in its claims. Returns `false` before
 * then, and when no provider is mounted.
 */
export function useHasPermission(permission: string): boolean {
  return useCheck((client) => client.hasPermission(permission));
}

/** Returns `true` once the verified token's `roles` claim is found to contain `role`. */
export function useHasRole(role: string): boolean {
  return useCheck((client) => client.hasRole(role));
}

/** Returns `true` once the verified token's `groups` claim is found to contain `group`. */
export function useInGroup(group: string): boolean {
  return useCheck((client) => client.inGroup(group));
}

/** Returns `true` once the verified token's `oid` claim is found to equal `org`. */
export function useInOrg(org: string): boolean {
  return useCheck((client) => client.inOrg(org));
}
