import { useHasRole, useHasPermission } from "@hearth-auth/sdk";

interface RoleGateProps {
  /** Render children when the user has this role. */
  role?: string;
  /** Render children when the user has this permission. */
  permission?: string;
  /** Fallback UI when the check fails. Defaults to null (hidden). */
  fallback?: React.ReactNode;
  children: React.ReactNode;
}

/**
 * Conditionally renders children based on JWT role or permission claims.
 *
 * Uses `useHasRole` / `useHasPermission` from the Hearth SDK — no network
 * call; claims are read directly from the in-memory access token.
 */
export default function RoleGate({
  role,
  permission,
  fallback = null,
  children,
}: RoleGateProps) {
  const hasRole = useHasRole(role ?? "");
  const hasPerm = useHasPermission(permission ?? "");

  const allowed = (role ? hasRole : true) && (permission ? hasPerm : true);
  return <>{allowed ? children : fallback}</>;
}
