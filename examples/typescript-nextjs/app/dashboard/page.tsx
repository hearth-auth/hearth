"use client";

import { useEffect, useState } from "react";
import {
  createHearth,
  HearthProvider,
  useHasPermission,
  useHasRole,
} from "@hearth-auth/sdk";
import Link from "next/link";

const hearth = createHearth({
  baseUrl: process.env.NEXT_PUBLIC_HEARTH_BASE_URL ?? "",
  realmId: process.env.NEXT_PUBLIC_HEARTH_REALM_ID ?? "",
  // Read the token from the cookie. In production use an API route that
  // returns a non-HttpOnly copy of the access token (or read from memory).
  getToken: () => {
    if (typeof document === "undefined") return null;
    return (
      document.cookie
        .split("; ")
        .find((c) => c.startsWith("access_token="))
        ?.split("=")[1] ?? null
    );
  },
});

function DashboardContent() {
  const canPublish = useHasPermission("docs.publish");
  const isAdmin = useHasRole("admin");
  const [permissions, setPermissions] = useState<string[]>([]);

  useEffect(() => {
    hearth.client
      .permissions()
      .then((p) => setPermissions(p.permissions))
      .catch(() => setPermissions([]));
  }, []);

  return (
    <main>
      <h1>Dashboard</h1>
      <p style={{ margin: "1rem 0 0.5rem" }}>
        Signed in. Your RBAC claims from the JWT:
      </p>

      {isAdmin && (
        <p style={{ color: "green" }}>
          ✓ You have the <strong>admin</strong> role.
        </p>
      )}

      {canPublish ? (
        <p style={{ color: "green" }}>
          ✓ You can publish (<code>docs.publish</code> permission).
        </p>
      ) : (
        <p style={{ color: "#999" }}>
          ✗ No <code>docs.publish</code> permission.
        </p>
      )}

      <h2 style={{ marginTop: "1.5rem" }}>Live permissions (from server)</h2>
      <pre>{JSON.stringify(permissions, null, 2)}</pre>

      <p style={{ marginTop: "1.5rem" }}>
        <Link href="/api/auth/logout">Sign out</Link>
      </p>
    </main>
  );
}

export default function DashboardPage() {
  return (
    <HearthProvider client={hearth}>
      <DashboardContent />
    </HearthProvider>
  );
}
