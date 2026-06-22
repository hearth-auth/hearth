import { hearthAuth } from "../main.js";
import { getAccessToken } from "@hearth-auth/sdk";

/** Decode only the JWT payload — signature is trusted because we issued it. */
function decodePayload(token: string): Record<string, unknown> {
  try {
    const payload = token.split(".")[1] ?? "";
    // Fix padding, convert base64url → base64.
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/** Avatar + display name chip with a Logout button. */
export default function UserMenu() {
  const token = getAccessToken();
  const claims = token ? decodePayload(token) : {};
  const name =
    (claims.name as string | undefined) ??
    (claims.email as string | undefined) ??
    "User";
  const initials = name
    .split(" ")
    .map((w) => w[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className="user-menu">
      <div className="avatar" title={name}>
        {initials}
      </div>
      <span className="user-name">{name}</span>
      <button
        className="btn btn-ghost"
        onClick={() => void hearthAuth.logout()}
      >
        Sign out
      </button>
    </div>
  );
}
