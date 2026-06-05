import { Link } from "react-router-dom";
import { useHasRole, useHasPermission, useInGroup, useInOrg } from "@hearth/sdk";
import UserMenu from "../components/UserMenu.js";
import { getAccessToken } from "@hearth/sdk";

function decodePayload(token: string): Record<string, unknown> {
  try {
    const b64 = (token.split(".")[1] ?? "").replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4))) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/** Shows decoded JWT claims + role/permission badges. */
export default function Dashboard() {
  const token = getAccessToken() ?? "";
  const claims = decodePayload(token);

  // SDK hooks — read JWT claims synchronously, no network.
  const isViewer = useHasRole("viewer");
  const isEditor = useHasRole("editor");
  const isAdmin = useHasRole("admin");
  const canRead = useHasPermission("content.read");
  const canWrite = useHasPermission("content.write");
  const canAdminister = useHasPermission("content.admin");

  return (
    <div className="page">
      <header className="page-header">
        <nav className="nav">
          <span className="nav-brand">Hearth Hub</span>
          <div className="nav-links">
            <Link to="/dashboard" className="nav-link active">Dashboard</Link>
            <Link to="/notes" className="nav-link">Notes</Link>
            {isAdmin && <Link to="/admin" className="nav-link">Admin</Link>}
          </div>
          <UserMenu />
        </nav>
      </header>

      <main className="page-content">
        <h2>Dashboard</h2>

        <section className="card">
          <h3>Your roles</h3>
          <div className="badge-row">
            {isViewer && <span className="badge badge-viewer">viewer</span>}
            {isEditor && <span className="badge badge-editor">editor</span>}
            {isAdmin && <span className="badge badge-admin">admin</span>}
            {!isViewer && !isEditor && !isAdmin && (
              <span className="badge">no roles</span>
            )}
          </div>
        </section>

        <section className="card">
          <h3>Your permissions</h3>
          <div className="badge-row">
            {canRead && <span className="badge badge-perm">content.read</span>}
            {canWrite && <span className="badge badge-perm">content.write</span>}
            {canAdminister && <span className="badge badge-perm">content.admin</span>}
            {!canRead && !canWrite && !canAdminister && (
              <span className="badge">no permissions</span>
            )}
          </div>
        </section>

        <section className="card">
          <h3>Group &amp; org membership</h3>
          <p className="hint">
            <code>useInGroup</code> / <code>useInOrg</code> — checks the{" "}
            <code>groups</code> / <code>oid</code> JWT claims. Assign a user to
            a group or org in Hearth to see these update.
          </p>
          <ClaimProbe />
        </section>

        <section className="card">
          <h3>Raw JWT claims</h3>
          <pre className="code-block">
            {JSON.stringify(claims, null, 2)}
          </pre>
        </section>
      </main>
    </div>
  );
}

/** Live probe of useInGroup / useInOrg — illustrates how the hooks work. */
function ClaimProbe() {
  // These will return false for the demo seed users (no groups/org assigned).
  const inDemoGroup = useInGroup("demo-team");
  const inDemoOrg = useInOrg("acme");

  return (
    <ul className="claim-list">
      <li>
        <code>useInGroup("demo-team")</code> →{" "}
        <strong>{String(inDemoGroup)}</strong>
      </li>
      <li>
        <code>useInOrg("acme")</code> →{" "}
        <strong>{String(inDemoOrg)}</strong>
      </li>
    </ul>
  );
}
