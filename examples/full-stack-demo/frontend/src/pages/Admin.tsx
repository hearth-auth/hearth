import { useEffect, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { useHasRole } from "@hearth-auth/sdk";
import UserMenu from "../components/UserMenu.js";
import { api, type ApiUser } from "../api.js";

/** Admin-only page — redirects non-admins to /dashboard. */
export default function Admin() {
  const isAdmin = useHasRole("admin");
  const [users, setUsers] = useState<ApiUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAdmin) return;
    api
      .getUsers()
      .then(setUsers)
      .catch((err: unknown) =>
        setError(
          err instanceof Error
            ? err.message
            : "Backend not running — start Phase 3 (cd backend && cargo run)",
        ),
      )
      .finally(() => setLoading(false));
  }, [isAdmin]);

  // Non-admins are silently redirected — they never see a 403.
  if (!isAdmin) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div className="page">
      <header className="page-header">
        <nav className="nav">
          <span className="nav-brand">Hearth Hub</span>
          <div className="nav-links">
            <Link to="/dashboard" className="nav-link">Dashboard</Link>
            <Link to="/notes" className="nav-link">Notes</Link>
            <Link to="/admin" className="nav-link active">Admin</Link>
          </div>
          <UserMenu />
        </nav>
      </header>

      <main className="page-content">
        <h2>Admin — Users</h2>

        {error && (
          <div className="alert alert-error">
            <strong>Could not load users</strong>
            <p>{error}</p>
          </div>
        )}

        {loading && (
          <div className="loading-inline">
            <span className="spinner" /> Loading…
          </div>
        )}

        {!loading && !error && users.length === 0 && (
          <div className="empty-state">No users found.</div>
        )}

        {!loading && users.length > 0 && (
          <div className="card table-card">
            <table className="user-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Roles</th>
                  <th>ID</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.display_name}</td>
                    <td>{u.email}</td>
                    <td>
                      <div className="badge-row">
                        {u.roles.map((r) => (
                          <span key={r} className={`badge badge-${r}`}>{r}</span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <code className="id-cell">{u.id}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>
    </div>
  );
}
