import { useState } from "react";
import { Navigate } from "react-router-dom";
import { hearthAuth } from "../main.js";
import { isAuthenticated } from "@hearth/sdk";

export default function Login() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Already logged in — skip straight to dashboard.
  if (isAuthenticated()) {
    return <Navigate to="/dashboard" replace />;
  }

  async function handleSignIn() {
    setLoading(true);
    setError(null);
    try {
      await hearthAuth.startLogin();
      // Browser navigates away; this line is never reached.
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setLoading(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="brand">
          <h1>Hearth Hub</h1>
          <p className="subtitle">Full-stack demo · Vite + React + Hearth</p>
        </div>

        {error && <div className="alert alert-error">{error}</div>}

        <button
          className="btn btn-primary btn-full"
          onClick={() => void handleSignIn()}
          disabled={loading}
        >
          {loading ? "Redirecting…" : "Sign in with Hearth"}
        </button>

        <div className="demo-users">
          <p className="hint">Demo users (password: <code>HearthTest123!</code>)</p>
          <table>
            <thead>
              <tr><th>Email</th><th>Role</th><th>Unlocks</th></tr>
            </thead>
            <tbody>
              <tr>
                <td><code>viewer@hearth.test</code></td>
                <td><span className="badge badge-viewer">viewer</span></td>
                <td>Read-only dashboard</td>
              </tr>
              <tr>
                <td><code>editor@hearth.test</code></td>
                <td><span className="badge badge-editor">editor</span></td>
                <td>New Note button</td>
              </tr>
              <tr>
                <td><code>admin@hearth.test</code></td>
                <td><span className="badge badge-admin">admin</span></td>
                <td>Admin → Users tab</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
