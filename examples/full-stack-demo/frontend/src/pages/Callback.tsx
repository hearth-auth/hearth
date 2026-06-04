import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { hearthAuth } from "../main.js";

/** Handles the OIDC redirect — exchanges the authorization code for tokens. */
export default function Callback() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const errorParam = params.get("error");
    const errorDesc = params.get("error_description");

    if (errorParam) {
      setError(errorDesc ?? errorParam);
      return;
    }

    if (!code || !state) {
      setError("Missing code or state in callback URL.");
      return;
    }

    hearthAuth
      .handleCallback(code, state)
      .then(() => navigate("/dashboard", { replace: true }))
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      );
  }, [navigate]);

  if (error) {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <div className="alert alert-error">
            <strong>Authentication failed</strong>
            <p>{error}</p>
          </div>
          <a href="/" className="btn btn-primary btn-full">
            Back to sign in
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="loading-screen">
      <span className="spinner" />
      <p>Completing sign in…</p>
    </div>
  );
}
