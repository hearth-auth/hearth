import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { hearthAuth } from "./main.js";
import { getRefreshToken, clearTokens, isAuthenticated } from "@hearth-auth/sdk";
import Login from "./pages/Login.js";
import Callback from "./pages/Callback.js";
import Dashboard from "./pages/Dashboard.js";
import Notes from "./pages/Notes.js";
import Admin from "./pages/Admin.js";
import ProtectedRoute from "./components/ProtectedRoute.js";

export default function App() {
  // Restore session from localStorage refresh token on page load.
  const [restoring, setRestoring] = useState(() => {
    return getRefreshToken() !== null && !isAuthenticated();
  });

  useEffect(() => {
    if (!restoring) return;
    hearthAuth
      .refreshAccessToken()
      .catch(() => clearTokens())
      .finally(() => setRestoring(false));
  }, [restoring]);

  if (restoring) {
    return (
      <div className="loading-screen">
        <span className="spinner" />
        <p>Restoring session…</p>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        {/* Public */}
        <Route path="/" element={<Login />} />
        <Route path="/callback" element={<Callback />} />

        {/* Protected */}
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/notes" element={<Notes />} />
          <Route path="/admin" element={<Admin />} />
        </Route>

        {/* Fallback */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
