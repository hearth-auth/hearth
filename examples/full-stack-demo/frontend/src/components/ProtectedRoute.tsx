import { Navigate, Outlet } from "react-router-dom";
import { hearthAuth } from "../main.js";

/** Redirects unauthenticated visitors to `/`. */
export default function ProtectedRoute() {
  if (!hearthAuth.isAuthenticated()) {
    return <Navigate to="/" replace />;
  }
  return <Outlet />;
}
