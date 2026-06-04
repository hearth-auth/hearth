import { Navigate, Outlet } from "react-router-dom";
import { isAuthenticated } from "../auth/session.js";

/** Redirects unauthenticated visitors to `/`. */
export default function ProtectedRoute() {
  if (!isAuthenticated()) {
    return <Navigate to="/" replace />;
  }
  return <Outlet />;
}
