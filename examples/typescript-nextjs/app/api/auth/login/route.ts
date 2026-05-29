import { NextResponse } from "next/server";
import { randomBytes, createHash } from "crypto";
import { cookies } from "next/headers";
import { CLIENT_ID, REDIRECT_URI, getHearthClient } from "@/lib/hearth";

export const dynamic = "force-dynamic";

export async function GET() {
  // Fetch Hearth's OIDC discovery document to get the authorization_endpoint.
  const discovery = await getHearthClient().discovery();

  // Generate PKCE verifier + challenge (RFC 7636).
  const codeVerifier = randomBytes(32).toString("hex");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  // CSRF protection: bind state to this browser session.
  const state = randomBytes(16).toString("hex");

  // Store verifier + state in short-lived HTTP-only cookies so the callback
  // route can verify them without exposing them to JavaScript.
  const cookieStore = await cookies();
  cookieStore.set("pkce_verifier", codeVerifier, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 300, // 5 minutes
    path: "/",
  });
  cookieStore.set("oauth_state", state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 300,
    path: "/",
  });

  // Build the authorization URL — redirect the browser to Hearth's login page.
  const authUrl = new URL(discovery.authorization_endpoint as string);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("scope", "openid profile email");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return NextResponse.redirect(authUrl.toString());
}
