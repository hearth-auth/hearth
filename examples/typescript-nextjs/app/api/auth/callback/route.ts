import { NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";
import { hearthClient, CLIENT_ID, REDIRECT_URI } from "@/lib/hearth";

export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;
  const code = searchParams.get("code");
  const returnedState = searchParams.get("state");
  const error = searchParams.get("error");

  if (error) {
    return NextResponse.redirect(new URL(`/?error=${error}`, req.url));
  }

  const cookieStore = cookies();
  const savedState = cookieStore.get("oauth_state")?.value;
  const codeVerifier = cookieStore.get("pkce_verifier")?.value;

  // Constant-time state comparison would be ideal; NextResponse.redirect on
  // mismatch is safe because we don't expose any token material.
  if (!code || !returnedState || returnedState !== savedState || !codeVerifier) {
    return NextResponse.redirect(new URL("/?error=invalid_state", req.url));
  }

  // Exchange the authorization code for tokens.
  const tokens = await hearthClient.exchangeCode({
    clientId: CLIENT_ID,
    code,
    redirectUri: REDIRECT_URI,
    codeVerifier,
  });

  const response = NextResponse.redirect(new URL("/dashboard", req.url));

  // Store tokens in HTTP-only cookies — never expose them to JavaScript.
  response.cookies.set("access_token", tokens.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: tokens.expires_in,
    path: "/",
  });
  response.cookies.set("refresh_token", tokens.refresh_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 60 * 60 * 24 * 7, // 7 days
    path: "/",
  });

  // Clean up PKCE cookies.
  response.cookies.delete("pkce_verifier");
  response.cookies.delete("oauth_state");

  return response;
}
