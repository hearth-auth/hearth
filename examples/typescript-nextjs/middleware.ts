import { NextRequest, NextResponse } from "next/server";
import { jwtVerify, createRemoteJWKSet } from "jose";

const HEARTH_BASE_URL = process.env.HEARTH_BASE_URL!;
const HEARTH_REALM_ID = process.env.HEARTH_REALM_ID!;

// Edge-compatible JWKS (jose fetches and caches keys).
const JWKS = createRemoteJWKSet(
  new URL(`${HEARTH_BASE_URL}/.well-known/jwks.json`),
);

// Protect every route under /dashboard.
export const config = { matcher: ["/dashboard/:path*"] };

export async function middleware(req: NextRequest) {
  const token = req.cookies.get("access_token")?.value;

  if (!token) {
    return NextResponse.redirect(new URL("/", req.url));
  }

  try {
    await jwtVerify(token, JWKS, { issuer: HEARTH_BASE_URL });
    return NextResponse.next();
  } catch {
    // Token missing, expired, or signature invalid — redirect to login.
    const response = NextResponse.redirect(new URL("/", req.url));
    response.cookies.delete("access_token");
    response.cookies.delete("refresh_token");
    return response;
  }
}
