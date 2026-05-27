import { NextResponse } from "next/server";

export async function GET() {
  const response = NextResponse.redirect(
    new URL("/", process.env.HEARTH_REDIRECT_URI!.replace("/api/auth/callback", "")),
  );
  response.cookies.delete("access_token");
  response.cookies.delete("refresh_token");
  return response;
}
