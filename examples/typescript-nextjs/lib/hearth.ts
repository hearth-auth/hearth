import { HearthApiClient, createHearth } from "@hearth-auth/sdk";
import { createRemoteJWKSet, jwtVerify } from "jose";

export const CLIENT_ID = process.env.HEARTH_CLIENT_ID!;
export const REDIRECT_URI = process.env.HEARTH_REDIRECT_URI!;

// Lazy singletons: defer construction until first request so that
// `npm run build` succeeds when env vars are absent from the build env.
let _client: HearthApiClient | undefined;
let _jwks: ReturnType<typeof createRemoteJWKSet> | undefined;

export function getHearthClient(): HearthApiClient {
  if (!_client) {
    _client = new HearthApiClient({
      baseUrl: process.env.HEARTH_BASE_URL!,
      realmId: process.env.HEARTH_REALM_ID!,
    });
  }
  return _client;
}

function getJwks() {
  if (!_jwks) {
    _jwks = createRemoteJWKSet(
      new URL(`${process.env.HEARTH_BASE_URL!}/.well-known/jwks.json`),
    );
  }
  return _jwks;
}

export async function verifyAccessToken(token: string) {
  const { payload } = await jwtVerify(token, getJwks(), {
    issuer: process.env.HEARTH_BASE_URL!,
  });
  return payload;
}

// Client-side RBAC facade — verifies the in-memory JWT against the realm JWKS
// (fetched once, then cached), then reads its claims. The checks are async.
// Only available after import on the client; do not import server-only modules here.
export function makeHearthFacade(getToken: () => string | null | undefined) {
  return createHearth({
    baseUrl: process.env.HEARTH_BASE_URL!,
    realmId: process.env.HEARTH_REALM_ID!,
    issuerUrl: process.env.HEARTH_BASE_URL!,
    getToken,
  });
}
