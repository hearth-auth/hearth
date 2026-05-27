import { HearthClient, createHearth } from "@hearth/sdk";
import { createRemoteJWKSet, jwtVerify } from "jose";

const HEARTH_BASE_URL = process.env.HEARTH_BASE_URL!;
const HEARTH_REALM_ID = process.env.HEARTH_REALM_ID!;

export const CLIENT_ID = process.env.HEARTH_CLIENT_ID!;
export const REDIRECT_URI = process.env.HEARTH_REDIRECT_URI!;

// Low-level HTTP client: token exchange, admin ops, JWKS retrieval.
export const hearthClient = new HearthClient({
  baseUrl: HEARTH_BASE_URL,
  realmId: HEARTH_REALM_ID,
});

// JWKS set for server-side token verification.
// createRemoteJWKSet caches the keys and re-fetches on a key miss.
export const JWKS = createRemoteJWKSet(
  new URL(`${HEARTH_BASE_URL}/.well-known/jwks.json`),
);

export async function verifyAccessToken(token: string) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: HEARTH_BASE_URL,
  });
  return payload;
}

// Client-side RBAC facade — reads claims from the JWT in memory (zero network).
// Only available after import on the client; do not import server-only modules here.
export function makeHearthFacade(getToken: () => string | null | undefined) {
  return createHearth({
    baseUrl: HEARTH_BASE_URL,
    realmId: HEARTH_REALM_ID,
    getToken,
  });
}
