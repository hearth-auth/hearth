export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number; // Unix timestamp ms
  scope?: string;
}

export interface OIDCDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  introspection_endpoint?: string;
}

export function isExpired(tokens: TokenSet, bufferMs = 60_000): boolean {
  return Date.now() >= tokens.expiresAt - bufferMs;
}

export function parseJwtPayload(jwt: string): Record<string, unknown> {
  const [, payload] = jwt.split(".");
  if (!payload) throw new Error("Invalid JWT");
  const padded = payload.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(padded));
}
