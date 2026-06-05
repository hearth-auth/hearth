/** Minimal interface required by {@link startLogin} — satisfied by {@link HearthApiClient}. */
interface DiscoverySource {
  discovery(): Promise<Record<string, unknown>>;
}

/** Generate a cryptographically random RFC 7636 code verifier (256-bit / 32 bytes). */
export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

/** Derive the S256 code challenge from a verifier (RFC 7636 §4.2). */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return base64urlEncode(new Uint8Array(hash));
}

/** Options for {@link buildAuthorizationUrl}. */
export interface BuildAuthorizationUrlOptions {
  /** OIDC `authorization_endpoint` from the discovery document. */
  authorizationEndpoint: string;
  /** OAuth 2.0 client ID. */
  clientId: string;
  /** Redirect URI registered for this client. */
  redirectUri: string;
  /** Base64url-encoded S256 code challenge (from {@link generateCodeChallenge}). */
  codeChallenge: string;
  /** OAuth 2.0 scope string. Default: `"openid profile email"`. */
  scope?: string;
  /** CSRF state token. Auto-generated (16 random bytes) when absent. */
  state?: string;
}

/** Return value of {@link buildAuthorizationUrl}. */
export interface AuthorizationUrlResult {
  /** Full authorization redirect URL to navigate the browser to. */
  url: string;
  /** State value embedded in the URL — persist for CSRF validation in the callback. */
  state: string;
}

/** Build the full authorization redirect URL for an RFC 7636 PKCE flow. */
export function buildAuthorizationUrl(
  opts: BuildAuthorizationUrlOptions,
): AuthorizationUrlResult {
  const state = opts.state ?? generateState();
  const params = new URLSearchParams({
    response_type: "code",
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
    code_challenge: opts.codeChallenge,
    code_challenge_method: "S256",
    scope: opts.scope ?? "openid profile email",
    state,
  });
  return { url: `${opts.authorizationEndpoint}?${params.toString()}`, state };
}

/** Options for {@link startLogin}. */
export interface StartLoginOptions {
  /** OAuth 2.0 client ID. */
  clientId: string;
  /** Redirect URI registered for this client. */
  redirectUri: string;
  /** OAuth 2.0 scope string. Default: `"openid profile email"`. */
  scope?: string;
  /** CSRF state token. Auto-generated when absent. */
  state?: string;
}

/** Return value of {@link startLogin}. */
export interface StartLoginResult {
  /** Full authorization URL — redirect the browser here to begin login. */
  url: string;
  /** OAuth 2.0 state value — persist for CSRF validation in the callback. */
  state: string;
  /**
   * RFC 7636 code verifier — persist (e.g. `sessionStorage`) and pass as
   * `codeVerifier` to `handleCallback()` during the token exchange step.
   */
  codeVerifier: string;
}

/**
 * One-shot PKCE login initiation: discovers the authorization endpoint,
 * generates a code verifier/challenge, and builds the redirect URL.
 *
 * The caller MUST persist `codeVerifier` and `state` (e.g. in `sessionStorage`)
 * before navigating to `url`, and pass them to `handleCallback()` on return.
 */
export async function startLogin(
  client: DiscoverySource,
  opts: StartLoginOptions,
): Promise<StartLoginResult> {
  const doc = await client.discovery();
  const authorizationEndpoint = doc["authorization_endpoint"] as string | undefined;
  if (!authorizationEndpoint) {
    throw new Error(
      "startLogin: authorization_endpoint not found in OIDC discovery document",
    );
  }
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const { url, state } = buildAuthorizationUrl({
    authorizationEndpoint,
    clientId: opts.clientId,
    redirectUri: opts.redirectUri,
    codeChallenge,
    scope: opts.scope,
    state: opts.state,
  });
  return { url, state, codeVerifier };
}

function generateState(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

function base64urlEncode(input: Uint8Array): string {
  let binary = "";
  for (const byte of input) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
