// PKCE helpers using native Web Crypto API — no third-party dependencies.
// RFC 7636 §4.1–4.2.
//
// Why PKCE? Public clients (SPAs, mobile apps) cannot keep a client secret.
// PKCE replaces the secret with a per-flow, one-time proof: the authorization
// request carries only the SHA-256 *hash* of a random verifier; the token
// endpoint receives the verifier itself. An attacker who intercepts the
// authorization code in the redirect cannot exchange it — they don't have the
// verifier that was generated in the browser and never left it.
//
// Why native Web Crypto? Avoids third-party crypto dependencies entirely,
// removing supply-chain attack surface. SubtleCrypto is a browser standard with
// audited, hardware-accelerated implementations.

function base64UrlEncode(bytes: Uint8Array): string {
  // btoa works on binary strings; spread avoids stack overflow on large arrays.
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // RFC 4648 §5: replace standard base64 chars that are unsafe in URLs/params.
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Generate a 32-byte (256-bit) cryptographically random code verifier.
 *
 * RFC 7636 §4.1 requires at least 32 octets of entropy. 256 bits makes
 * brute-force search computationally infeasible for the lifetime of any token.
 * The verifier is kept in JS memory only — never written to localStorage or
 * sessionStorage, so it is destroyed when the tab closes.
 */
export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  // crypto.getRandomValues uses the OS CSPRNG — not Math.random().
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/**
 * Derive an S256 code challenge from a verifier (SHA-256 → base64url).
 *
 * Only the challenge is sent in the authorization redirect URL. The verifier
 * itself travels only over the back-channel token exchange (TLS-protected POST),
 * so it is never exposed in browser history, server logs, or referrer headers.
 *
 * S256 is mandatory here: Hearth rejects authorization requests that omit a
 * code_challenge, and rejects token requests that don't match via S256.
 * The `plain` method (challenge == verifier) is intentionally unsupported — it
 * provides no protection against an attacker who can read the authorization URL.
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoded = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return base64UrlEncode(new Uint8Array(digest));
}
