/** §PKCE — RFC 7636 S256 code verifier and challenge generation. */

import { createHash, randomBytes } from "node:crypto";

/** A PKCE code verifier and its derived SHA-256 challenge (RFC 7636). */
export interface PkcePair {
  /**
   * Random high-entropy verifier (43 Base64url chars, 32-byte CSPRNG source, no padding).
   * Send as `code_verifier` at the token exchange step. Keep secret until then.
   */
  verifier: string;
  /**
   * `BASE64URL(SHA256(verifier))` — send as `code_challenge` in the authorization request.
   */
  challenge: string;
  /**
   * Always `"S256"` — Hearth mandates S256 and rejects the `"plain"` method.
   * Send as `code_challenge_method` in the authorization request.
   */
  method: "S256";
}

/**
 * Generate a cryptographically random PKCE pair using the S256 method (RFC 7636).
 *
 * Usage:
 * 1. `const pkce = generatePkce()`
 * 2. Start auth request: include `pkce.challenge` and `pkce.method` as
 *    `code_challenge` and `code_challenge_method` in the authorization URL.
 * 3. Exchange code: pass `pkce.verifier` as `codeVerifier` to `exchangeCode()`.
 */
export function generatePkce(): PkcePair {
  // 32 random bytes → 43 Base64url chars (no padding), satisfying RFC 7636 §4.1 minimum.
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge, method: "S256" };
}
