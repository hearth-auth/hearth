//! PKCE generation utilities (RFC 7636).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// A PKCE code verifier and its corresponding SHA-256 challenge (RFC 7636).
///
/// Pass `verifier` as `code_verifier` at token exchange, and `challenge` as
/// `code_challenge` (with `method = "S256"`) in the authorization request.
pub struct PkcePair {
    /// Random verifier string (43 Base64url characters, 256 bits of entropy).
    pub verifier: String,
    /// `BASE64URL(SHA256(verifier))` — send as `code_challenge` in authorize request.
    pub challenge: String,
    /// Always `"S256"` — Hearth requires SHA-256 challenges.
    pub method: &'static str,
}

/// Generate a fresh PKCE pair using a cryptographically random 32-byte verifier.
///
/// # Example
/// ```rust,ignore
/// let pkce = hearth_sdk::pkce::generate_pkce_pair();
/// // Pass to authorize:
/// client.authorize(client_id, redirect_uri, scope, state, None,
///                  Some(&pkce.challenge), Some(pkce.method)).await?;
/// // Pass to exchange_code:
/// client.exchange_code(code, client_id, secret, redirect_uri, Some(&pkce.verifier)).await?;
/// ```
pub fn generate_pkce_pair() -> PkcePair {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

    PkcePair {
        verifier,
        challenge,
        method: "S256",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_sha256_of_verifier() {
        let pair = generate_pkce_pair();
        let mut hasher = Sha256::new();
        hasher.update(pair.verifier.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(
            pair.challenge, expected,
            "challenge must be BASE64URL(SHA256(verifier))"
        );
    }

    #[test]
    fn pkce_method_is_s256() {
        let pair = generate_pkce_pair();
        assert_eq!(pair.method, "S256");
    }

    #[test]
    fn pkce_verifier_length_and_charset() {
        let pair = generate_pkce_pair();
        // 32 bytes base64url-no-pad = ceil(32 * 4/3) = 43 chars
        assert_eq!(pair.verifier.len(), 43, "verifier should be 43 chars");
        assert!(
            pair.verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "verifier must be URL-safe base64 (no padding)"
        );
    }

    #[test]
    fn pkce_pairs_are_unique() {
        let p1 = generate_pkce_pair();
        let p2 = generate_pkce_pair();
        assert_ne!(p1.verifier, p2.verifier, "each call should produce unique verifier");
        assert_ne!(p1.challenge, p2.challenge, "each call should produce unique challenge");
    }

    #[test]
    fn pkce_challenge_length() {
        let pair = generate_pkce_pair();
        // SHA-256 = 32 bytes → 43 Base64url chars
        assert_eq!(pair.challenge.len(), 43, "challenge should be 43 chars");
    }
}
