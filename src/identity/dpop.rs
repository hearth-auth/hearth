//! DPoP (Demonstrating Proof-of-Possession) validation — RFC 9449.
//!
//! Provides:
//! - JWK thumbprint computation (RFC 7638)
//! - DPoP proof JWT parsing and validation
//! - Stateless HMAC-SHA256 nonce generation with 5-minute sliding windows
//! - In-memory JTI replay cache

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;
use ring::{digest, hmac, signature};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::identity::error::IdentityError;

/// Maximum allowed clock skew when validating `iat` (seconds).
pub const DPOP_MAX_CLOCK_SKEW_SECS: i64 = 60;
/// Duration of each nonce window in seconds (5 minutes).
pub const DPOP_NONCE_WINDOW_SECS: i64 = 300;
/// Maximum acceptable `iat` age — older proofs are rejected.
pub const DPOP_MAX_AGE_SECS: i64 = 120;

// ===== JWK types =====

/// Minimal JWK representation used in DPoP proof headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPopJwk {
    /// Key type (`EC` or `OKP`).
    pub kty: String,
    /// Curve name (`P-256` for EC, `Ed25519` for OKP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// Base64url-encoded x coordinate / public key bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Base64url-encoded y coordinate (EC only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// RSA modulus (RSA only — used for rejection detection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent (RSA only — used for rejection detection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

/// DPoP proof JWT header fields.
#[derive(Debug, Deserialize)]
struct DPopHeader {
    /// Must be `"dpop+jwt"`.
    typ: String,
    /// Signing algorithm (`ES256` or `EdDSA`).
    alg: String,
    /// Client public key — MUST NOT contain private key material.
    jwk: DPopJwk,
    /// Private key parameter — must be absent.
    #[serde(rename = "d")]
    private_key_d: Option<serde_json::Value>,
}

/// DPoP proof JWT claims.
#[derive(Debug, Deserialize)]
struct DPopClaims {
    /// Unique JWT ID — used for replay prevention.
    jti: String,
    /// HTTP Method the proof covers.
    htm: String,
    /// HTTP URI the proof covers (without query/fragment).
    htu: String,
    /// Issued-at timestamp (Unix seconds).
    iat: i64,
    /// Server-issued nonce (optional but required when server requests one).
    #[serde(default)]
    nonce: Option<String>,
    /// Access token hash (`BASE64URL(SHA-256(ASCII(access_token)))`).
    /// Required on resource server requests (not token endpoint).
    #[serde(default)]
    #[allow(dead_code)]
    ath: Option<String>,
}

/// Result of successful DPoP proof validation.
#[derive(Debug, Clone)]
pub struct ValidatedDPopProof {
    /// JWK thumbprint of the client's public key.
    pub jkt: String,
    /// The unique `jti` — caller MUST record this in the JTI cache.
    pub jti: String,
    /// The `nonce` from the proof (if any).
    pub nonce: Option<String>,
}

// ===== JWK Thumbprint (RFC 7638) =====

/// Computes the JWK thumbprint: `BASE64URL(SHA-256(canonical-JWK-JSON))`.
///
/// Canonical form: lexicographically-ordered required members only, no
/// whitespace. Supported key types: EC P-256 (`crv`, `kty`, `x`, `y`) and
/// OKP Ed25519 (`crv`, `kty`, `x`).
pub fn compute_jwk_thumbprint(jwk: &DPopJwk) -> Result<String, IdentityError> {
    let canonical = match jwk.kty.as_str() {
        "EC" => {
            let crv = jwk
                .crv
                .as_deref()
                .ok_or_else(|| IdentityError::InvalidDPopProof {
                    reason: "EC JWK missing crv".to_string(),
                })?;
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| IdentityError::InvalidDPopProof {
                    reason: "EC JWK missing x".to_string(),
                })?;
            let y = jwk
                .y
                .as_deref()
                .ok_or_else(|| IdentityError::InvalidDPopProof {
                    reason: "EC JWK missing y".to_string(),
                })?;
            // RFC 7638 §3.2: members sorted lexicographically
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        "OKP" => {
            let crv = jwk
                .crv
                .as_deref()
                .ok_or_else(|| IdentityError::InvalidDPopProof {
                    reason: "OKP JWK missing crv".to_string(),
                })?;
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| IdentityError::InvalidDPopProof {
                    reason: "OKP JWK missing x".to_string(),
                })?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        other => {
            return Err(IdentityError::InvalidDPopProof {
                reason: format!("unsupported key type: {other}"),
            })
        }
    };

    let hash = digest::digest(&digest::SHA256, canonical.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref()))
}

// ===== Signature verification =====

fn verify_dpop_signature(
    header_b64: &str,
    payload_b64: &str,
    sig_b64: &str,
    jwk: &DPopJwk,
    alg: &str,
) -> Result<(), IdentityError> {
    let message = format!("{header_b64}.{payload_b64}");
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| IdentityError::InvalidDPopProof {
            reason: "invalid base64url in signature".to_string(),
        })?;

    match alg {
        "ES256" => {
            let x_bytes = decode_b64url_field(jwk.x.as_deref(), "x")?;
            let y_bytes = decode_b64url_field(jwk.y.as_deref(), "y")?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return Err(IdentityError::InvalidDPopProof {
                    reason: "P-256 x/y must be 32 bytes each".to_string(),
                });
            }
            // Uncompressed EC point: 0x04 || x || y
            let mut pub_key = Vec::with_capacity(65);
            pub_key.push(0x04);
            pub_key.extend_from_slice(&x_bytes);
            pub_key.extend_from_slice(&y_bytes);

            let key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &pub_key);
            key.verify(message.as_bytes(), &sig_bytes).map_err(|_| {
                IdentityError::InvalidDPopProof {
                    reason: "ES256 signature verification failed".to_string(),
                }
            })
        }
        "EdDSA" => {
            let x_bytes = decode_b64url_field(jwk.x.as_deref(), "x")?;
            if x_bytes.len() != 32 {
                return Err(IdentityError::InvalidDPopProof {
                    reason: "Ed25519 x must be 32 bytes".to_string(),
                });
            }
            let key = signature::UnparsedPublicKey::new(&signature::ED25519, &x_bytes);
            key.verify(message.as_bytes(), &sig_bytes).map_err(|_| {
                IdentityError::InvalidDPopProof {
                    reason: "EdDSA signature verification failed".to_string(),
                }
            })
        }
        other => Err(IdentityError::InvalidDPopProof {
            reason: format!("unsupported DPoP algorithm: {other}"),
        }),
    }
}

fn decode_b64url_field(value: Option<&str>, name: &str) -> Result<Vec<u8>, IdentityError> {
    let v = value.ok_or_else(|| IdentityError::InvalidDPopProof {
        reason: format!("JWK missing field: {name}"),
    })?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(v)
        .map_err(|_| IdentityError::InvalidDPopProof {
            reason: format!("invalid base64url in JWK field: {name}"),
        })
}

// ===== htu normalisation =====

/// Strips query string and fragment from a URI, returning just scheme://host/path.
pub fn normalize_htu(htu: &str) -> Result<String, IdentityError> {
    // Strip fragment first
    let without_fragment = htu.split('#').next().unwrap_or(htu);
    // Then strip query
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    Ok(without_query.to_string())
}

// ===== Main validation entry point =====

/// Validates a DPoP proof JWT.
///
/// Checks (in order):
/// 1. JWT structure (3 parts, valid base64url)
/// 2. Header: `typ == "dpop+jwt"`, supported `alg`, valid `jwk`, no private key
/// 3. Signature verifies against `jwk`
/// 4. Claims: `jti` non-empty, `htm` matches, `htu` matches (after normalisation)
/// 5. `iat` within clock skew + max age window
/// 6. `nonce` matches expected (if provided)
///
/// Returns `ValidatedDPopProof` on success. The caller is responsible for:
/// - Checking `jti` against the replay cache
/// - Recording the `jti` in the replay cache
#[allow(clippy::similar_names)] // expected_htm / expected_htu are RFC 9449 §4.3 names
pub fn validate_dpop_proof(
    proof_jwt: &str,
    expected_htm: &str,
    expected_htu: &str,
    now_secs: i64,
    expected_nonce: Option<&str>,
) -> Result<ValidatedDPopProof, IdentityError> {
    // 1. Split JWT
    let parts: Vec<&str> = proof_jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(IdentityError::InvalidDPopProof {
            reason: "proof JWT must have 3 parts".to_string(),
        });
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    // 2. Decode header
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| IdentityError::InvalidDPopProof {
            reason: "invalid base64url in header".to_string(),
        })?;
    let header: DPopHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| IdentityError::InvalidDPopProof {
            reason: format!("header parse error: {e}"),
        })?;

    if header.typ != "dpop+jwt" {
        return Err(IdentityError::InvalidDPopProof {
            reason: format!("typ must be dpop+jwt, got {}", header.typ),
        });
    }
    if header.private_key_d.is_some() {
        return Err(IdentityError::InvalidDPopProof {
            reason: "JWK in header must not contain private key material".to_string(),
        });
    }

    // 3. Verify signature
    verify_dpop_signature(header_b64, payload_b64, sig_b64, &header.jwk, &header.alg)?;

    // 4. Decode claims
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| IdentityError::InvalidDPopProof {
            reason: "invalid base64url in payload".to_string(),
        })?;
    let claims: DPopClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| IdentityError::InvalidDPopProof {
            reason: format!("payload parse error: {e}"),
        })?;

    if claims.jti.is_empty() {
        return Err(IdentityError::InvalidDPopProof {
            reason: "jti must be non-empty".to_string(),
        });
    }

    // htm check — case-insensitive per RFC 9110
    if !claims.htm.eq_ignore_ascii_case(expected_htm) {
        return Err(IdentityError::InvalidDPopProof {
            reason: format!("htm mismatch: expected {expected_htm}, got {}", claims.htm),
        });
    }

    // htu check — strip query/fragment before comparing
    let proof_htu = normalize_htu(&claims.htu)?;
    let server_htu = normalize_htu(expected_htu)?;
    if proof_htu != server_htu {
        return Err(IdentityError::InvalidDPopProof {
            reason: format!("htu mismatch: expected {server_htu}, got {proof_htu}"),
        });
    }

    // 5. iat check
    let age = now_secs.saturating_sub(claims.iat);
    if age > DPOP_MAX_AGE_SECS + DPOP_MAX_CLOCK_SKEW_SECS {
        return Err(IdentityError::InvalidDPopProof {
            reason: format!("proof iat too old: age={age}s"),
        });
    }
    if claims.iat > now_secs + DPOP_MAX_CLOCK_SKEW_SECS {
        return Err(IdentityError::InvalidDPopProof {
            reason: "proof iat is in the future".to_string(),
        });
    }

    // 6. Nonce check
    if let Some(expected) = expected_nonce {
        match claims.nonce.as_deref() {
            Some(n) if n == expected => {}
            _ => return Err(IdentityError::DPopNonceInvalid),
        }
    }

    // Compute thumbprint for the validated key
    let jkt = compute_jwk_thumbprint(&header.jwk)?;

    Ok(ValidatedDPopProof {
        jkt,
        jti: claims.jti,
        nonce: claims.nonce,
    })
}

// ===== Stateless HMAC nonce =====

/// Computes a DPoP nonce for the given 5-minute window ID.
///
/// `window_id = now_secs / DPOP_NONCE_WINDOW_SECS`
pub fn compute_dpop_nonce(secret: &[u8; 32], window_id: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, &window_id.to_le_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag.as_ref())
}

/// Returns the current DPoP nonce (for inclusion in `DPoP-Nonce` response header).
pub fn current_dpop_nonce(secret: &[u8; 32], now_secs: i64) -> String {
    compute_dpop_nonce(secret, now_secs / DPOP_NONCE_WINDOW_SECS)
}

/// Validates a nonce presented by the client.
///
/// Accepts the current window and the previous window (gives ~10 minutes of
/// grace for clock drift and window transitions).
pub fn is_valid_dpop_nonce(secret: &[u8; 32], nonce: &str, now_secs: i64) -> bool {
    let current_window = now_secs / DPOP_NONCE_WINDOW_SECS;
    let cur = compute_dpop_nonce(secret, current_window);
    let prev = compute_dpop_nonce(secret, current_window - 1);
    // Bitwise | (not ||) so both ct_eq calls always execute — no short-circuit timing oracle.
    // Residual: subtle's ct_eq returns early on length mismatch, but compute_dpop_nonce always
    // produces a fixed 43-byte base64url string (public via DPoP-Nonce header), so no secret
    // is disclosed by the length fast-path.
    (nonce.as_bytes().ct_eq(cur.as_bytes()) | nonce.as_bytes().ct_eq(prev.as_bytes())).into()
}

/// Computes the `ath` claim value: `BASE64URL(SHA-256(ASCII(access_token)))`.
pub fn compute_access_token_hash(access_token: &str) -> String {
    let hash = digest::digest(&digest::SHA256, access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref())
}

// ===== JTI replay cache =====

/// Thread-safe in-memory cache for DPoP proof JTI values.
///
/// Prevents replay of DPoP proof JWTs within a configurable time window.
/// Entries are lazily evicted when the cache is checked.
pub struct DPopJtiCache {
    /// Maps JTI → expiry timestamp (Unix seconds).
    inner: Mutex<HashMap<String, i64>>,
}

impl DPopJtiCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Checks whether `jti` is already in the cache (replay), then inserts it.
    ///
    /// Returns `Err(DPopProofReplay)` if the JTI was already present. On
    /// success, records the JTI with an expiry of `now_secs + ttl_secs`.
    pub fn check_and_insert(
        &self,
        jti: &str,
        now_secs: i64,
        ttl_secs: i64,
    ) -> Result<(), IdentityError> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Evict expired entries
        map.retain(|_, exp| *exp > now_secs);

        if map.contains_key(jti) {
            return Err(IdentityError::DPopProofReplay);
        }
        map.insert(jti.to_string(), now_secs + ttl_secs);
        Ok(())
    }
}

impl Default for DPopJtiCache {
    fn default() -> Self {
        Self::new()
    }
}

// ===== DPoP processor =====

/// Encapsulates DPoP state (replay cache + nonce secret) that belongs in the
/// identity layer rather than the HTTP protocol layer.
///
/// The protocol layer holds an `Arc<DPopProcessor>` and delegates all DPoP
/// enforcement through this type — keeping the HTTP adapter thin and stateless.
pub struct DPopProcessor {
    jti_cache: DPopJtiCache,
    nonce_secret: [u8; 32],
}

impl DPopProcessor {
    /// Creates a new processor with the given HMAC nonce secret.
    #[must_use]
    pub fn new(nonce_secret: [u8; 32]) -> Self {
        Self {
            jti_cache: DPopJtiCache::new(),
            nonce_secret,
        }
    }

    /// Returns the current DPoP nonce for inclusion in the `DPoP-Nonce` response header.
    #[must_use]
    pub fn current_nonce(&self, now_secs: i64) -> String {
        current_dpop_nonce(&self.nonce_secret, now_secs)
    }

    /// Returns `true` if the client-supplied nonce matches the current or previous window.
    #[must_use]
    pub fn is_valid_nonce(&self, nonce: &str, now_secs: i64) -> bool {
        is_valid_dpop_nonce(&self.nonce_secret, nonce, now_secs)
    }

    /// Records `jti` in the replay cache. Returns `Err(DPopProofReplay)` on replay.
    pub fn check_and_insert_jti(&self, jti: &str, now_secs: i64) -> Result<(), IdentityError> {
        self.jti_cache
            .check_and_insert(jti, now_secs, DPOP_MAX_AGE_SECS)
    }
}

// ===== Unit tests =====

#[cfg(test)]
mod tests {
    use super::*;

    /// EC P-256 key thumbprint — coordinates from RFC 7517 Appendix A.2, canonical
    /// JSON computed per RFC 7638 §3.2.
    #[test]
    fn ec_thumbprint_matches_rfc7638_vector() {
        let jwk = DPopJwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string()),
            y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string()),
            n: None,
            e: None,
        };
        // SHA-256({"crv":"P-256","kty":"EC","x":"f83…","y":"x_F…"}) base64url-nopad
        let expected = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U";
        assert_eq!(compute_jwk_thumbprint(&jwk).expect("thumbprint"), expected);
    }

    #[test]
    fn jti_cache_rejects_replay() {
        let cache = DPopJtiCache::new();
        assert!(cache.check_and_insert("jti-1", 1000, 120).is_ok());
        assert!(matches!(
            cache.check_and_insert("jti-1", 1001, 120),
            Err(IdentityError::DPopProofReplay)
        ));
    }

    #[test]
    fn jti_cache_allows_different_jtis() {
        let cache = DPopJtiCache::new();
        assert!(cache.check_and_insert("jti-a", 1000, 120).is_ok());
        assert!(cache.check_and_insert("jti-b", 1000, 120).is_ok());
    }

    #[test]
    fn jti_cache_evicts_expired() {
        let cache = DPopJtiCache::new();
        // Insert with 1s TTL
        assert!(cache.check_and_insert("jti-old", 1000, 1).is_ok());
        // At t=1002, the entry has expired (exp=1001 < 1002)
        assert!(cache.check_and_insert("jti-old", 1002, 120).is_ok());
    }

    #[test]
    fn nonce_current_and_previous_accepted() {
        let secret = [42u8; 32];
        let now = 1_000 * DPOP_NONCE_WINDOW_SECS + 1; // mid-window
        let current = current_dpop_nonce(&secret, now);
        let prev = compute_dpop_nonce(&secret, now / DPOP_NONCE_WINDOW_SECS - 1);
        assert!(is_valid_dpop_nonce(&secret, &current, now));
        assert!(is_valid_dpop_nonce(&secret, &prev, now));
    }

    #[test]
    fn nonce_two_windows_ago_rejected() {
        let secret = [7u8; 32];
        let now = 2000 * DPOP_NONCE_WINDOW_SECS;
        let old = compute_dpop_nonce(&secret, now / DPOP_NONCE_WINDOW_SECS - 2);
        assert!(!is_valid_dpop_nonce(&secret, &old, now));
    }

    #[test]
    fn nonce_tampered_rejected() {
        // Ensure a single-character mutation of a valid nonce is rejected.
        // This exercises the constant-time rejection path.
        let secret = [99u8; 32];
        let now = 500 * DPOP_NONCE_WINDOW_SECS + 42;
        let mut tampered = current_dpop_nonce(&secret, now).into_bytes();
        tampered[0] ^= 0x01;
        let tampered_str = String::from_utf8(tampered).expect("utf8");
        assert!(!is_valid_dpop_nonce(&secret, &tampered_str, now));
    }

    #[test]
    fn normalize_htu_strips_query_and_fragment() {
        assert_eq!(
            normalize_htu("https://server.example.com/token?foo=1#bar").expect("normalize"),
            "https://server.example.com/token"
        );
        assert_eq!(
            normalize_htu("https://server.example.com/token").expect("normalize"),
            "https://server.example.com/token"
        );
    }

    #[test]
    fn unsupported_key_type_rejected() {
        let jwk = DPopJwk {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: Some("abc".to_string()),
            e: Some("AQAB".to_string()),
        };
        assert!(matches!(
            compute_jwk_thumbprint(&jwk),
            Err(IdentityError::InvalidDPopProof { .. })
        ));
    }
}
