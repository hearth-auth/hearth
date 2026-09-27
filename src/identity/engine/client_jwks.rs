//! Verifying a JWS a client signed with a key from its registered JWKS.
//!
//! Two inputs are signed by the client with the keys it registered as `jwks`:
//! request objects (JAR, RFC 9101) and `private_key_jwt` client assertions
//! (RFC 7523 §2.2). Both select the key the same way and verify the signature
//! with the same code; they differ only in which algorithms they accept.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::identity::federation::oidc as fed_oidc;

/// Algorithms a request object may be signed with.
pub(super) const JAR_ALGS: &[&str] = &["EdDSA", "RS256", "PS256", "ES256"];

/// Algorithms a `private_key_jwt` assertion verified against the client's
/// JWKS may be signed with: the FAPI 2.0 Security Profile set (§5.4 — PS256,
/// ES256, EdDSA). RS256 (PKCS#1 v1.5) is not accepted for client
/// authentication.
pub(super) const CLIENT_ASSERTION_ALGS: &[&str] = &["PS256", "ES256", "EdDSA"];

/// Verifies the signature of the compact JWS `header.payload.signature`
/// (already split into `parts`) with the key `kid` selects from `jwks_json`.
///
/// `alg` is the JWS header's algorithm; it must be one of `allowed`. The key
/// is the one whose `kid` equals the header's, or the only key when the header
/// has no `kid`. A key whose own `alg` names a different algorithm is refused.
///
/// # Errors
///
/// A human-readable reason, free of key material, for every refusal.
pub(super) fn verify_with_client_jwks(
    parts: [&str; 3],
    alg: &str,
    kid: Option<&str>,
    jwks_json: &str,
    allowed: &[&str],
) -> Result<(), String> {
    if !allowed.contains(&alg) {
        return Err(format!(
            "unsupported algorithm '{alg}'; supported: {}",
            allowed.join(", ")
        ));
    }

    #[derive(serde::Deserialize)]
    struct JwksContainer {
        keys: Vec<fed_oidc::Jwk>,
    }
    let jwks: JwksContainer =
        serde_json::from_str(jwks_json).map_err(|_| "client jwks is not valid JSON".to_string())?;

    let selected = if let Some(k) = kid {
        jwks.keys.iter().find(|j| j.kid.as_deref() == Some(k))
    } else if jwks.keys.len() == 1 {
        jwks.keys.first()
    } else {
        None
    }
    .ok_or_else(|| "no matching key found in client jwks".to_string())?;
    if selected
        .alg
        .as_deref()
        .is_some_and(|key_alg| key_alg != alg)
    {
        return Err("the selected jwk is registered for a different algorithm".to_string());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| "invalid signature encoding".to_string())?;
    let b64 = |field: Option<&str>, what: &str| -> Result<Vec<u8>, String> {
        let value = field.ok_or_else(|| format!("{alg} JWK missing '{what}' parameter"))?;
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| format!("{alg} JWK '{what}' is not valid base64url"))
    };

    match alg {
        "EdDSA" => {
            if selected.crv.as_deref() != Some("Ed25519") {
                return Err("EdDSA JWK must have crv=Ed25519".to_string());
            }
            let pk_bytes = b64(selected.x.as_deref(), "x")?;
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk_bytes)
                .verify(signing_input.as_bytes(), &sig_bytes)
                .map_err(|_| "EdDSA signature verification failed".to_string())
        }
        "RS256" => fed_oidc::verify_rs256(&format!("{signing_input}.{}", parts[2]), selected)
            .map_err(|_| "RS256 signature verification failed".to_string()),
        "PS256" => {
            if selected.kty != "RSA" {
                return Err("PS256 requires an RSA key (kty=RSA)".to_string());
            }
            let n = b64(selected.n.as_deref(), "n")?;
            let e = b64(selected.e.as_deref(), "e")?;
            ring::signature::RsaPublicKeyComponents {
                n: n.as_slice(),
                e: e.as_slice(),
            }
            .verify(
                &ring::signature::RSA_PSS_2048_8192_SHA256,
                signing_input.as_bytes(),
                &sig_bytes,
            )
            .map_err(|_| "PS256 signature verification failed".to_string())
        }
        "ES256" => {
            if selected.kty != "EC" {
                return Err("ES256 requires an EC key (kty=EC)".to_string());
            }
            if selected.crv.as_deref() != Some("P-256") {
                return Err("ES256 JWK must have crv=P-256".to_string());
            }
            let x = b64(selected.x.as_deref(), "x")?;
            let y = b64(selected.y.as_deref(), "y")?;
            // ring expects the uncompressed point: 0x04 || x || y.
            let mut pk_bytes = Vec::with_capacity(1 + x.len() + y.len());
            pk_bytes.push(0x04);
            pk_bytes.extend_from_slice(&x);
            pk_bytes.extend_from_slice(&y);
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_FIXED,
                &pk_bytes,
            )
            .verify(signing_input.as_bytes(), &sig_bytes)
            .map_err(|_| "ES256 signature verification failed".to_string())
        }
        _ => Err(format!("unsupported signing algorithm '{alg}'")),
    }
}
