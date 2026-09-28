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

/// Most keys a client JWKS may hold.
pub(crate) const MAX_CLIENT_JWKS_KEYS: usize = 8;
/// Largest client JWKS accepted, in bytes of JSON.
pub(crate) const MAX_CLIENT_JWKS_BYTES: usize = 16 * 1024;

/// JWK members that carry private or symmetric key material (RFC 7518
/// §6.2.2, §6.3.2, §6.4). A client registers PUBLIC keys only.
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Validates a client's inline JWKS — at registration, on update, in
/// `hearth config validate`, and before every signature verification (so a
/// JWKS stored before these rules fails closed too).
///
/// A client JWKS holds PUBLIC SIGNING keys only:
///
/// - at most [`MAX_CLIENT_JWKS_BYTES`] of JSON and [`MAX_CLIENT_JWKS_KEYS`]
///   keys, at least one;
/// - no private or symmetric material ([`PRIVATE_JWK_MEMBERS`]; `kty: oct`);
/// - `use`, when present, is `sig`; `key_ops`, when present, includes
///   `verify` — an encryption-only key is refused;
/// - `kty` and `crv` agree with what can verify a supported algorithm:
///   `OKP`/`Ed25519` (EdDSA), `EC`/`P-256` (ES256), `RSA` with `n` and `e`
///   (RS256 for request objects, PS256); a key's `alg`, when present, is one
///   its `kty` supports;
/// - `kid`s are unique, and present on every key when there is more than one
///   (a key without one could never be selected).
///
/// # Errors
///
/// A human-readable reason, free of key material.
pub(crate) fn validate_client_jwks(jwks_json: &str) -> Result<(), String> {
    use serde_json::Value;
    if jwks_json.len() > MAX_CLIENT_JWKS_BYTES {
        return Err(format!("jwks exceeds {MAX_CLIENT_JWKS_BYTES} bytes"));
    }
    let value: Value =
        serde_json::from_str(jwks_json).map_err(|_| "jwks is not valid JSON".to_string())?;
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "jwks must be an object with a \"keys\" array".to_string())?;
    if keys.is_empty() {
        return Err("jwks holds no keys".to_string());
    }
    if keys.len() > MAX_CLIENT_JWKS_KEYS {
        return Err(format!("jwks holds more than {MAX_CLIENT_JWKS_KEYS} keys"));
    }
    let mut kids = std::collections::HashSet::new();
    for key in keys {
        let jwk = key
            .as_object()
            .ok_or_else(|| "every jwk must be a JSON object".to_string())?;
        if PRIVATE_JWK_MEMBERS.iter().any(|m| jwk.contains_key(*m)) {
            return Err(
                "jwks must hold public keys only; private or symmetric key material \
                 (d, p, q, dp, dq, qi, oth, k) is refused"
                    .to_string(),
            );
        }
        check_public_signing_jwk(jwk)?;
        match jwk.get("kid") {
            Some(Value::String(kid)) => {
                if !kids.insert(kid.as_str()) {
                    return Err("jwks holds more than one key with the same kid".to_string());
                }
            }
            Some(_) => return Err("a jwk kid must be a string".to_string()),
            None if keys.len() > 1 => {
                return Err("every key needs a kid when the jwks holds more than one".to_string());
            }
            None => {}
        }
    }
    Ok(())
}

/// One key of [`validate_client_jwks`]: a public key usable for signatures.
fn check_public_signing_jwk(
    jwk: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    use serde_json::Value;
    let text = |name: &str| jwk.get(name).and_then(Value::as_str);
    if let Some(key_use) = jwk.get("use") {
        if key_use.as_str() != Some("sig") {
            return Err("a jwk's use must be \"sig\"; encryption keys are refused".to_string());
        }
    }
    if let Some(ops) = jwk.get("key_ops") {
        let verifies = ops
            .as_array()
            .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify")));
        if !verifies {
            return Err("a jwk's key_ops must include \"verify\"".to_string());
        }
    }
    let has = |name: &str| text(name).is_some_and(|v| !v.is_empty());
    let algs: &[&str] = match text("kty") {
        Some("OKP") if text("crv") == Some("Ed25519") && has("x") => &["EdDSA"],
        Some("EC") if text("crv") == Some("P-256") && has("x") && has("y") => &["ES256"],
        Some("RSA") if has("n") && has("e") => &["RS256", "PS256"],
        Some("OKP" | "EC" | "RSA") => {
            return Err(
                "a jwk must be OKP/Ed25519 with x, EC/P-256 with x and y, or RSA with n and e"
                    .to_string(),
            );
        }
        _ => return Err("a jwk's kty must be OKP, EC or RSA".to_string()),
    };
    match jwk.get("alg") {
        None => Ok(()),
        Some(Value::String(alg)) if algs.contains(&alg.as_str()) => Ok(()),
        Some(_) => Err(format!(
            "a jwk's alg does not match its kty (expected one of {})",
            algs.join(", ")
        )),
    }
}

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

    // The stored set must satisfy the registration rules too: a JWKS stored
    // before they existed (private material, an encryption key, a
    // duplicated kid) fails closed here rather than being partly trusted.
    validate_client_jwks(jwks_json)?;

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
            if selected.kty != "OKP" || selected.crv.as_deref() != Some("Ed25519") {
                return Err("EdDSA JWK must have kty=OKP and crv=Ed25519".to_string());
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

#[cfg(test)]
mod tests {
    //! Registration-time JWKS validation and the verify-time key rules
    //! (FAPI review L-FAPI-2): a client JWKS holds public signing keys only,
    //! each consistent in `kty`/`crv`/`alg`, with unique `kid`s, bounded in
    //! size; the verifier refuses an encryption-only key, an EdDSA key that is
    //! not `kty: OKP`, and an ambiguous `kid`.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn ed_key() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn ed_jwk(key: &Ed25519KeyPair, kid: &str) -> serde_json::Value {
        serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
        })
    }

    fn jwks(keys: &[serde_json::Value]) -> String {
        serde_json::json!({ "keys": keys }).to_string()
    }

    /// A compact EdDSA JWS over a fixed payload, split into its parts.
    fn signed(key: &Ed25519KeyPair, kid: &str) -> (String, String, String) {
        let h = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#));
        let p = URL_SAFE_NO_PAD.encode(r#"{"iss":"x"}"#);
        let s = URL_SAFE_NO_PAD.encode(key.sign(format!("{h}.{p}").as_bytes()).as_ref());
        (h, p, s)
    }

    fn verify(key: &Ed25519KeyPair, kid: &str, jwks_json: &str) -> Result<(), String> {
        let (h, p, s) = signed(key, kid);
        verify_with_client_jwks(
            [h.as_str(), p.as_str(), s.as_str()],
            "EdDSA",
            Some(kid),
            jwks_json,
            CLIENT_ASSERTION_ALGS,
        )
    }

    #[test]
    fn a_public_signing_jwks_is_accepted() {
        let k = ed_key();
        validate_client_jwks(&jwks(&[ed_jwk(&k, "a")])).unwrap();
        let rsa =
            serde_json::json!({"kty": "RSA", "kid": "r", "alg": "PS256", "n": "AQAB", "e": "AQAB"});
        let ec = serde_json::json!({"kty": "EC", "crv": "P-256", "kid": "e", "alg": "ES256",
            "x": "AA", "y": "AA", "key_ops": ["verify"]});
        validate_client_jwks(&jwks(&[ed_jwk(&k, "a"), rsa, ec])).unwrap();
    }

    #[test]
    fn private_key_material_is_refused() {
        let k = ed_key();
        for member in ["d", "p", "q", "dp", "dq", "qi", "k"] {
            let mut jwk = ed_jwk(&k, "a");
            jwk[member] = serde_json::json!("AAAA");
            let err = validate_client_jwks(&jwks(&[jwk])).unwrap_err();
            assert!(err.contains("private"), "{member}: {err}");
        }
        let oct = serde_json::json!({"kty": "oct", "kid": "s", "k": "c2VjcmV0"});
        assert!(
            validate_client_jwks(&jwks(&[oct])).is_err(),
            "symmetric keys"
        );
    }

    #[test]
    fn encryption_keys_and_inconsistent_keys_are_refused() {
        let k = ed_key();
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("use=enc", {
                let mut j = ed_jwk(&k, "a");
                j["use"] = serde_json::json!("enc");
                j
            }),
            ("key_ops without verify", {
                let mut j = ed_jwk(&k, "a");
                j["key_ops"] = serde_json::json!(["encrypt", "wrapKey"]);
                j
            }),
            ("EdDSA on kty EC", {
                let mut j = ed_jwk(&k, "a");
                j["kty"] = serde_json::json!("EC");
                j
            }),
            ("OKP with crv X25519", {
                let mut j = ed_jwk(&k, "a");
                j["crv"] = serde_json::json!("X25519");
                j
            }),
            (
                "ES256 on an RSA key",
                serde_json::json!({"kty": "RSA", "kid": "r", "alg": "ES256", "n": "AQAB", "e": "AQAB"}),
            ),
            (
                "EC P-384",
                serde_json::json!({"kty": "EC", "crv": "P-384", "kid": "e", "x": "AA", "y": "AA"}),
            ),
            (
                "unknown alg",
                serde_json::json!({"kty": "RSA", "kid": "r", "alg": "HS256", "n": "AQAB", "e": "AQAB"}),
            ),
            (
                "RSA without n",
                serde_json::json!({"kty": "RSA", "kid": "r", "e": "AQAB"}),
            ),
        ];
        for (what, jwk) in cases {
            assert!(
                validate_client_jwks(&jwks(&[jwk])).is_err(),
                "{what} must be refused"
            );
        }
    }

    #[test]
    fn duplicate_or_missing_kids_and_oversized_sets_are_refused() {
        let (a, b) = (ed_key(), ed_key());
        assert!(
            validate_client_jwks(&jwks(&[ed_jwk(&a, "same"), ed_jwk(&b, "same")])).is_err(),
            "duplicate kid"
        );
        let mut no_kid = ed_jwk(&b, "x");
        no_kid.as_object_mut().unwrap().remove("kid");
        assert!(
            validate_client_jwks(&jwks(&[ed_jwk(&a, "a"), no_kid])).is_err(),
            "a key without kid among several can never be selected"
        );
        let many: Vec<_> = (0..=MAX_CLIENT_JWKS_KEYS)
            .map(|i| ed_jwk(&a, &format!("k{i}")))
            .collect();
        assert!(validate_client_jwks(&jwks(&many)).is_err(), "too many keys");
        let mut big = ed_jwk(&a, "a");
        big["x5c"] = serde_json::json!(["A".repeat(MAX_CLIENT_JWKS_BYTES)]);
        assert!(
            validate_client_jwks(&jwks(&[big])).is_err(),
            "too many bytes"
        );
        assert!(validate_client_jwks(&jwks(&[])).is_err(), "no keys");
        assert!(validate_client_jwks("not json").is_err(), "not JSON");
        assert!(validate_client_jwks("[1,2]").is_err(), "not an object");
    }

    #[test]
    fn the_verifier_refuses_enc_keys_non_okp_eddsa_keys_and_ambiguous_kids() {
        let k = ed_key();
        verify(&k, "a", &jwks(&[ed_jwk(&k, "a")])).expect("control: a valid key verifies");

        let mut enc = ed_jwk(&k, "a");
        enc["use"] = serde_json::json!("enc");
        assert!(verify(&k, "a", &jwks(&[enc])).is_err(), "use=enc");

        let mut ops = ed_jwk(&k, "a");
        ops["key_ops"] = serde_json::json!(["encrypt"]);
        assert!(
            verify(&k, "a", &jwks(&[ops])).is_err(),
            "key_ops without verify"
        );

        let mut not_okp = ed_jwk(&k, "a");
        not_okp["kty"] = serde_json::json!("EC");
        assert!(
            verify(&k, "a", &jwks(&[not_okp])).is_err(),
            "EdDSA on kty EC"
        );

        // Two keys under one kid: the right key second. `find` used to pick
        // the first; an ambiguous kid is now refused outright.
        let other = ed_key();
        let dup = jwks(&[ed_jwk(&other, "a"), ed_jwk(&k, "a")]);
        let err = verify(&k, "a", &dup).unwrap_err();
        assert!(err.contains("kid"), "{err}");

        let mut private = ed_jwk(&k, "a");
        private["d"] = serde_json::json!("AAAA");
        assert!(
            verify(&k, "a", &jwks(&[private])).is_err(),
            "private material"
        );
    }
}
