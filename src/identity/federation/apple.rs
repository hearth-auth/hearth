//! `AppleConnector` — Sign In with Apple relying-party implementation.
//!
//! Apple Sign In diverges from generic OIDC in three ways that prevent
//! the `GenericOidcConnector` from covering it without custom code:
//!
//! 1. **`private_key_jwt` client auth** — instead of a static
//!    `client_secret`, each token-endpoint call presents a dynamically
//!    generated ES256 JWT signed with the operator's P-256 private key.
//!    Claims: `iss=team_id`, `sub=client_id`,
//!    `aud="https://appleid.apple.com"`, short `exp`.
//!
//! 2. **`response_mode=form_post`** — Apple HTTP POSTs the authorization
//!    response (code + state) to the redirect URI instead of encoding it
//!    as query parameters.  The web handler must accept POST at the
//!    callback route and extract `code`, `state`, and the optional `user`
//!    field from the form body.
//!
//! 3. **First-login-only name** — Apple includes the user's given name and
//!    family name in the `user` form field exactly once (first consent).
//!    The ID token never contains name claims.  The name must be read from
//!    `StateBag::apple_user_json`, which the web handler populates from the
//!    POST body before calling `FederationService::callback`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;

use crate::identity::federation::connector::{AuthorizeUrl, IdpConnector};
use crate::identity::federation::http::{FedHttpRequest, FederationHttpTransport};
use crate::identity::federation::oidc::{verify_rs256, Jwk, JwksDoc};
use crate::identity::federation::types::{
    AppleConfig, ExternalIdentity, IdpConfig, IdpKind, StateBag,
};
use crate::identity::IdentityError;

/// Apple Sign In connector.
pub struct AppleConnector {
    config: IdpConfig,
    /// Apple-specific config (team_id, key_id, private_key_pem).
    apple: AppleConfig,
    http: Arc<dyn FederationHttpTransport>,
    redirect_uri: String,
}

impl AppleConnector {
    /// Creates a new Apple connector from a persisted [`IdpConfig`].
    ///
    /// Returns an error when `config.apple` is absent — this indicates a
    /// misconfigured IdP record that should never reach production (the
    /// reconciler validates this at write time).
    pub fn new(
        config: IdpConfig,
        http: Arc<dyn FederationHttpTransport>,
        redirect_uri: String,
    ) -> Result<Self, IdentityError> {
        let apple = config
            .apple
            .clone()
            .ok_or_else(|| IdentityError::InvalidInput {
                reason: "Apple IdP connector requires apple.team_id / key_id / private_key_pem"
                    .to_string(),
            })?;
        Ok(Self {
            config,
            apple,
            http,
            redirect_uri,
        })
    }
}

impl IdpConnector for AppleConnector {
    fn kind(&self) -> IdpKind {
        IdpKind::Apple
    }

    fn display_name(&self) -> &str {
        &self.config.display_name
    }

    /// Builds the Apple Sign In authorization URL.
    ///
    /// Key differences from generic OIDC:
    /// - `response_mode=form_post` — required by Apple; instructs it to POST
    ///   the callback rather than redirecting with query params.
    /// - No `code_challenge` — Apple Sign In does not support PKCE.
    /// - `nonce` is included for replay protection (Apple echoes it in the
    ///   ID token).
    fn begin(&self, state: &StateBag) -> Result<AuthorizeUrl, IdentityError> {
        let scopes = self.config.scopes.join(" ");
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("response_mode", "form_post")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &scopes)
            .append_pair("state", &state.state_token)
            .append_pair("nonce", &state.nonce)
            .finish();
        let sep = if self.config.authorization_endpoint.contains('?') {
            "&"
        } else {
            "?"
        };
        Ok(AuthorizeUrl(format!(
            "{}{sep}{query}",
            self.config.authorization_endpoint
        )))
    }

    /// Exchanges an authorization code for an Apple identity.
    ///
    /// Generates a `client_secret` JWT (ES256 signed with the operator's
    /// P-256 key), exchanges the code at Apple's token endpoint, verifies
    /// the returned RS256 ID token, and extracts identity claims.
    ///
    /// First-login name is read from `state.apple_user_json` when present.
    fn exchange(&self, code: &str, state: &StateBag) -> Result<ExternalIdentity, IdentityError> {
        // 1. Generate the client_secret JWT (ES256, 5-minute expiry).
        let client_secret = build_client_secret_jwt(
            &self.apple.team_id,
            &self.apple.key_id,
            &self.config.client_id,
            self.apple.private_key_pem.expose_secret(),
        )?;

        // 2. POST the token endpoint.
        // Apple does not support PKCE, so code_verifier is omitted.
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("client_id", &self.config.client_id)
            .append_pair("client_secret", &client_secret)
            .finish();
        let token_resp = self.http.send(&FedHttpRequest {
            method: "POST",
            url: self.config.token_endpoint.clone(),
            headers: vec![("Accept".to_string(), "application/json".to_string())],
            body: body.into_bytes(),
            content_type: Some("application/x-www-form-urlencoded".to_string()),
        })?;
        if token_resp.status < 200 || token_resp.status >= 300 {
            return Err(IdentityError::FederationUpstreamError {
                provider: IdpKind::Apple.label().to_string(),
                reason: format!("token endpoint returned {}", token_resp.status),
            });
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: String,
        }
        let parsed: TokenResponse = serde_json::from_str(&token_resp.body).map_err(|e| {
            IdentityError::FederationUpstreamError {
                provider: IdpKind::Apple.label().to_string(),
                reason: format!("invalid token response: {e}"),
            }
        })?;

        // 3. Parse the JWT header to locate the signing key.
        let (header_b64, payload_b64, _) = split_jwt(&parsed.id_token)?;
        let header: JwtHeader = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(header_b64)
                .map_err(|_| IdentityError::FederationTokenVerificationFailed)?,
        )
        .map_err(|_| IdentityError::FederationTokenVerificationFailed)?;

        // Apple signs ID tokens with RS256 only.
        if header.alg != "RS256" {
            return Err(IdentityError::FederationTokenVerificationFailed);
        }

        // 4. Fetch JWKS and verify the signature.
        let jwks = fetch_apple_jwks(&self.config, &*self.http)?;
        let key = select_jwk(&jwks, header.kid.as_deref())
            .ok_or(IdentityError::FederationTokenVerificationFailed)?;
        verify_rs256(&parsed.id_token, key)
            .map_err(|_| IdentityError::FederationTokenVerificationFailed)?;

        // 5. Decode and validate claims.
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| IdentityError::FederationTokenVerificationFailed)?;
        let claims: AppleIdTokenClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|_| IdentityError::FederationTokenVerificationFailed)?;

        verify_apple_claims(&claims, &self.config, state, now_unix())?;

        // 6. Extract name from first-login user JSON (if present).
        let (first_name, last_name) = extract_name(state.apple_user_json.as_deref());

        let email = claims.email.clone().unwrap_or_default();
        // Apple always considers its own email addresses verified.  When the
        // claim is a string (`"true"` / `"false"`) we normalize it; absent
        // means the scope wasn't granted — treat as unverified.
        let email_verified = claims.email_verified_as_bool().unwrap_or(false);
        let display_name = build_display_name(first_name.as_deref(), last_name.as_deref(), &email);

        Ok(ExternalIdentity {
            idp_id: self.config.id.clone(),
            external_sub: claims.sub.clone(),
            email,
            email_verified,
            display_name,
            first_name: first_name.unwrap_or_default(),
            last_name: last_name.unwrap_or_default(),
            picture_url: None,
        })
    }
}

// ---------- JWT construction for client_secret ----------

/// Builds the ES256-signed client_secret JWT for Apple's token endpoint.
///
/// Called once per `exchange()`. The JWT carries a 5-minute window so
/// Apple's token endpoint will accept it even under moderate clock skew.
pub(crate) fn build_client_secret_jwt(
    team_id: &str,
    key_id: &str,
    client_id: &str,
    private_key_pem: &str,
) -> Result<String, IdentityError> {
    let der = pem_to_der(private_key_pem)?;
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &der,
        &rng,
    )
    .map_err(|_| IdentityError::FederationUpstreamError {
        provider: IdpKind::Apple.label().to_string(),
        reason: "failed to load Apple private key".to_string(),
    })?;

    let now = now_unix();
    let header = serde_json::json!({"alg": "ES256", "kid": key_id});
    let payload = serde_json::json!({
        "iss": team_id,
        "iat": now,
        "exp": now + 300,
        "aud": "https://appleid.apple.com",
        "sub": client_id,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&header)
            .map_err(|_| IdentityError::FederationUpstreamError {
                provider: IdpKind::Apple.label().to_string(),
                reason: "header serialization failed".to_string(),
            })?
            .as_bytes(),
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&payload)
            .map_err(|_| IdentityError::FederationUpstreamError {
                provider: IdpKind::Apple.label().to_string(),
                reason: "payload serialization failed".to_string(),
            })?
            .as_bytes(),
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = key_pair.sign(&rng, signing_input.as_bytes()).map_err(|_| {
        IdentityError::FederationUpstreamError {
            provider: IdpKind::Apple.label().to_string(),
            reason: "ES256 signing failed".to_string(),
        }
    })?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Decodes a PEM-wrapped PKCS#8 key block into raw DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, IdentityError> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    BASE64_STD
        .decode(b64.trim())
        .map_err(|_| IdentityError::FederationUpstreamError {
            provider: IdpKind::Apple.label().to_string(),
            reason: "invalid Apple private key PEM (expected PKCS#8 base64)".to_string(),
        })
}

// ---------- JWKS helpers ----------

/// Selects the signing key by `kid`. When no `kid` is given and there is
/// exactly one key, falls through — some Apple key rotations emit a
/// single-key JWKS without a `kid` during the transition window.
fn select_jwk<'a>(jwks: &'a JwksDoc, kid: Option<&str>) -> Option<&'a Jwk> {
    if let Some(k) = kid {
        jwks.keys.iter().find(|j| j.kid.as_deref() == Some(k))
    } else if jwks.keys.len() == 1 {
        jwks.keys.first()
    } else {
        None
    }
}

fn fetch_apple_jwks(
    cfg: &IdpConfig,
    http: &dyn FederationHttpTransport,
) -> Result<JwksDoc, IdentityError> {
    let url = cfg
        .jwks_uri
        .as_deref()
        .ok_or_else(|| IdentityError::FederationUpstreamError {
            provider: IdpKind::Apple.label().to_string(),
            reason: "Apple IdP config has no jwks_uri".to_string(),
        })?;
    let resp = http.send(&FedHttpRequest {
        method: "GET",
        url: url.to_string(),
        headers: vec![("Accept".to_string(), "application/json".to_string())],
        body: Vec::new(),
        content_type: None,
    })?;
    if resp.status < 200 || resp.status >= 300 {
        return Err(IdentityError::FederationUpstreamError {
            provider: IdpKind::Apple.label().to_string(),
            reason: format!("JWKS endpoint returned {}", resp.status),
        });
    }
    serde_json::from_str(&resp.body).map_err(|e| IdentityError::FederationUpstreamError {
        provider: IdpKind::Apple.label().to_string(),
        reason: format!("invalid JWKS document: {e}"),
    })
}

// ---------- Claims ----------

/// Apple-specific ID token claims.
///
/// Apple sends `email_verified` as either a JSON bool or the string
/// `"true"` / `"false"` depending on the SDK version and platform.
/// We use `Option<serde_json::Value>` and normalise in
/// `email_verified_as_bool()`.
#[derive(Debug, Deserialize)]
struct AppleIdTokenClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    aud: Option<serde_json::Value>,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(default)]
    #[allow(dead_code)]
    iat: Option<i64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
}

impl AppleIdTokenClaims {
    fn email_verified_as_bool(&self) -> Option<bool> {
        match &self.email_verified {
            Some(serde_json::Value::Bool(b)) => Some(*b),
            Some(serde_json::Value::String(s)) => Some(s == "true"),
            _ => None,
        }
    }
}

/// Validates Apple ID token claims: issuer, audience, expiry, nonce.
fn verify_apple_claims(
    claims: &AppleIdTokenClaims,
    cfg: &IdpConfig,
    state: &StateBag,
    now_unix_secs: i64,
) -> Result<(), IdentityError> {
    if claims.iss != cfg.issuer {
        return Err(IdentityError::FederationTokenVerificationFailed);
    }
    if !audience_contains(&claims.aud, &cfg.client_id) {
        return Err(IdentityError::FederationTokenVerificationFailed);
    }
    let leeway = i64::from(cfg.leeway_seconds);
    if claims.exp + leeway < now_unix_secs {
        return Err(IdentityError::FederationTokenVerificationFailed);
    }
    if let Some(nbf) = claims.nbf {
        if nbf > now_unix_secs + leeway {
            return Err(IdentityError::FederationTokenVerificationFailed);
        }
    }
    // Nonce replay protection — must match when present.
    match claims.nonce.as_deref() {
        Some(n) if n == state.nonce => {}
        _ => return Err(IdentityError::FederationTokenVerificationFailed),
    }
    Ok(())
}

fn audience_contains(aud: &Option<serde_json::Value>, client_id: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(s)) => s == client_id,
        Some(serde_json::Value::Array(xs)) => xs
            .iter()
            .any(|v| v.as_str().map(|s| s == client_id).unwrap_or(false)),
        _ => false,
    }
}

// ---------- Name extraction ----------

/// Extracts `(first_name, last_name)` from Apple's first-login `user` JSON.
///
/// Shape: `{"name":{"firstName":"Alice","lastName":"Smith"},"email":"..."}`
///
/// Returns `(None, None)` when the field is absent (all subsequent logins)
/// or when parsing fails.
fn extract_name(user_json: Option<&str>) -> (Option<String>, Option<String>) {
    let json = match user_json {
        Some(j) if !j.is_empty() => j,
        _ => return (None, None),
    };
    #[derive(Deserialize)]
    struct UserName {
        #[serde(rename = "firstName", default)]
        first: Option<String>,
        #[serde(rename = "lastName", default)]
        last: Option<String>,
    }
    #[derive(Deserialize)]
    struct UserJson {
        #[serde(default)]
        name: Option<UserName>,
    }
    let parsed: UserJson = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let name = match parsed.name {
        Some(n) => n,
        None => return (None, None),
    };
    let first = name.first.filter(|s| !s.is_empty());
    let last = name.last.filter(|s| !s.is_empty());
    (first, last)
}

/// Builds a display name from first/last name or email local-part.
fn build_display_name(first: Option<&str>, last: Option<&str>, email: &str) -> String {
    match (first, last) {
        (Some(f), Some(l)) => format!("{f} {l}"),
        (Some(f), None) => f.to_string(),
        (None, Some(l)) => l.to_string(),
        (None, None) => email
            .split_once('@')
            .map(|(local, _)| local.to_string())
            .unwrap_or_default(),
    }
}

// ---------- Helpers ----------

fn split_jwt(jwt: &str) -> Result<(&str, &str, &str), IdentityError> {
    let mut parts = jwt.splitn(3, '.');
    let header = parts
        .next()
        .ok_or(IdentityError::FederationTokenVerificationFailed)?;
    let payload = parts
        .next()
        .ok_or(IdentityError::FederationTokenVerificationFailed)?;
    let sig = parts
        .next()
        .ok_or(IdentityError::FederationTokenVerificationFailed)?;
    if parts.next().is_some() {
        return Err(IdentityError::FederationTokenVerificationFailed);
    }
    Ok((header, payload, sig))
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{IdpId, RealmId, Timestamp};
    use crate::identity::federation::http::StubFederationTransport;
    use crate::identity::federation::types::{AppleConfig, FederationSecret};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use uuid::Uuid;

    fn apple_config() -> IdpConfig {
        IdpConfig {
            id: IdpId::new(Uuid::nil()),
            realm_id: RealmId::new(Uuid::nil()),
            name: "apple".to_string(),
            kind: IdpKind::Apple,
            display_name: "Apple".to_string(),
            issuer: "https://appleid.apple.com".to_string(),
            authorization_endpoint: "https://appleid.apple.com/auth/authorize".to_string(),
            token_endpoint: "https://appleid.apple.com/auth/token".to_string(),
            userinfo_endpoint: None,
            jwks_uri: Some("https://appleid.apple.com/auth/keys".to_string()),
            scopes: vec!["name".to_string(), "email".to_string()],
            client_id: "com.example.app".to_string(),
            client_secret: FederationSecret::new(String::new()),
            claim_mappings: BTreeMap::new(),
            leeway_seconds: IdpConfig::default_leeway_seconds(),
            apple: Some(AppleConfig {
                team_id: "TEAM123456".to_string(),
                key_id: "KEY123456".to_string(),
                private_key_pem: FederationSecret::new(test_p256_pkcs8_pem()),
            }),
            created_at: Timestamp::from_micros(0),
            updated_at: Timestamp::from_micros(0),
        }
    }

    fn sample_state(nonce: &str) -> StateBag {
        StateBag {
            state_token: "st".to_string(),
            realm_id: RealmId::new(Uuid::nil()),
            idp_id: IdpId::new(Uuid::nil()),
            nonce: nonce.to_string(),
            pkce_verifier: "v".to_string(),
            return_to: "/ui/account".to_string(),
            expires_at: Timestamp::from_micros(0),
            apple_user_json: None,
        }
    }

    /// Generates a fresh P-256 PKCS#8 private key as PEM.
    ///
    /// Used only in tests — the key is ephemeral and has no real-world
    /// identity.
    fn test_p256_pkcs8_pem() -> String {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        let rng = SystemRandom::new();
        #[allow(clippy::unwrap_used)]
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let b64 = BASE64_STD.encode(doc.as_ref());
        format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
    }

    // ----- begin() URL construction -----

    #[test]
    fn begin_emits_form_post_response_mode() {
        let cfg = apple_config();
        let stub = Arc::new(StubFederationTransport::new());
        let conn =
            AppleConnector::new(cfg, stub, "https://hearth.local/cb".to_string()).expect("new");
        let state = sample_state("nonce-abc");
        let url = conn.begin(&state).expect("begin").0;

        assert!(url.starts_with("https://appleid.apple.com/auth/authorize?"));
        assert!(
            url.contains("response_mode=form_post"),
            "must set form_post"
        );
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=com.example.app"));
        assert!(url.contains("state=st"));
        assert!(url.contains("nonce=nonce-abc"));
        // PKCE must NOT be included — Apple doesn't support it.
        assert!(
            !url.contains("code_challenge"),
            "Apple does not support PKCE"
        );
    }

    #[test]
    fn begin_includes_name_email_scope() {
        let cfg = apple_config();
        let stub = Arc::new(StubFederationTransport::new());
        let conn = AppleConnector::new(cfg, stub, "https://h/cb".to_string()).expect("new");
        let state = sample_state("n");
        let url = conn.begin(&state).expect("begin").0;
        assert!(
            url.contains("scope=name+email") || url.contains("scope=name%20email"),
            "scope must include name and email"
        );
    }

    // ----- client_secret JWT construction -----

    #[test]
    fn client_secret_jwt_has_correct_header_and_claims() {
        let pem = test_p256_pkcs8_pem();
        let jwt = build_client_secret_jwt("TEAM123", "KID456", "com.example.app", &pem)
            .expect("build jwt");

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have three parts");

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("decode header"))
                .expect("parse header");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KID456");

        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("decode payload"))
                .expect("parse payload");
        assert_eq!(payload["iss"], "TEAM123");
        assert_eq!(payload["sub"], "com.example.app");
        assert_eq!(payload["aud"], "https://appleid.apple.com");
        let iat = payload["iat"].as_i64().expect("iat");
        let exp = payload["exp"].as_i64().expect("exp");
        assert!(exp > iat, "exp must be after iat");
        assert_eq!(exp - iat, 300, "expiry window must be 5 minutes");
    }

    #[test]
    fn client_secret_jwt_rejects_invalid_pem() {
        assert!(matches!(
            build_client_secret_jwt("T", "K", "c", "not-a-pem"),
            Err(IdentityError::FederationUpstreamError { .. })
        ));
    }

    // ----- Name extraction -----

    #[test]
    fn extract_name_parses_first_and_last() {
        let json = r#"{"name":{"firstName":"Alice","lastName":"Smith"},"email":"a@b.c"}"#;
        let (first, last) = extract_name(Some(json));
        assert_eq!(first.as_deref(), Some("Alice"));
        assert_eq!(last.as_deref(), Some("Smith"));
    }

    #[test]
    fn extract_name_handles_missing_last() {
        let json = r#"{"name":{"firstName":"Bob"}}"#;
        let (first, last) = extract_name(Some(json));
        assert_eq!(first.as_deref(), Some("Bob"));
        assert!(last.is_none());
    }

    #[test]
    fn extract_name_returns_none_for_absent() {
        let (first, last) = extract_name(None);
        assert!(first.is_none());
        assert!(last.is_none());
    }

    #[test]
    fn extract_name_returns_none_for_empty_string() {
        let (first, last) = extract_name(Some(""));
        assert!(first.is_none());
        assert!(last.is_none());
    }

    #[test]
    fn extract_name_returns_none_for_invalid_json() {
        let (first, last) = extract_name(Some("not json"));
        assert!(first.is_none());
        assert!(last.is_none());
    }

    // ----- Display name synthesis -----

    #[test]
    fn display_name_from_full_name() {
        assert_eq!(
            build_display_name(Some("Alice"), Some("Smith"), "a@b.c"),
            "Alice Smith"
        );
    }

    #[test]
    fn display_name_from_first_only() {
        assert_eq!(build_display_name(Some("Alice"), None, "a@b.c"), "Alice");
    }

    #[test]
    fn display_name_from_email_when_no_name() {
        assert_eq!(build_display_name(None, None, "alice@example.com"), "alice");
    }

    // ----- exchange() error paths (via stub) -----

    #[test]
    fn exchange_rejects_token_endpoint_5xx() {
        let cfg = apple_config();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub(
            "POST",
            "https://appleid.apple.com/auth/token".to_string(),
            500,
            "error",
        );
        let conn = AppleConnector::new(cfg, stub, "https://h/cb".to_string()).expect("new");
        assert!(matches!(
            conn.exchange("code", &sample_state("n")),
            Err(IdentityError::FederationUpstreamError { .. })
        ));
    }

    #[test]
    fn exchange_rejects_token_endpoint_garbage_body() {
        let cfg = apple_config();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub(
            "POST",
            "https://appleid.apple.com/auth/token".to_string(),
            200,
            "not json",
        );
        let conn = AppleConnector::new(cfg, stub, "https://h/cb".to_string()).expect("new");
        assert!(matches!(
            conn.exchange("code", &sample_state("n")),
            Err(IdentityError::FederationUpstreamError { .. })
        ));
    }

    #[test]
    fn exchange_rejects_non_rs256_id_token() {
        let cfg = apple_config();
        let stub = Arc::new(StubFederationTransport::new());
        let hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let pay = URL_SAFE_NO_PAD.encode(br#"{"iss":"x"}"#);
        let token_body = serde_json::json!({"id_token": format!("{hdr}.{pay}.sig")}).to_string();
        stub.stub(
            "POST",
            "https://appleid.apple.com/auth/token".to_string(),
            200,
            token_body,
        );
        let conn = AppleConnector::new(cfg, stub, "https://h/cb".to_string()).expect("new");
        assert!(matches!(
            conn.exchange("code", &sample_state("n")),
            Err(IdentityError::FederationTokenVerificationFailed)
        ));
    }

    #[test]
    fn exchange_rejects_malformed_jwt() {
        let cfg = apple_config();
        let stub = Arc::new(StubFederationTransport::new());
        let token_body = serde_json::json!({"id_token": "not.a.jwt.at.all"}).to_string();
        stub.stub(
            "POST",
            "https://appleid.apple.com/auth/token".to_string(),
            200,
            token_body,
        );
        let conn = AppleConnector::new(cfg, stub, "https://h/cb".to_string()).expect("new");
        // JWT with >3 parts is rejected during split.
        assert!(matches!(
            conn.exchange("code", &sample_state("n")),
            Err(IdentityError::FederationTokenVerificationFailed)
        ));
    }

    // ----- AppleConfig missing -----

    #[test]
    fn new_fails_when_apple_config_absent() {
        let mut cfg = apple_config();
        cfg.apple = None;
        let stub = Arc::new(StubFederationTransport::new());
        assert!(matches!(
            AppleConnector::new(cfg, stub, "https://h/cb".to_string()),
            Err(IdentityError::InvalidInput { .. })
        ));
    }

    // ----- pem_to_der -----

    #[test]
    fn pem_to_der_strips_headers() {
        let pem = test_p256_pkcs8_pem();
        let der = pem_to_der(&pem).expect("parse");
        // PKCS#8 for P-256 is at least 100 bytes.
        assert!(der.len() > 100, "DER must be non-trivial");
    }

    #[test]
    fn pem_to_der_rejects_garbage() {
        assert!(matches!(
            pem_to_der("garbage"),
            Err(IdentityError::FederationUpstreamError { .. })
        ));
    }

    // ----- Claims validation -----

    fn sample_apple_claims(nonce: &str, now: i64) -> AppleIdTokenClaims {
        AppleIdTokenClaims {
            iss: "https://appleid.apple.com".to_string(),
            sub: "000abc.def123".to_string(),
            aud: Some(serde_json::Value::String("com.example.app".to_string())),
            exp: now + 600,
            nbf: None,
            iat: Some(now),
            nonce: Some(nonce.to_string()),
            email: Some("alice@privaterelay.appleid.com".to_string()),
            email_verified: Some(serde_json::Value::Bool(true)),
        }
    }

    fn sample_apple_config_for_claims() -> IdpConfig {
        let mut cfg = apple_config();
        cfg.leeway_seconds = 60;
        cfg
    }

    #[test]
    fn apple_claims_valid() {
        let cfg = sample_apple_config_for_claims();
        let state = sample_state("nnn");
        let claims = sample_apple_claims("nnn", 1_700_000_000);
        verify_apple_claims(&claims, &cfg, &state, 1_700_000_000).expect("valid");
    }

    #[test]
    fn apple_claims_reject_wrong_issuer() {
        let cfg = sample_apple_config_for_claims();
        let state = sample_state("nnn");
        let mut claims = sample_apple_claims("nnn", 1_700_000_000);
        claims.iss = "https://evil.example".to_string();
        assert!(verify_apple_claims(&claims, &cfg, &state, 1_700_000_000).is_err());
    }

    #[test]
    fn apple_claims_reject_wrong_audience() {
        let cfg = sample_apple_config_for_claims();
        let state = sample_state("nnn");
        let mut claims = sample_apple_claims("nnn", 1_700_000_000);
        claims.aud = Some(serde_json::Value::String("other.app".to_string()));
        assert!(verify_apple_claims(&claims, &cfg, &state, 1_700_000_000).is_err());
    }

    #[test]
    fn apple_claims_reject_expired() {
        let cfg = sample_apple_config_for_claims();
        let state = sample_state("nnn");
        let mut claims = sample_apple_claims("nnn", 1_700_000_000);
        claims.exp = 1_700_000_000;
        // now = exp + 90 → outside 60s leeway
        assert!(verify_apple_claims(&claims, &cfg, &state, 1_700_000_090).is_err());
    }

    #[test]
    fn apple_claims_reject_nonce_mismatch() {
        let cfg = sample_apple_config_for_claims();
        let state = sample_state("expected");
        let claims = sample_apple_claims("different", 1_700_000_000);
        assert!(verify_apple_claims(&claims, &cfg, &state, 1_700_000_000).is_err());
    }

    #[test]
    fn apple_claims_reject_absent_nonce() {
        // Apple always echoes the nonce we send. Absence means the token
        // was tampered with or produced by a non-compliant provider — reject.
        let cfg = sample_apple_config_for_claims();
        let state = sample_state("expected");
        let mut claims = sample_apple_claims("expected", 1_700_000_000);
        claims.nonce = None;
        assert!(verify_apple_claims(&claims, &cfg, &state, 1_700_000_000).is_err());
    }

    #[test]
    fn email_verified_handles_string_true() {
        let claims = AppleIdTokenClaims {
            iss: "i".to_string(),
            sub: "s".to_string(),
            aud: None,
            exp: 0,
            nbf: None,
            iat: None,
            nonce: None,
            email: None,
            email_verified: Some(serde_json::Value::String("true".to_string())),
        };
        assert_eq!(claims.email_verified_as_bool(), Some(true));
    }

    #[test]
    fn email_verified_handles_string_false() {
        let claims = AppleIdTokenClaims {
            iss: "i".to_string(),
            sub: "s".to_string(),
            aud: None,
            exp: 0,
            nbf: None,
            iat: None,
            nonce: None,
            email: None,
            email_verified: Some(serde_json::Value::String("false".to_string())),
        };
        assert_eq!(claims.email_verified_as_bool(), Some(false));
    }
}
