//! Required-Action session token.
//!
//! A short-lived Ed25519-signed JWT (`typ = "ra+JWT"`) that binds interceptor
//! state across required-action completion pages.  Transported as an HttpOnly
//! SameSite=Strict cookie scoped to `/required-action`.
//!
//! TTL: 15 minutes (900 seconds).  Stateless — no storage record needed.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature;
use serde::{Deserialize, Serialize};

use crate::core::Timestamp;
use crate::identity::error::IdentityError;
use crate::identity::tokens::SigningKey;
use crate::identity::types::RequiredAction;

/// Cookie name for the RA session token.
pub const RA_SESSION_COOKIE: &str = "hearth_ra_session";

/// RA token TTL in seconds (15 minutes).
pub const RA_TOKEN_TTL_SECS: i64 = 900;

const MICROS_PER_SEC: i64 = 1_000_000;
const JWT_ALGORITHM: &str = "EdDSA";

/// `typ` header value for RA tokens — prevents cross-context acceptance
/// by any validator that checks the `typ` claim (RFC 8725 §3.11).
const RA_TOKEN_TYPE: &str = "ra+JWT";

/// OIDC authorization parameters captured at the interception point.
///
/// Preserved in the RA token so the original authorization flow can be
/// resumed once all required actions are complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcParams {
    /// OAuth 2.0 client identifier.
    pub client_id: String,
    /// Redirect URI the authorization code will be delivered to.
    pub redirect_uri: String,
    /// Space-delimited requested scopes.
    pub scope: String,
    /// PKCE code challenge (base64url SHA-256 of verifier).
    pub code_challenge: String,
    /// PKCE challenge method — `"S256"` for all PKCE-mandatory flows.
    pub code_challenge_method: String,
    /// OIDC nonce, echoed unmodified into the eventual ID token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// OAuth 2.0 state parameter for CSRF protection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Response type (e.g., `"code"`).
    pub response_type: String,
    /// JARM response mode wire string (`query.jwt`, `fragment.jwt`, `jwt`).
    ///
    /// `None` means default `query` mode. Preserved so that, after all
    /// required actions complete, the authorization code redirect uses the
    /// originally-requested mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    /// Whether the originating request went through PAR (RFC 9126).
    ///
    /// Preserved here so that `resume_oidc_flow` can pass `via_par = true`
    /// to `issue_authorization_code` — FAPI Baseline/Advanced realms reject
    /// code issuance when this flag is `false`.
    #[serde(default)]
    pub via_par: bool,
}

/// Claims embedded in a Required-Action session JWT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaClaims {
    /// Subject — the authenticated user's ID string.
    pub sub: String,
    /// Realm ID that scopes this token.
    pub realm: String,
    /// Ordered list of remaining required actions.
    pub pending_actions: Vec<RequiredAction>,
    /// Preserved OIDC authorization parameters for OIDC flow resumption.
    ///
    /// `Some` for the OIDC login path; `None` for the direct browser login
    /// path (which resumes by creating a session cookie instead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_params: Option<OidcParams>,
    /// Return-to URL for browser-login-path flow resumption.
    ///
    /// `Some` for the direct browser login path; `None` for OIDC.
    /// After all required actions complete, the handler creates a session
    /// and redirects to this path (or `/ui` when `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_return_to: Option<String>,
    /// Issued-at time (Unix seconds).
    pub iat: i64,
    /// Expiry time (Unix seconds).
    pub exp: i64,
}

/// Errors that can occur when validating an RA session token.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RaTokenError {
    /// The token's `exp` claim is in the past.
    #[error("RA session token has expired")]
    Expired,
    /// Ed25519 signature verification failed.
    #[error("RA session token signature is invalid")]
    InvalidSignature,
    /// The token is structurally malformed (bad base64, bad JSON, wrong alg/typ).
    #[error("RA session token claims are malformed")]
    MalformedClaims,
    /// The `sub` claim does not match the expected user ID.
    #[error("RA session token subject does not match the expected user")]
    UserMismatch,
}

/// Minimal JWT header used when decoding incoming tokens.
#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

/// Generates a signed RA session JWT for the OIDC login path.
///
/// The token is valid for [`RA_TOKEN_TTL_SECS`] seconds from `now`.
pub fn generate(
    user_id: &str,
    realm_id: &str,
    pending_actions: Vec<RequiredAction>,
    oidc_params: OidcParams,
    signing_key: &SigningKey,
    now: Timestamp,
) -> Result<String, IdentityError> {
    let iat = now.as_micros() / MICROS_PER_SEC;
    let exp = iat + RA_TOKEN_TTL_SECS;

    let claims = RaClaims {
        sub: user_id.to_string(),
        realm: realm_id.to_string(),
        pending_actions,
        oidc_params: Some(oidc_params),
        browser_return_to: None,
        iat,
        exp,
    };

    signing_key.sign_jwt(&claims, RA_TOKEN_TYPE)
}

/// Generates a signed RA session JWT for the direct browser login path.
///
/// After all required actions complete, the flow resumes by creating a
/// session cookie and redirecting to `return_to` (or `/ui` when `None`).
pub fn generate_browser(
    user_id: &str,
    realm_id: &str,
    pending_actions: Vec<RequiredAction>,
    return_to: Option<String>,
    signing_key: &SigningKey,
    now: Timestamp,
) -> Result<String, IdentityError> {
    let iat = now.as_micros() / MICROS_PER_SEC;
    let exp = iat + RA_TOKEN_TTL_SECS;

    let claims = RaClaims {
        sub: user_id.to_string(),
        realm: realm_id.to_string(),
        pending_actions,
        oidc_params: None,
        browser_return_to: return_to,
        iat,
        exp,
    };

    signing_key.sign_jwt(&claims, RA_TOKEN_TYPE)
}

/// Validates an RA session JWT and returns the decoded claims.
///
/// Checks Ed25519 signature, `alg`/`typ` headers, and expiry.
/// Does NOT check that `sub` matches any specific user — use
/// [`validate_for_user`] when the caller knows the expected subject.
pub fn validate(
    token: &str,
    public_key_bytes: &[u8],
    now: Timestamp,
) -> Result<RaClaims, RaTokenError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(RaTokenError::MalformedClaims);
    }

    // Decode and validate the header.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| RaTokenError::MalformedClaims)?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| RaTokenError::MalformedClaims)?;

    if header.alg != JWT_ALGORITHM || header.typ != RA_TOKEN_TYPE {
        return Err(RaTokenError::MalformedClaims);
    }

    // Verify Ed25519 signature before decoding claims.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| RaTokenError::MalformedClaims)?;

    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
    public_key
        .verify(signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| RaTokenError::InvalidSignature)?;

    // Decode claims only after signature is verified.
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| RaTokenError::MalformedClaims)?;
    let claims: RaClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| RaTokenError::MalformedClaims)?;

    // Check expiry.
    let now_secs = now.as_micros() / MICROS_PER_SEC;
    if now_secs >= claims.exp {
        return Err(RaTokenError::Expired);
    }

    Ok(claims)
}

/// Validates an RA session JWT and additionally asserts the subject matches.
///
/// Returns [`RaTokenError::UserMismatch`] when `claims.sub != expected_user_id`.
pub fn validate_for_user(
    token: &str,
    public_key_bytes: &[u8],
    now: Timestamp,
    expected_user_id: &str,
) -> Result<RaClaims, RaTokenError> {
    let claims = validate(token, public_key_bytes, now)?;
    if claims.sub != expected_user_id {
        return Err(RaTokenError::UserMismatch);
    }
    Ok(claims)
}

/// Extracts the `realm` field from an RA token's payload WITHOUT verifying the
/// signature.  Only use this to bootstrap the realm key lookup before calling
/// [`validate`] — the signature is always checked immediately after.
#[must_use]
pub fn extract_realm_unchecked(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&claims_bytes).ok()?;
    v.get("realm")?.as_str().map(str::to_string)
}

/// Builds the `Set-Cookie` header value for the RA session cookie.
///
/// Attributes: `HttpOnly; Path=/required-action; SameSite=Strict; Max-Age=900`.
/// `Secure` is appended when TLS is active.
#[must_use]
pub fn ra_session_cookie(value: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{RA_SESSION_COOKIE}={value}; HttpOnly; Path=/required-action; \
         SameSite=Strict; Max-Age={RA_TOKEN_TTL_SECS}{secure_attr}"
    )
}

/// Builds the `Set-Cookie` header value that expires the RA session cookie.
#[must_use]
pub fn clear_ra_session_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{RA_SESSION_COOKIE}=; HttpOnly; Path=/required-action; \
         SameSite=Strict; Max-Age=0{secure_attr}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::tokens::SigningKey;

    fn test_oidc_params() -> OidcParams {
        OidcParams {
            client_id: "test-client".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            code_challenge: "abc123".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: Some("nonce-xyz".to_string()),
            state: Some("state-abc".to_string()),
            response_type: "code".to_string(),
            response_mode: None,
            via_par: false,
        }
    }

    fn test_now() -> Timestamp {
        // Fixed point in time so tests are deterministic.
        Timestamp::from_micros(1_700_000_000 * MICROS_PER_SEC)
    }

    // ── AC-4: round-trip sign / verify ──────────────────────────────────────

    #[test]
    fn round_trip_sign_and_verify() {
        let key = SigningKey::generate().expect("key generation");
        let now = test_now();

        let token = generate(
            "user_abc",
            "realm_xyz",
            vec![RequiredAction::VerifyEmail, RequiredAction::UpdatePassword],
            test_oidc_params(),
            &key,
            now,
        )
        .expect("generate");

        let claims = validate(&token, key.public_key_bytes(), now).expect("validate");

        assert_eq!(claims.sub, "user_abc");
        assert_eq!(claims.realm, "realm_xyz");
        assert_eq!(
            claims.pending_actions,
            vec![RequiredAction::VerifyEmail, RequiredAction::UpdatePassword]
        );
        assert_eq!(claims.oidc_params, Some(test_oidc_params()));
        assert_eq!(claims.exp, claims.iat + RA_TOKEN_TTL_SECS);
    }

    // ── AC-4: expiry rejection ───────────────────────────────────────────────

    #[test]
    fn expired_token_is_rejected() {
        let key = SigningKey::generate().expect("key generation");
        let issue_time = test_now();

        let token = generate(
            "user_abc",
            "realm_xyz",
            vec![RequiredAction::VerifyEmail],
            test_oidc_params(),
            &key,
            issue_time,
        )
        .expect("generate");

        // Advance time past the TTL.
        let later = Timestamp::from_micros(
            issue_time.as_micros() + (RA_TOKEN_TTL_SECS + 1) * MICROS_PER_SEC,
        );

        let err = validate(&token, key.public_key_bytes(), later).expect_err("should be expired");
        assert_eq!(err, RaTokenError::Expired);
    }

    // ── AC-4: wrong key rejection ────────────────────────────────────────────

    #[test]
    fn token_signed_with_wrong_key_is_rejected() {
        let signing_key = SigningKey::generate().expect("signing key");
        let other_key = SigningKey::generate().expect("other key");
        let now = test_now();

        let token = generate(
            "user_abc",
            "realm_xyz",
            vec![RequiredAction::VerifyEmail],
            test_oidc_params(),
            &signing_key,
            now,
        )
        .expect("generate");

        let err = validate(&token, other_key.public_key_bytes(), now)
            .expect_err("should reject wrong key");
        assert_eq!(err, RaTokenError::InvalidSignature);
    }

    // ── AC-4: userId mismatch ────────────────────────────────────────────────

    #[test]
    fn user_id_mismatch_is_rejected() {
        let key = SigningKey::generate().expect("key generation");
        let now = test_now();

        let token = generate(
            "user_alice",
            "realm_xyz",
            vec![RequiredAction::VerifyEmail],
            test_oidc_params(),
            &key,
            now,
        )
        .expect("generate");

        let err = validate_for_user(&token, key.public_key_bytes(), now, "user_bob")
            .expect_err("should reject mismatched user");
        assert_eq!(err, RaTokenError::UserMismatch);
    }

    // ── correct user passes the mismatch guard ───────────────────────────────

    #[test]
    fn validate_for_user_passes_when_subject_matches() {
        let key = SigningKey::generate().expect("key generation");
        let now = test_now();

        let token = generate(
            "user_alice",
            "realm_xyz",
            vec![],
            test_oidc_params(),
            &key,
            now,
        )
        .expect("generate");

        let claims = validate_for_user(&token, key.public_key_bytes(), now, "user_alice")
            .expect("validate_for_user");
        assert_eq!(claims.sub, "user_alice");
    }

    // ── cookie helpers ───────────────────────────────────────────────────────

    #[test]
    fn ra_session_cookie_format_with_secure() {
        let cookie = ra_session_cookie("tok123", true);
        assert!(cookie.starts_with("hearth_ra_session=tok123;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Path=/required-action"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Max-Age=900"));
        assert!(cookie.contains("Secure"));
    }

    #[test]
    fn ra_session_cookie_format_without_secure() {
        let cookie = ra_session_cookie("tok123", false);
        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn clear_ra_session_cookie_sets_max_age_zero() {
        let cookie = clear_ra_session_cookie(true);
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("hearth_ra_session=;"));
        assert!(cookie.contains("Secure"));
    }

    // ── malformed token rejected ─────────────────────────────────────────────

    #[test]
    fn malformed_token_is_rejected() {
        let key = SigningKey::generate().expect("key generation");
        let now = test_now();

        let err =
            validate("not.a.valid.jwt.at.all", key.public_key_bytes(), now).expect_err("malformed");
        assert_eq!(err, RaTokenError::MalformedClaims);
    }
}
