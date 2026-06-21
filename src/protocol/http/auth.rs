//! Shared authentication and helper utilities used across HTTP handlers.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::core::{ClientId, RealmId, UserId};
use crate::protocol::admin_auth::{
    ExportRateLimitOutcome, RateLimitOutcome, TokenRateLimitOutcome,
};
use crate::rbac::RbacError;
use base64::Engine as _;

use super::state::AppState;

/// Returns the current Unix timestamp in microseconds.
///
/// Used for rate-limiter calls throughout the HTTP layer. Extracted into a
/// helper so the `#[allow(cast_possible_truncation)]` suppression is in one
/// place.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

/// Authenticated admin context extracted from request headers.
///
/// Contains the realm and user that passed both token validation
/// and the `hearth.admin` permission check. `permissions` carries the full
/// permission set from the token claims so callers can check capability-level
/// gates (e.g. `hearth.export`) without re-validating the token.
#[derive(Debug, Clone)]
pub struct AdminAuth {
    pub(crate) realm_id: RealmId,
    pub(crate) user_id: UserId,
    /// Full permission set from the validated token claims.
    pub(crate) permissions: Vec<String>,
}

/// Extracts and validates admin authentication from request headers.
///
/// 1. Extracts `Authorization: Bearer <token>` and `X-Realm-ID`
/// 2. Validates the token via `identity.validate_token()`
/// 3. Checks `hearth.admin` appears in the token's `permissions` claim
/// 4. Checks rate limit (100 req/min per admin user)
pub(crate) fn extract_admin_auth(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<AdminAuth, (StatusCode, Json<serde_json::Value>)> {
    let realm_id = extract_realm_id(headers)?;

    // Extract bearer token
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "missing authorization header"})),
            )
        })?
        .to_str()
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid authorization header"})),
            )
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid authorization scheme"})),
        )
    })?;

    // Validate token
    let claims = state
        .identity
        .validate_token(&realm_id, token)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid token"})),
            )
        })?;

    // sub is "user_{uuid}" — strip prefix to get raw UUID
    let uuid_str = claims.sub.strip_prefix("user_").unwrap_or(&claims.sub);
    let user_uuid: uuid::Uuid = uuid_str.parse().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid token"})),
        )
    })?;
    let user_id = UserId::new(user_uuid);

    // Check admin role via the token's `permissions` claim (§ 5.2).
    // Accepts hearth.admin (full superuser) or any granular sub-permission
    // (hearth.users.admin, hearth.clients.admin, hearth.realm.admin). Sub-admins
    // pass this outer gate but are still checked per-handler via
    // require_admin_permission(). hearth.admin bypasses all per-handler checks.
    let is_admin = claims.permissions.iter().any(|p| {
        matches!(
            p.as_str(),
            "hearth.admin" | "hearth.users.admin" | "hearth.clients.admin" | "hearth.realm.admin"
        )
    });
    if !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        ));
    }

    // Rate limiting
    check_admin_rate_limit(state, &user_id)?;

    Ok(AdminAuth {
        realm_id,
        user_id,
        permissions: claims.permissions,
    })
}

/// Extracts and validates admin authentication for cluster-level operations.
///
/// Identical to [`extract_admin_auth`] but additionally asserts that the
/// `X-Realm-ID` header identifies the **system realm** (nil UUID). Cluster
/// operations are node-wide, not realm-scoped; accepting a tenant-realm token
/// would allow a tenant admin to transfer Raft leadership or bootstrap the
/// cluster — a privilege-escalation vector (HEA-763).
///
/// Returns `403 Forbidden` with `"cluster admin requires system realm"` if the
/// realm is non-nil, even when the bearer token is otherwise valid.
///
/// **Future note:** if `extract_admin_auth` is ever changed to support
/// non-realm-scoped tokens (e.g. a static allowlist), this function still
/// provides the correct boundary for cluster endpoints.
pub(crate) fn extract_cluster_admin_auth(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<AdminAuth, (StatusCode, Json<serde_json::Value>)> {
    let auth = extract_admin_auth(headers, state)?;
    if !auth.realm_id.as_uuid().is_nil() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "cluster admin requires system realm"})),
        ));
    }
    Ok(auth)
}

/// Checks the admin API rate limit for a user.
///
/// Returns 429 if the user has exceeded 100 requests in the current
/// 1-minute window.
fn check_admin_rate_limit(
    state: &AppState,
    user_id: &UserId,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    #[allow(clippy::cast_possible_truncation)]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;

    match state.admin_rate_limiter.check(user_id, now) {
        RateLimitOutcome::Allowed => Ok(()),
        RateLimitOutcome::Exceeded => Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "rate limit exceeded"})),
        )),
    }
}

/// Checks that the authenticated admin token carries the `hearth.export`
/// permission required for backup/export endpoints (A-30).
///
/// Returns `403 Forbidden` when the permission is absent. The check is separate
/// from the normal `hearth.admin` gate so operators can grant export access to
/// dedicated service accounts without granting full admin privileges.
pub(crate) fn check_export_capability(
    auth: &AdminAuth,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let has_export = auth.permissions.iter().any(|p| p == "hearth.export");
    if !has_export {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "error_description": "hearth.export permission required for export operations"
            })),
        ));
    }
    Ok(())
}

/// Checks that the caller holds either `hearth.admin` (full superuser) or the
/// specific granular sub-permission `required`. Call this in handlers that
/// belong to a sub-admin domain (users, clients, realm management) immediately
/// after [`extract_admin_auth`].
///
/// Returns `403 Forbidden` when neither permission is present. `hearth.admin`
/// always grants access regardless of `required`.
pub(crate) fn require_admin_permission(
    auth: &AdminAuth,
    required: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let permitted = auth
        .permissions
        .iter()
        .any(|p| p == "hearth.admin" || p == required);
    if !permitted {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "error_description": format!("{required} or hearth.admin permission required")
            })),
        ));
    }
    Ok(())
}

/// Checks the per-user export rate limit (A-30).
///
/// Returns `429 Too Many Requests` when the user has exceeded the export quota
/// in the current hour. The limit is intentionally low (10/hour by default)
/// to limit the blast radius of a compromised admin token.
pub(crate) fn check_export_rate_limit(
    state: &AppState,
    user_id: &UserId,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    #[allow(clippy::cast_possible_truncation)]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;

    match state.export_rate_limiter.check(user_id, now) {
        ExportRateLimitOutcome::Allowed => Ok(()),
        ExportRateLimitOutcome::Exceeded => Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "export_rate_limit_exceeded",
                "error_description": "export rate limit exceeded; maximum exports per hour reached"
            })),
        )),
    }
}

/// Emits a `RealmExportWatermarked` audit event for every export operation (A-30).
///
/// Called at the START of export operations regardless of the outcome so the
/// watermark exists even when the export is later rate-limited or rejected.
pub(crate) fn emit_export_watermark(
    state: &AppState,
    realm_id: &RealmId,
    user_id: &UserId,
    export_type: &str,
    realm_slug: Option<&str>,
    export_id: &str,
) {
    let mut metadata = serde_json::json!({
        "export_id": export_id,
        "export_type": export_type,
    });
    if let Some(slug) = realm_slug {
        metadata["realm_slug"] = serde_json::Value::String(slug.to_string());
    }
    let _ = state.audit.append(&crate::audit::CreateAuditEvent {
        realm_id: realm_id.clone(),
        actor: user_id.as_uuid().to_string(),
        action: crate::audit::AuditAction::RealmExportWatermarked,
        resource_type: "export".to_string(),
        resource_id: export_id.to_string(),
        metadata: Some(metadata),
    });
}

/// Verifies a detached Ed25519 signature on a backup manifest (A-30).
///
/// `public_key_bytes` must be the 32-byte raw Ed25519 public key.
/// `manifest` must carry a `detached_signature_b64` field; the signature
/// is verified against `manifest.canonical_bytes()`.
///
/// Returns `Err` with a 400 body when:
/// - the signature field is absent
/// - the signature is not valid base64url
/// - the Ed25519 verification fails
pub(crate) fn verify_manifest_signature(
    manifest: &crate::backup::BackupManifest,
    public_key_bytes: &[u8; 32],
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    use ring::signature::{UnparsedPublicKey, ED25519};

    let sig_b64 = manifest.detached_signature_b64.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "missing_manifest_signature",
                "error_description": "restore archive must carry a detached_signature_b64 when backup_verify_key is configured"
            })),
        )
    })?;

    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_manifest_signature",
                    "error_description": "detached_signature_b64 is not valid base64url"
                })),
            )
        })?;

    let canonical = manifest.canonical_bytes().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to serialize manifest for signature verification"})),
        )
    })?;

    let pk = UnparsedPublicKey::new(&ED25519, public_key_bytes.as_slice());
    pk.verify(&canonical, &sig_bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_manifest_signature",
                "error_description": "manifest signature verification failed; archive may be tampered or signed with the wrong key"
            })),
        )
    })
}

/// Checks the per-`(realm, client)` token endpoint rate limit.
///
/// Returns `Ok(())` when the request is allowed; `Err(Response)` with
/// `429 Too Many Requests` and a `Retry-After` header when exceeded.
pub(crate) fn check_token_rate_limit(
    state: &AppState,
    realm_id: &RealmId,
    client_id: &ClientId,
) -> Result<(), Response> {
    #[allow(clippy::cast_possible_truncation)]
    let now_micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;

    match state
        .token_rate_limiter
        .check(realm_id, client_id, now_micros)
    {
        TokenRateLimitOutcome::Allowed => Ok(()),
        TokenRateLimitOutcome::Exceeded { retry_after_secs } => {
            let retry_str = retry_after_secs.to_string();
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", retry_str.as_str())],
                Json(serde_json::json!({
                    "error": "too_many_requests",
                    "error_description": "rate limit exceeded"
                })),
            )
                .into_response())
        }
    }
}

/// Builds a 429 Too Many Requests response with a `Retry-After` header.
///
/// Used for per-IP login rate limits on the token and magic-link endpoints.
pub(crate) fn make_ip_rate_limit_response(retry_after_secs: u32) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(
            axum::http::header::RETRY_AFTER,
            retry_after_secs.to_string(),
        )],
        Json(serde_json::json!({
            "error": "too_many_requests",
            "error_description": "rate limit exceeded"
        })),
    )
        .into_response()
}

/// Builds the HTTP router with all configured routes.
/// Extracts a `RealmId` from the `X-Realm-ID` header.
///
/// Returns a `(StatusCode, Json)` error if the header is missing or invalid.
pub(crate) fn extract_realm_id(
    headers: &HeaderMap,
) -> Result<RealmId, (StatusCode, Json<serde_json::Value>)> {
    let header_value = headers
        .get("x-realm-id")
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing X-Realm-ID header"})),
            )
        })?
        .to_str()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid X-Realm-ID header"})),
            )
        })?;

    let uuid: uuid::Uuid = header_value.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "X-Realm-ID must be a valid UUID"})),
        )
    })?;

    Ok(RealmId::new(uuid))
}
/// Maps an `IdentityError` to an HTTP status code and safe error message.
///
/// Error messages are intentionally vague to prevent information leakage
/// per the cross-cutting security requirements.
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub(crate) fn identity_error_to_response(
    err: &crate::identity::IdentityError,
) -> (StatusCode, Json<serde_json::Value>) {
    use crate::identity::IdentityError;

    // RequiredActionsBlocking carries a structured payload — handle before the
    // flat (status, message) match so we can embed the actions array.
    if let IdentityError::RequiredActionsBlocking { actions } = err {
        let action_strs: Vec<&str> = actions
            .iter()
            .map(|a| crate::protocol::convert::identity::required_action_to_wire(*a))
            .collect();
        let error_code = crate::protocol::error_codes::for_identity_error(err);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "required_actions_pending",
                "error_code": error_code,
                "actions": action_strs,
            })),
        );
    }

    let (status, message) = match err {
        IdentityError::RealmNotFound | IdentityError::UserNotFound => {
            (StatusCode::NOT_FOUND, "not found")
        }
        IdentityError::RealmSuspended => (StatusCode::FORBIDDEN, "realm suspended"),
        IdentityError::DuplicateRealmName => (StatusCode::CONFLICT, "duplicate realm name"),
        IdentityError::DuplicateEmail => (StatusCode::CONFLICT, "duplicate email"),
        IdentityError::InvalidInput { .. } => (StatusCode::BAD_REQUEST, "invalid input"),
        IdentityError::CredentialNotFound => (StatusCode::NOT_FOUND, "credential not found"),
        IdentityError::InvalidCredential { .. } => (StatusCode::UNAUTHORIZED, "invalid credential"),
        IdentityError::SessionNotFound => (StatusCode::NOT_FOUND, "session not found"),
        IdentityError::SessionVersionDisabled => (
            StatusCode::NOT_FOUND,
            "session versioning disabled for realm",
        ),
        IdentityError::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid token"),
        IdentityError::TokenExpired => (StatusCode::UNAUTHORIZED, "token expired"),
        // RFC 6749 §5.2: all client authentication failures MUST return 401 with
        // "invalid_client" — distinguishable status codes are an enumeration oracle
        // (OAuth 2.0 Security BCP §2.2).
        IdentityError::InvalidClient => (StatusCode::UNAUTHORIZED, "invalid_client"),
        IdentityError::InvalidRedirectUri => (StatusCode::BAD_REQUEST, "invalid redirect URI"),
        IdentityError::InvalidAuthorizationCode => {
            (StatusCode::BAD_REQUEST, "invalid authorization code")
        }
        IdentityError::InvalidGrant { .. } => (StatusCode::BAD_REQUEST, "invalid grant"),
        IdentityError::InvalidClientSecret => (StatusCode::UNAUTHORIZED, "invalid_client"),
        IdentityError::AuthorizationPending => (StatusCode::BAD_REQUEST, "authorization_pending"),
        IdentityError::SlowDown => (StatusCode::BAD_REQUEST, "slow_down"),
        IdentityError::DeviceCodeExpired => (StatusCode::BAD_REQUEST, "expired_token"),
        IdentityError::DeviceCodeDenied => (StatusCode::BAD_REQUEST, "access_denied"),
        IdentityError::TokenRevoked => (StatusCode::UNAUTHORIZED, "token revoked"),
        IdentityError::UnsupportedGrantType => (StatusCode::BAD_REQUEST, "unsupported_grant_type"),
        IdentityError::MfaRequired => (StatusCode::FORBIDDEN, "MFA verification required"),
        IdentityError::InvalidMfaCode => (StatusCode::UNAUTHORIZED, "invalid MFA code"),
        IdentityError::MfaNotEnabled => (StatusCode::BAD_REQUEST, "MFA not enabled"),
        IdentityError::MfaAlreadyEnabled => (StatusCode::CONFLICT, "MFA already enabled"),
        IdentityError::WebAuthnRegistrationFailed { .. } => {
            (StatusCode::BAD_REQUEST, "webauthn registration failed")
        }
        IdentityError::WebAuthnAuthenticationFailed { .. } => {
            (StatusCode::UNAUTHORIZED, "webauthn authentication failed")
        }
        IdentityError::WebAuthnCredentialNotFound => {
            (StatusCode::NOT_FOUND, "credential not found")
        }
        IdentityError::InvalidAttestation { .. } => {
            (StatusCode::BAD_REQUEST, "invalid attestation")
        }
        IdentityError::InvalidAssertion { .. } => (StatusCode::UNAUTHORIZED, "invalid assertion"),
        IdentityError::InvalidClientAssertion { .. } => {
            (StatusCode::UNAUTHORIZED, "invalid_client")
        }
        IdentityError::Unauthorized => (StatusCode::FORBIDDEN, "forbidden"),
        IdentityError::ClientNotFound => (StatusCode::NOT_FOUND, "not found"),
        IdentityError::MagicLinkTokenInvalid => {
            (StatusCode::UNAUTHORIZED, "invalid or expired link")
        }
        IdentityError::VerificationTokenInvalid => {
            (StatusCode::GONE, "invalid or expired verification link")
        }
        IdentityError::PasswordResetTokenInvalid => {
            (StatusCode::UNAUTHORIZED, "invalid or expired reset link")
        }
        IdentityError::UserNotVerified => (StatusCode::FORBIDDEN, "email not verified"),
        IdentityError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "too many requests"),
        IdentityError::OrganizationNotFound => (StatusCode::NOT_FOUND, "organization not found"),
        IdentityError::DuplicateOrgSlug => (StatusCode::CONFLICT, "duplicate organization slug"),
        IdentityError::OrganizationSuspended => (StatusCode::FORBIDDEN, "organization suspended"),
        IdentityError::AlreadyMember => (StatusCode::CONFLICT, "already a member"),
        IdentityError::NotAMember => (StatusCode::NOT_FOUND, "not a member"),
        IdentityError::LastOwner => (StatusCode::CONFLICT, "cannot remove last owner"),
        IdentityError::MemberLimitReached => {
            (StatusCode::UNPROCESSABLE_ENTITY, "member limit reached")
        }
        IdentityError::InvitationInvalid => (StatusCode::BAD_REQUEST, "invalid invitation"),
        IdentityError::DuplicateInvitation => (StatusCode::CONFLICT, "duplicate invitation"),
        IdentityError::ReservedSlug { .. } => (StatusCode::CONFLICT, "slug_reserved"),
        IdentityError::SlugInCooldown { .. } => (StatusCode::CONFLICT, "slug_cooldown"),
        IdentityError::SystemRealmProtected { .. } => {
            (StatusCode::FORBIDDEN, "system realm is read-only")
        }
        IdentityError::RegistrationDisabled => (StatusCode::FORBIDDEN, "registration disabled"),
        IdentityError::RegistrationDomainNotAllowed { .. } => {
            (StatusCode::FORBIDDEN, "email domain not permitted")
        }
        IdentityError::RegistrationRequiresInvitation => {
            (StatusCode::FORBIDDEN, "invitation required")
        }
        IdentityError::ConsentRequired => (StatusCode::FORBIDDEN, "consent required"),
        IdentityError::ConsentTicketNotFound | IdentityError::ConsentTicketExpired => {
            (StatusCode::BAD_REQUEST, "consent ticket invalid")
        }
        IdentityError::ConsentScopeNotRequested => {
            (StatusCode::BAD_REQUEST, "scope not in original request")
        }
        IdentityError::ConsentNotFound => (StatusCode::NOT_FOUND, "consent not found"),
        IdentityError::FederationUnknownConnector => {
            (StatusCode::NOT_FOUND, "federation connector not found")
        }
        IdentityError::FederationInvalidState => {
            (StatusCode::BAD_REQUEST, "invalid federation state")
        }
        IdentityError::FederationUpstreamError { .. } => {
            (StatusCode::BAD_GATEWAY, "federation upstream error")
        }
        IdentityError::FederationTokenVerificationFailed => (
            StatusCode::UNAUTHORIZED,
            "federation token verification failed",
        ),
        IdentityError::FederationEmailNotVerified => {
            (StatusCode::FORBIDDEN, "upstream email not verified")
        }
        IdentityError::FederationIdpMixup => (StatusCode::BAD_REQUEST, "federation IdP mismatch"),
        IdentityError::FederationLinkConfirmationRequired { .. } => {
            // Browser flows redirect to /ui/federation/confirm-link; JSON
            // callers (rare for federation) get a terse 409 so they know
            // a linking decision is required.
            (
                StatusCode::CONFLICT,
                "federation link confirmation required",
            )
        }
        IdentityError::FederationNotLinked => {
            (StatusCode::NOT_FOUND, "external identity not linked")
        }
        IdentityError::FederationAlreadyLinked => {
            (StatusCode::CONFLICT, "external identity already linked")
        }
        IdentityError::DuplicateScimExternalId => {
            (StatusCode::CONFLICT, "SCIM externalId already in use")
        }
        IdentityError::Saml(ref e) => match e {
            crate::identity::federation::saml::SamlError::MetadataFetch { .. } => {
                (StatusCode::BAD_GATEWAY, "SAML metadata fetch failed")
            }
            crate::identity::federation::saml::SamlError::UnknownSp
            | crate::identity::federation::saml::SamlError::UnknownIdp => {
                (StatusCode::NOT_FOUND, "SAML entity not found")
            }
            _ => (StatusCode::BAD_REQUEST, "invalid SAML message"),
        },
        IdentityError::SigningError { .. }
        | IdentityError::Storage(_)
        | IdentityError::Serialization { .. }
        | IdentityError::Internal { .. }
        | IdentityError::ConfigInvalid { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
        IdentityError::TokenTooLarge { .. } => (StatusCode::PAYLOAD_TOO_LARGE, "token too large"),
        IdentityError::InvalidAttribute { .. } => (StatusCode::BAD_REQUEST, "invalid attribute"),
        IdentityError::AuthMethodNotAllowed { .. } => {
            (StatusCode::FORBIDDEN, "authentication method not permitted")
        }
        IdentityError::PasswordExpired => (StatusCode::UNAUTHORIZED, "password expired"),
        IdentityError::PasswordReused => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "password was recently used",
        ),
        IdentityError::PasswordCompromised => {
            (StatusCode::UNPROCESSABLE_ENTITY, "password_compromised")
        }
        IdentityError::AuditFailure { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        IdentityError::WebhookNotFound => (StatusCode::NOT_FOUND, "webhook not found"),
        IdentityError::StepUpChallengeRequired => (StatusCode::UNAUTHORIZED, "mfa_required"),
        IdentityError::EnrollMfaRequired => (StatusCode::FORBIDDEN, "mfa_enrollment_required"),
        // Handled by the early return above; this arm satisfies exhaustiveness.
        IdentityError::RequiredActionsBlocking { .. } => {
            (StatusCode::BAD_REQUEST, "required_actions_pending")
        }
        IdentityError::InvalidSmsOtp => (StatusCode::UNAUTHORIZED, "invalid_sms_otp"),
        IdentityError::SmsResendLimitExceeded => {
            (StatusCode::TOO_MANY_REQUESTS, "sms_resend_limit_exceeded")
        }
        IdentityError::InvalidEmailOtp => (StatusCode::UNAUTHORIZED, "invalid_email_otp"),
        IdentityError::InvalidPushedAuthorizationRequest => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        IdentityError::InvalidDPopProof { .. } => (StatusCode::UNAUTHORIZED, "invalid_dpop_proof"),
        IdentityError::DPopProofReplay | IdentityError::DPopNonceInvalid => {
            (StatusCode::UNAUTHORIZED, "use_dpop_nonce")
        }
        IdentityError::DPopBindingMismatch => (StatusCode::UNAUTHORIZED, "invalid_token"),
        IdentityError::JwtBearerAssertionInvalid { .. } => {
            (StatusCode::UNAUTHORIZED, "invalid_grant")
        }
        IdentityError::InvalidJar { .. } => (StatusCode::BAD_REQUEST, "invalid_request_object"),
        IdentityError::FapiViolation { .. } => (StatusCode::BAD_REQUEST, "invalid_request"),
        IdentityError::SessionLimitExceeded { .. } => {
            (StatusCode::TOO_MANY_REQUESTS, "session_limit_exceeded")
        }
        // A-19: email-change flow errors.
        IdentityError::QuotaExceeded { .. } => (StatusCode::TOO_MANY_REQUESTS, "quota_exceeded"),
        IdentityError::EmailReserved => (StatusCode::CONFLICT, "email_reserved"),
        IdentityError::EmailChangeTokenInvalid => (
            StatusCode::UNAUTHORIZED,
            "invalid or expired email-change link",
        ),
        // A-37: silent-auth rate-limit exceeded (prompt=none).
        IdentityError::SilentAuthRateLimited => {
            (StatusCode::TOO_MANY_REQUESTS, "silent_auth_rate_limited")
        }
        // A-13: attestation policy violation (AAGUID not in allowlist, "none" rejected, etc.).
        IdentityError::AttestationPolicyViolation { .. } => {
            (StatusCode::FORBIDDEN, "attestation_policy_violation")
        }
        IdentityError::AgentNotFound => (StatusCode::NOT_FOUND, "agent not found"),
        IdentityError::AgentRevoked => (StatusCode::FORBIDDEN, "agent revoked"),
        IdentityError::AgentCredentialNotFound => {
            (StatusCode::NOT_FOUND, "agent credential not found")
        }
        // HEA-1324: pre-token webhook failed with fail_closed policy.
        IdentityError::PreTokenWebhookFailed { .. } => {
            (StatusCode::BAD_GATEWAY, "pre_token_webhook_failed")
        }
        // M2: protected resource + RFC 8693 token exchange
        IdentityError::ProtectedResourceNotFound => {
            (StatusCode::NOT_FOUND, "protected_resource_not_found")
        }
        IdentityError::DuplicateResourceUri => (StatusCode::CONFLICT, "duplicate_resource_uri"),
        IdentityError::TokenExchangeRejected { oauth_error, .. } => {
            (StatusCode::BAD_REQUEST, *oauth_error)
        }
        IdentityError::DelegationDepthExceeded { .. } => (StatusCode::BAD_REQUEST, "invalid_grant"),
        IdentityError::EmptyScopeIntersection => (StatusCode::BAD_REQUEST, "invalid_scope"),
        IdentityError::ActorTokenReplayed => (StatusCode::BAD_REQUEST, "invalid_grant"),
        IdentityError::DelegationGrantNotFound => (StatusCode::NOT_FOUND, "not_found"),
        // Phase C
        IdentityError::ToolAccessDenied { .. } => (StatusCode::FORBIDDEN, "tool_access_denied"),
        IdentityError::ToolApprovalRequired { .. } => {
            (StatusCode::FORBIDDEN, "tool_approval_required")
        }
        IdentityError::ApprovalRequestNotFound => (StatusCode::NOT_FOUND, "not_found"),
        IdentityError::ApprovalRequestNotPending { .. } => {
            (StatusCode::CONFLICT, "approval_request_not_pending")
        }
        IdentityError::ApprovalRequestExpired => (StatusCode::GONE, "approval_request_expired"),
    };

    let error_code = crate::protocol::error_codes::for_identity_error(err);
    (
        status,
        Json(serde_json::json!({"error": message, "error_code": error_code})),
    )
}
/// Maps [`RbacError`] values to HTTP responses.
pub(crate) fn rbac_error_to_response(err: &RbacError) -> (StatusCode, Json<serde_json::Value>) {
    let (status, code) = match err {
        RbacError::RoleNotFound | RbacError::GroupNotFound | RbacError::AssignmentNotFound => {
            (StatusCode::NOT_FOUND, "not_found")
        }
        RbacError::DuplicateRoleName | RbacError::DuplicateGroupSlug => {
            (StatusCode::CONFLICT, "already_exists")
        }
        RbacError::InvalidPermission { .. }
        | RbacError::InvalidRoleName { .. }
        | RbacError::InvalidGroupSlug { .. } => (StatusCode::BAD_REQUEST, "invalid_request"),
        RbacError::CycleDetected { .. } => (StatusCode::BAD_REQUEST, "cycle_detected"),
        RbacError::DepthExceeded { .. }
        | RbacError::BreadthExceeded { .. }
        | RbacError::TokenSizeExceeded { .. } => {
            (StatusCode::PAYLOAD_TOO_LARGE, "resource_exhausted")
        }
        RbacError::RoleArchived => (StatusCode::CONFLICT, "role_archived"),
        RbacError::ReservedNamespace { .. } => (StatusCode::FORBIDDEN, "reserved_namespace"),
        RbacError::InvalidScope { .. } => (StatusCode::BAD_REQUEST, "invalid_scope"),
        RbacError::Storage(_) | RbacError::Serialization { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    };
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": err.to_string(),
        })),
    )
}
/// pbjson follows the proto3 JSON mapping spec which encodes int64/uint64
/// as strings to avoid IEEE 754 precision loss. REST APIs conventionally
/// use numeric JSON values, so this helper post-processes the serialized
/// JSON to convert string-encoded integers back to numbers.
pub(crate) fn proto_to_rest_json<T: Serialize>(value: &T) -> serde_json::Value {
    match serde_json::to_value(value) {
        Ok(v) => coerce_string_ints(v),
        Err(e) => {
            tracing::error!(error = %e, "proto serialization failed");
            serde_json::Value::Null
        }
    }
}

/// Recursively converts string values that represent integers to JSON numbers.
fn coerce_string_ints(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(ref s) => {
            if let Ok(n) = s.parse::<i64>() {
                serde_json::Value::Number(n.into())
            } else {
                v
            }
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, coerce_string_ints(v)))
                .collect(),
        ),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(coerce_string_ints).collect())
        }
        other => other,
    }
}
pub(crate) fn extract_user_auth(
    headers: &HeaderMap,
    state: &AppState,
    realm_id: &RealmId,
) -> Result<UserId, (StatusCode, Json<serde_json::Value>)> {
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        ));
    };

    let claims = state
        .identity
        .validate_token(realm_id, token)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
        })?;

    uuid::Uuid::parse_str(&claims.sub)
        .map(UserId::new)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
        })
}
pub(crate) fn extract_bearer_token(
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "missing authorization header"})),
            )
        })?
        .to_str()
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid authorization header"})),
            )
        })?;
    auth_header
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid authorization scheme"})),
            )
        })
}

/// Resolves a realm by URL-path name, returning an error Response if not found.
pub(crate) fn resolve_realm_by_name(
    state: &AppState,
    name: &str,
) -> Result<RealmId, axum::response::Response> {
    match state.identity.get_realm_by_name(name) {
        Ok(Some(realm)) => Ok(realm.id().clone()),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "realm_not_found"})),
        )
            .into_response()),
        Err(e) => {
            tracing::warn!(error = %e, realm_name = %name, "realm lookup failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal_error"})),
            )
                .into_response())
        }
    }
}
