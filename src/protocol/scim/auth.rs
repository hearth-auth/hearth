//! Realm-scoped SCIM bearer authentication helpers.
//!
//! # Authentication model
//!
//! SCIM endpoints use a two-path model based on whether the realm has a
//! dedicated SCIM bearer token configured:
//!
//! - **`scim_bearer_token_hash` is set** → only the pre-shared SCIM bearer
//!   token is accepted; admin JWTs are rejected with 401. This enforces
//!   least-privilege service-account isolation for SCIM provisioning.
//! - **`scim_bearer_token_hash` is absent** → admin JWT is accepted as a
//!   fallback so realms that have not configured a dedicated SCIM token still
//!   work without breaking changes.
//!
//! Operators who set `scim_bearer_token_hash` in realm config can be
//! confident that SCIM endpoints are isolated from the admin JWT path.

use axum::http::{HeaderMap, StatusCode};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::core::{RealmId, UserId};
use crate::protocol::admin_auth::RateLimitOutcome;
use crate::protocol::http::{extract_admin_auth, AppState};
use crate::protocol::scim::error::ScimError;

/// Authenticated SCIM principal — either a realm-scoped service account or an
/// admin user who accessed SCIM via the JWT fallback path.
#[derive(Debug, Clone)]
pub struct ScimAuth {
    pub realm_id: RealmId,
    /// Opaque actor string for audit events.
    ///
    /// Format is `"scim_token:<realm_uuid>"` for the bearer-token path, or
    /// the admin user UUID string for the JWT fallback path.
    pub actor: String,
}

/// Authenticate a SCIM request using the dual-path model.
///
/// When the realm has a `scim_bearer_token_hash` configured, only the
/// matching SCIM bearer token is accepted and admin JWTs are rejected. When
/// no SCIM token is configured, falls back to admin JWT authentication so
/// existing deployments continue to work.
pub fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<ScimAuth, ScimError> {
    let realm_id = extract_realm_id(headers)?;

    let realm = state
        .identity
        .get_realm(&realm_id)
        .map_err(|e| {
            tracing::warn!(error = %e, "SCIM auth realm lookup failed");
            ScimError::internal()
        })?
        .ok_or_else(|| ScimError::forbidden("realm unavailable"))?;

    if let Some(expected_hash) = realm.config().scim_bearer_token_hash.as_deref() {
        // Realm-scoped SCIM bearer token path: only accept the pre-shared token.
        let token = extract_bearer_token(headers)?;
        let incoming_hash = sha256_hex(&token);
        let hash_match: bool = expected_hash
            .as_bytes()
            .ct_eq(incoming_hash.as_bytes())
            .into();
        if !hash_match {
            return Err(ScimError::unauthorized("invalid bearer token"));
        }
        check_scim_rate_limit(state, &realm_id)?;
        Ok(ScimAuth {
            actor: format!("scim_token:{}", realm_id.as_uuid()),
            realm_id,
        })
    } else {
        // No SCIM token configured: fall back to admin JWT.
        extract_admin_auth(headers, state)
            .map(|admin| ScimAuth {
                actor: admin.user_id.as_uuid().to_string(),
                realm_id: admin.realm_id,
            })
            .map_err(|(status, body)| {
                let detail = body
                    .0
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("authentication failed")
                    .to_string();
                ScimError::new(status, detail)
            })
    }
}

fn extract_realm_id(headers: &HeaderMap) -> Result<RealmId, ScimError> {
    let header_value = headers
        .get("x-realm-id")
        .ok_or_else(|| ScimError::bad_request("invalidValue", "missing X-Realm-ID header"))?
        .to_str()
        .map_err(|_| ScimError::bad_request("invalidValue", "invalid X-Realm-ID header"))?;

    let uuid: uuid::Uuid = header_value
        .parse()
        .map_err(|_| ScimError::bad_request("invalidValue", "X-Realm-ID must be a valid UUID"))?;

    Ok(RealmId::new(uuid))
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, ScimError> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| ScimError::unauthorized("missing authorization header"))?
        .to_str()
        .map_err(|_| ScimError::unauthorized("invalid authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ScimError::unauthorized("invalid authorization scheme"))?;

    Ok(token.to_string())
}

fn check_scim_rate_limit(state: &AppState, realm_id: &RealmId) -> Result<(), ScimError> {
    #[allow(clippy::cast_possible_truncation)]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;

    // Reuse the shared limiter by keying SCIM traffic on the realm UUID.
    let synthetic_actor = UserId::new(*realm_id.as_uuid());
    match state.admin_rate_limiter.check(&synthetic_actor, now) {
        RateLimitOutcome::Allowed => Ok(()),
        RateLimitOutcome::Exceeded => Err(ScimError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        )),
    }
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
