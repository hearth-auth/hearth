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
//!
//! Both paths are gated on realm status first: a realm that is not `Active` is
//! refused with `403` before either credential is examined.
//!
//! # Authorization on the admin-JWT fallback
//!
//! The fallback admits the same tokens the admin plane does — any
//! admin-grade permission — so it must then narrow exactly as each resource's
//! admin twin narrows. [`authenticate`] takes the [`ScimResource`] being
//! served and demands its [`ScimResource::required_admin_permission`] (or
//! `hearth.admin`) before returning. It used to return after the outer gate,
//! so a `hearth.clients.admin`-only token could create, rewrite and delete
//! every user in the realm, superusers included (GA audit round 3, G-5).
//! Taking the resource as a parameter means no handler can forget the check.

use axum::http::{HeaderMap, StatusCode};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::core::{RealmId, UserId};
use crate::identity::{Realm, RealmStatus};
use crate::protocol::admin_auth::{grants_admin_permission, RateLimitOutcome};
use crate::protocol::http::{extract_admin_auth, AppState};
use crate::protocol::scim::error::ScimError;

/// The SCIM resource family a request addresses. It decides which admin
/// permission the admin-JWT fallback must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimResource {
    /// `/scim/v2/Users` — the user directory.
    Users,
    /// `/scim/v2/Groups` — organizations and their memberships.
    Groups,
}

impl ScimResource {
    /// The admin sub-permission the admin-JWT fallback must hold (besides
    /// `hearth.admin`, which always suffices) — the one the resource's admin
    /// twin requires:
    ///
    /// - `Users` → `hearth.users.admin`, as on every REST `/admin/users*` route.
    /// - `Groups` → `hearth.realm.admin`, as on every gRPC organization RPC.
    #[must_use]
    pub const fn required_admin_permission(self) -> &'static str {
        match self {
            Self::Users => "hearth.users.admin",
            Self::Groups => "hearth.realm.admin",
        }
    }
}

/// Authenticated SCIM principal — either a realm-scoped service account or an
/// admin user who accessed SCIM via the JWT fallback path.
#[derive(Debug, Clone)]
pub struct ScimAuth {
    /// The realm named by `X-Realm-ID` (and, on the JWT path, by the token).
    pub realm_id: RealmId,
    /// Opaque actor string for audit events.
    ///
    /// Format is `"scim_token:<realm_uuid>"` for the bearer-token path, or
    /// the admin user UUID string for the JWT fallback path.
    pub actor: String,
    /// The permissions the caller acts with, for the privilege ceiling on user
    /// administration ([`crate::protocol::admin_auth::check_user_admin_ceiling`]).
    ///
    /// Empty for the provisioning token: a narrowed service account that may
    /// act on no principal holding an admin permission. The admin-JWT
    /// fallback carries the token's permissions, so a sub-admin may act only
    /// on same-or-lower users, exactly as on REST `/admin/users*`.
    pub actor_permissions: Vec<String>,
}

/// Authenticate and authorize a SCIM request for `resource` using the
/// dual-path model.
///
/// When the realm has a `scim_bearer_token_hash` configured, only the
/// matching SCIM bearer token is accepted and admin JWTs are rejected; the
/// token is a provisioning credential for every SCIM resource. When no SCIM
/// token is configured, falls back to admin JWT authentication, and the token
/// must then hold `hearth.admin` or `resource`'s
/// [`ScimResource::required_admin_permission`] — `403` otherwise.
pub fn authenticate(
    headers: &HeaderMap,
    state: &AppState,
    resource: ScimResource,
) -> Result<ScimAuth, ScimError> {
    let realm_id = extract_realm_id(headers)?;
    let realm = active_realm(state, &realm_id)?;

    if let Some(expected_hash) = realm.config().scim_bearer_token_hash.as_deref() {
        // Realm-scoped SCIM bearer token path: only accept the pre-shared token.
        let token = extract_bearer_token(headers)?;
        if !scim_token_matches(expected_hash, &token) {
            return Err(ScimError::unauthorized("invalid bearer token"));
        }
        check_scim_rate_limit(state, &realm_id)?;
        Ok(ScimAuth {
            actor: format!("scim_token:{}", realm_id.as_uuid()),
            realm_id,
            actor_permissions: Vec::new(),
        })
    } else {
        // No SCIM token configured: fall back to admin JWT.
        let admin = admin_jwt(headers, state, &realm_id)?;
        // Apply the same per-realm rate limiter to the admin-JWT fallback path
        // so it cannot be used to bypass SCIM throttling (defect 3 / HEA-2032).
        check_scim_rate_limit(state, &realm_id)?;
        // Narrow to the resource's admin permission, exactly as its admin twin
        // does: the outer gate above admits every admin-grade permission.
        let required = resource.required_admin_permission();
        if !grants_admin_permission(&admin.permissions, required) {
            return Err(ScimError::forbidden(format!(
                "{required} or hearth.admin permission required"
            )));
        }
        Ok(ScimAuth {
            actor: admin.user_id.as_uuid().to_string(),
            realm_id,
            actor_permissions: admin.permissions,
        })
    }
}

/// Authenticate a request to a SCIM discovery endpoint
/// (`/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`).
///
/// Accepts the realm's SCIM provisioning token — the credential an IdP was
/// given, and uses to read discovery before provisioning — as well as any
/// admin token for the realm (any admin-grade permission: the responses are
/// static capability documents). Discovery used to accept only the admin
/// token, so the realm's own SCIM token got `401` (GA audit round 3).
///
/// A bearer that is not the realm's SCIM token is then tried as an admin
/// token, so a wrong bearer still answers `401`.
pub fn authenticate_discovery(headers: &HeaderMap, state: &AppState) -> Result<(), ScimError> {
    let realm_id = extract_realm_id(headers)?;
    let realm = active_realm(state, &realm_id)?;

    if let Some(expected_hash) = realm.config().scim_bearer_token_hash.as_deref() {
        let token = extract_bearer_token(headers)?;
        if scim_token_matches(expected_hash, &token) {
            return check_scim_rate_limit(state, &realm_id);
        }
    }
    admin_jwt(headers, state, &realm_id).map(|_| ())
}

/// Looks the realm up and refuses (`403`) one that is missing or not active.
fn active_realm(state: &AppState, realm_id: &RealmId) -> Result<Realm, ScimError> {
    let realm = state
        .identity
        .get_realm(realm_id)
        .map_err(|e| {
            tracing::warn!(error = %e, "SCIM auth realm lookup failed");
            ScimError::internal()
        })?
        .ok_or_else(|| ScimError::forbidden("realm unavailable"))?;

    // Realm status is the incident-response freeze control, and it has to hold
    // on the SCIM plane as well as on the token and admin planes. Without this,
    // a pre-shared SCIM bearer token kept reading — and writing — a suspended or
    // archived realm's user directory (audit 2026-08-28 §4.1#5).
    //
    // The gate sits here, before either credential path, so both the bearer
    // token and the admin-JWT fallback are refused identically. It leaks no new
    // information: the realm lookup above already answers `403` pre-auth for a
    // realm that does not exist.
    if realm.status() != RealmStatus::Active {
        return Err(ScimError::forbidden("realm unavailable"));
    }
    Ok(realm)
}

/// Constant-time comparison of the presented bearer against the realm's
/// stored SCIM token hash.
fn scim_token_matches(expected_hash: &str, token: &str) -> bool {
    let incoming_hash = sha256_hex(token);
    expected_hash
        .as_bytes()
        .ct_eq(incoming_hash.as_bytes())
        .into()
}

/// Validates the bearer as an admin token for `realm_id` (any admin-grade
/// permission), mapping the admin plane's refusal onto a SCIM error.
fn admin_jwt(
    headers: &HeaderMap,
    state: &AppState,
    realm_id: &RealmId,
) -> Result<crate::protocol::http::AdminAuth, ScimError> {
    let admin = extract_admin_auth(headers, state).map_err(|(status, body)| {
        let detail = body
            .0
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("authentication failed")
            .to_string();
        ScimError::new(status, detail)
    })?;
    // Assert the JWT's realm matches the X-Realm-ID header to prevent
    // cross-realm privilege escalation on the fallback path.
    if &admin.realm_id != realm_id {
        return Err(ScimError::forbidden("realm mismatch"));
    }
    Ok(admin)
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
