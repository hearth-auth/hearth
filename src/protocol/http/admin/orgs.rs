//! `/admin/organizations` — organization CRUD and per-member extra roles.
//!
//! These operations existed only over the public gRPC API until 3.0.0
//! (scope-trim-trusted-core). They follow the REST admin conventions, which
//! are stricter than the gRPC handlers were in four places: a suspension is
//! checked against the admin privilege ceiling like a delete, a `slug` in an
//! update is refused instead of ignored, `granted_by` is the caller rather
//! than a body field, and a missing organization answers `404`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::super::{
    ceiling_refusal, extract_admin_auth, identity_error_to_response, rbac_error_to_response,
    require_admin_permission, AdminAuth, AppState,
};
use super::{
    parse_user_id_path, reject_system_realm_write, require_user_in_realm,
    role_permission_ceiling_refusal, PaginationParams,
};
use crate::core::OrganizationId;
use crate::identity::{
    CreateOrganizationRequest, Organization, OrganizationConfig, OrganizationStatus,
    UpdateOrganizationRequest,
};

/// An organization as the REST admin API returns it.
#[derive(Debug, Serialize)]
struct OrganizationDto {
    id: String,
    slug: String,
    display_name: String,
    /// `active`, `suspended` or `archived`.
    status: &'static str,
    member_limit: Option<u32>,
    /// Whether members need MFA even where the realm does not require it.
    mfa_required: bool,
    attributes: BTreeMap<String, String>,
    /// Microseconds since the Unix epoch.
    created_at: i64,
    /// Microseconds since the Unix epoch.
    updated_at: i64,
}

impl From<&Organization> for OrganizationDto {
    fn from(o: &Organization) -> Self {
        Self {
            id: o.id().as_uuid().to_string(),
            slug: o.slug().to_string(),
            display_name: o.name().to_string(),
            status: match o.status() {
                OrganizationStatus::Active => "active",
                OrganizationStatus::Suspended => "suspended",
                OrganizationStatus::Archived => "archived",
            },
            member_limit: o.config().max_members,
            mfa_required: o.config().mfa_required,
            attributes: o.attributes().clone(),
            created_at: o.created_at().as_micros(),
            updated_at: o.updated_at().as_micros(),
        }
    }
}

/// Body of `POST /admin/organizations`.
#[derive(Debug, Deserialize)]
pub(super) struct CreateOrganizationBody {
    slug: String,
    display_name: String,
    #[serde(default)]
    member_limit: Option<u32>,
    /// Members need MFA even where the realm does not require it. Default
    /// `false`; it can only tighten the realm's policy.
    #[serde(default)]
    mfa_required: bool,
    #[serde(default)]
    attributes: BTreeMap<String, String>,
}

/// Body of `PATCH /admin/organizations/{id}`. Absent fields are unchanged.
#[derive(Debug, Deserialize)]
pub(super) struct UpdateOrganizationBody {
    /// Present only to be refused: the slug is immutable.
    #[serde(default)]
    slug: Option<serde_json::Value>,
    #[serde(default)]
    display_name: Option<String>,
    /// `active` or `suspended`.
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    member_limit: Option<u32>,
    #[serde(default)]
    mfa_required: Option<bool>,
    /// Replaces the whole attribute map.
    #[serde(default)]
    attributes: Option<BTreeMap<String, String>>,
}

/// Body of `POST /admin/organizations/{id}/members/{user_id}/roles`.
#[derive(Debug, Deserialize)]
pub(super) struct AddAdditionalRoleBody {
    role_name: String,
}

fn bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid_request", "error_description": message})),
    )
        .into_response()
}

fn org_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "organization not found"})),
    )
        .into_response()
}

fn parse_org_id(raw: &str) -> Result<OrganizationId, Response> {
    let stripped = raw.strip_prefix("org_").unwrap_or(raw);
    uuid::Uuid::parse_str(stripped)
        .map(OrganizationId::new)
        .map_err(|_| bad_request("invalid organization id"))
}

/// Authenticates a realm administrator; `write` also refuses the system realm.
fn realm_admin(headers: &HeaderMap, state: &AppState, write: bool) -> Result<AdminAuth, Response> {
    let auth = extract_admin_auth(headers, state).map_err(IntoResponse::into_response)?;
    require_admin_permission(&auth, "hearth.realm.admin").map_err(IntoResponse::into_response)?;
    if write {
        reject_system_realm_write(&auth)?;
    }
    Ok(auth)
}

/// Loads an organization of the caller's realm, or answers `404`.
fn require_org(
    state: &AppState,
    auth: &AdminAuth,
    org: &OrganizationId,
) -> Result<Organization, Response> {
    match state.identity.get_organization(&auth.realm_id, org) {
        Ok(Some(o)) => Ok(o),
        Ok(None) => Err(org_not_found()),
        Err(e) => Err(identity_error_to_response(&e).into_response()),
    }
}

/// `GET /admin/organizations` — `cursor` is a decimal offset.
pub(super) async fn admin_list_organizations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationParams>,
) -> Response {
    let auth = match realm_admin(&headers, &state, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let page = pagination.as_page_request();
    match state.identity.list_organizations(&auth.realm_id, &page) {
        Ok(result) => {
            let end = page.offset + result.items.len() as u64;
            let next_cursor = (end < result.total).then(|| end.to_string());
            let items: Vec<OrganizationDto> = result.items.iter().map(Into::into).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({"items": items, "next_cursor": next_cursor})),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `POST /admin/organizations`.
pub(super) async fn admin_create_organization(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateOrganizationBody>,
) -> Response {
    let auth = match realm_admin(&headers, &state, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let request = CreateOrganizationRequest {
        name: body.display_name,
        slug: body.slug,
        description: None,
        config: Some(OrganizationConfig {
            max_members: body.member_limit,
            mfa_required: body.mfa_required,
        }),
        attributes: body.attributes,
    };
    match state.identity.create_organization(&auth.realm_id, &request) {
        Ok(org) => (StatusCode::CREATED, Json(OrganizationDto::from(&org))).into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `GET /admin/organizations/{id}`.
pub(super) async fn admin_get_organization(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match realm_admin(&headers, &state, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let org_id = match parse_org_id(&id) {
        Ok(o) => o,
        Err(e) => return e,
    };
    match require_org(&state, &auth, &org_id) {
        Ok(org) => (StatusCode::OK, Json(OrganizationDto::from(&org))).into_response(),
        Err(e) => e,
    }
}

/// `PATCH /admin/organizations/{id}`.
///
/// Suspending an organization strips every admin permission its members hold
/// only inside it, exactly as deleting it does, so a status change away from
/// `active` passes the same admin privilege ceiling as a delete.
pub(super) async fn admin_update_organization(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateOrganizationBody>,
) -> Response {
    let auth = match realm_admin(&headers, &state, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let org_id = match parse_org_id(&id) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if body.slug.is_some() {
        return bad_request("an organization's slug cannot be changed");
    }
    let status = match body.status.as_deref() {
        None => None,
        Some("active") => Some(OrganizationStatus::Active),
        Some("suspended") => Some(OrganizationStatus::Suspended),
        Some(_) => return bad_request("status must be \"active\" or \"suspended\""),
    };
    let current = match require_org(&state, &auth, &org_id) {
        Ok(org) => org,
        Err(e) => return e,
    };
    if status == Some(OrganizationStatus::Suspended) {
        if let Err(e) = crate::protocol::admin_auth::check_org_admin_ceiling(
            state.identity.as_ref(),
            state.rbac.as_ref(),
            &auth.realm_id,
            &org_id,
            &auth.permissions,
        ) {
            return ceiling_refusal(e).into_response();
        }
    }
    let update = UpdateOrganizationRequest {
        name: body.display_name,
        description: None,
        status,
        // Start from the stored config: a field the body leaves out is kept.
        config: (body.member_limit.is_some() || body.mfa_required.is_some()).then(|| {
            OrganizationConfig {
                max_members: body.member_limit.or(current.config().max_members),
                mfa_required: body.mfa_required.unwrap_or(current.config().mfa_required),
            }
        }),
        attributes: body.attributes,
    };
    match state
        .identity
        .update_organization(&auth.realm_id, &org_id, &update)
    {
        Ok(org) => (StatusCode::OK, Json(OrganizationDto::from(&org))).into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `DELETE /admin/organizations/{id}`.
pub(super) async fn admin_delete_organization(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match realm_admin(&headers, &state, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let org_id = match parse_org_id(&id) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if let Err(e) = require_org(&state, &auth, &org_id) {
        return e;
    }
    // Deleting the organization strips every admin permission its members
    // hold only in it (GA sweep 4).
    if let Err(e) = crate::protocol::admin_auth::check_org_admin_ceiling(
        state.identity.as_ref(),
        state.rbac.as_ref(),
        &auth.realm_id,
        &org_id,
        &auth.permissions,
    ) {
        return ceiling_refusal(e).into_response();
    }
    match state.identity.delete_organization(&auth.realm_id, &org_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Parses the `{id}/members/{user_id}` pair and confirms both exist.
fn member_target(
    state: &AppState,
    auth: &AdminAuth,
    org: &str,
    user: &str,
) -> Result<(OrganizationId, crate::core::UserId), Response> {
    let org_id = parse_org_id(org)?;
    let user_id = parse_user_id_path(user).map_err(IntoResponse::into_response)?;
    require_org(state, auth, &org_id)?;
    require_user_in_realm(state, &auth.realm_id, &user_id)?;
    Ok((org_id, user_id))
}

/// `GET /admin/organizations/{id}/members/{user_id}/roles`.
pub(super) async fn admin_list_additional_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, user)): Path<(String, String)>,
) -> Response {
    let auth = match realm_admin(&headers, &state, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let (org_id, user_id) = match member_target(&state, &auth, &org, &user) {
        Ok(t) => t,
        Err(e) => return e,
    };
    match state
        .rbac
        .list_additional_roles(&auth.realm_id, &org_id, &user_id)
    {
        Ok(names) => (StatusCode::OK, Json(serde_json::json!({"items": names}))).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

/// `POST /admin/organizations/{id}/members/{user_id}/roles`.
///
/// The user must already be a member: an extra role on a non-member would be
/// org-scoped authority the membership list does not show (GA sweep 4).
pub(super) async fn admin_add_additional_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, user)): Path<(String, String)>,
    Json(body): Json<AddAdditionalRoleBody>,
) -> Response {
    let auth = match realm_admin(&headers, &state, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let (org_id, user_id) = match member_target(&state, &auth, &org, &user) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let role = match state.rbac.get_role_by_name(&auth.realm_id, &body.role_name) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "role not found"})),
            )
                .into_response()
        }
        Err(e) => return rbac_error_to_response(&e).into_response(),
    };
    if let Some(refusal) = role_permission_ceiling_refusal(&state, &auth, &role.id) {
        return refusal;
    }
    match state
        .identity
        .get_membership(&auth.realm_id, &org_id, &user_id)
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "not_a_member",
                    "error_description": "the user is not a member of the organization"
                })),
            )
                .into_response()
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    }
    match state.rbac.add_additional_role(
        &auth.realm_id,
        &org_id,
        &user_id,
        &body.role_name,
        Some(&auth.user_id),
    ) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

/// `DELETE /admin/organizations/{id}/members/{user_id}/roles/{role_name}`.
pub(super) async fn admin_remove_additional_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, user, role_name)): Path<(String, String, String)>,
) -> Response {
    let auth = match realm_admin(&headers, &state, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let (org_id, user_id) = match member_target(&state, &auth, &org, &user) {
        Ok(t) => t,
        Err(e) => return e,
    };
    // Removing a role demotes the user: the ceiling applies.
    if let Err(e) = crate::protocol::admin_auth::check_user_admin_ceiling(
        state.identity.as_ref(),
        state.rbac.as_ref(),
        &auth.realm_id,
        &user_id,
        &auth.permissions,
    ) {
        return ceiling_refusal(e).into_response();
    }
    match state
        .rbac
        .remove_additional_role(&auth.realm_id, &org_id, &user_id, &role_name)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}
