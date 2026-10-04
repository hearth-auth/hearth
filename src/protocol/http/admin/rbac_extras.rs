//! RBAC admin routes that existed only over the public gRPC API until 3.0.0
//! (scope-trim-trusted-core): group role assignment, role members, direct
//! user permissions, the realm permission registry and audit integrity.
//!
//! Unassigning a group's role needs no new route: `DELETE
//! /admin/assignments/{id}` already accepts a group assignment and applies the
//! admin privilege ceiling to every member.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::super::{
    extract_admin_auth, rbac_error_to_response, require_admin_permission,
    require_user_admin_ceiling, AdminAuth, AppState,
};
use super::{
    parse_group_id, parse_role_id, parse_user_id_path, reject_system_realm_write,
    require_group_in_realm, require_user_in_realm, resolve_org_scope,
    role_permission_ceiling_refusal, PaginationParams,
};
use crate::audit::{AuditAction, CreateAuditEvent};
use crate::rbac::{
    AssignRoleRequest, Permission, RoleSubject, Scope, Subject, UserPermissionGrant,
};

/// Body of `POST /admin/groups/{id}/roles`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssignGroupRoleBody {
    role_id: String,
    /// Optional org ID for an org-scoped assignment; omit for realm scope.
    #[serde(default)]
    org_id: Option<String>,
}

/// Body of `POST /admin/users/{id}/permissions`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantPermissionBody {
    permission: String,
    /// Optional org ID for an org-scoped grant; omit for realm scope.
    #[serde(default)]
    org_id: Option<String>,
}

/// Query of `DELETE /admin/users/{id}/permissions/{permission}`.
#[derive(Debug, Deserialize)]
pub(super) struct RevokePermissionQuery {
    /// The org of an org-scoped grant; omit for a realm-scoped one.
    #[serde(default)]
    org_id: Option<String>,
}

/// One direct permission grant, as the REST admin API returns it.
#[derive(Debug, Serialize)]
struct PermissionGrantDto {
    permission: String,
    /// `realm` or `org`.
    scope_type: &'static str,
    org_id: Option<String>,
    granted_by: Option<String>,
    /// Microseconds since the Unix epoch.
    granted_at: i64,
}

impl From<&UserPermissionGrant> for PermissionGrantDto {
    fn from(g: &UserPermissionGrant) -> Self {
        let (scope_type, org_id) = match &g.scope {
            Scope::Org { org_id } => ("org", Some(org_id.as_uuid().to_string())),
            _ => ("realm", None),
        };
        Self {
            permission: g.permission.as_str().to_string(),
            scope_type,
            org_id,
            granted_by: g.granted_by.as_ref().map(|u| u.as_uuid().to_string()),
            granted_at: g.granted_at.as_micros(),
        }
    }
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

fn bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid_request", "error_description": message})),
    )
        .into_response()
}

/// Appends a permission grant or revocation to the audit log. A failed append
/// is logged, not fatal: the grant already happened (same as the console).
fn audit_permission_change(
    state: &AppState,
    auth: &AdminAuth,
    action: AuditAction,
    target: &crate::core::UserId,
    permission: &str,
    scope: &Scope,
) {
    let scope = match scope {
        Scope::Org { org_id } => format!("org:{}", org_id.as_uuid()),
        _ => "realm".to_string(),
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: auth.realm_id.clone(),
        actor: auth.user_id.as_uuid().to_string(),
        action,
        resource_type: "user".to_string(),
        resource_id: target.as_uuid().to_string(),
        metadata: Some(serde_json::json!({
            "via": "api",
            "permission": permission,
            "scope": scope,
        })),
    }) {
        tracing::warn!(error = %e, "permission change audit append failed");
    }
}

/// `POST /admin/groups/{id}/roles` — assigns a role to every group member.
pub(super) async fn admin_assign_group_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AssignGroupRoleBody>,
) -> Response {
    let auth = match realm_admin(&headers, &state, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_group_in_realm(&state, &auth.realm_id, &group_id) {
        return e;
    }
    let role_id = match parse_role_id(&body.role_id) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    if let Some(refusal) = role_permission_ceiling_refusal(&state, &auth, &role_id) {
        return refusal;
    }
    let scope = match resolve_org_scope(&state, &auth, body.org_id.as_deref()) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match state.rbac.assign_role(
        &auth.realm_id,
        &AssignRoleRequest {
            subject: Subject::Group(group_id),
            role_id,
            scope,
            assigned_by: Some(auth.user_id.clone()),
        },
    ) {
        Ok(a) => (StatusCode::CREATED, Json(a)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

/// `GET /admin/roles/{id}/members` — the users and groups holding a role.
pub(super) async fn admin_list_role_members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(pagination): Query<PaginationParams>,
) -> Response {
    let auth = match realm_admin(&headers, &state, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let role_id = match parse_role_id(&id) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match state.rbac.list_role_members(
        &auth.realm_id,
        &role_id,
        pagination.cursor.as_deref(),
        pagination.effective_limit(),
    ) {
        Ok(page) => {
            let items: Vec<serde_json::Value> = page
                .items
                .iter()
                .map(|m| match m {
                    RoleSubject::User(u) => serde_json::json!({
                        "subject_type": "user",
                        "subject_id": u.as_uuid().to_string(),
                    }),
                    RoleSubject::Group(g) => serde_json::json!({
                        "subject_type": "group",
                        "subject_id": g.as_uuid().to_string(),
                    }),
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({"items": items, "next_cursor": page.next_cursor})),
            )
                .into_response()
        }
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

/// `GET /admin/users/{id}/permissions` — the user's direct grants.
pub(super) async fn admin_list_user_permissions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match realm_admin(&headers, &state, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let user_id = match parse_user_id_path(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_user_in_realm(&state, &auth.realm_id, &user_id) {
        return e;
    }
    match state.rbac.list_user_permissions(&auth.realm_id, &user_id) {
        Ok(grants) => {
            let items: Vec<PermissionGrantDto> = grants.iter().map(Into::into).collect();
            (StatusCode::OK, Json(serde_json::json!({"items": items}))).into_response()
        }
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

/// `POST /admin/users/{id}/permissions` — grants a permission directly.
///
/// A sub-admin may grant only a permission it holds itself (HEA-SEC-13);
/// `hearth.admin` may grant any.
pub(super) async fn admin_grant_user_permission(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<GrantPermissionBody>,
) -> Response {
    let auth = match realm_admin(&headers, &state, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let user_id = match parse_user_id_path(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_user_in_realm(&state, &auth.realm_id, &user_id) {
        return e;
    }
    let Ok(permission) = Permission::new(&body.permission) else {
        return bad_request("invalid permission name");
    };
    let is_superuser = auth.permissions.iter().any(|p| p == "hearth.admin");
    if !is_superuser && !auth.permissions.iter().any(|p| p == permission.as_str()) {
        tracing::warn!(
            granter = %auth.user_id,
            realm_id = %auth.realm_id,
            "permission grant blocked: the granter does not hold the permission"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "error_description": "the caller does not hold the permission it tries to grant"
            })),
        )
            .into_response();
    }
    let scope = match resolve_org_scope(&state, &auth, body.org_id.as_deref()) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let grant = UserPermissionGrant {
        realm_id: auth.realm_id.clone(),
        user_id: user_id.clone(),
        permission,
        scope,
        granted_at: crate::core::Timestamp::from_micros(super::super::now_micros()),
        granted_by: Some(auth.user_id.clone()),
    };
    match state.rbac.grant_user_permission(&auth.realm_id, &grant) {
        Ok(stored) => {
            audit_permission_change(
                &state,
                &auth,
                AuditAction::UserPermissionGranted,
                &user_id,
                stored.permission.as_str(),
                &stored.scope,
            );
            (StatusCode::CREATED, Json(PermissionGrantDto::from(&stored))).into_response()
        }
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

/// `DELETE /admin/users/{id}/permissions/{permission}[?org_id=…]`.
///
/// Revoking demotes the user: the admin privilege ceiling applies.
pub(super) async fn admin_revoke_user_permission(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, permission)): Path<(String, String)>,
    Query(query): Query<RevokePermissionQuery>,
) -> Response {
    let auth = match realm_admin(&headers, &state, true) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let user_id = match parse_user_id_path(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_user_in_realm(&state, &auth.realm_id, &user_id) {
        return e;
    }
    let Ok(permission) = Permission::new(&permission) else {
        return bad_request("invalid permission name");
    };
    if let Err(e) = require_user_admin_ceiling(&state, &auth, &auth.realm_id, &user_id) {
        return e.into_response();
    }
    let scope = match resolve_org_scope(&state, &auth, query.org_id.as_deref()) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match state
        .rbac
        .revoke_user_permission(&auth.realm_id, &user_id, &permission, &scope)
    {
        Ok(()) => {
            audit_permission_change(
                &state,
                &auth,
                AuditAction::UserPermissionRevoked,
                &user_id,
                permission.as_str(),
                &scope,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

/// `GET /admin/permissions` — the realm's permission registry.
pub(super) async fn admin_list_permissions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = match realm_admin(&headers, &state, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    match state.rbac.export_all_permissions(&auth.realm_id) {
        Ok(records) => {
            let items: Vec<serde_json::Value> = records
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "name": r.name.as_str(),
                        "status": r.status,
                    })
                })
                .collect();
            (StatusCode::OK, Json(serde_json::json!({"items": items}))).into_response()
        }
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

/// `POST /admin/audit/verify` — walks the realm's audit hash chain.
pub(super) async fn admin_verify_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let auth = match realm_admin(&headers, &state, false) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let ok = match state.audit.verify_integrity(&auth.realm_id, None, None) {
        Ok(ok) => ok,
        Err(e) => {
            tracing::error!(error = %e, realm_id = %auth.realm_id, "audit integrity check failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "audit integrity check failed"})),
            )
                .into_response();
        }
    };
    let event_count = match state
        .audit
        .query(&crate::audit::AuditQuery::for_realm(auth.realm_id.clone()))
    {
        Ok(events) => events.len(),
        Err(e) => {
            tracing::error!(error = %e, realm_id = %auth.realm_id, "audit event count failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "audit event count failed"})),
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": ok, "event_count": event_count})),
    )
        .into_response()
}
