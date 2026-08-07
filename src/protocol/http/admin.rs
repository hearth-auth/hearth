//! Admin API endpoints: users, realms, clients, audit, RBAC, webhooks, backup.

#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::audit::{Actor, AuditContext, CreateAuditEvent};
use crate::core::{ClientId, RealmId, UserId, WebhookId};
use crate::identity::email::{validate_email_template, EmailBranding, LocalizedEmailTemplate};
use crate::identity::UpdateRealmRequest;
use crate::protocol::convert::identity::{
    proto_user_status_to_domain, realm_page_to_proto, user_bulk_result_to_proto,
    user_page_to_proto, void_bulk_result_to_proto,
};
use crate::protocol::convert::oauth::client_page_to_proto;
use crate::protocol::proto::identity::v1 as pb;
use crate::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, GroupId, GroupMember, Permission,
    RbacError, RoleId, Scope, Subject, UpdateGroupRequest, UpdateRoleRequest,
};
use crate::webhook::{
    CreateWebhookRequest, DeliveryQuery, UpdateWebhookRequest, WebhookEngine, WebhookQuery,
};
use tracing::error;

use super::{
    check_export_capability, check_export_rate_limit, emit_export_watermark, extract_admin_auth,
    extract_realm_id, identity_error_to_response, proto_to_rest_json, rbac_error_to_response,
    require_admin_permission, require_any_admin_permission, verify_manifest_signature, AdminAuth,
    AppState, BACKUP_RESTORE_BODY_LIMIT,
};

/// Registers all admin API routes (mounted under `/admin` by the parent router).
pub(super) fn admin_api_routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::{delete, get, patch, post};
    axum::Router::new()
        .route("/users", get(admin_list_users).post(admin_create_user))
        .route("/users/bulk", post(admin_bulk_users))
        .route("/users/import", post(admin_import_users))
        .route("/users/export", get(admin_export_users))
        .route(
            "/users/{id}",
            get(admin_get_user)
                .patch(admin_update_user)
                .delete(admin_delete_user),
        )
        .route(
            "/users/{id}/device-fingerprints",
            delete(admin_delete_user_device_fingerprints),
        )
        .route("/realms", get(admin_list_realms).post(admin_create_realm))
        .route(
            "/realms/{id}",
            get(admin_get_realm)
                .patch(admin_update_realm)
                .delete(admin_delete_realm),
        )
        .route(
            "/realms/{id}/rotate-signing-key",
            post(admin_rotate_realm_signing_key),
        )
        .route(
            "/realms/{id}/branding",
            get(admin_get_realm_branding).patch(admin_patch_realm_branding),
        )
        .route(
            "/realms/{id}/email-templates",
            get(admin_list_realm_email_templates),
        )
        .route(
            "/realms/{id}/email-templates/{kind}",
            get(admin_get_realm_email_template)
                .put(admin_put_realm_email_template)
                .delete(admin_delete_realm_email_template),
        )
        .route(
            "/applications",
            get(admin_list_clients).post(admin_register_client),
        )
        .route(
            "/applications/{id}",
            get(admin_get_client)
                .patch(admin_update_client)
                .delete(admin_delete_client),
        )
        .route("/users/{id}/consents", get(admin_list_user_consents))
        .route(
            "/users/{id}/consents/{client_id}",
            delete(admin_revoke_user_consent),
        )
        .route(
            "/users/{id}/effective-permissions",
            get(admin_get_user_effective_permissions),
        )
        .route("/audit", get(admin_list_audit))
        .route("/roles", get(admin_list_roles).post(admin_create_role))
        .route(
            "/roles/{id}",
            get(admin_get_role)
                .patch(admin_update_role)
                .delete(admin_delete_role),
        )
        .route("/groups", get(admin_list_groups).post(admin_create_group))
        .route(
            "/groups/{id}",
            get(admin_get_group)
                .patch(admin_update_group)
                .delete(admin_delete_group),
        )
        .route(
            "/groups/{id}/members",
            get(admin_list_group_members).post(admin_add_group_member),
        )
        .route(
            "/groups/{id}/members/{member_id}",
            delete(admin_remove_group_member),
        )
        .route(
            "/users/{id}/roles",
            get(admin_list_user_assignments).post(admin_assign_role),
        )
        .route("/assignments/{id}", delete(admin_unassign_role))
        .route(
            "/webhooks",
            get(admin_list_webhooks).post(admin_create_webhook),
        )
        .route(
            "/webhooks/{id}",
            get(admin_get_webhook)
                .put(admin_update_webhook)
                .delete(admin_delete_webhook),
        )
        .route(
            "/webhooks/{id}/deliveries",
            get(admin_list_webhook_deliveries),
        )
        .route("/backup", post(admin_backup_create))
        .route(
            "/backup/restore",
            post(admin_backup_restore)
                .route_layer(DefaultBodyLimit::max(BACKUP_RESTORE_BODY_LIMIT)),
        )
        .route(
            "/realms/{realm_id}/users/{user_id}/required-actions",
            patch(admin_patch_user_required_actions),
        )
        .route("/realms/{realm_id}/config", patch(admin_patch_realm_config))
        .route(
            "/sessions/{session_id}/sv-bump",
            post(admin_sv_bump_session),
        )
        .route("/sessions/{id}", delete(admin_revoke_session))
        .route("/users/{id}/sessions", get(admin_list_user_sessions))
        .route("/realms/{realm_id}/sv-bump-all", post(admin_sv_bump_all))
        .route(
            "/cluster/bootstrap",
            post(crate::protocol::cluster_admin::admin_cluster_bootstrap),
        )
        .route(
            "/cluster/status",
            get(crate::protocol::cluster_admin::admin_cluster_status),
        )
        .route(
            "/cluster/transfer-leadership",
            post(crate::protocol::cluster_admin::admin_cluster_transfer_leadership),
        )
}

/// Pagination query parameters (also carries optional search query and field filters).
#[derive(Debug, Deserialize)]
pub(super) struct PaginationParams {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<usize>,
    pub(super) search: Option<String>,
    /// Exact email filter (case-insensitive, applied after normalisation).
    pub(super) email: Option<String>,
    /// Substring filter on `display_name` (case-insensitive).
    pub(super) username: Option<String>,
    /// Status filter: accepts `"active"`, `"disabled"`, or `"pending_verification"`.
    pub(super) status: Option<String>,
    /// Attribute filter in `key:value` form. Matches users whose custom attributes
    /// contain an entry where `attributes[key] == value` (exact, case-sensitive).
    pub(super) attr: Option<String>,
}

impl PaginationParams {
    /// Returns the limit clamped to [1, 100] with a default of 20.
    pub(super) fn effective_limit(&self) -> usize {
        self.limit.unwrap_or(20).clamp(1, 100)
    }

    /// Returns a `PageRequest` treating `cursor` as a decimal offset.
    pub(super) fn as_page_request(&self) -> crate::core::PageRequest {
        let offset: u64 = self
            .cursor
            .as_deref()
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        crate::core::PageRequest::new(offset, self.effective_limit() as u32)
    }
}

fn parse_realm_id(id: &str) -> Result<RealmId, Response> {
    id.parse::<uuid::Uuid>().map(RealmId::new).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid realm ID"})),
        )
            .into_response()
    })
}

fn require_realm(state: &AppState, realm_id: &RealmId) -> Result<crate::identity::Realm, Response> {
    match state.identity.get_realm(realm_id) {
        Ok(Some(r)) => Ok(r),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "realm not found"})),
        )
            .into_response()),
        Err(e) => Err(identity_error_to_response(&e).into_response()),
    }
}

/// Enforces realm-level object authorization (BOLA guard).
///
/// Returns `path_realm_id` when access is permitted:
/// - The **system realm** (nil UUID) is a superuser that may operate on any realm.
/// - Otherwise `auth.realm_id` must equal `path_realm_id` exactly.
///
/// Returns `403 Forbidden` in all other cases. Every handler that exposes a
/// `{realm_id}` path parameter **must** obtain the realm through this function
/// rather than using `path_realm_id` directly.
fn scoped_realm(auth: &AdminAuth, path_realm_id: RealmId) -> Result<RealmId, Response> {
    if auth.realm_id.as_uuid().is_nil() || auth.realm_id == path_realm_id {
        Ok(path_realm_id)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler implementations extracted verbatim from src/protocol/http.rs
// (lines 3330-3302 skipped: rbac_error_to_response stays in parent module;
//  PaginationParams defined above)
// ─────────────────────────────────────────────────────────────────────────────
async fn admin_list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }

    if let Some(q) = &params.search {
        // Short queries return empty results immediately (no index hit).
        if q.len() < 2 {
            return (
                StatusCode::OK,
                Json(serde_json::json!({"items": [], "next_cursor": null})),
            )
                .into_response();
        }
        return match state.identity.search_users(
            &auth.realm_id,
            q,
            &params.as_page_request(),
            None,
            crate::identity::search::SortDir::default(),
        ) {
            Ok(result) => {
                let items: Vec<serde_json::Value> = result
                    .items
                    .iter()
                    .map(|u| proto_to_rest_json(&pb::User::from(u)))
                    .collect();
                let next = result.offset + result.items.len() as u64;
                let next_cursor: Option<String> = if next < result.total {
                    Some(next.to_string())
                } else {
                    None
                };
                (
                    StatusCode::OK,
                    Json(serde_json::json!({"items": items, "next_cursor": next_cursor, "total": result.total})),
                )
                    .into_response()
            }
            Err(e) => identity_error_to_response(&e).into_response(),
        };
    }

    let has_field_filters = params.email.is_some()
        || params.username.is_some()
        || params.status.is_some()
        || params.attr.is_some();

    if has_field_filters {
        // Fast path: exact email-index lookup (O(1)) when only ?email= is given.
        // This exercises the hot-tier storage path without a full corpus scan,
        // making it suitable for tier-miss latency profiling (HEA-1876).
        if params.email.is_some()
            && params.username.is_none()
            && params.status.is_none()
            && params.attr.is_none()
        {
            let email_raw = params.email.as_deref().unwrap_or("");
            return match state.identity.get_user_by_email(&auth.realm_id, email_raw) {
                Ok(Some(user)) => {
                    let item = proto_to_rest_json(&pb::User::from(&user));
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({"items": [item], "next_cursor": null, "total": 1})),
                    )
                        .into_response()
                }
                Ok(None) => (
                    StatusCode::OK,
                    Json(serde_json::json!({"items": [], "next_cursor": null, "total": 0})),
                )
                    .into_response(),
                Err(e) => identity_error_to_response(&e).into_response(),
            };
        }

        // Parse the status filter value if provided.
        let status_filter = if let Some(s) = &params.status {
            let parsed = match s.as_str() {
                "active" => Some(crate::identity::UserStatus::Active),
                "disabled" => Some(crate::identity::UserStatus::Disabled),
                "pending_verification" => Some(crate::identity::UserStatus::PendingVerification),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid status filter; expected active, disabled, or pending_verification"})),
                    )
                        .into_response();
                }
            };
            parsed
        } else {
            None
        };

        // Full scan via offset pages up to a bounded cap, then apply predicates.
        // Filtered results don't support cursor pagination — next_cursor is always null.
        const FILTER_SCAN_CAP: usize = 10_000;
        let mut all_users: Vec<crate::identity::User> = Vec::new();
        let mut scan_offset = 0u64;
        loop {
            let batch = crate::core::MAX_PAGE_LIMIT;
            let scan_page = match state.identity.list_users(
                &auth.realm_id,
                &crate::core::PageRequest::new(scan_offset, batch),
            ) {
                Ok(p) => p,
                Err(e) => return identity_error_to_response(&e).into_response(),
            };
            let n = scan_page.items.len() as u64;
            all_users.extend(scan_page.items);
            if n == 0 || scan_offset + n >= scan_page.total || all_users.len() >= FILTER_SCAN_CAP {
                break;
            }
            scan_offset += n;
        }

        let email_norm = params.email.as_deref().map(|e| e.to_lowercase());
        let username_lower = params.username.as_deref().map(|u| u.to_lowercase());

        // Parse `?attr=key:value` — split on the first colon only so values may
        // contain colons (e.g. ISO timestamps or URLs).
        let attr_filter: Option<(String, String)> = params.attr.as_deref().and_then(|s| {
            let (k, v) = s.split_once(':')?;
            Some((k.to_owned(), v.to_owned()))
        });

        if params.attr.is_some() && attr_filter.is_none() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid attr filter; expected key:value format"
                })),
            )
                .into_response();
        }

        let items: Vec<serde_json::Value> = all_users
            .iter()
            .filter(|u| {
                if let Some(ref ef) = email_norm {
                    if u.email() != ef.as_str() {
                        return false;
                    }
                }
                if let Some(ref uf) = username_lower {
                    if !u.display_name().to_lowercase().contains(uf.as_str()) {
                        return false;
                    }
                }
                if let Some(sf) = status_filter {
                    if u.status() != sf {
                        return false;
                    }
                }
                if let Some((ref ak, ref av)) = attr_filter {
                    if u.attributes().get(ak.as_str()).map(String::as_str) != Some(av.as_str()) {
                        return false;
                    }
                }
                true
            })
            .take(params.effective_limit())
            .map(|u| proto_to_rest_json(&pb::User::from(u)))
            .collect();

        return (
            StatusCode::OK,
            Json(serde_json::json!({"items": items, "next_cursor": null})),
        )
            .into_response();
    }

    match state
        .identity
        .list_users(&auth.realm_id, &params.as_page_request())
    {
        Ok(page) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&user_page_to_proto(&page))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Import request body — one entry per user to import.
// A-47: admin request bodies use deny_unknown_fields to prevent silent
// extension-field bypass.  OAuth/OIDC protocol bodies (HttpTokenRequest,
// HttpRevocationBody, HttpParRequest) are exempt — RFC 6749 §3.2 allows
// extension parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportUsersBody {
    users: Vec<ImportUserEntry>,
}

/// Single user entry in a bulk import request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportUserEntry {
    email: String,
    display_name: String,
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    last_name: String,
    /// Accepts `"active"`, `"disabled"`, `"suspended"`, or `"pending_verification"`.
    status: Option<String>,
    #[serde(default)]
    attributes: std::collections::BTreeMap<String, String>,
}

/// Admin: bulk import users (`POST /admin/users/import`).
async fn admin_import_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ImportUsersBody>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }

    if body.users.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "users array must not be empty"})),
        )
            .into_response();
    }

    const MAX_BULK_IMPORT: usize = 10_000;
    if body.users.len() > MAX_BULK_IMPORT {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("batch size {n} exceeds maximum of {MAX_BULK_IMPORT}", n = body.users.len())})),
        )
            .into_response();
    }

    let mut imported = 0u32;
    let mut failed = 0u32;
    let mut results = Vec::with_capacity(body.users.len());

    for entry in &body.users {
        let status = match entry.status.as_deref().unwrap_or("active") {
            "active" => crate::identity::UserStatus::Active,
            "disabled" => crate::identity::UserStatus::Disabled,
            "pending_verification" => crate::identity::UserStatus::PendingVerification,
            other => {
                failed += 1;
                results.push(serde_json::json!({
                    "email": entry.email,
                    "error": format!("unknown status: {other}")
                }));
                continue;
            }
        };

        let req = crate::identity::ImportUserRequest {
            id: None,
            email: entry.email.clone(),
            display_name: entry.display_name.clone(),
            first_name: entry.first_name.clone(),
            last_name: entry.last_name.clone(),
            status,
            credential: None,
            attributes: entry.attributes.clone(),
        };

        match state.identity.import_user(&auth.realm_id, &req) {
            Ok(u) => {
                imported += 1;
                results.push(serde_json::json!({
                    "email": entry.email,
                    "id": u.id().as_uuid().to_string(),
                    "error": null
                }));
            }
            Err(e) => {
                failed += 1;
                results.push(serde_json::json!({
                    "email": entry.email,
                    "error": e.to_string()
                }));
            }
        }
    }

    let total = imported + failed;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "imported": imported,
            "failed": failed,
            "total": total,
            "results": results
        })),
    )
        .into_response()
}

/// Export format query parameter.
#[derive(Debug, Deserialize)]
struct ExportParams {
    format: Option<String>,
}

/// Admin: bulk export users (`GET /admin/users/export`).
///
/// Default format is JSON (`{"count": N, "users": [...]}`).
/// Pass `?format=ndjson` for newline-delimited JSON (one object per line).
async fn admin_export_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ExportParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }

    // A-30: require hearth.export capability.
    if let Err(e) = check_export_capability(&auth) {
        return e.into_response();
    }
    // A-30: per-export rate limit.
    if let Err(e) = check_export_rate_limit(&state, &auth.user_id) {
        return e.into_response();
    }
    // A-30: watermark this export.
    let export_id = uuid::Uuid::new_v4().to_string();
    emit_export_watermark(
        &state,
        &auth.realm_id,
        &auth.user_id,
        "users",
        None,
        &export_id,
    );

    // Collect all users by draining pages.
    let mut all_users: Vec<crate::identity::User> = Vec::new();
    let mut offset = 0u64;
    let batch = crate::core::MAX_PAGE_LIMIT;
    loop {
        let page = match state.identity.list_users(
            &auth.realm_id,
            &crate::core::PageRequest::new(offset, batch),
        ) {
            Ok(p) => p,
            Err(e) => return identity_error_to_response(&e).into_response(),
        };
        let n = page.items.len() as u64;
        all_users.extend(page.items);
        if n == 0 || offset + n >= page.total {
            break;
        }
        offset += n;
    }

    let user_to_json = |u: &crate::identity::User| -> serde_json::Value {
        let mut v = proto_to_rest_json(&pb::User::from(u));
        if !u.attributes().is_empty() {
            v["attributes"] = serde_json::json!(u.attributes());
        }
        v
    };

    let ndjson = params.format.as_deref() == Some("ndjson");
    if ndjson {
        let mut body = String::new();
        for u in &all_users {
            body.push_str(&serde_json::to_string(&user_to_json(u)).unwrap_or_default());
            body.push('\n');
        }
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
            body,
        )
            .into_response();
    }

    let users: Vec<serde_json::Value> = all_users.iter().map(user_to_json).collect();
    let count = users.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({"count": count, "users": users})),
    )
        .into_response()
}

/// Admin: create user.
async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::CreateUserRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }

    let request = crate::identity::CreateUserRequest::from(body);

    let identity = Arc::clone(&state.identity);
    let realm_id = auth.realm_id.clone();
    let admin_actor = auth.user_id.clone();
    // create_user hashes an Argon2id credential — route through the shared KDF
    // admission gate so bulk provisioning can't oversubscribe the blocking pool
    // and blow the peak-memory ceiling (HEA-1891 / F3).
    let result = match super::run_kdf_gated_rest(
        move || {
            let audit_ctx = AuditContext {
                actor: Actor::User(admin_actor),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            };
            identity.create_user_attributed(&realm_id, &request, &audit_ctx)
        },
        |e| {
            tracing::error!(error = %e, "admin_create_user KDF task failed");
            Err(crate::identity::IdentityError::Storage(Box::new(e)))
        },
    )
    .await
    {
        Ok(r) => r,
        Err(shed) => return shed,
    };

    match result {
        Ok(user) => (
            StatusCode::CREATED,
            Json(proto_to_rest_json(&pb::User::from(&user))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: get user by ID.
async fn admin_get_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }

    let user_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user ID"})),
            )
                .into_response()
        }
    };

    match state
        .identity
        .get_user(&auth.realm_id, &UserId::new(user_uuid))
    {
        Ok(Some(user)) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::User::from(&user))),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: update user by ID.
async fn admin_update_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<pb::UpdateUserRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }

    let user_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user ID"})),
            )
                .into_response()
        }
    };

    // Validate status if provided
    if let Some(status_val) = body.status {
        if proto_user_status_to_domain(status_val).is_none() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid status"})),
            )
                .into_response();
        }
    }

    let request = crate::identity::UpdateUserRequest::from(body);
    let uid = UserId::new(user_uuid);
    let audit_ctx = AuditContext {
        actor: Actor::User(auth.user_id.clone()),
        metadata: Some(serde_json::json!({"via": "admin_api"})),
    };

    match state
        .identity
        .update_user_attributed(&auth.realm_id, &uid, &request, &audit_ctx)
    {
        Ok(user) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::User::from(&user))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: delete user by ID.
async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }

    let user_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user ID"})),
            )
                .into_response()
        }
    };

    let audit_ctx = AuditContext {
        actor: Actor::User(auth.user_id.clone()),
        metadata: Some(serde_json::json!({"via": "admin_api"})),
    };

    match state
        .identity
        .delete_user_attributed(&auth.realm_id, &UserId::new(user_uuid), &audit_ctx)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: erase all device fingerprints for a user (GDPR Art. 17 / AC-11).
///
/// `DELETE /admin/users/{id}/device-fingerprints`
///
/// Satisfies DSAR erasure requests for biometric/device-signal data without
/// requiring deletion of the entire user account.  Returns `{ "erased": N }`.
async fn admin_delete_user_device_fingerprints(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }

    let user_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user ID"})),
            )
                .into_response()
        }
    };

    let user_id = UserId::new(user_uuid);

    match state
        .identity
        .delete_user_device_fingerprints(&auth.realm_id, &user_id)
    {
        Ok(erased) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::DeviceFingerprintsErased,
                resource_type: "user".to_string(),
                resource_id: user_uuid.to_string(),
                metadata: Some(serde_json::json!({
                    "via": "admin_api",
                    "count": erased,
                })),
            });
            (StatusCode::OK, Json(serde_json::json!({"erased": erased}))).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// HTTP request body for bulk user operations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpBulkUsersRequest {
    operation: String,
    #[serde(default)]
    users: Vec<pb::CreateUserRequest>,
    #[serde(default)]
    user_ids: Vec<String>,
}

/// Admin: bulk user operations (create or disable).
#[allow(clippy::too_many_lines)]
async fn admin_bulk_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpBulkUsersRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }

    match body.operation.as_str() {
        "create" => {
            let requests: Vec<crate::identity::CreateUserRequest> = body
                .users
                .into_iter()
                .map(crate::identity::CreateUserRequest::from)
                .collect();

            match state.identity.bulk_create_users(&auth.realm_id, &requests) {
                Ok(results) => {
                    let _ = state.audit.append(&CreateAuditEvent {
                        realm_id: auth.realm_id.clone(),
                        actor: auth.user_id.as_uuid().to_string(),
                        action: crate::audit::AuditAction::BulkUsersCreated,
                        resource_type: "user".to_string(),
                        resource_id: format!("batch:{}", results.len()),
                        metadata: Some(serde_json::json!({"via": "admin_api"})),
                    });

                    let proto_results: Vec<_> =
                        results.iter().map(user_bulk_result_to_proto).collect();

                    (
                        StatusCode::OK,
                        Json(proto_to_rest_json(&pb::BulkResult {
                            results: proto_results,
                        })),
                    )
                        .into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "disable" => {
            let mut user_ids = Vec::new();
            for id_str in &body.user_ids {
                match id_str.parse::<uuid::Uuid>() {
                    Ok(uuid) => user_ids.push(UserId::new(uuid)),
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "invalid user ID in list"})),
                        )
                            .into_response()
                    }
                }
            }

            match state.identity.bulk_disable_users(&auth.realm_id, &user_ids) {
                Ok(results) => {
                    let _ = state.audit.append(&CreateAuditEvent {
                        realm_id: auth.realm_id.clone(),
                        actor: auth.user_id.as_uuid().to_string(),
                        action: crate::audit::AuditAction::BulkUsersDisabled,
                        resource_type: "user".to_string(),
                        resource_id: format!("batch:{}", results.len()),
                        metadata: Some(serde_json::json!({"via": "admin_api"})),
                    });

                    let proto_results: Vec<_> =
                        results.iter().map(void_bulk_result_to_proto).collect();

                    (
                        StatusCode::OK,
                        Json(proto_to_rest_json(&pb::BulkResult {
                            results: proto_results,
                        })),
                    )
                        .into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid operation, expected 'create' or 'disable'"})),
        )
            .into_response(),
    }
}

/// Admin: list realms (paginated).
async fn admin_list_realms(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }

    match state.identity.list_realms(&params.as_page_request()) {
        Ok(page) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&realm_page_to_proto(&page))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: create realm — disabled; realms are managed via `hearth.yaml`.
async fn admin_create_realm() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({
            "error": "method_not_allowed",
            "message": "Realms are managed via hearth.yaml. Remove this endpoint from your client."
        })),
    )
}

/// Admin: get realm by ID.
async fn admin_get_realm(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }

    let realm_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid realm ID"})),
            )
                .into_response()
        }
    };

    let realm_id = match scoped_realm(&auth, RealmId::new(realm_uuid)) {
        Ok(r) => r,
        Err(e) => return e,
    };

    match state.identity.get_realm(&realm_id) {
        Ok(Some(realm)) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::Realm::from(&realm))),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: update realm — disabled; realms are managed via `hearth.yaml`.
async fn admin_update_realm(Path(_id): Path<String>) -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({
            "error": "method_not_allowed",
            "message": "Realms are managed via hearth.yaml. Remove this endpoint from your client."
        })),
    )
}

/// Admin: delete realm by ID.
///
/// Only allows permanent deletion of realms with `Archived` status.
/// Active or Suspended realms must first be removed from `hearth.yaml`
/// and the server restarted (which archives them via reconciliation).
async fn admin_delete_realm(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }

    let realm_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid realm ID"})),
            )
                .into_response()
        }
    };

    let tid = match scoped_realm(&auth, RealmId::new(realm_uuid)) {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Check realm status — only Archived realms can be permanently deleted.
    match state.identity.get_realm(&tid) {
        Ok(Some(realm))
            if realm.status() == crate::identity::RealmStatus::Archived =>
        {
            match state.identity.delete_realm(&tid) {
                Ok(()) => {
                    let _ = state.audit.append(&CreateAuditEvent {
                        realm_id: tid.clone(),
                        actor: auth.user_id.as_uuid().to_string(),
                        action: crate::audit::AuditAction::RealmDeleted,
                        resource_type: "realm".to_string(),
                        resource_id: realm_uuid.to_string(),
                        metadata: Some(serde_json::json!({"via": "admin_api"})),
                    });
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        Ok(Some(_)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "conflict",
                "message": "Only archived realms can be permanently deleted. Remove the realm from hearth.yaml and restart to archive it first."
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: PATCH required-actions for a specific user in a realm (HEA-807).
///
/// `PATCH /admin/realms/{realm_id}/users/{user_id}/required-actions`
///
/// Body: `{ "add": ["VERIFY_EMAIL"], "remove": [] }`
///
/// Validates action strings against the v1 allowlist, adds/removes from the
/// user's list atomically, emits one audit event per modified action, and
/// returns the updated user JSON.
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
async fn admin_patch_user_required_actions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((realm_id_str, user_id_str)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    use crate::audit::AuditAction;
    use crate::identity::{RequiredAction, UpdateUserRequest};

    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }

    let realm_uuid: uuid::Uuid = match realm_id_str.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid realm ID"})),
            )
                .into_response()
        }
    };
    let realm_id = RealmId::new(realm_uuid);

    if auth.realm_id != realm_id {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }

    let user_uuid: uuid::Uuid = match user_id_str.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user ID"})),
            )
                .into_response()
        }
    };
    let uid = UserId::new(user_uuid);

    // Parse and validate action string arrays from the request body.
    let parse_actions = |key: &str| -> Result<Vec<RequiredAction>, axum::response::Response> {
        let arr = body[key].as_array().cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(arr.len());
        for v in arr {
            match serde_json::from_value::<RequiredAction>(v.clone()) {
                Ok(a) => out.push(a),
                Err(_) => {
                    let s = v.as_str().unwrap_or("(non-string)");
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": format!("unknown action type: {s}")})),
                    )
                        .into_response());
                }
            }
        }
        Ok(out)
    };

    let add_actions = match parse_actions("add") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let remove_actions = match parse_actions("remove") {
        Ok(v) => v,
        Err(e) => return e,
    };

    let user = match state.identity.get_user(&realm_id, &uid) {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "user not found"})),
            )
                .into_response()
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let mut actions: Vec<RequiredAction> = user.required_actions().to_vec();
    for a in &add_actions {
        if !actions.contains(a) {
            actions.push(*a);
        }
    }
    actions.retain(|a| !remove_actions.contains(a));

    let updated = match state.identity.update_user(
        &realm_id,
        &uid,
        &UpdateUserRequest {
            required_actions: Some(actions),
            ..Default::default()
        },
    ) {
        Ok(u) => u,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let admin_id = auth.user_id.as_uuid().to_string();
    for a in &add_actions {
        let _ = state.audit.append(&CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: admin_id.clone(),
            action: AuditAction::RequiredActionAssigned,
            resource_type: "user".to_string(),
            resource_id: uid.as_uuid().to_string(),
            metadata: Some(serde_json::json!({
                "action_type": serde_json::to_value(a).unwrap_or(serde_json::Value::Null),
                "admin_id": admin_id,
                "via": "admin_api",
            })),
        });
    }
    for a in &remove_actions {
        let _ = state.audit.append(&CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: admin_id.clone(),
            action: AuditAction::RequiredActionRemoved,
            resource_type: "user".to_string(),
            resource_id: uid.as_uuid().to_string(),
            metadata: Some(serde_json::json!({
                "action_type": serde_json::to_value(a).unwrap_or(serde_json::Value::Null),
                "admin_id": admin_id,
                "via": "admin_api",
            })),
        });
    }

    (
        StatusCode::OK,
        Json(proto_to_rest_json(&pb::User::from(&updated))),
    )
        .into_response()
}

/// Admin: PATCH realm config — sets `default_required_actions` (HEA-807).
///
/// `PATCH /admin/realms/{realm_id}/config`
///
/// Body: `{ "default_required_actions": ["VERIFY_EMAIL"] }`
///
/// Replaces the realm's default required-actions list. Only affects users
/// created after this call. Unknown action strings return 400.
///
/// Optional fields applied only when present: `mfa_methods`,
/// `sms_otp_expiry_seconds`, `sms_otp_max_attempts`, `email_otp_expiry_seconds`,
/// `email_otp_max_attempts`, `fapi_profile` (`"baseline"`/`"advanced"`/`null`),
/// and `dcr_policy` (`"disabled"`/`"open"`/`"authenticated"`/`null`) — the
/// Dynamic Client Registration policy for `POST /register`.
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
async fn admin_patch_realm_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(realm_id_str): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    use crate::identity::{RequiredAction, UpdateRealmRequest};

    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }

    let realm_uuid: uuid::Uuid = match realm_id_str.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid realm ID"})),
            )
                .into_response()
        }
    };
    let realm_id = RealmId::new(realm_uuid);

    if auth.realm_id != realm_id {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }

    let action_strs = body["default_required_actions"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut actions: Vec<RequiredAction> = Vec::with_capacity(action_strs.len());
    for v in action_strs {
        match serde_json::from_value::<RequiredAction>(v.clone()) {
            Ok(a) => actions.push(a),
            Err(_) => {
                let s = v.as_str().unwrap_or("(non-string)");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("unknown action type: {s}")})),
                )
                    .into_response();
            }
        }
    }

    let realm = match state.identity.get_realm(&realm_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "realm not found"})),
            )
                .into_response()
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let mut config = realm.config().clone();
    config.default_required_actions = actions;

    // Optional fields: apply only when present in the JSON body.
    if let Some(methods) = body["mfa_methods"].as_array() {
        let strs: Vec<String> = methods
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        config.mfa_methods = if strs.is_empty() { None } else { Some(strs) };
    }
    if let Some(v) = body["sms_otp_expiry_seconds"].as_u64() {
        config.sms_otp_expiry_seconds = Some(v);
    }
    if let Some(v) = body["sms_otp_max_attempts"].as_u64() {
        #[allow(clippy::cast_possible_truncation)]
        {
            config.sms_otp_max_attempts = Some(v as u32);
        }
    }
    if let Some(v) = body["email_otp_expiry_seconds"].as_u64() {
        config.email_otp_expiry_seconds = Some(v);
    }
    if let Some(v) = body["email_otp_max_attempts"].as_u64() {
        #[allow(clippy::cast_possible_truncation)]
        {
            config.email_otp_max_attempts = Some(v as u32);
        }
    }
    if let Some(v) = body.get("fapi_profile") {
        use crate::identity::FapiProfile;
        if v.is_null() {
            config.fapi_profile = None;
        } else if let Some(s) = v.as_str() {
            match s {
                "baseline" => config.fapi_profile = Some(FapiProfile::Baseline),
                "advanced" => config.fapi_profile = Some(FapiProfile::Advanced),
                other => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("unknown fapi_profile value {other:?}; expected \"baseline\", \"advanced\", or null")
                        })),
                    )
                        .into_response();
                }
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "fapi_profile must be a string or null"
                })),
            )
                .into_response();
        }
    }
    if let Some(v) = body.get("dcr_policy") {
        use crate::identity::DcrPolicy;
        if v.is_null() {
            config.dcr_policy = None;
        } else if let Some(s) = v.as_str() {
            match s {
                "disabled" => config.dcr_policy = Some(DcrPolicy::Disabled),
                "open" => config.dcr_policy = Some(DcrPolicy::Open),
                "authenticated" => config.dcr_policy = Some(DcrPolicy::Authenticated),
                other => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("unknown dcr_policy value {other:?}; expected \"disabled\", \"open\", \"authenticated\", or null")
                        })),
                    )
                        .into_response();
                }
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "dcr_policy must be a string or null"
                })),
            )
                .into_response();
        }
    }

    match state.identity.update_realm(
        &realm_id,
        &UpdateRealmRequest {
            config: Some(config),
            ..Default::default()
        },
    ) {
        Ok(updated) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::Realm::from(&updated))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: rotate the Ed25519 signing key for a realm.
///
/// Generates a new key, promotes it to the active key, and keeps the old key
/// in the JWKS response for the configured grace period (default 24 h) so
/// tokens signed with the old key remain valid during that window.
async fn admin_rotate_realm_signing_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }

    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let realm_id = match scoped_realm(&auth, realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let _ = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let grace_period_secs = state.signing_key_rotation_grace_period_secs;

    match state
        .identity
        .rotate_realm_signing_key(&realm_id, grace_period_secs)
    {
        Ok(()) => {
            let _ = state.audit.append(&crate::audit::CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::RealmUpdated,
                resource_type: "realm".to_string(),
                resource_id: realm_id.as_uuid().to_string(),
                metadata: Some(serde_json::json!({"action": "rotate_signing_key", "grace_period_secs": grace_period_secs})),
            });
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": "signing key rotated",
                    "grace_period_secs": grace_period_secs
                })),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Realm branding & email-template admin API
// ---------------------------------------------------------------------------

/// Request body for `PATCH /realms/{id}/branding`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchRealmBrandingRequest {
    #[serde(default)]
    logo_url: Option<String>,
    #[serde(default)]
    primary_color: Option<String>,
    /// Email-level branding (accent_color, support_email, custom_footer_text).
    #[serde(default)]
    email_branding: Option<EmailBranding>,
}

/// Response body for `GET /realms/{id}/branding`.
#[derive(Debug, Serialize)]
struct RealmBrandingResponse {
    logo_url: Option<String>,
    primary_color: Option<String>,
    email_branding: Option<EmailBranding>,
}

/// `GET /realms/{id}/branding` — return current per-realm branding settings.
async fn admin_get_realm_branding(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm_id = match scoped_realm(&auth, realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let cfg = realm.config();
    (
        StatusCode::OK,
        Json(RealmBrandingResponse {
            logo_url: cfg.logo_url.clone(),
            primary_color: cfg.primary_color.clone(),
            email_branding: cfg.email_branding.clone(),
        }),
    )
        .into_response()
}

/// `PATCH /realms/{id}/branding` — update per-realm branding settings.
///
/// Only fields present in the request body are updated; omitted fields are
/// left unchanged. Use `null` to clear a previously-set value.
async fn admin_patch_realm_branding(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PatchRealmBrandingRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm_id = match scoped_realm(&auth, realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Validate hex color format if provided.
    if let Some(color) = body.primary_color.as_deref() {
        if !color.starts_with('#') || (color.len() != 4 && color.len() != 7) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "invalid_color",
                    "message": "primary_color must be a CSS hex color (#RGB or #RRGGBB)"
                })),
            )
                .into_response();
        }
    }

    let mut new_config = realm.config().clone();
    // Merge: explicit `Some` overwrites; `None` in request body clears.
    // The PATCH semantics here treat the request as a partial update where
    // serde's `#[serde(default)]` delivers `None` for absent fields — so
    // we only overwrite when the caller explicitly sent the field.
    // Use JSON `null` to explicitly clear a field.
    if body.logo_url.is_some() {
        new_config.logo_url = body.logo_url;
    }
    if body.primary_color.is_some() {
        new_config.primary_color = body.primary_color;
    }
    if body.email_branding.is_some() {
        new_config.email_branding = body.email_branding;
    }

    match state.identity.update_realm(
        &realm_id,
        &UpdateRealmRequest {
            config: Some(new_config),
            ..UpdateRealmRequest::default()
        },
    ) {
        Ok(updated) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::RealmUpdated,
                resource_type: "realm".to_string(),
                resource_id: realm_id.as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api", "op": "patch_branding"})),
            });
            let cfg = updated.config();
            (
                StatusCode::OK,
                Json(RealmBrandingResponse {
                    logo_url: cfg.logo_url.clone(),
                    primary_color: cfg.primary_color.clone(),
                    email_branding: cfg.email_branding.clone(),
                }),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `GET /realms/{id}/email-templates` — list all stored template overrides.
async fn admin_list_realm_email_templates(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm_id = match scoped_realm(&auth, realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    (StatusCode::OK, Json(realm.config().email_templates.clone())).into_response()
}

/// `GET /realms/{id}/email-templates/{kind}` — get a single stored template.
async fn admin_get_realm_email_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, kind)): Path<(String, String)>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm_id = match scoped_realm(&auth, realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    match realm.config().email_templates.get(&kind) {
        Some(tmpl) => (StatusCode::OK, Json(tmpl.clone())).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "template not found"})),
        )
            .into_response(),
    }
}

/// `PUT /realms/{id}/email-templates/{kind}` — upsert a stored template.
///
/// Validates that all `{{placeholder}}` tokens in the body are in the
/// allowlist for the given template kind before persisting.
async fn admin_put_realm_email_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, kind)): Path<(String, String)>,
    Json(body): Json<LocalizedEmailTemplate>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm_id = match scoped_realm(&auth, realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Validate template kind and placeholders in all body fields.
    let fields_to_validate: Vec<(&str, &str)> = {
        let mut v = Vec::new();
        if let Some(ref s) = body.default.subject {
            v.push(("default.subject", s.as_str()));
        }
        if let Some(ref s) = body.default.html_body {
            v.push(("default.html_body", s.as_str()));
        }
        if let Some(ref s) = body.default.text_body {
            v.push(("default.text_body", s.as_str()));
        }
        for (locale, lb) in &body.locales {
            if let Some(ref s) = lb.subject {
                v.push((locale.as_str(), s.as_str()));
            }
            if let Some(ref s) = lb.html_body {
                v.push((locale.as_str(), s.as_str()));
            }
            if let Some(ref s) = lb.text_body {
                v.push((locale.as_str(), s.as_str()));
            }
        }
        v
    };

    for (_field, text) in &fields_to_validate {
        if let Err(e) = validate_email_template(&kind, text) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "invalid_template",
                    "message": format!("{e}")
                })),
            )
                .into_response();
        }
    }

    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let mut new_config = realm.config().clone();
    new_config.email_templates.insert(kind.clone(), body);

    match state.identity.update_realm(
        &realm_id,
        &UpdateRealmRequest {
            config: Some(new_config),
            ..UpdateRealmRequest::default()
        },
    ) {
        Ok(updated) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::RealmUpdated,
                resource_type: "realm".to_string(),
                resource_id: realm_id.as_uuid().to_string(),
                metadata: Some(
                    serde_json::json!({"via": "admin_api", "op": "put_email_template", "kind": kind}),
                ),
            });
            match updated.config().email_templates.get(&kind) {
                Some(tmpl) => (StatusCode::OK, Json(tmpl.clone())).into_response(),
                None => StatusCode::NO_CONTENT.into_response(),
            }
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `DELETE /realms/{id}/email-templates/{kind}` — remove a stored template override.
async fn admin_delete_realm_email_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, kind)): Path<(String, String)>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm_id = match scoped_realm(&auth, realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if !realm.config().email_templates.contains_key(&kind) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "template not found"})),
        )
            .into_response();
    }
    let mut new_config = realm.config().clone();
    new_config.email_templates.remove(&kind);

    match state.identity.update_realm(
        &realm_id,
        &UpdateRealmRequest {
            config: Some(new_config),
            ..UpdateRealmRequest::default()
        },
    ) {
        Ok(_) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::RealmUpdated,
                resource_type: "realm".to_string(),
                resource_id: realm_id.as_uuid().to_string(),
                metadata: Some(
                    serde_json::json!({"via": "admin_api", "op": "delete_email_template", "kind": kind}),
                ),
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: list clients (paginated).
async fn admin_list_clients(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.clients.admin") {
        return e.into_response();
    }

    match state
        .identity
        .list_clients(&auth.realm_id, &params.as_page_request())
    {
        Ok(page) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&client_page_to_proto(&page))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: register a new client.
async fn admin_register_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::RegisterClientRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.clients.admin") {
        return e.into_response();
    }

    let mut request = crate::identity::RegisterClientRequest::from(body);
    request.client_secret = None;

    match state.identity.register_client(&auth.realm_id, &request) {
        Ok(client) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::ClientRegistered,
                resource_type: "client".to_string(),
                resource_id: client.client_id().as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            (
                StatusCode::CREATED,
                Json(proto_to_rest_json(&pb::OAuthClient::from(&client))),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: get client by ID.
async fn admin_get_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.clients.admin") {
        return e.into_response();
    }

    let client_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client ID"})),
            )
                .into_response()
        }
    };

    match state
        .identity
        .get_client(&auth.realm_id, &ClientId::new(client_uuid))
    {
        Ok(Some(client)) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::OAuthClient::from(&client))),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// JSON body for `PUT /admin/applications/{id}`.
///
/// Extends the proto `UpdateClientRequest` with logout URI fields that are
/// not (yet) in the proto schema.
#[derive(Debug, Deserialize, Default)]
struct AdminUpdateClientBody {
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    /// Back-channel logout URI. `null` clears it; omit to leave unchanged.
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    backchannel_logout_uri: Option<Option<String>>,
    /// Front-channel logout URI. `null` clears it; omit to leave unchanged.
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    frontchannel_logout_uri: Option<Option<String>>,
    /// Replaces the allowed post-logout redirect URI list.
    post_logout_redirect_uris: Option<Vec<String>>,
    /// Whether user consent is required for this client. `true` for
    /// third-party apps; `false` for trusted first-party clients.
    require_consent: Option<bool>,
    /// Access-token authorization mode. `null`/omitted leaves unchanged.
    access_token_authorization: Option<String>,
    /// Per-client MFA requirement. `true` forces MFA enrollment for all users
    /// of this client. `null`/omitted leaves unchanged.
    #[serde(default)]
    mfa_required: Option<bool>,
    /// Replaces the CORS allowed origins list. `null`/omitted leaves unchanged;
    /// `[]` clears all CORS origins.
    cors_origins: Option<Vec<String>>,
}

/// Deserializes an optional nullable string field.
///
/// - Field absent → `None` (leave unchanged)
/// - `null` → `Some(None)` (clear the field)
/// - `"uri"` → `Some(Some("uri"))` (set to value)
fn deserialize_nullable_string<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    // Option<Option<String>> naturally handles null vs absent vs string.
    Option::<Option<String>>::deserialize(d)
}

/// Admin: update client by ID.
async fn admin_update_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AdminUpdateClientBody>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.clients.admin") {
        return e.into_response();
    }

    let client_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client ID"})),
            )
                .into_response()
        }
    };

    use crate::identity::oidc::AccessTokenAuthorization;
    let access_token_authorization = body.access_token_authorization.as_deref().map(|s| match s {
        "introspection" => AccessTokenAuthorization::Introspection,
        "decision" => AccessTokenAuthorization::Decision,
        _ => AccessTokenAuthorization::Embedded,
    });
    let request = crate::identity::UpdateClientRequest {
        client_name: body.client_name,
        redirect_uris: if body.redirect_uris.is_empty() {
            None
        } else {
            Some(body.redirect_uris)
        },
        grant_types: if body.grant_types.is_empty() {
            None
        } else {
            Some(body.grant_types)
        },
        backchannel_logout_uri: body.backchannel_logout_uri,
        frontchannel_logout_uri: body.frontchannel_logout_uri,
        post_logout_redirect_uris: body.post_logout_redirect_uris,
        require_consent: body.require_consent,
        access_token_authorization,
        mfa_required: body.mfa_required.map(Some),
        cors_origins: body.cors_origins,
        ..Default::default()
    };

    match state
        .identity
        .update_client(&auth.realm_id, &ClientId::new(client_uuid), &request)
    {
        Ok(client) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::ClientUpdated,
                resource_type: "client".to_string(),
                resource_id: client_uuid.to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            (
                StatusCode::OK,
                Json(proto_to_rest_json(&pb::OAuthClient::from(&client))),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: delete client by ID.
async fn admin_delete_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.clients.admin") {
        return e.into_response();
    }

    let client_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client ID"})),
            )
                .into_response()
        }
    };

    match state
        .identity
        .delete_client(&auth.realm_id, &ClientId::new(client_uuid))
    {
        Ok(()) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::ClientDeleted,
                resource_type: "client".to_string(),
                resource_id: client_uuid.to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Audit Endpoint ===

/// Query params for `GET /admin/audit`.
#[derive(Debug, Deserialize)]
struct AuditQueryParams {
    /// Filter by actor UUID (as string).
    actor: Option<String>,
    /// Filter by action name (e.g. `user_created`).
    action: Option<String>,
    /// Start of time window (inclusive, Unix micros).
    start_time: Option<i64>,
    /// End of time window (exclusive, Unix micros).
    end_time: Option<i64>,
    /// Maximum number of events to return (default 50).
    limit: Option<usize>,
}

/// `GET /admin/audit` — queries the audit log.
async fn admin_list_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<AuditQueryParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }

    let action = params
        .action
        .as_deref()
        .and_then(|s| s.parse::<crate::audit::AuditAction>().ok());

    let query = crate::audit::AuditQuery {
        realm_id: auth.realm_id.clone(),
        start_time: params.start_time.map(crate::core::Timestamp::from_micros),
        end_time: params.end_time.map(crate::core::Timestamp::from_micros),
        actor: params.actor,
        action,
        limit: Some(params.limit.unwrap_or(50).min(200)),
        agent_id: None,
        tool: None,
    };

    match state.audit.query(&query) {
        Ok(events) => (
            StatusCode::OK,
            Json(serde_json::json!({ "events": events })),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "audit query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "audit query failed"})),
            )
                .into_response()
        }
    }
}

// === OAuth Consent (self-service + admin) ===

/// `GET /oauth/consents` — lists the current user's consents.
async fn admin_list_user_consents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(user_id_str): axum::extract::Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }
    let Ok(uuid) = user_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid user_id"})),
        )
            .into_response();
    };
    let user_id = UserId::new(uuid);
    match state
        .identity
        .list_consents_by_user(&auth.realm_id, &user_id)
    {
        Ok(entries) => {
            let body = serde_json::json!({
                "items": entries.iter().map(|e| serde_json::json!({
                    "client_id": e.record.client_id.as_uuid().to_string(),
                    "client_name": e.client_name,
                    "client_logo_url": e.client_logo_url,
                    "scopes": e.record.granted_scopes,
                    "granted_at": e.record.granted_at.as_micros(),
                    "updated_at": e.record.updated_at.as_micros(),
                })).collect::<Vec<_>>(),
            });
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `DELETE /admin/users/{id}/consents/{client_id}` — admin revoke on
/// behalf of a user.
async fn admin_revoke_user_consent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path((user_id_str, client_id_str)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }
    let Ok(uuid_u) = user_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid user_id"})),
        )
            .into_response();
    };
    let Ok(uuid_c) = client_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid client_id"})),
        )
            .into_response();
    };
    let user_id = UserId::new(uuid_u);
    let client_id = crate::core::ClientId::new(uuid_c);
    match state
        .identity
        .revoke_consent(&auth.realm_id, &user_id, &client_id)
    {
        Ok(()) => {
            let _ = state.audit.append(&crate::audit::CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::ConsentRevoked,
                resource_type: "oauth_client".to_string(),
                resource_id: client_id.as_uuid().to_string(),
                metadata: Some(serde_json::json!({
                    "via": "admin",
                    "target_user": user_id.as_uuid().to_string(),
                    "client_id": client_id.as_uuid().to_string(),
                })),
            });
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}
/// Response body for effective-permissions endpoints.
#[derive(Debug, serde::Serialize)]
struct MePermissionsResponse {
    roles: Vec<String>,
    groups: Vec<String>,
    permissions: Vec<String>,
    scope: Option<String>,
}

/// `GET /admin/users/{id}/effective-permissions` — resolves the effective
/// roles, groups, and permissions for a given user in the admin's realm.
///
/// Accepts optional `org_id` and `scope` query parameters. Returns the
/// same response shape as `GET /v1/me/permissions` but scoped to an
/// arbitrary user (admin-only).
async fn admin_get_user_effective_permissions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(user_id_str): axum::extract::Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }
    let Ok(uuid) = user_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid user_id"})),
        )
            .into_response();
    };
    let user_id = UserId::new(uuid);

    // Precheck: the target user must exist in the admin's realm.
    match state.identity.get_user(&auth.realm_id, &user_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "not found"})),
            )
                .into_response();
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    }

    let org_id = match params.get("org_id") {
        Some(s) => {
            let stripped = s.strip_prefix("org_").unwrap_or(s);
            match uuid::Uuid::parse_str(stripped) {
                Ok(u) => Some(crate::core::OrganizationId::new(u)),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid org_id"})),
                    )
                        .into_response();
                }
            }
        }
        None => None,
    };
    let scope = params.get("scope").cloned();

    let resolved = match state.rbac.resolve_permissions(
        &user_id,
        &auth.realm_id,
        org_id.as_ref(),
        scope.as_deref(),
    ) {
        Ok(r) => r,
        Err(e) => return rbac_error_to_response(&e).into_response(),
    };

    (
        StatusCode::OK,
        Json(MePermissionsResponse {
            roles: resolved.roles,
            groups: resolved.groups,
            permissions: resolved
                .permissions
                .into_iter()
                .map(|p| p.into_string())
                .collect(),
            scope,
        }),
    )
        .into_response()
}

// === Dev Bootstrap Endpoint ===

/// Generates a random 32-character alphanumeric password using the OS CSPRNG.
/// `GET /dev/probe-user?realm_id={uuid}&email={email}` — dev-mode-only storage
/// latency probe for the tier-miss load sweep (C8, HEA-1876).
///
/// Performs a hot-tier-aware indexed user lookup (`get_user_by_email`) and
/// returns 200 OK whether or not the user exists. No bearer token is required;
/// the route is unregistered in production so it cannot be fingerprinted or
/// reached in a non-dev deployment. The loopback-only bind constraint (enforced
/// at config validation) ensures only local processes can reach this endpoint.
pub(super) async fn dev_probe_user(
    State(state): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let realm_str = match params.get("realm_id") {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing realm_id"})),
            )
                .into_response()
        }
    };
    let email = match params.get("email") {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing email"})),
            )
                .into_response()
        }
    };
    let realm_uuid = match realm_str.parse::<uuid::Uuid>() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid realm_id"})),
            )
                .into_response()
        }
    };
    let realm_id = crate::core::RealmId::new(realm_uuid);
    // Drive the same two-step indexed storage lookup that ROPC used, so the
    // hot-vs-cold tier split is visible in the latency distribution.
    let _result = state.identity.get_user_by_email(&realm_id, email);
    // Return 200 regardless of found/not-found — the measurement is latency,
    // not correctness. A missing user (e.g. index > corpus_size) contributes
    // a fast cached-miss path, which is fine noise for the sweep.
    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

/// POST /dev/seed-session — creates a raw session record for the given user.
///
/// Dev-only: the route is registered only when the server runs with `--dev`.
/// Used by the load-test seed harness so `--sessions-frac > 0` can create real
/// session records without re-introducing ROPC (removed by HEA-1862, HEA-1907).
///
/// Required headers: `X-Realm-ID: <realm-uuid>`
/// Request body:  `{"user_id": "<user-uuid>"}`
/// Response body: `{"session_id": "<session-uuid>"}`
pub(super) async fn dev_seed_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DevSeedSessionRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_uuid = match body.user_id.parse::<uuid::Uuid>() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user_id"})),
            )
                .into_response()
        }
    };
    let user_id = UserId::new(user_uuid);
    match state.identity.create_session(
        &realm_id,
        &user_id,
        &crate::identity::SessionContext::default(),
    ) {
        Ok(session) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"session_id": session.id().as_uuid().to_string()})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct DevSeedSessionRequest {
    user_id: String,
}

/// POST /dev/seed-token — creates a session and issues an access token for the given user.
///
/// Dev-only: the route is registered only when the server runs with `--dev`.
/// Used by the load-test harness to populate a live token corpus (seed step)
/// and to mint tokens dynamically during issuance + revoke journeys, without
/// re-introducing ROPC (removed by HEA-1862, fixed by HEA-1991).
///
/// Required headers: `X-Realm-ID: <realm-uuid>`
/// Request body:  `{"user_id": "<user-uuid>"}`
/// Response body: `{"access_token": "<jwt>"}`
pub(super) async fn dev_seed_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DevSeedTokenRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_uuid = match body.user_id.parse::<uuid::Uuid>() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user_id"})),
            )
                .into_response()
        }
    };
    let user_id = UserId::new(user_uuid);
    let session = match state.identity.create_session(
        &realm_id,
        &user_id,
        &crate::identity::SessionContext::default(),
    ) {
        Ok(s) => s,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };
    match state
        .identity
        .issue_tokens(&realm_id, &user_id, session.id())
    {
        Ok(tokens) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"access_token": tokens.access_token()})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct DevSeedTokenRequest {
    user_id: String,
}

/// POST /dev/seed-password — sets a password credential on the given user.
///
/// Dev-only: the route is registered only when the server runs with `--dev`.
/// Used by the load-test seed harness to provision the login / KDF saturation
/// plane, which drives `POST /ui/realms/{realm}/login` (Argon2id `verify_password`)
/// against the seeded corpus. The plain admin `POST /admin/users` path has no way
/// to set a credential, so users would otherwise have no password to log in with
/// (HEA-1998). The password is applied via the same `set_password` primitive the
/// admin UI uses, so a subsequent login succeeds.
///
/// Because `set_password` revokes all of the user's existing sessions (A-42
/// credential-change revocation), the seeder MUST call this **before** minting
/// tokens/sessions for the user, or the read-plane corpus would be wiped.
///
/// Required headers: `X-Realm-ID: <realm-uuid>`
/// Request body:  `{"user_id": "<user-uuid>", "password": "<cleartext>"}`
/// Response: `204 No Content` on success.
pub(super) async fn dev_seed_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DevSeedPasswordRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_uuid = match body.user_id.parse::<uuid::Uuid>() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user_id"})),
            )
                .into_response()
        }
    };
    let user_id = UserId::new(user_uuid);
    let password = crate::identity::CleartextPassword::from_string(body.password);
    match state.identity.set_password(&realm_id, &user_id, &password) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct DevSeedPasswordRequest {
    user_id: String,
    password: String,
}

/// Fixed dev-mode password for `admin@hearth.test`.
///
/// Using a stable value (rather than a random one) lets the Playwright UI
/// test suite log in without needing to propagate the password through the
/// bootstrap response. Acceptable in dev mode; `admin_bootstrap` is a 404
/// in production.
pub(super) const DEV_SYSTEM_ADMIN_PASSWORD: &str = "HearthTest123!";

/// Seeds a system-realm admin user (`admin@hearth.test`) the first time a dev
/// server is bootstrapped. Returns `Some(password)` when the user was newly
/// created (caller should include it in the response). Returns `None` if the
/// user already existed — the existing password is left untouched.
///
/// Best-effort: logs on error but never returns a failure to the caller.
fn dev_seed_system_admin(state: &AppState) -> Option<String> {
    let sys = crate::identity::keys::system_realm_id();

    // Ensure the system realm has RBAC roles seeded.
    if let Err(e) = state.rbac.seed_realm(&sys) {
        tracing::warn!(error = %e, "dev bootstrap: RBAC seed for system realm failed");
        return None;
    }

    // If the user already exists, leave the password unchanged. Re-bootstrap
    // only issues fresh tokens — it never resets credentials (HEA-1670).
    match state.identity.get_user_by_email(&sys, "admin@hearth.test") {
        Ok(Some(_)) => return None,
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, "dev bootstrap: system realm user lookup failed");
            return None;
        }
    }

    let admin = match state
        .identity
        .create_admin_user(&crate::identity::CreateUserRequest {
            email: "admin@hearth.test".to_string(),
            display_name: "Dev Admin".to_string(),
            ..Default::default()
        }) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "dev bootstrap: system realm user creation failed");
            return None;
        }
    };

    // Ensure the account is Active regardless of server default_status config,
    // so dev logins work without completing email verification.
    let _ = state.identity.update_user(
        &sys,
        admin.id(),
        &crate::identity::UpdateUserRequest {
            status: Some(crate::identity::UserStatus::Active),
            ..Default::default()
        },
    );

    let password = DEV_SYSTEM_ADMIN_PASSWORD.to_string();
    let pwd = crate::identity::CleartextPassword::from_string(password.clone());
    if let Err(e) = state.identity.set_password(&sys, admin.id(), &pwd) {
        tracing::warn!(error = %e, "dev bootstrap: system realm password set failed");
        return None;
    }

    let role = match state.rbac.get_role_by_name(&sys, "realm.admin") {
        Ok(Some(r)) => r,
        Ok(None) => {
            tracing::warn!("dev bootstrap: realm.admin role missing from system realm");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "dev bootstrap: system realm role lookup failed");
            return None;
        }
    };

    if let Err(e) = state.rbac.assign_role(
        &sys,
        &AssignRoleRequest {
            subject: Subject::User(admin.id().clone()),
            role_id: role.id.clone(),
            scope: Scope::Realm,
            assigned_by: None,
        },
    ) {
        tracing::warn!(error = %e, "dev bootstrap: system realm role assignment failed");
    }

    Some(password)
}

/// Issues a fresh access token for the reserved system-realm admin
/// (`admin@hearth.test`, nil-UUID realm) seeded by [`dev_seed_system_admin`].
///
/// The returned token carries the `realm.admin` permission set and is scoped to
/// the nil-UUID system realm, so it can manage **any** realm cross-realm — the
/// `scoped_realm` BOLA guard only permits cross-realm operations for a nil-realm
/// token. Bootstrap hands this back so SDK / integration consumers have a
/// credential that can actually perform cross-realm admin (e.g. rotate another
/// realm's signing key), which the dev-realm `access_token` cannot (HEA-2087).
///
/// Best-effort: logs on error and returns `None` rather than failing bootstrap.
/// Call [`dev_seed_system_admin`] first to guarantee the admin user exists.
fn dev_system_admin_token(state: &AppState) -> Option<String> {
    let sys = crate::identity::keys::system_realm_id();
    let admin = match state.identity.get_user_by_email(&sys, "admin@hearth.test") {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!("dev bootstrap: system admin missing; cannot mint system token");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "dev bootstrap: system admin lookup failed");
            return None;
        }
    };
    let session = match state.identity.create_session(
        &sys,
        admin.id(),
        &crate::identity::SessionContext::default(),
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "dev bootstrap: system admin session creation failed");
            return None;
        }
    };
    match state.identity.issue_tokens(&sys, admin.id(), session.id()) {
        Ok(tokens) => Some(tokens.access_token().to_string()),
        Err(e) => {
            tracing::warn!(error = %e, "dev bootstrap: system admin token issuance failed");
            None
        }
    }
}

/// POST /admin/bootstrap — creates a realm, admin user, session, assigns
/// the admin role, and issues tokens. Returns everything needed for SDK tests.
///
/// Only available when `AppState.dev_mode` is `true` (i.e., `--dev` flag).
/// Returns 404 in production mode.
///
/// First call: creates the dev-realm and system admin; `admin_password` is
/// returned once in the response body. Subsequent calls (re-bootstrap) require
/// a valid Bearer token and do NOT change the existing admin password (HEA-1670).
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub(super) async fn admin_bootstrap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.dev_mode {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response();
    }

    // Create realm — or refresh tokens if it already exists.
    // The dev-realm is persistent across server restarts; access tokens expire
    // in 15 minutes, so callers must be able to get fresh tokens without
    // wiping state. On DuplicateRealmName we look up the existing realm and
    // admin user, create a new session, and return fresh tokens as 200 OK.
    // Re-bootstrap requires an existing valid Bearer token (HEA-1670).
    let realm = match state
        .identity
        .create_realm(&crate::identity::CreateRealmRequest {
            name: "dev-realm".to_string(),
            config: None,
        }) {
        Ok(t) => t,
        Err(crate::identity::IdentityError::DuplicateRealmName) => {
            // Dev-realm already exists — this is a re-bootstrap. Require a
            // valid Bearer token issued during the first bootstrap (HEA-1670).
            let bearer = match super::auth::extract_bearer_token(&headers) {
                Ok(t) => t,
                Err(e) => return e.into_response(),
            };
            let existing = match state.identity.get_realm_by_name("dev-realm") {
                Ok(Some(r)) => r,
                Ok(None) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "dev-realm missing after duplicate signal"})),
                    )
                        .into_response();
                }
                Err(e) => return identity_error_to_response(&e).into_response(),
            };
            let rid = existing.id().clone();

            // Validate the Bearer token against the dev-realm to confirm the
            // caller completed the first bootstrap.
            if state.identity.validate_token(&rid, &bearer).is_err() {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "invalid or expired token"})),
                )
                    .into_response();
            }

            // Reconciliation archives realms not in hearth.yaml. Re-activate
            // the dev-realm so create_session doesn't reject it as non-Active.
            if existing.status() != crate::identity::RealmStatus::Active {
                if let Err(e) = state.identity.update_realm(
                    &rid,
                    &crate::identity::UpdateRealmRequest {
                        status: Some(crate::identity::RealmStatus::Active),
                        ..Default::default()
                    },
                ) {
                    return identity_error_to_response(&e).into_response();
                }
            }

            let admin = match state.identity.get_user_by_email(&rid, "admin@dev.local") {
                Ok(Some(u)) => u,
                Ok(None) => {
                    // User was deleted while dev-realm survived — re-create idempotently
                    // so callers never need to wipe data just to re-bootstrap.
                    let _ = state.rbac.seed_realm(&rid);
                    let new_user = match state.identity.create_user(
                        &rid,
                        &crate::identity::CreateUserRequest {
                            email: "admin@dev.local".to_string(),
                            display_name: "Dev Admin".to_string(),
                            ..Default::default()
                        },
                    ) {
                        Ok(u) => u,
                        Err(e) => return identity_error_to_response(&e).into_response(),
                    };
                    let new_uid = new_user.id().clone();
                    let _ = state.identity.update_user(
                        &rid,
                        &new_uid,
                        &crate::identity::UpdateUserRequest {
                            status: Some(crate::identity::UserStatus::Active),
                            ..Default::default()
                        },
                    );
                    let dev_pwd = crate::identity::CleartextPassword::from_string(
                        "HearthDev123!".to_string(),
                    );
                    let _ = state.identity.set_password(&rid, &new_uid, &dev_pwd);
                    if let Ok(Some(admin_role)) = state.rbac.get_role_by_name(&rid, "realm.admin") {
                        let _ = state.rbac.assign_role(
                            &rid,
                            &AssignRoleRequest {
                                subject: Subject::User(new_uid.clone()),
                                role_id: admin_role.id.clone(),
                                scope: Scope::Realm,
                                assigned_by: None,
                            },
                        );
                    }
                    new_user
                }
                Err(e) => return identity_error_to_response(&e).into_response(),
            };
            let uid = admin.id().clone();
            let session = match state.identity.create_session(
                &rid,
                &uid,
                &crate::identity::SessionContext::default(),
            ) {
                Ok(s) => s,
                Err(e) => return identity_error_to_response(&e).into_response(),
            };
            let tokens = match state.identity.issue_tokens(&rid, &uid, session.id()) {
                Ok(t) => t,
                Err(e) => return identity_error_to_response(&e).into_response(),
            };
            let rid_str = rid.as_uuid().to_string();
            let at_str = tokens.access_token().to_string();
            let qs = format!(
                r#"# 1. Register an OAuth application
curl -fsS -X POST http://127.0.0.1:8420/clients \
  -H "Authorization: Bearer {at_str}" \
  -H "X-Realm-ID: {rid_str}" \
  -H "Content-Type: application/json" \
  -d '{{"client_name":"my-app","redirect_uris":["https://myapp.example.com/callback"]}}'

# 2. Full PKCE flow — see docs/guides/getting-started.md"#
            );
            // Re-bootstrap: do not modify existing password (HEA-1670). Still
            // mint a fresh cross-realm system token (HEA-2087).
            dev_seed_system_admin(&state);
            let system_access_token = dev_system_admin_token(&state).unwrap_or_default();
            return (
                StatusCode::OK,
                Json(pb::BootstrapResponse {
                    realm_id: rid_str,
                    user_id: uid.as_uuid().to_string(),
                    access_token: at_str,
                    refresh_token: tokens.refresh_token().to_string(),
                    quickstart: qs,
                    admin_password: String::new(),
                    system_access_token,
                    system_realm_id: crate::identity::keys::system_realm_id()
                        .as_uuid()
                        .to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let realm_id = realm.id().clone();

    // Seed RBAC defaults on the new realm. Hard error: a dev bootstrap
    // with a broken seed produces a realm where the admin user cannot be
    // granted realm.admin, making the bootstrap useless.
    if let Err(e) = state.rbac.seed_realm(&realm_id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("RBAC seed failed: {e}")})),
        )
            .into_response();
    }

    // Create admin user
    let user = match state.identity.create_user(
        &realm_id,
        &crate::identity::CreateUserRequest {
            email: "admin@dev.local".to_string(),
            display_name: "Dev Admin".to_string(),
            ..Default::default()
        },
    ) {
        Ok(u) => u,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let user_id = user.id().clone();

    // Activate the user and set a well-known dev password so browser-based
    // UI tests can log in at /ui/realms/dev-realm/login.
    let _ = state.identity.update_user(
        &realm_id,
        &user_id,
        &crate::identity::UpdateUserRequest {
            status: Some(crate::identity::UserStatus::Active),
            ..Default::default()
        },
    );
    let dev_pwd = crate::identity::CleartextPassword::from_string("HearthDev123!".to_string());
    let _ = state.identity.set_password(&realm_id, &user_id, &dev_pwd);

    // Grant the realm.admin role to the admin user BEFORE issuing tokens so
    // the access-token `permissions` claim contains `hearth.admin` — otherwise
    // the returned token would be unable to call any admin endpoint.
    let admin_role = match state.rbac.get_role_by_name(&realm_id, "realm.admin") {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "seed role realm.admin missing"})),
            )
                .into_response();
        }
        Err(e) => return rbac_error_to_response(&e).into_response(),
    };
    if let Err(e) = state.rbac.assign_role(
        &realm_id,
        &AssignRoleRequest {
            subject: Subject::User(user_id.clone()),
            role_id: admin_role.id.clone(),
            scope: Scope::Realm,
            assigned_by: None,
        },
    ) {
        return rbac_error_to_response(&e).into_response();
    }

    // Create session (API-initiated — no browser context)
    let session = match state.identity.create_session(
        &realm_id,
        &user_id,
        &crate::identity::SessionContext::default(),
    ) {
        Ok(s) => s,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    // Issue tokens — now resolves `realm.admin` role's permissions into
    // the JWT claim set.
    let tokens = match state
        .identity
        .issue_tokens(&realm_id, &user_id, session.id())
    {
        Ok(t) => t,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let realm_id_str = realm_id.as_uuid().to_string();
    let access_token_str = tokens.access_token().to_string();
    let quickstart = format!(
        r#"# 1. Register an OAuth application
curl -fsS -X POST http://127.0.0.1:8420/clients \
  -H "Authorization: Bearer {access_token_str}" \
  -H "X-Realm-ID: {realm_id_str}" \
  -H "Content-Type: application/json" \
  -d '{{"client_name":"my-app","redirect_uris":["https://myapp.example.com/callback"]}}'

# 2. Full PKCE flow — see docs/guides/getting-started.md"#
    );

    let admin_password = dev_seed_system_admin(&state).unwrap_or_default();
    // Cross-realm system-realm admin token (HEA-2087) — the dev-realm
    // `access_token` above cannot manage other realms.
    let system_access_token = dev_system_admin_token(&state).unwrap_or_default();
    (
        StatusCode::OK,
        Json(pb::BootstrapResponse {
            realm_id: realm_id_str,
            user_id: user_id.as_uuid().to_string(),
            access_token: access_token_str,
            refresh_token: tokens.refresh_token().to_string(),
            quickstart,
            admin_password,
            system_access_token,
            system_realm_id: crate::identity::keys::system_realm_id()
                .as_uuid()
                .to_string(),
        }),
    )
        .into_response()
}

// =======================================================================
// RBAC admin endpoints (AUTHORIZATION.md § 8.2)
// =======================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRoleBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    parent_roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRoleBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<Option<String>>,
    #[serde(default)]
    permissions: Option<Vec<String>>,
    #[serde(default)]
    parent_roles: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateGroupBody {
    name: String,
    slug: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateGroupBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    description: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddGroupMemberBody {
    /// `"user"` or `"group"`.
    #[serde(rename = "type")]
    member_type: String,
    /// UUID of the member entity.
    id: String,
}

#[derive(Debug, Deserialize)]
struct AssignRoleBody {
    role_id: String,
    /// Optional org ID for org-scoped assignments; omit for realm scope.
    #[serde(default)]
    org_id: Option<String>,
}

fn parse_role_id(raw: &str) -> Result<RoleId, (StatusCode, Json<serde_json::Value>)> {
    let stripped = raw.strip_prefix("role_").unwrap_or(raw);
    uuid::Uuid::parse_str(stripped)
        .map(RoleId::new)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid role id"})),
            )
        })
}

fn parse_group_id(raw: &str) -> Result<GroupId, (StatusCode, Json<serde_json::Value>)> {
    let stripped = raw.strip_prefix("group_").unwrap_or(raw);
    uuid::Uuid::parse_str(stripped)
        .map(GroupId::new)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid group id"})),
            )
        })
}

fn parse_assignment_id(
    raw: &str,
) -> Result<crate::rbac::AssignmentId, (StatusCode, Json<serde_json::Value>)> {
    let stripped = raw.strip_prefix("assign_").unwrap_or(raw);
    uuid::Uuid::parse_str(stripped)
        .map(crate::rbac::AssignmentId::new)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid assignment id"})),
            )
        })
}

fn parse_user_id_path(raw: &str) -> Result<UserId, (StatusCode, Json<serde_json::Value>)> {
    let stripped = raw.strip_prefix("user_").unwrap_or(raw);
    uuid::Uuid::parse_str(stripped)
        .map(UserId::new)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user id"})),
            )
        })
}

fn permissions_from_strings(raw: Vec<String>) -> Result<Vec<Permission>, RbacError> {
    raw.into_iter()
        .map(|s| Permission::new(s).map_err(|reason| RbacError::InvalidPermission { reason }))
        .collect()
}

async fn admin_list_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationParams>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    match state.rbac.list_roles(
        &auth.realm_id,
        pagination.cursor.as_deref(),
        pagination.effective_limit(),
    ) {
        Ok(page) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "items": page.items,
                "next_cursor": page.next_cursor,
            })),
        )
            .into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_create_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateRoleBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let permissions = match permissions_from_strings(body.permissions) {
        Ok(p) => p,
        Err(e) => return rbac_error_to_response(&e).into_response(),
    };
    let parent_roles: Result<Vec<RoleId>, _> = body
        .parent_roles
        .into_iter()
        .map(|s| parse_role_id(&s))
        .collect();
    let parent_roles = match parent_roles {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match state.rbac.create_role(
        &auth.realm_id,
        &CreateRoleRequest {
            name: body.name,
            description: body.description,
            permissions,
            parent_roles,
            scope_kind: crate::rbac::RoleScopeKind::Realm,
            allow_reserved_permissions: false,
        },
    ) {
        Ok(role) => (StatusCode::CREATED, Json(role)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_get_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let role_id = match parse_role_id(&id) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match state.rbac.get_role(&auth.realm_id, &role_id) {
        Ok(Some(role)) => (StatusCode::OK, Json(role)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
            .into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_update_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateRoleBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let role_id = match parse_role_id(&id) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let permissions = match body.permissions {
        Some(raw) => match permissions_from_strings(raw) {
            Ok(p) => Some(p),
            Err(e) => return rbac_error_to_response(&e).into_response(),
        },
        None => None,
    };
    let parent_roles = match body.parent_roles {
        Some(raw) => {
            let parsed: Result<Vec<RoleId>, _> =
                raw.into_iter().map(|s| parse_role_id(&s)).collect();
            match parsed {
                Ok(v) => Some(v),
                Err(e) => return e.into_response(),
            }
        }
        None => None,
    };
    match state.rbac.update_role(
        &auth.realm_id,
        &role_id,
        &UpdateRoleRequest {
            name: body.name,
            description: body.description,
            permissions,
            parent_roles,
            scope_kind: None,
            status: None,
            allow_reserved_permissions: false,
        },
    ) {
        Ok(role) => (StatusCode::OK, Json(role)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_delete_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let role_id = match parse_role_id(&id) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match state.rbac.delete_role(&auth.realm_id, &role_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_list_groups(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationParams>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    match state
        .rbac
        .list_groups(&auth.realm_id, &pagination.as_page_request())
    {
        Ok(page) => {
            let next = page.offset + page.items.len() as u64;
            let next_cursor: Option<String> = if next < page.total {
                Some(next.to_string())
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "items": page.items,
                    "next_cursor": next_cursor,
                    "total": page.total,
                })),
            )
                .into_response()
        }
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_create_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateGroupBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    match state.rbac.create_group(
        &auth.realm_id,
        &CreateGroupRequest {
            name: body.name,
            slug: body.slug,
            description: body.description,
        },
    ) {
        Ok(g) => (StatusCode::CREATED, Json(g)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_get_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) =
        require_any_admin_permission(&auth, &["hearth.realm.admin", "hearth.users.admin"])
    {
        return e.into_response();
    }
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    match state.rbac.get_group(&auth.realm_id, &group_id) {
        Ok(Some(g)) => (StatusCode::OK, Json(g)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
            .into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_update_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateGroupBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    match state.rbac.update_group(
        &auth.realm_id,
        &group_id,
        &UpdateGroupRequest {
            name: body.name,
            slug: body.slug,
            description: body.description,
        },
    ) {
        Ok(g) => (StatusCode::OK, Json(g)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_delete_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    match state.rbac.delete_group(&auth.realm_id, &group_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_list_group_members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(pagination): Query<PaginationParams>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) =
        require_any_admin_permission(&auth, &["hearth.realm.admin", "hearth.users.admin"])
    {
        return e.into_response();
    }
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    match state.rbac.list_group_members(
        &auth.realm_id,
        &group_id,
        pagination.cursor.as_deref(),
        pagination.effective_limit(),
    ) {
        Ok(page) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "items": page.items,
                "next_cursor": page.next_cursor,
            })),
        )
            .into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_add_group_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AddGroupMemberBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    let member = match body.member_type.as_str() {
        "user" => match parse_user_id_path(&body.id) {
            Ok(u) => GroupMember::User(u),
            Err(e) => return e.into_response(),
        },
        "group" => match parse_group_id(&body.id) {
            Ok(g) => GroupMember::Group(g),
            Err(e) => return e.into_response(),
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid member type"})),
            )
                .into_response();
        }
    };
    match state
        .rbac
        .add_group_member(&auth.realm_id, &group_id, &member)
    {
        Ok(m) => (StatusCode::CREATED, Json(m)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_remove_group_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, member_id)): Path<(String, String)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    let member_type = params.get("type").map_or("user", String::as_str);
    let member = match member_type {
        "user" => match parse_user_id_path(&member_id) {
            Ok(u) => GroupMember::User(u),
            Err(e) => return e.into_response(),
        },
        "group" => match parse_group_id(&member_id) {
            Ok(g) => GroupMember::Group(g),
            Err(e) => return e.into_response(),
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid member type"})),
            )
                .into_response();
        }
    };
    match state
        .rbac
        .remove_group_member(&auth.realm_id, &group_id, &member)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_list_user_assignments(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let user_id = match parse_user_id_path(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    match state.rbac.list_user_assignments(&auth.realm_id, &user_id) {
        Ok(items) => (StatusCode::OK, Json(serde_json::json!({"items": items}))).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_assign_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AssignRoleBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let user_id = match parse_user_id_path(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let role_id = match parse_role_id(&body.role_id) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    // Privilege-ceiling check (HEA-SEC-13): a sub-admin (hearth.realm.admin) may only
    // assign roles whose effective permissions are a subset of their own. hearth.admin
    // bypasses this — they unconditionally hold all permissions.
    if !auth.permissions.iter().any(|p| p == "hearth.admin") {
        let role_perms = match state
            .rbac
            .resolve_role_permissions(&auth.realm_id, &role_id)
        {
            Ok(perms) => perms,
            Err(e) => return rbac_error_to_response(&e).into_response(),
        };
        let assigner_perms: std::collections::HashSet<&str> =
            auth.permissions.iter().map(String::as_str).collect();
        if let Some(p) = role_perms
            .iter()
            .find(|p| !assigner_perms.contains(p.as_str()))
        {
            tracing::warn!(
                assigner = %auth.user_id,
                realm_id = %auth.realm_id,
                missing_permission = %p,
                "role assignment blocked: role contains permission assigner does not hold"
            );
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "forbidden",
                    "error_description": "role contains permissions the assigner does not hold"
                })),
            )
                .into_response();
        }
    }
    let scope = match body.org_id {
        Some(s) => {
            let stripped = s.strip_prefix("org_").unwrap_or(&s);
            match uuid::Uuid::parse_str(stripped).map(crate::core::OrganizationId::new) {
                Ok(oid) => Scope::Org { org_id: oid },
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid org id"})),
                    )
                        .into_response();
                }
            }
        }
        None => Scope::Realm,
    };
    match state.rbac.assign_role(
        &auth.realm_id,
        &AssignRoleRequest {
            subject: Subject::User(user_id),
            role_id,
            scope,
            assigned_by: Some(auth.user_id.clone()),
        },
    ) {
        Ok(a) => (StatusCode::CREATED, Json(a)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_unassign_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let aid = match parse_assignment_id(&id) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    match state.rbac.unassign_role(&auth.realm_id, &aid) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

// ============================================================================
// WebAuthn / Passkey REST API
// ============================================================================

// === Webhook management (admin) ===

/// JSON body for `POST /admin/webhooks`.
#[derive(Debug, Deserialize)]
struct CreateWebhookBody {
    url: String,
    secret: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    event_filters: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

/// JSON body for `PUT /admin/webhooks/{id}`.
#[derive(Debug, Deserialize)]
struct UpdateWebhookBody {
    url: Option<String>,
    secret: Option<String>,
    enabled: Option<bool>,
    event_filters: Option<Vec<String>>,
}

/// Query params for `GET /admin/webhooks`.
#[derive(Debug, Deserialize, Default)]
struct WebhookListParams {
    enabled_only: Option<bool>,
}

/// Query params for `GET /admin/webhooks/{id}/deliveries`.
#[derive(Debug, Deserialize, Default)]
struct DeliveryListParams {
    limit: Option<usize>,
}

fn require_webhook_engine(
    state: &AppState,
) -> Result<Arc<dyn WebhookEngine>, (StatusCode, Json<serde_json::Value>)> {
    state.webhook.clone().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({"error": "webhooks not configured"})),
        )
    })
}

fn parse_event_filters(
    raw: &[String],
) -> Result<Vec<crate::audit::AuditAction>, (StatusCode, Json<serde_json::Value>)> {
    raw.iter()
        .map(|s| {
            s.parse::<crate::audit::AuditAction>().map_err(|_| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": format!("unknown event type: {s}")})),
                )
            })
        })
        .collect()
}

/// `GET /admin/webhooks` — list webhook subscriptions for the authenticated realm.
async fn admin_list_webhooks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<WebhookListParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };

    let query = WebhookQuery {
        realm_id: auth.realm_id,
        enabled_only: params.enabled_only.unwrap_or(false),
    };

    match engine.list(&query) {
        Ok(subs) => (
            StatusCode::OK,
            Json(serde_json::json!({ "webhooks": subs })),
        )
            .into_response(),
        Err(e) => {
            error!("list webhooks failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "list webhooks failed"})),
            )
                .into_response()
        }
    }
}

/// `POST /admin/webhooks` — create a webhook subscription.
async fn admin_create_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateWebhookBody>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };

    let event_filters = match parse_event_filters(&body.event_filters) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };

    let req = CreateWebhookRequest {
        realm_id: auth.realm_id,
        url: body.url,
        secret: body.secret,
        enabled: body.enabled,
        event_filters,
    };

    // SSRF guard at registration time (F3/HEA-1651). DNS I/O is blocking so
    // we run it on the blocking thread pool before persisting the URL.
    let url_to_check = req.url.clone();
    match tokio::task::spawn_blocking(move || {
        crate::webhook::ssrf::check_webhook_url(&url_to_check)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "ssrf check failed"})),
            )
                .into_response();
        }
    }

    match engine.create(&req) {
        Ok(sub) => (StatusCode::CREATED, Json(sub)).into_response(),
        Err(crate::webhook::WebhookError::InvalidUrl { reason }) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": reason})),
        )
            .into_response(),
        Err(crate::webhook::WebhookError::SecretTooShort) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "secret must be at least 16 bytes"})),
        )
            .into_response(),
        Err(e) => {
            error!("create webhook failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "create webhook failed"})),
            )
                .into_response()
        }
    }
}

/// `GET /admin/webhooks/{id}` — fetch a single webhook subscription.
async fn admin_get_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let webhook_id = match parse_webhook_id(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    match engine.get(&auth.realm_id, &webhook_id) {
        Ok(sub) => (StatusCode::OK, Json(sub)).into_response(),
        Err(crate::webhook::WebhookError::NotFound { .. }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "webhook not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("get webhook failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "get webhook failed"})),
            )
                .into_response()
        }
    }
}

/// `PUT /admin/webhooks/{id}` — update a webhook subscription.
async fn admin_update_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateWebhookBody>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let webhook_id = match parse_webhook_id(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let event_filters = match body.event_filters.as_deref() {
        Some(raw) => match parse_event_filters(raw) {
            Ok(f) => Some(f),
            Err(e) => return e.into_response(),
        },
        None => None,
    };

    let req = UpdateWebhookRequest {
        url: body.url,
        secret: body.secret,
        enabled: body.enabled,
        event_filters,
    };

    // SSRF guard: re-validate the new URL if one was supplied (F3/HEA-1651).
    if let Some(url) = req.url.as_deref() {
        let url_to_check = url.to_string();
        match tokio::task::spawn_blocking(move || {
            crate::webhook::ssrf::check_webhook_url(&url_to_check)
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "ssrf check failed"})),
                )
                    .into_response();
            }
        }
    }

    match engine.update(&auth.realm_id, &webhook_id, &req) {
        Ok(sub) => (StatusCode::OK, Json(sub)).into_response(),
        Err(crate::webhook::WebhookError::NotFound { .. }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "webhook not found"})),
        )
            .into_response(),
        Err(crate::webhook::WebhookError::InvalidUrl { reason }) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": reason})),
        )
            .into_response(),
        Err(crate::webhook::WebhookError::SecretTooShort) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "secret must be at least 16 bytes"})),
        )
            .into_response(),
        Err(e) => {
            error!("update webhook failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "update webhook failed"})),
            )
                .into_response()
        }
    }
}

/// `DELETE /admin/webhooks/{id}` — delete a webhook subscription.
async fn admin_delete_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let webhook_id = match parse_webhook_id(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    match engine.delete(&auth.realm_id, &webhook_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(crate::webhook::WebhookError::NotFound { .. }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "webhook not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("delete webhook failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "delete webhook failed"})),
            )
                .into_response()
        }
    }
}

/// `GET /admin/webhooks/{id}/deliveries` — list delivery log for a subscription.
async fn admin_list_webhook_deliveries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(params): Query<DeliveryListParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let webhook_id = match parse_webhook_id(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let query = DeliveryQuery {
        realm_id: auth.realm_id,
        webhook_id: Some(webhook_id),
        limit: Some(params.limit.unwrap_or(50).min(200)),
    };

    match engine.list_deliveries(&query) {
        Ok(deliveries) => (
            StatusCode::OK,
            Json(serde_json::json!({ "deliveries": deliveries })),
        )
            .into_response(),
        Err(e) => {
            error!("list webhook deliveries failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "list deliveries failed"})),
            )
                .into_response()
        }
    }
}

fn parse_webhook_id(s: &str) -> Result<WebhookId, (StatusCode, Json<serde_json::Value>)> {
    // IDs arrive either as bare UUIDs or as "wh_{uuid}" — strip the prefix.
    let uuid_str = s.strip_prefix("wh_").unwrap_or(s);
    uuid_str
        .parse::<uuid::Uuid>()
        .map(WebhookId::new)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid webhook id"})),
            )
        })
}

// === Backup / Restore (admin) ===

/// Query parameters for `POST /admin/backup`.
#[derive(Debug, Deserialize)]
struct BackupCreateParams {
    /// Optional realm slug to restrict the export to a single realm.
    realm: Option<String>,
    /// Include audit events in the archive (default: false).
    #[serde(default)]
    include_audit: bool,
}

/// Query parameters for `POST /admin/backup/restore`.
#[derive(Debug, Deserialize)]
struct BackupRestoreParams {
    /// Conflict resolution strategy: `skip` (default), `overwrite`, or `merge`.
    mode: Option<String>,
    /// Restore only the named realm from the archive.
    realm: Option<String>,
    /// Parse and validate without writing anything.
    #[serde(default)]
    dry_run: bool,
}

/// `POST /admin/backup` — export a backup archive and stream it as a download.
///
/// Optional query params:
/// - `realm=<slug>` — restrict to a single realm
/// - `include_audit=true` — include audit events
///
/// Response: `application/octet-stream` with `Content-Disposition: attachment`.
/// No passphrase encryption — TLS provides transport security; encryption is
/// CLI-only (`--encrypt` flag on `hearth backup create`).
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
async fn admin_backup_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<BackupCreateParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    // A-30: require hearth.export capability (separate from hearth.admin).
    if let Err(e) = check_export_capability(&auth) {
        return e.into_response();
    }

    // A-30: per-export rate limit (10/hour per user).
    if let Err(e) = check_export_rate_limit(&state, &auth.user_id) {
        return e.into_response();
    }

    // A-30: emit audit watermark at the start of every export.
    let export_id = uuid::Uuid::new_v4().to_string();
    emit_export_watermark(
        &state,
        &auth.realm_id,
        &auth.user_id,
        "backup",
        params.realm.as_deref(),
        &export_id,
    );

    let identity = Arc::clone(&state.identity);
    let audit_engine = Arc::clone(&state.audit);
    let rbac = Arc::clone(&state.rbac);
    let realm_filter_slug = params.realm.clone();
    let include_audit = params.include_audit;
    let auth_realm_id = auth.realm_id.clone();
    let actor = auth.user_id.as_uuid().to_string();

    let result = tokio::task::spawn_blocking(move || {
        use crate::backup::{BackupArchive, BackupExporter, BackupManifest, ExportOptions};

        // Resolve optional realm slug to a RealmId.
        let filter_id: Option<crate::core::RealmId> = if let Some(slug) = &realm_filter_slug {
            let mut found = None;
            let batch = crate::core::MAX_PAGE_LIMIT;
            let mut offset = 0u64;
            loop {
                let page = identity
                    .list_realms(&crate::core::PageRequest::new(offset, batch))
                    .map_err(|e| format!("list_realms: {e}"))?;
                let n = page.items.len() as u64;
                for realm in &page.items {
                    if realm.name() == slug {
                        found = Some(realm.id().clone());
                        break;
                    }
                }
                if found.is_some() || n == 0 || offset + n >= page.total {
                    break;
                }
                offset += n;
            }
            Some(found.ok_or_else(|| format!("realm '{slug}' not found"))?)
        } else {
            None
        };

        // Write the archive to a temporary file; read it back as bytes.
        let tmp = tempfile::NamedTempFile::new().map_err(|e| format!("tempfile: {e}"))?;
        let tmp_path = tmp.path().to_path_buf();

        let exporter = BackupExporter::new(
            Arc::clone(&identity),
            Arc::clone(&audit_engine),
            Arc::clone(&rbac),
        );
        let dek = BackupExporter::generate_dek().map_err(|e| format!("generate_dek: {e}"))?;
        let opts = ExportOptions {
            include_audit,
            realm_filter: filter_id.as_ref().map(|id| vec![id.clone()]),
        };

        let realms_to_export: Vec<crate::core::RealmId> = if let Some(id) = filter_id {
            vec![id]
        } else {
            let mut ids = Vec::new();
            let batch = crate::core::MAX_PAGE_LIMIT;
            let mut offset = 0u64;
            loop {
                let page = identity
                    .list_realms(&crate::core::PageRequest::new(offset, batch))
                    .map_err(|e| format!("list_realms: {e}"))?;
                let n = page.items.len() as u64;
                for realm in &page.items {
                    ids.push(realm.id().clone());
                }
                if n == 0 || offset + n >= page.total {
                    break;
                }
                offset += n;
            }
            ids
        };

        let mut writer =
            BackupArchive::create(&tmp_path).map_err(|e| format!("create archive: {e}"))?;
        let mut realm_manifests = Vec::new();
        for realm_id in &realms_to_export {
            let rm = exporter
                .export_realm(realm_id, &mut writer, &opts, &dek)
                .map_err(|e| format!("export_realm: {e}"))?;
            realm_manifests.push(rm);
        }

        // Wrap the DEK with HEARTH_MASTER_KEY (required for HTTP endpoint).
        let master_key = std::env::var("HEARTH_MASTER_KEY").map_err(|_| {
            "HEARTH_MASTER_KEY is not set — backup requires a master key".to_string()
        })?;
        if master_key.is_empty() {
            return Err::<Vec<u8>, String>("HEARTH_MASTER_KEY is empty".to_string());
        }
        let passphrase = secrecy::SecretString::from(master_key);
        let (wrapped_dek_b64, wrapping_params) =
            crate::backup::BackupExporter::wrap_dek(&dek, &passphrase)
                .map_err(|e| format!("DEK wrap: {e}"))?;
        let mut manifest = BackupManifest::new(realm_manifests);
        manifest.sections_encrypted = true;
        manifest.wrapped_dek_b64 = Some(wrapped_dek_b64);
        manifest.dek_wrapping_params = Some(wrapping_params);

        writer
            .finish(manifest)
            .map_err(|e| format!("finish archive: {e}"))?;

        let bytes = std::fs::read(&tmp_path).map_err(|e| format!("read archive: {e}"))?;
        Ok::<Vec<u8>, String>(bytes)
    })
    .await;

    match result {
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("backup task panicked: {e}")})),
        )
            .into_response(),
        Ok(Err(msg)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
        Ok(Ok(bytes)) => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let filename = format!("hearth-backup-{ts}.hearth-backup");

            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth_realm_id,
                actor,
                action: crate::audit::AuditAction::BackupCreated,
                resource_type: "backup".to_string(),
                resource_id: filename.clone(),
                metadata: params.realm.map(|s| serde_json::json!({"realm_slug": s})),
            });

            axum::http::Response::builder()
                .status(StatusCode::OK)
                .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
                .header(
                    axum::http::header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{filename}\""),
                )
                .body(axum::body::Body::from(bytes))
                .unwrap_or_else(|_| {
                    axum::http::Response::new(axum::body::Body::from(
                        b"internal error building response" as &[u8],
                    ))
                })
        }
    }
}

/// `POST /admin/backup/restore` — restore from a `.hearth-backup` archive.
///
/// Body: `multipart/form-data`, field `file` = `.hearth-backup` archive.
///
/// Optional query params:
/// - `mode=skip|overwrite|merge` (default: `skip`)
/// - `realm=<slug>` — restore only the named realm from the archive
/// - `dry_run=true` — validate without writing
///
/// Response: JSON `ImportReport` with per-realm counts and any conflicts.
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
async fn admin_backup_restore(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<BackupRestoreParams>,
    mut multipart: axum::extract::Multipart,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    // SEC-14: require hearth.export capability for restore (destructive write operation).
    if let Err(e) = check_export_capability(&auth) {
        return e.into_response();
    }

    // SEC-14: per-user rate limit shared with export operations (A-30).
    if let Err(e) = check_export_rate_limit(&state, &auth.user_id) {
        return e.into_response();
    }

    let mode_str = params.mode.as_deref().unwrap_or("skip").to_string();
    let realm_filter = params.realm.clone();
    let dry_run = params.dry_run;
    // Clone out of Arc before entering spawn_blocking.
    let verify_key_bytes = state.backup_verify_key_bytes;

    // Stream the `file` multipart field to a tempfile to avoid holding the
    // entire archive in memory while parsing.
    let tmp = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("tempfile: {e}")})),
            )
                .into_response()
        }
    };
    let tmp_path = tmp.path().to_path_buf();

    let mut file_found = false;
    'fields: while let Ok(Some(field)) = multipart.next_field().await {
        if field.name().unwrap_or("") != "file" {
            continue;
        }
        file_found = true;

        use tokio::io::AsyncWriteExt as _;
        let mut async_tmp = match tokio::fs::OpenOptions::new()
            .write(true)
            .open(&tmp_path)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("open tempfile: {e}")})),
                )
                    .into_response()
            }
        };

        // Chunk the field into the tempfile.
        let mut field = field;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    if let Err(e) = async_tmp.write_all(&chunk).await {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": format!("write tempfile: {e}")})),
                        )
                            .into_response();
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": format!("read upload: {e}")})),
                    )
                        .into_response();
                }
            }
        }

        if let Err(e) = async_tmp.flush().await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("flush tempfile: {e}")})),
            )
                .into_response();
        }

        break 'fields;
    }

    if !file_found {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "missing 'file' field in multipart body"})),
        )
            .into_response();
    }

    // SEC-14: emit audit event at restore start, before any destructive write.
    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: auth.realm_id.clone(),
        actor: auth.user_id.as_uuid().to_string(),
        action: crate::audit::AuditAction::BackupRestored,
        resource_type: "backup".to_string(),
        resource_id: "restore".to_string(),
        metadata: Some(serde_json::json!({
            "dry_run": dry_run,
            "mode": mode_str,
            "realm_filter": realm_filter,
        })),
    });

    let identity = Arc::clone(&state.identity);
    let rbac = Arc::clone(&state.rbac);

    let result = tokio::task::spawn_blocking(move || {
        use crate::backup::{
            BackupArchive, BackupImporter, ImportOptions, ImportReport, RestoreMode,
        };

        let mode = match mode_str.as_str() {
            "overwrite" => RestoreMode::Overwrite,
            "merge" => RestoreMode::Merge,
            "skip" | "" => RestoreMode::Skip,
            other => {
                return Err(format!(
                    "unknown mode '{other}'; expected skip | overwrite | merge"
                ))
            }
        };

        let reader = BackupArchive::open(&tmp_path).map_err(|e| format!("open archive: {e}"))?;

        // A-30: verify detached manifest signature when an operator verify key is configured.
        if let Some(key_bytes) = verify_key_bytes.as_ref() {
            verify_manifest_signature(&reader.manifest, key_bytes)
                .map_err(|(_, body)| format!("{}", body.0))?;
        }

        let importer = BackupImporter::new(identity, rbac);
        let dek_passphrase: Option<secrecy::SecretString> = if reader.manifest.sections_encrypted {
            let mk = std::env::var("HEARTH_MASTER_KEY")
                .map_err(|_| "HEARTH_MASTER_KEY not set for encrypted restore".to_string())?;
            Some(secrecy::SecretString::from(mk))
        } else {
            None
        };
        let opts = ImportOptions {
            mode,
            dry_run,
            realm_target: None,
            dek_passphrase,
        };

        let slugs: Vec<String> = if let Some(slug) = &realm_filter {
            if reader.realms().iter().any(|r| &r.slug == slug) {
                vec![slug.clone()]
            } else {
                return Err(format!("realm '{slug}' not found in archive"));
            }
        } else {
            reader.realms().iter().map(|r| r.slug.clone()).collect()
        };

        let mut reports: std::collections::HashMap<String, ImportReport> =
            std::collections::HashMap::new();
        for slug in &slugs {
            let report = importer
                .import_realm(slug, &reader, &opts)
                .map_err(|e| format!("import_realm '{slug}': {e}"))?;
            reports.insert(slug.clone(), report);
        }

        Ok::<_, String>(reports)
    })
    .await;

    match result {
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("restore task panicked: {e}")})),
        )
            .into_response(),
        Ok(Err(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response(),
        Ok(Ok(reports)) => {
            let mut realms_restored = 0u64;
            let mut counts = serde_json::Map::new();
            let mut errors: Vec<serde_json::Value> = Vec::new();

            for (slug, report) in &reports {
                if report.realms.created > 0 || report.realms.overwritten > 0 {
                    realms_restored += 1;
                }
                counts.insert(
                    slug.clone(),
                    serde_json::json!({
                        "users": {
                            "created": report.users.created,
                            "skipped": report.users.skipped,
                            "overwritten": report.users.overwritten,
                            "errored": report.users.errored,
                        },
                        "clients": {
                            "created": report.clients.created,
                            "skipped": report.clients.skipped,
                            "overwritten": report.clients.overwritten,
                            "errored": report.clients.errored,
                        },
                    }),
                );
                for conflict in &report.conflicts {
                    errors.push(serde_json::json!({
                        "realm": slug,
                        "entity_type": conflict.entity_type,
                        "identifier": conflict.identifier,
                        "reason": conflict.reason,
                    }));
                }
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "realms_restored": realms_restored,
                    "counts": counts,
                    "errors": errors,
                    "dry_run": dry_run,
                })),
            )
                .into_response()
        }
    }
}

// === RP-Initiated Logout (OIDC RPL §2 + OIDC BCL §2.5) ===

/// `GET /realms/{realm}/end_session` — realm-path-scoped RP-initiated logout.
///
/// Identical to [`end_session`] but resolves the realm from the URL path
/// instead of the `X-Realm-ID` header, so browser navigations from SPAs work.
async fn admin_sv_bump_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id_str): Path<String>,
) -> Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }

    let uuid = match uuid::Uuid::parse_str(&session_id_str) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid session_id"})),
            )
                .into_response()
        }
    };
    let session_id = crate::core::SessionId::new(uuid);

    let result = tokio::task::spawn_blocking({
        let identity = Arc::clone(&state.identity);
        let realm_id = auth.realm_id.clone();
        move || identity.sv_bump_session(&realm_id, &session_id)
    })
    .await;

    match result {
        Ok(Ok(new_min_sv)) => Json(serde_json::json!({"new_min_sv": new_min_sv})).into_response(),
        Ok(Err(crate::identity::IdentityError::SessionVersionDisabled)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "session versioning disabled for realm"})),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response(),
    }
}

/// `POST /admin/realms/{realm_id}/sv-bump-all` — bump every active session in the realm.
///
/// Returns `{"bumped": <n>}`. Heavy operation — generates O(active_sessions) delta entries.
/// Requires `hearth.admin`.
async fn admin_sv_bump_all(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(realm_id_str): Path<String>,
) -> Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.realm.admin") {
        return e.into_response();
    }

    let uuid = match uuid::Uuid::parse_str(&realm_id_str) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid realm_id"})),
            )
                .into_response()
        }
    };
    let realm_id = match scoped_realm(&auth, RealmId::new(uuid)) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let result = tokio::task::spawn_blocking({
        let identity = Arc::clone(&state.identity);
        move || identity.sv_bump_all(&realm_id)
    })
    .await;

    match result {
        Ok(Ok(bumped)) => Json(serde_json::json!({"bumped": bumped})).into_response(),
        Ok(Err(crate::identity::IdentityError::SessionVersionDisabled)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "session versioning disabled for realm"})),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response(),
    }
}

/// `GET /admin/users/{id}/sessions` — lists active sessions for a user.
///
/// Returns `{"items": [...], "next_cursor": null|"..."}`.
/// Requires `hearth.users.admin`.
async fn admin_list_user_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id_str): Path<String>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }
    let Ok(uuid) = user_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid user_id"})),
        )
            .into_response();
    };
    let user_id = crate::core::UserId::new(uuid);
    match state
        .identity
        .list_sessions_by_user(&auth.realm_id, &user_id, &params.as_page_request())
    {
        Ok(page) => {
            // Filter out revoked sessions before serialising — the engine returns
            // all index entries regardless of revocation status.
            let items: Vec<serde_json::Value> = page
                .items
                .iter()
                .filter(|s| !s.is_revoked())
                .map(|s| {
                    serde_json::json!({
                        "id": s.id().as_uuid().to_string(),
                        "user_id": s.user_id().as_uuid().to_string(),
                        "created_at": s.created_at().as_micros(),
                        "expires_at": s.expires_at().as_micros(),
                        "last_refreshed_at": s.last_refreshed_at().as_micros(),
                        "ip_address": s.ip_address(),
                        "device_label": s.device_label(),
                    })
                })
                .collect();
            let next = page.offset + page.items.len() as u64;
            let next_cursor: Option<String> = if next < page.total {
                Some(next.to_string())
            } else {
                None
            };
            let body = serde_json::json!({
                "items": items,
                "next_cursor": next_cursor,
                "total": page.total,
            });
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `DELETE /admin/sessions/{id}` — hard-revokes a session by ID.
///
/// Marks the session record as revoked and cascades to any grant families
/// issued under it. Returns `204 No Content` on success.
/// Requires `hearth.users.admin`.
async fn admin_revoke_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id_str): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_admin_permission(&auth, "hearth.users.admin") {
        return e.into_response();
    }
    let Ok(uuid) = session_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid session_id"})),
        )
            .into_response();
    };
    let session_id = crate::core::SessionId::new(uuid);
    match state.identity.revoke_session(&auth.realm_id, &session_id) {
        Ok(()) => {
            let _ = state.audit.append(&crate::audit::CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::SessionRevoked,
                resource_type: "session".to_string(),
                resource_id: session_id.as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}
