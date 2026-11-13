//! SCIM 2.0 `/Users` handlers (RFC 7644 §3.4).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::abuse::{MAX_SCIM_OPERATIONS, SCIM_FILTER_SCAN_LIMIT};
use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{RealmId, UserId};
use crate::identity::{CreateUserRequest, UpdateUserRequest, User, UserStatus};
use crate::protocol::admin_auth::check_user_admin_ceiling;
use crate::protocol::http::AppState;
use crate::protocol::scim::auth::{authenticate, ScimAuth, ScimResource};
use crate::protocol::scim::error::{from_ceiling_error, from_identity_error, ScimError};
use crate::protocol::scim::etag::{check_if_match, resource_response};
use crate::protocol::scim::filter::{self, FilterExpr};
use crate::protocol::scim::mount::{ResourceIdPath, ScimBase};
use crate::protocol::scim::patch_apply::apply_user_patch;
use crate::protocol::scim::types::{
    ListResponse, Meta, PatchRequest, ScimEmail, ScimName, ScimUser, USER_SCHEMA,
};

/// The path of a user resource under the request's SCIM base, for example
/// `/realms/acme/scim/v2/Users/{id}`.
fn user_location(base: &ScimBase, user: &User) -> String {
    format!("{}/{}", base.collection("Users"), user.id().as_uuid())
}

/// Converts a stored `User` to a SCIM wire resource. `meta.location` is built
/// from `base`, the base path the request was addressed to.
fn user_to_scim(user: &User, external_id: Option<String>, base: &ScimBase) -> ScimUser {
    let location = user_location(base, user);
    let version = format!("W/\"{}\"", user.updated_at().as_micros());
    let name = if user.first_name().is_empty() && user.last_name().is_empty() {
        None
    } else {
        Some(ScimName {
            formatted: Some(
                format!("{} {}", user.first_name(), user.last_name())
                    .trim()
                    .to_string(),
            ),
            given_name: if user.first_name().is_empty() {
                None
            } else {
                Some(user.first_name().to_string())
            },
            family_name: if user.last_name().is_empty() {
                None
            } else {
                Some(user.last_name().to_string())
            },
        })
    };
    ScimUser {
        schemas: vec![USER_SCHEMA.to_string()],
        id: Some(user.id().as_uuid().to_string()),
        external_id,
        user_name: user.email().to_string(),
        display_name: if user.display_name().is_empty() {
            None
        } else {
            Some(user.display_name().to_string())
        },
        name,
        emails: vec![ScimEmail {
            value: user.email().to_string(),
            primary: Some(true),
            r#type: None,
        }],
        active: matches!(user.status(), UserStatus::Active),
        meta: Some(Meta {
            resource_type: "User".to_string(),
            created: iso8601(user.created_at().as_micros()),
            last_modified: iso8601(user.updated_at().as_micros()),
            location,
            version,
        }),
    }
}

/// Current ETag validator for a user — the weak form of its last-modified
/// micros, matching the `meta.version` emitted in the resource body.
fn user_version(user: &User) -> String {
    format!("W/\"{}\"", user.updated_at().as_micros())
}

fn iso8601(micros: i64) -> String {
    let nanos = i128::from(micros) * 1_000;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// Primary email from a SCIM user payload: first entry with `primary: true`,
/// else first email, else None. SCIM clients that send `userName` = email
/// hit the fallback at the end.
fn primary_email(u: &ScimUser) -> String {
    u.emails
        .iter()
        .find(|e| e.primary.unwrap_or(false))
        .or_else(|| u.emails.first())
        .map(|e| e.value.clone())
        .unwrap_or_else(|| u.user_name.clone())
}

fn require_name(u: &ScimUser) -> Result<(String, String), ScimError> {
    match u.name.as_ref() {
        Some(n) => Ok((
            n.given_name.clone().unwrap_or_default(),
            n.family_name.clone().unwrap_or_default(),
        )),
        None => {
            // Synthesize from displayName when SCIM client omits structured
            // name. Real-world IdPs always send `name`, but some test
            // clients don't.
            Ok((String::new(), String::new()))
        }
    }
}

fn audit(
    state: &AppState,
    realm_id: &RealmId,
    actor: &str,
    action: AuditAction,
    user_id: &UserId,
    external_id: Option<&str>,
) {
    let metadata = json!({
        "via": "scim",
        "external_id": external_id,
    });
    crate::protocol::audit_log::record(
        state.audit.as_ref(),
        &CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: actor.to_string(),
            action,
            resource_type: "user".to_string(),
            resource_id: user_id.as_uuid().to_string(),
            metadata: Some(metadata),
        },
    );
}

/// The privilege ceiling on user administration, applied to SCIM: refuses
/// (`403`, with `refusal` as the detail) when the target user holds an admin
/// permission the caller lacks
/// ([`crate::protocol::admin_auth::check_user_admin_ceiling`], the rule REST
/// `/admin/users*` calls too).
///
/// Runs on both credential paths:
///
/// - The provisioning token acts with no permissions, so it may not modify or
///   delete any principal holding an admin permission — a compromised
///   integration token must not reach realm takeover. (This guard used to
///   carry its own two-entry list, which left realm, clients and agents
///   sub-admins exposed: GA audit round 3, G-6.)
/// - The admin-JWT fallback acts with its token's permissions, so a
///   `hearth.users.admin` sub-admin may not rewrite a superuser's email and
///   reset the password.
///
/// Fails CLOSED on an RBAC read error (GA audit L13): the error is a `503`
/// the caller returns instead of mutating. A user with no assignments (or an
/// unseeded realm) resolves to an empty set, not an error, so provisioning of
/// ordinary users is unaffected.
fn admin_principal_guard(
    state: &AppState,
    auth: &ScimAuth,
    user_id: &UserId,
    refusal: &str,
) -> Result<(), Response> {
    check_user_admin_ceiling(
        state.identity.as_ref(),
        state.rbac.as_ref(),
        &auth.realm_id,
        user_id,
        &auth.actor_permissions,
    )
    .map_err(|e| from_ceiling_error(e, refusal).into_response())
}

// ================== Handlers ==================

/// `POST /scim/v2/Users`
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    base: ScimBase,
    Json(body): Json<ScimUser>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Users) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    // A SCIM sync is a provisioning burst: each create takes a user-create
    // permit and runs on the blocking pool (#446). Past the queue wait it is
    // shed with `503` + `Retry-After`, which SCIM clients retry.
    match crate::identity::user_create_gate()
        .run(move || create_user_admitted(&state, &auth, &base, &body))
        .await
    {
        Ok(resp) => resp,
        Err(crate::identity::UserCreateGateError::Overloaded { retry_after }) => {
            let mut resp = ScimError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Server is busy creating other users. Please retry shortly.",
            )
            .into_response();
            resp.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from(retry_after.as_secs().max(1)),
            );
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, "SCIM create_user task failed");
            ScimError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// The blocking body of `POST /scim/v2/Users`, run under a user-create permit.
fn create_user_admitted(
    state: &AppState,
    auth: &ScimAuth,
    base: &ScimBase,
    body: &ScimUser,
) -> Response {
    let _span = tracing::info_span!(
        "hearth.scim.users.create",
        "hearth.realm_id" = %auth.realm_id,
        "hearth.scim.resource_type" = "User",
    )
    .entered();

    // Idempotency: if the client supplies an externalId already seen in
    // this realm, refuse with 409 uniqueness (rather than create a dup).
    if let Some(ext) = &body.external_id {
        match state
            .identity
            .find_user_by_scim_external_id(&auth.realm_id, ext)
        {
            Ok(Some(_)) => {
                return ScimError::uniqueness("externalId already provisioned").into_response();
            }
            Ok(None) => {}
            Err(e) => return from_identity_error(&e).into_response(),
        }
    }

    let email = primary_email(body);
    let (first_name, last_name) = match require_name(body) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let display_name = body.display_name.clone().unwrap_or_default();

    let req = CreateUserRequest {
        email,
        display_name,
        first_name,
        last_name,
        attributes: Default::default(),
    };

    let user = match state.identity.create_user(&auth.realm_id, &req) {
        Ok(u) => u,
        Err(e) => return from_identity_error(&e).into_response(),
    };

    // Apply active=false (create_user returns Active by default).
    if !body.active {
        let _ = state.identity.update_user(
            &auth.realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Disabled),
                ..Default::default()
            },
        );
    }

    // Register externalId.
    if let Some(ext) = &body.external_id {
        if let Err(e) = state
            .identity
            .set_scim_external_id(&auth.realm_id, user.id(), ext)
        {
            return from_identity_error(&e).into_response();
        }
    }

    // Re-read to pick up status change (refresh `updated_at`).
    let refreshed = state
        .identity
        .get_user(&auth.realm_id, user.id())
        .ok()
        .flatten()
        .unwrap_or(user.clone());

    audit(
        state,
        &auth.realm_id,
        &auth.actor,
        AuditAction::ScimUserCreated,
        refreshed.id(),
        body.external_id.as_deref(),
    );

    let scim = user_to_scim(&refreshed, body.external_id.clone(), base);
    let mut resp = (StatusCode::CREATED, Json(scim.clone())).into_response();
    // The path is built from a UUID and a realm name of ASCII letters, digits,
    // `-` and `_`, so it is always a valid header value.
    if let Ok(location) = HeaderValue::from_str(&user_location(base, &refreshed)) {
        resp.headers_mut()
            .insert(axum::http::header::LOCATION, location);
    }
    if let Some(m) = &scim.meta {
        if let Ok(v) = HeaderValue::from_str(&m.version) {
            resp.headers_mut().insert(axum::http::header::ETAG, v);
        }
    }
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    resp
}

/// `GET /scim/v2/Users/{id}`
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    base: ScimBase,
    Path(ResourceIdPath { id }): Path<ResourceIdPath>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Users) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let _span = tracing::info_span!(
        "hearth.scim.users.get",
        "hearth.realm_id" = %auth.realm_id,
        "hearth.scim.resource_type" = "User",
        "enduser.id" = %id,
    )
    .entered();
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("user not found").into_response();
    };
    let user_id = UserId::new(uuid);
    match state.identity.get_user(&auth.realm_id, &user_id) {
        Ok(Some(user)) => {
            let ext = state
                .identity
                .get_scim_external_id(&auth.realm_id, &user_id)
                .ok()
                .flatten();
            let version = user_version(&user);
            let scim = user_to_scim(&user, ext, &base);
            resource_response(&scim, &version)
        }
        Ok(None) => ScimError::not_found("user not found").into_response(),
        Err(e) => from_identity_error(&e).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default, rename = "startIndex")]
    pub start_index: Option<usize>,
    #[serde(default)]
    pub count: Option<usize>,
}

/// `GET /scim/v2/Users`
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    base: ScimBase,
    Query(q): Query<ListQuery>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Users) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let filter_expr: Option<FilterExpr> = match q.filter.as_deref() {
        Some(f) => match filter::parse(f) {
            Ok(e) => Some(e),
            Err(e) => return e.into_response(),
        },
        None => None,
    };

    let start = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(100).min(200);

    // No filter: one page of users and the exact total (#644).
    let Some(expr) = filter_expr else {
        let position = u64::try_from(start - 1).unwrap_or(u64::MAX);
        let limit = u32::try_from(count).unwrap_or(crate::core::MAX_PAGE_LIMIT);
        let page = match state
            .identity
            .list_users_at_position(&auth.realm_id, position, limit)
        {
            Ok(p) => p,
            Err(e) => return from_identity_error(&e).into_response(),
        };
        let resources: Vec<ScimUser> = page
            .items
            .iter()
            .map(|user| scim_user_with_external_id(&state, &auth.realm_id, user, &base))
            .collect();
        let total = usize::try_from(page.total).unwrap_or(usize::MAX);
        return Json(ListResponse::new(total, start, resources)).into_response();
    };

    let matches = match filtered_users(&state, &auth.realm_id, &expr, &base) {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    let total = matches.len();
    let slice: Vec<ScimUser> = matches.into_iter().skip(start - 1).take(count).collect();
    Json(ListResponse::new(total, start, slice)).into_response()
}

/// The SCIM form of `user`, with its `externalId` when it has one.
fn scim_user_with_external_id(
    state: &AppState,
    realm_id: &RealmId,
    user: &User,
    base: &ScimBase,
) -> ScimUser {
    let ext = state
        .identity
        .get_scim_external_id(realm_id, user.id())
        .ok()
        .flatten();
    user_to_scim(user, ext, base)
}

/// An `eq` comparison that an index serves.
enum IndexedEq<'a> {
    /// `userName` or `emails.value`: the email index.
    Email(&'a str),
    /// `externalId`: the SCIM external-id index.
    ExternalId(&'a str),
    /// `id`: the user record itself.
    Id(&'a str),
}

/// The indexed `eq` of `expr`: the filter itself, or one side of an `and`.
/// An index then gives the only user that can match the whole filter.
fn indexed_eq(expr: &FilterExpr) -> Option<IndexedEq<'_>> {
    match expr {
        FilterExpr::Eq(attr, filter::Value::Str(value)) => {
            match attr.to_ascii_lowercase().as_str() {
                "username" | "emails.value" => Some(IndexedEq::Email(value)),
                "externalid" => Some(IndexedEq::ExternalId(value)),
                "id" => Some(IndexedEq::Id(value)),
                _ => None,
            }
        }
        FilterExpr::And(a, b) => indexed_eq(a).or_else(|| indexed_eq(b)),
        _ => None,
    }
}

/// The user that an indexed `eq` names, if any.
fn indexed_user(
    state: &AppState,
    realm_id: &RealmId,
    eq: &IndexedEq<'_>,
) -> Result<Option<User>, crate::identity::IdentityError> {
    match eq {
        IndexedEq::Email(email) => match state.identity.get_user_by_email(realm_id, email) {
            // A value that is not an email address names no user.
            Err(crate::identity::IdentityError::InvalidInput { .. }) => Ok(None),
            other => other,
        },
        IndexedEq::ExternalId(external_id) => state
            .identity
            .find_user_by_scim_external_id(realm_id, external_id),
        IndexedEq::Id(id) => match uuid::Uuid::parse_str(id) {
            Ok(uuid) => state.identity.get_user(realm_id, &UserId::new(uuid)),
            Err(_) => Ok(None),
        },
    }
}

/// The users that match `expr`, in user-id order (#644).
///
/// An indexed `eq` (alone or in an `and`) reads its index. Any other filter
/// reads every user of the realm, so a realm with more than
/// [`SCIM_FILTER_SCAN_LIMIT`] users gets `400` `tooMany` (RFC 7644 §3.12),
/// not the matches of part of the realm.
fn filtered_users(
    state: &AppState,
    realm_id: &RealmId,
    expr: &FilterExpr,
    base: &ScimBase,
) -> Result<Vec<ScimUser>, ScimError> {
    let keep = |user: &User| {
        let scim = scim_user_with_external_id(state, realm_id, user, base);
        filter::matches_user(expr, &scim).then_some(scim)
    };

    if let Some(eq) = indexed_eq(expr) {
        let user = indexed_user(state, realm_id, &eq).map_err(|e| from_identity_error(&e))?;
        return Ok(user.as_ref().and_then(keep).into_iter().collect());
    }

    let scan_limit = u64::try_from(SCIM_FILTER_SCAN_LIMIT).unwrap_or(u64::MAX);
    let realm_users = state
        .identity
        .list_users_at_position(realm_id, 0, 0)
        .map_err(|e| from_identity_error(&e))?
        .total;
    if realm_users > scan_limit {
        return Err(ScimError::bad_request(
            "tooMany",
            format!(
                "This filter reads every user, and the realm has more than \
                 {SCIM_FILTER_SCAN_LIMIT} users. Use eq on userName, emails.value, \
                 externalId or id."
            ),
        ));
    }

    let mut matches = Vec::new();
    let mut position = 0u64;
    // The bound holds when users are created during the walk.
    while position < scan_limit {
        let page = state
            .identity
            .list_users_at_position(realm_id, position, crate::core::MAX_PAGE_LIMIT)
            .map_err(|e| from_identity_error(&e))?;
        if page.items.is_empty() {
            break;
        }
        position = position.saturating_add(page.items.len() as u64);
        matches.extend(page.items.iter().filter_map(keep));
    }
    Ok(matches)
}

/// `PUT /scim/v2/Users/{id}` — full replace.
pub async fn replace_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    base: ScimBase,
    Path(ResourceIdPath { id }): Path<ResourceIdPath>,
    Json(body): Json<ScimUser>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Users) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("user not found").into_response();
    };
    let user_id = UserId::new(uuid);

    // Ensure user exists first so 404 comes from the existence check, not
    // from a field mismatch downstream.
    let existing = match state.identity.get_user(&auth.realm_id, &user_id) {
        Ok(Some(u)) => u,
        Ok(None) => return ScimError::not_found("user not found").into_response(),
        Err(e) => return from_identity_error(&e).into_response(),
    };

    // Optimistic concurrency: reject if the caller's `If-Match` validator is
    // stale, so a replace built against an out-of-date copy fails loudly
    // instead of silently clobbering a newer write (HEA-2172).
    if let Err(e) = check_if_match(&headers, &user_version(&existing)) {
        return e.into_response();
    }

    // Privilege ceiling: neither a provisioning token nor a sub-admin may
    // replace a principal that outranks it (HEA-2032, GA audit round 3).
    if let Err(resp) = admin_principal_guard(
        &state,
        &auth,
        &user_id,
        "the caller may not replace a principal holding admin permissions it lacks",
    ) {
        return resp;
    }

    let (first_name, last_name) = match require_name(&body) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let email = primary_email(&body);
    let display_name = body.display_name.clone();

    let req = UpdateUserRequest {
        email: Some(email),
        display_name,
        first_name: Some(first_name),
        last_name: Some(last_name),
        status: Some(if body.active {
            UserStatus::Active
        } else {
            UserStatus::Disabled
        }),
        attributes: None,
        required_actions: None,
        email_otp_enabled: None,
    };

    let user = match state.identity.update_user(&auth.realm_id, &user_id, &req) {
        Ok(u) => u,
        Err(e) => return from_identity_error(&e).into_response(),
    };

    match body.external_id.as_deref() {
        Some(ext) if !ext.is_empty() => {
            if let Err(e) = state
                .identity
                .set_scim_external_id(&auth.realm_id, &user_id, ext)
            {
                return from_identity_error(&e).into_response();
            }
        }
        _ => {
            let _ = state
                .identity
                .clear_scim_external_id(&auth.realm_id, &user_id);
        }
    }

    audit(
        &state,
        &auth.realm_id,
        &auth.actor,
        AuditAction::ScimUserUpdated,
        &user_id,
        body.external_id.as_deref(),
    );

    let refreshed = state
        .identity
        .get_user(&auth.realm_id, &user_id)
        .ok()
        .flatten()
        .unwrap_or(user);
    let ext = state
        .identity
        .get_scim_external_id(&auth.realm_id, &user_id)
        .ok()
        .flatten();
    let version = user_version(&refreshed);
    let scim = user_to_scim(&refreshed, ext, &base);
    resource_response(&scim, &version)
}

/// `PATCH /scim/v2/Users/{id}`
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub async fn patch_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    base: ScimBase,
    Path(ResourceIdPath { id }): Path<ResourceIdPath>,
    Json(body): Json<PatchRequest>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Users) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    // A-35a: bound PATCH work per request to avoid a single call fanning out
    // into unbounded per-operation processing.
    if body.operations.len() > MAX_SCIM_OPERATIONS {
        return ScimError::payload_too_large(format!(
            "PATCH Operations count exceeds maximum of {MAX_SCIM_OPERATIONS}"
        ))
        .into_response();
    }
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("user not found").into_response();
    };
    let user_id = UserId::new(uuid);

    let existing = match state.identity.get_user(&auth.realm_id, &user_id) {
        Ok(Some(u)) => u,
        Ok(None) => return ScimError::not_found("user not found").into_response(),
        Err(e) => return from_identity_error(&e).into_response(),
    };

    // Optimistic concurrency: reject a stale `If-Match` before mutating
    // (HEA-2172).
    if let Err(e) = check_if_match(&headers, &user_version(&existing)) {
        return e.into_response();
    }

    // Privilege ceiling: neither a provisioning token nor a sub-admin may
    // patch a principal that outranks it (HEA-2032, GA audit round 3).
    if let Err(resp) = admin_principal_guard(
        &state,
        &auth,
        &user_id,
        "the caller may not patch a principal holding admin permissions it lacks",
    ) {
        return resp;
    }

    let current_ext = state
        .identity
        .get_scim_external_id(&auth.realm_id, &user_id)
        .ok()
        .flatten();

    let mut scim = user_to_scim(&existing, current_ext.clone(), &base);
    if let Err(e) = apply_user_patch(&mut scim, &body.operations) {
        return e.into_response();
    }

    let (first_name, last_name) = match require_name(&scim) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let email = primary_email(&scim);
    let status = if scim.active {
        UserStatus::Active
    } else {
        UserStatus::Disabled
    };

    let req = UpdateUserRequest {
        email: Some(email),
        display_name: scim.display_name.clone().or(Some(String::new())),
        first_name: Some(first_name),
        last_name: Some(last_name),
        status: Some(status),
        attributes: None,
        required_actions: None,
        email_otp_enabled: None,
    };
    // `display_name` Some("") would clear it — but `validate_display_name`
    // rejects empty. Re-synthesize if empty.
    let display_name_final = req
        .display_name
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let fn_ = scim
                .name
                .as_ref()
                .and_then(|n| n.given_name.clone())
                .unwrap_or_default();
            let ln = scim
                .name
                .as_ref()
                .and_then(|n| n.family_name.clone())
                .unwrap_or_default();
            let synth = format!("{fn_} {ln}").trim().to_string();
            if synth.is_empty() {
                Some(existing.display_name().to_string())
            } else {
                Some(synth)
            }
        });
    let req = UpdateUserRequest {
        display_name: display_name_final,
        ..req
    };

    if let Err(e) = state.identity.update_user(&auth.realm_id, &user_id, &req) {
        return from_identity_error(&e).into_response();
    }

    // Sync externalId.
    if scim.external_id != current_ext {
        match scim.external_id.as_deref() {
            Some(ext) if !ext.is_empty() => {
                if let Err(e) = state
                    .identity
                    .set_scim_external_id(&auth.realm_id, &user_id, ext)
                {
                    return from_identity_error(&e).into_response();
                }
            }
            _ => {
                let _ = state
                    .identity
                    .clear_scim_external_id(&auth.realm_id, &user_id);
            }
        }
    }

    audit(
        &state,
        &auth.realm_id,
        &auth.actor,
        AuditAction::ScimUserUpdated,
        &user_id,
        scim.external_id.as_deref(),
    );

    let refreshed = state
        .identity
        .get_user(&auth.realm_id, &user_id)
        .ok()
        .flatten()
        .unwrap_or(existing);
    let ext = state
        .identity
        .get_scim_external_id(&auth.realm_id, &user_id)
        .ok()
        .flatten();
    let version = user_version(&refreshed);
    let scim = user_to_scim(&refreshed, ext, &base);
    resource_response(&scim, &version)
}

/// `DELETE /scim/v2/Users/{id}`
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ResourceIdPath { id }): Path<ResourceIdPath>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Users) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("user not found").into_response();
    };
    let user_id = UserId::new(uuid);

    // Optimistic concurrency: when the caller supplies `If-Match`, reject a
    // stale validator so a delete built against an out-of-date copy fails
    // loudly (HEA-2172). Only pay the extra read when the header is present.
    if headers.contains_key(axum::http::header::IF_MATCH) {
        match state.identity.get_user(&auth.realm_id, &user_id) {
            Ok(Some(user)) => {
                if let Err(e) = check_if_match(&headers, &user_version(&user)) {
                    return e.into_response();
                }
            }
            Ok(None) => return ScimError::not_found("user not found").into_response(),
            Err(e) => return from_identity_error(&e).into_response(),
        }
    }

    // Privilege ceiling: neither a provisioning token nor a sub-admin may
    // delete a principal that outranks it (HEA-2032, GA audit round 3).
    if let Err(resp) = admin_principal_guard(
        &state,
        &auth,
        &user_id,
        "the caller may not delete a principal holding admin permissions it lacks",
    ) {
        return resp;
    }

    match state.identity.delete_user(&auth.realm_id, &user_id) {
        Ok(()) => {
            audit(
                &state,
                &auth.realm_id,
                &auth.actor,
                AuditAction::ScimUserDeleted,
                &user_id,
                None,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => from_identity_error(&e).into_response(),
    }
}
