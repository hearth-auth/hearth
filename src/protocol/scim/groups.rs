//! SCIM 2.0 `/Groups` handlers. Maps SCIM Groups onto Hearth
//! Organizations + `OrganizationMembership`.
//!
//! **Role:** all SCIM-managed members are provisioned with role
//! `Member`. SCIM has no concept of roles beyond membership, and Hearth
//! already prevents last-owner removal so there's no risk of locking
//! operators out of organizations they created out-of-band.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::abuse::{MAX_SCIM_OPERATIONS, SCIM_FILTER_SCAN_LIMIT};
use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{OrganizationId, PageRequest, RealmId, UserId, MAX_PAGE_LIMIT};
use crate::identity::{
    CreateOrganizationRequest, Organization, OrganizationRole, UpdateOrganizationRequest,
};
use crate::protocol::admin_auth::{check_org_admin_ceiling, check_users_admin_ceiling};
use crate::protocol::http::AppState;
use crate::protocol::scim::auth::{authenticate, ScimAuth, ScimResource};
use crate::protocol::scim::error::{from_ceiling_error, from_identity_error, ScimError};
use crate::protocol::scim::etag::{check_if_match, resource_response};
use crate::protocol::scim::filter::{self, FilterExpr};
use crate::protocol::scim::mount::{ResourceIdPath, ScimBase};
use crate::protocol::scim::patch_apply::apply_group_patch;
use crate::protocol::scim::types::{
    ListResponse, Meta, PatchRequest, ScimGroup, ScimMember, GROUP_SCHEMA,
};

/// Current ETag validator for a group — the weak form of its last-modified
/// micros, matching the `meta.version` emitted in the resource body.
fn group_version(org: &Organization) -> String {
    format!("W/\"{}\"", org.updated_at().as_micros())
}

/// Refuses (`403`) a provisioning-token write to an organization SCIM did not
/// create. The realm's SCIM token may replace, patch or delete only the
/// organizations it provisioned ([`Organization::scim_provisioned`]);
/// organizations an operator created through the admin API, the console or
/// `hearth.yaml` are read-only to it. Admin-token callers are unaffected
/// (GA audit round 3).
fn provisioning_token_may_write(auth: &ScimAuth, org: &Organization) -> Result<(), Response> {
    if auth.provisioning_token && !org.scim_provisioned() {
        return Err(ScimError::forbidden(
            "the SCIM provisioning token may modify only organizations SCIM created",
        )
        .into_response());
    }
    Ok(())
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

/// Derives a URL-safe slug from an arbitrary display name. If the base
/// result collides with an existing org, the caller should retry with a
/// uuid-suffixed version.
fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_hyphen = true;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_hyphen = false;
        } else if !last_hyphen {
            out.push('-');
            last_hyphen = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.len() < 3 {
        format!("{}-grp", trimmed)
    } else if trimmed.len() > 63 {
        trimmed[..63].to_string()
    } else {
        trimmed
    }
}

/// The path of a group resource under the request's SCIM base, for example
/// `/realms/acme/scim/v2/Groups/{id}`.
fn group_location(base: &ScimBase, org: &Organization) -> String {
    format!("{}/{}", base.collection("Groups"), org.id().as_uuid())
}

/// Converts an organization to a SCIM Group. `meta.location` is built from
/// `base`, the base path the request was addressed to.
fn group_to_scim(
    org: &Organization,
    members: &[ScimMember],
    external_id: Option<String>,
    base: &ScimBase,
) -> ScimGroup {
    let location = group_location(base, org);
    let version = format!("W/\"{}\"", org.updated_at().as_micros());
    ScimGroup {
        schemas: vec![GROUP_SCHEMA.to_string()],
        id: Some(org.id().as_uuid().to_string()),
        external_id,
        display_name: org.name().to_string(),
        members: members.to_vec(),
        meta: Some(Meta {
            resource_type: "Group".to_string(),
            created: iso8601(org.created_at().as_micros()),
            last_modified: iso8601(org.updated_at().as_micros()),
            location,
            version,
        }),
    }
}

/// Page size for reading an organization's membership.
const MEMBER_PAGE: usize = 1000;

/// Every membership of the organization, read page by page. A group's SCIM
/// representation and its membership reconciliation must see all of it: a
/// reconciliation that saw only the first page could not remove the members
/// beyond it, and a `PATCH` built on a truncated representation would drop
/// them.
fn all_members(
    state: &AppState,
    realm_id: &RealmId,
    org_id: &OrganizationId,
) -> Result<Vec<crate::identity::OrganizationMembership>, ScimError> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = state
            .identity
            .list_members(realm_id, org_id, cursor.as_deref(), MEMBER_PAGE)
            .map_err(|e| from_identity_error(&e))?;
        out.extend(page.items);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(out),
        }
    }
}

/// The organization's members as SCIM `members`.
fn load_members(
    state: &AppState,
    realm_id: &RealmId,
    org_id: &OrganizationId,
) -> Result<Vec<ScimMember>, ScimError> {
    Ok(all_members(state, realm_id, org_id)?
        .iter()
        .map(|m| ScimMember {
            value: m.user_id().as_uuid().to_string(),
            display: None,
            r#type: Some("User".to_string()),
        })
        .collect())
}

fn audit(
    state: &AppState,
    realm_id: &RealmId,
    actor: &str,
    action: AuditAction,
    org_id: &OrganizationId,
    external_id: Option<&str>,
) {
    crate::protocol::audit_log::record(
        state.audit.as_ref(),
        &CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: actor.to_string(),
            action,
            resource_type: "organization".to_string(),
            resource_id: org_id.as_uuid().to_string(),
            metadata: Some(json!({"via": "scim", "external_id": external_id})),
        },
    );
}

/// The user ids `desired` names. A value that is not a user id is refused
/// (`400 invalidValue`) rather than ignored: ignoring it would turn a
/// malformed member into a removal.
fn desired_member_ids(
    desired: &[ScimMember],
) -> Result<std::collections::HashSet<UserId>, ScimError> {
    desired
        .iter()
        .map(|m| {
            uuid::Uuid::parse_str(&m.value)
                .map(UserId::new)
                .map_err(|_| {
                    ScimError::bad_request(
                        "invalidValue",
                        "a member value is not a user id; nothing was changed",
                    )
                })
        })
        .collect()
}

/// Refuses (`400 invalidValue`) a member that is not a user of the realm, so
/// a membership change can be refused before anything is written.
fn check_members_exist<'u>(
    state: &AppState,
    realm_id: &RealmId,
    ids: impl IntoIterator<Item = &'u UserId>,
) -> Result<(), ScimError> {
    for id in ids {
        match state.identity.get_user(realm_id, id) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ScimError::bad_request(
                    "invalidValue",
                    format!(
                        "member {} is not a user of this realm; nothing was changed",
                        id.as_uuid()
                    ),
                ))
            }
            Err(e) => return Err(from_identity_error(&e)),
        }
    }
    Ok(())
}

/// The current members a reconciliation to `desired` removes. Owners and
/// Admins are kept: SCIM reconciliation doesn't demote operator-assigned
/// Owners/Admins who were created out-of-band (and last-owner protection in
/// the engine would refuse an Owner anyway).
fn stale_members(
    current: &[crate::identity::OrganizationMembership],
    desired: &std::collections::HashSet<UserId>,
) -> Vec<UserId> {
    current
        .iter()
        .filter(|m| !desired.contains(m.user_id()))
        .filter(|m| !matches!(m.role(), OrganizationRole::Owner | OrganizationRole::Admin))
        .map(|m| m.user_id().clone())
        .collect()
}

/// Refuses, before any write, a membership change that cannot be applied
/// whole: one that names a user who does not exist in the realm (`400`), or
/// one that would drop a member who out-ranks the caller (`403`) — leaving
/// the organization strips every admin permission the user holds only in it
/// (GA sweep 4). The provisioning token acts with no admin permission, so it
/// may drop no admin principal. Reads the full membership.
fn check_member_change(
    state: &AppState,
    auth: &ScimAuth,
    org_id: &OrganizationId,
    desired: &[ScimMember],
) -> Result<(), ScimError> {
    let current = all_members(state, &auth.realm_id, org_id)?;
    let current_ids: std::collections::HashSet<&UserId> = current
        .iter()
        .map(crate::identity::OrganizationMembership::user_id)
        .collect();
    let desired_ids = desired_member_ids(desired)?;
    check_members_exist(
        state,
        &auth.realm_id,
        desired_ids.iter().filter(|id| !current_ids.contains(id)),
    )?;
    let removed = stale_members(&current, &desired_ids);
    check_users_admin_ceiling(
        state.identity.as_ref(),
        state.rbac.as_ref(),
        &auth.realm_id,
        &removed,
        &auth.actor_permissions,
    )
    .map_err(|e| {
        from_ceiling_error(
            e,
            "a member this change removes holds admin permissions the caller lacks",
        )
    })
}

/// Brings the organization's membership to `desired`, against its full
/// current membership. The caller ran [`check_member_change`] first; a write
/// that still fails fails the request, and the error says how much was
/// applied.
fn reconcile_members(
    state: &AppState,
    auth: &ScimAuth,
    org_id: &OrganizationId,
    desired: &[ScimMember],
) -> Result<(), ScimError> {
    let current = all_members(state, &auth.realm_id, org_id)?;
    let current_ids: std::collections::HashSet<UserId> =
        current.iter().map(|m| m.user_id().clone()).collect();
    let desired_ids = desired_member_ids(desired)?;
    let to_add: Vec<UserId> = desired_ids.difference(&current_ids).cloned().collect();
    let to_remove = stale_members(&current, &desired_ids);
    apply_membership_diff(
        &to_add,
        &to_remove,
        |id| {
            state
                .identity
                .add_member(&auth.realm_id, org_id, id, OrganizationRole::Member)
                .map(|_| ())
        },
        |id| state.identity.remove_member(&auth.realm_id, org_id, id),
    )
}

/// Applies a membership diff: every add, then every removal. An add of a
/// current member or a removal of a former one is benign (a concurrent
/// change got there first). Any other failure stops the diff and fails the
/// request with an error naming the failed step and how much was applied —
/// never a silent partial success.
fn apply_membership_diff(
    to_add: &[UserId],
    to_remove: &[UserId],
    mut add: impl FnMut(&UserId) -> Result<(), crate::identity::IdentityError>,
    mut remove: impl FnMut(&UserId) -> Result<(), crate::identity::IdentityError>,
) -> Result<(), ScimError> {
    use crate::identity::IdentityError;

    let failed = |step: &str, id: &UserId, e: &IdentityError, added: usize, removed: usize| {
        let cause = from_identity_error(e);
        let status = if cause.status.is_success() {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            cause.status
        };
        tracing::warn!(
            error = %e,
            step,
            added,
            removed,
            "SCIM group membership update failed part-way"
        );
        ScimError::new(
            status,
            format!(
                "membership update failed to {step} member {}: {}; applied {added} of {} \
                 additions and {removed} of {} removals before the failure",
                id.as_uuid(),
                cause.detail,
                to_add.len(),
                to_remove.len(),
            ),
        )
    };
    let mut added = 0usize;
    for id in to_add {
        match add(id) {
            Ok(()) | Err(IdentityError::AlreadyMember) => added += 1,
            Err(e) => return Err(failed("add", id, &e, added, 0)),
        }
    }
    let mut removed = 0usize;
    for id in to_remove {
        match remove(id) {
            Ok(()) | Err(IdentityError::NotAMember) => removed += 1,
            Err(e) => return Err(failed("remove", id, &e, added, removed)),
        }
    }
    Ok(())
}

/// The response to a successful `PUT` / `PATCH`: the group as stored now
/// (`fallback` if it can no longer be read), with its full membership.
fn updated_group_response(
    state: &AppState,
    realm_id: &RealmId,
    org_id: &OrganizationId,
    fallback: Organization,
    base: &ScimBase,
) -> Response {
    let refreshed = state
        .identity
        .get_organization(realm_id, org_id)
        .ok()
        .flatten()
        .unwrap_or(fallback);
    let ext = state
        .identity
        .get_scim_group_external_id(realm_id, org_id)
        .ok()
        .flatten();
    let members = match load_members(state, realm_id, org_id) {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    let version = group_version(&refreshed);
    let scim = group_to_scim(&refreshed, &members, ext, base);
    resource_response(&scim, &version)
}

// ================== Handlers ==================

/// `POST /scim/v2/Groups`
pub async fn create_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    base: ScimBase,
    Json(body): Json<ScimGroup>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Groups) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    if let Some(ext) = &body.external_id {
        if let Ok(Some(_)) = state
            .identity
            .find_group_by_scim_external_id(&auth.realm_id, ext)
        {
            return ScimError::uniqueness("externalId already provisioned").into_response();
        }
    }

    // Every member is checked before the organization is created, so an
    // unknown or malformed member leaves nothing half-created.
    let validated = desired_member_ids(&body.members)
        .and_then(|ids| check_members_exist(&state, &auth.realm_id, &ids));
    if let Err(e) = validated {
        return e.into_response();
    }

    let mut slug = slugify(&body.display_name);
    // Retry with uuid suffix on conflict (up to 3 tries).
    for _ in 0..3 {
        let exists = state
            .identity
            .get_organization_by_slug(&auth.realm_id, &slug)
            .map(|o| o.is_some())
            .unwrap_or(false);
        if !exists {
            break;
        }
        let tail = uuid::Uuid::new_v4().to_string();
        slug = format!("{}-{}", slug, &tail[..6]);
    }

    let req = CreateOrganizationRequest {
        name: body.display_name.clone(),
        slug,
        description: None,
        config: None,
        attributes: std::collections::BTreeMap::new(),
    };
    // SCIM-created organizations carry the durable "provisioned by SCIM"
    // marker: the only ones a provisioning token may later modify or delete.
    let org = match state
        .identity
        .create_scim_organization(&auth.realm_id, &req)
    {
        Ok(o) => o,
        Err(e) => return from_identity_error(&e).into_response(),
    };

    if let Some(ext) = &body.external_id {
        if let Err(e) = state
            .identity
            .set_scim_group_external_id(&auth.realm_id, org.id(), ext)
        {
            return from_identity_error(&e).into_response();
        }
    }

    if let Err(e) = reconcile_members(&state, &auth, org.id(), &body.members) {
        return e.into_response();
    }

    audit(
        &state,
        &auth.realm_id,
        &auth.actor,
        AuditAction::ScimGroupCreated,
        org.id(),
        body.external_id.as_deref(),
    );

    let members = match load_members(&state, &auth.realm_id, org.id()) {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    let scim = group_to_scim(&org, &members, body.external_id.clone(), &base);
    let mut resp = (StatusCode::CREATED, Json(scim.clone())).into_response();
    // The path is built from a UUID and a realm name of ASCII letters, digits,
    // `-` and `_`, so it is always a valid header value.
    if let Ok(location) = HeaderValue::from_str(&group_location(&base, &org)) {
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

/// `GET /scim/v2/Groups/{id}`
pub async fn get_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    base: ScimBase,
    Path(ResourceIdPath { id }): Path<ResourceIdPath>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Groups) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("group not found").into_response();
    };
    let org_id = OrganizationId::new(uuid);
    match state.identity.get_organization(&auth.realm_id, &org_id) {
        Ok(Some(org)) => {
            let ext = state
                .identity
                .get_scim_group_external_id(&auth.realm_id, &org_id)
                .ok()
                .flatten();
            let members = match load_members(&state, &auth.realm_id, &org_id) {
                Ok(m) => m,
                Err(e) => return e.into_response(),
            };
            let version = group_version(&org);
            let scim = group_to_scim(&org, &members, ext, &base);
            resource_response(&scim, &version)
        }
        Ok(None) => ScimError::not_found("group not found").into_response(),
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

/// `GET /scim/v2/Groups`
pub async fn list_groups(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    base: ScimBase,
    Query(q): Query<ListQuery>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Groups) {
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
    let count = q.count.unwrap_or(100).min(MAX_PAGE_LIMIT as usize);
    let listed = match filter_expr {
        None => unfiltered_groups(&state, &auth.realm_id, start, count),
        Some(expr) => filtered_groups(&state, &auth.realm_id, &expr, &base)
            .map(|matches| page_of(matches, start, count)),
    };
    let (total, page) = match listed {
        Ok(listed) => listed,
        Err(e) => return e.into_response(),
    };
    let mut slice: Vec<ScimGroup> = Vec::with_capacity(page.len());
    for (org, external_id) in page {
        let members = match load_members(&state, &auth.realm_id, org.id()) {
            Ok(m) => m,
            Err(e) => return e.into_response(),
        };
        slice.push(group_to_scim(&org, &members, external_id, &base));
    }
    Json(ListResponse::new(total, start, slice)).into_response()
}

/// One group of a list page and its SCIM `externalId`.
type GroupRow = (Organization, Option<String>);

/// The external id of `org`, or `None` when it has none or the read fails.
fn external_id_of(state: &AppState, realm_id: &RealmId, org: &Organization) -> Option<String> {
    state
        .identity
        .get_scim_group_external_id(realm_id, org.id())
        .ok()
        .flatten()
}

/// The `[start, start + count)` slice (1-based `start`) of `matches`, and
/// the number of matches.
fn page_of(matches: Vec<GroupRow>, start: usize, count: usize) -> (usize, Vec<GroupRow>) {
    let total = matches.len();
    let page = matches
        .into_iter()
        .skip(start.saturating_sub(1))
        .take(count)
        .collect();
    (total, page)
}

/// One page of every group of the realm, read directly at `start` (#644).
///
/// The total is the exact number of groups of the realm.
fn unfiltered_groups(
    state: &AppState,
    realm_id: &RealmId,
    start: usize,
    count: usize,
) -> Result<(usize, Vec<GroupRow>), ScimError> {
    let offset = u64::try_from(start.saturating_sub(1)).unwrap_or(u64::MAX);
    // `PageRequest` reads at least one row; `count=0` asks for the total only.
    let limit = u32::try_from(count).unwrap_or(MAX_PAGE_LIMIT);
    let page = state
        .identity
        .list_organizations(realm_id, &PageRequest::new(offset, limit))
        .map_err(|e| from_identity_error(&e))?;
    let total = usize::try_from(page.total).unwrap_or(usize::MAX);
    let rows = page
        .items
        .into_iter()
        .take(count)
        .map(|org| {
            let ext = external_id_of(state, realm_id, &org);
            (org, ext)
        })
        .collect();
    Ok((total, rows))
}

/// The groups that match `expr`, in group-id order (#644).
///
/// A filter reads every group of the realm, so a realm with more than
/// [`SCIM_FILTER_SCAN_LIMIT`] groups gets `400` `tooMany` (RFC 7644 §3.12),
/// not the matches of part of the realm. Filters never read `members`, so
/// the match uses the member-less representation.
fn filtered_groups(
    state: &AppState,
    realm_id: &RealmId,
    expr: &FilterExpr,
    base: &ScimBase,
) -> Result<Vec<GroupRow>, ScimError> {
    let scan_limit = u64::try_from(SCIM_FILTER_SCAN_LIMIT).unwrap_or(u64::MAX);
    let realm_groups = state
        .identity
        .list_organizations(realm_id, &PageRequest::new(0, 1))
        .map_err(|e| from_identity_error(&e))?
        .total;
    if realm_groups > scan_limit {
        return Err(ScimError::bad_request(
            "tooMany",
            format!(
                "This filter reads every group, and the realm has more than \
                 {SCIM_FILTER_SCAN_LIMIT} groups. Use GET /Groups/{{id}} or page \
                 the list without a filter."
            ),
        ));
    }

    let mut matches = Vec::new();
    let mut offset = 0u64;
    // The bound holds when groups are created during the walk.
    while offset < scan_limit {
        let page = state
            .identity
            .list_organizations(realm_id, &PageRequest::new(offset, MAX_PAGE_LIMIT))
            .map_err(|e| from_identity_error(&e))?;
        if page.items.is_empty() {
            break;
        }
        offset = offset.saturating_add(page.items.len() as u64);
        for org in page.items {
            let ext = external_id_of(state, realm_id, &org);
            let scim = group_to_scim(&org, &[], ext, base);
            if filter::matches_group(expr, &scim) {
                matches.push((org, scim.external_id));
            }
        }
    }
    Ok(matches)
}

/// `PUT /scim/v2/Groups/{id}`
pub async fn replace_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    base: ScimBase,
    Path(ResourceIdPath { id }): Path<ResourceIdPath>,
    Json(body): Json<ScimGroup>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Groups) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("group not found").into_response();
    };
    let org_id = OrganizationId::new(uuid);

    let existing = match state.identity.get_organization(&auth.realm_id, &org_id) {
        Ok(Some(o)) => o,
        Ok(None) => return ScimError::not_found("group not found").into_response(),
        Err(e) => return from_identity_error(&e).into_response(),
    };

    // Optimistic concurrency: reject a stale `If-Match` before mutating
    // (HEA-2172).
    if let Err(e) = check_if_match(&headers, &group_version(&existing)) {
        return e.into_response();
    }
    if let Err(resp) = provisioning_token_may_write(&auth, &existing) {
        return resp;
    }
    if let Err(e) = check_member_change(&state, &auth, &org_id, &body.members) {
        return e.into_response();
    }

    let req = UpdateOrganizationRequest {
        name: Some(body.display_name.clone()),
        description: None,
        status: None,
        config: None,
        attributes: None,
    };
    if let Err(e) = state
        .identity
        .update_organization(&auth.realm_id, &org_id, &req)
    {
        return from_identity_error(&e).into_response();
    }

    match body.external_id.as_deref() {
        Some(ext) if !ext.is_empty() => {
            if let Err(e) = state
                .identity
                .set_scim_group_external_id(&auth.realm_id, &org_id, ext)
            {
                return from_identity_error(&e).into_response();
            }
        }
        _ => {
            let _ = state
                .identity
                .clear_scim_group_external_id(&auth.realm_id, &org_id);
        }
    }

    if let Err(e) = reconcile_members(&state, &auth, &org_id, &body.members) {
        return e.into_response();
    }

    audit(
        &state,
        &auth.realm_id,
        &auth.actor,
        AuditAction::ScimGroupUpdated,
        &org_id,
        body.external_id.as_deref(),
    );

    updated_group_response(&state, &auth.realm_id, &org_id, existing, &base)
}

/// `PATCH /scim/v2/Groups/{id}`
pub async fn patch_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    base: ScimBase,
    Path(ResourceIdPath { id }): Path<ResourceIdPath>,
    Json(body): Json<PatchRequest>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Groups) {
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
        return ScimError::not_found("group not found").into_response();
    };
    let org_id = OrganizationId::new(uuid);

    let existing = match state.identity.get_organization(&auth.realm_id, &org_id) {
        Ok(Some(o)) => o,
        Ok(None) => return ScimError::not_found("group not found").into_response(),
        Err(e) => return from_identity_error(&e).into_response(),
    };

    // Optimistic concurrency: reject a stale `If-Match` before mutating
    // (HEA-2172).
    if let Err(e) = check_if_match(&headers, &group_version(&existing)) {
        return e.into_response();
    }
    if let Err(resp) = provisioning_token_may_write(&auth, &existing) {
        return resp;
    }

    let current_ext = state
        .identity
        .get_scim_group_external_id(&auth.realm_id, &org_id)
        .ok()
        .flatten();
    let members = match load_members(&state, &auth.realm_id, &org_id) {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    let mut scim = group_to_scim(&existing, &members, current_ext.clone(), &base);
    if let Err(e) = apply_group_patch(&mut scim, &body.operations) {
        return e.into_response();
    }
    if let Err(e) = check_member_change(&state, &auth, &org_id, &scim.members) {
        return e.into_response();
    }

    // Apply displayName change.
    if scim.display_name != existing.name() {
        let req = UpdateOrganizationRequest {
            name: Some(scim.display_name.clone()),
            description: None,
            status: None,
            config: None,
            attributes: None,
        };
        if let Err(e) = state
            .identity
            .update_organization(&auth.realm_id, &org_id, &req)
        {
            return from_identity_error(&e).into_response();
        }
    }

    // Sync externalId.
    if scim.external_id != current_ext {
        match scim.external_id.as_deref() {
            Some(ext) if !ext.is_empty() => {
                if let Err(e) =
                    state
                        .identity
                        .set_scim_group_external_id(&auth.realm_id, &org_id, ext)
                {
                    return from_identity_error(&e).into_response();
                }
            }
            _ => {
                let _ = state
                    .identity
                    .clear_scim_group_external_id(&auth.realm_id, &org_id);
            }
        }
    }

    // Reconcile membership.
    if let Err(e) = reconcile_members(&state, &auth, &org_id, &scim.members) {
        return e.into_response();
    }

    audit(
        &state,
        &auth.realm_id,
        &auth.actor,
        AuditAction::ScimGroupUpdated,
        &org_id,
        scim.external_id.as_deref(),
    );

    updated_group_response(&state, &auth.realm_id, &org_id, existing, &base)
}

/// `DELETE /scim/v2/Groups/{id}`
pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ResourceIdPath { id }): Path<ResourceIdPath>,
) -> Response {
    let auth = match authenticate(&headers, &state, ScimResource::Groups) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return ScimError::not_found("group not found").into_response();
    };
    let org_id = OrganizationId::new(uuid);

    // The provisioning token needs the organization's SCIM marker, and a
    // caller's `If-Match` needs its version: read it when either applies.
    if auth.provisioning_token || headers.contains_key(axum::http::header::IF_MATCH) {
        match state.identity.get_organization(&auth.realm_id, &org_id) {
            Ok(Some(org)) => {
                // Optimistic concurrency: reject a stale validator before
                // deleting (HEA-2172).
                if let Err(e) = check_if_match(&headers, &group_version(&org)) {
                    return e.into_response();
                }
                if let Err(resp) = provisioning_token_may_write(&auth, &org) {
                    return resp;
                }
            }
            Ok(None) => return ScimError::not_found("group not found").into_response(),
            Err(e) => return from_identity_error(&e).into_response(),
        }
    }

    // Deleting the organization strips every admin permission its members
    // hold only in it (GA sweep 4).
    if let Err(e) = check_org_admin_ceiling(
        state.identity.as_ref(),
        state.rbac.as_ref(),
        &auth.realm_id,
        &org_id,
        &auth.actor_permissions,
    ) {
        return from_ceiling_error(
            e,
            "a member of this group holds admin permissions the caller lacks",
        )
        .into_response();
    }
    match state.identity.delete_organization(&auth.realm_id, &org_id) {
        Ok(()) => {
            audit(
                &state,
                &auth.realm_id,
                &auth.actor,
                AuditAction::ScimGroupDeleted,
                &org_id,
                None,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => from_identity_error(&e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityError;

    fn ids(n: usize) -> Vec<UserId> {
        (0..n).map(|_| UserId::generate()).collect()
    }

    /// A removal that fails fails the whole request, stops the diff there,
    /// and says how much was applied; it is never swallowed.
    #[test]
    fn a_failed_removal_fails_the_request_and_reports_progress() {
        let (add, remove) = (ids(1), ids(3));
        let mut attempted = Vec::new();

        let err = apply_membership_diff(
            &add,
            &remove,
            |_| Ok(()),
            |id| {
                attempted.push(id.clone());
                if *id == remove[1] {
                    Err(IdentityError::Internal {
                        reason: "disk full".into(),
                    })
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("a failed removal must fail the request");

        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            err.detail.contains("failed to remove member")
                && err.detail.contains(&remove[1].as_uuid().to_string())
                && err
                    .detail
                    .contains("applied 1 of 1 additions and 1 of 3 removals"),
            "{}",
            err.detail
        );
        assert_eq!(
            attempted,
            remove[..2].to_vec(),
            "the diff stops at the failure"
        );
    }

    /// A failed addition stops before any removal.
    #[test]
    fn a_failed_addition_stops_before_removals() {
        let (add, remove) = (ids(2), ids(2));
        let mut removals = 0usize;

        let err = apply_membership_diff(
            &add,
            &remove,
            |id| {
                if *id == add[0] {
                    Err(IdentityError::UserNotFound)
                } else {
                    Ok(())
                }
            },
            |_| {
                removals += 1;
                Ok(())
            },
        )
        .expect_err("a failed addition must fail the request");

        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert!(
            err.detail.contains("failed to add member"),
            "{}",
            err.detail
        );
        assert_eq!(removals, 0);
    }

    /// A concurrent change that got there first is not a failure.
    #[test]
    fn already_applied_steps_are_benign() {
        let (add, remove) = (ids(1), ids(1));

        let mut calls = 0usize;
        apply_membership_diff(
            &add,
            &remove,
            |_| {
                calls += 1;
                Err(IdentityError::AlreadyMember)
            },
            |_| Err(IdentityError::NotAMember),
        )
        .expect("steps a concurrent change already applied are benign");

        assert_eq!(calls, 1, "the addition was attempted");
    }
}
