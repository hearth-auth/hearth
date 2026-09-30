//! Shared authentication and helper utilities used across HTTP handlers.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::core::{ClientId, RealmId, UserId};
use crate::protocol::admin_auth::{
    ExportRateLimitOutcome, RateLimitOutcome, TokenRateLimitOutcome, TokenRateLimiter,
};
use crate::rbac::RbacError;

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
///
/// The `Result` **must** be used — discarding it silently bypasses authentication.
#[must_use = "discarding this Result bypasses authentication; bind the return value"]
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
    // (`ADMIN_PERMISSIONS`). Sub-admins pass this outer gate but are still
    // checked per-handler via require_admin_permission(). hearth.admin
    // bypasses all per-handler checks.
    let is_admin = claims
        .permissions
        .iter()
        .any(|p| crate::protocol::admin_auth::is_admin_permission(p));
    // A token held by a third-party client never administers the realm, even
    // when a claim profile releases admin permissions to it (GA audit B1).
    if !is_admin
        || !crate::protocol::admin_auth::token_client_may_administer(
            state.identity.as_ref(),
            &realm_id,
            &claims,
        )
    {
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
        // `claims` is an `Arc<TokenClaims>` (HEA-1771); clone the owned field.
        permissions: claims.permissions.clone(),
    })
}

/// Enforces the DPoP sender-constraint (RFC 9449 §7.2) on the administrative
/// surface.
///
/// `extract_admin_auth` (and SCIM's `authenticate`) validate the bearer token's
/// signature, realm and permissions but never looked at `cnf`. A DPoP-bound
/// admin token — one whose holder proved possession of a private key at
/// issuance — was therefore accepted as a plain `Bearer` for every admin read
/// and write, which is exactly the replay the binding exists to prevent
/// (audit 2026-08-28 §4.19#8). The resource endpoints under `/oauth` have
/// enforced this since HEA-2031 through `enforce_dpop_binding`; the admin
/// surface simply never called it.
///
/// It runs as a layer rather than inside `extract_admin_auth` because the
/// proof covers the request method and URI, and the extractor sees only
/// headers. Applied with `route_layer`, so it never fires on an unmatched path.
///
/// Mounted on every router whose handlers authenticate through
/// `extract_admin_auth`: the `/admin` and `/scim/v2` nests (18.18), and — since
/// task 25.17 — `users::routes()`, `oauth::admin_routes()`, `agents::routes()`,
/// `approval::routes()` and `advanced::routes()`, which are merged at the
/// router root rather than nested and were therefore missed the first time.
/// `tool_invocation::routes()` is deliberately excluded: it validates the proof
/// itself, and a second validation would record the proof's `jti` on the first
/// pass and reject the second as a replay (RFC 9449 §11.1). The list of mount
/// points lives in `router_with`; a new `extract_admin_auth` call site in a new
/// router must be added there.
///
/// Fail-open is deliberate for *unauthenticated* shapes only: a request with no
/// bearer token, no realm header, or a token that does not validate is passed
/// through untouched so the handler's own gate produces the usual `400`/`401`.
/// A token that **would** be accepted and carries `cnf.jkt` must present a
/// matching proof or the request is rejected here.
pub(crate) async fn enforce_admin_dpop(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // `nest` strips the mount prefix from `Uri`, so the path the client signed
    // survives only in `OriginalUri` (HEA-2031 hit the same trap on
    // `/userinfo`). Fall back to the request URI when the extension is absent.
    let path = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map_or_else(|| req.uri().path().to_string(), |o| o.0.path().to_string());
    let method = req.method().as_str().to_string();

    let outcome = {
        let headers = req.headers();
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned);
        match (token, extract_realm_id(headers)) {
            (Some(token), Ok(realm_id)) => state
                .identity
                .validate_token(&realm_id, &token)
                .ok()
                .and_then(|claims| claims.cnf.as_ref().map(|cnf| cnf.jkt.clone()))
                .map(|jkt| {
                    let htu = format!("{}{}", state.identity.oidc_discovery().issuer, path);
                    enforce_dpop_binding(headers, &state, &realm_id, &token, &jkt, &method, &htu)
                }),
            _ => None,
        }
    };

    match outcome {
        Some(Err(rejection)) => rejection.into_response(),
        _ => next.run(req).await,
    }
}

/// Extracts and validates admin authentication for cluster-level operations.
///
/// Identical to [`extract_admin_auth`] but additionally asserts **both** of:
///
/// 1. The `X-Realm-ID` header identifies the **system realm** (nil UUID).
///    Cluster operations are node-wide, not realm-scoped; accepting a
///    tenant-realm token would allow a tenant admin to transfer Raft leadership
///    or bootstrap the cluster — a privilege-escalation vector (HEA-763).
/// 2. The caller holds `hearth.admin`. `extract_admin_auth` deliberately admits
///    every `hearth.*.admin` sub-admin, so condition (1) alone let a system-realm
///    operator delegated only `hearth.users.admin` bootstrap Raft membership or
///    transfer leadership — the two most destructive operations in the product.
///    There is no narrower permission for the cluster plane and inventing one
///    would be a delegation boundary nobody asked for, so the gate is the
///    superuser permission itself.
///
/// Returns `403 Forbidden` in both cases, even when the bearer token is
/// otherwise valid.
///
/// The permission gate lives **here** rather than in each handler on purpose:
/// all three cluster handlers call this function first, before any
/// cluster-availability check, so a single-node deployment answers `403` to an
/// unauthorized caller rather than disclosing `503 not in cluster mode` — and a
/// future fourth cluster handler cannot forget the gate, which is exactly the
/// defect this closes.
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
    require_superuser(&auth, "cluster operations")?;
    Ok(auth)
}

/// Checks that the caller holds `hearth.admin` itself — not merely one of the
/// `hearth.*.admin` sub-admin permissions [`extract_admin_auth`] also admits.
///
/// For operations whose reach exceeds any sub-admin domain: the cluster plane
/// ([`extract_cluster_admin_auth`]), every backup restore (it writes users,
/// clients, role assignments, agents and keys at once), and a backup export by
/// a system-realm caller, which reaches every realm — the system realm's
/// operator accounts and signing key included. `purpose` names the operation
/// in the `403` body.
pub(crate) fn require_superuser(
    auth: &AdminAuth,
    purpose: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if auth.permissions.iter().any(|p| p == "hearth.admin") {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "forbidden",
            "error_description": format!("hearth.admin permission required for {purpose}")
        })),
    ))
}

// ── Rate-limiter attribution (HEA-2010) ──────────────────────────────────────
//
// Several independent limiters can answer `429`, and until now every one of
// them produced an untagged body. An operator seeing 429s under load had no way
// to tell which limiter shed the request, so the natural (and wrong) conclusion
// was `security.request_shaper` — even when the shed came from the admin cap.
// Every limiter 429 now carries a `limiter` field naming its source.

/// Admin API per-user limiter (`security.rate_limiting.admin_per_minute`).
pub(crate) const LIMITER_ADMIN: &str = "admin";
/// Token endpoint per-`(realm, client)` limiter (`…token_per_minute`).
pub(crate) const LIMITER_TOKEN: &str = "token";
/// Backup/export per-user hourly limiter (`security.backup.export_rate_limit`).
pub(crate) const LIMITER_EXPORT: &str = "export";
/// Per-IP login limiter on the token and magic-link endpoints.
pub(crate) const LIMITER_LOGIN_IP: &str = "login_ip";
/// Global per-IP + per-realm request shaper (`security.request_shaper`, A-2).
pub(crate) const LIMITER_SHAPER: &str = "shaper";

/// Builds a `429` JSON body tagged with the limiter that shed the request.
///
/// The `error` code stays `too_many_requests` so existing clients keep working;
/// `limiter` is additive.
pub(crate) fn rate_limit_body(limiter: &str, description: &str) -> serde_json::Value {
    serde_json::json!({
        "error": "too_many_requests",
        "error_description": description,
        "limiter": limiter,
    })
}

/// The `429` response returned when the admin API limiter sheds a request.
fn admin_rate_limit_response() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(rate_limit_body(LIMITER_ADMIN, "rate limit exceeded")),
    )
}

/// The `429` response returned when the export limiter sheds a request.
fn export_rate_limit_response() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": "export_rate_limit_exceeded",
            "error_description": "export rate limit exceeded; maximum exports per hour reached",
            "limiter": LIMITER_EXPORT,
        })),
    )
}

/// Checks the admin API rate limit for a user.
///
/// Returns 429 if the user has exceeded the configured per-minute quota
/// (`security.rate_limiting.admin_per_minute`, default 100).
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
        RateLimitOutcome::Exceeded => Err(admin_rate_limit_response()),
    }
}

/// Returns `true` when the given permission set grants the `hearth.export`
/// capability required for backup/export endpoints (A-30).
///
/// This is the single production predicate backing [`check_export_capability`];
/// it is exposed so tests can pin the exact permission-model rule rather than
/// re-implementing the membership check.
#[must_use]
pub fn has_export_capability(permissions: &[String]) -> bool {
    permissions.iter().any(|p| p == "hearth.export")
}

/// Checks that the authenticated admin token carries the `hearth.export`
/// permission required for backup/export endpoints (A-30).
///
/// Returns `403 Forbidden` when the permission is absent. `hearth.export` is
/// held *in addition to* an admin permission: a tenant realm may grant it with
/// a sub-admin permission to a backup service account that EXPORTS that realm.
/// A backup restore — which writes across every sub-admin domain — and an
/// export by a **system-realm** caller, which reaches every realm, also
/// require `hearth.admin` ([`require_superuser`]).
pub(crate) fn check_export_capability(
    auth: &AdminAuth,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if !has_export_capability(&auth.permissions) {
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
    if !crate::protocol::admin_auth::grants_admin_permission(&auth.permissions, required) {
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

/// REST face of the privilege ceiling on user administration
/// ([`crate::protocol::admin_auth::check_user_admin_ceiling`]): the caller may
/// not modify, re-email, reset, disable, delete, demote or sign out a user of
/// `realm_id` who holds an admin permission the caller lacks. Call it after
/// [`require_admin_permission`] and before the mutation, on every
/// user-targeting admin write.
///
/// Returns `403 Forbidden` when the target outranks the caller and
/// `503 Service Unavailable` when the target's permissions cannot be resolved.
pub(crate) fn require_user_admin_ceiling(
    state: &AppState,
    auth: &AdminAuth,
    realm_id: &RealmId,
    target: &UserId,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    crate::protocol::admin_auth::check_user_admin_ceiling(
        state.identity.as_ref(),
        state.rbac.as_ref(),
        realm_id,
        target,
        &auth.permissions,
    )
    .map_err(ceiling_refusal)
}

/// Maps a privilege-ceiling refusal onto the REST error response: `403` when
/// the target outranks the caller, `503` when it could not be resolved.
pub(crate) fn ceiling_refusal(
    e: crate::protocol::admin_auth::UserCeilingError,
) -> (StatusCode, Json<serde_json::Value>) {
    use crate::protocol::admin_auth::UserCeilingError;
    match e {
        UserCeilingError::Exceeded => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "error_description": "the target user holds admin permissions the caller lacks"
            })),
        ),
        UserCeilingError::Unresolved => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "service_unavailable",
                "error_description":
                    "could not resolve the target user's permissions; retry later"
            })),
        ),
    }
}

/// Checks that the caller holds `hearth.admin` or **any one** of the listed
/// granular sub-permissions. Use on read-only endpoints that are safely
/// accessible to multiple sub-admin roles (e.g. both `hearth.realm.admin` and
/// `hearth.users.admin` may read group details without being able to mutate
/// membership).
///
/// Returns `403 Forbidden` when no accepted permission is present.
pub(crate) fn require_any_admin_permission(
    auth: &AdminAuth,
    accepted: &[&str],
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let permitted = auth
        .permissions
        .iter()
        .any(|p| p == "hearth.admin" || accepted.iter().any(|a| p == a));
    if !permitted {
        let list = accepted.join(", ");
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "error_description": format!("one of [{list}] or hearth.admin permission required")
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
        ExportRateLimitOutcome::Exceeded => Err(export_rate_limit_response()),
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
    crate::protocol::audit_log::record(
        state.audit.as_ref(),
        &crate::audit::CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor: user_id.as_uuid().to_string(),
            action: crate::audit::AuditAction::RealmExportWatermarked,
            resource_type: "export".to_string(),
            resource_id: export_id.to_string(),
            metadata: Some(metadata),
        },
    );
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
    token_rate_limit_outcome(
        state
            .token_rate_limiter
            .check(realm_id, client_id, now_micros()),
    )
}

/// Checks the token endpoint rate limit for a request that carries **no**
/// client identity, bucketing it by client IP instead.
///
/// A `grant_type=refresh_token` exchange with no `client_id` and no Basic
/// auth (Hearth's clientless session refresh) never reaches
/// [`check_token_rate_limit`], because there is no `ClientId` to key on. That
/// left the endpoint's only unauthenticated shape completely unbucketed
/// (audit 2026-08-28 §4.16#8). `client_ip` must come from
/// `client_info::extract_client_ip`, which is trusted-proxy aware — a raw
/// `X-Forwarded-For` would let the flooder pick its own bucket.
pub(crate) fn check_anonymous_token_rate_limit(
    state: &AppState,
    realm_id: &RealmId,
    client_ip: &str,
) -> Result<(), Response> {
    let bucket = TokenRateLimiter::anonymous_ip_bucket(client_ip);
    token_rate_limit_outcome(
        state
            .token_rate_limiter
            .check_bucket(realm_id, &bucket, now_micros()),
    )
}

/// Checks a per-client limiter shaped like the token limiter — the claimed
/// client's bucket, or the client-IP bucket when no client id parses — for an
/// endpoint with a budget of its own (`/as/par`).
pub(crate) fn check_client_or_ip_rate_limit(
    limiter: &TokenRateLimiter,
    realm_id: &RealmId,
    claimed_client: Option<&ClientId>,
    peer_ip: &str,
) -> Result<(), Response> {
    token_rate_limit_outcome(match claimed_client {
        Some(client) => limiter.check(realm_id, client, now_micros()),
        None => limiter.check_bucket(
            realm_id,
            &TokenRateLimiter::anonymous_ip_bucket(peer_ip),
            now_micros(),
        ),
    })
}

/// Maps a [`TokenRateLimitOutcome`] onto the shared 429 response shape.
fn token_rate_limit_outcome(outcome: TokenRateLimitOutcome) -> Result<(), Response> {
    match outcome {
        TokenRateLimitOutcome::Allowed => Ok(()),
        TokenRateLimitOutcome::Exceeded { retry_after_secs } => {
            let retry_str = retry_after_secs.to_string();
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", retry_str.as_str())],
                Json(rate_limit_body(LIMITER_TOKEN, "rate limit exceeded")),
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
        Json(rate_limit_body(LIMITER_LOGIN_IP, "rate limit exceeded")),
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

    // A transient cluster failure is a 503 with a fixed message; the router
    // adds `Retry-After` to every 503 that lacks one.
    if let IdentityError::Storage(e) = err {
        if let Some(class) = crate::storage::StorageError::retry_class_of(&**e) {
            tracing::warn!(error = %e, "request refused: cluster unavailable");
            return cluster_unavailable_response(class);
        }
    }

    // A FAPI auth-method refusal says which method is required (RFC 6749 §5.2
    // `error_description`); it names the realm's or client's profile, never
    // whether a presented credential was right.
    if matches!(err, IdentityError::PrivateKeyJwtRequired) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_client",
                "error_description": err.to_string(),
                "error_code": crate::protocol::error_codes::for_identity_error(err),
            })),
        );
    }

    let (status, message) = match err {
        IdentityError::RealmNotFound | IdentityError::UserNotFound => {
            (StatusCode::NOT_FOUND, "not found")
        }
        IdentityError::RealmSuspended => (StatusCode::FORBIDDEN, "realm suspended"),
        IdentityError::RealmNotArchived => (
            StatusCode::CONFLICT,
            "only archived realms can be permanently deleted",
        ),
        IdentityError::RealmArchived => (
            StatusCode::CONFLICT,
            "the realm is archived or being deleted; only an active or suspended realm can \
             be suspended or reinstated",
        ),
        IdentityError::YamlManagedResource { .. } => (
            StatusCode::CONFLICT,
            "this resource is managed by hearth.yaml: it cannot be deleted, and its \
             credentials and security profile cannot be changed, at runtime",
        ),
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
        IdentityError::InvalidClientSecret | IdentityError::PrivateKeyJwtRequired => {
            (StatusCode::UNAUTHORIZED, "invalid_client")
        }
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
        IdentityError::ClientMismatch => (StatusCode::FORBIDDEN, "client mismatch"),
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
        IdentityError::MfaMethodNotAllowed { .. } => (
            StatusCode::FORBIDDEN,
            "mfa method not offered by this realm",
        ),
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
        IdentityError::DPopBindingMismatch | IdentityError::DPopJktBlocked => {
            (StatusCode::UNAUTHORIZED, "invalid_token")
        }
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
        // Shed by the KDF admission gate; callers that can set headers use
        // `identity_error_response`, which adds `Retry-After`.
        IdentityError::KdfOverloaded { .. } => (StatusCode::SERVICE_UNAVAILABLE, "kdf_overloaded"),
        // A-13: attestation policy violation (AAGUID not in allowlist, "none" rejected, etc.).
        IdentityError::AttestationPolicyViolation { .. } => {
            (StatusCode::FORBIDDEN, "attestation_policy_violation")
        }
        IdentityError::AgentNotFound => (StatusCode::NOT_FOUND, "agent not found"),
        IdentityError::AgentRevoked => (StatusCode::FORBIDDEN, "agent revoked"),
        IdentityError::AgentRateLimitExceeded => {
            (StatusCode::TOO_MANY_REQUESTS, "agent_rate_limit_exceeded")
        }
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
        IdentityError::InvalidTarget { .. } => (StatusCode::BAD_REQUEST, "invalid_target"),
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
        // Phase D
        IdentityError::AatScopeEscalation
        | IdentityError::AatChainBroken { .. }
        | IdentityError::AatRevoked
        | IdentityError::AatExpired
        | IdentityError::AatAudienceMismatch => (StatusCode::FORBIDDEN, "aat_validation_failed"),
        IdentityError::TransactionTokenReplayed => (StatusCode::CONFLICT, "txn_token_replayed"),
        IdentityError::CrossRealmPolicyNotFound | IdentityError::SpiffeMappingNotFound => {
            (StatusCode::NOT_FOUND, "not_found")
        }
        IdentityError::CrossRealmPolicyConflict | IdentityError::SpiffeMappingConflict => {
            (StatusCode::CONFLICT, "already_exists")
        }
        IdentityError::CrossRealmCapabilityNotAllowed { .. } => {
            (StatusCode::FORBIDDEN, "cross_realm_capability_not_allowed")
        }
        IdentityError::SpiffeIdInvalid { .. } | IdentityError::SpiffeCertInvalid { .. } => {
            (StatusCode::BAD_REQUEST, "spiffe_invalid")
        }
        IdentityError::SpiffeCertExpired => (StatusCode::UNAUTHORIZED, "spiffe_cert_expired"),
    };

    // The body of a 500 is deliberately vague and the trace layer logs only
    // the status, so this is the one place the cause of a 500 is recorded —
    // in a PII-safe form: an internal error can wrap text Hearth did not
    // write, such as an SMTP rejection naming the recipient.
    if status == StatusCode::INTERNAL_SERVER_ERROR {
        tracing::error!(
            error = %crate::protocol::redact::LogSafeError(err),
            "request failed with an internal error"
        );
    }

    let error_code = crate::protocol::error_codes::for_identity_error(err);
    (
        status,
        Json(serde_json::json!({"error": message, "error_code": error_code})),
    )
}
/// The `503` body for a transient cluster failure: a fixed message per
/// [`RetryClass`](crate::storage::RetryClass) and its stable `error_code`,
/// never the operator-facing detail behind it.
pub(crate) fn cluster_unavailable_response(
    class: crate::storage::RetryClass,
) -> (StatusCode, Json<serde_json::Value>) {
    use crate::protocol::error_codes::{CLUSTER_UNAVAILABLE, CLUSTER_WRITE_OUTCOME_UNKNOWN};
    let (error, description, code) = match class {
        crate::storage::RetryClass::OutcomeUnknown => (
            "write_outcome_unknown",
            "The write may or may not have been applied. Re-read before retrying.",
            CLUSTER_WRITE_OUTCOME_UNKNOWN,
        ),
        _ => (
            "cluster_unavailable",
            "The cluster cannot serve this request right now and nothing was written. \
             Retry shortly.",
            CLUSTER_UNAVAILABLE,
        ),
    };
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
            "error_code": code,
        })),
    )
}

/// Maps [`RbacError`] values to HTTP responses.
pub(crate) fn rbac_error_to_response(err: &RbacError) -> (StatusCode, Json<serde_json::Value>) {
    if let RbacError::Storage(e) = err {
        if let Some(class) = crate::storage::StorageError::retry_class_of(&**e) {
            tracing::warn!(error = %e, "request refused: cluster unavailable");
            return cluster_unavailable_response(class);
        }
    }
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
/// Enforces DPoP proof validation for `cnf`-bound tokens at resource endpoints
/// (RFC 9449 §7.2). Called from the user-token extractors
/// ([`extract_user_auth_claims`] and its first-party / session variants) when
/// the validated token carries a `cnf.jkt` claim.
fn enforce_dpop_binding(
    headers: &HeaderMap,
    state: &AppState,
    realm_id: &RealmId,
    token: &str,
    expected_jkt: &str,
    htm: &str,
    htu: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let proof = headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "DPoP proof required for cnf-bound access token"
                })),
            )
        })?;

    #[allow(clippy::cast_possible_truncation)]
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let validated = crate::identity::dpop::validate_dpop_proof(
        proof,
        htm,
        htu,
        now_secs,
        None,        // nonce not required at resource server
        Some(token), // ath = SHA-256(access_token) required at resource endpoints
    )
    .map_err(|e| identity_error_to_response(&e))?;

    // JKT must match what was bound at token issuance (RFC 9449 §7.1).
    if validated.jkt != expected_jkt {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": "DPoP proof key does not match token cnf.jkt binding"
            })),
        ));
    }

    // Record JTI to prevent proof replay (RFC 9449 §11.1).
    state
        .identity
        .check_and_record_dpop_jti(realm_id, &validated.jti, now_secs)
        .map_err(|e| identity_error_to_response(&e))?;

    Ok(())
}

/// Extracts and validates user authentication, enforcing DPoP binding for
/// `cnf`-bound tokens (RFC 9449 §7.2), and returns the user with the bearer
/// token's validated claims — for a handler that judges the client the token
/// was issued to. Any client's token passes; a surface that acts with the
/// user's full authority uses [`extract_first_party_user_auth`] instead.
///
/// `htm` is the HTTP method (e.g. `"GET"`). `htu` is the full request URI
/// including scheme and authority (e.g. `"https://auth.example.com/oauth/consents"`).
pub(crate) fn extract_user_auth_claims(
    headers: &HeaderMap,
    state: &AppState,
    realm_id: &RealmId,
    htm: &str,
    htu: &str,
) -> Result<
    (UserId, std::sync::Arc<crate::identity::TokenClaims>),
    (StatusCode, Json<serde_json::Value>),
> {
    user_auth_claims(headers, state, realm_id, htm, htu)
}

/// [`extract_user_auth_claims`] for account self-service surfaces that act with the
/// user's full authority over their own account — consents, passkeys (GA
/// audit 3 B-5). The token must be a first-party session token or one issued
/// to a first-party client
/// ([`crate::protocol::admin_auth::token_client_may_administer`], the gate the
/// admin API applies); a third-party client's token is refused
/// `403 forbidden`, whatever the claim profile released to it.
pub(crate) fn extract_first_party_user_auth(
    headers: &HeaderMap,
    state: &AppState,
    realm_id: &RealmId,
    htm: &str,
    htu: &str,
) -> Result<UserId, (StatusCode, Json<serde_json::Value>)> {
    let (user_id, claims) = user_auth_claims(headers, state, realm_id, htm, htu)?;
    if !crate::protocol::admin_auth::token_client_may_administer(
        state.identity.as_ref(),
        realm_id,
        &claims,
    ) {
        return Err(third_party_token_forbidden());
    }
    Ok(user_id)
}

/// The refusal of a third-party client's token on a first-party-only surface.
pub(crate) fn third_party_token_forbidden() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "forbidden",
            "error_description": "a token issued to a third-party client cannot use this endpoint"
        })),
    )
}

/// [`extract_user_auth_claims`] for a surface the engine must judge by the
/// token itself: the
/// non-interactive `/authorize` checks the client the token was issued to
/// (GA audit 3 B-1) and the factor its session proved (GA audit B2/B5). A
/// token whose `sid` names no session (a sessionless token) is refused.
pub(crate) fn extract_user_session_auth(
    headers: &HeaderMap,
    state: &AppState,
    realm_id: &RealmId,
    htm: &str,
    htu: &str,
) -> Result<
    (UserId, std::sync::Arc<crate::identity::TokenClaims>),
    (StatusCode, Json<serde_json::Value>),
> {
    let (user_id, claims) = user_auth_claims(headers, state, realm_id, htm, htu)?;
    if claims.sid.parse::<crate::core::SessionId>().is_err() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        ));
    }
    Ok((user_id, claims))
}

/// Validates the bearer token (with its DPoP binding) and parses its user.
fn user_auth_claims(
    headers: &HeaderMap,
    state: &AppState,
    realm_id: &RealmId,
    htm: &str,
    htu: &str,
) -> Result<
    (UserId, std::sync::Arc<crate::identity::TokenClaims>),
    (StatusCode, Json<serde_json::Value>),
> {
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

    let claims = validate_user_token_with_dpop(headers, state, realm_id, token, htm, htu)?;

    // sub is "user_{uuid}" — strip the prefix before UUID parse.
    let sub_str = claims.sub.strip_prefix("user_").unwrap_or(&claims.sub);
    let user_id = uuid::Uuid::parse_str(sub_str)
        .map(UserId::new)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
        })?;
    Ok((user_id, claims))
}

/// Validates a bearer `token` and enforces the DPoP sender-constraint
/// (RFC 9449 §7.2) when the token carries a `cnf.jkt` confirmation claim,
/// returning the decoded claims on success.
///
/// Resource endpoints that consume the raw access token directly — rather than
/// through [`extract_user_auth_claims`] — MUST route through this guard so a
/// stolen DPoP-bound token cannot be replayed as a plain `Bearer` (HEA-2031).
/// Callers that only need the [`UserId`] should prefer
/// [`extract_first_party_user_auth`]; this
/// helper exists for handlers that must hand the raw token to the identity
/// layer (e.g. `/userinfo`, `/v1/me/permissions`).
///
/// Fails closed: a token presenting `cnf.jkt` without a valid matching DPoP
/// proof is rejected with `401 invalid_token` before any user lookup.
pub(crate) fn validate_user_token_with_dpop(
    headers: &HeaderMap,
    state: &AppState,
    realm_id: &RealmId,
    token: &str,
    htm: &str,
    htu: &str,
) -> Result<std::sync::Arc<crate::identity::TokenClaims>, (StatusCode, Json<serde_json::Value>)> {
    let claims = state
        .identity
        .validate_token(realm_id, token)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
        })?;

    // Resource servers MUST verify the DPoP proof for cnf-bound tokens
    // (RFC 9449 §7.2). Plain Bearer use of a DPoP-bound token is rejected
    // before any user lookup or permission resolution.
    if let Some(ref cnf) = claims.cnf {
        enforce_dpop_binding(headers, state, realm_id, token, &cnf.jkt, htm, htu)?;
    }

    Ok(claims)
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

#[cfg(test)]
mod proto_json_tests {
    //! Unit coverage for [`proto_to_rest_json`] int64-as-string coercion
    //! (HEA-1836; the §763 P0 "int64 REST coercion" box). pbjson follows the
    //! proto3 JSON mapping and serializes int64/uint64 fields as JSON strings;
    //! the helper must convert them back to numbers for REST clients without
    //! losing precision.
    use super::proto_to_rest_json;
    use crate::protocol::proto::identity::v1 as pb;

    #[test]
    fn coerces_proto_int64_field_to_json_number() {
        // ClientCredentialsResponse.expires_in is `int64` — pbjson serializes
        // it as the string "3600"; the REST helper must emit a JSON number.
        let resp = pb::ClientCredentialsResponse {
            access_token: "tok".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            scope: Some("openid".to_string()),
        };
        let v = proto_to_rest_json(&resp);
        let expires = v.get("expiresIn").or_else(|| v.get("expires_in"));
        let expires = expires.expect("expires_in field present in serialized proto");
        assert!(
            expires.is_number(),
            "int64 field must be coerced to a JSON number, got: {expires:?}"
        );
        assert_eq!(expires.as_i64(), Some(3600));
    }

    #[test]
    fn preserves_large_int64_without_precision_loss() {
        // 2^53 + 1 is not exactly representable as f64; coercion must keep the
        // exact integer value (the whole reason pbjson strings int64 fields).
        let big: i64 = 9_007_199_254_740_993;
        let v = proto_to_rest_json(&serde_json::json!({ "n": big.to_string() }));
        assert_eq!(v["n"].as_i64(), Some(big));
        assert!(v["n"].is_number());
    }

    #[test]
    fn recurses_into_nested_objects_and_arrays() {
        let v = proto_to_rest_json(&serde_json::json!({
            "outer": { "inner": "42" },
            "list": ["1", "2", "-3"],
        }));
        assert_eq!(v["outer"]["inner"].as_i64(), Some(42));
        assert_eq!(v["list"][0].as_i64(), Some(1));
        assert_eq!(v["list"][2].as_i64(), Some(-3));
    }

    #[test]
    fn leaves_non_integer_strings_untouched() {
        // Non-numeric strings (tokens, UUIDs) and booleans must be preserved.
        let v = proto_to_rest_json(&serde_json::json!({
            "token": "abc123def",
            "flag": true,
            "empty": "",
        }));
        assert_eq!(v["token"].as_str(), Some("abc123def"));
        assert_eq!(v["flag"].as_bool(), Some(true));
        assert_eq!(v["empty"].as_str(), Some(""));
    }
}

#[cfg(test)]
mod rate_limit_attribution_tests {
    //! Every limiter `429` must name its own source.
    //
    //! Without it the only signal an operator (or the saturation harness) has
    //! is the status code, which points them at `security.request_shaper` even
    //! when the shed came from the admin or token limiter — exactly the
    //! misdiagnosis that cost the HEA-1970 dry-run its read-plane knee.
    use super::{
        admin_rate_limit_response, export_rate_limit_response, rate_limit_body, LIMITER_ADMIN,
        LIMITER_EXPORT, LIMITER_LOGIN_IP, LIMITER_SHAPER, LIMITER_TOKEN,
    };
    use axum::http::StatusCode;
    use axum::Json;

    #[test]
    fn admin_rate_limit_body_is_tagged_admin() {
        let (status, Json(body)) = admin_rate_limit_response();
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["limiter"].as_str(), Some(LIMITER_ADMIN));
    }

    #[test]
    fn export_rate_limit_body_is_tagged_export() {
        let (status, Json(body)) = export_rate_limit_response();
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["limiter"].as_str(), Some(LIMITER_EXPORT));
        // The pre-existing machine-readable code must not change: SDKs and the
        // export runbook match on it.
        assert_eq!(body["error"].as_str(), Some("export_rate_limit_exceeded"));
    }

    #[test]
    fn token_rate_limit_body_is_tagged_token() {
        let body = rate_limit_body(LIMITER_TOKEN, "rate limit exceeded");
        assert_eq!(body["limiter"].as_str(), Some("token"));
        assert_eq!(body["error"].as_str(), Some("too_many_requests"));
    }

    #[test]
    fn ip_login_rate_limit_body_is_tagged_login_ip() {
        let body = rate_limit_body(LIMITER_LOGIN_IP, "rate limit exceeded");
        assert_eq!(body["limiter"].as_str(), Some("login_ip"));
    }

    #[test]
    fn limiter_ids_are_distinct() {
        // The harness buckets 429s by this string; a collision would silently
        // merge two limiters into one bucket and re-create the ambiguity.
        let ids = [
            LIMITER_ADMIN,
            LIMITER_TOKEN,
            LIMITER_EXPORT,
            LIMITER_LOGIN_IP,
            LIMITER_SHAPER,
        ];
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "limiter ids must be distinct");
        assert!(ids.iter().all(|id| !id.is_empty()));
    }
}

#[cfg(test)]
mod cluster_unavailable_tests {
    //! A transient cluster failure behind an RBAC or identity call is a
    //! `503` with a stable code, not a `500`.
    use super::{identity_error_to_response, rbac_error_to_response};
    use crate::identity::IdentityError;
    use crate::protocol::error_codes::{CLUSTER_UNAVAILABLE, CLUSTER_WRITE_OUTCOME_UNKNOWN};
    use crate::rbac::RbacError;
    use crate::storage::{ClusterUnavailableCause, StorageError};
    use axum::http::StatusCode;

    fn outage(unknown: bool) -> StorageError {
        if unknown {
            StorageError::ClusterWriteOutcomeUnknown {
                reason: "10.1.1.1".to_string(),
            }
        } else {
            StorageError::ClusterUnavailable {
                cause: ClusterUnavailableCause::LeaderBusy,
                reason: "10.1.1.1".to_string(),
            }
        }
    }

    #[test]
    fn rbac_and_identity_cluster_outages_are_503_with_stable_codes() {
        for (unknown, code) in [
            (false, CLUSTER_UNAVAILABLE),
            (true, CLUSTER_WRITE_OUTCOME_UNKNOWN),
        ] {
            let (status, body) =
                rbac_error_to_response(&RbacError::Storage(Box::new(outage(unknown))));
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body.0["error_code"], code, "{}", body.0);
            assert!(!body.0.to_string().contains("10.1.1.1"), "{}", body.0);

            let (status, body) =
                identity_error_to_response(&IdentityError::Storage(Box::new(outage(unknown))));
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body.0["error_code"], code, "{}", body.0);
            assert!(!body.0.to_string().contains("10.1.1.1"), "{}", body.0);
        }
    }
}

#[cfg(test)]
mod internal_error_logging_tests {
    //! A `500` must leave its cause in the server log.
    //!
    //! The body of a `500` is deliberately vague ("internal error"), and the
    //! HTTP trace layer logs only "response failed … 500". Before this, nothing
    //! logged which [`crate::identity::IdentityError`] produced it, so the 500s
    //! of a load-test run could not be explained even from the kept server log.
    use super::identity_error_to_response;
    use crate::identity::IdentityError;
    use crate::storage::StorageError;
    use axum::http::StatusCode;
    use axum::Json;

    #[derive(Clone, Default)]
    struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("capture mutex").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for CaptureWriter {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// Maps `err` with every event at ERROR captured; returns the status, the
    /// body, and the captured log.
    fn map_capturing(err: &IdentityError) -> (StatusCode, serde_json::Value, String) {
        let writer = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer.clone())
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .finish();
        let (status, Json(body)) =
            tracing::subscriber::with_default(subscriber, || identity_error_to_response(err));
        let bytes = writer.0.lock().expect("capture mutex").clone();
        (status, body, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[test]
    fn a_storage_error_500_logs_its_cause_but_not_in_the_body() {
        let err = IdentityError::Storage(Box::new(StorageError::Crypto {
            reason: "SST 000007.sst DEK unwrapping failed".to_string(),
        }));
        let (status, body, logs) = map_capturing(&err);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            logs.contains("ERROR") && logs.contains("DEK unwrapping failed"),
            "the cause of a 500 must be logged at ERROR: {logs:?}"
        );
        assert_eq!(
            body["error"].as_str(),
            Some("internal error"),
            "the body stays vague"
        );
        assert!(
            !body.to_string().contains("DEK"),
            "the cause must not reach the client: {body}"
        );
    }

    #[test]
    fn an_audit_failure_500_logs_its_cause() {
        let err = IdentityError::AuditFailure {
            action: "user_deleted".to_string(),
            reason: "audit chain append refused".to_string(),
        };
        let (status, _, logs) = map_capturing(&err);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            logs.contains("audit chain append refused"),
            "the cause of a 500 must be logged: {logs:?}"
        );
    }

    /// A 500's cause is logged in a PII-safe form: an email-transport failure
    /// carries the SMTP server's rejection, which names the recipient.
    #[test]
    fn an_email_transport_500_is_logged_without_the_address() {
        let err = IdentityError::Internal {
            reason: format!(
                "email OTP delivery failed: {}",
                crate::identity::EmailError::Transport {
                    reason: "550 5.1.1 <alice.smith+otp@example.com>: Recipient address \
                             rejected; auth token=tok_0123456789abcdefABCDEF0123456789"
                        .to_string(),
                }
            ),
        };
        let (status, _, logs) = map_capturing(&err);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            logs.contains("ERROR") && logs.contains("Recipient address rejected"),
            "the cause is still logged: {logs:?}"
        );
        assert!(
            logs.contains("Internal"),
            "the error kind is logged: {logs:?}"
        );
        for leaked in ["alice", "example.com", "tok_", "0123456789abcdef"] {
            assert!(
                !logs.contains(leaked),
                "the log must not carry {leaked:?}: {logs:?}"
            );
        }
    }

    #[test]
    fn a_client_error_is_not_logged_as_an_error() {
        let (status, _, logs) = map_capturing(&IdentityError::InvalidClient);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            logs.is_empty(),
            "a 4xx is the client's problem, not an ERROR: {logs:?}"
        );
    }
}
