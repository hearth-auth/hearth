//! Admin UI handlers for the agent approval-request queue (Phase C.6 — AGENT_AUTH.md §9).
//!
//! Routes:
//!   GET  /ui/admin/realms/{realm}/approvals          — pending queue
//!   GET  /ui/admin/realms/{realm}/approvals/{id}     — request detail
//!   POST /ui/admin/realms/{realm}/approvals/{id}/approve
//!   POST /ui/admin/realms/{realm}/approvals/{id}/deny

use super::*;
use crate::identity::{ApprovalRequest, ApprovalRequestStatus, IdentityError};

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

/// One row in the approval-request queue table.
pub struct ApprovalRow {
    /// UUID string for this request.
    pub request_id: String,
    /// UUID string for the requesting agent.
    pub agent_id: String,
    /// Tool name being requested (e.g. `"send_email"`).
    pub tool: String,
    /// Action being requested (e.g. `"invoke"`).
    pub action: String,
    /// Truncated preview of the invocation context JSON.
    pub context_preview: String,
    /// Number of entries in the delegation chain.
    pub delegation_depth: usize,
    /// Status label: `"pending"`, `"approved"`, `"denied"`, or `"expired"`.
    pub status: &'static str,
    /// Tailwind badge classes for the status chip.
    pub status_badge_class: &'static str,
    /// Absolute UTC timestamp for when the request was created.
    pub requested_display: String,
    /// ISO-8601 requested-at for `<time datetime>`.
    pub requested_iso: String,
    /// Relative timestamp (e.g. `"5m ago"`).
    pub requested_ago: String,
    /// Absolute UTC timestamp for when the request expires.
    pub expires_display: String,
    /// ISO-8601 expires-at for `<time datetime>`.
    pub expires_iso: String,
    /// `true` when the request is still actionable (status = Pending).
    pub is_pending: bool,
}

/// Full approval-request detail, used by the detail page and action forms.
pub struct ApprovalDetail {
    pub request_id: String,
    pub agent_id: String,
    pub tool: String,
    pub action: String,
    /// Pretty-printed JSON of the invocation context.
    pub context_json: String,
    /// Ordered delegation chain (agent IDs as strings, outermost first).
    pub delegation_chain: Vec<String>,
    pub status: &'static str,
    pub status_badge_class: &'static str,
    pub requested_display: String,
    pub requested_iso: String,
    pub requested_ago: String,
    pub expires_display: String,
    pub expires_iso: String,
    pub is_pending: bool,
    /// Populated when the request has been approved or denied.
    pub resolved_display: Option<String>,
    pub resolved_iso: Option<String>,
    pub resolved_ago: Option<String>,
    pub denial_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Askama templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/approvals/queue.html")]
struct ApprovalsQueueTemplate {
    realm_name: String,
    rows: Vec<ApprovalRow>,
    status_filter: String,
    next_cursor: Option<String>,
    flash: Option<Flash>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

#[derive(Template)]
#[template(path = "ui/admin/approvals/detail.html")]
struct ApprovalDetailTemplate {
    realm_name: String,
    req: ApprovalDetail,
    flash: Option<Flash>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

// ---------------------------------------------------------------------------
// Query / form types
// ---------------------------------------------------------------------------

/// Query parameters for the approval queue list page.
#[derive(Debug, serde::Deserialize)]
pub struct ApprovalQueueParams {
    pub status: Option<String>,
    pub cursor: Option<String>,
    pub flash: Option<String>,
}

/// POST body for approving a request via the UI form.
#[derive(Debug, serde::Deserialize)]
pub struct ApproveForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    /// Optional override for capability token TTL in seconds.
    pub capability_ttl_secs: Option<String>,
}

/// POST body for denying a request via the UI form.
#[derive(Debug, serde::Deserialize)]
pub struct DenyForm {
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn status_label(s: &ApprovalRequestStatus) -> &'static str {
    match s {
        ApprovalRequestStatus::Pending => "pending",
        ApprovalRequestStatus::Approved => "approved",
        ApprovalRequestStatus::Denied => "denied",
        ApprovalRequestStatus::Expired => "expired",
    }
}

fn status_badge_class(s: &ApprovalRequestStatus) -> &'static str {
    match s {
        ApprovalRequestStatus::Pending => "bg-warning/[0.12] text-warning-fg",
        ApprovalRequestStatus::Approved => "bg-success/[0.12] text-success-fg",
        ApprovalRequestStatus::Denied => "bg-danger/[0.12] text-danger-fg",
        ApprovalRequestStatus::Expired => "ring-1 ring-divider-subtle text-ht-content-muted",
    }
}

fn context_preview(ctx: &serde_json::Value) -> String {
    let s = ctx.to_string();
    if s.chars().count() > 80 {
        format!("{}…", s.chars().take(80).collect::<String>())
    } else {
        s
    }
}

fn context_pretty(ctx: &serde_json::Value) -> String {
    serde_json::to_string_pretty(ctx).unwrap_or_else(|_| ctx.to_string())
}

fn to_row(req: &ApprovalRequest) -> ApprovalRow {
    ApprovalRow {
        request_id: req.request_id.clone(),
        agent_id: req.agent_id.to_string(),
        tool: req.tool.clone(),
        action: req.action.clone(),
        context_preview: context_preview(&req.context),
        delegation_depth: req.delegation_chain.len(),
        status: status_label(&req.status),
        status_badge_class: status_badge_class(&req.status),
        requested_display: format_ts(req.requested_at),
        requested_iso: super::super::format_ts_iso(req.requested_at),
        requested_ago: format_ts_relative(req.requested_at),
        expires_display: format_ts(req.expires_at),
        expires_iso: super::super::format_ts_iso(req.expires_at),
        is_pending: matches!(req.status, ApprovalRequestStatus::Pending),
    }
}

fn to_detail(req: &ApprovalRequest) -> ApprovalDetail {
    ApprovalDetail {
        request_id: req.request_id.clone(),
        agent_id: req.agent_id.to_string(),
        tool: req.tool.clone(),
        action: req.action.clone(),
        context_json: context_pretty(&req.context),
        delegation_chain: req.delegation_chain.clone(),
        status: status_label(&req.status),
        status_badge_class: status_badge_class(&req.status),
        requested_display: format_ts(req.requested_at),
        requested_iso: super::super::format_ts_iso(req.requested_at),
        requested_ago: format_ts_relative(req.requested_at),
        expires_display: format_ts(req.expires_at),
        expires_iso: super::super::format_ts_iso(req.expires_at),
        is_pending: matches!(req.status, ApprovalRequestStatus::Pending),
        resolved_display: req.resolved_at.map(format_ts),
        resolved_iso: req.resolved_at.map(super::super::format_ts_iso),
        resolved_ago: req.resolved_at.map(format_ts_relative),
        denial_reason: req.denial_reason.clone(),
    }
}

fn parse_status_filter(s: &str) -> Option<ApprovalRequestStatus> {
    match s {
        "pending" => Some(ApprovalRequestStatus::Pending),
        "approved" => Some(ApprovalRequestStatus::Approved),
        "denied" => Some(ApprovalRequestStatus::Denied),
        "expired" => Some(ApprovalRequestStatus::Expired),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /ui/admin/realms/{realm}/approvals` — approval-request queue.
pub async fn admin_approvals_queue(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    Query(params): Query<ApprovalQueueParams>,
) -> Response {
    let realm_name = target.0.name().to_string();
    let realm_id = target.id().clone();

    let flash = params.flash.as_deref().map(|f| match f {
        "approved" => Flash::success("Request approved."),
        "denied" => Flash::success("Request denied."),
        other => Flash::success(other.to_string()),
    });

    let status_filter_str = params
        .status
        .clone()
        .unwrap_or_else(|| "pending".to_string());
    let status_filter = parse_status_filter(&status_filter_str);
    let cursor = params.cursor.clone();

    let identity = state.identity.clone();
    let (rows, next_cursor) = match tokio::task::spawn_blocking(move || {
        identity.list_approval_requests(&realm_id, status_filter, cursor.as_deref(), 25)
    })
    .await
    {
        Ok(Ok(page)) => {
            let rows: Vec<ApprovalRow> = page.items.iter().map(to_row).collect();
            (rows, page.next_cursor)
        }
        _ => (vec![], None),
    };

    render(&ApprovalsQueueTemplate {
        realm_name,
        rows,
        status_filter: status_filter_str,
        next_cursor,
        flash,
        chrome: true,
        active: "approvals",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name_for(target.id()),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

/// `GET /ui/admin/realms/{realm}/approvals/{id}` — single request detail.
pub async fn admin_approval_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, request_id)): AxumPath<(String, String)>,
) -> Response {
    let realm_name = target.0.name().to_string();
    let realm_id = target.id().clone();

    let identity = state.identity.clone();
    let result =
        tokio::task::spawn_blocking(move || identity.get_approval_request(&realm_id, &request_id))
            .await;

    let req = match result {
        Ok(Ok(r)) => r,
        Ok(Err(IdentityError::ApprovalRequestNotFound)) => {
            return StatusCode::NOT_FOUND.into_response()
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "admin_approval_detail: engine error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "admin_approval_detail: task panicked");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    render(&ApprovalDetailTemplate {
        realm_name,
        req: to_detail(&req),
        flash: None,
        chrome: true,
        active: "approvals",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name_for(target.id()),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

/// `POST /ui/admin/realms/{realm}/approvals/{id}/approve`
pub async fn admin_approval_approve(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((realm_name, request_id)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<ApproveForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_id = target.id().clone();
    let ttl: Option<i64> = form
        .capability_ttl_secs
        .as_deref()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&n| n > 0);

    let identity = state.identity.clone();
    match tokio::task::spawn_blocking(move || {
        identity.approve_approval_request(&realm_id, &request_id, ttl)
    })
    .await
    {
        Ok(Ok(_)) => Redirect::to(&format!(
            "/ui/admin/realms/{realm_name}/approvals?flash=approved"
        ))
        .into_response(),
        Ok(Err(IdentityError::ApprovalRequestNotFound)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "admin_approval_approve: engine error");
            StatusCode::UNPROCESSABLE_ENTITY.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "admin_approval_approve: task panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `POST /ui/admin/realms/{realm}/approvals/{id}/deny`
pub async fn admin_approval_deny(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((realm_name, request_id)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DenyForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_id = target.id().clone();
    let reason = form.reason.filter(|r| !r.trim().is_empty());

    let identity = state.identity.clone();
    match tokio::task::spawn_blocking(move || {
        identity.deny_approval_request(&realm_id, &request_id, reason)
    })
    .await
    {
        Ok(Ok(_)) => Redirect::to(&format!(
            "/ui/admin/realms/{realm_name}/approvals?flash=denied"
        ))
        .into_response(),
        Ok(Err(IdentityError::ApprovalRequestNotFound)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "admin_approval_deny: engine error");
            StatusCode::UNPROCESSABLE_ENTITY.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "admin_approval_deny: task panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
