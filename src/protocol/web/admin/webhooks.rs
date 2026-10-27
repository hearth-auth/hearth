//! Webhook management handlers for the admin UI.
//!
//! The pages use the webhook engine: the same store as the REST API
//! (`/admin/webhooks`) and the webhook dispatcher. They used the identity
//! engine's webhook store, which nothing delivers from (#617).

use super::*;
use crate::audit::AuditAction;
use crate::core::{FormSecret, WebhookId};
use crate::identity::RealmStatus;
use crate::webhook::{
    CreateWebhookRequest, UpdateWebhookRequest, WebhookEngine, WebhookError, WebhookQuery,
    MIN_SECRET_LEN,
};

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

/// A row in the webhooks list table.
pub struct WebhookRow {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    pub enabled: bool,
    pub last_delivery: Option<DeliveryRow>,
}

/// Summary of the most recent delivery attempt for a webhook.
pub struct DeliveryRow {
    pub success: bool,
    pub status_code: String,
    pub timestamp_display: String,
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/webhooks/list.html")]
struct WebhookListTemplate {
    webhooks: Vec<WebhookRow>,
    pagination: PaginationView,
    realm_name: String,
    search_query: String,
    sort_field: String,
    sort_dir: String,
    list_url: String,
    flash_message: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// Query params accepted by the webhook list page.
#[derive(Debug, Default, serde::Deserialize)]
pub struct WebhookListParams {
    pub flash: Option<String>,
    /// 1-based page number.
    pub page: Option<u32>,
    /// Items per page (allowlist: 5/10/25/50/100; defaults to 25).
    pub per_page: Option<u32>,
    /// Search query over webhook URL. Supports exact/glob/substring.
    pub q: Option<String>,
    /// Column to sort by: `url`. Unknown values → no sort.
    pub sort: Option<String>,
    /// Sort direction: `asc` | `desc`. Defaults to `asc`.
    pub dir: Option<String>,
}

impl WebhookListParams {}

/// `GET /ui/admin/realms/{realm}/webhooks` — lists registered webhooks.
pub async fn admin_webhooks_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    DedupQuery(params): DedupQuery<WebhookListParams>,
) -> Response {
    let flash_message = params.flash.as_deref().map(|f| match f {
        "created" => "Webhook created.".to_string(),
        "updated" => "Webhook updated.".to_string(),
        "deleted" => "Webhook deleted.".to_string(),
        other => other.to_string(),
    });

    let realm_name = target.0.name().to_string();
    let search_query = params.q.clone().unwrap_or_default();
    let sort_field_str = params.sort.clone().unwrap_or_default();
    let sort_dir_str = params.dir.clone().unwrap_or_default();
    let has_search = search_query.len() >= 2;
    let has_sort = !sort_field_str.is_empty();

    let engine = match webhook_engine(&state) {
        Ok(engine) => engine,
        Err(resp) => return resp,
    };
    let query = WebhookQuery {
        realm_id: target.id().clone(),
        enabled_only: false,
    };
    let mut subscriptions = tokio::task::spawn_blocking(move || engine.list(&query))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();
    subscriptions.sort_by_key(|s| s.created_at);

    let base_url = format!("/ui/admin/realms/{realm_name}/webhooks");
    // Collect into owned rows before slicing.
    let mut webhook_rows: Vec<WebhookRow> = subscriptions
        .into_iter()
        .map(|sub| WebhookRow {
            id: sub.id.as_uuid().to_string(),
            url: sub.url.clone(),
            events: event_names(&sub.event_filters),
            enabled: sub.enabled,
            last_delivery: None,
        })
        .collect();

    if has_search {
        use crate::identity::search::SearchQuery;
        let matcher = SearchQuery::compile(&search_query);
        webhook_rows.retain(|w| {
            let events_joined = w.events.join(" ");
            matcher.matches_any(&[w.url.as_str(), events_joined.as_str()])
        });
    }
    if has_sort {
        use crate::identity::search::SortDir;
        let sort_dir = SortDir::from_param(&sort_dir_str);
        webhook_rows.sort_by(|a, b| {
            let ord = a.url.cmp(&b.url);
            if sort_dir == SortDir::Desc {
                ord.reverse()
            } else {
                ord
            }
        });
    }

    let total = webhook_rows.len() as u64;
    let per = super::pagination::validate_per_page(params.per_page.unwrap_or(25)) as usize;
    let offset = ((params.page.unwrap_or(1).saturating_sub(1)) as usize) * per;
    let start = offset.min(webhook_rows.len());
    let end_idx = (start + per).min(webhook_rows.len());
    // Drain the slice window out of the vec to avoid requiring Clone on WebhookRow.
    let page_webhooks: Vec<WebhookRow> = webhook_rows.drain(start..end_idx).collect();
    let mock_page = crate::core::PagedResult::new(page_webhooks, total, offset as u64, per as u32);
    let preserved = super::pagination::join_params(&[
        super::pagination::encode_param("q", &search_query),
        super::pagination::encode_param("sort", &sort_field_str),
        super::pagination::encode_param("dir", &sort_dir_str),
    ]);
    let base_url_clone = base_url.clone();
    let pagination = PaginationView::new(&mock_page, base_url_clone, preserved);

    render(&WebhookListTemplate {
        webhooks: mock_page.items,
        pagination,
        realm_name,
        search_query,
        sort_field: sort_field_str,
        sort_dir: sort_dir_str,
        list_url: base_url.clone(),
        flash_message,
        chrome: true,
        active: "webhooks",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name_for(target.id()),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

// ---------------------------------------------------------------------------
// Event type constants (shown as checkboxes in the create form)
// ---------------------------------------------------------------------------

pub struct WebhookEventType {
    pub value: String,
    pub description: Option<String>,
    /// Whether this event type is already in the form's subscription list.
    /// Precomputed so templates avoid runtime `contains` with borrowed args.
    pub is_subscribed: bool,
}

/// The event types that the create and edit forms offer: the form name, the
/// audit action that the subscription matches, and a description. The
/// dispatcher matches audit actions, so each form name must map to one.
const EVENT_TYPES: &[(&str, AuditAction, &str)] = &[
    // ── Identity events ──────────────────────────────────────────────────
    ("user.created", AuditAction::UserCreated, "User was created"),
    (
        "user.updated",
        AuditAction::UserUpdated,
        "User profile was updated",
    ),
    ("user.deleted", AuditAction::UserDeleted, "User was deleted"),
    (
        "session.created",
        AuditAction::SessionCreated,
        "New session was created",
    ),
    (
        "session.revoked",
        AuditAction::SessionRevoked,
        "Session was revoked",
    ),
    (
        "role.assigned",
        AuditAction::RoleAssigned,
        "Role was assigned to a user",
    ),
    (
        "role.revoked",
        AuditAction::RoleRevoked,
        "Role was revoked from a user",
    ),
    (
        "credential.changed",
        AuditAction::CredentialChanged,
        "User changed their password",
    ),
    // ── Security events (A-7) ────────────────────────────────────────────
    // Wire these to SIEM, Slack, or a custom WAF via `security.*`. The
    // audit actions are the ones the `abuse-prevention` spec (A-7) names.
    (
        "security.login_failed",
        AuditAction::LoginFailed,
        "Credential verification failed (login attempt)",
    ),
    (
        "security.account_locked",
        AuditAction::LoginLocked,
        "Account temporarily locked after repeated failures",
    ),
    (
        "security.abuse_detected",
        AuditAction::AbuseDetected,
        "Abuse pattern detected (credential stuffing / spray)",
    ),
    (
        "security.password_compromised",
        AuditAction::PasswordCompromisedRejected,
        "Password rejected as known-compromised (HIBP)",
    ),
    (
        "security.rate_limit_exceeded",
        AuditAction::IpLoginLimitExceeded,
        "Per-IP login rate limit was exceeded",
    ),
];

/// The form checkboxes. A subscribed name that the form does not offer (an
/// audit action's wire key, from a subscription that the REST API made)
/// gets a checked box of its own, so an edit keeps it.
fn available_event_types(subscribed: &[String]) -> Vec<WebhookEventType> {
    let offered = EVENT_TYPES.iter().map(|(value, _, desc)| WebhookEventType {
        is_subscribed: subscribed.iter().any(|s| s == value),
        value: (*value).to_string(),
        description: Some((*desc).to_string()),
    });
    let kept = subscribed
        .iter()
        .filter(|s| !EVENT_TYPES.iter().any(|(value, _, _)| value == s))
        .map(|s| WebhookEventType {
            is_subscribed: true,
            value: s.clone(),
            description: None,
        });
    offered.chain(kept).collect()
}

/// The audit actions for the form's event names. A name that the form does
/// not offer must be an audit action's wire key.
fn parse_events(names: &[String]) -> Result<Vec<AuditAction>, String> {
    let mut actions = Vec::with_capacity(names.len());
    for name in names {
        let action = EVENT_TYPES
            .iter()
            .find(|(value, _, _)| value == name)
            .map(|(_, action, _)| action.clone())
            .or_else(|| name.parse::<AuditAction>().ok())
            .ok_or_else(|| format!("Unknown event type: {name}"))?;
        if !actions.contains(&action) {
            actions.push(action);
        }
    }
    Ok(actions)
}

/// The form names of a subscription's audit actions: the event type that
/// the form offers for the action, else the action's wire key.
fn event_names(actions: &[AuditAction]) -> Vec<String> {
    actions
        .iter()
        .map(|action| {
            EVENT_TYPES
                .iter()
                .find(|(_, offered, _)| offered == action)
                .map_or_else(
                    || action.as_str().to_string(),
                    |(value, _, _)| (*value).to_string(),
                )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Create form
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/webhooks/new.html")]
#[allow(dead_code)]
struct WebhookNewTemplate {
    realm_name: String,
    form_url: String,
    form_secret: String,
    form_enabled: bool,
    subscribed_events: Vec<String>,
    available_event_types: Vec<WebhookEventType>,
    error: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// `GET /ui/admin/realms/{realm}/webhooks/new` — render create form.
pub async fn admin_webhook_create_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    render(&WebhookNewTemplate {
        realm_name: target.0.name().to_string(),
        form_url: String::new(),
        form_secret: String::new(),
        form_enabled: true,
        subscribed_events: Vec::new(),
        available_event_types: available_event_types(&[]),
        error: None,
        chrome: true,
        active: "webhooks",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name_for(target.id()),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

/// Form body for creating or editing a webhook.
#[derive(Debug, Default)]
pub struct WebhookForm {
    pub url: String,
    pub secret: FormSecret,
    /// Checked event type checkboxes — may appear multiple times.
    pub events: Vec<String>,
    /// Checkbox: present means enabled.
    pub enabled: Option<String>,
    pub csrf: String,
}

impl WebhookForm {
    /// Reads the form body. Each ticked event checkbox repeats the `events`
    /// key, which `serde_urlencoded` refuses, so the form answered `400`
    /// whenever a box was ticked. The secret's value moves into the
    /// `FormSecret`, so no plain copy of it is left behind. For each other
    /// field the first value counts.
    fn read(body: &[u8]) -> Self {
        let mut form = Self::default();
        for (key, value) in form_urlencoded::parse(body).into_owned() {
            match key.as_str() {
                "url" if form.url.is_empty() => form.url = value,
                "secret" if form.secret.is_empty() => form.secret = FormSecret::new(value),
                "events" => form.events.push(value),
                "enabled" if form.enabled.is_none() => form.enabled = Some(value),
                "_csrf" if form.csrf.is_empty() => form.csrf = value,
                _ => {}
            }
        }
        form
    }
}

impl<S: Send + Sync> axum::extract::FromRequest<S> for WebhookForm {
    type Rejection = axum::response::Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = <axum::body::Bytes as axum::extract::FromRequest<S>>::from_request(req, state)
            .await
            .map_err(|e| e.into_response())?;
        Ok(Self::read(&bytes))
    }
}

/// `POST /ui/admin/realms/{realm}/webhooks/new` — create a webhook.
pub async fn admin_webhook_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    form: WebhookForm,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_name = target.0.name().to_string();

    let render_form_error = |error: String| {
        render(&WebhookNewTemplate {
            realm_name: realm_name.clone(),
            form_url: form.url.clone(),
            form_secret: form.secret.to_string(),
            form_enabled: form.enabled.is_some(),
            subscribed_events: form.events.clone(),
            available_event_types: available_event_types(&form.events),
            error: Some(error),
            chrome: true,
            active: "webhooks",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name_for(target.id()),
            logo_url: state.logo_url.clone(),
            realm_theme_url: state.realm_theme_url(),
            inline_theme_css: state.inline_theme_css(),
        })
    };

    let engine = match webhook_engine(&state) {
        Ok(engine) => engine,
        Err(resp) => return resp,
    };
    if let Err(error) = require_active_realm(&target) {
        return render_form_error(error);
    }
    if form.url.trim().is_empty() {
        return render_form_error("Endpoint URL is required.".to_string());
    }
    if form.secret.len() < MIN_SECRET_LEN {
        return render_form_error(secret_too_short());
    }
    let event_filters = match parse_events(&form.events) {
        Ok(actions) => actions,
        Err(error) => return render_form_error(error),
    };
    let url = form.url.trim().to_string();
    if let Err(error) = check_url(&url).await {
        return render_form_error(error);
    }

    let req = CreateWebhookRequest {
        realm_id: target.id().clone(),
        url,
        secret: form.secret.to_string(),
        enabled: form.enabled.is_some(),
        event_filters,
    };
    let result = tokio::task::spawn_blocking(move || engine.create(&req))
        .await
        .unwrap_or_else(|e| {
            Err(WebhookError::Storage {
                reason: e.to_string(),
            })
        });

    match result {
        Ok(_) => axum::response::Redirect::to(&format!(
            "/ui/admin/realms/{realm_name}/webhooks?flash=created"
        ))
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "create webhook failed");
            render_form_error(save_error_message(&e))
        }
    }
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

/// `POST /ui/admin/realms/{realm}/webhooks/{id}/delete` — delete a webhook.
pub async fn admin_webhook_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, webhook_id)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let Ok(uuid) = webhook_id.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Webhook not found");
    };
    let wid = WebhookId::new(uuid);

    let engine = match webhook_engine(&state) {
        Ok(engine) => engine,
        Err(resp) => return resp,
    };
    if let Err(error) = require_active_realm(&target) {
        return super::handlers_common::bad_request(&error);
    }
    let realm_id = target.id().clone();
    let result = tokio::task::spawn_blocking(move || engine.delete(&realm_id, &wid))
        .await
        .unwrap_or_else(|e| {
            Err(WebhookError::Storage {
                reason: e.to_string(),
            })
        });

    match result {
        Ok(()) => axum::response::Redirect::to(&format!(
            "/ui/admin/realms/{}/webhooks?flash=deleted",
            target.0.name()
        ))
        .into_response(),
        Err(WebhookError::NotFound { .. }) => {
            super::handlers_common::not_found("Webhook not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "delete webhook failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Test (fire event to existing webhook)
// ---------------------------------------------------------------------------

/// `POST /ui/admin/realms/{realm}/webhooks/{id}/test` — fire a test event to an existing webhook.
pub async fn admin_webhook_test(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, webhook_id)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let Ok(uuid) = webhook_id.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Webhook not found");
    };
    let wid = WebhookId::new(uuid);

    let engine = match webhook_engine(&state) {
        Ok(engine) => engine,
        Err(resp) => return resp,
    };
    let realm_id = target.id().clone();
    let Some(sub) = tokio::task::spawn_blocking(move || engine.get(&realm_id, &wid))
        .await
        .ok()
        .and_then(|r| r.ok())
    else {
        return super::handlers_common::not_found("Webhook not found");
    };

    fire_test_ping(sub.url.as_str(), Some(sub.secret.as_str())).await;

    axum::response::Redirect::to(&format!(
        "/ui/admin/realms/{}/webhooks?flash=test_sent",
        target.0.name()
    ))
    .into_response()
}

// ---------------------------------------------------------------------------
// Test-ping JSON endpoint (pre-save test from the create form)
// ---------------------------------------------------------------------------

/// Minimal JSON body for the pre-save test-ping endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestPingBody {
    pub url: String,
    #[serde(default)]
    pub secret: Option<FormSecret>,
}

/// `POST /ui/admin/realms/{realm}/webhooks/test-ping` — fires a synthetic ping
/// to an arbitrary URL (used by the new-webhook form before saving).
///
/// Returns `application/json` with `{"success": bool, "message": "..."}` so
/// the caller can display the result inline.
///
/// Returns HTTP 422 when the SSRF guard rejects the URL (non-`https://` scheme
/// or destination resolves to a private/reserved IP).
pub async fn admin_webhook_test_ping(
    RequireAdmin(_session): RequireAdmin,
    _csrf: RequireCsrf,
    AxumPath(_realm_name): AxumPath<String>,
    axum::Json(body): axum::Json<TestPingBody>,
) -> Response {
    // SSRF guard: enforce https-only and block private/reserved destinations.
    // Runs in spawn_blocking because check_webhook_url does DNS resolution.
    let url_to_check = body.url.clone();
    let ssrf_result =
        tokio::task::spawn_blocking(move || crate::webhook::ssrf::check_webhook_url(&url_to_check))
            .await
            .unwrap_or_else(|_| {
                Err(crate::webhook::WebhookError::InvalidUrl {
                    reason: "SSRF check task panicked".to_string(),
                })
            });

    if let Err(e) = ssrf_result {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            axum::response::Json(serde_json::json!({
                "success": false,
                "message": format!("Blocked: {e}"),
            })),
        )
            .into_response();
    }

    let (success, message) = fire_test_ping_result(body.url.as_str(), body.secret.as_deref()).await;
    axum::response::Json(serde_json::json!({
        "success": success,
        "message": message,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Edit
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/webhooks/edit.html")]
#[allow(dead_code)]
struct WebhookEditTemplate {
    webhook_id: String,
    realm_name: String,
    form_url: String,
    form_secret: String,
    form_enabled: bool,
    subscribed_events: Vec<String>,
    available_event_types: Vec<WebhookEventType>,
    error: Option<String>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    realm_theme_url: Option<String>,
    inline_theme_css: Option<String>,
}

/// `GET /ui/admin/realms/{realm}/webhooks/{id}/edit` — pre-populated edit form.
pub async fn admin_webhook_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, webhook_id)): AxumPath<(String, String)>,
) -> Response {
    let Ok(uuid) = webhook_id.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Webhook not found");
    };
    let wid = WebhookId::new(uuid);

    let engine = match webhook_engine(&state) {
        Ok(engine) => engine,
        Err(resp) => return resp,
    };
    let realm_id = target.id().clone();
    let Some(sub) = tokio::task::spawn_blocking(move || engine.get(&realm_id, &wid))
        .await
        .ok()
        .and_then(|r| r.ok())
    else {
        return super::handlers_common::not_found("Webhook not found");
    };
    let subscribed = event_names(&sub.event_filters);

    render(&WebhookEditTemplate {
        webhook_id: sub.id.as_uuid().to_string(),
        realm_name: target.0.name().to_string(),
        form_url: sub.url.clone(),
        // The stored secret is never sent back to the browser. An empty
        // field keeps it.
        form_secret: String::new(),
        form_enabled: sub.enabled,
        available_event_types: available_event_types(&subscribed),
        subscribed_events: subscribed,
        error: None,
        chrome: true,
        active: "webhooks",
        user_email: Some(session.user_email.clone()),
        is_admin: true,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: false,
        product_name: state.product_name_for(target.id()),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

/// `POST /ui/admin/realms/{realm}/webhooks/{id}/edit` — save webhook changes.
pub async fn admin_webhook_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, webhook_id)): AxumPath<(String, String)>,
    form: WebhookForm,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let Ok(uuid) = webhook_id.parse::<uuid::Uuid>() else {
        return super::handlers_common::not_found("Webhook not found");
    };
    let wid = WebhookId::new(uuid);
    let realm_name = target.0.name().to_string();

    let render_form_error = |error: String| {
        render(&WebhookEditTemplate {
            webhook_id: wid.as_uuid().to_string(),
            realm_name: realm_name.clone(),
            form_url: form.url.clone(),
            form_secret: form.secret.to_string(),
            form_enabled: form.enabled.is_some(),
            subscribed_events: form.events.clone(),
            available_event_types: available_event_types(&form.events),
            error: Some(error),
            chrome: true,
            active: "webhooks",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name_for(target.id()),
            logo_url: state.logo_url.clone(),
            realm_theme_url: state.realm_theme_url(),
            inline_theme_css: state.inline_theme_css(),
        })
    };

    let engine = match webhook_engine(&state) {
        Ok(engine) => engine,
        Err(resp) => return resp,
    };
    if let Err(error) = require_active_realm(&target) {
        return render_form_error(error);
    }
    if form.url.trim().is_empty() {
        return render_form_error("Endpoint URL is required.".to_string());
    }
    // An empty secret field keeps the stored secret.
    if !form.secret.is_empty() && form.secret.len() < MIN_SECRET_LEN {
        return render_form_error(secret_too_short());
    }
    let event_filters = match parse_events(&form.events) {
        Ok(actions) => actions,
        Err(error) => return render_form_error(error),
    };
    let url = form.url.trim().to_string();
    if let Err(error) = check_url(&url).await {
        return render_form_error(error);
    }

    let req = UpdateWebhookRequest {
        url: Some(url),
        secret: (!form.secret.is_empty()).then(|| form.secret.to_string()),
        enabled: Some(form.enabled.is_some()),
        event_filters: Some(event_filters),
    };
    let realm_id = target.id().clone();
    let wid_clone = wid.clone();
    let result = tokio::task::spawn_blocking(move || engine.update(&realm_id, &wid_clone, &req))
        .await
        .unwrap_or_else(|e| {
            Err(WebhookError::Storage {
                reason: e.to_string(),
            })
        });

    match result {
        Ok(_) => axum::response::Redirect::to(&format!(
            "/ui/admin/realms/{realm_name}/webhooks?flash=updated"
        ))
        .into_response(),
        Err(WebhookError::NotFound { .. }) => {
            super::handlers_common::not_found("Webhook not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "update webhook failed");
            render_form_error(save_error_message(&e))
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// The webhook store, or the error page when the server has none.
fn webhook_engine(state: &WebState) -> Result<Arc<dyn WebhookEngine>, Response> {
    state.webhook.clone().ok_or_else(|| {
        tracing::warn!("admin UI webhook page: the server has no webhook engine");
        super::handlers_common::server_error()
    })
}

/// Archival is a freeze: webhooks of a realm that is not active do not
/// change (audit 2026-08-28 §4.20#5).
fn require_active_realm(target: &TargetRealm) -> Result<(), String> {
    if matches!(target.0.status(), RealmStatus::Active) {
        Ok(())
    } else {
        Err("This realm is not active, so its webhooks cannot change.".to_string())
    }
}

/// The SSRF check that the REST API applies at registration (F3/HEA-1651).
/// It resolves DNS, so it runs on the blocking pool.
async fn check_url(url: &str) -> Result<(), String> {
    let url = url.to_string();
    match tokio::task::spawn_blocking(move || crate::webhook::ssrf::check_webhook_url(&url)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("Endpoint URL refused: {e}")),
        Err(_) => Err("The URL check failed. Please try again.".to_string()),
    }
}

fn secret_too_short() -> String {
    format!("The signing secret must be at least {MIN_SECRET_LEN} bytes.")
}

fn save_error_message(e: &WebhookError) -> String {
    match e {
        WebhookError::InvalidUrl { reason } | WebhookError::BlockedDestination { reason } => {
            format!("Endpoint URL refused: {reason}")
        }
        WebhookError::SecretTooShort => secret_too_short(),
        _ => "Failed to save webhook. Please try again.".to_string(),
    }
}

async fn fire_test_ping(url: &str, secret: Option<&str>) {
    let _ = fire_test_ping_result(url, secret).await;
}

async fn fire_test_ping_result(url: &str, secret: Option<&str>) -> (bool, String) {
    let url = url.to_string();
    let secret = secret.map(ToString::to_string);
    tokio::task::spawn_blocking(move || {
        // Defense-in-depth: re-check SSRF inside the blocking task so any
        // future call path that bypasses the handler-level guard is still
        // protected (e.g. DNS rebinding between the two checks).
        if let Err(e) = crate::webhook::ssrf::check_webhook_url(&url) {
            return (false, format!("Blocked: {e}"));
        }

        let payload = serde_json::json!({
            "event": "ping",
            "realm_id": null,
            "timestamp": crate::core::Timestamp::now().as_micros(),
        });
        let payload_bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(e) => return (false, format!("Failed to build payload: {e}")),
        };
        // ssrf_agent SSRF-validates the connect-time DNS lookup, closing the
        // DNS-rebinding TOCTOU left open by the pre-flight check_webhook_url
        // above (W1 residual risk, HEA-1762). This admin test-ping is a fourth
        // webhook egress path and must be guarded like the other three.
        let config = ureq::config::Config::builder()
            .timeout_connect(Some(std::time::Duration::from_secs(5)))
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .https_only(true)
            .max_redirects(crate::webhook::ssrf::MAX_WEBHOOK_REDIRECTS)
            .build();
        let agent = crate::webhook::ssrf::ssrf_agent(config);
        let mut req = agent
            .post(&url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "Hearth-Webhook/1.0");

        // Sign with HMAC-SHA256 when a secret is configured.
        if let Some(s) = &secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;
            if let Ok(mut mac) = HmacSha256::new_from_slice(s.as_bytes()) {
                mac.update(&payload_bytes);
                let sig = mac.finalize().into_bytes();
                let sig_hex = hex::encode(sig);
                req = req.header("X-Hearth-Signature-256", &format!("sha256={sig_hex}"));
            }
        }

        match req.send(payload_bytes.as_slice()) {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    (true, format!("HTTP {}", status.as_u16()))
                } else {
                    (false, format!("HTTP {}", status.as_u16()))
                }
            }
            Err(e) => (false, format!("Connection error: {e}")),
        }
    })
    .await
    .unwrap_or((false, "Delivery task panicked".to_string()))
}

/// Webhook signing secrets are wiped on drop and never printed by `Debug`
/// (GA audit L20).
#[cfg(test)]
mod secret_field_tests {
    use super::*;
    use crate::core::secrets::assert_zeroize_on_drop;

    fn assert_redacted(dbg: &str) {
        assert!(!dbg.contains("CANARY"), "Debug leaked a secret: {dbg}");
    }

    #[test]
    fn webhook_form_secret_is_zeroized_and_redacted() {
        let form = WebhookForm::read(b"url=https%3A%2F%2Fx.test&secret=CANARY-whs");
        assert_zeroize_on_drop(&form.secret);
        assert_eq!(form.secret.expose(), "CANARY-whs");
        assert_redacted(&format!("{form:?}"));
    }

    /// One ticked box sends `events` once; two send it twice. Both must
    /// read (#617: the serde form refused both with `400`).
    #[test]
    fn webhook_form_keeps_every_ticked_event() {
        let one = WebhookForm::read(b"url=u&events=security.login_failed&_csrf=c");
        assert_eq!(one.events, vec!["security.login_failed".to_string()]);
        assert_eq!(one.csrf, "c");
        let two = WebhookForm::read(b"events=user.created&enabled=on&events=user.deleted");
        assert_eq!(
            two.events,
            vec!["user.created".to_string(), "user.deleted".to_string()]
        );
        assert_eq!(two.enabled.as_deref(), Some("on"));
    }

    #[test]
    fn test_ping_body_secret_is_zeroized_and_redacted() {
        let body: TestPingBody =
            serde_json::from_str(r#"{"url":"https://x.test","secret":"CANARY-whs"}"#)
                .expect("json parses");
        assert_zeroize_on_drop(&body.secret);
        assert_eq!(
            body.secret.as_ref().map(FormSecret::expose),
            Some("CANARY-whs")
        );
        assert_redacted(&format!("{body:?}"));
    }
}
