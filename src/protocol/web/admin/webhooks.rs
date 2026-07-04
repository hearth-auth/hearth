//! Webhook management handlers for the admin UI.

use super::*;
use crate::core::WebhookId;
use crate::identity::{CreateWebhookRequest, UpdateWebhookRequest};

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

    let identity = state.identity.clone();
    let realm_id = target.id().clone();
    // Load a full window when filtering/sorting so we slice after.
    let load_limit = if has_search || has_sort {
        crate::core::MAX_PAGE_LIMIT
    } else {
        params.per_page.unwrap_or(25)
    };
    let load_req = crate::core::PageRequest::new(0, load_limit);
    let page_result =
        tokio::task::spawn_blocking(move || identity.list_webhooks(&realm_id, &load_req))
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or_default();

    let base_url = format!("/ui/admin/realms/{realm_name}/webhooks");
    // Collect into owned rows before slicing.
    let mut webhook_rows: Vec<WebhookRow> = page_result
        .items
        .into_iter()
        .map(|wh| WebhookRow {
            id: wh.id().as_uuid().to_string(),
            url: wh.url.clone(),
            events: wh.events.clone(),
            enabled: wh.enabled,
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

fn available_event_types(subscribed: &[String]) -> Vec<WebhookEventType> {
    [
        // ── Identity events ──────────────────────────────────────────────────
        ("user.created", "User was created"),
        ("user.updated", "User profile was updated"),
        ("user.deleted", "User was deleted"),
        ("session.created", "New session was created"),
        ("session.revoked", "Session was revoked"),
        ("role.assigned", "Role was assigned to a user"),
        ("role.revoked", "Role was revoked from a user"),
        ("credential.changed", "User changed their password"),
        // ── Security events (A-7) ────────────────────────────────────────────
        // Wire these to SIEM, Slack, or a custom WAF via `security.*`.
        (
            "security.login_failed",
            "Credential verification failed (login attempt)",
        ),
        (
            "security.account_locked",
            "Account temporarily locked after repeated failures",
        ),
        (
            "security.abuse_detected",
            "Abuse pattern detected (credential stuffing / spray)",
        ),
        (
            "security.password_compromised",
            "Password rejected as known-compromised (HIBP)",
        ),
        (
            "security.rate_limit_exceeded",
            "Per-IP login rate limit was exceeded",
        ),
    ]
    .into_iter()
    .map(|(value, desc)| WebhookEventType {
        is_subscribed: subscribed.iter().any(|s| s == value),
        value: value.to_string(),
        description: Some(desc.to_string()),
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

/// Form body for creating a webhook.
#[derive(Debug, Deserialize)]
pub struct CreateWebhookForm {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub secret: String,
    /// Checked event type checkboxes — may appear multiple times.
    #[serde(default)]
    pub events: Vec<String>,
    /// Checkbox: present means enabled.
    #[serde(default)]
    pub enabled: Option<String>,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/realms/{realm}/webhooks/new` — create a webhook.
pub async fn admin_webhook_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<CreateWebhookForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_name = target.0.name().to_string();

    if form.url.trim().is_empty() {
        return render(&WebhookNewTemplate {
            realm_name,
            form_url: form.url.clone(),
            form_secret: form.secret.clone(),
            form_enabled: form.enabled.is_some(),
            subscribed_events: form.events.clone(),
            available_event_types: available_event_types(&form.events),
            error: Some("Endpoint URL is required.".to_string()),
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
        });
    }

    let req = CreateWebhookRequest {
        url: form.url.trim().to_string(),
        secret: if form.secret.is_empty() {
            None
        } else {
            Some(form.secret.clone())
        },
        events: form.events.clone(),
        enabled: form.enabled.is_some(),
    };

    let identity = state.identity.clone();
    let realm_id = target.id().clone();
    let result = tokio::task::spawn_blocking(move || identity.create_webhook(&realm_id, &req))
        .await
        .unwrap_or_else(|e| {
            Err(crate::identity::IdentityError::Internal {
                reason: e.to_string(),
            })
        });

    match result {
        Ok(_wh) => axum::response::Redirect::to(&format!(
            "/ui/admin/realms/{realm_name}/webhooks?flash=created"
        ))
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "create_webhook failed");
            render(&WebhookNewTemplate {
                realm_name,
                form_url: form.url.clone(),
                form_secret: form.secret.clone(),
                form_enabled: form.enabled.is_some(),
                subscribed_events: form.events.clone(),
                available_event_types: available_event_types(&form.events),
                error: Some("Failed to save webhook. Please try again.".to_string()),
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

    let identity = state.identity.clone();
    let realm_id = target.id().clone();
    let result = tokio::task::spawn_blocking(move || identity.delete_webhook(&realm_id, &wid))
        .await
        .unwrap_or_else(|e| {
            Err(crate::identity::IdentityError::Internal {
                reason: e.to_string(),
            })
        });

    match result {
        Ok(()) => axum::response::Redirect::to(&format!(
            "/ui/admin/realms/{}/webhooks?flash=deleted",
            target.0.name()
        ))
        .into_response(),
        Err(crate::identity::IdentityError::WebhookNotFound) => {
            super::handlers_common::not_found("Webhook not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "delete_webhook failed");
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

    let identity = state.identity.clone();
    let realm_id = target.id().clone();
    let wh = match tokio::task::spawn_blocking(move || identity.get_webhook(&realm_id, &wid))
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten()
    {
        Some(w) => w,
        None => return super::handlers_common::not_found("Webhook not found"),
    };

    fire_test_ping(wh.url.as_str(), wh.secret.as_deref()).await;

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
pub struct TestPingBody {
    pub url: String,
    #[serde(default)]
    pub secret: Option<String>,
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

    let identity = state.identity.clone();
    let realm_id = target.id().clone();
    let wh = match tokio::task::spawn_blocking(move || identity.get_webhook(&realm_id, &wid))
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten()
    {
        Some(w) => w,
        None => return super::handlers_common::not_found("Webhook not found"),
    };

    render(&WebhookEditTemplate {
        webhook_id: wh.id().as_uuid().to_string(),
        realm_name: target.0.name().to_string(),
        form_url: wh.url.clone(),
        form_secret: wh.secret.clone().unwrap_or_default(),
        form_enabled: wh.enabled,
        subscribed_events: wh.events.clone(),
        available_event_types: available_event_types(&wh.events),
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

/// Form body for editing a webhook.
#[derive(Debug, Deserialize)]
pub struct EditWebhookForm {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub secret: String,
    /// Checked event type checkboxes — may appear multiple times.
    #[serde(default)]
    pub events: Vec<String>,
    /// Checkbox: present means enabled.
    #[serde(default)]
    pub enabled: Option<String>,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/realms/{realm}/webhooks/{id}/edit` — save webhook changes.
pub async fn admin_webhook_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, webhook_id)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<EditWebhookForm>,
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
            form_secret: form.secret.clone(),
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

    if form.url.trim().is_empty() {
        return render_form_error("Endpoint URL is required.".to_string());
    }

    let req = UpdateWebhookRequest {
        url: form.url.trim().to_string(),
        secret: if form.secret.is_empty() {
            None
        } else {
            Some(form.secret.clone())
        },
        events: form.events.clone(),
        enabled: form.enabled.is_some(),
    };

    let identity = state.identity.clone();
    let realm_id = target.id().clone();
    let wid_clone = wid.clone();
    let result =
        tokio::task::spawn_blocking(move || identity.update_webhook(&realm_id, &wid_clone, &req))
            .await
            .unwrap_or_else(|e| {
                Err(crate::identity::IdentityError::Internal {
                    reason: e.to_string(),
                })
            });

    match result {
        Ok(_) => axum::response::Redirect::to(&format!(
            "/ui/admin/realms/{realm_name}/webhooks?flash=updated"
        ))
        .into_response(),
        Err(crate::identity::IdentityError::WebhookNotFound) => {
            super::handlers_common::not_found("Webhook not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_webhook failed");
            render_form_error("Failed to update webhook. Please try again.".to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

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
        let mut req = ureq::post(&url)
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
