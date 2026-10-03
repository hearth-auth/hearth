//! OAuth client (application) registration and management.

use super::*;

// ---------------------------------------------------------------------------
// Application list
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/list.html")]
struct AppListTemplate {
    applications: Vec<OAuthClient>,
    pagination: PaginationView,
    realm_name: String,
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

/// `GET /ui/admin/applications`.
pub async fn admin_apps_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    Query(params): Query<AdminPageParams>,
) -> Response {
    let realm_name = target.0.name().to_string();
    match state
        .identity
        .list_clients(target.id(), &params.as_page_request())
    {
        Ok(page) => {
            let base_url = format!("/ui/admin/realms/{realm_name}/applications");
            let pagination = PaginationView::new(&page, base_url, "");
            render(&AppListTemplate {
                applications: page.items,
                pagination,
                realm_name,
                chrome: true,
                active: "applications",
                user_email: Some(session.user_email.clone()),
                is_admin: true,
                flash: None,
                csrf: session.csrf.clone(),
                narrow: false,
                product_name: state.product_name.clone(),
                logo_url: state.logo_url.clone(),
                realm_theme_url: state.realm_theme_url(),
                inline_theme_css: state.inline_theme_css(),
            })
        }
        Err(e) => {
            tracing::warn!(error = %e, "list_clients failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Application detail (read-only — apps managed via hearth.yaml)
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/detail.html")]
struct AppDetailTemplate {
    app: OAuthClient,
    realm_name: String,
    client_secret: Option<String>,
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

/// `GET /ui/admin/applications/:id`.
pub async fn admin_app_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, cid)): AxumPath<(String, String)>,
) -> Response {
    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    match state.identity.get_client(target.id(), &client_id) {
        Ok(Some(app)) => render(&AppDetailTemplate {
            app,
            realm_name: target.0.name().to_string(),
            // A secret this session's create or regenerate just minted is
            // shown here, once (post/redirect/get; HTML is `no-store`).
            client_secret: state
                .secret_reveals
                .take(&session.session_id, &client_id)
                .map(|secret| secret.as_str().to_string()),
            chrome: true,
            active: "applications",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            realm_theme_url: state.realm_theme_url(),
            inline_theme_css: state.inline_theme_css(),
        }),
        Ok(None) => super::handlers_common::not_found("Application not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_client failed");
            super::handlers_common::server_error()
        }
    }
}

/// `POST /ui/admin/applications/:id/regenerate-secret`.
///
/// Generates a new client secret for a confidential OAuth client.
/// Redirects back to the detail page with the new secret displayed once.
pub async fn admin_app_regenerate_secret(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, cid)): AxumPath<(String, String)>,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    match state
        .identity
        .regenerate_client_secret(target.id(), &client_id)
    {
        Ok(new_secret) => {
            audit_app_event(&state, &session, &target.0, &client_id, "update");
            // Post/redirect/get: the application's page shows the new secret
            // once, from the server-side reveal, so a reload cannot rotate it
            // again.
            state.secret_reveals.stash(
                &session.session_id,
                &client_id,
                zeroize::Zeroizing::new(new_secret),
            );
            Redirect::to(&format!(
                "/ui/admin/realms/{}/applications/{}",
                target.0.name(),
                client_id.as_uuid()
            ))
            .into_response()
        }
        Err(IdentityError::InvalidClient) => {
            super::handlers_common::not_found("Application not found")
        }
        Err(IdentityError::InvalidInput { .. }) => {
            super::handlers_common::not_found("Cannot regenerate secret for a public client")
        }
        Err(e) => {
            tracing::warn!(error = %e, "regenerate_client_secret failed");
            super::handlers_common::server_error()
        }
    }
}

/// Best-effort audit for application operations.
fn audit_app_event(
    state: &Arc<WebState>,
    session: &super::auth::UiSession,
    target_realm: &Realm,
    client_id: &ClientId,
    op: &'static str,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let action = match op {
        "create" => AuditAction::ClientRegistered,
        "update" => AuditAction::ClientUpdated,
        "delete" => AuditAction::ClientDeleted,
        _ => return,
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: target_realm.id().clone(),
        actor: session.user_id.as_uuid().to_string(),
        action,
        resource_type: "client".to_string(),
        resource_id: client_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    }) {
        tracing::warn!(error = %e, "app admin audit append failed");
    }
}

// ---------------------------------------------------------------------------
// ID-token signing algorithm (task 26.55)
// ---------------------------------------------------------------------------

/// The ID-token algorithm an edit-form post changes a client to, if any.
///
/// The edit form always posts the radio's value, so getting the stored value
/// back is no change, just as an omitted field is none on the REST update.
/// Forwarding it anyway would re-validate a choice nobody made. An empty value (no radio posted,
/// as when the selected one is disabled) is no change either. `stored` is
/// `None` when the client could not be read; the value is then forwarded and
/// the engine answers for the client.
fn changed_id_token_alg(
    submitted: &str,
    stored: Option<crate::identity::IdTokenSigningAlg>,
) -> Option<String> {
    if submitted.is_empty() || stored.is_some_and(|alg| alg.as_str() == submitted) {
        return None;
    }
    Some(submitted.to_string())
}

// ---------------------------------------------------------------------------
// Application create
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/new.html")]
struct AppNewTemplate {
    error: Option<String>,
    realm_name: String,
    form_client_name: String,
    form_slug: String,
    form_client_type: String,
    form_redirect_uris: String,
    form_grant_authorization_code: bool,
    form_grant_client_credentials: bool,
    form_grant_refresh_token: bool,
    form_grant_device_code: bool,
    form_trust_level: String,
    form_require_consent: bool,
    form_declared_scopes: String,
    form_client_logo_url: String,
    form_access_token_authorization: String,
    /// `"EdDSA"` or `"RS256"` — the client's ID-token signing algorithm.
    form_id_token_signed_response_alg: String,
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

impl AppNewTemplate {
    fn blank(realm: &Realm, session: &super::auth::UiSession, state: &Arc<WebState>) -> Self {
        Self {
            error: None,
            realm_name: realm.name().to_string(),
            form_client_name: String::new(),
            form_slug: String::new(),
            form_client_type: "public".to_string(),
            form_redirect_uris: String::new(),
            form_grant_authorization_code: true,
            form_grant_client_credentials: false,
            form_grant_refresh_token: true,
            form_grant_device_code: false,
            form_trust_level: "third_party".to_string(),
            form_require_consent: true,
            form_declared_scopes: String::new(),
            form_client_logo_url: String::new(),
            form_access_token_authorization: "embedded".to_string(),
            // Hearth's administrative default; RS256 is opt-in (task 26.55).
            form_id_token_signed_response_alg: "EdDSA".to_string(),
            chrome: true,
            active: "applications",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            realm_theme_url: state.realm_theme_url(),
            inline_theme_css: state.inline_theme_css(),
        }
    }
}

/// `GET /ui/admin/realms/{realm}/applications/new`
pub async fn admin_app_create_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
) -> Response {
    render(&AppNewTemplate::blank(&target.0, &session, &state))
}

#[derive(Debug, Deserialize)]
pub struct AppCreateForm {
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub client_type: String,
    #[serde(default)]
    pub redirect_uris: String,
    #[serde(default)]
    pub grant_authorization_code: String,
    #[serde(default)]
    pub grant_client_credentials: String,
    #[serde(default)]
    pub grant_refresh_token: String,
    #[serde(default)]
    pub grant_device_code: String,
    #[serde(default)]
    pub trust_level: String,
    #[serde(default)]
    pub require_consent: String,
    #[serde(default)]
    pub declared_scopes: String,
    #[serde(default)]
    pub client_logo_url: String,
    #[serde(default)]
    pub access_token_authorization: String,
    /// `"EdDSA"` or `"RS256"`; empty keeps the default (create) or the
    /// current value (edit). The engine refuses anything else.
    #[serde(default)]
    pub id_token_signed_response_alg: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

fn parse_app_create_form(form: &AppCreateForm) -> RegisterClientRequest {
    let redirect_uris: Vec<String> = form
        .redirect_uris
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut grant_types = Vec::new();
    if form.grant_authorization_code == "1" {
        grant_types.push("authorization_code".to_string());
    }
    if form.grant_client_credentials == "1" {
        grant_types.push("client_credentials".to_string());
    }
    if form.grant_refresh_token == "1" {
        grant_types.push("refresh_token".to_string());
    }
    if form.grant_device_code == "1" {
        grant_types.push("urn:ietf:params:oauth:grant-type:device_code".to_string());
    }
    if grant_types.is_empty() {
        grant_types.push("authorization_code".to_string());
    }

    // A confidential client's secret is minted here, by Hearth: 256 CSPRNG
    // bits (it used to be a 122-bit UUID v4), carried as a
    // `GeneratedClientSecret` so the engine stores it in the fast format.
    let generated_client_secret =
        (form.client_type == "confidential").then(crate::identity::GeneratedClientSecret::generate);

    let trust_level = if form.trust_level == "first_party" {
        ClientTrustLevel::FirstParty
    } else {
        ClientTrustLevel::ThirdParty
    };

    let declared_scopes: Vec<String> = form
        .declared_scopes
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let slug = if form.slug.is_empty() {
        None
    } else {
        Some(form.slug.clone())
    };

    let client_logo_url = if form.client_logo_url.is_empty() {
        None
    } else {
        Some(form.client_logo_url.clone())
    };

    use crate::identity::oidc::AccessTokenAuthorization;
    let access_token_authorization = match form.access_token_authorization.as_str() {
        "introspection" => AccessTokenAuthorization::Introspection,
        "decision" => AccessTokenAuthorization::Decision,
        _ => AccessTokenAuthorization::Embedded,
    };

    RegisterClientRequest {
        client_name: form.client_name.clone(),
        redirect_uris,
        client_secret: None,
        generated_client_secret,
        grant_types,
        require_consent: form.require_consent == "1",
        client_logo_url,
        slug,
        trust_level,
        declared_scopes,
        consent_spans_orgs: false,
        access_token_authorization,
        cors_origins: Vec::new(),
        jwks: None,
        jwks_uri: None,
        id_token_signed_response_alg: (!form.id_token_signed_response_alg.is_empty())
            .then(|| form.id_token_signed_response_alg.clone()),
        dpop_bound_access_tokens: false,
        mfa_required: None,
    }
}

/// `POST /ui/admin/realms/{realm}/applications/new`
pub async fn admin_app_create_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    FriendlyForm(form): FriendlyForm<AppCreateForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let req = parse_app_create_form(&form);
    let realm_name = target.0.name().to_string();

    match state.identity.register_client(target.id(), &req) {
        Ok(client) => {
            audit_app_event(&state, &session, &target.0, client.client_id(), "create");
            // A confidential client's secret exists only in this request:
            // storage keeps its hash. It is held server-side for this session
            // and shown once by the page this redirect lands on — never in a
            // URL, a redirect or a log. Post/redirect/get matters: answering
            // this POST with the secret meant a reload re-submitted the form
            // (the CSRF token is per session) and registered a duplicate.
            if let Some(secret) = &req.generated_client_secret {
                state.secret_reveals.stash(
                    &session.session_id,
                    client.client_id(),
                    zeroize::Zeroizing::new(secret.expose().to_string()),
                );
            }
            Redirect::to(&format!(
                "/ui/admin/realms/{}/applications/{}",
                realm_name,
                client.client_id().as_uuid(),
            ))
            .into_response()
        }
        // Invalid input is the operator's to fix: say why.
        Err(IdentityError::InvalidInput { reason }) => {
            let mut tpl = AppNewTemplate::blank(&target.0, &session, &state);
            tpl.error = Some(reason);
            tpl.form_client_name = form.client_name.clone();
            tpl.form_slug = form.slug.clone();
            tpl.form_client_type = form.client_type.clone();
            tpl.form_redirect_uris = form.redirect_uris.clone();
            tpl.form_grant_authorization_code = form.grant_authorization_code == "1";
            tpl.form_grant_client_credentials = form.grant_client_credentials == "1";
            tpl.form_grant_refresh_token = form.grant_refresh_token == "1";
            tpl.form_grant_device_code = form.grant_device_code == "1";
            tpl.form_trust_level = form.trust_level.clone();
            tpl.form_require_consent = form.require_consent == "1";
            tpl.form_declared_scopes = form.declared_scopes.clone();
            tpl.form_client_logo_url = form.client_logo_url.clone();
            tpl.form_access_token_authorization = form.access_token_authorization.clone();
            // No radio posted keeps the default rather than selecting none.
            if !form.id_token_signed_response_alg.is_empty() {
                tpl.form_id_token_signed_response_alg = form.id_token_signed_response_alg.clone();
            }
            render(&tpl)
        }
        Err(e) => {
            tracing::warn!(error = %e, "register_client failed");
            let mut tpl = AppNewTemplate::blank(&target.0, &session, &state);
            tpl.error = Some("Unable to register application right now.".to_string());
            render(&tpl)
        }
    }
}

// ---------------------------------------------------------------------------
// Application edit
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/applications/edit.html")]
struct AppEditTemplate {
    app: OAuthClient,
    error: Option<String>,
    realm_name: String,
    form_client_name: String,
    form_slug: String,
    form_redirect_uris: String,
    form_grant_authorization_code: bool,
    form_grant_client_credentials: bool,
    form_grant_refresh_token: bool,
    form_grant_device_code: bool,
    form_trust_level: String,
    form_require_consent: bool,
    form_declared_scopes: String,
    form_client_logo_url: String,
    form_access_token_authorization: String,
    /// `"EdDSA"` or `"RS256"` — the client's ID-token signing algorithm.
    form_id_token_signed_response_alg: String,
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

impl AppEditTemplate {
    fn from_client(
        app: OAuthClient,
        realm: &Realm,
        session: &super::auth::UiSession,
        state: &Arc<WebState>,
    ) -> Self {
        let redirect_uris = app.redirect_uris().join("\n");
        let grant_authorization_code = app
            .grant_types()
            .contains(&"authorization_code".to_string());
        let grant_client_credentials = app
            .grant_types()
            .contains(&"client_credentials".to_string());
        let grant_refresh_token = app.allows_refresh_token();
        let grant_device_code = app
            .grant_types()
            .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string());
        let trust_level = if format!("{:?}", app.trust_level()) == "FirstParty" {
            "first_party".to_string()
        } else {
            "third_party".to_string()
        };
        let declared_scopes = app.declared_scopes().join(" ");
        let client_logo_url = app.client_logo_url().unwrap_or("").to_string();
        let slug = app.slug().to_string();
        let require_consent = app.require_consent();

        use crate::identity::oidc::AccessTokenAuthorization;
        let access_token_authorization_mode = match app.access_token_authorization() {
            AccessTokenAuthorization::Introspection => "introspection",
            AccessTokenAuthorization::Decision => "decision",
            _ => "embedded",
        }
        .to_string();
        let id_token_alg = app.id_token_signed_response_alg();

        Self {
            app,
            error: None,
            realm_name: realm.name().to_string(),
            form_client_name: String::new(),
            form_slug: slug,
            form_redirect_uris: redirect_uris,
            form_grant_authorization_code: grant_authorization_code,
            form_grant_client_credentials: grant_client_credentials,
            form_grant_refresh_token: grant_refresh_token,
            form_grant_device_code: grant_device_code,
            form_trust_level: trust_level,
            form_require_consent: require_consent,
            form_declared_scopes: declared_scopes,
            form_client_logo_url: client_logo_url,
            form_access_token_authorization: access_token_authorization_mode,
            form_id_token_signed_response_alg: id_token_alg.as_str().to_string(),
            chrome: true,
            active: "applications",
            user_email: Some(session.user_email.clone()),
            is_admin: true,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: false,
            product_name: state.product_name.clone(),
            logo_url: state.logo_url.clone(),
            realm_theme_url: state.realm_theme_url(),
            inline_theme_css: state.inline_theme_css(),
        }
    }
}

/// `GET /ui/admin/realms/{realm}/applications/{id}/edit`
pub async fn admin_app_edit_form(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, cid)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Task 21.6: `hearth_ui_flash` must carry `Secure` over TLS.
    let secure = state.is_secure_request(&headers);
    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };
    match state.identity.get_client(target.id(), &client_id) {
        Ok(Some(app)) => {
            if app.is_yaml_managed() {
                return super::templates::redirect_with_flash(
                    &format!(
                        "/ui/admin/realms/{}/applications/{}",
                        target.0.name(),
                        client_id.as_uuid()
                    ),
                    "This application is managed by hearth.yaml and cannot be edited via the UI.",
                    "error",
                    secure,
                );
            }
            let mut tpl = AppEditTemplate::from_client(app.clone(), &target.0, &session, &state);
            tpl.form_client_name = app.client_name().to_string();
            render(&tpl)
        }
        Ok(None) => super::handlers_common::not_found("Application not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_client failed");
            super::handlers_common::server_error()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AppEditForm {
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub redirect_uris: String,
    #[serde(default)]
    pub grant_authorization_code: String,
    #[serde(default)]
    pub grant_client_credentials: String,
    #[serde(default)]
    pub grant_refresh_token: String,
    #[serde(default)]
    pub grant_device_code: String,
    #[serde(default)]
    pub trust_level: String,
    #[serde(default)]
    pub require_consent: String,
    #[serde(default)]
    pub declared_scopes: String,
    #[serde(default)]
    pub client_logo_url: String,
    #[serde(default)]
    pub access_token_authorization: String,
    /// `"EdDSA"` or `"RS256"`; empty keeps the default (create) or the
    /// current value (edit). The engine refuses anything else.
    #[serde(default)]
    pub id_token_signed_response_alg: String,
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/admin/realms/{realm}/applications/{id}/edit`
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
pub async fn admin_app_edit_submit(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, cid)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<AppEditForm>,
) -> Response {
    // Task 21.6: `hearth_ui_flash` must carry `Secure` over TLS.
    let secure = state.is_secure_request(&headers);
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    let existing = state
        .identity
        .get_client(target.id(), &client_id)
        .ok()
        .flatten();
    if existing.as_ref().is_some_and(OAuthClient::is_yaml_managed) {
        return super::templates::redirect_with_flash(
            &format!(
                "/ui/admin/realms/{}/applications/{}",
                target.0.name(),
                client_id.as_uuid()
            ),
            "This application is managed by hearth.yaml and cannot be edited via the UI.",
            "error",
            secure,
        );
    }

    let redirect_uris: Vec<String> = form
        .redirect_uris
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut grant_types = Vec::new();
    if form.grant_authorization_code == "1" {
        grant_types.push("authorization_code".to_string());
    }
    if form.grant_client_credentials == "1" {
        grant_types.push("client_credentials".to_string());
    }
    if form.grant_refresh_token == "1" {
        grant_types.push("refresh_token".to_string());
    }
    if form.grant_device_code == "1" {
        grant_types.push("urn:ietf:params:oauth:grant-type:device_code".to_string());
    }
    // Grants this form has no toggle for (jwt-bearer, token-exchange) are
    // kept: every grant is enforced against `grant_types` (GA audit M7), so
    // saving the form must not silently withdraw one.
    if let Some(app) = existing.as_ref() {
        for grant in app.grant_types() {
            let managed = matches!(
                grant.as_str(),
                "authorization_code"
                    | "client_credentials"
                    | "refresh_token"
                    | "urn:ietf:params:oauth:grant-type:device_code"
            );
            if !managed && !grant_types.contains(grant) {
                grant_types.push(grant.clone());
            }
        }
    }
    if grant_types.is_empty() {
        grant_types.push("authorization_code".to_string());
    }

    let trust_level = if form.trust_level == "first_party" {
        Some(ClientTrustLevel::FirstParty)
    } else {
        Some(ClientTrustLevel::ThirdParty)
    };

    let declared_scopes: Vec<String> = form
        .declared_scopes
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let client_logo_url = if form.client_logo_url.is_empty() {
        Some(None)
    } else {
        Some(Some(form.client_logo_url.clone()))
    };

    let slug = if form.slug.is_empty() {
        None
    } else {
        Some(form.slug.clone())
    };

    use crate::identity::oidc::AccessTokenAuthorization;
    let access_token_authorization = Some(match form.access_token_authorization.as_str() {
        "introspection" => AccessTokenAuthorization::Introspection,
        "decision" => AccessTokenAuthorization::Decision,
        _ => AccessTokenAuthorization::Embedded,
    });

    let req = UpdateClientRequest {
        cors_origins: None,
        client_name: if form.client_name.is_empty() {
            None
        } else {
            Some(form.client_name.clone())
        },
        redirect_uris: Some(redirect_uris),
        grant_types: Some(grant_types),
        require_consent: Some(form.require_consent == "1"),
        client_logo_url,
        slug,
        trust_level,
        declared_scopes: Some(declared_scopes),
        consent_spans_orgs: None,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        post_logout_redirect_uris: None,
        status: None,
        assertion_public_key: None,
        access_token_authorization,
        id_token_signed_response_alg: changed_id_token_alg(
            &form.id_token_signed_response_alg,
            existing
                .as_ref()
                .map(OAuthClient::id_token_signed_response_alg),
        ),
        dpop_bound_access_tokens: None,
        jwks: None,
        mfa_required: None,
    };

    let realm_name = target.0.name().to_string();

    match state.identity.update_client(target.id(), &client_id, &req) {
        Ok(_client) => {
            audit_app_event(&state, &session, &target.0, &client_id, "update");
            Redirect::to(&format!(
                "/ui/admin/realms/{}/applications/{}",
                realm_name,
                client_id.as_uuid(),
            ))
            .into_response()
        }
        Err(IdentityError::InvalidClient) => {
            super::handlers_common::not_found("Application not found")
        }
        // Invalid input is the operator's to fix: say why.
        Err(IdentityError::InvalidInput { reason }) => {
            match state.identity.get_client(target.id(), &client_id) {
                Ok(Some(app)) => {
                    let mut tpl = AppEditTemplate::from_client(app, &target.0, &session, &state);
                    tpl.error = Some(reason);
                    tpl.form_client_name = form.client_name.clone();
                    tpl.form_access_token_authorization = form.access_token_authorization.clone();
                    // No radio posted keeps the stored value selected.
                    if !form.id_token_signed_response_alg.is_empty() {
                        tpl.form_id_token_signed_response_alg =
                            form.id_token_signed_response_alg.clone();
                    }
                    render(&tpl)
                }
                _ => super::handlers_common::server_error(),
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "update_client failed");
            super::handlers_common::server_error()
        }
    }
}

/// `POST /ui/admin/realms/{realm}/applications/{id}/delete`
pub async fn admin_app_delete(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, cid)): AxumPath<(String, String)>,
    headers: axum::http::HeaderMap,
    FriendlyForm(form): FriendlyForm<DeleteForm>,
) -> Response {
    // Task 21.6: `hearth_ui_flash` must carry `Secure` over TLS.
    let secure = state.is_secure_request(&headers);
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let client_id = match cid.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => return super::handlers_common::not_found("Application not found"),
    };

    let realm_name = target.0.name().to_string();

    // The YAML-managed gate lives in `delete_client`, so every adapter gets it
    // (audit 2026-08-28 §4.20#10). This handler renders the refusal as a flash
    // message; it does not decide it.
    match state.identity.delete_client(target.id(), &client_id) {
        Ok(()) => {
            audit_app_event(&state, &session, &target.0, &client_id, "delete");
            Redirect::to(&format!("/ui/admin/realms/{}/applications", realm_name)).into_response()
        }
        Err(IdentityError::InvalidClient) => {
            super::handlers_common::not_found("Application not found")
        }
        Err(IdentityError::YamlManagedResource { .. }) => super::templates::redirect_with_flash(
            &format!(
                "/ui/admin/realms/{}/applications/{}",
                realm_name,
                client_id.as_uuid()
            ),
            "This application is managed by hearth.yaml and cannot be deleted via the UI.",
            "error",
            secure,
        ),
        Err(e) => {
            tracing::warn!(error = %e, "delete_client failed");
            super::handlers_common::server_error()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_form(body: &str) -> AppCreateForm {
        serde_urlencoded::from_str(body).expect("create form parses")
    }

    /// Task 26.55: the console's ID-token algorithm radio reaches the engine
    /// verbatim — the engine validates it — and an unset radio keeps the
    /// administrative default (EdDSA) rather than inventing a value.
    #[test]
    fn create_form_carries_the_id_token_signing_algorithm() {
        let base = "client_name=Console+App&redirect_uris=https%3A%2F%2Fapp.example.com%2Fcb";
        let rs256 = parse_app_create_form(&create_form(&format!(
            "{base}&id_token_signed_response_alg=RS256"
        )));
        assert_eq!(rs256.id_token_signed_response_alg.as_deref(), Some("RS256"));

        let unset = parse_app_create_form(&create_form(base));
        assert_eq!(unset.id_token_signed_response_alg, None);
    }

    /// Task 26.55: the edit form always posts the ID-token radio, so only a
    /// value that differs from the stored one is a change. Re-posting the
    /// stored RS256 must not reach the engine as a change.
    #[test]
    fn edit_form_forwards_only_a_changed_id_token_algorithm() {
        use crate::identity::IdTokenSigningAlg::{EdDsa, Rs256};

        assert_eq!(changed_id_token_alg("RS256", Some(Rs256)), None);
        assert_eq!(changed_id_token_alg("EdDSA", Some(EdDsa)), None);
        assert_eq!(
            changed_id_token_alg("RS256", Some(EdDsa)).as_deref(),
            Some("RS256")
        );
        assert_eq!(
            changed_id_token_alg("EdDSA", Some(Rs256)).as_deref(),
            Some("EdDSA")
        );
        // No radio posted is no change.
        assert_eq!(changed_id_token_alg("", Some(Rs256)), None);
        // An unreadable client: forward, and let the engine answer for it,
        // including a value it refuses.
        assert_eq!(
            changed_id_token_alg("HS256", None).as_deref(),
            Some("HS256")
        );
    }

    /// The console mints a confidential client's secret itself, so it must be
    /// a [`crate::identity::GeneratedClientSecret`] — 256 CSPRNG bits, stored
    /// as a fast SHA-256 digest — never a caller-chosen `client_secret` (which
    /// the engine must store as Argon2id). The old code minted a UUID v4:
    /// 122 bits, and on the Argon2id path.
    #[test]
    fn confidential_create_form_uses_a_generated_client_secret() {
        let base = "client_name=Console+App&redirect_uris=https%3A%2F%2Fapp.example.com%2Fcb";
        let conf = parse_app_create_form(&create_form(&format!("{base}&client_type=confidential")));
        assert!(
            conf.client_secret.is_none(),
            "a console-minted secret must not travel as a caller-chosen one"
        );
        assert!(conf.generated_client_secret.is_some());

        let public = parse_app_create_form(&create_form(&format!("{base}&client_type=public")));
        assert!(public.client_secret.is_none());
        assert!(public.generated_client_secret.is_none());
    }
}
