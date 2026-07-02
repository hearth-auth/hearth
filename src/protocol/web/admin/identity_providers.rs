//! Identity provider (federation connector) read-only admin views.
//!
//! IdP configuration is owned by `hearth.yaml` and reconciled into storage on
//! startup/reload. The UI is a read-only inspection surface only.

use super::*;
use crate::core::IdpId;
use crate::identity::federation::IdpConfig;

// ---------------------------------------------------------------------------
// Shared view types
// ---------------------------------------------------------------------------

/// Flattened row used by the list template.
pub struct IdpRow {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub kind: String,
    pub issuer: String,
}

impl From<IdpConfig> for IdpRow {
    fn from(c: IdpConfig) -> Self {
        Self {
            id: c.id.to_string(),
            name: c.name,
            display_name: c.display_name,
            kind: c.kind.label().to_string(),
            issuer: c.issuer,
        }
    }
}

/// Flat template-friendly view of an `IdpConfig` for the detail page.
pub struct IdpDetailRow {
    pub name: String,
    pub display_name: String,
    /// Lowercase label string: "oidc", "github", or "saml".
    pub kind: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// Empty string when `None`.
    pub userinfo_endpoint: String,
    /// Empty string when `None`.
    pub jwks_uri: String,
    pub client_id: String,
    pub scopes: Vec<String>,
}

impl From<IdpConfig> for IdpDetailRow {
    fn from(c: IdpConfig) -> Self {
        Self {
            name: c.name,
            display_name: c.display_name,
            kind: c.kind.label().to_string(),
            issuer: c.issuer,
            authorization_endpoint: c.authorization_endpoint,
            token_endpoint: c.token_endpoint,
            userinfo_endpoint: c.userinfo_endpoint.unwrap_or_default(),
            jwks_uri: c.jwks_uri.unwrap_or_default(),
            client_id: c.client_id,
            scopes: c.scopes,
        }
    }
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

/// Query params for the IdP list page.
#[derive(Debug, Default, serde::Deserialize)]
pub struct IdpListParams {
    /// Column to sort by: `name` | `kind`. Unknown values ignored (no sort).
    pub sort: Option<String>,
    /// Sort direction: `asc` | `desc`. Defaults to `asc`.
    pub dir: Option<String>,
}

#[derive(Template)]
#[template(path = "ui/admin/identity_providers/list.html")]
struct IdpListTemplate {
    providers: Vec<IdpRow>,
    sort_field: String,
    sort_dir: String,
    list_url: String,
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

/// `GET /ui/admin/realms/{realm}/identity-providers`
pub async fn admin_idp_list(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath(_realm_name): AxumPath<String>,
    DedupQuery(params): DedupQuery<IdpListParams>,
) -> Response {
    let realm_name = target.0.name().to_string();
    let sort_field_str = params.sort.clone().unwrap_or_default();
    let sort_dir_str = params.dir.clone().unwrap_or_default();
    let sort_dir = crate::identity::search::SortDir::from_param(&sort_dir_str);

    match state.identity.list_idps(target.id()) {
        Ok(idps) => {
            let mut providers: Vec<IdpRow> = idps.into_iter().map(IdpRow::from).collect();
            match sort_field_str.as_str() {
                "kind" => providers.sort_by(|a, b| {
                    let ord = a.kind.cmp(&b.kind);
                    if sort_dir == crate::identity::search::SortDir::Desc {
                        ord.reverse()
                    } else {
                        ord
                    }
                }),
                _ if !sort_field_str.is_empty() || sort_field_str == "name" => {
                    providers.sort_by(|a, b| {
                        let ord = a.name.cmp(&b.name);
                        if sort_dir == crate::identity::search::SortDir::Desc {
                            ord.reverse()
                        } else {
                            ord
                        }
                    });
                }
                _ => {}
            }
            let list_url = format!("/ui/admin/realms/{realm_name}/identity-providers");
            render(&IdpListTemplate {
                providers,
                sort_field: sort_field_str,
                sort_dir: sort_dir_str,
                list_url,
                realm_name,
                chrome: true,
                active: "identity_providers",
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
            tracing::warn!(error = %e, "list_idps failed");
            super::handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Detail
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "ui/admin/identity_providers/detail.html")]
struct IdpDetailTemplate {
    idp: IdpDetailRow,
    idp_id: String,
    realm_name: String,
    callback_url: String,
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

/// `GET /ui/admin/realms/{realm}/identity-providers/{id}`
pub async fn admin_idp_detail(
    State(state): State<Arc<WebState>>,
    RequireAdmin(session): RequireAdmin,
    target: TargetRealm,
    AxumPath((_realm_name, id_str)): AxumPath<(String, String)>,
) -> Response {
    let idp_id = match id_str.parse::<uuid::Uuid>() {
        Ok(u) => IdpId::new(u),
        Err(_) => return super::handlers_common::not_found("Identity provider not found"),
    };

    let realm_name = target.0.name().to_string();
    let callback_url = format!("/realms/{realm_name}/federation/callback");

    match state.identity.get_idp(target.id(), &idp_id) {
        Ok(Some(config)) => render(&IdpDetailTemplate {
            idp_id: idp_id.as_uuid().to_string(),
            idp: IdpDetailRow::from(config),
            realm_name,
            callback_url,
            chrome: true,
            active: "identity_providers",
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
        Ok(None) => super::handlers_common::not_found("Identity provider not found"),
        Err(e) => {
            tracing::warn!(error = %e, "get_idp failed");
            super::handlers_common::server_error()
        }
    }
}
