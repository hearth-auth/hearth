//! Self-service agent-delegation consent management (`/ui/consent/delegations`).
//!
//! Surfaces the RFC 8693 delegation grants the signed-in user has approved,
//! letting them revoke individual delegations. Revocation adds the bound JTI
//! to the token blocklist, immediately invalidating the issued access token.
//!
//! # Routes
//!
//! * `GET  /ui/consent/delegations` — list active agent delegations for the user.
//! * `POST /ui/consent/delegations/{delegation_id}/revoke` — revoke one delegation.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;

use crate::identity::IdentityError;

use super::auth::{verify_csrf_form_field, UiSession};
use super::handlers_common;
use super::templates::{render, Flash};
use super::WebState;

// ---------------------------------------------------------------------------
// Template data types
// ---------------------------------------------------------------------------

struct DelegationRow {
    delegation_id: String,
    actor_sub: String,
    granted_scopes: Vec<String>,
    created_at: String,
    created_at_iso: String,
    expires_at: String,
    expires_at_iso: String,
}

#[derive(Template)]
#[template(path = "ui/consent/delegations.html")]
#[allow(clippy::struct_excessive_bools)]
struct ConsentDelegationsTemplate {
    delegations: Vec<DelegationRow>,
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /ui/consent/delegations` — lists active agent delegations for the
/// signed-in user, with per-row revoke actions.
pub async fn delegations_index(State(state): State<Arc<WebState>>, session: UiSession) -> Response {
    let rows = load_delegations(&state, &session);
    let admin = super::handlers::is_admin(state.as_ref(), &session);
    render(&ConsentDelegationsTemplate {
        delegations: rows,
        chrome: true,
        active: "account",
        user_email: Some(session.user_email.clone()),
        is_admin: admin,
        flash: None,
        csrf: session.csrf.clone(),
        narrow: true,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        realm_theme_url: state.realm_theme_url(),
        inline_theme_css: state.inline_theme_css(),
    })
}

/// `POST /ui/consent/delegations/{delegation_id}/revoke`.
///
/// Revokes a single delegation grant and redirects back to the index.
/// Returns 404 when `delegation_id` is unknown or belongs to a different user.
pub async fn revoke_delegation(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    axum::extract::Path(delegation_id): axum::extract::Path<String>,
    Form(form): Form<super::account_consents::CsrfOnlyForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }
    // The JWT sub claim uses the prefixed Display format ("user_{uuid}").
    let user_sub = session.user_id.to_string();
    match state
        .identity
        .revoke_delegation_grant(&session.realm_id, &delegation_id, &user_sub)
    {
        Ok(()) => Redirect::to("/ui/consent/delegations").into_response(),
        Err(IdentityError::DelegationGrantNotFound) => {
            handlers_common::not_found("Delegation not found")
        }
        Err(e) => {
            tracing::warn!(error = %e, %delegation_id, "revoke_delegation failed");
            handlers_common::server_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_delegations(state: &Arc<WebState>, session: &UiSession) -> Vec<DelegationRow> {
    let user_sub = session.user_id.to_string();
    state
        .identity
        .list_delegation_grants(&session.realm_id, &user_sub)
        .unwrap_or_default()
        .into_iter()
        .map(|e| DelegationRow {
            delegation_id: e.delegation_id,
            actor_sub: e.actor_sub,
            granted_scopes: e.granted_scopes,
            created_at: super::format_ts(e.created_at),
            created_at_iso: super::format_ts_iso(e.created_at),
            expires_at: super::format_ts(e.expires_at),
            expires_at_iso: super::format_ts_iso(e.expires_at),
        })
        .collect()
}
