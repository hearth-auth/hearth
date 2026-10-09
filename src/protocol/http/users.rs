//! User management endpoints: `POST /users`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

use crate::audit::{Actor, AuditContext};
use crate::protocol::proto::identity::v1 as pb;

use super::{
    extract_admin_auth, identity_error_to_response, proto_to_rest_json, require_admin_permission,
    AppState,
};

/// Registers user management routes.
pub(super) fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::post;
    axum::Router::new().route("/users", post(create_user))
}

/// Create a new user (admin-only).
///
/// This is the administrative creation path: it lands the new user in
/// [`UserStatus::Active`](crate::identity::UserStatus) and enforces **no**
/// registration policy. It therefore requires an authenticated admin bearer
/// token carrying `hearth.users.admin` (or `hearth.admin`), exactly like
/// `admin_create_user` at `POST /admin/users` (HEA-2023).
///
/// Self-service registration (which honours the realm's
/// [`RegistrationPolicy`](crate::identity::RegistrationPolicy) and lands users
/// in `PendingVerification`) is served separately by the web `/register` flow
/// via `identity.register_user`; it is **not** this endpoint.
///
/// The realm is taken from the validated token (`auth.realm_id`), never from an
/// attacker-controllable `X-Realm-ID` header alone — this prevents a
/// `hearth.users.admin` token scoped to realm A from creating users in realm B.
async fn create_user(
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
    // Bind the realm to the validated token, not the raw header (HEA-2023).
    let realm_id = auth.realm_id.clone();
    let admin_actor = auth.user_id.clone();
    // Creating a user hashes nothing (the request carries no password), so it
    // takes no KDF permit (#439). It takes a user-create permit instead (#446):
    // a provisioning burst waits for one asynchronously and is shed with `503`
    // past the queue wait, rather than filling the blocking pool logins share.
    let result = match super::run_user_create_admitted(
        move || {
            let audit_ctx = AuditContext {
                actor: Actor::User(admin_actor),
                metadata: Some(serde_json::json!({"via": "user_api"})),
            };
            identity.create_user_attributed(&realm_id, &request, &audit_ctx)
        },
        |e| {
            tracing::error!(error = %e, "create_user task failed");
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
