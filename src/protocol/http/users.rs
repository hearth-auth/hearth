//! User management endpoints: `POST /users`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

use crate::protocol::proto::identity::v1 as pb;

use super::{extract_realm_id, identity_error_to_response, proto_to_rest_json, AppState};

/// Registers user management routes.
pub(super) fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::post;
    axum::Router::new().route("/users", post(create_user))
}

/// Create a new user.
///
/// Requires `X-Realm-ID` header. Returns the created user record.
async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::CreateUserRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = crate::identity::CreateUserRequest::from(body);

    let identity = Arc::clone(&state.identity);
    // create_user hashes an Argon2id credential — route through the shared KDF
    // admission gate (HEA-1891 / F3) so it shares the one permit pool with the
    // UI auth paths rather than oversubscribing the blocking pool.
    let result = match super::run_kdf_gated_rest(
        move || identity.create_user(&realm_id, &request),
        |e| {
            tracing::error!(error = %e, "create_user KDF task failed");
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
