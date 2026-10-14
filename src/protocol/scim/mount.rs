//! How the SCIM router is mounted: the header mount and the realm-path mount.
//!
//! The same [`crate::protocol::scim::router`] is served at two bases:
//!
//! - `/scim/v2` — the `X-Realm-ID` header selects the realm.
//! - `/realms/{realm_name}/scim/v2` — the path selects the realm. Many IdPs
//!   (Okta, Entra) take only a base URL and a bearer token and cannot send a
//!   custom header (OpenSpec change `scim-realm-path`).
//!
//! On the realm-path mount, [`bind_path_realm`] resolves the realm and sets
//! `X-Realm-ID` from it, so the handlers and their auth stay the same on both
//! mounts. It also records the base path in a [`ScimBase`] extension, so the
//! URLs SCIM writes point at the base the client used.

use std::sync::Arc;

use axum::extract::{FromRequestParts, RawPathParams, Request, State};
use axum::http::request::Parts;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::protocol::http::AppState;
use crate::protocol::scim::error::ScimError;

/// The SCIM base path of the header mount.
pub const HEADER_MOUNT_BASE: &str = "/scim/v2";

/// The path parameter that names the realm on the realm-path mount.
const REALM_NAME_PARAM: &str = "realm_name";

/// The base path a SCIM request was addressed to, without a trailing slash:
/// `/scim/v2` or `/realms/{realm_name}/scim/v2`.
///
/// `meta.location` and the `Location` header are built from it. As an
/// extractor it reads the extension that [`bind_path_realm`] sets, and falls
/// back to [`HEADER_MOUNT_BASE`] on the header mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimBase(String);

impl ScimBase {
    /// The base of the realm-path mount for the realm named `realm_name`.
    ///
    /// Realm names allow only ASCII letters, digits, `-` and `_`, so the name
    /// needs no URL encoding.
    #[must_use]
    pub fn realm_path(realm_name: &str) -> Self {
        Self(format!("/realms/{realm_name}{HEADER_MOUNT_BASE}"))
    }

    /// The base path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path of a resource collection under this base, for example
    /// `/realms/acme/scim/v2/Users` for `collection = "Users"`.
    #[must_use]
    pub fn collection(&self, collection: &str) -> String {
        format!("{}/{collection}", self.0)
    }
}

impl Default for ScimBase {
    fn default() -> Self {
        Self(HEADER_MOUNT_BASE.to_owned())
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ScimBase {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned().unwrap_or_default())
    }
}

/// The `{id}` path parameter of a SCIM resource route, read by name.
///
/// Under `/realms/{realm_name}/scim/v2/Users/{id}` the route has two path
/// parameters, and a `Path<String>` extractor refuses the request. Reading
/// the parameter by name works on both mounts.
#[derive(Debug, Deserialize)]
pub struct ResourceIdPath {
    /// The resource ID from the URL.
    pub id: String,
}

/// Binds a realm-path SCIM request to the realm its path names.
///
/// It resolves `{realm_name}` and answers `404` (a SCIM error) when no realm
/// has that name. Otherwise it sets `X-Realm-ID` to the realm's ID and stores
/// the request's [`ScimBase`].
///
/// It MUST run before the admin DPoP layer. That layer reads the realm from
/// `X-Realm-ID`; without the header it finds no realm and lets the request
/// through, so a DPoP-bound token would replay as a plain Bearer.
///
/// The header is overwritten, never trusted: `realm_path_header_agreement`
/// runs first and refuses a header that names another realm with `400`.
pub async fn bind_path_realm(
    State(state): State<Arc<AppState>>,
    params: RawPathParams,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(realm_name) = params
        .iter()
        .find_map(|(name, value)| (name == REALM_NAME_PARAM).then_some(value))
    else {
        // Mounted only under `/realms/{realm_name}`; a route without the
        // parameter is a wiring bug. Fail closed.
        tracing::error!("SCIM realm-path route has no realm_name parameter");
        return ScimError::internal().into_response();
    };

    let realm = match state.identity.get_realm_by_name(realm_name) {
        Ok(Some(realm)) => realm,
        Ok(None) => return ScimError::not_found("realm not found").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "SCIM realm-path realm lookup failed");
            return ScimError::internal().into_response();
        }
    };

    let Ok(realm_header) = HeaderValue::from_str(&realm.id().as_uuid().to_string()) else {
        return ScimError::internal().into_response();
    };
    req.headers_mut().insert("x-realm-id", realm_header);
    req.extensions_mut()
        .insert(ScimBase::realm_path(realm.name()));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::{ScimBase, HEADER_MOUNT_BASE};

    #[test]
    fn the_header_mount_base_is_the_default() {
        assert_eq!(ScimBase::default().as_str(), HEADER_MOUNT_BASE);
        assert_eq!(ScimBase::default().collection("Users"), "/scim/v2/Users");
    }

    #[test]
    fn the_realm_path_base_names_the_realm() {
        let base = ScimBase::realm_path("acme");
        assert_eq!(base.as_str(), "/realms/acme/scim/v2");
        assert_eq!(base.collection("Groups"), "/realms/acme/scim/v2/Groups");
    }
}
