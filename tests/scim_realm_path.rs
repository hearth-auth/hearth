#![allow(clippy::unwrap_used)]
//! SCIM 2.0 under the realm path, `/realms/{realm_name}/scim/v2` (OpenSpec
//! change `scim-realm-path`).
//!
//! An IdP such as Okta or Entra takes a SCIM base URL and a bearer token. Many
//! IdPs cannot send a custom header, so they cannot send `X-Realm-ID`. SCIM
//! was mounted only at `/scim/v2`, where that header selects the realm. The
//! realm path names the realm in the URL, as every other per-realm protocol
//! surface does.
//!
//! 1. The realm path works with the realm's provisioning token and with an
//!    admin token, without `X-Realm-ID`. The URLs SCIM writes
//!    (`meta.location`, `Location`) use the path the client used.
//! 2. A header that names another realm is `400`. An unknown realm is `404`.
//! 3. A credential of one realm cannot act on another realm through that
//!    realm's path.
//! 4. The legacy `/scim/v2` mount still works with the header.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::{RealmId, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, RealmConfig, SessionContext, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;

// ── fixtures ─────────────────────────────────────────────────────────────────

fn app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

/// A realm under test: its ID and its URL name.
struct TestRealm {
    id: RealmId,
    name: String,
}

impl TestRealm {
    /// The SCIM base URL path of this realm.
    fn scim(&self) -> String {
        format!("/realms/{}/scim/v2", self.name)
    }
}

/// A seeded realm with no SCIM provisioning token: SCIM takes admin tokens.
fn jwt_realm(h: &common::TestHarness) -> TestRealm {
    let name = format!(
        "scim-path-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: name.clone(),
            config: None,
        })
        .expect("create realm");
    h.rbac().seed_realm(realm.id()).expect("seed realm");
    TestRealm {
        id: realm.id().clone(),
        name,
    }
}

/// A seeded realm with a SCIM provisioning token. Returns the realm and the
/// plaintext token.
fn token_realm(h: &common::TestHarness) -> (TestRealm, String) {
    let realm = jwt_realm(h);
    let token = format!("scim-path-token-{}", uuid::Uuid::new_v4());
    let hash: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    h.identity()
        .update_realm(
            &realm.id,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    scim_bearer_token_hash: Some(hash),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set the SCIM token");
    (realm, token)
}

/// An access token of a fresh user who holds the seeded `realm.admin` role.
fn admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("admin-{}@scim-path.test", uuid::Uuid::new_v4()),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("role lookup")
        .expect("seeded realm.admin role");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign realm.admin");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

/// One SCIM response: the status, the `Location` header and the JSON body.
struct Reply {
    status: StatusCode,
    location: Option<String>,
    body: Value,
}

/// Sends one SCIM request. `realm_header` is the `X-Realm-ID` value, if any.
async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    bearer: &str,
    realm_header: Option<&RealmId>,
    body: Option<Value>,
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/scim+json")
        .header("authorization", format!("Bearer {bearer}"));
    if let Some(realm) = realm_header {
        builder = builder.header("x-realm-id", realm.as_uuid().to_string());
    }
    let req = builder
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    Reply {
        status,
        location,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

fn user_payload(email: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": email,
        "name": {"givenName": "Ada", "familyName": "Lovelace"},
        "emails": [{"value": email, "primary": true}],
        "active": true
    })
}

fn email(label: &str) -> String {
    format!("{label}-{}@scim-path.test", uuid::Uuid::new_v4())
}

fn user_in(h: &common::TestHarness, realm: &RealmId, email: &str) -> Option<UserId> {
    h.identity()
        .get_user_by_email(realm, email)
        .expect("user lookup")
        .map(|u| u.id().clone())
}

/// Asserts a `201` create through `base` and returns the new resource's ID.
/// The body's `meta.location` and the `Location` header must both be
/// `{base}/{collection}/{id}`.
fn assert_created(reply: &Reply, base: &str, collection: &str) -> String {
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let id = reply.body["id"].as_str().expect("SCIM id").to_string();
    let expected = format!("{base}/{collection}/{id}");
    assert_eq!(
        reply.body["meta"]["location"].as_str(),
        Some(expected.as_str()),
        "meta.location must use the path the client used: {}",
        reply.body
    );
    assert_eq!(
        reply.location.as_deref(),
        Some(expected.as_str()),
        "the Location header must use the path the client used"
    );
    id
}

// ── 1. the realm path, both credentials ──────────────────────────────────────

#[tokio::test]
async fn provisioning_token_creates_a_user_through_the_realm_path() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, token) = token_realm(&h);
    let app = app(&h);
    let address = email("token");

    let reply = send(
        &app,
        "POST",
        &format!("{}/Users", realm.scim()),
        &token,
        None,
        Some(user_payload(&address)),
    )
    .await;
    let id = assert_created(&reply, &realm.scim(), "Users");
    let stored = user_in(&h, &realm.id, &address).expect("the user exists in the path realm");
    assert_eq!(stored.as_uuid().to_string(), id);

    // The location the server wrote is a working URL for the same client.
    let location = reply.body["meta"]["location"].as_str().unwrap();
    let read = send(&app, "GET", location, &token, None, None).await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.body);
    assert_eq!(read.body["id"].as_str(), Some(id.as_str()));
    assert_eq!(read.body["userName"].as_str(), Some(address.as_str()));
}

#[tokio::test]
async fn admin_token_creates_a_user_through_the_realm_path() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = jwt_realm(&h);
    let token = admin_token(&h, &realm.id);
    let app = app(&h);
    let address = email("admin");

    let reply = send(
        &app,
        "POST",
        &format!("{}/Users", realm.scim()),
        &token,
        None,
        Some(user_payload(&address)),
    )
    .await;
    let id = assert_created(&reply, &realm.scim(), "Users");
    assert!(
        user_in(&h, &realm.id, &address).is_some(),
        "the user exists in the path realm"
    );

    let location = reply.body["meta"]["location"].as_str().unwrap();
    let read = send(&app, "GET", location, &token, None, None).await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.body);
    assert_eq!(read.body["id"].as_str(), Some(id.as_str()));
}

// ── 2. header disagreement and unknown realms ───────────────────────────────

#[tokio::test]
async fn a_header_naming_another_realm_is_rejected() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, token) = token_realm(&h);
    let other = jwt_realm(&h);
    let app = app(&h);
    let address = email("mismatch");

    let reply = send(
        &app,
        "POST",
        &format!("{}/Users", realm.scim()),
        &token,
        Some(&other.id),
        Some(user_payload(&address)),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.body["error"].as_str(), Some("realm_mismatch"));
    assert!(user_in(&h, &realm.id, &address).is_none());
    assert!(user_in(&h, &other.id, &address).is_none());

    // A header that agrees with the path is accepted.
    let reply = send(
        &app,
        "POST",
        &format!("{}/Users", realm.scim()),
        &token,
        Some(&realm.id),
        Some(user_payload(&address)),
    )
    .await;
    assert_created(&reply, &realm.scim(), "Users");
}

#[tokio::test]
async fn an_unknown_realm_name_is_not_found() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (_realm, token) = token_realm(&h);
    let app = app(&h);

    for (method, path) in [
        ("POST", "/Users"),
        ("GET", "/Users"),
        ("GET", "/Users/7f0c3a52-0d7a-4f43-9d0c-3f1b2c4d5e6f"),
        ("GET", "/ServiceProviderConfig"),
    ] {
        let uri = format!(
            "/realms/no-such-realm-{}/scim/v2{path}",
            uuid::Uuid::new_v4().simple()
        );
        let body = (method == "POST").then(|| user_payload(&email("unknown")));
        let reply = send(&app, method, &uri, &token, None, body).await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{method} {path}: {}",
            reply.body
        );
        // A SCIM error, so the 404 comes from the realm lookup and not from
        // a route that does not exist.
        assert_eq!(
            reply.body["schemas"][0].as_str(),
            Some("urn:ietf:params:scim:api:messages:2.0:Error"),
            "{method} {path}: {}",
            reply.body
        );
        assert_eq!(reply.body["status"].as_str(), Some("404"));
    }
}

// ── 3. a credential stays in its realm ──────────────────────────────────────

#[tokio::test]
async fn a_provisioning_token_cannot_act_on_another_realm_through_its_path() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (home, home_token) = token_realm(&h);
    let (victim, _victim_token) = token_realm(&h);
    let fallback_victim = jwt_realm(&h);
    let app = app(&h);

    // The victim realm has its own token, and the victim realm accepts admin
    // tokens: the home realm's token is a credential for neither.
    for target in [&victim, &fallback_victim] {
        let address = email("cross-token");
        let reply = send(
            &app,
            "POST",
            &format!("{}/Users", target.scim()),
            &home_token,
            None,
            Some(user_payload(&address)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
        assert!(user_in(&h, &target.id, &address).is_none());
        assert!(user_in(&h, &home.id, &address).is_none());
    }
}

#[tokio::test]
async fn an_admin_token_cannot_act_on_another_realm_through_its_path() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let home = jwt_realm(&h);
    let victim = jwt_realm(&h);
    let token = admin_token(&h, &home.id);
    let app = app(&h);
    let address = email("cross-admin");

    let reply = send(
        &app,
        "POST",
        &format!("{}/Users", victim.scim()),
        &token,
        None,
        Some(user_payload(&address)),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert!(user_in(&h, &victim.id, &address).is_none());
}

// ── 4. the legacy mount ─────────────────────────────────────────────────────

#[tokio::test]
async fn the_legacy_mount_still_works_with_the_header() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, token) = token_realm(&h);
    let app = app(&h);
    let address = email("legacy");

    let reply = send(
        &app,
        "POST",
        "/scim/v2/Users",
        &token,
        Some(&realm.id),
        Some(user_payload(&address)),
    )
    .await;
    let id = assert_created(&reply, "/scim/v2", "Users");
    assert!(user_in(&h, &realm.id, &address).is_some());

    let read = send(
        &app,
        "GET",
        &format!("/scim/v2/Users/{id}"),
        &token,
        Some(&realm.id),
        None,
    )
    .await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.body);
    assert_eq!(
        read.body["meta"]["location"].as_str(),
        Some(format!("/scim/v2/Users/{id}").as_str())
    );
}

// ── the whole surface works under the realm path ─────────────────────────────

#[tokio::test]
async fn the_realm_path_serves_the_user_lifecycle() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, token) = token_realm(&h);
    let app = app(&h);
    let base = realm.scim();
    let address = email("lifecycle");

    let created = send(
        &app,
        "POST",
        &format!("{base}/Users"),
        &token,
        None,
        Some(user_payload(&address)),
    )
    .await;
    let id = assert_created(&created, &base, "Users");
    let location = format!("{base}/Users/{id}");

    let list = send(&app, "GET", &format!("{base}/Users"), &token, None, None).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    let resources = list.body["Resources"].as_array().expect("Resources");
    assert!(
        resources
            .iter()
            .any(|r| r["id"].as_str() == Some(id.as_str())),
        "the list must contain the created user: {}",
        list.body
    );
    for resource in resources {
        let rid = resource["id"].as_str().unwrap();
        assert_eq!(
            resource["meta"]["location"].as_str(),
            Some(format!("{base}/Users/{rid}").as_str()),
            "a listed resource's location must use the realm path"
        );
    }

    let patched = send(
        &app,
        "PATCH",
        &location,
        &token,
        None,
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": false}]
        })),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["active"], json!(false));
    assert_eq!(
        patched.body["meta"]["location"].as_str(),
        Some(location.as_str())
    );

    let mut replacement = user_payload(&address);
    replacement["displayName"] = json!("Ada L.");
    let replaced = send(&app, "PUT", &location, &token, None, Some(replacement)).await;
    assert_eq!(replaced.status, StatusCode::OK, "{}", replaced.body);
    assert_eq!(replaced.body["displayName"].as_str(), Some("Ada L."));
    assert_eq!(
        replaced.body["meta"]["location"].as_str(),
        Some(location.as_str())
    );

    let deleted = send(&app, "DELETE", &location, &token, None, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.body);
    let gone = send(&app, "GET", &location, &token, None, None).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND, "{}", gone.body);
}

#[tokio::test]
async fn the_realm_path_serves_groups_and_discovery() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, token) = token_realm(&h);
    let app = app(&h);
    let base = realm.scim();

    for doc in ["ServiceProviderConfig", "Schemas", "ResourceTypes"] {
        let reply = send(&app, "GET", &format!("{base}/{doc}"), &token, None, None).await;
        assert_eq!(reply.status, StatusCode::OK, "{doc}: {}", reply.body);
    }

    let created = send(
        &app,
        "POST",
        &format!("{base}/Groups"),
        &token,
        None,
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering"
        })),
    )
    .await;
    let id = assert_created(&created, &base, "Groups");
    let location = format!("{base}/Groups/{id}");

    let read = send(&app, "GET", &location, &token, None, None).await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.body);
    assert_eq!(
        read.body["meta"]["location"].as_str(),
        Some(location.as_str())
    );

    let list = send(&app, "GET", &format!("{base}/Groups"), &token, None, None).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    assert!(list.body["Resources"]
        .as_array()
        .expect("Resources")
        .iter()
        .any(|g| g["meta"]["location"].as_str() == Some(location.as_str())));

    let deleted = send(&app, "DELETE", &location, &token, None, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.body);
}
