//! Creating a confidential OAuth client through the admin API.
//!
//! The admin REST create paths (`POST /admin/applications`, `POST /clients`)
//! dropped a `client_secret` from the body ("Hearth mints secrets itself") and
//! minted none, so they could only create public clients. Now `token_endpoint_auth_method` =
//! `client_secret_basic` / `client_secret_post` makes Hearth generate the
//! secret, return it exactly once in the create response, and store only its
//! hash. A caller-chosen secret on REST is refused
//! rather than silently dropped.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

const ROUTES: [&str; 2] = ["/admin/applications", "/clients"];

struct Fx {
    h: common::TestHarness,
    realm: RealmId,
    token: String,
}

async fn fixture() -> Fx {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("admin-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Admin".into(),
                ..Default::default()
            },
        )
        .expect("create user");
    let role = h
        .rbac()
        .get_role_by_name(&realm, "hearth.clients.admin")
        .expect("lookup role")
        .expect("seed role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();
    Fx { h, realm, token }
}

impl Fx {
    fn app(&self) -> axum::Router {
        router(Arc::new(AppState::new(
            self.h.identity_arc(),
            self.h.rbac_arc(),
            self.h.audit_arc(),
        )))
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = self.app().oneshot(req).await.expect("response");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// POSTs a client-create body to an admin route.
    async fn create(
        &self,
        route: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        self.send(
            Request::builder()
                .method("POST")
                .uri(route)
                .header("X-Realm-ID", self.realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {}", self.token))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    /// `client_credentials` at `/token`, authenticated by `client_secret_basic`
    /// or `client_secret_post`.
    async fn client_credentials(&self, id: &str, secret: &str, basic: bool) -> StatusCode {
        let mut body = serde_json::json!({"grant_type": "client_credentials"});
        let mut req = Request::builder()
            .method("POST")
            .uri("/token")
            .header("X-Realm-ID", self.realm.as_uuid().to_string())
            .header("Content-Type", "application/json");
        if basic {
            let creds = base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"));
            req = req.header("Authorization", format!("Basic {creds}"));
        } else {
            body["client_id"] = serde_json::json!(id);
            body["client_secret"] = serde_json::json!(secret);
        }
        self.send(req.body(Body::from(body.to_string())).unwrap())
            .await
            .0
    }

    fn stored_hash(&self, client_id: &str) -> Option<String> {
        self.h
            .identity()
            .get_client(&self.realm, &ClientId::new(client_id.parse().unwrap()))
            .unwrap()
            .expect("client stored")
            .client_secret_hash()
            .map(str::to_string)
    }
}

fn confidential_body(method: &str) -> serde_json::Value {
    serde_json::json!({
        "client_name": "Backend service",
        "redirect_uris": ["https://svc.example.com/cb"],
        "grant_types": ["client_credentials"],
        // First-party: `client_credentials` without a scope.
        "trust_level": "CLIENT_TRUST_LEVEL_FIRST_PARTY",
        "token_endpoint_auth_method": method,
    })
}

/// Both REST routes create a confidential client for both secret methods:
/// the secret is in the create response once, authenticates at `/token` in
/// the requested way, is never read back, and only its hash is stored.
#[tokio::test]
async fn rest_admin_create_returns_a_generated_secret_once() {
    let fx = fixture().await;
    for route in ROUTES {
        for (method, basic) in [("client_secret_basic", true), ("client_secret_post", false)] {
            let (status, body) = fx.create(route, confidential_body(method)).await;
            assert_eq!(status, StatusCode::CREATED, "{route} {method}: {body}");
            let id = body["client_id"].as_str().unwrap().to_string();
            let secret = body["client_secret"]
                .as_str()
                .unwrap_or_else(|| panic!("{route} {method}: no client_secret in {body}"))
                .to_string();
            assert_eq!(secret.len(), 43, "256-bit base64url secret");
            assert_eq!(body["is_confidential"], true, "{route} {method}: {body}");

            let hash = fx
                .stored_hash(&id)
                .expect("a confidential client stores a hash");
            assert!(
                !hash.contains(&secret),
                "the plaintext secret is not stored"
            );

            assert_eq!(
                fx.client_credentials(&id, &secret, basic).await,
                StatusCode::OK,
                "{route} {method}: the returned secret authenticates"
            );
            assert_eq!(
                fx.client_credentials(&id, "not-the-secret", basic).await,
                StatusCode::UNAUTHORIZED,
                "{route} {method}: a wrong secret does not"
            );

            let (status, read) = fx
                .send(
                    Request::builder()
                        .uri(format!("/admin/applications/{id}"))
                        .header("X-Realm-ID", fx.realm.as_uuid().to_string())
                        .header("Authorization", format!("Bearer {}", fx.token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{read}");
            assert!(
                read.get("client_secret").is_none(),
                "{route} {method}: the secret is never read back: {read}"
            );
        }
    }
}

/// Without a method the admin routes still create a public client.
#[tokio::test]
async fn rest_admin_create_without_method_stays_public() {
    let fx = fixture().await;
    for route in ROUTES {
        let mut body = confidential_body("none");
        body.as_object_mut()
            .unwrap()
            .remove("token_endpoint_auth_method");
        body["grant_types"] = serde_json::json!(["authorization_code"]);
        let (status, body) = fx.create(route, body).await;
        assert_eq!(status, StatusCode::CREATED, "{route}: {body}");
        assert!(body.get("client_secret").is_none(), "{route}: {body}");
        let id = body["client_id"].as_str().unwrap();
        assert!(fx.stored_hash(id).is_none(), "{route}: public client");
    }
}

/// A caller-chosen secret was silently dropped (creating a PUBLIC client the
/// operator believed confidential); now it is refused. So are an unknown
/// method and `private_key_jwt` without keys.
#[tokio::test]
async fn rest_admin_create_refuses_what_it_cannot_honour() {
    let fx = fixture().await;
    for route in ROUTES {
        let mut chosen = confidential_body("client_secret_basic");
        chosen["client_secret"] = serde_json::json!("operator-chosen-secret-123!");
        let mut chosen_no_method = confidential_body("none");
        chosen_no_method["client_secret"] = serde_json::json!("operator-chosen-secret-123!");
        for (what, body) in [
            ("caller-chosen secret", chosen),
            ("caller-chosen secret, no method", chosen_no_method),
            ("unknown method", confidential_body("client_secret_jwt")),
            (
                "private_key_jwt without jwks",
                confidential_body("private_key_jwt"),
            ),
        ] {
            let (status, resp) = fx.create(route, body).await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{route} {what}: {resp}"
            );
            assert!(resp.get("client_id").is_none(), "{route} {what}: {resp}");
        }
    }
}

impl Fx {
    async fn regenerate(&self, id: &str) -> (StatusCode, serde_json::Value) {
        self.send(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/applications/{id}/regenerate-secret"))
                .header("X-Realm-ID", self.realm.as_uuid().to_string())
                .header("Authorization", format!("Bearer {}", self.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    fn regeneration_events(&self, id: &str) -> usize {
        let mut q = hearth::audit::AuditQuery::for_realm(self.realm.clone());
        q.action = Some(hearth::audit::AuditAction::ClientUpdated);
        self.h
            .audit()
            .query(&q)
            .unwrap()
            .into_iter()
            .filter(|e| {
                e.resource_id == id
                    && e.metadata.as_ref().and_then(|m| m.get("change"))
                        == Some(&serde_json::json!("client_secret_regenerated"))
                    && !e.actor.is_empty()
            })
            .count()
    }
}

/// `POST /admin/applications/{id}/regenerate-secret` returns a new secret
/// once; the old one stops working at once; the change is audited with the
/// acting admin.
#[tokio::test]
async fn rest_regenerate_secret_replaces_it_at_once() {
    let fx = fixture().await;
    let (_, created) = fx
        .create(
            "/admin/applications",
            confidential_body("client_secret_basic"),
        )
        .await;
    let id = created["client_id"].as_str().unwrap().to_string();
    let old = created["client_secret"].as_str().unwrap().to_string();

    let (status, body) = fx.regenerate(&id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new = body["client_secret"]
        .as_str()
        .expect("new secret")
        .to_string();
    assert_eq!(new.len(), 43);
    assert_ne!(new, old);
    assert_eq!(body["client_id"], id.as_str());

    assert_eq!(
        fx.client_credentials(&id, &old, true).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(fx.client_credentials(&id, &new, true).await, StatusCode::OK);
    assert_eq!(fx.regeneration_events(&id), 1, "one audited regeneration");

    // A public client has no secret to regenerate; an unknown one is 404.
    let mut public = confidential_body("none");
    public["grant_types"] = serde_json::json!(["authorization_code"]);
    let (_, public) = fx.create("/admin/applications", public).await;
    let (status, body) = fx.regenerate(public["client_id"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.get("client_secret").is_none());
    let (status, _) = fx.regenerate(&uuid::Uuid::new_v4().to_string()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A FAPI 2.0 Advanced realm accepts `private_key_jwt` only, so creating a
/// secret-based client there is refused up front, as is
/// regenerating the secret of a client that predates the profile.
#[tokio::test]
async fn fapi_advanced_realm_refuses_secret_clients_at_creation() {
    let fx = fixture().await;
    // A secret client created before the realm turns Advanced.
    let (_, before) = fx
        .create(
            "/admin/applications",
            confidential_body("client_secret_basic"),
        )
        .await;
    let before_id = before["client_id"].as_str().unwrap().to_string();

    let mut config =
        fx.h.identity()
            .get_realm(&fx.realm)
            .unwrap()
            .unwrap()
            .config()
            .clone();
    config.fapi_profile = Some(hearth::identity::FapiProfile::Advanced);
    fx.h.identity()
        .update_realm(
            &fx.realm,
            &hearth::identity::UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .unwrap();

    for route in ROUTES {
        for method in ["client_secret_basic", "client_secret_post"] {
            let (status, body) = fx.create(route, confidential_body(method)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{route} {method}: {body}");
            assert!(
                body.to_string().contains("private_key_jwt"),
                "{route} {method}: the error names the required method: {body}"
            );
            assert!(body.get("client_id").is_none(), "{route} {method}: {body}");
        }
    }

    let (status, body) = fx.regenerate(&before_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.get("client_secret").is_none(), "{body}");
}
