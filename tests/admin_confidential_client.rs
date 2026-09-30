//! Creating a confidential OAuth client through the admin API.
//!
//! The admin REST create paths (`POST /admin/applications`, `POST /clients`)
//! dropped a `client_secret` from the body ("Hearth mints secrets itself") and
//! minted none, so they could only create public clients; gRPC honoured a
//! caller-chosen secret. Now `token_endpoint_auth_method` =
//! `client_secret_basic` / `client_secret_post` makes Hearth generate the
//! secret, return it exactly once in the create response, and store only its
//! hash — on REST and gRPC alike. A caller-chosen secret on REST is refused
//! rather than silently dropped.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::identity::AppAdminSvc;
use hearth::protocol::grpc::oauth::OAuthSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::http::{router, AppState};
use hearth::protocol::proto::identity::v1 as id_pb;
use hearth::protocol::proto::identity::v1::application_admin_service_server::ApplicationAdminService;
use hearth::protocol::proto::identity::v1::o_auth_service_server::OAuthService;
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tonic::{Code, Request as TonicRequest};
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

    fn grpc(&self) -> GrpcState {
        GrpcState::new(
            self.h.identity_arc(),
            self.h.rbac_arc(),
            self.h.audit_arc(),
            Arc::new(AdminRateLimiter::new()),
        )
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

fn grpc_request(
    realm: &RealmId,
    token: &str,
    method: &str,
) -> TonicRequest<id_pb::RegisterClientRequest> {
    let mut r = TonicRequest::new(id_pb::RegisterClientRequest {
        client_name: "gRPC backend".to_string(),
        redirect_uris: vec!["https://svc.example.com/cb".to_string()],
        client_secret: None,
        grant_types: vec!["client_credentials".to_string()],
        access_token_authorization: 0,
        trust_level: Some(id_pb::ClientTrustLevel::FirstParty as i32),
        id_token_signed_response_alg: None,
        token_endpoint_auth_method: Some(method.to_string()),
    });
    r.metadata_mut()
        .insert("x-realm-id", realm.as_uuid().to_string().parse().unwrap());
    r.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    r
}

/// gRPC `RegisterClient` and `CreateApplication` honour the same field.
#[tokio::test]
async fn grpc_admin_create_returns_a_generated_secret_once() {
    let fx = fixture().await;
    let oauth = OAuthSvc::new(fx.grpc());
    let apps = AppAdminSvc::new(fx.grpc());
    let created = [
        oauth
            .register_client(grpc_request(&fx.realm, &fx.token, "client_secret_basic"))
            .await
            .expect("RegisterClient")
            .into_inner(),
        apps.create_application(grpc_request(&fx.realm, &fx.token, "client_secret_post"))
            .await
            .expect("CreateApplication")
            .into_inner(),
    ];
    for client in created {
        let secret = client.client_secret.expect("generated secret returned");
        assert_eq!(secret.len(), 43);
        assert!(client.is_confidential);
        assert_eq!(
            fx.client_credentials(&client.client_id, &secret, true)
                .await,
            StatusCode::OK
        );
    }

    let err = oauth
        .register_client(grpc_request(&fx.realm, &fx.token, "client_secret_jwt"))
        .await
        .expect_err("unknown method");
    assert_eq!(err.code(), Code::InvalidArgument);
}
