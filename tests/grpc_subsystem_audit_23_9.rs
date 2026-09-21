#![allow(clippy::unwrap_used)]
//! Task 23.9 — the gRPC management API beyond the `Decide` and admin paths
//! that audit 2026-08-28 §4.2 and §4.19 reached.
//!
//! | Finding | Test |
//! |---|---|
//! | `OAuthService::DeviceAuthorize` never authenticated a confidential client, while its REST sibling has since §4.19#4 | `grpc_device_authorize_rejects_a_confidential_client_without_its_secret`, `grpc_device_authorize_accepts_a_confidential_client_with_its_secret`, `grpc_device_authorize_still_serves_a_public_client` |
//! | The A-15 shaper bucketed every realm under the empty key, so one tenant spent the whole per-realm budget for all of them | `grpc_rate_limiter_buckets_each_realm_separately` |

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hearth::abuse::shaper::{RequestShaper, ShaperConfig};
use hearth::core::{ClientId, RealmId};
use hearth::identity::{ClientTrustLevel, RegisterClientRequest};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::oauth::OAuthSvc;
use hearth::protocol::grpc::server::{grpc_rate_limit_interceptor, GrpcState};
use hearth::protocol::proto::identity::v1 as id_pb;
use hearth::protocol::proto::identity::v1::o_auth_service_server::OAuthService;
use tonic::transport::server::TcpConnectInfo;
use tonic::{Code, Request as TonicRequest};

const CONFIDENTIAL_SECRET: &str = "device-grant-confidential-secret";

fn grpc_state(h: &common::TestHarness) -> GrpcState {
    GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    )
}

/// Registers a client in `realm`, confidential when `secret` is `Some`.
fn register_client(
    h: &common::TestHarness,
    realm: &RealmId,
    name: &str,
    secret: Option<&str>,
) -> ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: name.to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: secret.map(str::to_string),
                grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                // A third-party client must declare scopes; that rule is not
                // what these tests measure.
                trust_level: ClientTrustLevel::FirstParty,
                ..RegisterClientRequest::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone()
}

/// Builds a `DeviceAuthorize` request, optionally carrying gRPC client
/// credentials in the metadata keys `verify_grpc_client_auth` reads.
fn device_request(
    realm: &RealmId,
    client_id: &ClientId,
    credentials: Option<(&ClientId, &str)>,
) -> TonicRequest<id_pb::DeviceAuthorizationRequest> {
    let mut r = TonicRequest::new(id_pb::DeviceAuthorizationRequest {
        client_id: client_id.as_uuid().to_string(),
        scope: None,
        client_secret: None,
    });
    r.metadata_mut().insert(
        "x-realm-id",
        realm.as_uuid().to_string().parse().expect("realm meta"),
    );
    if let Some((id, secret)) = credentials {
        r.metadata_mut().insert(
            "x-hearth-client-id",
            id.as_uuid().to_string().parse().expect("client id meta"),
        );
        r.metadata_mut()
            .insert("x-hearth-client-secret", secret.parse().expect("secret"));
    }
    r
}

// ===== DeviceAuthorize: confidential-client authentication =====

#[tokio::test]
async fn grpc_device_authorize_rejects_a_confidential_client_without_its_secret() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let client_id = register_client(&h, &realm, "Confidential TV", Some(CONFIDENTIAL_SECRET));
    let svc = OAuthSvc::new(grpc_state(&h));

    let err = svc
        .device_authorize(device_request(&realm, &client_id, None))
        .await
        .expect_err("a confidential client identifier alone must not start an RFC 8628 flow");

    assert_eq!(
        err.code(),
        Code::Unauthenticated,
        "gRPC DeviceAuthorize must authenticate a confidential client, as POST /device_authorization does"
    );
}

#[tokio::test]
async fn grpc_device_authorize_rejects_a_wrong_secret() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let client_id = register_client(&h, &realm, "Confidential TV", Some(CONFIDENTIAL_SECRET));
    let svc = OAuthSvc::new(grpc_state(&h));

    let err = svc
        .device_authorize(device_request(
            &realm,
            &client_id,
            Some((&client_id, "not-the-secret")),
        ))
        .await
        .expect_err("a wrong client secret must not start an RFC 8628 flow");

    assert_eq!(err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn grpc_device_authorize_accepts_a_confidential_client_with_its_secret() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let client_id = register_client(&h, &realm, "Confidential TV", Some(CONFIDENTIAL_SECRET));
    let svc = OAuthSvc::new(grpc_state(&h));

    let resp = svc
        .device_authorize(device_request(
            &realm,
            &client_id,
            Some((&client_id, CONFIDENTIAL_SECRET)),
        ))
        .await
        .expect("a confidential client presenting its secret must be served")
        .into_inner();

    assert!(
        !resp.device_code.is_empty(),
        "the gate must not break the legitimate flow"
    );
    assert!(!resp.user_code.is_empty());
}

#[tokio::test]
async fn grpc_device_authorize_still_serves_a_public_client() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let client_id = register_client(&h, &realm, "Public TV", None);
    let svc = OAuthSvc::new(grpc_state(&h));

    let resp = svc
        .device_authorize(device_request(&realm, &client_id, None))
        .await
        .expect("a public client needs no secret (RFC 8628 §3.1)")
        .into_inner();

    assert!(!resp.device_code.is_empty());
}

/// The `client_secret_post` fallback the proto documents: the secret rides in
/// the request body rather than in metadata.
fn device_request_with_body_secret(
    realm: &RealmId,
    client_id: &ClientId,
    secret: &str,
) -> TonicRequest<id_pb::DeviceAuthorizationRequest> {
    let mut r = TonicRequest::new(id_pb::DeviceAuthorizationRequest {
        client_id: client_id.as_uuid().to_string(),
        scope: None,
        client_secret: Some(secret.to_string()),
    });
    r.metadata_mut().insert(
        "x-realm-id",
        realm.as_uuid().to_string().parse().expect("realm meta"),
    );
    r
}

#[tokio::test]
async fn grpc_device_authorize_honours_the_body_client_secret_the_proto_documents() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let client_id = register_client(&h, &realm, "Confidential TV", Some(CONFIDENTIAL_SECRET));
    let svc = OAuthSvc::new(grpc_state(&h));

    let resp = svc
        .device_authorize(device_request_with_body_secret(
            &realm,
            &client_id,
            CONFIDENTIAL_SECRET,
        ))
        .await
        .expect("DeviceAuthorizationRequest.client_secret is the documented post fallback")
        .into_inner();
    assert!(!resp.device_code.is_empty());

    let err = svc
        .device_authorize(device_request_with_body_secret(&realm, &client_id, "wrong"))
        .await
        .expect_err("a wrong body secret must be refused");
    assert_eq!(err.code(), Code::Unauthenticated);
}

// ===== A-15 shaper: per-realm buckets =====

/// A request carrying a peer address (so the interceptor does not fail open)
/// and the given realm header.
fn shaped_request(realm: &str) -> TonicRequest<()> {
    let mut r = TonicRequest::new(());
    r.metadata_mut()
        .insert("x-realm-id", realm.parse().expect("realm meta"));
    r.extensions_mut().insert(TcpConnectInfo {
        local_addr: None,
        remote_addr: Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            4000,
        )),
    });
    r
}

#[test]
fn grpc_rate_limiter_buckets_each_realm_separately() {
    // Per-IP disabled so only the per-realm arm can reject. Budget of 1 rps.
    let shaper = Arc::new(RequestShaper::with_config(ShaperConfig {
        ip_rps: None,
        realm_rps: Some(1),
    }));
    let intercept = grpc_rate_limit_interceptor(shaper);

    let realm_a = "11111111-1111-1111-1111-111111111111";
    let realm_b = "22222222-2222-2222-2222-222222222222";

    assert!(
        intercept(shaped_request(realm_a)).is_ok(),
        "realm A's first call is within its own budget"
    );
    assert!(
        intercept(shaped_request(realm_b)).is_ok(),
        "realm B must have its own budget — one tenant must not spend another tenant's"
    );
    // And the budget is still enforced per realm.
    let err = intercept(shaped_request(realm_a))
        .map(|_| ())
        .expect_err("realm A's second call exceeds its own 1 rps budget");
    assert_eq!(err.code(), Code::ResourceExhausted);
}
