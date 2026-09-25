//! RFC 7009 §2.1 — the revocation endpoint revokes a token only for the
//! client it was issued to.
//!
//! RFC 7009 §2.1: "The authorization server first validates the client
//! credentials … and then verifies whether the token was issued to the client
//! making the revocation request. If this validation fails, the request is
//! refused". §2.2 lets the refusal be the ordinary `200`, so it reveals
//! nothing about the token.
//!
//! Before this check `/revoke`, `/realms/{realm}/revoke` and gRPC `Revoke`
//! revoked any valid token for any authenticated caller — and a public client
//! authenticates on its `client_id` alone. Anyone holding a user's token (a
//! resource server that legitimately received it, or anyone who found a
//! leaked one) could therefore end the user's whole session, or a refresh
//! token's entire grant family, while presenting nothing but a public
//! identifier.
//!
//! Ownership is the client the token was issued to: `azp` when the token
//! carries one, the grant family's client for a family-bound access or
//! refresh token, and `sub` for a `client_credentials` token. A token no
//! client was issued (a Hearth first-party session token) is not revocable
//! through this endpoint by any client. In every refused case the response is
//! still `200` and the token stays live.

mod common;

use std::sync::Arc;

use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    ClientCredentialsRequest, ClientTrustLevel, CreateRealmRequest, CreateUserRequest,
    RegisterClientRequest, SessionContext, TokenIntrospectionRequest, TokenIssuanceContext,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::oauth::OAuthSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::identity::v1 as id_pb;
use hearth::protocol::proto::identity::v1::o_auth_service_server::OAuthService;
use tonic::Request as TonicRequest;

const SECRET: &str = "revoke-ownership-secret-1!";

struct Env {
    h: common::TestHarness,
    base: String,
    realm_name: String,
    realm_id: RealmId,
}

async fn server_env() -> Env {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("revoke-own-{}", uuid::Uuid::new_v4());
    let realm_id = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    Env {
        h,
        base,
        realm_name,
        realm_id,
    }
}

/// Registers a client — confidential when `secret` is `Some`, public otherwise.
fn register(h: &common::TestHarness, realm: &RealmId, secret: Option<&str>) -> ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("client-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: secret.map(str::to_string),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "client_credentials".to_string(),
                    "refresh_token".to_string(),
                ],
                trust_level: ClientTrustLevel::FirstParty,
                ..RegisterClientRequest::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone()
}

/// Mints a user access/refresh pair. `client` is the OAuth client the grant
/// is issued to; `None` is a Hearth first-party session token.
fn user_pair(
    h: &common::TestHarness,
    realm: &RealmId,
    client: Option<&ClientId>,
) -> (String, String) {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("victim-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Victim".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("create session");
    let pair = h
        .identity()
        .issue_tokens_with_context(
            realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                client_id: client.cloned(),
                ..TokenIssuanceContext::default()
            },
        )
        .expect("issue tokens");
    (
        pair.access_token().to_string(),
        pair.refresh_token().to_string(),
    )
}

/// Mints a `client_credentials` access token for a confidential client.
fn machine_token(h: &common::TestHarness, realm: &RealmId, client: &ClientId) -> String {
    h.identity()
        .client_credentials_token(
            realm,
            &ClientCredentialsRequest {
                client_id: client.clone(),
                client_secret: Some(SECRET.to_string()),
                scope: None,
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("mint machine token")
        .access_token()
        .to_string()
}

/// Whether an access token is still live, read from storage (introspection
/// consults the session record and the JTI blocklist directly).
fn is_active(h: &common::TestHarness, realm: &RealmId, access_token: &str) -> bool {
    h.identity()
        .introspect_token(
            realm,
            &TokenIntrospectionRequest {
                token: access_token.to_string(),
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .expect("introspect")
        .active
}

/// POSTs to `/realms/{realm}/revoke` as `client` (with its secret when given).
async fn revoke_realm(env: &Env, token: &str, client: &ClientId, secret: Option<&str>) -> u16 {
    let mut body = serde_json::json!({
        "token": token,
        "client_id": client.as_uuid().to_string(),
    });
    if let Some(s) = secret {
        body["client_secret"] = serde_json::Value::String(s.to_string());
    }
    reqwest::Client::new()
        .post(format!("{}/realms/{}/revoke", env.base, env.realm_name))
        .json(&body)
        .send()
        .await
        .expect("request")
        .status()
        .as_u16()
}

/// POSTs to the header-form `/revoke` as `client`.
async fn revoke_header_form(env: &Env, token: &str, client: &ClientId) -> u16 {
    reqwest::Client::new()
        .post(format!("{}/revoke", env.base))
        .header("X-Realm-ID", env.realm_id.as_uuid().to_string())
        .json(&serde_json::json!({
            "token": token,
            "client_id": client.as_uuid().to_string(),
        }))
        .send()
        .await
        .expect("request")
        .status()
        .as_u16()
}

// ===== A client revokes its own tokens =====

#[tokio::test]
async fn a_public_client_revokes_its_own_access_token() {
    let env = server_env().await;
    let public = register(&env.h, &env.realm_id, None);
    let (access, _) = user_pair(&env.h, &env.realm_id, Some(&public));
    assert!(is_active(&env.h, &env.realm_id, &access), "precondition");

    let status = revoke_realm(&env, &access, &public, None).await;
    assert_eq!(status, 200);
    assert!(
        !is_active(&env.h, &env.realm_id, &access),
        "RFC 7009 §2.1 lets a public client revoke a token issued to it"
    );
}

#[tokio::test]
async fn a_public_client_revokes_its_own_refresh_token() {
    let env = server_env().await;
    let public = register(&env.h, &env.realm_id, None);
    let (access, refresh) = user_pair(&env.h, &env.realm_id, Some(&public));

    let status = revoke_header_form(&env, &refresh, &public).await;
    assert_eq!(status, 200);
    assert!(
        !is_active(&env.h, &env.realm_id, &access),
        "revoking its own refresh token ends the grant's session"
    );
}

#[tokio::test]
async fn a_confidential_client_revokes_its_own_machine_token() {
    let env = server_env().await;
    let conf = register(&env.h, &env.realm_id, Some(SECRET));
    let token = machine_token(&env.h, &env.realm_id, &conf);

    let status = revoke_realm(&env, &token, &conf, Some(SECRET)).await;
    assert_eq!(status, 200);
    assert!(
        !is_active(&env.h, &env.realm_id, &token),
        "the owning client revokes its own client_credentials token"
    );
}

#[tokio::test]
async fn a_confidential_client_revokes_its_own_user_refresh_token() {
    let env = server_env().await;
    let conf = register(&env.h, &env.realm_id, Some(SECRET));
    let (access, refresh) = user_pair(&env.h, &env.realm_id, Some(&conf));

    let status = revoke_realm(&env, &refresh, &conf, Some(SECRET)).await;
    assert_eq!(status, 200);
    assert!(
        !is_active(&env.h, &env.realm_id, &access),
        "a confidential client revokes the grant family issued to it"
    );
}

// ===== Confidential clients must authenticate =====

#[tokio::test]
async fn a_confidential_client_without_its_secret_cannot_revoke_even_its_own_token() {
    let env = server_env().await;
    let conf = register(&env.h, &env.realm_id, Some(SECRET));
    let (access, _) = user_pair(&env.h, &env.realm_id, Some(&conf));

    assert_eq!(
        revoke_realm(&env, &access, &conf, None).await,
        401,
        "a confidential client presenting only its public client_id is unauthenticated"
    );
    assert_eq!(
        revoke_realm(&env, &access, &conf, Some("wrong-secret-entirely-1!")).await,
        401,
        "a wrong secret is rejected"
    );
    assert!(
        is_active(&env.h, &env.realm_id, &access),
        "an unauthenticated revocation must not revoke anything"
    );
}

// ===== A client cannot revoke another client's tokens =====

#[tokio::test]
async fn a_public_client_cannot_revoke_another_clients_access_token() {
    let env = server_env().await;
    let owner = register(&env.h, &env.realm_id, None);
    let attacker = register(&env.h, &env.realm_id, None);
    let (access, _) = user_pair(&env.h, &env.realm_id, Some(&owner));

    let status = revoke_realm(&env, &access, &attacker, None).await;
    assert_eq!(
        status, 200,
        "RFC 7009 §2.2: the refusal is indistinguishable from success"
    );
    assert!(
        is_active(&env.h, &env.realm_id, &access),
        "a token issued to another client must survive (RFC 7009 §2.1)"
    );
}

#[tokio::test]
async fn a_public_client_cannot_revoke_another_clients_refresh_token() {
    let env = server_env().await;
    let owner = register(&env.h, &env.realm_id, None);
    let attacker = register(&env.h, &env.realm_id, None);
    let (access, refresh) = user_pair(&env.h, &env.realm_id, Some(&owner));

    let status = revoke_header_form(&env, &refresh, &attacker).await;
    assert_eq!(status, 200);
    assert!(
        is_active(&env.h, &env.realm_id, &access),
        "another client's refresh token must not end the owner's session or grant family"
    );
}

#[tokio::test]
async fn a_confidential_client_cannot_revoke_another_clients_machine_token() {
    let env = server_env().await;
    let owner = register(&env.h, &env.realm_id, Some(SECRET));
    let other = register(&env.h, &env.realm_id, Some(SECRET));
    let token = machine_token(&env.h, &env.realm_id, &owner);

    let status = revoke_realm(&env, &token, &other, Some(SECRET)).await;
    assert_eq!(status, 200);
    assert!(
        is_active(&env.h, &env.realm_id, &token),
        "client B must not revoke client A's client_credentials token"
    );
}

#[tokio::test]
async fn no_client_can_revoke_a_first_party_session_token() {
    let env = server_env().await;
    let public = register(&env.h, &env.realm_id, None);
    let conf = register(&env.h, &env.realm_id, Some(SECRET));
    let (access, refresh) = user_pair(&env.h, &env.realm_id, None);

    assert_eq!(revoke_realm(&env, &access, &public, None).await, 200);
    assert_eq!(revoke_realm(&env, &refresh, &conf, Some(SECRET)).await, 200);
    assert!(
        is_active(&env.h, &env.realm_id, &access),
        "a token issued to no OAuth client was issued to neither caller"
    );
}

// ===== gRPC Revoke applies the same rule =====

fn grpc_state(h: &common::TestHarness) -> GrpcState {
    GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    )
}

fn grpc_revoke_request(
    realm: &RealmId,
    token: &str,
    client: &ClientId,
) -> TonicRequest<id_pb::TokenRevocationRequest> {
    let mut r = TonicRequest::new(id_pb::TokenRevocationRequest {
        token: token.to_string(),
        token_type_hint: None,
    });
    r.metadata_mut().insert(
        "x-realm-id",
        realm.as_uuid().to_string().parse().expect("realm meta"),
    );
    r.metadata_mut().insert(
        "x-hearth-client-id",
        client.as_uuid().to_string().parse().expect("client meta"),
    );
    r
}

#[tokio::test]
async fn grpc_revoke_only_revokes_the_callers_own_tokens() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let owner = register(&h, &realm, None);
    let attacker = register(&h, &realm, None);
    let (access, _) = user_pair(&h, &realm, Some(&owner));
    let svc = OAuthSvc::new(grpc_state(&h));

    svc.revoke(grpc_revoke_request(&realm, &access, &attacker))
        .await
        .expect("a foreign revoke still answers OK (RFC 7009 §2.2)");
    assert!(
        is_active(&h, &realm, &access),
        "gRPC Revoke must not revoke a token issued to another client"
    );

    svc.revoke(grpc_revoke_request(&realm, &access, &owner))
        .await
        .expect("owner revokes");
    assert!(
        !is_active(&h, &realm, &access),
        "the owning client revokes its own token over gRPC"
    );
}
