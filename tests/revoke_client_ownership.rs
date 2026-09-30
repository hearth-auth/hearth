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
//! Ownership is the client the token was issued to: `act.sub` for an RFC
//! 8693 exchanged token, `azp` when the token carries one, the grant family's
//! client for a family-bound access or refresh token, and `sub` for a
//! `client_credentials` token. A token no client was issued (a Hearth
//! first-party session token) is not revocable through this endpoint by any
//! client. In every refused case the response is still `200` and the token
//! stays live.

mod common;

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::tokens::{Audience, JwtAssertionClaims};
use hearth::identity::{
    AccessTokenAuthorization, ClientCredentialsRequest, ClientTrustLevel, CreateRealmRequest,
    CreateUserRequest, DeviceAuthorizationRequest, RegisterClientRequest, Rfc8693Request,
    SessionContext, SigningKey, TokenIntrospectionRequest, TokenIssuanceContext,
    UpdateClientRequest,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::oauth::OAuthSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::identity::v1 as id_pb;
use hearth::protocol::proto::identity::v1::o_auth_service_server::OAuthService;
use tonic::{Code, Request as TonicRequest};

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
                    "urn:ietf:params:oauth:grant-type:device_code".to_string(),
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

// ===== Tokens minted by real grant flows carry their issuing client =====
//
// The cases above mint through `issue_tokens_with_context` directly. The ones
// below go through the grant that really issues the token, because a grant
// that forgets to record its client leaves the owning client unable to revoke
// — a silent `200` over a token that stays live.

/// Runs a full RFC 8628 device flow for `client` and returns the access and
/// refresh tokens the poll mints.
fn device_pair(h: &common::TestHarness, realm: &RealmId, client: &ClientId) -> (String, String) {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("tv-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "TV viewer".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user");
    let auth = h
        .identity()
        .device_authorize(
            realm,
            &DeviceAuthorizationRequest {
                client_id: client.clone(),
                scope: None,
            },
        )
        .expect("device authorize");
    h.identity()
        .approve_device(realm, &auth.user_code, user.id())
        .expect("approve device");
    let resp = h
        .identity()
        .poll_device_token(realm, &auth.device_code, client, None)
        .expect("poll device token");
    (
        resp.access_token().to_string(),
        resp.refresh_token().to_string(),
    )
}

#[tokio::test]
async fn a_device_client_revokes_its_own_device_grant_access_token() {
    let env = server_env().await;
    let tv = register(&env.h, &env.realm_id, None);
    let (access, _) = device_pair(&env.h, &env.realm_id, &tv);
    assert!(is_active(&env.h, &env.realm_id, &access), "precondition");

    assert_eq!(revoke_realm(&env, &access, &tv, None).await, 200);
    assert!(
        !is_active(&env.h, &env.realm_id, &access),
        "the device client the token was issued to must be able to revoke it"
    );
}

#[tokio::test]
async fn a_device_client_revokes_its_own_device_grant_refresh_token() {
    let env = server_env().await;
    let tv = register(&env.h, &env.realm_id, None);
    let (access, refresh) = device_pair(&env.h, &env.realm_id, &tv);

    assert_eq!(revoke_header_form(&env, &refresh, &tv).await, 200);
    assert!(
        !is_active(&env.h, &env.realm_id, &access),
        "revoking the device grant's refresh token ends its session"
    );
    assert!(
        env.h
            .identity()
            .refresh_tokens(&env.realm_id, &refresh, None, None)
            .is_err(),
        "a revoked device-grant refresh token must not rotate"
    );
}

#[tokio::test]
async fn another_client_cannot_revoke_a_device_grant_token() {
    let env = server_env().await;
    let tv = register(&env.h, &env.realm_id, None);
    let attacker = register(&env.h, &env.realm_id, None);
    let (access, refresh) = device_pair(&env.h, &env.realm_id, &tv);

    assert_eq!(revoke_realm(&env, &access, &attacker, None).await, 200);
    assert_eq!(revoke_header_form(&env, &refresh, &attacker).await, 200);
    assert!(
        is_active(&env.h, &env.realm_id, &access),
        "a device-grant token issued to another client must survive"
    );
}

// ===== RFC 8693 token exchange: the exchanged token belongs to the actor =====

/// Registers a confidential client declaring `scope`, able to mint
/// `client_credentials` tokens and to perform token exchange.
fn register_scoped(h: &common::TestHarness, realm: &RealmId, scope: &str) -> ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("scoped-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some(SECRET.to_string()),
                // GA audit M8: an exchanging client must hold the grant.
                grant_types: vec![
                    "client_credentials".to_string(),
                    "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                ],
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: scope.split_whitespace().map(String::from).collect(),
                access_token_authorization: AccessTokenAuthorization::Embedded,
                ..RegisterClientRequest::default()
            },
        )
        .expect("register scoped client")
        .client_id()
        .clone()
}

/// A user access token issued to `client` with a non-empty `scope`, so it can
/// be exchanged (RFC 8693 §4.4 refuses an empty scope intersection).
fn scoped_user_access(h: &common::TestHarness, realm: &RealmId, client: &ClientId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("subject-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Subject".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("create session");
    h.identity()
        .issue_tokens_with_context(
            realm,
            user.id(),
            session.id(),
            &TokenIssuanceContext {
                client_id: Some(client.clone()),
                granted_scopes: std::iter::once("read".to_string()).collect(),
                ..TokenIssuanceContext::default()
            },
        )
        .expect("issue subject tokens")
        .access_token()
        .to_string()
}

/// Exchanges `subject_token` at the token endpoint as `actor` (RFC 8693).
fn exchange(
    h: &common::TestHarness,
    realm: &RealmId,
    actor: &ClientId,
    subject_token: &str,
) -> String {
    h.identity()
        .rfc8693_token_exchange(
            realm,
            &Rfc8693Request {
                client_id: actor.clone(),
                subject_token: subject_token.to_string(),
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: None,
                actor_token_type: None,
                requested_token_type: None,
                scope: None,
                resource: None,
                audience: None,
                dpop_jkt: None,
            },
        )
        .expect("token exchange")
        .access_token
}

#[tokio::test]
async fn an_exchanged_user_token_belongs_to_the_exchanging_client() {
    let env = server_env().await;
    let subject_client = register(&env.h, &env.realm_id, None);
    let actor = register_scoped(&env.h, &env.realm_id, "read");
    let subject = scoped_user_access(&env.h, &env.realm_id, &subject_client);
    let exchanged = exchange(&env.h, &env.realm_id, &actor, &subject);
    assert!(is_active(&env.h, &env.realm_id, &exchanged), "precondition");

    assert_eq!(
        revoke_realm(&env, &exchanged, &subject_client, None).await,
        200
    );
    assert!(
        is_active(&env.h, &env.realm_id, &exchanged),
        "the subject token's client was not issued the exchanged token and must not revoke it"
    );

    assert_eq!(
        revoke_realm(&env, &exchanged, &actor, Some(SECRET)).await,
        200
    );
    assert!(
        !is_active(&env.h, &env.realm_id, &exchanged),
        "the client the exchanged token was issued to must be able to revoke it"
    );
    assert!(
        is_active(&env.h, &env.realm_id, &subject),
        "revoking the delegated token must not end the session behind the subject \
         client's own token — that would revoke a token issued to another client"
    );
}

#[tokio::test]
async fn an_exchanged_machine_token_belongs_to_the_exchanging_client() {
    let env = server_env().await;
    let subject_client = register_scoped(&env.h, &env.realm_id, "read");
    let actor = register_scoped(&env.h, &env.realm_id, "read");
    let subject = env
        .h
        .identity()
        .client_credentials_token(
            &env.realm_id,
            &ClientCredentialsRequest {
                client_id: subject_client.clone(),
                client_secret: Some(SECRET.to_string()),
                scope: Some("read".to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("mint subject machine token")
        .access_token()
        .to_string();
    let exchanged = exchange(&env.h, &env.realm_id, &actor, &subject);
    assert!(is_active(&env.h, &env.realm_id, &exchanged), "precondition");

    assert_eq!(
        revoke_realm(&env, &exchanged, &subject_client, Some(SECRET)).await,
        200
    );
    assert!(
        is_active(&env.h, &env.realm_id, &exchanged),
        "the subject machine token's client must not revoke a token issued to another client"
    );

    assert_eq!(
        revoke_realm(&env, &exchanged, &actor, Some(SECRET)).await,
        200
    );
    assert!(
        !is_active(&env.h, &env.realm_id, &exchanged),
        "the exchanging client revokes the machine token it was issued"
    );
}

/// Whether `client` sees the access token as active when it introspects it
/// (RFC 7662), i.e. with the endpoint's audience gate applied.
fn introspects_active_as(
    h: &common::TestHarness,
    realm: &RealmId,
    access_token: &str,
    client: &ClientId,
) -> bool {
    h.identity()
        .introspect_token(
            realm,
            &TokenIntrospectionRequest {
                token: access_token.to_string(),
                token_type_hint: None,
                introspecting_client_id: Some(client.clone()),
            },
        )
        .expect("introspect")
        .active
}

/// Recording who an exchanged token was issued to (for RFC 7009 ownership)
/// must not narrow who may introspect it. A resource server that receives an
/// agent's delegated user token and validates it by introspection is neither
/// the exchanging client nor (with `resource=`) named in `aud` by client_id;
/// the RFC 7662 audience gate lets a declared resource server (GA audit L11:
/// `access_token_authorization` `introspection`/`decision`) introspect a
/// user-session token that is bound to no `azp`, and exchange must keep it so.
#[tokio::test]
async fn a_resource_server_can_still_introspect_an_exchanged_user_token() {
    let env = server_env().await;
    let subject_client = register(&env.h, &env.realm_id, None);
    let actor = register_scoped(&env.h, &env.realm_id, "read");
    let resource_server = register_scoped(&env.h, &env.realm_id, "read");
    env.h
        .identity()
        .update_client(
            &env.realm_id,
            &resource_server,
            &UpdateClientRequest {
                access_token_authorization: Some(AccessTokenAuthorization::Introspection),
                ..Default::default()
            },
        )
        .expect("declare the resource server");
    let subject = scoped_user_access(&env.h, &env.realm_id, &subject_client);
    let exchanged = exchange(&env.h, &env.realm_id, &actor, &subject);

    assert!(
        introspects_active_as(&env.h, &env.realm_id, &exchanged, &resource_server),
        "a third-party resource server must still be able to introspect a delegated user token"
    );
    assert!(introspects_active_as(
        &env.h,
        &env.realm_id,
        &exchanged,
        &actor
    ));
}

/// The machine-subject case of the same rule: an exchanged `client_credentials`
/// token keeps the subject's introspection audience (its own client, or an
/// `aud` member), exactly as before ownership was recorded.
#[tokio::test]
async fn an_exchanged_machine_token_keeps_its_introspection_audience() {
    let env = server_env().await;
    let subject_client = register_scoped(&env.h, &env.realm_id, "read");
    let actor = register_scoped(&env.h, &env.realm_id, "read");
    let stranger = register_scoped(&env.h, &env.realm_id, "read");
    let subject = env
        .h
        .identity()
        .client_credentials_token(
            &env.realm_id,
            &ClientCredentialsRequest {
                client_id: subject_client.clone(),
                client_secret: Some(SECRET.to_string()),
                scope: Some("read".to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("mint subject machine token")
        .access_token()
        .to_string();
    let exchanged = exchange(&env.h, &env.realm_id, &actor, &subject);

    assert!(
        introspects_active_as(&env.h, &env.realm_id, &exchanged, &subject_client),
        "the machine subject's own client keeps introspecting the exchanged token"
    );
    assert!(
        !introspects_active_as(&env.h, &env.realm_id, &exchanged, &stranger),
        "control: an unrelated client is still refused by the audience gate"
    );
}

/// With an `actor_token` the exchanged token's `act.sub` is the actor token's
/// `sub` — the prefixed `client_<uuid>` form, not the bare UUID the
/// actor-less path records. Ownership must resolve both spellings.
#[tokio::test]
async fn an_exchanged_token_with_an_actor_token_belongs_to_the_actor() {
    let env = server_env().await;
    let subject_client = register(&env.h, &env.realm_id, None);
    let actor = register_scoped(&env.h, &env.realm_id, "read");
    let subject = scoped_user_access(&env.h, &env.realm_id, &subject_client);
    let actor_token = env
        .h
        .identity()
        .client_credentials_token(
            &env.realm_id,
            &ClientCredentialsRequest {
                client_id: actor.clone(),
                client_secret: Some(SECRET.to_string()),
                scope: Some("read".to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("mint actor token")
        .access_token()
        .to_string();
    let exchanged = env
        .h
        .identity()
        .rfc8693_token_exchange(
            &env.realm_id,
            &Rfc8693Request {
                client_id: actor.clone(),
                subject_token: subject.clone(),
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
                actor_token: Some(actor_token),
                actor_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
                requested_token_type: None,
                scope: None,
                resource: None,
                audience: None,
                dpop_jkt: None,
            },
        )
        .expect("token exchange with actor_token")
        .access_token;
    assert!(is_active(&env.h, &env.realm_id, &exchanged), "precondition");

    assert_eq!(
        revoke_realm(&env, &exchanged, &subject_client, None).await,
        200
    );
    assert!(
        is_active(&env.h, &env.realm_id, &exchanged),
        "the subject token's client must not revoke the delegated token"
    );
    assert_eq!(
        revoke_realm(&env, &exchanged, &actor, Some(SECRET)).await,
        200
    );
    assert!(
        !is_active(&env.h, &env.realm_id, &exchanged),
        "the actor the delegated token was issued to revokes it"
    );
}

// ===== private_key_jwt clients authenticate with their assertion =====

const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Registers a secretless client that authenticates with `private_key_jwt`
/// (an assertion key and no `client_secret`, as a FAPI 2.0 client must be).
fn register_pkjwt(h: &common::TestHarness, realm: &RealmId) -> (ClientId, SigningKey) {
    let key = SigningKey::generate().expect("key");
    let client_id = register(h, realm, None);
    h.identity()
        .update_client(
            realm,
            &client_id,
            &UpdateClientRequest {
                assertion_public_key: Some(Some(URL_SAFE_NO_PAD.encode(key.public_key_bytes()))),
                ..Default::default()
            },
        )
        .expect("install assertion key");
    (client_id, key)
}

/// Signs a `private_key_jwt` assertion for the realm's issuer.
fn assertion(env: &Env, key: &SigningKey, client_id: &ClientId) -> String {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs(),
    )
    .expect("secs");
    let issuer = env.h.identity().oidc_discovery().issuer;
    key.issue_assertion_jwt(&JwtAssertionClaims {
        iss: client_id.as_uuid().to_string(),
        sub: client_id.as_uuid().to_string(),
        aud: Audience::single(format!("{issuer}/realms/{}", env.realm_name)),
        exp: now + 60,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        iat: Some(now),
    })
    .expect("sign assertion")
}

async fn revoke_realm_json(env: &Env, body: serde_json::Value) -> u16 {
    reqwest::Client::new()
        .post(format!("{}/realms/{}/revoke", env.base, env.realm_name))
        .json(&body)
        .send()
        .await
        .expect("request")
        .status()
        .as_u16()
}

#[tokio::test]
async fn a_private_key_jwt_client_cannot_revoke_by_client_id_alone() {
    let env = server_env().await;
    let (client, _key) = register_pkjwt(&env.h, &env.realm_id);
    let (access, _) = user_pair(&env.h, &env.realm_id, Some(&client));

    assert_eq!(
        revoke_realm(&env, &access, &client, None).await,
        401,
        "a private_key_jwt client is confidential: its public client_id alone must not authenticate"
    );
    assert_eq!(
        revoke_realm(&env, &access, &client, Some("a-made-up-secret-1!")).await,
        401,
        "a made-up secret must not stand in for the assertion"
    );
    assert!(
        is_active(&env.h, &env.realm_id, &access),
        "an unauthenticated revocation must not revoke anything"
    );
}

#[tokio::test]
async fn a_private_key_jwt_client_revokes_its_own_token_with_its_assertion() {
    let env = server_env().await;
    let (client, key) = register_pkjwt(&env.h, &env.realm_id);
    let (access, _) = user_pair(&env.h, &env.realm_id, Some(&client));
    let id = client.as_uuid().to_string();

    let stranger = SigningKey::generate().expect("key");
    let status = revoke_realm_json(
        &env,
        serde_json::json!({
            "token": access,
            "client_id": id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion(&env, &stranger, &client),
        }),
    )
    .await;
    assert_eq!(
        status, 401,
        "an assertion signed by the wrong key is refused"
    );
    assert!(is_active(&env.h, &env.realm_id, &access));

    let status = revoke_realm_json(
        &env,
        serde_json::json!({
            "token": access,
            "client_id": id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion(&env, &key, &client),
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        !is_active(&env.h, &env.realm_id, &access),
        "a valid assertion authenticates the owning client, which revokes its token"
    );
}

#[tokio::test]
async fn revoke_refuses_an_assertion_combined_with_a_secret() {
    let env = server_env().await;
    let (client, key) = register_pkjwt(&env.h, &env.realm_id);
    let (access, _) = user_pair(&env.h, &env.realm_id, Some(&client));

    let status = revoke_realm_json(
        &env,
        serde_json::json!({
            "token": access,
            "client_id": client.as_uuid().to_string(),
            "client_secret": "also-a-secret-1!",
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion(&env, &key, &client),
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "RFC 6749 §2.3: more than one client authentication method is invalid_request"
    );
    assert!(is_active(&env.h, &env.realm_id, &access));
}

#[tokio::test]
async fn grpc_revoke_refuses_a_private_key_jwt_client_by_client_id_alone() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let (client, _key) = register_pkjwt(&h, &realm);
    let (access, _) = user_pair(&h, &realm, Some(&client));
    let svc = OAuthSvc::new(grpc_state(&h));

    let err = svc
        .revoke(grpc_revoke_request(&realm, &access, &client))
        .await
        .expect_err("a private_key_jwt client_id alone must not authenticate over gRPC");
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(is_active(&h, &realm, &access));
}

#[tokio::test]
async fn discovery_advertises_private_key_jwt_for_revocation() {
    let env = server_env().await;
    for url in [
        format!("{}/.well-known/openid-configuration", env.base),
        format!(
            "{}/realms/{}/.well-known/openid-configuration",
            env.base, env.realm_name
        ),
    ] {
        let doc: serde_json::Value = reqwest::get(&url)
            .await
            .expect("request")
            .json()
            .await
            .expect("json");
        let methods: Vec<&str> = doc["revocation_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap_or_else(|| panic!("{url}: revocation auth methods must be advertised"))
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert!(
            methods.contains(&"private_key_jwt"),
            "{url}: got {methods:?}"
        );
    }
}
