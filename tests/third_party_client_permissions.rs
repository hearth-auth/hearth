#![allow(clippy::unwrap_used)]
//! GA audit 2026-09-28 B1 — a third-party client must never receive the
//! user's RBAC permissions, on any grant.
//!
//! The default claim profile marks `permissions` as `first_party_only`, so
//! `apply_claim_profile` returns an empty list for a third-party client. The
//! authorization-code exchange honoured that. The refresh grant and the device
//! grant then fell back to the user's full permission set whenever the
//! filtered list was empty (`if permissions.is_empty() { perm_strs }`), so the
//! first refresh handed a third-party app everything the user held — up to
//! `hearth.admin` — and that token passed the admin API gate.
//!
//! The access token also named no client, so the admin API could not tell a
//! token held by a third-party app from the user's own session token. Access
//! tokens issued for a client now carry the RFC 9068 §2.2 `client_id` claim,
//! and the admin API refuses a token whose client is not first-party.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::claims_config::{ClaimMapping, ClaimProfile, ClaimSource};
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, DeviceAuthorizationRequest, RealmConfig, RegisterClientRequest,
    TokenExchangeRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://tp.example.com/cb";
const VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

fn pkce_challenge() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, VERIFIER.as_bytes()).as_ref())
}

fn decode_claims_json(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("JWT payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("claims JSON")
}

fn create_user(h: &common::TestHarness, realm: &RealmId) -> hearth::identity::User {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Third Party Subject".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .expect("create user")
}

/// Grants `user` a custom role carrying `docs.view` + `docs.edit`.
fn grant_docs_role(h: &common::TestHarness, realm: &RealmId, user: &UserId) {
    let role = h
        .rbac()
        .create_role(
            realm,
            &CreateRoleRequest {
                name: "docs.editor".into(),
                description: None,
                permissions: vec![
                    Permission::new("docs.view").unwrap(),
                    Permission::new("docs.edit").unwrap(),
                ],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("create role");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
}

/// Grants `user` the seeded `realm.admin` role (which carries admin
/// permissions the admin API gate accepts).
fn grant_realm_admin(h: &common::TestHarness, realm: &RealmId, user: &UserId) {
    h.rbac().seed_realm(realm).expect("seed realm");
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("role lookup")
        .expect("seeded realm.admin role");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
}

fn register(
    h: &common::TestHarness,
    realm: &RealmId,
    trust_level: ClientTrustLevel,
    grant_types: &[&str],
) -> ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "tp-app".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                grant_types: grant_types.iter().map(|g| (*g).to_string()).collect(),
                require_consent: trust_level != ClientTrustLevel::FirstParty,
                trust_level,
                ..Default::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone()
}

/// Runs the authorization-code grant and returns `(access, refresh)`.
fn code_grant(
    h: &common::TestHarness,
    realm: &RealmId,
    client: &ClientId,
    user: &UserId,
) -> (String, String) {
    let auth = h
        .identity()
        .authorize(
            realm,
            &AuthorizationRequest {
                client_id: client.clone(),
                redirect_uri: REDIRECT_URI.into(),
                scope: "openid".into(),
                state: "s".into(),
                response_type: "code".into(),
                user_id: user.clone(),
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
            },
        )
        .expect("authorize");
    let pair = h
        .identity()
        .exchange_authorization_code(
            realm,
            &TokenExchangeRequest {
                client_id: client.clone(),
                code: auth.code().to_string(),
                redirect_uri: REDIRECT_URI.into(),
                code_verifier: Some(VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange");
    (
        pair.access_token().to_string(),
        pair.refresh_token().to_string(),
    )
}

fn device_grant(
    h: &common::TestHarness,
    realm: &RealmId,
    client: &ClientId,
    user: &UserId,
) -> String {
    let started = h
        .identity()
        .device_authorize(
            realm,
            &DeviceAuthorizationRequest {
                client_id: client.clone(),
                scope: Some("openid".into()),
            },
        )
        .expect("device_authorize");
    h.identity()
        .approve_device(realm, &started.user_code, user)
        .expect("approve device");
    h.identity()
        .poll_device_token(realm, &started.device_code, client, None)
        .expect("poll device token")
        .access_token()
        .to_string()
}

#[tokio::test]
async fn third_party_refresh_token_carries_no_permissions() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let user = create_user(&h, &realm);
    grant_docs_role(&h, &realm, user.id());
    let client = register(
        &h,
        &realm,
        ClientTrustLevel::ThirdParty,
        &["authorization_code", "refresh_token"],
    );

    let (access, refresh) = code_grant(&h, &realm, &client, user.id());
    let first = h.identity().validate_token(&realm, &access).expect("v1");
    assert!(
        first.permissions.is_empty(),
        "control: the code exchange already withholds permissions from a \
         third-party client; got {:?}",
        first.permissions
    );

    let refreshed = h
        .identity()
        .refresh_tokens(&realm, &refresh, None, None)
        .expect("refresh");
    let second = h
        .identity()
        .validate_token(&realm, refreshed.access_token())
        .expect("v2");
    assert!(
        second.permissions.is_empty(),
        "a third-party client's refreshed access token must not carry the \
         user's permissions; got {:?}",
        second.permissions
    );
}

#[tokio::test]
async fn third_party_device_token_carries_no_permissions() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let user = create_user(&h, &realm);
    grant_docs_role(&h, &realm, user.id());
    let client = register(&h, &realm, ClientTrustLevel::ThirdParty, &[DEVICE_GRANT]);

    let access = device_grant(&h, &realm, &client, user.id());
    let claims = h.identity().validate_token(&realm, &access).expect("valid");
    assert!(
        claims.permissions.is_empty(),
        "a third-party client's device-grant access token must not carry the \
         user's permissions; got {:?}",
        claims.permissions
    );
}

/// Control: the fix must not strip permissions from first-party clients.
#[tokio::test]
async fn first_party_refresh_and_device_tokens_keep_permissions() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let user = create_user(&h, &realm);
    grant_docs_role(&h, &realm, user.id());
    let code_client = register(
        &h,
        &realm,
        ClientTrustLevel::FirstParty,
        &["authorization_code", "refresh_token"],
    );
    let device_client = register(&h, &realm, ClientTrustLevel::FirstParty, &[DEVICE_GRANT]);

    let (_, refresh) = code_grant(&h, &realm, &code_client, user.id());
    let refreshed = h
        .identity()
        .refresh_tokens(&realm, &refresh, None, None)
        .expect("refresh");
    let refreshed = h
        .identity()
        .validate_token(&realm, refreshed.access_token())
        .expect("valid");
    let device = device_grant(&h, &realm, &device_client, user.id());
    let device = h.identity().validate_token(&realm, &device).expect("valid");

    for (what, perms) in [
        ("refresh", &refreshed.permissions),
        ("device", &device.permissions),
    ] {
        assert!(
            perms.iter().any(|p| p == "docs.view") && perms.iter().any(|p| p == "docs.edit"),
            "a first-party {what} token must keep the user's permissions; got {perms:?}"
        );
    }
}

/// Every access token minted for a client names that client (RFC 9068 §2.2
/// `client_id`), on the code, refresh and device grants alike.
#[tokio::test]
async fn access_tokens_name_the_client_they_were_issued_to() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let user = create_user(&h, &realm);
    let code_client = register(
        &h,
        &realm,
        ClientTrustLevel::ThirdParty,
        &["authorization_code", "refresh_token"],
    );
    let device_client = register(&h, &realm, ClientTrustLevel::ThirdParty, &[DEVICE_GRANT]);

    let (access, refresh) = code_grant(&h, &realm, &code_client, user.id());
    let refreshed = h
        .identity()
        .refresh_tokens(&realm, &refresh, None, None)
        .expect("refresh")
        .access_token()
        .to_string();
    let device = device_grant(&h, &realm, &device_client, user.id());

    let code_cid = code_client.as_uuid().to_string();
    let device_cid = device_client.as_uuid().to_string();
    for (what, token, expected) in [
        ("code exchange", &access, &code_cid),
        ("refresh", &refreshed, &code_cid),
        ("device", &device, &device_cid),
    ] {
        let claims = decode_claims_json(token);
        assert_eq!(
            claims["client_id"].as_str(),
            Some(expected.as_str()),
            "the {what} access token must carry client_id; got {claims}"
        );
    }
}

/// A realm whose claim profile deliberately releases `permissions` to every
/// client — the defence-in-depth case: even when a third-party token does
/// carry admin permissions, the admin API must refuse it.
fn realm_releasing_permissions_to_everyone(h: &common::TestHarness) -> RealmId {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("tp-admin-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                claim_profile: Some(ClaimProfile {
                    mappings: vec![ClaimMapping {
                        claim: "permissions".into(),
                        source: ClaimSource::EffectivePermissions,
                        include_in_access_token: true,
                        include_in_id_token: false,
                        include_in_userinfo: false,
                        first_party_only: false,
                        required_scopes: None,
                        allowed_clients: None,
                    }],
                    updated_at: None,
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    realm.id().clone()
}

async fn get_admin_users(h: &common::TestHarness, realm: &RealmId, token: &str) -> StatusCode {
    let app = router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri("/admin/users")
            .header("authorization", format!("Bearer {token}"))
            .header("x-realm-id", realm.as_uuid().to_string())
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

#[tokio::test]
async fn admin_api_refuses_a_token_held_by_a_third_party_client() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm_releasing_permissions_to_everyone(&h);
    let user = create_user(&h, &realm);
    grant_realm_admin(&h, &realm, user.id());

    let third = register(
        &h,
        &realm,
        ClientTrustLevel::ThirdParty,
        &["authorization_code", "refresh_token"],
    );
    let (tp_access, _) = code_grant(&h, &realm, &third, user.id());
    let tp_claims = h.identity().validate_token(&realm, &tp_access).expect("v");
    assert!(
        !tp_claims.permissions.is_empty(),
        "precondition: this realm's profile releases permissions to third \
         parties, so the admin gate is the only thing left to refuse the token"
    );
    assert_eq!(
        get_admin_users(&h, &realm, &tp_access).await,
        StatusCode::FORBIDDEN,
        "the admin API must refuse a token issued to a third-party client, \
         whatever permissions it carries"
    );

    // Control: the same user through a first-party client is admitted.
    let first = register(
        &h,
        &realm,
        ClientTrustLevel::FirstParty,
        &["authorization_code", "refresh_token"],
    );
    let (fp_access, _) = code_grant(&h, &realm, &first, user.id());
    assert_eq!(
        get_admin_users(&h, &realm, &fp_access).await,
        StatusCode::OK,
        "a first-party client's token for an admin must still reach the admin API"
    );
}
