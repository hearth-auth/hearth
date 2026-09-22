//! `POST /realms/{realm}/introspect` and `/revoke` must require client
//! authentication and the RFC 7662 audience restriction, exactly like their
//! header-form twins (audit 2026-08-28 §4.1#3, §4.19#2, §4.22#1, §4.25#1).
//!
//! Before the fix the realm-scoped routes read no client credentials at all:
//! an anonymous internet caller got `active: true` with the subject from
//! introspect, and could destroy a session through revoke. The introspect
//! response also omitted `active` on the negative answer (§4.1#4) because it
//! serialized through proto3, which drops `false` defaults.

mod common;

use hearth::core::RealmId;
use hearth::identity::{ClientCredentialsRequest, CreateRealmRequest, RegisterClientRequest};

const CLIENT_SECRET: &str = "realm-introspect-secret-1!";

/// Creates a realm and returns `(name, id)`.
fn make_realm(h: &common::TestHarness) -> (String, RealmId) {
    let name = format!("intro-auth-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: name.clone(),
            config: None,
        })
        .expect("create realm");
    (name, realm.id().clone())
}

/// Registers a confidential client and returns its ID string.
fn register_client(h: &common::TestHarness, realm: &RealmId, name: &str) -> String {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: name.to_string(),
                redirect_uris: vec![],
                client_secret: Some(CLIENT_SECRET.to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client")
        .client_id()
        .as_uuid()
        .to_string()
}

/// Mints a client-credentials access token for `client_id`.
fn mint_token(h: &common::TestHarness, realm: &RealmId, client_id: &str) -> String {
    h.identity()
        .client_credentials_token(
            realm,
            &ClientCredentialsRequest {
                client_id: hearth::core::ClientId::new(client_id.parse().expect("uuid")),
                client_secret: Some(CLIENT_SECRET.to_string()),
                scope: Some("read".to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("mint token")
        .access_token()
        .to_string()
}

/// An anonymous introspection must be refused — not answer `active: true`
/// with the subject.
#[tokio::test]
async fn realm_introspect_refuses_anonymous_caller() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (realm_name, realm_id) = make_realm(&h);
    let client_id = register_client(&h, &realm_id, "Anon Introspect Victim");
    let token = mint_token(&h, &realm_id, &client_id);

    let resp = reqwest::Client::new()
        .post(format!("{base}/realms/{realm_name}/introspect"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status().as_u16(),
        401,
        "anonymous introspection must be refused (audit §4.1#3)"
    );
}

/// An anonymous revocation must be refused, and the token must stay valid.
#[tokio::test]
async fn realm_revoke_refuses_anonymous_caller() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (realm_name, realm_id) = make_realm(&h);
    let client_id = register_client(&h, &realm_id, "Anon Revoke Victim");
    let token = mint_token(&h, &realm_id, &client_id);

    let resp = reqwest::Client::new()
        .post(format!("{base}/realms/{realm_name}/revoke"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "anonymous revocation must be refused (audit §4.1#3)"
    );

    // The token must have survived the anonymous attempt.
    let introspect = h
        .identity()
        .introspect_token(
            &realm_id,
            &hearth::identity::TokenIntrospectionRequest {
                token,
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .expect("introspect");
    assert!(
        introspect.active,
        "an anonymous caller must not be able to revoke a token"
    );
}

/// The authenticated owner can introspect its own token, and the negative
/// response carries an explicit `active: false` (RFC 7662 §2.2, audit §4.1#4).
#[tokio::test]
async fn realm_introspect_authenticated_owner_and_explicit_negative() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (realm_name, realm_id) = make_realm(&h);
    let client_id = register_client(&h, &realm_id, "Owner Client");
    let token = mint_token(&h, &realm_id, &client_id);
    let http = reqwest::Client::new();

    let positive: serde_json::Value = http
        .post(format!("{base}/realms/{realm_name}/introspect"))
        .json(&serde_json::json!({
            "token": token,
            "client_id": client_id,
            "client_secret": CLIENT_SECRET,
        }))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        positive["active"],
        serde_json::Value::Bool(true),
        "owner must introspect its own live token as active, got {positive}"
    );

    let negative: serde_json::Value = http
        .post(format!("{base}/realms/{realm_name}/introspect"))
        .json(&serde_json::json!({
            "token": "not-a-real-token",
            "client_id": client_id,
            "client_secret": CLIENT_SECRET,
        }))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        negative["active"],
        serde_json::Value::Bool(false),
        "the negative response must carry an explicit active:false \
         (RFC 7662 §2.2, audit §4.1#4), got {negative}"
    );
}

/// RFC 7662 §2 audience restriction: client B may not introspect a
/// machine-to-machine token minted for client A.
#[tokio::test]
async fn realm_introspect_enforces_audience_restriction() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (realm_name, realm_id) = make_realm(&h);
    let client_a = register_client(&h, &realm_id, "Client A");
    let client_b = register_client(&h, &realm_id, "Client B");
    let token_a = mint_token(&h, &realm_id, &client_a);

    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/realms/{realm_name}/introspect"))
        .json(&serde_json::json!({
            "token": token_a,
            "client_id": client_b,
            "client_secret": CLIENT_SECRET,
        }))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        body["active"],
        serde_json::Value::Bool(false),
        "client B must not introspect client A's M2M token \
         (RFC 7662 §2 audience restriction), got {body}"
    );
}
