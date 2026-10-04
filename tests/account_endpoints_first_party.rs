#![allow(clippy::unwrap_used)]
//! GA audit 3 B-5 / D-6 / I-14 — account self-service and permission-gated
//! realm feeds judge the client the bearer token was issued to.
//!
//! - **B-5** — `GET /oauth/consents`, `DELETE /oauth/consents/{client_id}`,
//!   `GET /webauthn/credentials` and `DELETE /webauthn/credentials/{id}`
//!   accepted ANY client's access token: a third-party app the user signed in
//!   to listed the user's other apps, revoked the user's consent to them, and
//!   stripped the user's passkeys. They now require a first-party token (a
//!   third-party client may still revoke its OWN consent — "disconnect").
//! - **D-6** — removing a passkey needed no step-up, unlike enrolling one or
//!   disabling TOTP; a stolen access token stripped the phishing-resistant
//!   factor. `DELETE /webauthn/credentials/{id}` now takes the same step-up
//!   proof as enrolment.
//! - **I-14** — the session-version feed and the DCR initial-access check read
//!   `permissions` without the first-party-client gate the admin API applies,
//!   so a realm whose claim profile released permissions to third-party
//!   clients let a third-party token read the realm-wide feed and register
//!   clients.

mod common;

#[path = "common/webauthn_helper.rs"]
mod webauthn_helper;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::claims_config::{ClaimMapping, ClaimProfile, ClaimSource};
use hearth::identity::{
    CleartextPassword, ClientTrustLevel, CreateRealmRequest, CreateUserRequest, DcrPolicy,
    RealmConfig, RegisterClientRequest, RegistrationOptions, SessionContext, TokenIssuanceContext,
    UpdateUserRequest, UserStatus,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

const PASSWORD: &str = "correct-horse-battery-staple";
const RP_ID: &str = "example.com";
const ORIGIN: &str = "http://example.com";

struct Fixture {
    h: common::TestHarness,
    realm: RealmId,
    user: UserId,
    /// A first-party session token (no `client_id` claim).
    first_party: String,
    /// The consented third-party client and a token issued to it.
    third_party_client: ClientId,
    third_party: String,
}

/// A realm whose claim profile releases `permissions` to every client and
/// allows authenticated DCR, and a user holding the seeded `realm.admin`
/// role (`hearth.admin`) with a password.
async fn setup() -> Fixture {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("acct-fp-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                dcr_policy: Some(DcrPolicy::Authenticated),
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
        .expect("realm")
        .id()
        .clone();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("acct-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Account".into(),
                ..CreateUserRequest::default()
            },
        )
        .expect("user")
        .id()
        .clone();
    h.identity()
        .set_password(
            &realm,
            &user,
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("password");
    h.identity()
        .update_user(
            &realm,
            &user,
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    h.rbac().seed_realm(&realm).expect("seed realm");
    let admin = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("role lookup")
        .expect("seeded realm.admin role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.clone()),
                role_id: admin.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");
    let third_party_client = register(&h, &realm, ClientTrustLevel::ThirdParty);

    let mut f = Fixture {
        h,
        realm,
        user,
        first_party: String::new(),
        third_party_client,
        third_party: String::new(),
    };
    f.first_party = f.token(None);
    f.third_party = f.token(Some(&f.third_party_client.clone()));
    f
}

fn register(h: &common::TestHarness, realm: &RealmId, trust_level: ClientTrustLevel) -> ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: format!("app-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec!["https://app.example.com/cb".into()],
                grant_types: vec!["authorization_code".into()],
                require_consent: trust_level == ClientTrustLevel::ThirdParty,
                trust_level,
                declared_scopes: vec!["openid".into()],
                ..RegisterClientRequest::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone()
}

impl Fixture {
    fn token(&self, client: Option<&ClientId>) -> String {
        let session = self
            .h
            .identity()
            .create_session(&self.realm, &self.user, &SessionContext::default())
            .expect("session");
        self.h
            .identity()
            .issue_tokens_with_context(
                &self.realm,
                &self.user,
                session.id(),
                &TokenIssuanceContext {
                    client_id: client.cloned(),
                    ..TokenIssuanceContext::default()
                },
            )
            .expect("tokens")
            .access_token()
            .to_string()
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let app = router(Arc::new(AppState::new(
            self.h.identity_arc(),
            self.h.rbac_arc(),
            self.h.audit_arc(),
        )));
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("x-realm-id", self.realm.as_uuid().to_string());
        let body = match body {
            Some(json) => {
                req = req.header("content-type", "application/json");
                Body::from(json.to_string())
            }
            None => Body::empty(),
        };
        let resp = app.oneshot(req.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// Enrols a passkey for the user; returns its URL-safe credential id.
    fn enrol_passkey(&self) -> String {
        let authenticator = webauthn_helper::TestAuthenticator::new(RP_ID);
        let challenge = self
            .h
            .identity()
            .start_webauthn_registration(
                &self.realm,
                &self.user,
                &RegistrationOptions {
                    rp_id: RP_ID.to_string(),
                    discoverable: true,
                },
            )
            .expect("start registration");
        let (cdj, att) = authenticator.build_registration_response(&challenge, ORIGIN);
        self.h
            .identity()
            .complete_webauthn_registration(
                &self.realm,
                &self.user,
                &cdj,
                &att,
                ORIGIN,
                true,
                &Default::default(),
            )
            .expect("complete registration");
        URL_SAFE_NO_PAD.encode(&authenticator.credential_id)
    }

    fn passkey_count(&self) -> usize {
        self.h
            .identity()
            .list_webauthn_credentials(&self.realm, &self.user)
            .expect("list")
            .len()
    }

    fn has_consent(&self, client: &ClientId) -> bool {
        self.h
            .identity()
            .get_consent(&self.realm, &self.user, client)
            .expect("get consent")
            .is_some()
    }
}

fn assert_forbidden(status: StatusCode, body: &serde_json::Value, what: &str) {
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{what}: a third-party client's token must be refused; body {body}"
    );
}

// ── B-5: /oauth/consents ────────────────────────────────────────────────────

#[tokio::test]
async fn consent_listing_refuses_a_third_party_clients_token() {
    let f = setup().await;
    let (status, body) = f.call("GET", "/oauth/consents", &f.first_party, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "control: first-party token; body {body}"
    );

    let (status, body) = f.call("GET", "/oauth/consents", &f.third_party, None).await;
    assert_forbidden(status, &body, "GET /oauth/consents");
}

#[tokio::test]
async fn a_third_party_client_cannot_revoke_the_users_consent_to_another_app() {
    let f = setup().await;
    let other = register(&f.h, &f.realm, ClientTrustLevel::ThirdParty);
    f.h.identity()
        .grant_consent(&f.realm, &f.user, &other, &["openid".to_string()])
        .expect("consent");

    let uri = format!("/oauth/consents/{}", other.as_uuid());
    let (status, body) = f.call("DELETE", &uri, &f.third_party, None).await;
    assert_forbidden(status, &body, "DELETE /oauth/consents/{other}");
    assert!(
        f.has_consent(&other),
        "the other app's consent must survive"
    );

    // Control: the user's first-party token revokes it.
    let (status, body) = f.call("DELETE", &uri, &f.first_party, None).await;
    assert!(
        status.is_success(),
        "control: first-party revoke; {status} {body}"
    );
    assert!(!f.has_consent(&other));
}

/// "Disconnect this app": a third-party client may still revoke the consent
/// the user granted IT (the `examples/oauth-consent-flow` client does).
#[tokio::test]
async fn a_third_party_client_may_revoke_its_own_consent() {
    let f = setup().await;
    f.h.identity()
        .grant_consent(
            &f.realm,
            &f.user,
            &f.third_party_client,
            &["openid".to_string()],
        )
        .expect("consent");
    let uri = format!("/oauth/consents/{}", f.third_party_client.as_uuid());
    let (status, body) = f.call("DELETE", &uri, &f.third_party, None).await;
    assert!(status.is_success(), "own revoke: {status} {body}");
    assert!(!f.has_consent(&f.third_party_client));
}

// ── B-5 + D-6: /webauthn/credentials ────────────────────────────────────────

#[tokio::test]
async fn passkey_listing_refuses_a_third_party_clients_token() {
    let f = setup().await;
    f.enrol_passkey();
    let (status, body) = f
        .call("GET", "/webauthn/credentials", &f.first_party, None)
        .await;
    assert_eq!(status, StatusCode::OK, "control; body {body}");
    assert_eq!(body["credentials"].as_array().map(Vec::len), Some(1));

    let (status, body) = f
        .call("GET", "/webauthn/credentials", &f.third_party, None)
        .await;
    assert_forbidden(status, &body, "GET /webauthn/credentials");
}

/// D-6: a stolen access token alone stripped the user's passkey.
#[tokio::test]
async fn passkey_removal_requires_a_step_up() {
    let f = setup().await;
    let id = f.enrol_passkey();
    let uri = format!("/webauthn/credentials/{id}");

    let (status, body) = f.call("DELETE", &uri, &f.first_party, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an access token alone must not remove a passkey; body {body}"
    );
    assert_eq!(body["error"], "step_up_required", "body {body}");
    let (status, body) = f
        .call(
            "DELETE",
            &uri,
            &f.first_party,
            Some(serde_json::json!({"password": "not-the-password-at-all-1234"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "wrong password; body {body}");
    assert_eq!(
        f.passkey_count(),
        1,
        "the passkey must survive both attempts"
    );

    let (status, body) = f
        .call(
            "DELETE",
            &uri,
            &f.first_party,
            Some(serde_json::json!({"password": PASSWORD})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the current password removes it; body {body}"
    );
    assert_eq!(f.passkey_count(), 0);
}

#[tokio::test]
async fn passkey_removal_refuses_a_third_party_clients_token() {
    let f = setup().await;
    let id = f.enrol_passkey();
    let (status, body) = f
        .call(
            "DELETE",
            &format!("/webauthn/credentials/{id}"),
            &f.third_party,
            Some(serde_json::json!({"password": PASSWORD})),
        )
        .await;
    assert_forbidden(status, &body, "DELETE /webauthn/credentials/{id}");
    assert_eq!(f.passkey_count(), 1);
}

// ── I-14: permission-gated realm feeds ──────────────────────────────────────

#[tokio::test]
async fn session_version_feed_refuses_a_third_party_clients_token() {
    let f = setup().await;
    for uri in [
        "/oauth/session-versions?since=0",
        "/oauth/session-versions/snapshot",
    ] {
        let (status, body) = f.call("GET", uri, &f.first_party, None).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "control: a first-party admin token passes the gate on {uri}; body {body}"
        );
        let (status, body) = f.call("GET", uri, &f.third_party, None).await;
        assert_forbidden(status, &body, uri);
    }
}

#[tokio::test]
async fn dcr_initial_access_refuses_a_third_party_clients_token() {
    let f = setup().await;
    let registration = serde_json::json!({
        "client_name": "registered-by-dcr",
        "redirect_uris": ["https://dcr.example.com/cb"],
    });
    let (status, body) = f
        .call(
            "POST",
            "/register",
            &f.third_party,
            Some(registration.clone()),
        )
        .await;
    assert_forbidden(status, &body, "POST /register");

    let (status, body) = f
        .call("POST", "/register", &f.first_party, Some(registration))
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "control: first-party admin; body {body}"
    );
}

// ── Round 3: passkey enrolment is first-party only too ─────────────────────

/// Enrolling a passkey added a credential to the user's account with a
/// third-party app's token (the step-up still asked for the password, but a
/// third-party app has no business driving the ceremony at all).
#[tokio::test]
async fn passkey_enrolment_refuses_a_third_party_clients_token() {
    let f = setup().await;
    let proof = serde_json::json!({"password": PASSWORD});

    let (status, body) = f
        .call(
            "POST",
            "/webauthn/register/begin",
            &f.first_party,
            Some(proof.clone()),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "control: first-party enrolment; body {body}"
    );

    let (status, body) = f
        .call(
            "POST",
            "/webauthn/register/begin",
            &f.third_party,
            Some(proof),
        )
        .await;
    assert_forbidden(status, &body, "POST /webauthn/register/begin");

    let (status, body) = f
        .call(
            "POST",
            "/webauthn/register/complete",
            &f.third_party,
            Some(serde_json::json!({
                "client_data_json": "e30",
                "attestation_object": "oA",
                "origin": ORIGIN,
            })),
        )
        .await;
    assert_forbidden(status, &body, "POST /webauthn/register/complete");
    assert_eq!(f.passkey_count(), 0, "no credential may be added");
}
