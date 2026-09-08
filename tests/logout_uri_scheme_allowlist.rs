//! Scheme allowlist for the client logout URIs (production-readiness task 12.1,
//! audit §4.3#1).
//!
//! `frontchannel_logout_uri` is rendered into an `<iframe src>` on the Hearth
//! origin by `GET /end_session`. A `javascript:` URI there executes script on
//! the identity-provider origin, so the value must never reach the page.
//! `backchannel_logout_uri` is dereferenced server-side, so it is held to the
//! same scheme rules.
//!
//! The threat model is an untrusted tenant admin: whoever can update a client
//! must not be able to choose the scheme Hearth emits or fetches.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    CreateRealmRequest, OAuthClient, RegisterClientRequest, UpdateClientRequest,
};

/// URIs that must be refused on both logout fields.
const REFUSED: &[&str] = &[
    "javascript:alert(document.domain)",
    "JavaScript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    // A native-app deep link is fine as a redirect URI but not as a URI the
    // identity provider itself frames or fetches.
    "com.example.app://logout",
    // Fragments and wildcards are rejected as they are for redirect URIs.
    "https://app.example.com/logout#frag",
    "https://*.example.com/logout",
    // Plain http is only permitted on loopback.
    "http://app.example.com/logout",
    // No scheme at all.
    "/logout",
];

/// URIs that must keep working on the front channel. Loopback `http` stays
/// usable there because the browser, not Hearth, fetches it.
const FRONTCHANNEL_ACCEPTED: &[&str] = &[
    "https://app.example.com/logout",
    "http://localhost:3000/logout",
    "http://127.0.0.1:3000/logout",
];

/// The back channel is `https` only — Hearth dereferences it itself, and the
/// SSRF guard refuses loopback at delivery time regardless.
const BACKCHANNEL_ACCEPTED: &[&str] = &["https://app.example.com/logout"];

/// Loopback `http` is a front-channel-only allowance.
const BACKCHANNEL_ALSO_REFUSED: &[&str] = &[
    "http://localhost:3000/logout",
    "http://127.0.0.1:3000/logout",
];

async fn setup() -> (common::TestHarness, RealmId, OAuthClient) {
    let harness = common::TestHarness::embedded()
        .await
        .expect("embedded harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("logout-uri-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let client = harness
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Logout URI App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");
    let realm_id = realm.id().clone();
    (harness, realm_id, client)
}

#[tokio::test]
async fn frontchannel_logout_uri_refuses_disallowed_schemes() {
    let (harness, realm_id, client) = setup().await;
    for uri in REFUSED {
        let result = harness.identity().update_client(
            &realm_id,
            client.client_id(),
            &UpdateClientRequest {
                frontchannel_logout_uri: Some(Some((*uri).to_string())),
                ..Default::default()
            },
        );
        assert!(
            result.is_err(),
            "frontchannel_logout_uri accepted the disallowed URI {uri:?}"
        );
    }
}

#[tokio::test]
async fn backchannel_logout_uri_refuses_disallowed_schemes() {
    let (harness, realm_id, client) = setup().await;
    for uri in REFUSED.iter().chain(BACKCHANNEL_ALSO_REFUSED) {
        let result = harness.identity().update_client(
            &realm_id,
            client.client_id(),
            &UpdateClientRequest {
                backchannel_logout_uri: Some(Some((*uri).to_string())),
                ..Default::default()
            },
        );
        assert!(
            result.is_err(),
            "backchannel_logout_uri accepted the disallowed URI {uri:?}"
        );
    }
}

#[tokio::test]
async fn frontchannel_logout_uri_accepts_https_and_loopback_http() {
    let (harness, realm_id, client) = setup().await;
    for uri in FRONTCHANNEL_ACCEPTED {
        let updated = harness
            .identity()
            .update_client(
                &realm_id,
                client.client_id(),
                &UpdateClientRequest {
                    frontchannel_logout_uri: Some(Some((*uri).to_string())),
                    ..Default::default()
                },
            )
            .unwrap_or_else(|e| panic!("update_client refused the allowed URI {uri:?}: {e}"));
        assert_eq!(updated.frontchannel_logout_uri(), Some(*uri));
    }
}

#[tokio::test]
async fn backchannel_logout_uri_accepts_https() {
    let (harness, realm_id, client) = setup().await;
    for uri in BACKCHANNEL_ACCEPTED {
        let updated = harness
            .identity()
            .update_client(
                &realm_id,
                client.client_id(),
                &UpdateClientRequest {
                    backchannel_logout_uri: Some(Some((*uri).to_string())),
                    ..Default::default()
                },
            )
            .unwrap_or_else(|e| panic!("update_client refused the allowed URI {uri:?}: {e}"));
        assert_eq!(updated.backchannel_logout_uri(), Some(*uri));
    }
}

/// Clearing the field must stay possible — `Some(None)` is a delete, not a URI.
#[tokio::test]
async fn logout_uris_can_be_cleared() {
    let (harness, realm_id, client) = setup().await;
    harness
        .identity()
        .update_client(
            &realm_id,
            client.client_id(),
            &UpdateClientRequest {
                frontchannel_logout_uri: Some(Some("https://app.example.com/lo".to_string())),
                ..Default::default()
            },
        )
        .expect("set");
    let cleared = harness
        .identity()
        .update_client(
            &realm_id,
            client.client_id(),
            &UpdateClientRequest {
                frontchannel_logout_uri: Some(None),
                ..Default::default()
            },
        )
        .expect("clear");
    assert_eq!(cleared.frontchannel_logout_uri(), None);
}
