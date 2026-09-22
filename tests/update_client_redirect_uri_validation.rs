//! §4.3#3 (task 22.1) — `update_client` must re-validate redirect URIs.
//!
//! `register_client` runs every redirect URI through
//! `identity::validation::validate_redirect_uri`, which rejects a fragment
//! component (RFC 6749 §3.1.2), a wildcard, a dangerous scheme, and a
//! non-loopback `http://` host (RFC 8252 §8.3). `update_client` — the engine
//! call behind `PATCH /admin/applications/{id}` and the gRPC/web equivalents —
//! wrote the new list straight onto the record, so every one of those rules was
//! bypassable by register-then-PATCH.
//!
//! These tests drive the engine API directly because that is the single seam
//! all three protocol surfaces funnel through.

#![allow(clippy::unwrap_used)]

mod common;

use hearth::core::RealmId;
use hearth::identity::{CreateRealmRequest, RegisterClientRequest, UpdateClientRequest};

const GOOD_URI: &str = "https://app.example.com/cb";

fn realm(h: &common::TestHarness) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("upd-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap()
        .id()
        .clone()
}

fn register(h: &common::TestHarness, realm_id: &RealmId) -> hearth::identity::OAuthClient {
    h.identity()
        .register_client(
            realm_id,
            &RegisterClientRequest {
                client_name: format!("upd-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec![GOOD_URI.to_string()],
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .unwrap()
}

/// Attempts a redirect-URI-only update and returns the engine result.
fn patch_redirects(
    h: &common::TestHarness,
    realm_id: &RealmId,
    client: &hearth::identity::OAuthClient,
    uris: &[&str],
) -> Result<hearth::identity::OAuthClient, hearth::identity::IdentityError> {
    h.identity().update_client(
        realm_id,
        client.client_id(),
        &UpdateClientRequest {
            redirect_uris: Some(uris.iter().map(|s| (*s).to_string()).collect()),
            ..Default::default()
        },
    )
}

/// The headline bypass from the audit: a client registered with a compliant
/// `https` URI is PATCHed to a plain-`http`, non-loopback URI carrying a
/// fragment. Registration refuses this string twice over; the update must too.
#[tokio::test]
async fn update_client_rejects_http_non_loopback_uri_with_fragment() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm_id = realm(&h);
    let client = register(&h, &realm_id);

    let err = patch_redirects(&h, &realm_id, &client, &["http://evil.example/#frag"])
        .expect_err("PATCH to http://evil.example/#frag must be refused");
    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidInput { .. }),
        "expected InvalidInput, got {err:?}"
    );

    // The stored record must be untouched.
    let stored = h
        .identity()
        .get_client(&realm_id, client.client_id())
        .unwrap()
        .expect("client still exists");
    assert_eq!(stored.redirect_uris(), &[GOOD_URI.to_string()]);
}

/// Each register-time rule, exercised one at a time so a partial fix cannot
/// pass by accident.
#[tokio::test]
async fn update_client_enforces_every_register_time_redirect_rule() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm_id = realm(&h);
    let client = register(&h, &realm_id);

    for bad in [
        // RFC 6749 §3.1.2 — no fragment component.
        "https://app.example.com/cb#frag",
        // Wildcards are never valid in a registered redirect URI.
        "https://*.example.com/cb",
        // RFC 8252 §8.3 — http is loopback-only.
        "http://evil.example/cb",
        // Dangerous schemes.
        "javascript://app.example.com/cb",
        "data://app.example.com/cb",
        // No scheme at all.
        "app.example.com/cb",
    ] {
        let result = patch_redirects(&h, &realm_id, &client, &[bad]);
        assert!(
            result.is_err(),
            "update_client accepted redirect URI {bad:?}"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, hearth::identity::IdentityError::InvalidInput { .. }),
            "expected InvalidInput for {bad:?}, got {err:?}"
        );
    }

    // A second, valid URI alongside a bad one must not smuggle the bad one in.
    let err = patch_redirects(
        &h,
        &realm_id,
        &client,
        &[GOOD_URI, "https://app.example.com/cb#frag"],
    )
    .expect_err("a bad URI in a mixed list must be refused");
    assert!(matches!(
        err,
        hearth::identity::IdentityError::InvalidInput { .. }
    ));
}

/// Fence: the rules must not have become so strict that a legitimate update
/// is refused. Loopback http and RFC 8252 native deep links stay valid.
#[tokio::test]
async fn update_client_still_accepts_valid_redirect_uris() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm_id = realm(&h);
    let client = register(&h, &realm_id);

    let updated = patch_redirects(
        &h,
        &realm_id,
        &client,
        &[
            "https://app.example.com/cb2",
            "http://127.0.0.1:9000/cb",
            "http://localhost:9000/cb",
            "com.example.myapp://oauth/cb",
        ],
    )
    .expect("valid redirect URIs must still be accepted");
    assert_eq!(updated.redirect_uris().len(), 4);
}
