//! Integration tests for the `/certs` JWKS endpoint.
//!
//! Verifies that:
//!
//! - `GET /certs` returns an RFC 7517 JWKS document.
//! - **Every published entry is `EdDSA`/`OKP`** — the only algorithm Hearth
//!   signs with. This file previously asserted the opposite, requiring an
//!   `RS256` and an `ES256` entry "for ecosystem compatibility". Hearth signed
//!   with neither: the RSA private key existed only to fill the JWKS (and was
//!   the one key family stored without the HKEY envelope), and the EC private
//!   key was regenerated on every process start, so a relying party that
//!   selected the ES256 entry cached — for `max-age=3600` — a public key whose
//!   private half no longer existed (audit 2026-08-28 §4.2#4, §4.15#5).
//! - Each entry has the field set required by its key type: `OKP`/Ed25519
//!   carries `crv` + `x` and no `n`/`e`/`y`.
//! - Aliases `/jwks` and `/.well-known/jwks.json` return identical
//!   documents.
//!
//! Asserting field-level RFC 7517 conformance here is the in-process Rust
//! equivalent of consuming the document with `jose` / `python-jose` —
//! anything that passes these checks is parseable by spec-compliant JOSE
//! libraries.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

async fn fetch_jwks(app: &axum::Router, path: &str) -> serde_json::Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "GET {path}");
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("body bytes");
    serde_json::from_slice(&body_bytes).expect("JWKS JSON")
}

#[tokio::test]
async fn certs_publishes_only_the_algorithm_hearth_signs_with() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h).await;

    let body = fetch_jwks(&app, "/certs").await;

    let keys = body["keys"].as_array().expect("keys array");
    assert!(!keys.is_empty(), "JWKS must not be empty");
    let algs: Vec<&str> = keys
        .iter()
        .map(|k| k["alg"].as_str().unwrap_or_default())
        .collect();

    assert!(
        algs.contains(&"EdDSA"),
        "JWKS must include EdDSA (the signer); got {algs:?}"
    );
    assert!(
        algs.iter().all(|a| *a == "EdDSA"),
        "JWKS must publish only algorithms Hearth signs with; got {algs:?}"
    );

    // RFC 7517 invariants: every entry has kty, kid, use="sig", alg.
    for entry in keys {
        assert!(entry["kty"].as_str().is_some(), "kty required");
        assert!(entry["kid"].as_str().is_some(), "kid required");
        assert_eq!(entry["use"].as_str(), Some("sig"), "use must be sig");
        assert!(entry["alg"].as_str().is_some(), "alg required");
    }

    // Per-algorithm field invariants.
    for entry in keys {
        assert_eq!(entry["kty"].as_str(), Some("OKP"));
        assert_eq!(entry["crv"].as_str(), Some("Ed25519"));
        let x = entry["x"].as_str().expect("OKP entry must include x");
        let decoded = URL_SAFE_NO_PAD.decode(x).expect("x is base64url");
        assert_eq!(decoded.len(), 32, "Ed25519 public key is 32 bytes");
        assert!(entry.get("y").map_or(true, |v| v.is_null()));
        assert!(entry.get("n").map_or(true, |v| v.is_null()));
        assert!(entry.get("e").map_or(true, |v| v.is_null()));
    }
}

/// HEA-1716: since HEA-1712 tokens are signed with per-realm keys, the global
/// JWKS includes the system-realm key so any client verifying tokens issued
/// under the system realm (RealmId::nil()) can find the matching key.
/// (Note: the bootstrap token is issued for the user-created dev-realm, not the
/// system realm. The canonical fix for JWKS-verifying clients is to use the
/// iss-derived realm JWKS; this test covers the system-realm inclusion as
/// defence-in-depth.)
#[tokio::test]
async fn global_jwks_includes_system_realm_signing_key() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h).await;

    // System realm is the nil UUID — mirrors identity::keys::system_realm_id()
    // which isn't re-exported from the public crate surface.
    let sys = hearth::core::RealmId::new(uuid::Uuid::nil());
    let realm_doc = h.identity().realm_jwks(&sys).expect("system realm JWKS");
    assert!(
        !realm_doc.keys.is_empty(),
        "system realm must have at least one signing key"
    );
    let sys_kid = &realm_doc.keys[0].kid;

    let global = fetch_jwks(&app, "/.well-known/jwks.json").await;
    let global_keys = global["keys"].as_array().expect("keys array");
    let found = global_keys
        .iter()
        .any(|k| k["kid"].as_str() == Some(sys_kid.as_str()));
    assert!(
        found,
        "global JWKS must contain system-realm kid '{sys_kid}' so \
         bootstrap tokens can be verified"
    );
}

#[tokio::test]
async fn jwks_aliases_return_same_document() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h).await;

    // Each route must return an identical JWKS document. Stable `kid`s
    // are critical so that an OIDC client landing on any of the three
    // mount points sees consistent verification material.
    let certs = fetch_jwks(&app, "/certs").await;
    let jwks = fetch_jwks(&app, "/jwks").await;
    let well_known = fetch_jwks(&app, "/.well-known/jwks.json").await;

    assert_eq!(certs, jwks, "/certs and /jwks must match");
    assert_eq!(
        certs, well_known,
        "/certs and /.well-known/jwks.json must match"
    );
}

#[tokio::test]
async fn jwt_kid_header_matches_a_jwks_entry() {
    use hearth::identity::{verify_token_signature, CreateUserRequest, SessionContext};

    let h = common::TestHarness::embedded().await.expect("harness");

    // A realm scope is required so the identity engine has a JWKS to
    // hand out. Using a fresh RealmId mirrors the other token tests
    // and avoids the create_realm setup overhead.
    let realm_id = h.create_realm();

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("kid-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Kid Match Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let session = h
        .identity()
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("create session");
    let pair = h
        .identity()
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");

    // Pull the JWT header `kid` out of the access token.
    let header_b64 = pair
        .access_token()
        .split('.')
        .next()
        .expect("access token has header segment");
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("decode JWT header");
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).expect("parse JWT header");
    let token_kid = header["kid"].as_str().expect("JWT must carry kid");

    // Tokens are signed with per-realm keys (HEA-1712); the global /certs endpoint
    // only carries system-realm keys. Fetch JWKS from the realm directly.
    let jwks_doc = h
        .identity()
        .realm_jwks(&realm_id)
        .expect("realm_jwks must succeed");
    let jwks = serde_json::to_value(&jwks_doc).expect("jwks to json");
    let keys = jwks["keys"].as_array().expect("keys array");

    let matched = keys
        .iter()
        .find(|j| j["kid"].as_str() == Some(token_kid))
        .unwrap_or_else(|| {
            panic!(
                "no JWKS entry with kid {token_kid}; JWKS kids = {:?}",
                keys.iter().map(|j| j["kid"].as_str()).collect::<Vec<_>>()
            )
        });

    // Cross-check: the matched entry is the EdDSA signer — the only
    // algorithm Hearth signs with, and the only one it publishes.
    assert_eq!(matched["alg"].as_str(), Some("EdDSA"));

    // The matched key should successfully verify the access token.
    let x_b64 = matched["x"].as_str().expect("Ed25519 JWK x");
    let pub_bytes = URL_SAFE_NO_PAD
        .decode(x_b64)
        .expect("decode Ed25519 pubkey");
    verify_token_signature(pair.access_token(), &pub_bytes)
        .expect("token must verify under matched JWKS entry");
}
