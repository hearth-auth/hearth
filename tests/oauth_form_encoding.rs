//! Conformance tests: OAuth endpoints MUST accept `application/x-www-form-urlencoded`
//! request bodies (HEA-2077).
//!
//! RFC 6749 §4.1.3 (token), RFC 7009 §2.1 (revocation), and RFC 7662 §2.1
//! (introspection) all mandate that clients POST a form-encoded body. Before
//! HEA-2077 every OAuth endpoint extracted with a bare `Json<...>`, so a
//! spec-compliant client or off-the-shelf library got `415 Unsupported Media
//! Type`. These tests drive each endpoint over real HTTP with a form body and
//! assert the server no longer rejects it — while keeping the legacy JSON path
//! working (backward-compat regression guard).
//!
//! TDD: written before the `JsonOrForm` extractor was wired into
//! `src/protocol/http/oauth.rs`.

mod common;

use hearth::identity::CreateRealmRequest;

const FORM: &str = "application/x-www-form-urlencoded";

/// Creates an isolated realm and returns its (unique) name for path routing.
fn make_realm(harness: &common::TestHarness) -> String {
    let name = format!("form-conformance-{}", uuid::Uuid::new_v4());
    harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: name.clone(),
            config: None,
        })
        .expect("create realm");
    name
}

/// RFC 7009 §2.1 — `POST /realms/{realm}/revoke` MUST accept a form body.
/// An unknown token yields 200 per RFC 7009 (no information leakage), so a
/// form body carrying a bogus token proves the endpoint parses the form
/// (previously 415).
#[tokio::test]
async fn realm_revoke_accepts_form_encoded_body() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let realm = make_realm(&h);
    let client = reqwest::Client::new();

    let status = client
        .post(format!("{base}/realms/{realm}/revoke"))
        .header("Content-Type", FORM)
        .body("token=not-a-real-token&token_type_hint=access_token")
        .send()
        .await
        .expect("form revoke request")
        .status()
        .as_u16();

    assert_eq!(
        status, 200,
        "RFC 7009 form-encoded revoke must be accepted (200), got {status}"
    );

    // Backward-compat: JSON must still work.
    let json_status = client
        .post(format!("{base}/realms/{realm}/revoke"))
        .json(&serde_json::json!({"token": "not-a-real-token"}))
        .send()
        .await
        .expect("json revoke request")
        .status()
        .as_u16();
    assert_eq!(
        json_status, 200,
        "JSON revoke must still work, got {json_status}"
    );
}

/// RFC 7662 §2.1 — `POST /realms/{realm}/introspect` MUST accept a form body.
/// An unknown token yields 200 with `active: false` per RFC 7662 §2.2.
#[tokio::test]
async fn realm_introspect_accepts_form_encoded_body() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let realm = make_realm(&h);
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/realms/{realm}/introspect"))
        .header("Content-Type", FORM)
        .body("token=not-a-real-token")
        .send()
        .await
        .expect("form introspect request");
    let status = resp.status().as_u16();
    assert_eq!(
        status, 200,
        "RFC 7662 form-encoded introspect must be accepted (200), got {status}"
    );
    let body: serde_json::Value = resp.json().await.expect("introspect JSON");
    // RFC 7662 §2.2 — an unknown token is not active. (The realm handler
    // serializes via proto3, which omits the `false` default, so `active` may be
    // absent rather than literally `false`; either way it must not be `true`.)
    assert_ne!(
        body["active"],
        serde_json::Value::Bool(true),
        "unknown token must not report active:true, got {body}"
    );

    // Backward-compat: JSON must still work.
    let json_status = client
        .post(format!("{base}/realms/{realm}/introspect"))
        .json(&serde_json::json!({"token": "not-a-real-token"}))
        .send()
        .await
        .expect("json introspect request")
        .status()
        .as_u16();
    assert_eq!(
        json_status, 200,
        "JSON introspect must still work, got {json_status}"
    );
}

/// RFC 6749 §4.1.3 — `POST /realms/{realm}/token` MUST accept a form body.
/// Bogus credentials produce a 4xx OAuth error, but crucially NOT 415: reaching
/// the grant-type dispatch proves the form body was parsed.
#[tokio::test]
async fn realm_token_accepts_form_encoded_body() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let realm = make_realm(&h);
    let client = reqwest::Client::new();

    let client_id = uuid::Uuid::new_v4();
    let status = client
        .post(format!("{base}/realms/{realm}/token"))
        .header("Content-Type", FORM)
        .body(format!(
            "grant_type=refresh_token&client_id={client_id}&refresh_token=bogus"
        ))
        .send()
        .await
        .expect("form token request")
        .status()
        .as_u16();

    assert_ne!(
        status, 415,
        "form-encoded token request must not be rejected as Unsupported Media Type"
    );
}

/// The global (header-routed) endpoints share the same extractor; a form body
/// with `X-Realm-ID` must clear the 415 gate on `/token`, `/revoke`, and
/// `/introspect`.
#[tokio::test]
async fn global_endpoints_accept_form_encoded_body() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let realm = make_realm(&h);
    let realm_id = h
        .identity()
        .get_realm_by_name(&realm)
        .expect("get realm by name")
        .expect("realm exists")
        .id()
        .as_uuid()
        .to_string();
    let client = reqwest::Client::new();

    let client_id = uuid::Uuid::new_v4();
    for (path, body) in [
        (
            "/token",
            format!("grant_type=refresh_token&client_id={client_id}&refresh_token=bogus"),
        ),
        ("/revoke", format!("token=bogus&client_id={client_id}")),
        ("/introspect", format!("token=bogus&client_id={client_id}")),
    ] {
        let status = client
            .post(format!("{base}{path}"))
            .header("Content-Type", FORM)
            .header("X-Realm-ID", &realm_id)
            .body(body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("form request to {path}: {e}"))
            .status()
            .as_u16();
        assert_ne!(
            status, 415,
            "form-encoded request to {path} must not be rejected as Unsupported Media Type (got {status})"
        );
    }
}

/// RFC 9126 §2.1 — the Pushed Authorization Request endpoint MUST accept a
/// form-encoded body (that is the *only* encoding the RFC defines). Bogus
/// parameters yield a 4xx OAuth error, but reaching the PAR handler (not 415)
/// proves the form body parsed. Covers both the header-routed and realm-scoped
/// twins.
#[tokio::test]
async fn par_accepts_form_encoded_body() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let realm = make_realm(&h);
    let realm_id = h
        .identity()
        .get_realm_by_name(&realm)
        .expect("get realm by name")
        .expect("realm exists")
        .id()
        .as_uuid()
        .to_string();
    let client = reqwest::Client::new();
    let client_id = uuid::Uuid::new_v4();
    let form_body =
        format!("client_id={client_id}&response_type=code&redirect_uri=https://app.example/cb");

    // Realm-scoped twin.
    let realm_status = client
        .post(format!("{base}/realms/{realm}/as/par"))
        .header("Content-Type", FORM)
        .body(form_body.clone())
        .send()
        .await
        .expect("form PAR request (realm)")
        .status()
        .as_u16();
    assert_ne!(
        realm_status, 415,
        "form-encoded PAR (realm) must not be 415, got {realm_status}"
    );

    // Header-routed twin.
    let hdr_status = client
        .post(format!("{base}/as/par"))
        .header("Content-Type", FORM)
        .header("X-Realm-ID", &realm_id)
        .body(form_body)
        .send()
        .await
        .expect("form PAR request (header)")
        .status()
        .as_u16();
    assert_ne!(
        hdr_status, 415,
        "form-encoded PAR (header) must not be 415, got {hdr_status}"
    );
}

/// RFC 8628 §3.1 — the Device Authorization endpoint MUST accept a form-encoded
/// body. Covers both the header-routed and realm-scoped twins.
#[tokio::test]
async fn device_authorization_accepts_form_encoded_body() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let realm = make_realm(&h);
    let realm_id = h
        .identity()
        .get_realm_by_name(&realm)
        .expect("get realm by name")
        .expect("realm exists")
        .id()
        .as_uuid()
        .to_string();
    let client = reqwest::Client::new();
    let client_id = uuid::Uuid::new_v4();

    // Realm-scoped twin.
    let realm_status = client
        .post(format!("{base}/realms/{realm}/device_authorization"))
        .header("Content-Type", FORM)
        .body(format!("client_id={client_id}&scope=openid"))
        .send()
        .await
        .expect("form device_authorization request (realm)")
        .status()
        .as_u16();
    assert_ne!(
        realm_status, 415,
        "form-encoded device_authorization (realm) must not be 415, got {realm_status}"
    );

    // Header-routed twin.
    let hdr_status = client
        .post(format!("{base}/device_authorization"))
        .header("Content-Type", FORM)
        .header("X-Realm-ID", &realm_id)
        .body(format!("client_id={client_id}&scope=openid"))
        .send()
        .await
        .expect("form device_authorization request (header)")
        .status()
        .as_u16();
    assert_ne!(
        hdr_status, 415,
        "form-encoded device_authorization (header) must not be 415, got {hdr_status}"
    );
}
