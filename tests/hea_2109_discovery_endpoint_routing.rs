//! HEA-2109 (HEA-2105/C) — the served OIDC discovery document MUST advertise
//! endpoint paths that the router actually serves.
//!
//! Two regressions this suite pins:
//!
//!  1. `authorization_endpoint` (`{issuer}/authorize`) was registered POST-only,
//!     so a conformant RP following discovery and redirecting a browser to it via
//!     GET received a **405 Method Not Allowed** instead of a redirect into the
//!     interactive login/consent UI.
//!  2. `device_authorization_endpoint` advertised `{issuer}/device/authorize`,
//!     but the router only serves `/device_authorization` — every device-grant
//!     client following discovery got a **404**.
//!
//! Both tests read the endpoint path *out of the served discovery document* (not
//! a hard-coded constant) and probe it, so they fail if discovery and the router
//! ever diverge again.

mod common;

/// Extracts the path (with no query) of an absolute endpoint URL advertised in
/// the discovery document.
fn endpoint_path(endpoint: &str) -> String {
    reqwest::Url::parse(endpoint)
        .expect("advertised endpoint is a valid absolute URL")
        .path()
        .to_string()
}

/// Fetches and parses the served top-level OIDC discovery document.
async fn served_discovery(base: &str) -> serde_json::Value {
    let body = reqwest::Client::new()
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .expect("GET discovery document")
        .text()
        .await
        .expect("discovery body");
    serde_json::from_str(&body).expect("discovery document is valid JSON")
}

/// The `authorization_endpoint` advertised by discovery MUST answer a browser
/// GET with a redirect (into the consent UI) — never a 405.
#[tokio::test]
async fn authorization_endpoint_answers_get_with_redirect() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");

    let doc = served_discovery(base).await;
    let endpoint = doc["authorization_endpoint"]
        .as_str()
        .expect("authorization_endpoint present");
    let path = endpoint_path(endpoint);

    // Do NOT follow the redirect — we want to inspect the 3xx itself.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build non-redirecting client");

    let resp = client
        .get(format!(
            "{base}{path}?response_type=code&client_id={}&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid&state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
            uuid::Uuid::new_v4()
        ))
        .send()
        .await
        .expect("GET authorization_endpoint");

    let status = resp.status().as_u16();
    assert_ne!(
        status, 405,
        "GET {path} (advertised authorization_endpoint) must not be 405 Method Not Allowed"
    );
    assert!(
        resp.status().is_redirection(),
        "GET {path} must redirect the browser into the consent UI, got {status}"
    );
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        location.starts_with("/ui/oauth/authorize"),
        "redirect Location must target the consent UI, got {location:?}"
    );
}

/// The `device_authorization_endpoint` advertised by discovery MUST be a path the
/// router actually serves — probing it with POST must not 404 (wrong path) or
/// 405 (wrong method).
#[tokio::test]
async fn device_authorization_endpoint_is_served() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");

    let doc = served_discovery(base).await;
    let endpoint = doc["device_authorization_endpoint"]
        .as_str()
        .expect("device_authorization_endpoint present");
    let path = endpoint_path(endpoint);

    let resp = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Realm-ID", uuid::Uuid::new_v4().to_string())
        .body(format!("client_id={}&scope=openid", uuid::Uuid::new_v4()))
        .send()
        .await
        .expect("POST device_authorization_endpoint");

    let status = resp.status().as_u16();
    assert_ne!(
        status, 404,
        "POST {path} (advertised device_authorization_endpoint) must route, got 404 — discovery advertises an unserved path"
    );
    assert_ne!(
        status, 405,
        "POST {path} (advertised device_authorization_endpoint) must accept POST, got 405"
    );
}
