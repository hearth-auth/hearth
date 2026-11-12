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

/// The query pairs of a relative `Location` such as `/ui/oauth/authorize?a=b`.
fn location_query_pairs(location: &str) -> Vec<(String, String)> {
    let url = reqwest::Url::parse(&format!("http://h{location}")).expect("Location is a path");
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// The path of a relative `Location`, without the query.
fn location_path(location: &str) -> &str {
    location.split('?').next().unwrap_or_default()
}

/// The parameters of a browser authorization request, in the order a
/// relying party sends them. The `redirect_uri` and the `scope` hold
/// characters that the form encoding escapes.
fn browser_authorization_params() -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_string()),
        ("client_id", uuid::Uuid::new_v4().to_string()),
        ("redirect_uri", "https://app.example/cb?x=1".to_string()),
        ("scope", "openid profile".to_string()),
        ("state", "st-781".to_string()),
        ("nonce", "n-781".to_string()),
    ]
}

/// Sends the request without a redirect and returns the status and `Location`.
async fn status_and_location(req: reqwest::RequestBuilder) -> (u16, String) {
    let resp = req.send().await.expect("send");
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (resp.status().as_u16(), location)
}

/// A client that does not follow redirects, so a test sees the `3xx` itself.
fn non_redirecting_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build non-redirecting client")
}

/// Creates a realm with a random name and returns it.
fn new_realm(h: &common::TestHarness, prefix: &str) -> hearth::identity::Realm {
    h.identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: format!("{prefix}-{}", uuid::Uuid::new_v4().simple()),
            config: None,
        })
        .expect("create realm")
}

/// OIDC Core §3.1.2.1: the authorization endpoint MUST support GET and POST.
/// A form POST (`application/x-www-form-urlencoded`) to `/authorize` or
/// `/realms/{realm}/authorize` starts the browser flow with the same
/// parameters as a GET: it goes to the same UI authorize page with the same
/// query (#781, OpenID Foundation `oidcc-ensure-post-request-succeeds`).
#[tokio::test]
async fn form_post_to_the_authorization_endpoint_starts_the_browser_flow() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let realm = new_realm(&h, "post").name().to_string();
    let client = non_redirecting_client();

    let params = browser_authorization_params();
    let expected: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    let form = serde_urlencoded::to_string(&params).expect("form body");

    for (endpoint, ui_page) in [
        ("/authorize".to_string(), "/ui/oauth/authorize".to_string()),
        (
            format!("/realms/{realm}/authorize"),
            format!("/ui/realms/{realm}/oauth/authorize"),
        ),
    ] {
        let (get_status, get_location) =
            status_and_location(client.get(format!("{base}{endpoint}?{form}"))).await;
        assert_eq!(get_status, 303, "control: GET {endpoint}");
        assert_eq!(
            location_path(&get_location),
            ui_page,
            "control: GET {endpoint}"
        );

        let (status, location) = status_and_location(
            client
                .post(format!("{base}{endpoint}"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(form.clone()),
        )
        .await;
        assert_eq!(
            status, 303,
            "a form POST to {endpoint} must redirect the browser into the UI authorize page \
             (got {status}, Location {location:?})"
        );
        assert_eq!(location_path(&location), ui_page, "form POST {endpoint}");
        assert_eq!(
            location_query_pairs(&location),
            expected,
            "form POST {endpoint}: the UI page must get every posted parameter"
        );
        assert_eq!(
            location_query_pairs(&location),
            location_query_pairs(&get_location),
            "form POST {endpoint}: the same parameters as the GET"
        );
    }
}

/// A form POST that names its charset, in any letter case, is still a form
/// POST.
#[tokio::test]
async fn form_post_with_a_charset_starts_the_browser_flow() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let form = serde_urlencoded::to_string(browser_authorization_params()).expect("form body");

    let (status, location) = status_and_location(
        non_redirecting_client()
            .post(format!("{base}/authorize"))
            .header(
                "Content-Type",
                "Application/X-WWW-Form-Urlencoded; charset=UTF-8",
            )
            .body(form),
    )
    .await;
    assert_eq!(status, 303, "got {status}, Location {location:?}");
    assert_eq!(location_path(&location), "/ui/oauth/authorize");
}

/// A JSON POST to `/authorize` keeps the Hearth JSON API: it needs a Bearer
/// token and answers in JSON, never with a browser redirect (#781).
#[tokio::test]
async fn json_post_to_the_authorization_endpoint_keeps_the_json_api() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let realm = new_realm(&h, "json");
    let client = non_redirecting_client();
    let body: serde_json::Map<String, serde_json::Value> = browser_authorization_params()
        .into_iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::String(v)))
        .collect();

    for req in [
        client
            .post(format!("{base}/authorize"))
            .header("X-Realm-ID", realm.id().as_uuid().to_string()),
        client.post(format!("{base}/realms/{}/authorize", realm.name())),
    ] {
        let resp = req.json(&body).send().await.expect("JSON POST /authorize");
        let status = resp.status().as_u16();
        assert_eq!(status, 401, "a JSON POST without a Bearer token is refused");
        assert!(resp.headers().get(reqwest::header::LOCATION).is_none());
        let json: serde_json::Value = resp.json().await.expect("JSON error body");
        assert!(json.get("error").is_some(), "a JSON error body, got {json}");
    }
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

/// OIDC Discovery 1.0 §3: `request_uri_parameter_supported` defaults to
/// `true` and `request_parameter_supported` to `false` when they are left out.
/// Hearth accepts a signed `request` object (RFC 9101) and does not fetch a
/// `request_uri` by reference: it accepts only the `request_uri` that its own
/// PAR endpoint returned (RFC 9126). Both documents MUST say so, so a relying
/// party does not send a request by reference that Hearth refuses (#639,
/// `oidcc-request-uri-signed-rs256`).
#[tokio::test]
async fn discovery_states_which_request_parameters_are_supported() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let realm = format!("disc-{}", uuid::Uuid::new_v4().simple());
    h.identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: realm.clone(),
            config: None,
        })
        .expect("create realm");

    let realm_doc = reqwest::Client::new()
        .get(format!(
            "{base}/realms/{realm}/.well-known/openid-configuration"
        ))
        .send()
        .await
        .expect("GET realm discovery document")
        .json::<serde_json::Value>()
        .await
        .expect("realm discovery document is valid JSON");
    for (which, doc) in [
        ("server", served_discovery(base).await),
        ("realm", realm_doc),
    ] {
        assert_eq!(
            doc["request_parameter_supported"],
            serde_json::Value::Bool(true),
            "{which} document: request_parameter_supported"
        );
        assert_eq!(
            doc["request_uri_parameter_supported"],
            serde_json::Value::Bool(false),
            "{which} document: request_uri_parameter_supported"
        );
    }
}

/// RFC 8414 §2: `token_endpoint_auth_signing_alg_values_supported` (and its
/// revocation and introspection twins) MUST be present when the matching
/// `*_auth_methods_supported` lists `private_key_jwt`. Without it, OIDC
/// Discovery 1.0 §3 lets a client assume `RS256`, which Hearth refuses for
/// client authentication. The lists name the algorithms that Hearth accepts
/// for a client assertion (#639, OpenID Foundation Dynamic OP).
#[tokio::test]
async fn discovery_lists_the_client_assertion_algorithms() {
    let h = common::TestHarness::server().await.expect("server harness");
    let doc = served_discovery(h.base_url().expect("base_url")).await;
    for endpoint in [
        "token_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
    ] {
        let methods = &doc[format!("{endpoint}_auth_methods_supported")];
        assert!(
            methods
                .as_array()
                .is_some_and(|m| m.iter().any(|v| v == "private_key_jwt")),
            "control: {endpoint} lists private_key_jwt: {methods}"
        );
        assert_eq!(
            doc[format!("{endpoint}_auth_signing_alg_values_supported")],
            serde_json::json!(["PS256", "ES256", "EdDSA"]),
            "{endpoint}_auth_signing_alg_values_supported"
        );
    }
}
