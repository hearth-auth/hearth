//! `X-Realm-ID` must agree with the realm named in a `/realms/{name}/…` path
//! (audit 2026-08-28 §4.16#12).
//!
//! The deployment guide (`docs/guides/concepts.md`, "Multi-tenancy routing in
//! depth") tells operators to put a reverse proxy in front of Hearth that maps
//! a tenant subdomain to `X-Realm-ID`. Every realm-path route used to ignore
//! that header entirely, so `tenant-a.auth.example.com/realms/tenant-b/token`
//! silently served tenant B while the proxy believed it had pinned tenant A —
//! a tenant-confusion hazard.
//!
//! The rule implemented here is the safe reading: when the header is present it
//! MUST name the same realm as the path, otherwise the request is refused with
//! `400 realm_mismatch`. The header never *overrides* the path realm, and a
//! request with no header behaves exactly as before.

mod common;

use hearth::identity::CreateRealmRequest;

/// Every route mounted under `/realms/{realm_name}` in `http::router()`, as
/// `(method, path suffix)`. Kept in sync with `oauth::realm_routes()` +
/// `session::realm_routes()`.
const REALM_ROUTES: &[(&str, &str)] = &[
    ("GET", "/.well-known/openid-configuration"),
    ("GET", "/.well-known/jwks.json"),
    ("GET", "/authorize"),
    ("POST", "/as/par"),
    ("POST", "/token"),
    ("POST", "/revoke"),
    ("POST", "/introspect"),
    ("POST", "/device_authorization"),
    ("GET", "/userinfo"),
    ("POST", "/register"),
    ("GET", "/end_session"),
];

/// Creates a realm and returns its name plus its UUID string.
fn make_realm(h: &common::TestHarness, prefix: &str) -> (String, String) {
    let name = format!("{prefix}-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: name.clone(),
            config: None,
        })
        .expect("create realm");
    let id = realm.id().as_uuid().to_string();
    (name, id)
}

fn request(client: &reqwest::Client, method: &str, url: &str) -> reqwest::RequestBuilder {
    match method {
        "GET" => client.get(url),
        "POST" => client.post(url).body(String::new()),
        other => panic!("unsupported method in route table: {other}"),
    }
}

/// A header naming a different realm than the path must be refused on every
/// realm-scoped route — never silently ignored.
#[tokio::test]
async fn realm_path_routes_refuse_a_mismatched_realm_header() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (realm_a, _id_a) = make_realm(&h, "hdr-a");
    let (_realm_b, id_b) = make_realm(&h, "hdr-b");

    let client = reqwest::Client::new();
    for (method, suffix) in REALM_ROUTES {
        let url = format!("{base}/realms/{realm_a}{suffix}");
        let resp = request(&client, method, &url)
            .header("X-Realm-ID", &id_b)
            .send()
            .await
            .expect("request");
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        assert_eq!(
            status, 400,
            "{method} /realms/{{A}}{suffix} with X-Realm-ID of realm B must be \
             refused, got {status} body {body}"
        );
        assert_eq!(
            body.get("error").and_then(serde_json::Value::as_str),
            Some("realm_mismatch"),
            "{method} /realms/{{A}}{suffix} must report realm_mismatch, got {body}"
        );
    }
}

/// A header that agrees with the path is accepted — the guard must not break
/// the subdomain-to-header routing the deployment guide prescribes.
#[tokio::test]
async fn realm_path_routes_accept_a_matching_realm_header() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (realm_a, id_a) = make_realm(&h, "hdr-match");

    let client = reqwest::Client::new();
    for suffix in [
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
    ] {
        let url = format!("{base}/realms/{realm_a}{suffix}");
        let resp = client
            .get(&url)
            .header("X-Realm-ID", &id_a)
            .send()
            .await
            .expect("request");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "a matching X-Realm-ID must not change {suffix}"
        );
    }
}

/// No header at all must keep working exactly as before.
#[tokio::test]
async fn realm_path_routes_still_work_without_a_realm_header() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (realm_a, _id_a) = make_realm(&h, "hdr-none");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{base}/realms/{realm_a}/.well-known/openid-configuration"
        ))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 200, "no header must still resolve");

    let resp = client
        .get(format!("{base}/realms/{realm_a}/.well-known/jwks.json"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 200, "no header must still resolve");
}

/// A malformed `X-Realm-ID` cannot agree with the path realm, so it is refused
/// rather than ignored.
#[tokio::test]
async fn realm_path_routes_refuse_a_malformed_realm_header() {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url");
    let (realm_a, _id_a) = make_realm(&h, "hdr-bad");

    let resp = reqwest::Client::new()
        .get(format!(
            "{base}/realms/{realm_a}/.well-known/openid-configuration"
        ))
        .header("X-Realm-ID", "not-a-uuid")
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a malformed X-Realm-ID must be refused, not ignored"
    );
}
