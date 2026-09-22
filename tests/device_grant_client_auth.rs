#![allow(clippy::unwrap_used)]
//! Audit §4.19#4 / §4.22#6 regression: neither device-grant endpoint
//! authenticated the client.
//!
//! RFC 8628 §3.1 and §3.4 both require a confidential client to authenticate,
//! exactly as it does at the token endpoint. Hearth read only `client_id`, so a
//! party holding a public client identifier — and no secret — could run the
//! whole device flow under a confidential client's identity.
//!
//! Both endpoints now enforce `enforce_confidential_client_auth`, the same
//! helper the `authorization_code` arm uses. Public clients are unaffected.

mod common;

use hearth::core::RealmId;
use hearth::identity::{CreateRealmRequest, RegisterClientRequest};

const FORM: &str = "application/x-www-form-urlencoded";
const CONFIDENTIAL_SECRET: &str = "device-grant-confidential-secret-32chars";

struct Ctx {
    base: String,
    realm_name: String,
    realm_id: String,
    confidential_client: String,
    public_client: String,
}

async fn setup(harness: &common::TestHarness) -> Ctx {
    let base = harness.base_url().expect("base_url").to_string();
    let realm_name = format!("device-auth-{}", uuid::Uuid::new_v4());
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm");
    let realm_id: RealmId = realm.id().clone();

    let confidential = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Confidential TV App".to_string(),
                redirect_uris: vec![],
                client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
                grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register confidential client");

    let public = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Public TV App".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register public client");

    Ctx {
        base,
        realm_name,
        realm_id: realm_id.as_uuid().to_string(),
        confidential_client: confidential.client_id().as_uuid().to_string(),
        public_client: public.client_id().as_uuid().to_string(),
    }
}

/// Posts a form body to the realm-scoped and the header-routed twin of `path`,
/// returning `(realm_status, header_status)`.
async fn post_both(ctx: &Ctx, path: &str, body: String) -> (u16, u16) {
    let http = reqwest::Client::new();
    let realm_status = http
        .post(format!("{}/realms/{}/{path}", ctx.base, ctx.realm_name))
        .header("Content-Type", FORM)
        .body(body.clone())
        .send()
        .await
        .expect("realm-scoped request")
        .status()
        .as_u16();
    let header_status = http
        .post(format!("{}/{path}", ctx.base))
        .header("Content-Type", FORM)
        .header("X-Realm-ID", &ctx.realm_id)
        .body(body)
        .send()
        .await
        .expect("header-routed request")
        .status()
        .as_u16();
    (realm_status, header_status)
}

/// RFC 8628 §3.1: a confidential client MUST authenticate at the device
/// authorization endpoint. Without a secret the request is refused.
#[tokio::test]
async fn device_authorization_refuses_a_confidential_client_without_its_secret() {
    let harness = common::TestHarness::server().await.expect("server harness");
    let ctx = setup(&harness).await;

    let (realm_status, header_status) = post_both(
        &ctx,
        "device_authorization",
        format!("client_id={}&scope=openid", ctx.confidential_client),
    )
    .await;
    assert_eq!(realm_status, 401, "realm-scoped twin must refuse");
    assert_eq!(header_status, 401, "header-routed twin must refuse");
}

/// The same request with the correct secret succeeds, so the guard rejects the
/// missing credential rather than the flow.
#[tokio::test]
async fn device_authorization_accepts_a_confidential_client_with_its_secret() {
    let harness = common::TestHarness::server().await.expect("server harness");
    let ctx = setup(&harness).await;

    let (realm_status, header_status) = post_both(
        &ctx,
        "device_authorization",
        format!(
            "client_id={}&client_secret={CONFIDENTIAL_SECRET}&scope=openid",
            ctx.confidential_client
        ),
    )
    .await;
    assert_eq!(realm_status, 200, "realm-scoped twin must succeed");
    assert_eq!(header_status, 200, "header-routed twin must succeed");
}

/// A public client authenticates with PKCE, not a secret. It keeps working.
#[tokio::test]
async fn device_authorization_still_serves_a_public_client() {
    let harness = common::TestHarness::server().await.expect("server harness");
    let ctx = setup(&harness).await;

    let (realm_status, header_status) = post_both(
        &ctx,
        "device_authorization",
        format!("client_id={}&scope=openid", ctx.public_client),
    )
    .await;
    assert_eq!(realm_status, 200, "realm-scoped twin must succeed");
    assert_eq!(header_status, 200, "header-routed twin must succeed");
}

/// RFC 8628 §3.4: the device access token request MUST authenticate the client
/// too. Without a secret the poll is refused before `poll_device_token` runs —
/// so the answer is 401, not the flow's own `authorization_pending`.
#[tokio::test]
async fn device_token_poll_refuses_a_confidential_client_without_its_secret() {
    let harness = common::TestHarness::server().await.expect("server harness");
    let ctx = setup(&harness).await;
    let http = reqwest::Client::new();

    // Obtain a real device_code, authenticating properly.
    let body: serde_json::Value = http
        .post(format!("{}/device_authorization", ctx.base))
        .header("Content-Type", FORM)
        .header("X-Realm-ID", &ctx.realm_id)
        .body(format!(
            "client_id={}&client_secret={CONFIDENTIAL_SECRET}&scope=openid",
            ctx.confidential_client
        ))
        .send()
        .await
        .expect("device authorization")
        .json()
        .await
        .expect("device authorization body");
    let device_code = body["device_code"]
        .as_str()
        .expect("device_code")
        .to_string();

    let (realm_status, header_status) = post_both(
        &ctx,
        "token",
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}\
             &client_id={}",
            ctx.confidential_client
        ),
    )
    .await;
    assert_eq!(realm_status, 401, "realm-scoped twin must refuse");
    assert_eq!(header_status, 401, "header-routed twin must refuse");
}
