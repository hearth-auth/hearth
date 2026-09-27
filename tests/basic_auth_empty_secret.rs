#![allow(clippy::unwrap_used)]
//! `Authorization: Basic base64("<client_id>:")` — an empty password — is a
//! client identifier with NO secret, on every endpoint.
//!
//! `resolve_client_credentials` returned the empty password as `Some("")`, a
//! presented (wrong) secret. The `authorization_code` arm of `/token`
//! normalized it to absent, so a public client identifying itself this way
//! could redeem its code — but `/as/par` and `/revoke` refused the same client
//! (`401`): a public client presenting a secret is refused there. An empty
//! Basic secret now reads as absent everywhere.

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{ClientTrustLevel, CreateRealmRequest, RegisterClientRequest};

const REDIRECT_URI: &str = "https://app.example.com/cb";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Env {
    _h: common::TestHarness,
    base: String,
    realm_name: String,
    realm_id: RealmId,
    public: ClientId,
}

async fn env() -> Env {
    let h = common::TestHarness::server().await.expect("server harness");
    let base = h.base_url().expect("base_url").to_string();
    let realm_name = format!("basic-empty-{}", uuid::Uuid::new_v4());
    let realm_id = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let public = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "public SPA".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register")
        .client_id()
        .clone();
    Env {
        _h: h,
        base,
        realm_name,
        realm_id,
        public,
    }
}

impl Env {
    async fn post(
        &self,
        realm_route: bool,
        endpoint: &str,
        form: &[(&str, &str)],
    ) -> (u16, String) {
        let url = if realm_route {
            format!("{}/realms/{}/{endpoint}", self.base, self.realm_name)
        } else {
            format!("{}/{endpoint}", self.base)
        };
        let mut req = reqwest::Client::new().post(url).form(form).header(
            "Authorization",
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:", self.public.as_uuid()))
            ),
        );
        if !realm_route {
            req = req.header("X-Realm-ID", self.realm_id.as_uuid().to_string());
        }
        let resp = req.send().await.expect("request");
        (
            resp.status().as_u16(),
            resp.text().await.unwrap_or_default(),
        )
    }
}

#[tokio::test]
async fn an_empty_basic_password_is_no_secret_at_par_and_revoke() {
    let env = env().await;
    for realm_route in [false, true] {
        let (status, body) = env
            .post(
                realm_route,
                "as/par",
                &[
                    ("redirect_uri", REDIRECT_URI),
                    ("scope", "openid"),
                    ("state", "s"),
                    ("response_type", "code"),
                    ("code_challenge", PKCE_CHALLENGE),
                    ("code_challenge_method", "S256"),
                ],
            )
            .await;
        assert_eq!(status, 201, "realm_route={realm_route} /as/par: {body}");

        let (status, body) = env
            .post(realm_route, "revoke", &[("token", "not-a-token")])
            .await;
        assert_eq!(status, 200, "realm_route={realm_route} /revoke: {body}");
    }
}
