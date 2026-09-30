//! The step-up-MFA grant (`urn:hearth:params:grant-type:step-up-mfa`) and
//! DPoP (RFC 9449) — GA sweep 4, OAUTH round 2.
//!
//! The grant validated no proof input at all and minted plain Bearer tokens,
//! also in a realm with a `fapi_profile`, where every other grant requires
//! sender-constrained tokens (OIDC.md §2.1). Its refresh tokens belong to a
//! clientless family, and the refresh path applied the FAPI check only to a
//! family with a client, so they rotated without a proof there too.
//!
//! Pinned here:
//! - a proof binds the access token, the refresh token and the grant family,
//!   and the response says `token_type: DPoP`;
//! - a FAPI realm refuses the grant without a proof, and refuses a
//!   clientless refresh without one;
//! - over HTTP, both `/token` routes pass the proof through.

#![allow(clippy::unwrap_used)]

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::{RealmId, UserId};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, FapiProfile, IdentityError,
    StepUpMfaGrantRequest, UpdateRealmRequest,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const PASSWORD: &str = "S3cur3P@ss!1-step-up-dpop";
const JKT: &str = "step-up-thumbprint-A";
const OTHER_JKT: &str = "step-up-thumbprint-B";
const GRANT: &str = "urn:hearth:params:grant-type:step-up-mfa";

struct Fx {
    h: common::TestHarness,
    realm: RealmId,
    realm_name: String,
    email: String,
    user: UserId,
    /// Unused recovery codes; each grant spends one.
    codes: std::cell::RefCell<Vec<String>>,
}

fn totp(secret_base32: &str, unix_secs: u64) -> String {
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        &data_encoding::BASE32_NOPAD
            .decode(secret_base32.as_bytes())
            .unwrap(),
    );
    let tag = ring::hmac::sign(&key, &(unix_secs / 30).to_be_bytes());
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

async fn fixture(h: common::TestHarness, fapi: Option<FapiProfile>) -> Fx {
    let realm_name = format!("stepup-dpop-{}", uuid::Uuid::new_v4());
    let rec = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .unwrap();
    let realm = rec.id().clone();
    if let Some(profile) = fapi {
        let mut config = rec.config().clone();
        config.fapi_profile = Some(profile);
        h.identity()
            .update_realm(
                &realm,
                &UpdateRealmRequest {
                    config: Some(config),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let email = format!("stepup-{}@example.com", uuid::Uuid::new_v4());
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "Step-up user".to_string(),
                ..Default::default()
            },
        )
        .unwrap()
        .id()
        .clone();
    h.identity()
        .set_password(
            &realm,
            &user,
            &CleartextPassword::from_string(PASSWORD.into()),
        )
        .unwrap();
    let enrollment = h.identity().enroll_totp(&realm, &user).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    h.identity()
        .verify_totp_enrollment(&realm, &user, &totp(&enrollment.secret_base32, now))
        .unwrap();
    let codes = enrollment.recovery_codes.as_slice().to_vec();
    Fx {
        h,
        realm,
        realm_name,
        email,
        user,
        codes: std::cell::RefCell::new(codes),
    }
}

impl Fx {
    fn code(&self) -> String {
        self.codes.borrow_mut().pop().expect("a recovery code left")
    }

    fn grant(&self, dpop_jkt: Option<&str>) -> StepUpMfaGrantRequest {
        StepUpMfaGrantRequest {
            email: self.email.clone(),
            password: PASSWORD.to_string(),
            mfa_code: self.code(),
            scope: None,
            client_ip: Some("10.9.8.7".to_string()),
            user_agent: Some("step-up-dpop-test".to_string()),
            dpop_jkt: dpop_jkt.map(str::to_string),
        }
    }
}

fn decode_claims(jwt: &str) -> serde_json::Value {
    let payload = jwt.split('.').nth(1).expect("JWT payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// A proof binds the pair and the family; the response is typed `DPoP`.
#[tokio::test]
async fn step_up_grant_with_dpop_binds_the_pair_and_the_family() {
    let fx = fixture(common::TestHarness::embedded().await.unwrap(), None).await;
    let resp =
        fx.h.identity()
            .step_up_mfa_grant_token(&fx.realm, &fx.grant(Some(JKT)))
            .expect("step-up grant with DPoP");
    assert_eq!(resp.token_type, "DPoP");
    let access =
        fx.h.identity()
            .validate_token(&fx.realm, resp.access_token())
            .expect("validates");
    assert_eq!(access.sub, fx.user.to_string());
    assert_eq!(access.cnf.as_ref().map(|c| c.jkt.as_str()), Some(JKT));
    assert_eq!(
        decode_claims(resp.refresh_token())["cnf"]["jkt"].as_str(),
        Some(JKT)
    );

    for (jkt, what) in [(None, "no proof"), (Some(OTHER_JKT), "another key")] {
        let err =
            fx.h.identity()
                .refresh_tokens(&fx.realm, resp.refresh_token(), jkt, None)
                .expect_err(what);
        assert!(
            matches!(err, IdentityError::DPopBindingMismatch),
            "refresh with {what}: {err:?}"
        );
    }
    fx.h.identity()
        .refresh_tokens(&fx.realm, resp.refresh_token(), Some(JKT), None)
        .expect("refresh with the bound key");
}

/// Without a proof a standard realm still issues Bearer tokens.
#[tokio::test]
async fn step_up_grant_without_dpop_in_a_standard_realm_stays_bearer() {
    let fx = fixture(common::TestHarness::embedded().await.unwrap(), None).await;
    let resp =
        fx.h.identity()
            .step_up_mfa_grant_token(&fx.realm, &fx.grant(None))
            .expect("step-up grant");
    assert_eq!(resp.token_type, "Bearer");
    let access =
        fx.h.identity()
            .validate_token(&fx.realm, resp.access_token())
            .unwrap();
    assert!(access.cnf.is_none());
}

/// A FAPI realm (either profile) refuses the grant without a proof and
/// honours it with one; a refresh of the resulting clientless family
/// without a proof is refused by the FAPI rule too.
#[tokio::test]
async fn fapi_realm_requires_dpop_on_the_step_up_grant_and_its_refresh() {
    for profile in [FapiProfile::Baseline, FapiProfile::Advanced] {
        let fx = fixture(
            common::TestHarness::embedded().await.unwrap(),
            Some(profile),
        )
        .await;
        let err =
            fx.h.identity()
                .step_up_mfa_grant_token(&fx.realm, &fx.grant(None))
                .expect_err("a FAPI realm must refuse unbound step-up tokens");
        assert!(
            matches!(err, IdentityError::FapiViolation { .. }),
            "{profile:?}: {err:?}"
        );

        let resp =
            fx.h.identity()
                .step_up_mfa_grant_token(&fx.realm, &fx.grant(Some(JKT)))
                .expect("with a proof");
        assert_eq!(resp.token_type, "DPoP", "{profile:?}");

        let err =
            fx.h.identity()
                .refresh_tokens(&fx.realm, resp.refresh_token(), None, None)
                .expect_err("a FAPI realm must refuse a clientless refresh without a proof");
        assert!(
            matches!(err, IdentityError::FapiViolation { .. }),
            "{profile:?}: {err:?}"
        );
    }
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

struct DpopKey(Ed25519KeyPair);

impl DpopKey {
    fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
    }

    fn x(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.public_key().as_ref())
    }

    fn thumbprint(&self) -> String {
        hearth::identity::dpop::compute_jwk_thumbprint(&hearth::identity::dpop::DPopJwk {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some(self.x()),
            y: None,
            n: None,
            e: None,
        })
        .unwrap()
    }

    fn proof(&self, htu: &str, nonce: &str) -> String {
        let header = serde_json::json!({
            "alg": "EdDSA", "typ": "dpop+jwt",
            "jwk": {"kty": "OKP", "crv": "Ed25519", "x": self.x()},
        });
        let claims = serde_json::json!({
            "htm": "POST", "htu": htu, "iat": now_secs(),
            "jti": uuid::Uuid::new_v4().to_string(), "nonce": nonce,
        });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig = self.0.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }
}

#[derive(Clone, Copy, Debug)]
enum Route {
    Header,
    Realm,
}

impl Fx {
    async fn post(&self, route: Route, dpop: Option<&DpopKey>) -> (u16, serde_json::Value) {
        let base = self.h.base_url().expect("server harness");
        let doc = self.h.identity().oidc_discovery();
        let (url, htu) = match route {
            Route::Header => (format!("{base}/token"), doc.token_endpoint),
            Route::Realm => (
                format!("{base}/realms/{}/token", self.realm_name),
                format!("{}/realms/{}/token", doc.issuer, self.realm_name),
            ),
        };
        let http = reqwest::Client::new();
        let with_realm = |r: reqwest::RequestBuilder| match route {
            Route::Header => r.header("X-Realm-ID", self.realm.as_uuid().to_string()),
            Route::Realm => r,
        };
        let mut req = with_realm(http.post(&url).json(&serde_json::json!({
            "grant_type": GRANT,
            "username": self.email,
            "password": PASSWORD,
            "mfa_code": self.code(),
        })));
        if let Some(key) = dpop {
            let probe = with_realm(http.post(&url).form(&[("grant_type", "nonce-probe")]))
                .send()
                .await
                .unwrap();
            let nonce = probe
                .headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .expect("DPoP-Nonce")
                .to_string();
            req = req.header("DPoP", key.proof(&htu, &nonce));
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(serde_json::Value::Null))
    }
}

/// Over HTTP, both `/token` routes bind the step-up pair to the proof key,
/// and a FAPI realm refuses the grant without a proof.
#[tokio::test]
async fn http_step_up_grant_binds_to_the_dpop_proof_on_both_routes() {
    let fx = fixture(
        common::TestHarness::server().await.unwrap(),
        Some(FapiProfile::Baseline),
    )
    .await;
    for route in [Route::Header, Route::Realm] {
        let (status, body) = fx.post(route, None).await;
        assert_eq!(status, 400, "{route:?} unbound: {body}");
        assert!(body.get("access_token").is_none(), "{route:?}: {body}");

        let key = DpopKey::new();
        let (status, body) = fx.post(route, Some(&key)).await;
        assert_eq!(status, 200, "{route:?} bound: {body}");
        assert_eq!(body["token_type"], "DPoP", "{route:?}: {body}");
        assert_eq!(
            decode_claims(body["access_token"].as_str().unwrap())["cnf"]["jkt"].as_str(),
            Some(key.thumbprint().as_str()),
            "{route:?}"
        );
    }
}
