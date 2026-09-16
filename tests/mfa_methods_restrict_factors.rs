//! 19.15 (audit 2026-08-28 §4.18#10) — `mfa_methods` must restrict which
//! second factors a user may enrol and present.
//!
//! CONFIGURATION.md says of `mfa_methods`: *"When set, only the listed methods
//! are offered for enrollment and challenge; methods not in the list are
//! rejected. Absent = all methods allowed."* Nothing enforced that. The list
//! was read in exactly three places, each of them a *positive* trigger —
//! inject an SMS or email-OTP enrolment required-action, and fire the OIDC SMS
//! interceptor. A realm that listed `["webauthn"]` still let every user enrol
//! TOTP and log in with it, and `"email_otp"` — a value the same document
//! lists and three code paths read — was rejected outright by the config
//! validator.

mod common;

use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, IdentityError, Realm, RealmConfig, User,
};

/// Creates a realm with the given `mfa_methods` plus one user in it.
async fn realm_with_methods(methods: Option<Vec<&str>>) -> (common::TestHarness, Realm, User) {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("mfa-methods-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_methods: methods
                    .map(|m| m.into_iter().map(ToString::to_string).collect::<Vec<_>>()),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Factor User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    (h, realm, user)
}

/// Control: with no list configured, nothing is restricted. Every rejection
/// below is measured against this — otherwise they could all be passing for
/// some unrelated reason.
#[tokio::test]
async fn an_absent_list_restricts_nothing() {
    let (h, realm, user) = realm_with_methods(None).await;
    h.identity()
        .enroll_totp(realm.id(), user.id())
        .expect("an unrestricted realm must allow TOTP enrolment");
}

/// A realm that offers only passkeys must not let a user enrol TOTP.
#[tokio::test]
async fn a_realm_that_does_not_offer_totp_refuses_totp_enrolment() {
    let (h, realm, user) = realm_with_methods(Some(vec!["webauthn"])).await;
    let err = h
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect_err("TOTP is not offered by this realm");
    assert!(
        matches!(err, IdentityError::MfaMethodNotAllowed { method: "totp" }),
        "the refusal must name the disallowed method, got {err:?}"
    );
}

/// Presentation is restricted too, not just enrolment. A realm that drops
/// `totp` from its list must stop accepting TOTP codes from users who enrolled
/// while it was still offered — that is what "methods not in the list are
/// rejected" means for a challenge.
#[tokio::test]
async fn dropping_a_method_stops_it_being_presented() {
    let (h, realm, user) = realm_with_methods(Some(vec!["totp"])).await;
    let enrolment = h
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect("totp is offered here");
    assert!(
        !enrolment.secret_base32.is_empty(),
        "enrolment must really have happened"
    );

    // The operator narrows the realm to passkeys only.
    let updated = h
        .identity()
        .update_realm(
            realm.id(),
            &hearth::identity::UpdateRealmRequest {
                name: None,
                config: Some(RealmConfig {
                    mfa_methods: Some(vec!["webauthn".to_string()]),
                    ..RealmConfig::default()
                }),
                status: None,
            },
        )
        .expect("narrow mfa_methods");
    assert_eq!(
        updated.config().mfa_methods.as_deref(),
        Some(["webauthn".to_string()].as_slice()),
        "the realm must really carry the narrowed list"
    );

    let err = h
        .identity()
        .verify_totp(realm.id(), user.id(), "000000")
        .expect_err("TOTP is no longer offered");
    assert!(
        matches!(err, IdentityError::MfaMethodNotAllowed { method: "totp" }),
        "presenting a withdrawn factor must be refused as such, not as a bad code: {err:?}"
    );

    // Recovery codes are TOTP's fallback and follow it.
    let err = h
        .identity()
        .verify_recovery_code(realm.id(), user.id(), "abcd-efgh")
        .expect_err("recovery codes follow TOTP's availability");
    assert!(
        matches!(err, IdentityError::MfaMethodNotAllowed { method: "totp" }),
        "recovery codes must follow the TOTP method gate, got {err:?}"
    );
}

/// The same rule in the other direction: a TOTP-only realm must refuse a
/// WebAuthn ceremony.
#[tokio::test]
async fn a_realm_that_does_not_offer_webauthn_refuses_a_passkey_ceremony() {
    let (h, realm, user) = realm_with_methods(Some(vec!["totp"])).await;
    let err = h
        .identity()
        .start_webauthn_registration(
            realm.id(),
            user.id(),
            &hearth::identity::RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect_err("webauthn is not offered by this realm");
    assert!(
        matches!(
            err,
            IdentityError::MfaMethodNotAllowed { method: "webauthn" }
        ),
        "the refusal must name webauthn, got {err:?}"
    );
}

/// `email_otp` is documented as a valid `mfa_methods` value and read by three
/// code paths, but the config validator's allow-list omitted it — so a realm
/// configured exactly as the manual describes failed to start.
#[test]
fn email_otp_is_a_valid_configured_mfa_method() {
    let yaml = r#"
server:
  bind_address: "127.0.0.1"
  port: 8420
storage:
  data_dir: "/tmp/hearth-mfa-methods-test"
realms:
  default:
    auth:
      mfa_methods: [totp, email_otp]
"#;
    let config = hearth::config::Config::from_yaml_str_unchecked(yaml).expect("config must parse");
    let issues = config.validate_all();
    let offending: Vec<_> = issues
        .iter()
        .filter(|i| i.field.ends_with("auth.mfa_methods"))
        .collect();
    assert!(
        offending.is_empty(),
        "email_otp must be accepted as an mfa_methods value, got {offending:?}"
    );

    // Non-vacuous: a genuinely unknown method is still refused, so the
    // assertion above is not passing because the check stopped running.
    let bogus = yaml.replace("email_otp", "carrier_pigeon");
    let config =
        hearth::config::Config::from_yaml_str_unchecked(&bogus).expect("config must parse");
    assert!(
        config
            .validate_all()
            .iter()
            .any(|i| i.field.ends_with("auth.mfa_methods")),
        "an unknown MFA method must still be refused"
    );
}
