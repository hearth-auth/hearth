//! scope-trim-trusted-core, group 7: risk scoring, adaptive MFA, device
//! fingerprinting and SMS OTP are removed.
//!
//! A-11 (step-up risk scorer) and A-49 (refresh-context drift scored by the
//! risk scorer) are now met by removal. MFA is a plain realm policy, never a
//! score: an operator who tries to switch the scorer back on must be refused
//! at startup, not silently ignored. A-49's DPoP and client binding on the
//! refresh path stay, and their own suites cover them.
//!
//! SMS OTP is gone: its config keys stop startup with a named error, `sms`
//! is no longer a valid MFA method, and its browser and admin routes answer
//! like paths that never existed.

mod common;

use axum::http::Method;
use common::routes::{assert_route_absent, composed_app, SEEDED_REALM};
use hearth::config::{Config, ConfigError};

/// Removed config keys, with the YAML that sets each one.
const REMOVED: &[(&str, &str, &str)] = &[
    // (yaml, dotted key, word the feature name must contain)
    (
        "security:\n  risk_scorer:\n    enabled: true\n",
        "security.risk_scorer",
        "risk scor",
    ),
    ("sms:\n  transport: log\n", "sms", "SMS"),
    (
        "security:\n  outbound_volume_shield:\n    sms_soft_cap: 5\n",
        "security.outbound_volume_shield.sms_soft_cap",
        "SMS",
    ),
    (
        "security:\n  outbound_volume_shield:\n    sms_hard_cap: 9\n",
        "security.outbound_volume_shield.sms_hard_cap",
        "SMS",
    ),
    (
        "security:\n  cross_realm_aggregation_cap:\n    sms_realm_soft_cap: 5\n",
        "security.cross_realm_aggregation_cap.sms_realm_soft_cap",
        "SMS",
    ),
    (
        "security:\n  cross_realm_aggregation_cap:\n    sms_realm_hard_cap: 9\n",
        "security.cross_realm_aggregation_cap.sms_realm_hard_cap",
        "SMS",
    ),
];

fn assert_names_removed(err: &ConfigError, key: &str, feature_word: &str) {
    assert!(
        matches!(err, ConfigError::RemovedKey { .. }),
        "{key}: expected RemovedKey, got {err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains(&format!("'{key}'")), "{key}: {msg}");
    assert!(msg.contains(feature_word), "{key}: {msg}");
    assert!(msg.contains("3.0.0"), "{key}: {msg}");
}

/// A-11 / A-49 adversarial: an operator enabling the removed scorer, or any
/// SMS key, is refused by the checked loader.
#[test]
fn a11_a49_removed_keys_stop_the_checked_loader() {
    for (yaml, key, word) in REMOVED {
        let err = Config::from_yaml_str(yaml).expect_err("removed key must fail");
        assert_names_removed(&err, key, word);
    }
}

/// The `--dev` loader refuses the same keys.
#[test]
fn a11_a49_removed_keys_stop_the_dev_loader() {
    for (yaml, key, word) in REMOVED {
        let err = Config::from_yaml_str_unchecked(yaml).expect_err("removed key must fail");
        assert_names_removed(&err, key, word);
    }
}

/// `sms` is no longer an MFA method, in dev mode or out of it.
#[test]
fn sms_is_not_a_valid_mfa_method() {
    let yaml = "realms:\n  acme:\n    auth:\n      mfa_methods: [totp, sms]\n";
    let config = Config::from_yaml_str_unchecked(yaml).expect("config must parse");
    let issue = config
        .validate_all()
        .into_iter()
        .find(|i| i.field.ends_with("auth.mfa_methods"))
        .expect("sms must be refused");
    assert!(
        issue.reason.contains("unknown MFA method 'sms'"),
        "got: {}",
        issue.reason
    );
    assert!(
        hearth::config::check_mfa_methods(&["sms".to_string()]).is_err(),
        "the shared admin-API rule refuses sms"
    );
    assert!(
        hearth::config::check_mfa_methods(&["totp".to_string()]).is_ok(),
        "control: totp stays valid"
    );
}

#[tokio::test]
async fn sms_and_fingerprint_routes_are_absent() {
    let app = composed_app();
    let user = uuid::Uuid::new_v4();
    for (method, path) in [
        (Method::GET, "/ui/sms-challenge".to_string()),
        (Method::POST, "/ui/sms-challenge".to_string()),
        (Method::GET, "/required-action/ENROLL_PHONE_OTP".to_string()),
        (
            Method::POST,
            "/required-action/ENROLL_PHONE_OTP/send".to_string(),
        ),
        (
            Method::POST,
            "/required-action/ENROLL_PHONE_OTP/verify".to_string(),
        ),
        (
            Method::POST,
            format!("/ui/admin/realms/{SEEDED_REALM}/users/{user}/remove-phone"),
        ),
        (
            Method::DELETE,
            format!("/admin/users/{user}/device-fingerprints"),
        ),
    ] {
        assert_route_absent(&app, method, &path).await;
    }
}

/// Control: a kept second-factor route is still served, so the absence check
/// above is not vacuous.
#[tokio::test]
#[should_panic(expected = "is still served")]
async fn email_otp_enrolment_is_still_served() {
    let app = composed_app();
    assert_route_absent(&app, Method::GET, "/required-action/ENROLL_EMAIL_OTP").await;
}
