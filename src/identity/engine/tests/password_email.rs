//! The password email an administrator sends a user (OpenSpec change
//! `admin-password-email`): a set-password link for a user with no
//! password, a reset link for a user with one.

use super::*;

use crate::identity::PasswordEmailKind;

const HOUR: i64 = 3_600 * 1_000_000;

fn realm_with(engine: &EmbeddedIdentityEngine, config: RealmConfig) -> RealmId {
    engine
        .create_realm(&CreateRealmRequest {
            name: format!("pwmail-{}", uuid::Uuid::new_v4()),
            config: Some(config),
        })
        .expect("create realm")
        .id()
        .clone()
}

fn password(text: &str) -> CleartextPassword {
    CleartextPassword::from_string(text.to_string())
}

#[test]
fn a_user_without_a_password_gets_a_set_password_link() {
    let (_dir, engine, clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);

    let mail = engine
        .request_password_email(&realm, user.id())
        .expect("password email");
    assert_eq!(mail.kind, PasswordEmailKind::Setup);
    assert_eq!(mail.email, user.email());
    assert_eq!(
        engine
            .password_link_kind(&realm, &mail.token)
            .expect("lookup"),
        Some(PasswordEmailKind::Setup),
        "the page can tell a set-password link without spending it"
    );

    // A set-password link outlives a reset link: it still works a day later.
    clock.advance(24 * HOUR);
    engine
        .reset_password_with_token(&realm, &mail.token, &password("FirstPassword1!"))
        .expect("the set-password link works after 24 hours");
    assert!(engine
        .verify_password(&realm, user.id(), &password("FirstPassword1!"))
        .expect("verify"));
    assert_eq!(
        engine
            .password_link_kind(&realm, &mail.token)
            .expect("lookup"),
        None,
        "a spent link has no kind"
    );
}

#[test]
fn a_set_password_link_expires_after_the_default_72_hours() {
    let (_dir, engine, clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    let mail = engine
        .request_password_email(&realm, user.id())
        .expect("password email");

    clock.advance(72 * HOUR + 1);
    let err = engine
        .reset_password_with_token(&realm, &mail.token, &password("FirstPassword1!"))
        .expect_err("an expired set-password link");
    assert!(
        matches!(err, IdentityError::PasswordResetTokenInvalid),
        "{err}"
    );
}

#[test]
fn the_realm_sets_the_set_password_link_lifetime() {
    let (_dir, engine, clock) = setup_engine();
    let realm = realm_with(
        &engine,
        RealmConfig {
            set_password_token_ttl_micros: Some(2 * HOUR),
            ..RealmConfig::default()
        },
    );
    let user = create_test_user(&engine, &realm);
    let mail = engine
        .request_password_email(&realm, user.id())
        .expect("password email");

    clock.advance(2 * HOUR + 1);
    assert!(engine
        .reset_password_with_token(&realm, &mail.token, &password("FirstPassword1!"))
        .is_err_and(|e| matches!(e, IdentityError::PasswordResetTokenInvalid)));
}

#[test]
fn a_user_with_a_password_gets_a_reset_link_with_the_reset_lifetime() {
    let (_dir, engine, clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    engine
        .set_password(&realm, user.id(), &password("ValidPassword1!"))
        .expect("set password");

    let mail = engine
        .request_password_email(&realm, user.id())
        .expect("password email");
    assert_eq!(mail.kind, PasswordEmailKind::Reset);
    assert_eq!(
        engine
            .password_link_kind(&realm, &mail.token)
            .expect("lookup"),
        Some(PasswordEmailKind::Reset)
    );

    // The reset default is 30 minutes.
    clock.advance(HOUR);
    assert!(engine
        .reset_password_with_token(&realm, &mail.token, &password("NewPassword1!"))
        .is_err_and(|e| matches!(e, IdentityError::PasswordResetTokenInvalid)));
}

#[test]
fn the_reset_limit_is_shared_with_self_service_reset() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);

    for _ in 0..2 {
        engine
            .request_password_reset(&realm, user.email())
            .expect("self-service reset");
    }
    engine
        .request_password_email(&realm, user.id())
        .expect("the third request in the window");
    let err = engine
        .request_password_email(&realm, user.id())
        .expect_err("the fourth request in the window");
    assert!(matches!(err, IdentityError::RateLimited), "{err:?}");
}

#[test]
fn a_newer_link_supersedes_a_set_password_link() {
    let (_dir, engine, clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    let first = engine
        .request_password_email(&realm, user.id())
        .expect("first email");
    // The watermark supersedes links issued before it, so the second link
    // needs a later timestamp.
    clock.advance(1);
    let _second = engine
        .request_password_email(&realm, user.id())
        .expect("second email");

    assert_eq!(
        engine
            .password_link_kind(&realm, &first.token)
            .expect("lookup"),
        None
    );
    assert!(engine
        .reset_password_with_token(&realm, &first.token, &password("FirstPassword1!"))
        .is_err_and(|e| matches!(e, IdentityError::PasswordResetTokenInvalid)));
}

#[test]
fn a_realm_without_password_sign_in_is_refused() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = realm_with(
        &engine,
        RealmConfig {
            allowed_auth_methods: Some(vec!["passkey".to_string()]),
            ..RealmConfig::default()
        },
    );
    let user = create_test_user(&engine, &realm);
    let err = engine
        .request_password_email(&realm, user.id())
        .expect_err("no password email in a passkey-only realm");
    assert!(
        matches!(err, IdentityError::AuthMethodNotAllowed { .. }),
        "{err:?}"
    );
}

#[test]
fn an_unknown_user_is_not_found() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let err = engine
        .request_password_email(&realm, &UserId::generate())
        .expect_err("unknown user");
    assert!(matches!(err, IdentityError::UserNotFound), "{err:?}");
}
