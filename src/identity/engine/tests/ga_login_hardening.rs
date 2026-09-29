//! Login abuse resistance in the engine (GA audit 2026-09-28, findings L14
//! and L15). L18's required-action token flow was removed outright; see
//! `tests/link_token_out_of_url.rs`.

use super::*;

use crate::identity::hibp::{HibpError, HibpTransport};

const PASSWORD: &str = "correct-horse-battery-staple";

fn realm_with(engine: &EmbeddedIdentityEngine, config: RealmConfig) -> RealmId {
    engine
        .create_realm(&CreateRealmRequest {
            name: format!("ga-login-{}", uuid::Uuid::new_v4().simple()),
            config: Some(config),
        })
        .expect("create realm")
        .id()
        .clone()
}

fn user_with_password(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> User {
    let user = engine
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4().simple()),
                display_name: "Hardening User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    engine
        .set_password(
            realm,
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("set password");
    user
}

// ─── L15: the breach check runs before the account exists ───────────────────

struct AlwaysPwned;
impl HibpTransport for AlwaysPwned {
    fn get_range(&self, prefix: &str, _api_key: Option<&str>) -> Result<String, HibpError> {
        // Reports `PASSWORD` as breached, and nothing else.
        let (pw_prefix, pw_suffix) = crate::identity::hibp::sha1_prefix_suffix(PASSWORD.as_bytes());
        if pw_prefix.eq_ignore_ascii_case(prefix) {
            Ok(format!("{pw_suffix}:42"))
        } else {
            Ok(String::new())
        }
    }
}

/// With `breach_check` on, a breached password used to be checked only after
/// the account was created: the request failed, the PendingVerification
/// account stayed (squatting the address), and the two arms answered
/// differently — an enumeration oracle.
#[test]
fn registration_checks_the_breach_list_before_creating_the_account() {
    let (_dir, engine, _clock) = setup_engine();
    let engine = engine.with_hibp_transport(Arc::new(AlwaysPwned));
    let realm = realm_with(
        &engine,
        RealmConfig {
            registration_policy: Some(RegistrationPolicy::Open),
            breach_check: crate::identity::BreachCheckConfig {
                enabled: true,
                ..Default::default()
            },
            ..RealmConfig::default()
        },
    );
    let fresh = format!("fresh-{}@example.com", uuid::Uuid::new_v4().simple());
    let err = engine
        .register_user(
            &realm,
            &RegisterUserRequest {
                email: fresh.clone(),
                display_name: "Fresh".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                password: CleartextPassword::from_string(PASSWORD.to_string()),
                client_ip: None,
                invitation_token: None,
            },
        )
        .expect_err("a breached password is refused");
    assert!(
        matches!(err, IdentityError::PasswordCompromised),
        "got {err:?}"
    );
    assert!(
        engine
            .get_user_by_email(&realm, &fresh)
            .expect("lookup")
            .is_none(),
        "no account may be left behind for the refused registration"
    );

    // A registered address answers the same way, so the refusal is no oracle.
    let existing = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("taken-{}@example.com", uuid::Uuid::new_v4().simple()),
                display_name: "Taken".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    let err = engine
        .register_user(
            &realm,
            &RegisterUserRequest {
                email: existing.email().to_string(),
                display_name: "Taken".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                password: CleartextPassword::from_string(PASSWORD.to_string()),
                client_ip: None,
                invitation_token: None,
            },
        )
        .expect_err("a breached password is refused for a registered address too");
    assert!(
        matches!(err, IdentityError::PasswordCompromised),
        "got {err:?}"
    );
}

// ─── L14: the unknown-account arm pays the realm's KDF cost ─────────────────

/// A realm with a raised Argon2 cost verifies real users at that cost. The
/// unknown-account arm of the step-up grant used the engine's global dummy
/// hash, which is cheaper, so an address with no account answered measurably
/// faster. With the realm's own dummy the two arms cost the same.
#[test]
fn the_unknown_account_arm_pays_the_realms_kdf_cost() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = realm_with(
        &engine,
        RealmConfig {
            password_memory_cost: Some(16 * 1024),
            password_time_cost: Some(2),
            ..RealmConfig::default()
        },
    );
    let user = user_with_password(&engine, &realm);
    // The known account is given its real password, so it pays exactly one
    // verify at the realm's cost and never trips the per-account lockout.
    let grant = |email: &str| crate::identity::oidc::StepUpMfaGrantRequest {
        email: email.to_string(),
        password: PASSWORD.to_string(),
        mfa_code: "000000".to_string(),
        scope: None,
        client_ip: None,
        user_agent: None,
    };

    // Warm both paths once (the realm dummy hash is computed lazily).
    let _ = engine.step_up_mfa_grant_token(&realm, &grant("nobody@example.com"));
    let _ = engine.step_up_mfa_grant_token(&realm, &grant(user.email()));

    let time = |email: &str| {
        let start = std::time::Instant::now();
        let _ = engine.step_up_mfa_grant_token(&realm, &grant(email));
        start.elapsed()
    };
    let known = (0..3).map(|_| time(user.email())).min().expect("samples");
    let unknown = (0..3)
        .map(|_| time("nobody@example.com"))
        .min()
        .expect("samples");
    assert!(
        unknown * 3 >= known,
        "an unknown address must cost about what a known one does: \
         known={known:?} unknown={unknown:?}"
    );
}
