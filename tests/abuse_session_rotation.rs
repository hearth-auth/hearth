//! Integration tests for A-41 (session-ID rotation on auth events) and
//! A-42 (sensitive-mutation mass-revocation).
//!
//! D-4 taxonomy: adversarial (A-41) + integration (A-42).
//!
//! Plan sections §3.44 (session fixation) and §3.45 (password-change
//! mass-revocation) from `docs/plans/HEA-1114-abuse-prevention.md`.

mod common;

use hearth::identity::{CleartextPassword, CreateUserRequest, SessionContext, UpdateUserRequest};

// ─────────────────────────────────────────────────────────────────────────────
// A-41 — Session-ID rotation: old session must not survive re-auth
// ─────────────────────────────────────────────────────────────────────────────

/// A pre-planted session cookie that exists before login must be revoked when
/// the user authenticates anew.  The web handlers call `revoke_session` on any
/// existing session ID parsed from the incoming cookie before calling
/// `create_session`; this test verifies the engine correctly removes it.
#[tokio::test]
async fn a41_pre_planted_session_revoked_on_re_auth() {
    let harness = common::TestHarness::embedded().await.expect("setup");
    let realm = harness.create_realm();
    let pw = CleartextPassword::from_string("Hunter2!!abcd".to_string());

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("alice-{}@session-rotation.test", uuid::Uuid::new_v4()),
                display_name: "Alice".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    harness
        .identity()
        .set_password(&realm, user.id(), &pw)
        .expect("set password");

    // 1. Attacker plants a session as if the user was already logged in.
    let old_session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("plant session");
    assert!(
        harness
            .identity()
            .get_session(&realm, old_session.id())
            .expect("get planted")
            .is_some(),
        "planted session must be valid before re-auth"
    );

    // 2. Simulate the login-handler rotation: revoke the old session before
    //    minting the new one.  This is exactly what `revoke_prior_session_cookie`
    //    does in `src/protocol/web/handlers.rs`.
    harness
        .identity()
        .revoke_session(&realm, old_session.id())
        .expect("revoke old session on re-auth");

    // 3. Create the fresh session (result of successful login).
    let new_session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("new session");
    assert_ne!(
        old_session.id(),
        new_session.id(),
        "new session must have a different ID"
    );

    // 4. Old session must be dead — the planted cookie cannot be replayed.
    assert!(
        harness
            .identity()
            .get_session(&realm, old_session.id())
            .expect("get old")
            .is_none(),
        "pre-planted session must not survive re-auth"
    );

    // 5. New session must be valid.
    assert!(
        harness
            .identity()
            .get_session(&realm, new_session.id())
            .expect("get new")
            .is_some(),
        "new session must be valid after login"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-42 — revoke_all_user_sessions: basic correctness
// ─────────────────────────────────────────────────────────────────────────────

/// Mass-revocation without a `keep` parameter revokes every live session.
#[tokio::test]
async fn a42_revoke_all_user_sessions_revokes_all() {
    let harness = common::TestHarness::embedded().await.expect("setup");
    let realm = harness.create_realm();

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("bob-{}@mass-revoc.test", uuid::Uuid::new_v4()),
                display_name: "Bob".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let s1 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s1");
    let s2 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s2");
    let s3 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s3");

    let count = harness
        .identity()
        .revoke_all_user_sessions(&realm, user.id(), None)
        .expect("revoke_all");
    assert_eq!(count, 3, "all three sessions must be counted as revoked");

    for (label, sid) in [("s1", s1.id()), ("s2", s2.id()), ("s3", s3.id())] {
        assert!(
            harness
                .identity()
                .get_session(&realm, sid)
                .expect("get")
                .is_none(),
            "{label} must be revoked"
        );
    }
}

/// Mass-revocation with a `keep` session-ID spares that session.
#[tokio::test]
async fn a42_revoke_all_user_sessions_keeps_specified_session() {
    let harness = common::TestHarness::embedded().await.expect("setup");
    let realm = harness.create_realm();

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("carol-{}@mass-revoc.test", uuid::Uuid::new_v4()),
                display_name: "Carol".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let current = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("current");
    let other_a = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("other_a");
    let other_b = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("other_b");

    let count = harness
        .identity()
        .revoke_all_user_sessions(&realm, user.id(), Some(current.id()))
        .expect("revoke_all with keep");
    assert_eq!(count, 2, "two other sessions must be revoked");

    assert!(
        harness
            .identity()
            .get_session(&realm, current.id())
            .expect("get current")
            .is_some(),
        "kept session must still be valid"
    );
    for (label, sid) in [("other_a", other_a.id()), ("other_b", other_b.id())] {
        assert!(
            harness
                .identity()
                .get_session(&realm, sid)
                .expect("get")
                .is_none(),
            "{label} must be revoked"
        );
    }
}

/// Mass-revocation on a user with no sessions returns `Ok(0)`.
#[tokio::test]
async fn a42_revoke_all_user_sessions_no_sessions_is_noop() {
    let harness = common::TestHarness::embedded().await.expect("setup");
    let realm = harness.create_realm();

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("dave-{}@mass-revoc.test", uuid::Uuid::new_v4()),
                display_name: "Dave".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let count = harness
        .identity()
        .revoke_all_user_sessions(&realm, user.id(), None)
        .expect("revoke_all on empty");
    assert_eq!(count, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// A-42 — Sensitive mutations trigger mass-revocation
// ─────────────────────────────────────────────────────────────────────────────

/// `set_password` revokes all sessions for the user.
#[tokio::test]
async fn a42_set_password_revokes_all_sessions() {
    let harness = common::TestHarness::embedded().await.expect("setup");
    let realm = harness.create_realm();
    let pw_a = CleartextPassword::from_string("OldPass1!abc".to_string());
    let pw_b = CleartextPassword::from_string("NewPass2!xyz".to_string());

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("eve-{}@revoc-set.test", uuid::Uuid::new_v4()),
                display_name: "Eve".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    harness
        .identity()
        .set_password(&realm, user.id(), &pw_a)
        .expect("set initial password");

    let s1 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s1");
    let s2 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s2");

    harness
        .identity()
        .set_password(&realm, user.id(), &pw_b)
        .expect("set new password");

    for (label, sid) in [("s1", s1.id()), ("s2", s2.id())] {
        assert!(
            harness
                .identity()
                .get_session(&realm, sid)
                .expect("get")
                .is_none(),
            "{label} must be revoked after set_password"
        );
    }
}

/// `change_password` revokes all sessions for the user.
#[tokio::test]
async fn a42_change_password_revokes_all_sessions() {
    let harness = common::TestHarness::embedded().await.expect("setup");
    let realm = harness.create_realm();
    let old_pw = CleartextPassword::from_string("OldSecret1!abc".to_string());
    let new_pw = CleartextPassword::from_string("NewSecret2!xyz".to_string());

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("frank-{}@revoc-change.test", uuid::Uuid::new_v4()),
                display_name: "Frank".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    harness
        .identity()
        .set_password(&realm, user.id(), &old_pw)
        .expect("set password");

    let s1 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s1");
    let s2 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s2");

    harness
        .identity()
        .change_password(&realm, user.id(), &old_pw, &new_pw)
        .expect("change_password");

    for (label, sid) in [("s1", s1.id()), ("s2", s2.id())] {
        assert!(
            harness
                .identity()
                .get_session(&realm, sid)
                .expect("get")
                .is_none(),
            "{label} must be revoked after change_password"
        );
    }
}

/// `disable_mfa` revokes all sessions for the user.
#[tokio::test]
async fn a42_disable_mfa_revokes_all_sessions() {
    let harness = common::TestHarness::embedded().await.expect("setup");
    let realm = harness.create_realm();

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("grace-{}@revoc-mfa.test", uuid::Uuid::new_v4()),
                display_name: "Grace".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    // Enroll TOTP so disable_mfa has something to disable.
    let enrollment = harness
        .identity()
        .enroll_totp(&realm, user.id())
        .expect("enroll_totp");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    // Confirm enrollment; retry with next step on replay-protection hit.
    if harness
        .identity()
        .verify_totp_enrollment(&realm, user.id(), &code)
        .is_err()
    {
        let code2 = compute_totp_code(&enrollment.secret_base32, now_secs + 30);
        harness
            .identity()
            .verify_totp_enrollment(&realm, user.id(), &code2)
            .expect("verify_totp_enrollment retry");
    }

    let s1 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s1");
    let s2 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s2");

    harness
        .identity()
        .disable_mfa(&realm, user.id())
        .expect("disable_mfa");

    for (label, sid) in [("s1", s1.id()), ("s2", s2.id())] {
        assert!(
            harness
                .identity()
                .get_session(&realm, sid)
                .expect("get")
                .is_none(),
            "{label} must be revoked after disable_mfa"
        );
    }
}

/// Email change (via `update_user`) revokes all sessions for the user.
#[tokio::test]
async fn a42_email_change_revokes_all_sessions() {
    let harness = common::TestHarness::embedded().await.expect("setup");
    let realm = harness.create_realm();

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("heidi-{}@revoc-email.test", uuid::Uuid::new_v4()),
                display_name: "Heidi".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let s1 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s1");
    let s2 = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("s2");

    harness
        .identity()
        .update_user(
            &realm,
            user.id(),
            &UpdateUserRequest {
                email: Some(format!(
                    "heidi-new-{}@revoc-email.test",
                    uuid::Uuid::new_v4()
                )),
                ..Default::default()
            },
        )
        .expect("update email");

    for (label, sid) in [("s1", s1.id()), ("s2", s2.id())] {
        assert!(
            harness
                .identity()
                .get_session(&realm, sid)
                .expect("get")
                .is_none(),
            "{label} must be revoked after email change"
        );
    }
}

/// A display-name-only `update_user` (no email change) must NOT revoke sessions.
#[tokio::test]
async fn a42_non_email_update_user_does_not_revoke_sessions() {
    let harness = common::TestHarness::embedded().await.expect("setup");
    let realm = harness.create_realm();

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("ivan-{}@no-revoc.test", uuid::Uuid::new_v4()),
                display_name: "Ivan".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let session = harness
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");

    harness
        .identity()
        .update_user(
            &realm,
            user.id(),
            &UpdateUserRequest {
                display_name: Some("Ivan Updated".to_string()),
                ..Default::default()
            },
        )
        .expect("update display name");

    assert!(
        harness
            .identity()
            .get_session(&realm, session.id())
            .expect("get")
            .is_some(),
        "session must survive a display-name-only update_user"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Computes a 6-digit TOTP code from a base32 secret and a Unix timestamp,
/// using the same HMAC-SHA1 algorithm as the identity engine.
fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32 secret");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let msg = step.to_be_bytes();
    let tag = ring::hmac::sign(&key, &msg);
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
