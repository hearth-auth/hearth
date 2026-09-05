//! Named adversarial tests for HEA-330 — test pyramid gaps.
//!
//! ## Coverage matrix
//!
//! | Threat scenario | Named test in this file | Related tests elsewhere |
//! |---|---|---|
//! | Timing attack — user enumeration via credential error type | `timing_attack_*` | — |
//! | Account lockout — brute-force protection | `account_lockout_*` | — |
//! | Mass enumeration via admin listing — timing | `admin_listing_response_time_constant_wrt_user_count` | — |
//! | User enumeration — magic link | — | `magic_link::magic_link_enumeration_resistance` |
//! | TLS downgrade prevention | — | `tls::tls_downgrade_prevention_rejects_tls10` |
//! | Privilege escalation (RBAC enforcement) | — | `admin_rbac_auth::permission_gated_denies_non_admin` |

mod common;

use std::sync::Arc;

use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, IdentityError, RateLimitConfig,
};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Builds a synchronous identity engine with the given `max_failed_attempts`.
fn build_engine(max_attempts: u32) -> (impl IdentityEngine, tempfile::TempDir) {
    let temp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().to_path_buf()))
            .expect("storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let engine = EmbeddedIdentityEngine::with_rbac(
        storage,
        clock,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            rate_limit: RateLimitConfig {
                max_failed_attempts: max_attempts,
                lockout_duration_micros: 15 * 60 * 1_000_000,
                ..RateLimitConfig::default()
            },
            ..IdentityConfig::default()
        },
        rbac as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
    )
    .expect("engine");
    (engine, temp)
}

fn make_realm(engine: &impl IdentityEngine) -> RealmId {
    engine
        .create_realm(&CreateRealmRequest {
            name: format!("adv-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn new_user_req(prefix: &str) -> CreateUserRequest {
    CreateUserRequest {
        email: format!("{prefix}-{}@test.example", uuid::Uuid::new_v4()),
        display_name: prefix.to_string(),
        first_name: String::new(),
        last_name: String::new(),
        attributes: Default::default(),
    }
}

// ── Timing attack: user enumeration via credential verify ────────────────────

/// Vulnerability class: User Enumeration via `verify_password` (timing)
///
/// When called for a completely nonexistent user ID, `verify_password` must
/// return `InvalidCredential` — the same error variant as a wrong password.
/// Returning a distinct variant (e.g. `UserNotFound`) leaks user existence.
///
/// Defense: the engine performs a dummy hash comparison even when no record
/// is found, keeping timing indistinguishable and returning a uniform error.
#[test]
fn timing_attack_password_verify_nonexistent_user_identical_error() {
    let (engine, _tmp) = build_engine(5);
    let realm = make_realm(&engine);
    let nonexistent = UserId::generate();
    let pw = CleartextPassword::from_string("any-password".to_string());

    let err = engine
        .verify_password(&realm, &nonexistent, &pw)
        .expect_err("must fail for nonexistent user");

    assert!(
        matches!(err, IdentityError::InvalidCredential { .. }),
        "nonexistent user must return InvalidCredential (not UserNotFound): {err:?}"
    );
}

/// Vulnerability class: User Enumeration via `verify_password` (no credential)
///
/// A user who exists but has no password set must return `InvalidCredential`,
/// not a distinct error (e.g. `CredentialNotFound`). The error type must be
/// identical to a wrong-password failure so callers cannot distinguish the
/// two cases.
#[test]
fn timing_attack_password_verify_no_credential_identical_error() {
    let (engine, _tmp) = build_engine(5);
    let realm = make_realm(&engine);
    let user = engine
        .create_user(&realm, &new_user_req("timing-nocred"))
        .expect("create user");
    let pw = CleartextPassword::from_string("any-password".to_string());

    let err = engine
        .verify_password(&realm, user.id(), &pw)
        .expect_err("must fail — no credential set");

    assert!(
        matches!(err, IdentityError::InvalidCredential { .. }),
        "user with no credential must return InvalidCredential: {err:?}"
    );
}

/// Structural invariant: both code paths (nonexistent user, no credential)
/// return the same `InvalidCredential` variant, preventing discrimination.
#[test]
fn timing_attack_both_failure_paths_return_same_error_variant() {
    let (engine, _tmp) = build_engine(5);
    let realm = make_realm(&engine);
    let pw = CleartextPassword::from_string("pw".to_string());

    // Path A: user does not exist at all.
    let err_nonexistent = engine
        .verify_password(&realm, &UserId::generate(), &pw)
        .expect_err("nonexistent path");

    // Path B: user exists, no credential set.
    let user = engine
        .create_user(&realm, &new_user_req("timing-both"))
        .expect("create user");
    let err_no_cred = engine
        .verify_password(&realm, user.id(), &pw)
        .expect_err("no-credential path");

    // Both must be InvalidCredential — same discriminant.
    assert!(
        matches!(err_nonexistent, IdentityError::InvalidCredential { .. }),
        "nonexistent path must return InvalidCredential: {err_nonexistent:?}"
    );
    assert!(
        matches!(err_no_cred, IdentityError::InvalidCredential { .. }),
        "no-credential path must return InvalidCredential: {err_no_cred:?}"
    );
}

// ── Account lockout: brute-force protection ───────────────────────────────────

/// Vulnerability class: Brute-Force Password Attack
///
/// After `max_failed_attempts` consecutive wrong-password calls the account
/// must be locked — subsequent calls return `RateLimited` regardless of the
/// password supplied, preventing automated credential guessing.
#[test]
fn account_lockout_blocks_after_n_failures() {
    const MAX: u32 = 3;
    let (engine, _tmp) = build_engine(MAX);
    let realm = make_realm(&engine);

    let user = engine
        .create_user(&realm, &new_user_req("lockout"))
        .expect("create user");
    engine
        .set_password(
            &realm,
            user.id(),
            &CleartextPassword::from_string("correct-pass-1!".to_string()),
        )
        .expect("set password");

    let wrong = CleartextPassword::from_string("wrong1111".to_string());

    // First MAX wrong attempts return Ok(false) — the attempt counter increments
    // on each false verification, but the lockout is not yet applied.
    for attempt in 1..=MAX {
        let result = engine.verify_password(&realm, user.id(), &wrong);
        assert!(
            matches!(result, Ok(false)),
            "attempt {attempt}: expected Ok(false) pre-lockout, got {result:?}"
        );
    }

    // The (MAX+1)th attempt — same wrong password — must now be locked out.
    let result = engine.verify_password(&realm, user.id(), &wrong);
    assert!(
        matches!(result, Err(IdentityError::RateLimited)),
        "after {MAX} failures expected RateLimited; got: {result:?}"
    );
}

/// Lockout blocks even the correct password during the lockout window,
/// preventing "keep guessing until the right answer slips through" attacks.
#[test]
fn account_lockout_blocks_correct_password_during_window() {
    const MAX: u32 = 3;
    let (engine, _tmp) = build_engine(MAX);
    let realm = make_realm(&engine);

    let user = engine
        .create_user(&realm, &new_user_req("lockout-correct"))
        .expect("create user");
    let correct = CleartextPassword::from_string("correct-pass-1!".to_string());
    engine
        .set_password(&realm, user.id(), &correct)
        .expect("set password");

    // Exhaust the attempt budget.
    let wrong = CleartextPassword::from_string("wrong1111".to_string());
    for _ in 0..MAX {
        let _ = engine.verify_password(&realm, user.id(), &wrong);
    }

    // Even the correct password must be blocked during the lockout window.
    let result = engine.verify_password(&realm, user.id(), &correct);
    assert!(
        matches!(result, Err(IdentityError::RateLimited)),
        "correct password must be blocked during lockout window: {result:?}"
    );
}

// ── Mass enumeration timing: admin user listing ───────────────────────────────

/// Vulnerability class: Mass Enumeration via Admin User Listing (timing)
///
/// `GET /admin/users` must not enable an attacker to infer realm user counts
/// via response timing.  The non-filter path issues a bounded page scan:
/// Phase 1 does a key-only scan for the total count (O(N_keys) but no value
/// bytes read), then Phase 2 reads exactly `limit` entries.  For realistic
/// realm sizes the Phase-1 overhead must not push the response time beyond a
/// generous ratio relative to an empty realm.
///
/// Test methodology:
/// - 5 warm-up calls (discarded) to stabilise JIT and in-process caches.
/// - 20 timed samples against an empty realm → median_empty.
/// - 50 regular users created in the realm.
/// - 20 timed samples against the populated realm → median_populated.
/// - Ratio bound: median_populated / median_empty < 25×.
///
/// Structural invariant: with `?limit=1` the `items` array always contains at
/// most 1 entry regardless of total user count, confirming pagination bounds
/// the response body independently of realm size.
#[tokio::test]
// The body is one timing methodology — warm-up, two sample sets, and the
// structural pagination check — and splitting it would hide the sequence the
// doc comment above describes. Revealed by the audit's Wave 0: clippy aborted
// on a hard compile error before it ever reached this file (§2.3).
#[allow(clippy::too_many_lines)]
async fn admin_listing_response_time_constant_wrt_user_count() {
    use std::time::Instant;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use hearth::identity::SessionContext;
    use hearth::protocol::http::{router, AppState};
    use hearth::rbac::{AssignRoleRequest, Scope, Subject};
    use tower::ServiceExt as _;

    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed realm roles");

    // Create an admin user with the realm.admin role and issue an access token.
    let admin = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "admin@enum-timing-test.example".into(),
                display_name: "Admin".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");
    let role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("look up realm.admin role")
        .expect("realm.admin must be present after seed_realm");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(admin.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign realm.admin role");
    let session = h
        .identity()
        .create_session(&realm, admin.id(), &SessionContext::default())
        .expect("create admin session");
    let token = h
        .identity()
        .issue_tokens(&realm, admin.id(), session.id())
        .expect("issue admin access token")
        .access_token()
        .to_string();
    let realm_uuid = realm.as_uuid().to_string();

    // Build the router once; clone it per call (Router is Arc-backed and cheap to clone).
    let app = router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));

    let build_req = || {
        Request::builder()
            .method("GET")
            .uri("/admin/users?limit=1")
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Realm-ID", &realm_uuid)
            .body(Body::empty())
            .expect("build list request")
    };

    // Warm-up: 5 discarded calls to stabilise in-process caches.
    for _ in 0..5 {
        app.clone()
            .oneshot(build_req())
            .await
            .expect("warm-up call");
    }

    // Phase 1: baseline timing (admin-only realm, 0 regular users).
    const SAMPLES: usize = 20;
    let mut times_empty: Vec<u128> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t0 = Instant::now();
        let resp = app
            .clone()
            .oneshot(build_req())
            .await
            .expect("empty sample");
        let elapsed = t0.elapsed().as_micros();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "empty-realm listing must return 200 OK"
        );
        times_empty.push(elapsed);
    }
    times_empty.sort_unstable();
    // Guard against sub-microsecond runs on very fast machines.
    let median_empty = times_empty[SAMPLES / 2].max(1);

    // Populate realm with 50 regular users.
    for i in 0..50u32 {
        h.identity()
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: format!("user{i}@enum-timing-test.example"),
                    display_name: format!("User {i}"),
                    first_name: "User".into(),
                    last_name: i.to_string(),
                    attributes: Default::default(),
                },
            )
            .expect("create regular user");
    }

    // Phase 2: populated timing (51 total users, page_size = 1).
    let mut times_populated: Vec<u128> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t0 = Instant::now();
        let resp = app
            .clone()
            .oneshot(build_req())
            .await
            .expect("populated sample");
        let elapsed = t0.elapsed().as_micros();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "populated-realm listing must return 200 OK"
        );
        times_populated.push(elapsed);
    }
    times_populated.sort_unstable();
    let median_populated = times_populated[SAMPLES / 2];

    // Structural check: page bound is honoured regardless of total user count.
    {
        let resp = app
            .clone()
            .oneshot(build_req())
            .await
            .expect("structural check");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body bytes");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("parse JSON body");
        let items = json["items"].as_array().expect("items must be an array");
        assert!(
            items.len() <= 1,
            "limit=1 must return at most 1 item regardless of realm size; \
             got {}: pagination contract is violated, enabling body-size enumeration",
            items.len()
        );
    }

    // Timing ratio assertion.
    // 25× is a deliberately generous ceiling: well above any realistic
    // constant-page-size scan difference, yet tight enough to catch an
    // O(N)-value regression that would make timing-based count inference feasible.
    // Integer comparison avoids u128-to-f64 precision loss.
    let ceiling = 25 * median_empty;
    assert!(
        median_populated < ceiling,
        "admin listing timing ratio exceeds 25× bound \
         (median_empty={median_empty}µs, median_populated={median_populated}µs, \
         25× ceiling={ceiling}µs). \
         Response time appears to scale with user count, which would enable \
         timing-based mass enumeration attacks against the admin listing endpoint."
    );
}
