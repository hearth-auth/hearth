#![allow(clippy::unwrap_used)]
//! Integration tests for SCIM realm-scoped bearer token authentication.
//!
//! Verifies:
//! 1. A realm-scoped SCIM bearer token (no admin JWT) can provision users.
//! 2. An admin JWT is rejected with 401 when the realm has `scim_bearer_token_hash`
//!    configured (realm-scoped token enforcement is active).
//! 3. An incorrect SCIM bearer token is rejected with 401.
//! 4. The fallback to admin JWT still works when no SCIM token is configured.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, RealmConfig, SessionContext, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

struct Rig {
    app: axum::Router,
    identity: Arc<EmbeddedIdentityEngine>,
    authz: Arc<EmbeddedRbacEngine>,
    _storage: Arc<EmbeddedStorageEngine>,
    _dir: tempfile::TempDir,
}

fn build_rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    );
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let state = Arc::new(AppState::new(identity.clone(), authz.clone(), audit));
    Rig {
        app: router(state),
        identity,
        authz,
        _storage: engine,
        _dir: dir,
    }
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Create a realm with a `scim_bearer_token_hash` configured.
fn setup_realm_with_scim_token(rig: &Rig, name: &str, token: &str) -> RealmId {
    let realm = rig
        .identity
        .create_realm(&CreateRealmRequest {
            name: name.to_string(),
            config: None,
        })
        .expect("create realm");

    rig.identity
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    scim_bearer_token_hash: Some(sha256_hex(token)),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("configure scim token");

    realm.id().clone()
}

/// Create a realm without a SCIM token and provision an admin JWT.
fn setup_realm_with_admin(rig: &Rig, name: &str) -> (RealmId, String) {
    let realm = rig
        .identity
        .create_realm(&CreateRealmRequest {
            name: name.to_string(),
            config: None,
        })
        .expect("create realm");
    let jwt = provision_admin_in_realm(rig, realm.id(), name);
    (realm.id().clone(), jwt)
}

/// Provision a `realm.admin` user in an *existing* realm and return an admin
/// JWT for it. Lets tests obtain a same-realm admin token so a rejection can be
/// attributed to the SCIM-token gate rather than a realm mismatch.
fn provision_admin_in_realm(rig: &Rig, realm_id: &RealmId, name: &str) -> String {
    let user = rig
        .identity
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: format!("admin@{name}.test"),
                display_name: "Admin".to_string(),
                first_name: "Admin".to_string(),
                last_name: "User".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");

    rig.authz.seed_realm(realm_id).expect("seed realm");
    let admin_role = rig
        .authz
        .get_role_by_name(realm_id, "realm.admin")
        .expect("lookup")
        .expect("seed role present");
    rig.authz
        .assign_role(
            realm_id,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(user.id().clone()),
                role_id: admin_role.id.clone(),
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    let session = rig
        .identity
        .create_session(realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let tokens = rig
        .identity
        .issue_tokens(realm_id, user.id(), session.id())
        .expect("tokens");
    tokens.access_token().to_string()
}

async fn post_scim_user(
    app: &axum::Router,
    realm_id: &RealmId,
    auth_header: &str,
    email: &str,
) -> (StatusCode, Value) {
    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": email,
        "name": {"givenName": "Test", "familyName": "User"},
        "emails": [{"value": email, "primary": true}],
    });
    let req = Request::builder()
        .method("POST")
        .uri("/scim/v2/Users")
        .header("content-type", "application/scim+json")
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .header("authorization", auth_header)
        .body(Body::from(body.to_string()))
        .expect("build request");

    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

/// A realm-scoped SCIM bearer token can provision users without an admin JWT.
#[tokio::test]
async fn scim_bearer_token_provisions_users() {
    const PLAINTEXT_TOKEN: &str = "super-secret-scim-service-account-token-32chars";

    let rig = build_rig();
    let realm_id = setup_realm_with_scim_token(&rig, "scim-bearer-test", PLAINTEXT_TOKEN);

    let auth_header = format!("Bearer {PLAINTEXT_TOKEN}");

    let (status, body) =
        post_scim_user(&rig.app, &realm_id, &auth_header, "provisioned@example.com").await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "SCIM bearer token should provision a user (got {status}): {body}"
    );
    assert_eq!(
        body.get("userName").and_then(Value::as_str),
        Some("provisioned@example.com"),
        "Response should echo the provisioned user's userName"
    );
}

/// Admin JWT is rejected with 401 when the realm has a `scim_bearer_token_hash`
/// configured — realm-scoped token enforcement is active.
///
/// The admin JWT is minted for the *same* realm that enforces the SCIM token,
/// so a 401 is attributable to the SCIM-token gate rather than a cross-realm
/// mismatch (which `scim_jwt_fallback_rejects_cross_realm_jwt` covers).
#[tokio::test]
async fn admin_jwt_rejected_when_scim_token_enforced() {
    const PLAINTEXT_TOKEN: &str = "another-secret-scim-token-for-enforcement-test";

    let rig = build_rig();
    let realm_id = setup_realm_with_scim_token(&rig, "scim-enforce-test", PLAINTEXT_TOKEN);

    // Mint a valid admin JWT for THIS realm. Because the realm enforces a SCIM
    // bearer token, even a legitimate same-realm admin JWT must be rejected —
    // isolating the SCIM-token gate from any realm-mismatch rejection.
    let admin_jwt = provision_admin_in_realm(&rig, &realm_id, "scim-enforce-test");

    let admin_header = format!("Bearer {admin_jwt}");
    let (status, _) = post_scim_user(
        &rig.app,
        &realm_id,
        &admin_header,
        "should-fail@example.com",
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Same-realm admin JWT must be rejected (401) when realm-scoped SCIM token is enforced (got {status})"
    );
}

/// An incorrect SCIM bearer token is rejected with 401.
#[tokio::test]
async fn wrong_scim_bearer_token_rejected() {
    const REAL_TOKEN: &str = "real-scim-service-token-correct-32chars-long";
    const WRONG_TOKEN: &str = "wrong-scim-token-that-does-not-match-at-all";

    let rig = build_rig();
    let realm_id = setup_realm_with_scim_token(&rig, "scim-wrong-token-test", REAL_TOKEN);
    let wrong_header = format!("Bearer {WRONG_TOKEN}");

    let (status, _) = post_scim_user(
        &rig.app,
        &realm_id,
        &wrong_header,
        "should-fail@example.com",
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Incorrect SCIM bearer token must be rejected with 401 (got {status})"
    );
}

/// L13: A JWT issued for realm A must be rejected when the X-Realm-ID header
/// identifies realm B (which has no SCIM bearer token configured and therefore
/// falls through to the JWT fallback path). The realm mismatch guard in the
/// JWT fallback branch must prevent cross-realm SCIM access.
///
/// In practice this is caught at JWT-signature validation (401), but the test
/// exercises the security boundary regardless of which layer rejects first.
#[tokio::test]
async fn scim_jwt_fallback_rejects_cross_realm_jwt() {
    let rig = build_rig();

    // Realm A: obtain a valid admin JWT.
    let (_, realm_a_jwt) = setup_realm_with_admin(&rig, "scim-crossrealm-a");

    // Realm B: no SCIM bearer token configured → falls into JWT fallback.
    let realm_b = rig
        .identity
        .create_realm(&CreateRealmRequest {
            name: "scim-crossrealm-b".to_string(),
            config: None,
        })
        .expect("create realm B");

    // Send realm A's JWT to realm B's SCIM endpoint via X-Realm-ID: realm B.
    let auth_header = format!("Bearer {realm_a_jwt}");
    let (status, _) = post_scim_user(
        &rig.app,
        realm_b.id(),
        &auth_header,
        "should-fail@example.com",
    )
    .await;

    assert!(
        !status.is_success(),
        "JWT from realm A must not grant SCIM access to realm B (got {status})"
    );
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "Expected 401 or 403 for cross-realm JWT attempt (got {status})"
    );
}

/// When no SCIM token is configured, admin JWT is still accepted as a fallback.
#[tokio::test]
async fn admin_jwt_accepted_as_fallback_without_scim_token() {
    let rig = build_rig();
    let (realm_id, admin_jwt) = setup_realm_with_admin(&rig, "scim-fallback-test");
    let auth_header = format!("Bearer {admin_jwt}");

    let (status, _) =
        post_scim_user(&rig.app, &realm_id, &auth_header, "fallback@example.com").await;

    assert!(
        status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
        "Admin JWT must be accepted when no SCIM token is configured (got {status})"
    );
}

/// JWT fallback path rejects a JWT issued for realm-A when `X-Realm-ID` is realm-B.
///
/// The SCIM auth layer must not permit cross-realm privilege escalation even on
/// the JWT fallback path. Rejection may come from the `tid` claim check inside
/// `validate_token` (401) or the explicit SCIM realm-mismatch guard (403) —
/// either counts as a successful defence.
#[tokio::test]
async fn scim_jwt_fallback_rejects_mismatched_realm_header() {
    let rig = build_rig();

    // realm_a has a valid admin JWT; realm_b has no SCIM token configured.
    let (realm_a, admin_jwt_a) = setup_realm_with_admin(&rig, "scim-mismatch-realm-a");
    let (realm_b, _) = setup_realm_with_admin(&rig, "scim-mismatch-realm-b");

    // Sanity: JWT for realm_a works against realm_a.
    let (ok_status, _) = post_scim_user(
        &rig.app,
        &realm_a,
        &format!("Bearer {admin_jwt_a}"),
        "good@example.com",
    )
    .await;
    assert!(
        ok_status.is_success(),
        "JWT for realm_a must work against realm_a (got {ok_status})"
    );

    // Attack: send realm_a's JWT but claim to operate on realm_b via the header.
    let (bad_status, _) = post_scim_user(
        &rig.app,
        &realm_b,
        &format!("Bearer {admin_jwt_a}"),
        "evil@example.com",
    )
    .await;

    assert!(
        bad_status.is_client_error(),
        "JWT for realm_a must be rejected when X-Realm-ID is realm_b (got {bad_status}); \
         expected 401 (tid mismatch) or 403 (SCIM realm guard)"
    );
}

/// Send a SCIM PATCH with `op_count` operations to `/scim/v2/Users/{user_id}`.
async fn patch_scim_user(
    app: &axum::Router,
    realm_id: &RealmId,
    auth_header: &str,
    user_id: &str,
    op_count: usize,
) -> (StatusCode, Value) {
    let ops: Vec<Value> = (0..op_count)
        .map(|_| json!({"op": "replace", "path": "displayName", "value": "x"}))
        .collect();
    let body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": ops,
    });
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/scim/v2/Users/{user_id}"))
        .header("content-type", "application/scim+json")
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .header("authorization", auth_header)
        .body(Body::from(body.to_string()))
        .expect("build request");

    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

/// A-35a: a SCIM PATCH whose `Operations` array exceeds `MAX_SCIM_OPERATIONS`
/// is rejected with 413 *before* any operation is applied. Exercises the real
/// handler-level cap, not just the exported constant.
#[tokio::test]
async fn scim_patch_over_operation_cap_rejected() {
    use hearth::abuse::MAX_SCIM_OPERATIONS;

    const PLAINTEXT_TOKEN: &str = "scim-token-for-patch-cap-enforcement-testing";

    let rig = build_rig();
    let realm_id = setup_realm_with_scim_token(&rig, "scim-patch-cap", PLAINTEXT_TOKEN);
    let auth_header = format!("Bearer {PLAINTEXT_TOKEN}");

    // Provision a user to PATCH.
    let (create_status, created) =
        post_scim_user(&rig.app, &realm_id, &auth_header, "patchee@example.com").await;
    assert_eq!(
        create_status,
        StatusCode::CREATED,
        "precondition: user must be provisioned (got {create_status}): {created}"
    );
    let user_id = created
        .get("id")
        .and_then(Value::as_str)
        .expect("created user must carry an id");

    // Just under the cap: accepted (not a 413).
    let (ok_status, _) = patch_scim_user(
        &rig.app,
        &realm_id,
        &auth_header,
        user_id,
        MAX_SCIM_OPERATIONS,
    )
    .await;
    assert_ne!(
        ok_status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a PATCH at exactly the cap must not be rejected as too large (got {ok_status})"
    );

    // One over the cap: rejected with 413.
    let (over_status, over_body) = patch_scim_user(
        &rig.app,
        &realm_id,
        &auth_header,
        user_id,
        MAX_SCIM_OPERATIONS + 1,
    )
    .await;
    assert_eq!(
        over_status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "PATCH with {} operations must be rejected with 413 (got {over_status}): {over_body}",
        MAX_SCIM_OPERATIONS + 1
    );
}
