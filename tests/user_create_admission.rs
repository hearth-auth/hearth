//! User creation has its own admission limit (#446).
//!
//! Creating a user hashes no password, so it takes no KDF permit (#439). That
//! left creates with no concurrency limit: under overload they queued in the
//! blocking pool that logins share. Every REST and SCIM create route now takes
//! a permit from the user-create gate first. With the gate full, the next
//! create answers `503` with `Retry-After` once the queue wait passes, and
//! the same create succeeds as soon as a permit is free again.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext, UserCreateGateConfig};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

const QUEUE_WAIT: Duration = Duration::from_millis(100);

async fn admin_token(harness: &common::TestHarness, realm: &RealmId) -> String {
    let user = harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "admin@test.example".into(),
                display_name: "Admin User".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");
    let role = harness
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin seeded");
    harness
        .rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");
    let session = harness
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    harness
        .identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

/// One create request per entry point. `i` keeps the addresses unique.
fn create_requests(realm: &RealmId, token: &str, i: usize) -> Vec<(&'static str, Request<Body>)> {
    let post = |uri: &str, content_type: &str, body: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Realm-ID", realm.as_uuid().to_string())
            .header("Content-Type", content_type)
            .body(Body::from(body.to_string()))
            .expect("request")
    };
    let user = |route: &str| {
        serde_json::json!({
            "email": format!("{route}{i}@example.com"),
            "display_name": format!("{route} {i}"),
        })
    };
    vec![
        (
            "POST /admin/users",
            post("/admin/users", "application/json", user("admin")),
        ),
        (
            "POST /users",
            post("/users", "application/json", user("api")),
        ),
        (
            "POST /admin/users/bulk",
            post(
                "/admin/users/bulk",
                "application/json",
                serde_json::json!({"operation": "create", "users": [user("bulk")]}),
            ),
        ),
        (
            "POST /admin/users/import",
            post(
                "/admin/users/import",
                "application/json",
                serde_json::json!({"users": [user("import")]}),
            ),
        ),
        (
            "POST /scim/v2/Users",
            post(
                "/scim/v2/Users",
                "application/scim+json",
                serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": format!("scim{i}@example.com"),
                    "name": {"givenName": "Scim", "familyName": "User"},
                    "emails": [{"value": format!("scim{i}@example.com"), "primary": true}],
                    "active": true
                }),
            ),
        ),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_user_create_limit_sheds_every_create_route_with_503_and_retry_after() {
    // nextest runs this in its own process, so it wins the OnceLock.
    assert!(hearth::identity::init_user_create_gate(
        UserCreateGateConfig {
            max_in_flight: 1,
            max_queue_wait: QUEUE_WAIT,
            retry_after: Duration::from_secs(3),
        }
    ));
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let app = router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));

    // Hold the gate's only permit, as an in-flight create would.
    let held = hearth::identity::user_create_gate()
        .admit()
        .await
        .expect("the holder is admitted");

    let mut shed = Vec::new();
    for (route, req) in create_requests(&realm, &token, 0) {
        let start = Instant::now();
        let resp = app.clone().oneshot(req).await.expect("response");
        let elapsed = start.elapsed();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        shed.push((route, resp.status(), retry_after, elapsed));
    }
    assert!(
        shed.iter().all(|(_, status, retry_after, _)| {
            *status == StatusCode::SERVICE_UNAVAILABLE && retry_after.as_deref() == Some("3")
        }),
        "every create route must answer 503 with Retry-After: 3 while the limit is full: {shed:?}"
    );
    for (route, _, _, elapsed) in &shed {
        assert!(
            *elapsed >= QUEUE_WAIT && *elapsed < Duration::from_secs(5),
            "{route}: a shed is answered after the queue wait, not served late (took {elapsed:?})"
        );
    }

    // Free the permit: the same routes now create, so the 503s came from the
    // gate and not from an unrelated failure.
    drop(held);
    let mut served = Vec::new();
    for (route, req) in create_requests(&realm, &token, 1) {
        let resp = app.clone().oneshot(req).await.expect("response");
        served.push((route, resp.status()));
    }
    assert!(
        served
            .iter()
            .all(|(_, status)| *status == StatusCode::CREATED || *status == StatusCode::OK),
        "with a permit free every create route must succeed: {served:?}"
    );
}

/// A web router over one realm (`solo`) with open self-registration. The
/// returned directory holds its storage.
fn registration_rig() -> (axum::Router, tempfile::TempDir) {
    use hearth::core::{Clock, SystemClock};
    use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
    use hearth::identity::onboarding::OnboardingService;
    use hearth::identity::{
        CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
        IdentityEngine, RealmConfig, RegistrationPolicy,
    };
    use hearth::protocol::web::{self, CookieSecret, WebState};
    use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
    use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

    let temp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().to_path_buf()))
            .expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
    identity
        .create_realm(&CreateRealmRequest {
            name: "solo".to_string(),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    let email = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        email,
        temp.path().to_path_buf(),
    ));
    let app = web::router(
        WebState::new(
            identity,
            authz,
            audit,
            onboarding,
            CookieSecret::from_bytes([7u8; 32]),
            None,
        )
        .with_dev_mode(true),
    );
    (app, temp)
}

/// `POST /ui/register` for a fresh address. Dev mode skips the CSRF
/// double-submit check.
fn register(i: usize) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/ui/register")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "email=new{i}%40example.test&display_name=New&\
             password=correct-horse-battery-staple&\
             password_confirm=correct-horse-battery-staple"
        )))
        .expect("request")
}

/// A self-registration creates a user too: with the user-create limit full,
/// `POST /ui/register` is shed with the themed `503` page and `Retry-After`,
/// and goes through once a permit is free. It takes the create permit only
/// once it holds a KDF permit, so it does not wait for one: it is shed at
/// once, not after the user-create queue wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_user_create_limit_sheds_self_registration_with_503_and_retry_after() {
    let create_queue_wait = Duration::from_secs(10);
    assert!(hearth::identity::init_user_create_gate(
        UserCreateGateConfig {
            max_in_flight: 1,
            max_queue_wait: create_queue_wait,
            retry_after: Duration::from_secs(3),
        }
    ));

    let (app, _storage_dir) = registration_rig();

    let held = hearth::identity::user_create_gate()
        .admit()
        .await
        .expect("the holder is admitted");
    let start = Instant::now();
    let resp = app.clone().oneshot(register(0)).await.expect("response");
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("3")
    );
    assert!(
        elapsed < create_queue_wait / 2,
        "a registration holding a KDF permit must not wait for a create permit (took {elapsed:?})"
    );

    drop(held);
    let resp = app.clone().oneshot(register(1)).await.expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "with a permit free the registration goes through to register/sent"
    );
}

/// A registration that waits for a KDF permit holds no user-create permit
/// (#446 review). Holding one there would let a login surge, which fills the
/// KDF queue, use up the create limit and shed admin and SCIM creates that
/// hash nothing. The registration takes its create permit only once it holds
/// a KDF permit, so one that the KDF gate sheds never touches the create gate:
/// no permit taken and no queue wait recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registration_waiting_for_a_kdf_permit_holds_no_user_create_permit() {
    const CREATE_PERMITS: usize = 4;
    assert!(hearth::identity::init_gate(
        hearth::identity::KdfGateConfig {
            max_in_flight: 1,
            max_queue_wait: Duration::from_millis(300),
            retry_after: Duration::from_secs(1),
        }
    ));
    assert!(hearth::identity::init_user_create_gate(
        UserCreateGateConfig {
            max_in_flight: CREATE_PERMITS,
            max_queue_wait: QUEUE_WAIT,
            retry_after: Duration::from_secs(3),
        }
    ));
    let (app, _storage_dir) = registration_rig();
    let create_waits = || {
        hearth::metrics::metrics()
            .user_create_queue_wait_seconds
            .get_sample_count()
    };

    // Hold the only KDF permit until `release` is sent.
    let (release, held_until) = std::sync::mpsc::channel::<()>();
    let (entered, kdf_held) = tokio::sync::oneshot::channel::<()>();
    let holder = tokio::spawn(async move {
        hearth::identity::gate()
            .run(move || {
                let _ = entered.send(());
                let _ = held_until.recv();
            })
            .await
            .expect("the holder is admitted");
    });
    kdf_held.await.expect("the holder holds the KDF permit");

    let resp = app.clone().oneshot(register(0)).await.expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the registration waits out the KDF queue wait and is shed"
    );
    assert_eq!(
        create_waits(),
        0,
        "a registration in the KDF queue must not take or wait for a user-create permit"
    );
    assert_eq!(
        hearth::identity::user_create_gate().available_permits(),
        CREATE_PERMITS
    );

    release.send(()).expect("release the KDF permit");
    holder.await.expect("holder task");
    let resp = app.clone().oneshot(register(1)).await.expect("response");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        create_waits(),
        1,
        "the registration takes its create permit once it holds the KDF permit"
    );
    assert_eq!(
        hearth::identity::user_create_gate().available_permits(),
        CREATE_PERMITS,
        "the registration releases its create permit when it returns"
    );
}
