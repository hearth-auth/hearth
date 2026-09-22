//! 21.11 (audit 2026-08-28 §4.23#10): the pre-auth `/ui/realms/{realm}/*` tree
//! must not answer "does tenant X exist on this deployment?" to an anonymous
//! caller.
//!
//! The audit found a real and a non-existent realm distinguishable by **status
//! and body length** on every pre-auth shape. This file drives the same request
//! twice — once at a realm that exists, once at a fabricated name — and asserts
//! the two responses are byte-identical: same status, same body, and the same
//! set of response header names.
//!
//! Both realms are created with the deployment defaults, which is the property
//! the fix can actually guarantee. A realm that sets its own `web.theme`,
//! `web.product_name` or `logo_url` publishes that branding to anonymous
//! visitors *by design* — that is what per-realm branding is for — and is
//! outside what this file claims.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{Clock, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [11u8; 32];

/// A realm that exists on the deployment under test.
const REAL_REALM: &str = "acme-corp";
/// A realm that does not. Same length as `REAL_REALM` so a body that echoes
/// the name cannot differ merely by width.
const FAKE_REALM: &str = "zyxw-corp";

fn null_email_service() -> Arc<EmailService> {
    Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    )
}

/// Builds a two-realm deployment (so no sole-realm shortcut fires) where both
/// realms take the deployment defaults.
fn build_app() -> axum::Router {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
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

    for name in [REAL_REALM, "other-corp"] {
        identity
            .create_realm(&CreateRealmRequest {
                name: name.to_string(),
                config: None,
            })
            .expect("create realm");
    }

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        authz,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    );
    web::router(state)
}

/// One observable response: status, body bytes, and the sorted header names.
struct Observed {
    status: StatusCode,
    body: Vec<u8>,
    header_names: Vec<String>,
}

async fn observe(app: &axum::Router, method: &str, path: &str, form: Option<&str>) -> Observed {
    let mut builder = Request::builder().method(method).uri(path);
    if form.is_some() {
        builder = builder.header("content-type", "application/x-www-form-urlencoded");
    }
    let body = form.map_or_else(Body::empty, |f| Body::from(f.to_string()));
    let resp = app
        .clone()
        .oneshot(builder.body(body).expect("build request"))
        .await
        .expect("send request");
    let status = resp.status();
    let mut header_names: Vec<String> = resp
        .headers()
        .keys()
        .map(|k| k.as_str().to_string())
        .collect();
    header_names.sort_unstable();
    header_names.dedup();
    let bytes = to_bytes(resp.into_body(), 4 << 20).await.expect("body");
    Observed {
        status,
        body: bytes.to_vec(),
        header_names,
    }
}

/// Every pre-auth shape registered under `/ui/realms/{realm}/`, as
/// `(method, path suffix, optional form body)`.
///
/// Kept in the same order as the route table in `protocol::web::router` so a
/// newly added pre-auth realm route is easy to mirror here.
const PRE_AUTH_SHAPES: &[(&str, &str, Option<&str>)] = &[
    ("GET", "/login", None),
    ("POST", "/login", Some("email=a%40b.test&password=hunter2")),
    ("GET", "/login/passkey-begin", None),
    ("POST", "/login/passkey-complete", Some("credential=%7B%7D")),
    ("GET", "/register", None),
    (
        "POST",
        "/register",
        Some("email=a%40b.test&password=hunter2hunter2"),
    ),
    ("GET", "/register/sent", None),
    ("GET", "/forgot-password", None),
    ("POST", "/forgot-password", Some("email=a%40b.test")),
    ("GET", "/forgot-password/sent", None),
    ("GET", "/reset-password?token=nope", None),
    (
        "POST",
        "/reset-password",
        Some("token=nope&password=hunter2hunter2"),
    ),
    ("GET", "/magic-link?token=nope", None),
    ("GET", "/verify-email?token=nope", None),
    ("GET", "/accept-invitation?token=nope", None),
    ("GET", "/federation/begin?idp=nope", None),
    ("GET", "/federation/callback?state=nope&code=nope", None),
    ("GET", "/federation/saml/metadata?idp=nope", None),
    ("GET", "/federation/saml/begin?idp=nope", None),
    ("POST", "/federation/saml/acs", Some("SAMLResponse=nope")),
    ("GET", "/saml/metadata", None),
    ("GET", "/saml/sso?SAMLRequest=nope", None),
    ("GET", "/saml/sso/init?sp=nope", None),
    ("GET", "/saml/slo-idp?SAMLRequest=nope", None),
    ("GET", "/oauth/authorize?client_id=nope", None),
];

/// Returns the shapes on which a real and a fabricated realm are
/// distinguishable, with a short description of how.
async fn distinguishing_shapes() -> Vec<String> {
    let app = build_app();
    let mut leaks = Vec::new();
    for &(method, suffix, form) in PRE_AUTH_SHAPES {
        let real = observe(
            &app,
            method,
            &format!("/ui/realms/{REAL_REALM}{suffix}"),
            form,
        )
        .await;
        let fake = observe(
            &app,
            method,
            &format!("/ui/realms/{FAKE_REALM}{suffix}"),
            form,
        )
        .await;

        if real.status != fake.status {
            leaks.push(format!(
                "{method} {suffix}: status {} vs {}",
                real.status, fake.status
            ));
        } else if real.body != fake.body {
            leaks.push(format!(
                "{method} {suffix}: body {} vs {} bytes",
                real.body.len(),
                fake.body.len()
            ));
        } else if real.header_names != fake.header_names {
            leaks.push(format!(
                "{method} {suffix}: header names {:?} vs {:?}",
                real.header_names, fake.header_names
            ));
        }
    }
    leaks
}

/// The oracle itself. A real and a fabricated realm name must produce
/// byte-identical responses on every pre-auth shape.
///
/// **Currently ignored — this is the acceptance criterion for the unfinished
/// half of task 21.11, not a passing property.** Closing it requires the
/// unknown-realm arm of `realm_resolver::resolve` to render what an existing
/// default-configured realm renders, rather than a "Realm not found" 404. The
/// obvious implementation — resolving an unknown name to a fabricated `Realm`
/// so every downstream handler runs unchanged — is not safe as written: the
/// SAML metadata route calls `get_or_create_saml_signing_key`, which would mint
/// and persist a key per fabricated name, and the audit writers would grow the
/// log under an attacker-chosen realm id. Both need a guard before the decoy
/// can land. Run with `--run-ignored all` to see the current inventory.
///
/// The other half of §4.23#10 — "no rate limit on the oracle" — is closed and
/// pinned by `rate_cap_reaches_realm_scoped_pre_auth_probes` in
/// `tests/web_router_shared_guards.rs`.
#[ignore = "openspec:production-readiness-remediation#21.11: byte-identity across pre-auth \
            realm shapes is not implemented yet; this test is the acceptance criterion for it"]
#[tokio::test]
async fn real_and_fabricated_realms_are_indistinguishable_pre_auth() {
    let leaks = distinguishing_shapes().await;
    assert!(
        leaks.is_empty(),
        "{} of {} pre-auth shapes distinguish a real realm from a fabricated one:\n  {}",
        leaks.len(),
        PRE_AUTH_SHAPES.len(),
        leaks.join("\n  ")
    );
}

/// A syntactically invalid realm name must land in the same place as a
/// well-formed but non-existent one, or the rejection itself is the oracle.
#[tokio::test]
async fn malformed_realm_name_matches_the_unknown_realm_answer() {
    let app = build_app();
    let unknown = observe(&app, "GET", &format!("/ui/realms/{FAKE_REALM}/login"), None).await;
    // 129 characters — one past `is_sane_name`'s length cap.
    let overlong = "a".repeat(129);
    let malformed = observe(&app, "GET", &format!("/ui/realms/{overlong}/login"), None).await;
    assert_eq!(
        unknown.status, malformed.status,
        "an over-long realm name must not be answered differently from an unknown one"
    );
}
