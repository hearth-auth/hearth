#![allow(clippy::unwrap_used)]
//! #644: the admin UI user list pages with a key cursor (prev / next), not
//! page numbers.
//!
//! Before, the list paged by page number (an offset). A user deleted while an
//! admin paged moved the next user onto a page already shown, so the admin
//! never saw it, and a deep page walked every index key before it. The
//! unsorted list was in user-id order, which has no reverse index for a
//! "previous" link; it is now in email order.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::audit::AuditEngine;
use hearth::core::{RealmId, SessionId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use hearth::webhook::{EmbeddedWebhookEngine, WebhookEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [11u8; 32];

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

struct Rig {
    app: axum::Router,
    admin_session_id: SessionId,
    system_realm_id: RealmId,
    tenant_realm_name: String,
    /// Identity engine handle, to seed and delete users.
    identity: Arc<dyn IdentityEngine>,
    /// The tenant realm whose user list the tests page through.
    tenant_realm_id: RealmId,
}

#[allow(clippy::too_many_lines)]
fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    let _ = temp.keep();

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
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
        .expect("identity"),
    ) as Arc<dyn IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let system_realm_id = RealmId::new(uuid::Uuid::nil());
    rbac.seed_realm(&system_realm_id).expect("seed system");

    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "pageradmin@test.example".to_string(),
            display_name: "PagerAdmin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin");
    identity
        .set_password(
            &system_realm_id,
            admin_user.id(),
            &CleartextPassword::from_string("s3cr3t1!-p@ss".to_string()),
        )
        .expect("password");
    identity
        .update_user(
            &system_realm_id,
            admin_user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    let admin_role = rbac
        .get_role_by_name(&system_realm_id, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    rbac.assign_role(
        &system_realm_id,
        &AssignRoleRequest {
            subject: Subject::User(admin_user.id().clone()),
            role_id: admin_role.id,
            scope: Scope::Realm,
            assigned_by: None,
        },
    )
    .expect("assign");
    let admin_session = identity
        .create_session(
            &system_realm_id,
            admin_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session");

    let tenant = identity
        .create_realm(&CreateRealmRequest {
            name: "pagerco".to_string(),
            config: None,
        })
        .expect("realm");

    let webhook = Arc::new(EmbeddedWebhookEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn WebhookEngine>;

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    )
    .with_dev_mode(true)
    .with_webhook(Arc::clone(&webhook));
    let app = web::router(state);

    Rig {
        app,
        admin_session_id: admin_session.id().clone(),
        system_realm_id,
        tenant_realm_name: "pagerco".to_string(),
        identity: Arc::clone(&identity),
        tenant_realm_id: tenant.id().clone(),
    }
}

fn admin_cookie(rig: &Rig, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.system_realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.admin_session_id.as_uuid(),
        rig.system_realm_id.as_uuid(),
        tag,
        csrf,
    )
}

// ---------------------------------------------------------------------------
// User list pager
// ---------------------------------------------------------------------------

/// The emails of the rows of a user list page, in page order.
fn row_emails(html: &str) -> Vec<String> {
    let mut emails = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("hover:text-ht-brand-deep\">") {
        rest = &rest[i + "hover:text-ht-brand-deep\">".len()..];
        let end = rest.find("</a>").expect("row link end");
        emails.push(rest[..end].trim().to_string());
        rest = &rest[end..];
    }
    emails
}

/// The `href` of the pager link with this `aria-label`, if the page has it.
fn pager_href(html: &str, label: &str) -> Option<String> {
    let mut rest = html;
    while let Some(i) = rest.find("<a ") {
        rest = &rest[i..];
        let end = rest.find('>').expect("tag end");
        let tag = &rest[..end];
        if tag.contains(&format!("aria-label=\"{label}\"")) {
            let h = tag.find("href=\"").expect("href") + "href=\"".len();
            let href = &tag[h..];
            let href = &href[..href.find('"').expect("href end")];
            return Some(href.replace("&amp;", "&"));
        }
        rest = &rest[end..];
    }
    None
}

async fn get_page(rig: &Rig, cookie: &str, uri: &str) -> String {
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "{uri}");
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

fn create_users(rig: &Rig, n: usize) -> Vec<(String, hearth::core::UserId)> {
    (0..n)
        .map(|i| {
            // Names run the other way from emails, so the two orders differ.
            let email = format!("user{i:02}@pager.test");
            let user = rig
                .identity
                .create_user(
                    &rig.tenant_realm_id,
                    &CreateUserRequest {
                        email: email.clone(),
                        display_name: format!("Name {:02}", n - i),
                        first_name: String::new(),
                        last_name: String::new(),
                        attributes: Default::default(),
                    },
                )
                .expect("create user");
            (email, user.id().clone())
        })
        .collect()
}

/// Follows "Next page" from `first` until the last page, and returns the
/// rows in walk order. `between` runs after the first page.
async fn walk_next(
    rig: &Rig,
    cookie: &str,
    first: &str,
    mut between: impl FnMut(&[String]),
) -> Vec<String> {
    let mut rows = Vec::new();
    let mut uri = first.to_string();
    for page in 0.. {
        assert!(page < 100, "the walk does not end");
        let html = get_page(rig, cookie, &uri).await;
        let emails = row_emails(&html);
        if page == 0 {
            between(&emails);
        }
        rows.extend(emails);
        match pager_href(&html, "Next page") {
            Some(next) => uri = next,
            None => break,
        }
    }
    rows
}

#[tokio::test]
async fn next_links_walk_every_user_once_in_email_order_when_a_user_is_deleted() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-pager");
    let users = create_users(&rig, 23);
    let realm = rig.tenant_realm_name.clone();

    let mut deleted: Option<String> = None;
    let rows = walk_next(
        &rig,
        &cookie,
        &format!("/ui/admin/realms/{realm}/users?per_page=5"),
        |first_page| {
            let victim = first_page[0].clone();
            let id = &users.iter().find(|(e, _)| *e == victim).expect("user").1;
            rig.identity
                .delete_user(&rig.tenant_realm_id, id)
                .expect("delete user");
            deleted = Some(victim);
        },
    )
    .await;

    let deleted = deleted.expect("a user was deleted");
    let mut expected: Vec<String> = users.iter().map(|(e, _)| e.clone()).collect();
    expected.sort();
    let walked: Vec<String> = rows.into_iter().filter(|e| *e != deleted).collect();
    let expected: Vec<String> = expected.into_iter().filter(|e| *e != deleted).collect();
    assert_eq!(walked, expected, "every user once, in email order");
}

#[tokio::test]
async fn a_sorted_walk_follows_the_sort_and_previous_returns_the_page_before() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-pager");
    create_users(&rig, 12);
    let realm = rig.tenant_realm_name.clone();
    let first = format!("/ui/admin/realms/{realm}/users?per_page=5&sort=name&dir=desc");

    let page1 = get_page(&rig, &cookie, &first).await;
    let page2_uri = pager_href(&page1, "Next page").expect("next from page 1");
    let page2 = get_page(&rig, &cookie, &page2_uri).await;
    let page3_uri = pager_href(&page2, "Next page").expect("next from page 2");
    let page3 = get_page(&rig, &cookie, &page3_uri).await;
    assert!(
        pager_href(&page3, "Next page").is_none(),
        "page 3 is the last"
    );

    // Names run the other way from emails: name descending is email ascending.
    let walked: Vec<String> = [&page1, &page2, &page3]
        .iter()
        .flat_map(|p| row_emails(p))
        .collect();
    let expected: Vec<String> = (0..12).map(|i| format!("user{i:02}@pager.test")).collect();
    assert_eq!(walked, expected, "name descending order");

    let back_uri = pager_href(&page3, "Previous page").expect("previous from page 3");
    let back = get_page(&rig, &cookie, &back_uri).await;
    assert_eq!(
        row_emails(&back),
        row_emails(&page2),
        "previous shows page 2 again"
    );
    let start_uri = pager_href(&back, "Previous page").expect("previous from page 2");
    let start = get_page(&rig, &cookie, &start_uri).await;
    assert_eq!(
        row_emails(&start),
        row_emails(&page1),
        "previous shows page 1 again"
    );
    assert!(
        pager_href(&start, "Previous page").is_none(),
        "page 1 has no previous"
    );
}

#[tokio::test]
async fn the_pager_has_no_page_number_links() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-pager");
    create_users(&rig, 30);
    let realm = rig.tenant_realm_name.clone();

    let html = get_page(
        &rig,
        &cookie,
        &format!("/ui/admin/realms/{realm}/users?per_page=5"),
    )
    .await;
    assert!(
        !html.contains("?page="),
        "a cursor pager links no page number"
    );
    assert!(html.contains("of 30"), "the pager shows the exact total");
}
