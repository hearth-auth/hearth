//! HEA-2030 regression: the client IP used for per-IP login rate limiting and
//! session / audit forensics MUST reflect the real TCP peer, not the module
//! constant `FALLBACK_PEER` (`127.0.0.1:0`).
//!
//! ## The defect
//!
//! `extract_client_ip(headers, peer, trusted_proxies)` returns `peer.ip()`
//! whenever `trusted_proxies` is empty — the default, direct-bind
//! configuration. Before the fix (landed under the duplicate ticket HEA-2027,
//! commit `da2212fc`) every auth handler passed the hard-coded `FALLBACK_PEER`
//! constant instead of the real `ConnectInfo<SocketAddr>` peer. On a direct-bind
//! deployment this collapsed every client into a *single* identity:
//!
//! 1. The per-IP login limiter (`check_ip_login_rate_limit`, keyed on exactly
//!    this `client_ip` string) became one global bucket — one attacker tripping
//!    it locked out every user in the realm.
//! 2. Every session / audit record stored `127.0.0.1` as the source IP,
//!    destroying forensics and anomaly detection.
//!
//! The fix threads the real peer through an infallible `PeerAddr` axum extractor
//! that reads `ConnectInfo<SocketAddr>`, then into `build_session_context`.
//!
//! ## Why this is a served-socket test, not a `tower::oneshot` test
//!
//! `ConnectInfo<SocketAddr>` is only populated by the
//! `into_make_service_with_connect_info::<SocketAddr>()` layer on a *real
//! accepted TCP connection* (see production `serve.rs`). A `oneshot` call
//! against a bare `Router` never installs it, so the extractor would silently
//! fall back to `FALLBACK_PEER` and a `oneshot` test could not distinguish the
//! bug from the fix. We therefore bind a real listener and serve with the same
//! connect-info layer production uses.
//!
//! ## Why distinct source IPs, and why raw sockets
//!
//! `FALLBACK_PEER` is `127.0.0.1`, so to prove a handler uses the *real* peer we
//! must make the real peer an IP that is *not* `127.0.0.1`. We bind each client
//! socket's source address to a distinct routable loopback address
//! (`127.0.0.2` / `127.0.0.3`) in the `127.0.0.0/8` range; the kernel then
//! presents those exact addresses to the acceptor. We drive the request over a
//! raw `TcpSocket` because that is the only way to control the connection's
//! source address deterministically. Asserting on the *stored session IP* is
//! fully deterministic — no rate-limiter timing races.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hearth::core::pagination::PageRequest;
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;

/// A no-op email service — these tests never exercise mail delivery.
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

/// Fully assembled web router plus the engine handle and the realm / user we
/// log in against.
struct LoginRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    user_id: UserId,
    realm_name: String,
}

/// Builds a `web::router` backed by real engines with one active,
/// password-capable user. `trusted_proxies` is empty — the vulnerable
/// direct-bind default — and `dev_mode` is on so the raw POST can skip the
/// CSRF double-submit cookie (the CSRF path is not what this test exercises).
fn build_login_rig() -> LoginRig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    // Leak the tempdir: the storage engine mmaps files inside it for the life of
    // the test process.
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

    let realm_name = "acme".to_string();
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .expect("create realm");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@acme.test".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let password = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
    identity
        .set_password(realm.id(), user.id(), &password)
        .expect("set password");
    // Flip straight to Active, skipping email verification.
    identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
                first_name: None,
                last_name: None,
                ..Default::default()
            },
        )
        .expect("activate user");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        audit,
        onboarding,
        CookieSecret::from_bytes([42u8; 32]),
        None,
    )
    .with_dev_mode(true);
    debug_assert!(
        state.trusted_proxies.is_empty(),
        "regression must exercise the vulnerable direct-bind default (no trusted proxies)"
    );
    let app = web::router(state);

    LoginRig {
        app,
        identity,
        realm_id: realm.id().clone(),
        user_id: user.id().clone(),
        realm_name,
    }
}

/// Performs a scoped browser login (`POST /ui/realms/{realm}/login`) over a raw
/// TCP connection whose *source* address is `src`, so the server observes `src`
/// as the TCP peer. Reads the response to completion (the connection is closed
/// by the server), which guarantees the handler — and therefore session
/// creation — has finished before we return.
async fn login_from_source(server: SocketAddr, src: Ipv4Addr, realm: &str) {
    let sock = TcpSocket::new_v4().expect("v4 socket");
    sock.bind(SocketAddr::new(IpAddr::V4(src), 0))
        .expect("bind source address");
    let mut stream = sock.connect(server).await.expect("connect to server");

    // `@` is percent-encoded so `serde_urlencoded` decodes the email cleanly.
    // `csrf` is empty: dev_mode bypasses the double-submit check, and no Origin
    // header is sent so the cross-origin guard is skipped.
    let body = "email=alice%40acme.test&password=correct-horse-battery-staple&csrf=";
    let request = format!(
        "POST /ui/realms/{realm}/login HTTP/1.1\r\n\
         Host: {server}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write login request");
    let mut resp = Vec::new();
    stream
        .read_to_end(&mut resp)
        .await
        .expect("read login response");
    // Sanity: a successful browser login is a 303 redirect. If this fails the
    // rig setup is wrong (bad realm/credentials), not the IP wiring.
    let head = String::from_utf8_lossy(&resp);
    assert!(
        head.starts_with("HTTP/1.1 303") || head.starts_with("HTTP/1.1 302"),
        "login did not succeed (expected 3xx redirect); response head: {:?}",
        head.lines().next()
    );
}

/// Two logins from two *distinct* peer IPs must yield two sessions each stamped
/// with its own real source IP — never the `FALLBACK_PEER` constant
/// `127.0.0.1`. This is the exact `client_ip` the per-IP login limiter keys on,
/// so proving the two are distinguished here proves the limiter no longer
/// collapses to one global bucket, and proves session forensics capture the
/// real peer.
///
/// Pre-HEA-2030 both sessions store `127.0.0.1` and this test fails on the
/// `assert!(!ips.contains("127.0.0.1"))` / distinct-set checks below.
#[tokio::test]
async fn login_sessions_capture_the_real_peer_ip_not_fallback() {
    let rig = build_login_rig();

    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener local addr");

    // Install `ConnectInfo<SocketAddr>` exactly as production `serve.rs` does.
    let app = rig.app.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
    });

    // Log in twice from two genuinely different peer IPs.
    login_from_source(addr, Ipv4Addr::new(127, 0, 0, 2), &rig.realm_name).await;
    login_from_source(addr, Ipv4Addr::new(127, 0, 0, 3), &rig.realm_name).await;

    let sessions = rig
        .identity
        .list_sessions_by_user(
            &rig.realm_id,
            &rig.user_id,
            &PageRequest {
                offset: 0,
                limit: 100,
            },
        )
        .expect("list sessions");

    let ips: Vec<String> = sessions
        .items
        .iter()
        .map(|s| s.ip_address().unwrap_or("<none>").to_string())
        .collect();

    assert_eq!(
        sessions.items.len(),
        2,
        "expected exactly two sessions (one per login); got IPs {ips:?}"
    );
    assert!(
        !ips.iter().any(|ip| ip == "127.0.0.1"),
        "no session may carry the FALLBACK_PEER address 127.0.0.1 — that is the \
         HEA-2030 collapse. Captured IPs: {ips:?}"
    );
    let mut sorted = ips.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted,
        vec!["127.0.0.2".to_string(), "127.0.0.3".to_string()],
        "the two logins must be attributed to their two distinct real peer IPs; \
         a collapse to a single bucket would show one repeated IP. Captured: {ips:?}"
    );
}
