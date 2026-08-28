//! HEA-2164 regression: TLS path must inject `ConnectInfo<SocketAddr>`.
//!
//! ## The defect
//!
//! `serve_tls_router` managed its own accept loop and called `app.into_service()`
//! without wrapping it in axum's `into_make_service_with_connect_info`. The
//! `PeerAddr` extractor therefore never found `ConnectInfo<SocketAddr>` in the
//! request extensions and silently fell back to `FALLBACK_PEER` (`127.0.0.1`).
//!
//! Consequences (all live on the production TLS path):
//! - The per-IP login rate limiter collapsed into **one global bucket** keyed on
//!   `127.0.0.1`. One client exhausting the limit would rate-lock every tenant.
//! - Every session and audit record stored `127.0.0.1`, destroying forensics.
//!
//! The fix adds an `AddConnectInfo<S>` tower wrapper that injects
//! `ConnectInfo::<SocketAddr>(peer_addr)` into each request's extension map.
//!
//! ## Why these must be served-socket TLS tests
//!
//! `ConnectInfo<SocketAddr>` is only populated on a *real* accepted TCP
//! connection; a `tower::oneshot` call never installs it. For TLS, using the
//! actual `serve_tls_router` path is the only way to distinguish the fix from
//! the bug.
//!
//! ## Source-IP control
//!
//! `FALLBACK_PEER` is `127.0.0.1`, so to prove the real peer is used we must
//! connect from an address that is *not* `127.0.0.1`. We bind client sockets
//! to `127.0.0.2` / `127.0.0.3` (distinct addresses in the `127.0.0.0/8`
//! loopback range). A `TcpSocket::bind` before `connect` makes the kernel
//! present those exact addresses to the acceptor.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use hearth::audit::EmbeddedAuditEngine;
use hearth::core::pagination::PageRequest;
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RateLimitConfig, UpdateUserRequest,
    UserStatus,
};
use hearth::protocol::http;
use hearth::protocol::tls::{build_server_config, ReloadableTlsConfig, TlsConfigParams};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::watch;

// ── helpers ─────────────────────────────────────────────────────────────────

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

struct TlsLoginRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    user_id: UserId,
    realm_name: String,
}

/// Builds a web router backed by real engines with one active,
/// password-capable user. `trusted_proxies` is empty — the default
/// direct-bind configuration. `dev_mode` is on so a raw POST can skip
/// the CSRF double-submit cookie.
fn build_tls_login_rig(identity_config: IdentityConfig) -> TlsLoginRig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    // The storage engine mmaps files for the test's lifetime; forget the guard.
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let realm_name = "tls-ip-test".to_string();
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
    identity
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("correct-horse-battery-staple".to_string()),
        )
        .expect("set password");
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
        "regression must exercise the direct-bind default (no trusted proxies)"
    );
    let app = web::router(state);

    TlsLoginRig {
        app,
        identity,
        realm_id: realm.id().clone(),
        user_id: user.id().clone(),
        realm_name,
    }
}

/// Generates a self-signed test CA and a server cert signed by it.
/// Returns `(ca_pem_bytes, cert_path, key_path)`.
fn generate_test_certs(dir: &std::path::Path) -> (Vec<u8>, PathBuf, PathBuf) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("ca keygen");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");
    let ca_pem = ca_cert.pem().into_bytes();

    let server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("server params");
    let server_key = rcgen::KeyPair::generate().expect("server keygen");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("sign server cert");

    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server-key.pem");
    let mut cert_chain = server_cert.pem();
    cert_chain.push_str(&ca_cert.pem());
    std::fs::write(&cert_path, cert_chain).expect("write server cert");
    std::fs::write(&key_path, server_key.serialize_pem()).expect("write server key");

    (ca_pem, cert_path, key_path)
}

/// Builds a `TlsAcceptor` for the test server using the given cert/key files.
fn build_test_acceptor(cert_path: PathBuf, key_path: PathBuf) -> tokio_rustls::TlsAcceptor {
    let tls_config = ReloadableTlsConfig::load(cert_path, key_path).expect("load TLS config");
    let params = TlsConfigParams {
        resolver: Arc::new(tls_config.resolver()),
        client_ca_path: None,
        require_client_cert: false,
        crl_paths: vec![],
        tls13_only: false,
    };
    let server_config = build_server_config(params).expect("build server config");
    tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
}

/// Performs a browser login over a TLS connection whose TCP source address is
/// `src_ip`. Returns the first line of the HTTP response (the status line).
///
/// Reads the response to completion so that the handler — including session
/// creation and `record_ip_login_attempt` — has finished before we return.
async fn tls_login_from_source(
    server_addr: SocketAddr,
    ca_pem: &[u8],
    src_ip: Ipv4Addr,
    realm: &str,
    password: &str,
) -> String {
    // Build a rustls client config that trusts our test CA.
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_pki_types::pem::PemObject::pem_slice_iter(ca_pem)
        .collect::<Result<Vec<rustls_pki_types::CertificateDer<'static>>, _>>()
        .expect("parse CA certs")
    {
        root_store.add(cert).expect("add CA cert");
    }
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .expect("tls version config")
    .with_root_certificates(root_store)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    // Bind the client socket to a specific source IP so the server observes it
    // as the TCP peer. This is the same technique used by HEA-2030.
    let sock = TcpSocket::new_v4().expect("v4 socket");
    sock.bind(SocketAddr::new(IpAddr::V4(src_ip), 0))
        .expect("bind source address");
    let tcp = sock.connect(server_addr).await.expect("tcp connect");

    let server_name = rustls_pki_types::ServerName::try_from("localhost")
        .expect("server name")
        .to_owned();
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake");

    // `csrf=` is empty: dev_mode bypasses the double-submit check.
    let body = format!("email=alice%40acme.test&password={password}&csrf=");
    let request = format!(
        "POST /ui/realms/{realm}/login HTTP/1.1\r\n\
         Host: {server_addr}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    tls.write_all(request.as_bytes())
        .await
        .expect("write request");

    // read_to_end waits until the server closes the connection (Connection: close),
    // guaranteeing the handler has fully completed before we return.
    let mut resp = Vec::new();
    tls.read_to_end(&mut resp).await.expect("read response");

    String::from_utf8_lossy(&resp)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

// ── Test 1: session records contain the real peer IP, not FALLBACK_PEER ──────

/// Two logins from two *distinct* peer IPs over TLS must each record the real
/// source IP in the created session — not `FALLBACK_PEER` (`127.0.0.1`).
///
/// Pre-fix: `serve_tls_router` used `app.into_service()` without injecting
/// `ConnectInfo<SocketAddr>`, so `PeerAddr` always resolved to `127.0.0.1`.
/// Both sessions would record `127.0.0.1` and the assertions below would fail.
#[tokio::test]
async fn tls_peer_ip_appears_in_session_not_fallback() {
    let rig = build_tls_login_rig(IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    });

    let cert_dir = tempfile::tempdir().expect("cert dir");
    let (ca_pem, cert_path, key_path) = generate_test_certs(cert_dir.path());
    let acceptor = build_test_acceptor(cert_path, key_path);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let server_addr = listener.local_addr().expect("local addr");
    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let app = rig.app.clone();
    tokio::spawn(async move {
        http::serve_tls_router(listener, app, acceptor, shutdown_rx)
            .await
            .expect("serve_tls_router");
    });

    // Log in from two genuinely different peer IPs.
    tls_login_from_source(
        server_addr,
        &ca_pem,
        Ipv4Addr::new(127, 0, 0, 2),
        &rig.realm_name,
        "correct-horse-battery-staple",
    )
    .await;
    tls_login_from_source(
        server_addr,
        &ca_pem,
        Ipv4Addr::new(127, 0, 0, 3),
        &rig.realm_name,
        "correct-horse-battery-staple",
    )
    .await;

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
        "no session may carry FALLBACK_PEER (127.0.0.1) — that indicates \
         ConnectInfo was not injected on the TLS path. Captured IPs: {ips:?}"
    );
    let mut sorted = ips.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted,
        vec!["127.0.0.2".to_string(), "127.0.0.3".to_string()],
        "the two TLS logins must record their two distinct real peer IPs; \
         a collapse to a single value indicates the bug is still present. \
         Captured: {ips:?}"
    );
}

// ── Test 2: independent per-IP rate-limiter buckets over TLS ─────────────────

/// With a rate limit of 1 failed attempt per window, a single failure from
/// IP A must not block IP B. If the TLS path collapses all peers to
/// `127.0.0.1`, A's failure fills the shared bucket and B's subsequent
/// correct-password login is rejected with 401 instead of 303.
///
/// Test strategy:
///  1. IP A sends one wrong-password login → increments A's bucket to 1
///     (A is now at the limit for the next check).
///  2. IP B sends a correct-password login → must succeed (303).
///     If the bug is present, B appears as 127.0.0.1, the shared bucket
///     already holds 1 failure, and the rate-limit check returns Err → 401.
#[tokio::test]
async fn tls_independent_rate_limit_buckets_per_ip() {
    // One failure saturates the IP's bucket immediately.
    let rig = build_tls_login_rig(IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        rate_limit: RateLimitConfig {
            ip_max_attempts: 1,
            ip_window_micros: 60_000_000, // 1 minute
            ..RateLimitConfig::default()
        },
        ..IdentityConfig::default()
    });

    let cert_dir = tempfile::tempdir().expect("cert dir");
    let (ca_pem, cert_path, key_path) = generate_test_certs(cert_dir.path());
    let acceptor = build_test_acceptor(cert_path, key_path);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let server_addr = listener.local_addr().expect("local addr");
    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let app = rig.app.clone();
    tokio::spawn(async move {
        http::serve_tls_router(listener, app, acceptor, shutdown_rx)
            .await
            .expect("serve_tls_router");
    });

    // Step 1 — IP A sends one wrong-password attempt. This increments
    // A's failed-attempt counter to 1 (= ip_max_attempts), saturating A's bucket.
    let status_a = tls_login_from_source(
        server_addr,
        &ca_pem,
        Ipv4Addr::new(127, 0, 0, 2),
        &rig.realm_name,
        "wrong-password",
    )
    .await;
    assert!(
        status_a.contains("401") || status_a.contains("302") || status_a.contains("303"),
        "IP A wrong-password must return a non-server-error response; got: {status_a}"
    );

    // Step 2 — IP B sends a correct-password login.
    // Bug: B appears as 127.0.0.1, the shared bucket has 1 failure → 401.
    // Fix: B has its own empty bucket → proceeds → 303.
    let status_b = tls_login_from_source(
        server_addr,
        &ca_pem,
        Ipv4Addr::new(127, 0, 0, 3),
        &rig.realm_name,
        "correct-horse-battery-staple",
    )
    .await;
    assert!(
        status_b.starts_with("HTTP/1.1 303") || status_b.starts_with("HTTP/1.1 302"),
        "IP B (a different IP from A) must succeed with a redirect despite A's \
         failed attempt — independent rate-limit buckets are required. \
         If this returns 401, the TLS path is still collapsing all peers to \
         FALLBACK_PEER. Status: {status_b}"
    );
}
