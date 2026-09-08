//! SIGTERM drain on the TLS-terminating server (audit 2026-08-28 §4.11#9, §4.11#10).
//!
//! ## The defect
//!
//! `serve_tls_router` runs its own accept loop. On the shutdown signal it
//! `break`s out of that loop and returns `Ok(())`. Every connection it had
//! spawned was left to be dropped when the runtime shut down, so an in-flight
//! request was cut off mid-response and the process still exited 0.
//!
//! The existing drain tests in `tests/graceful_shutdown.rs` never caught this:
//! they drive `hearth serve --dev`, which is the **plaintext** listener, and
//! that path gets its drain from `axum::serve().with_graceful_shutdown()`.
//!
//! ## Why these must be served-socket tests
//!
//! The drain is a property of the accept loop, not of any handler. Only a real
//! accepted TLS connection exercises it.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hearth::protocol::http;
use hearth::protocol::tls::{build_server_config, ReloadableTlsConfig, TlsConfigParams};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};

// ── helpers ─────────────────────────────────────────────────────────────────

/// Writes a self-signed server certificate and key, and returns the CA PEM
/// plus both paths.
fn write_test_certs(dir: &std::path::Path) -> (Vec<u8>, PathBuf, PathBuf) {
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

/// Builds a `TlsAcceptor` from the given cert/key files.
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

/// Builds a client TLS connector that trusts only `ca_pem`.
fn build_test_connector(ca_pem: &[u8]) -> tokio_rustls::TlsConnector {
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
    tokio_rustls::TlsConnector::from(Arc::new(client_config))
}

/// A router whose only route reports when it starts, then sleeps `work` before
/// answering. The report is what makes the shutdown deterministic: the test
/// signals only once the request is provably in flight.
fn slow_router(started: mpsc::Sender<()>, work: Duration) -> axum::Router {
    axum::Router::new().route(
        "/slow",
        axum::routing::get(move || async move {
            let _ = started.send(()).await;
            tokio::time::sleep(work).await;
            "done"
        }),
    )
}

/// Connects over TLS, sends `GET /slow`, and returns the open stream.
async fn send_slow_request(
    port: u16,
    connector: &tokio_rustls::TlsConnector,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect TCP");
    let server_name = rustls_pki_types::ServerName::try_from("localhost")
        .expect("server name")
        .to_owned();
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake");

    tls.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    tls.flush().await.expect("flush request");
    tls
}

// ── tests ───────────────────────────────────────────────────────────────────

/// An in-flight request must complete when the TLS server is told to shut down
/// (audit 2026-08-28 §4.11#9).
///
/// Before the fix the accept loop broke and returned immediately, and the
/// spawned connection task was dropped mid-response: the client saw a truncated
/// read, and the process still exited 0.
#[tokio::test]
async fn tls_server_drains_inflight_request_on_shutdown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (ca_pem, cert_path, key_path) = write_test_certs(dir.path());
    let acceptor = build_test_acceptor(cert_path, key_path);
    let connector = build_test_connector(&ca_pem);

    let (started_tx, mut started_rx) = mpsc::channel::<()>(1);
    let app = slow_router(started_tx, Duration::from_millis(750));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local addr").port();

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let server = tokio::spawn(async move {
        http::serve_tls_router(
            listener,
            app,
            acceptor,
            shutdown_rx,
            Duration::from_secs(10),
        )
        .await
    });

    let mut tls = send_slow_request(port, &connector).await;

    // The handler has started, so the connection is provably serving a
    // request rather than sitting idle.
    started_rx.recv().await.expect("handler must start");

    shutdown_tx.send(()).expect("signal shutdown");

    let mut response = Vec::new();
    tls.read_to_end(&mut response)
        .await
        .expect("an in-flight request must complete during the drain");
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "the drained request must get its full response; got: {}",
        text.lines().next().unwrap_or("<empty>")
    );
    assert!(
        text.ends_with("done"),
        "the response body must be complete; got: {text}"
    );

    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the server must return after the drain")
        .expect("server task must not panic");
    assert!(
        result.is_ok(),
        "a drain that completed must not report an error; got: {result:?}"
    );
}

/// A drain that does not complete within its deadline must be reported as an
/// error, so the process exits non-zero (audit 2026-08-28 §4.11#10).
///
/// Before the fix the TLS server returned `Ok(())` the instant it was signalled,
/// whatever was still in flight, so a truncated shutdown was indistinguishable
/// from a clean one.
#[tokio::test]
async fn tls_server_reports_a_drain_that_did_not_complete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (ca_pem, cert_path, key_path) = write_test_certs(dir.path());
    let acceptor = build_test_acceptor(cert_path, key_path);
    let connector = build_test_connector(&ca_pem);

    let (started_tx, mut started_rx) = mpsc::channel::<()>(1);
    // The handler outlasts the drain deadline by a wide margin.
    let app = slow_router(started_tx, Duration::from_secs(30));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local addr").port();

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let server = tokio::spawn(async move {
        http::serve_tls_router(
            listener,
            app,
            acceptor,
            shutdown_rx,
            Duration::from_millis(500),
        )
        .await
    });

    let _tls = send_slow_request(port, &connector).await;
    started_rx.recv().await.expect("handler must start");

    shutdown_tx.send(()).expect("signal shutdown");

    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the server must return once the deadline passes")
        .expect("server task must not panic");

    let err = result.expect_err("an incomplete drain must be reported as an error");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::TimedOut,
        "an incomplete drain must report TimedOut so the caller exits non-zero; got: {err}"
    );
}
