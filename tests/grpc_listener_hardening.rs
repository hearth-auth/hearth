#![allow(clippy::unwrap_used)]
//! GA audit 2026-09-28 — the gRPC management listener.
//!
//! * **M14** — the gRPC API was always plaintext: `grpc/server.rs` bound a bare
//!   `TcpListener` with no TLS configuration, so admin bearer tokens, OAuth
//!   client secrets and new agent API keys crossed the network in clear text
//!   even when the HTTP listener served TLS. It now serves TLS with the same
//!   certificate as HTTPS.
//! * **B6 (sibling path)** — the gRPC listener had no connection cap and no
//!   deadline for a client's first bytes or TLS handshake, so one client could
//!   hold connections without limit.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::http::limits::{init_server_limits, ServerLimits};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::HealthCheckRequest;

const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(2);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const PER_IP_CAP: u32 = 4;

const ATTACKER: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn install_limits() {
    let _ = init_server_limits(ServerLimits {
        header_read_timeout: HEADER_READ_TIMEOUT,
        tls_handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
        max_connections_per_ip: PER_IP_CAP,
        ..ServerLimits::default()
    });
}

/// Writes a self-signed `localhost` certificate; returns (cert PEM, cert path, key path).
fn generate_server_cert(dir: &Path) -> (String, std::path::PathBuf, std::path::PathBuf) {
    let key_pair = rcgen::KeyPair::generate().expect("keygen");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    (cert.pem(), cert_path, key_path)
}

/// The same acceptor `main.rs` builds for the HTTPS listener.
fn tls_acceptor(cert_path: &Path, key_path: &Path) -> tokio_rustls::TlsAcceptor {
    let reloadable = hearth::protocol::tls::ReloadableTlsConfig::load(
        cert_path.to_path_buf(),
        key_path.to_path_buf(),
    )
    .expect("load tls");
    let server_config =
        hearth::protocol::tls::build_server_config(hearth::protocol::tls::TlsConfigParams {
            resolver: Arc::new(reloadable.resolver()),
            client_ca_path: None,
            require_client_cert: false,
            crl_paths: vec![],
            tls13_only: false,
        })
        .expect("server config");
    tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
}

/// Serves the gRPC management API on an ephemeral port.
async fn spawn_grpc(
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> (
    SocketAddr,
    common::TestHarness,
    tokio::sync::oneshot::Sender<()>,
) {
    install_limits();
    let h = common::TestHarness::embedded().await.expect("harness");
    let state = GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = hearth::protocol::grpc::serve_on(listener, state, false, tls, async {
            let _ = rx.await;
        })
        .await;
    });
    (addr, h, tx)
}

async fn connect_from(from: Ipv4Addr, addr: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().expect("socket");
    socket
        .bind(SocketAddr::new(IpAddr::V4(from), 0))
        .expect("bind client address");
    socket.connect(addr).await.expect("connect")
}

async fn time_until_closed(sock: &mut TcpStream, ceiling: Duration) -> Option<Duration> {
    let started = Instant::now();
    let mut sink = Vec::new();
    match tokio::time::timeout(ceiling, sock.read_to_end(&mut sink)).await {
        Ok(_) => Some(started.elapsed()),
        Err(_elapsed) => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M14 — TLS
// ─────────────────────────────────────────────────────────────────────────────

/// Given the HTTPS certificate, the gRPC listener speaks TLS: a TLS client
/// that trusts the certificate is served, and a plaintext client is not.
#[tokio::test]
async fn the_grpc_listener_serves_tls_with_the_https_certificate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_pem, cert_path, key_path) = generate_server_cert(dir.path());
    let (addr, _h, _shutdown) = spawn_grpc(Some(tls_acceptor(&cert_path, &key_path))).await;

    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(cert_pem))
        .domain_name("localhost");
    let channel =
        tonic::transport::Endpoint::from_shared(format!("https://127.0.0.1:{}", addr.port()))
            .expect("endpoint")
            .tls_config(tls)
            .expect("client tls")
            .connect_timeout(Duration::from_secs(5))
            .connect()
            .await
            .expect(
                "a TLS client trusting the HTTPS certificate must connect to the gRPC listener",
            );
    let status = HealthClient::new(channel)
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await
        .expect("health check over TLS")
        .into_inner()
        .status();
    assert_eq!(status, ServingStatus::Serving);

    // The control: the same listener must refuse plaintext HTTP/2.
    let plaintext =
        tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{}", addr.port()))
            .expect("endpoint")
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(5))
            .connect_lazy();
    let result = HealthClient::new(plaintext)
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await;
    assert!(
        result.is_err(),
        "a plaintext gRPC call succeeded against a TLS-configured listener — admin tokens \
         would still cross the network in clear text"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// B6 — connection limits
// ─────────────────────────────────────────────────────────────────────────────

/// A connection that never sends the HTTP/2 preface is closed.
#[tokio::test]
async fn a_silent_grpc_connection_is_closed_after_the_header_timeout() {
    let (addr, _h, _shutdown) = spawn_grpc(None).await;
    let mut sock = connect_from(ATTACKER, addr).await;
    let closed_after = time_until_closed(&mut sock, HEADER_READ_TIMEOUT * 4)
        .await
        .expect("a gRPC connection that sent nothing was never closed");
    assert!(
        closed_after >= HEADER_READ_TIMEOUT / 2,
        "closed after {closed_after:?}, before the header timeout"
    );
}

/// A client that never starts its TLS handshake is dropped at the deadline.
#[tokio::test]
async fn a_stalled_grpc_tls_handshake_is_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_pem, cert_path, key_path) = generate_server_cert(dir.path());
    let (addr, _h, _shutdown) = spawn_grpc(Some(tls_acceptor(&cert_path, &key_path))).await;
    let mut sock = connect_from(ATTACKER, addr).await;
    let closed_after = time_until_closed(&mut sock, TLS_HANDSHAKE_TIMEOUT * 4)
        .await
        .expect("a gRPC connection that never started TLS was never closed");
    assert!(
        closed_after >= TLS_HANDSHAKE_TIMEOUT / 2,
        "closed after {closed_after:?}, before the handshake timeout"
    );
}

/// One address gets `max_connections_per_ip` gRPC connections; the next is
/// refused at once instead of being held.
#[tokio::test]
async fn the_grpc_listener_caps_connections_per_address() {
    let (addr, _h, _shutdown) = spawn_grpc(None).await;
    let mut held = Vec::new();
    for _ in 0..PER_IP_CAP {
        held.push(connect_from(ATTACKER, addr).await);
    }
    // AUDIT: justified-sleep: no observable signal that the accept loop has counted the sockets (B6).
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut extra = connect_from(ATTACKER, addr).await;
    let closed_after = time_until_closed(&mut extra, HEADER_READ_TIMEOUT / 2).await;
    assert!(
        closed_after.is_some(),
        "connection {} from one address must be refused immediately",
        PER_IP_CAP + 1
    );
    drop(held);
}
