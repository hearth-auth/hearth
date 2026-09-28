//! GA audit 2026-09-28 B6 — one unauthenticated client could use every
//! connection slot.
//!
//! The probe: 1100 sockets each sent `GET /health HTTP/1.1\r\nHost: x\r\n` and
//! never finished the headers. `/health` then timed out, and after 40 s the
//! server had closed 0 of the 1100. Neither accept loop set a header-read
//! timeout, the TLS loop awaited the handshake with no deadline while holding
//! an admission permit, and nothing capped connections per client address.
//!
//! Each test drives the real accept loops (`serve_router_on` for plaintext,
//! `serve_tls_router` for TLS) with short limits so the suite stays fast.
//! The attacker connects from `127.0.0.1`; the well-behaved client binds
//! `127.0.0.2` (Linux routes all of `127.0.0.0/8` to loopback) so the per-address
//! cap can tell them apart.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::protocol::http;
use hearth::protocol::http::limits::{init_server_limits, ServerLimits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

/// Budget for a request's headers (and a new connection's first bytes).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Budget for a TLS handshake.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Connections one address may hold.
const PER_IP_CAP: u32 = 8;

/// Total connection slots, deliberately small so the attack fills them.
const MAX_CONNECTIONS: u32 = 16;

/// The attacker's address.
const ATTACKER: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// A well-behaved client's address.
const CLIENT: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// An address listed as a trusted proxy — exempt from the per-address cap.
const TRUSTED_PROXY: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

/// Installs the limits every test in this binary shares (the limits are a
/// process-global `OnceLock`; nextest runs one process per test).
fn install_limits() {
    let _ = init_server_limits(ServerLimits {
        max_connections: MAX_CONNECTIONS,
        queue_depth: MAX_CONNECTIONS,
        header_read_timeout: HEADER_READ_TIMEOUT,
        tls_handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
        max_connections_per_ip: PER_IP_CAP,
        per_ip_exempt: vec![IpAddr::V4(TRUSTED_PROXY)],
        ..ServerLimits::default()
    });
}

fn health_app() -> axum::Router {
    axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }))
}

async fn spawn_plaintext() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = http::serve_router_on(listener, health_app(), async {
            let _ = rx.await;
        })
        .await;
    });
    (addr, tx)
}

/// Opens a TCP connection to `addr` from the loopback address `from`.
async fn connect_from(from: Ipv4Addr, addr: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().expect("socket");
    socket
        .bind(SocketAddr::new(IpAddr::V4(from), 0))
        .expect("bind client address");
    socket.connect(addr).await.expect("connect")
}

/// Sends a complete `GET /health` on `sock` and returns the status line.
async fn get_health(sock: &mut TcpStream) -> String {
    sock.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write request");
    let mut buf = vec![0_u8; 1024];
    let n = match sock.read(&mut buf).await {
        Ok(n) => n,
        Err(e) => return format!("<connection failed: {e}>"),
    };
    String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("<connection closed with no response>")
        .to_string()
}

/// Waits until the server closes `sock` and returns how long that took, or
/// `None` if it was still open after `ceiling`.
async fn time_until_closed(sock: &mut TcpStream, ceiling: Duration) -> Option<Duration> {
    let started = Instant::now();
    let mut sink = Vec::new();
    match tokio::time::timeout(ceiling, sock.read_to_end(&mut sink)).await {
        // EOF or a reset: either way the server let go of the connection.
        Ok(_) => Some(started.elapsed()),
        Err(_elapsed) => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Starvation — the audit's probe
// ─────────────────────────────────────────────────────────────────────────────

/// Many unfinished requests from one address must not stop a different client
/// from being served — and it must be served at once, not only after the
/// attacker's connections time out.
#[tokio::test]
async fn unfinished_requests_from_one_address_cannot_starve_another_client() {
    install_limits();
    let (addr, _shutdown) = spawn_plaintext().await;

    let mut attacker = Vec::new();
    for _ in 0..(MAX_CONNECTIONS * 4) {
        let mut sock = connect_from(ATTACKER, addr).await;
        // Never finished: no blank line ends the header block.
        let _ = sock.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n").await;
        attacker.push(sock);
    }
    // AUDIT: justified-sleep: no observable signal that the accept loop has admitted every socket (B6).
    tokio::time::sleep(Duration::from_millis(200)).await;

    let started = Instant::now();
    let status = tokio::time::timeout(HEADER_READ_TIMEOUT * 3, async {
        let mut sock = connect_from(CLIENT, addr).await;
        get_health(&mut sock).await
    })
    .await
    .expect("the well-behaved client got no answer at all: the attacker holds every slot");
    let elapsed = started.elapsed();

    assert!(
        status.starts_with("HTTP/1.1 200"),
        "the well-behaved client must be served while the attack is in progress; got {status:?}"
    );
    assert!(
        elapsed < HEADER_READ_TIMEOUT,
        "the client was served after {elapsed:?} — only once the attacker's connections timed \
         out. One address must not be able to hold every connection slot \
         (operational.max_connections_per_ip)."
    );
    drop(attacker);
}

// ─────────────────────────────────────────────────────────────────────────────
// Stalled connections are closed
// ─────────────────────────────────────────────────────────────────────────────

/// A connection whose request headers never finish is closed once
/// `operational.header_read_timeout_secs` passes.
#[tokio::test]
async fn a_connection_with_unfinished_headers_is_closed_after_the_header_timeout() {
    install_limits();
    let (addr, _shutdown) = spawn_plaintext().await;

    let mut sock = connect_from(ATTACKER, addr).await;
    sock.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n")
        .await
        .expect("write partial request");

    let closed_after = time_until_closed(&mut sock, HEADER_READ_TIMEOUT * 4).await;
    let closed_after = closed_after.expect(
        "a connection that never finished its headers was still open long after \
         operational.header_read_timeout_secs",
    );
    assert!(
        closed_after >= HEADER_READ_TIMEOUT / 2,
        "closed after {closed_after:?}, well before the header timeout — something other than \
         the timeout closed it"
    );
}

/// A connection that sends nothing at all is closed too. hyper's automatic
/// HTTP/1-vs-HTTP/2 detection waits for the first bytes with no timeout of its
/// own, so the header-read timeout alone would not reach it.
#[tokio::test]
async fn a_silent_connection_is_closed_after_the_header_timeout() {
    install_limits();
    let (addr, _shutdown) = spawn_plaintext().await;

    let mut sock = connect_from(ATTACKER, addr).await;
    let closed_after = time_until_closed(&mut sock, HEADER_READ_TIMEOUT * 4)
        .await
        .expect("a connection that sent nothing was still open long after the header timeout");
    assert!(
        closed_after >= HEADER_READ_TIMEOUT / 2,
        "closed after {closed_after:?}, well before the header timeout"
    );
}

/// A connection that stalls part-way through the HTTP/2 client preface keeps
/// protocol detection waiting; it must be closed as well.
#[tokio::test]
async fn a_connection_stalled_inside_the_http2_preface_is_closed() {
    install_limits();
    let (addr, _shutdown) = spawn_plaintext().await;

    let mut sock = connect_from(ATTACKER, addr).await;
    sock.write_all(b"PRI * HTTP/2.0\r\n")
        .await
        .expect("write partial preface");
    let closed_after = time_until_closed(&mut sock, HEADER_READ_TIMEOUT * 4).await;
    assert!(
        closed_after.is_some_and(|d| d >= HEADER_READ_TIMEOUT / 2),
        "a connection stalled inside the HTTP/2 preface must be closed by the header \
         timeout; closed after {closed_after:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-address cap
// ─────────────────────────────────────────────────────────────────────────────

/// One address gets `max_connections_per_ip` connections; the next is refused
/// at once. A trusted proxy — which carries every client behind it — is exempt.
#[tokio::test]
async fn the_per_address_cap_refuses_extra_connections_but_exempts_trusted_proxies() {
    install_limits();
    let (addr, _shutdown) = spawn_plaintext().await;

    // Fill the attacker's allowance with live keep-alive connections.
    let mut held = Vec::new();
    for i in 0..PER_IP_CAP {
        let mut sock = connect_from(ATTACKER, addr).await;
        let status = get_health(&mut sock).await;
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "connection {i} is within the allowance and must be served; got {status:?}"
        );
        held.push(sock);
    }

    let mut extra = connect_from(ATTACKER, addr).await;
    let closed_after = time_until_closed(&mut extra, HEADER_READ_TIMEOUT / 2).await;
    assert!(
        closed_after.is_some(),
        "connection {} from one address must be refused immediately, not held until a \
         timeout",
        PER_IP_CAP + 1
    );

    // The trusted proxy may exceed the per-address allowance.
    let mut proxied = Vec::new();
    for i in 0..(PER_IP_CAP + 2) {
        let mut sock = connect_from(TRUSTED_PROXY, addr).await;
        let status = get_health(&mut sock).await;
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "trusted-proxy connection {i} must not be capped per address; got {status:?}"
        );
        proxied.push(sock);
    }
    drop((held, proxied));
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS handshake deadline
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a self-signed server cert + key under `dir`.
fn generate_server_cert(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let key_pair = rcgen::KeyPair::generate().expect("keygen");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    (cert_path, key_path)
}

/// A client that opens a TCP connection to the HTTPS listener and never sends
/// a `ClientHello` must be dropped once the handshake deadline passes. Before
/// the fix the accept loop took an admission permit and then awaited the
/// handshake with no deadline, so each such socket held a slot forever.
#[tokio::test]
async fn a_stalled_tls_handshake_is_closed_after_the_handshake_timeout() {
    install_limits();
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path) = generate_server_cert(dir.path());
    let reloadable =
        hearth::protocol::tls::ReloadableTlsConfig::load(cert_path, key_path).expect("load tls");
    let server_config =
        hearth::protocol::tls::build_server_config(hearth::protocol::tls::TlsConfigParams {
            resolver: Arc::new(reloadable.resolver()),
            client_ca_path: None,
            require_client_cert: false,
            crl_paths: vec![],
            tls13_only: false,
        })
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    tokio::spawn(async move {
        let _ = http::serve_tls_router(
            listener,
            health_app(),
            acceptor,
            shutdown_rx,
            Duration::from_secs(1),
        )
        .await;
    });

    let mut sock = connect_from(ATTACKER, addr).await;
    let closed_after = time_until_closed(&mut sock, TLS_HANDSHAKE_TIMEOUT * 4).await;
    let closed_after = closed_after.expect(
        "a connection that never started its TLS handshake was still open long after \
         operational.tls_handshake_timeout_secs",
    );
    assert!(
        closed_after >= TLS_HANDSHAKE_TIMEOUT / 2,
        "closed after {closed_after:?}, well before the handshake timeout"
    );
}
