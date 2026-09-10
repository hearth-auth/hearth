//! Tasks 22.5 and 22.12 — `operational.*` and `security.http2.*` reach both listeners.
//!
//! Before this, `operational.request_timeout_secs`, `operational.max_connections`
//! and `operational.queue_depth` parsed, validated, and were read by nothing: a
//! 38-second socket transcript ran to completion against a configured 5-second
//! timeout (audit 2026-08-28 §4.4#3). `security.http2.*` had the same shape,
//! and the compiled-in caps that stood in for it were applied on the TLS accept
//! loop only, leaving the plaintext listener with no `MAX_CONCURRENT_STREAMS`
//! at all (§4.12#20).
//!
//! Each test drives the real `serve_router` plaintext path — the listener
//! `main.rs` uses when no TLS certificate is configured.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::protocol::http;
use hearth::protocol::http::limits::{init_server_limits, ServerLimits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Distinctive value so a passing assertion cannot be hyper's own default.
const TEST_MAX_CONCURRENT_STREAMS: u32 = 7;

/// Short enough to keep the suite fast, long enough not to be flaky.
const TEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Installs the limits both tests in this binary share.
///
/// `init_server_limits` is a process-global `OnceLock` and nextest runs one
/// process per test binary, so the two tests below must agree on one value.
fn install_limits() {
    let _ = init_server_limits(ServerLimits {
        request_timeout: TEST_REQUEST_TIMEOUT,
        max_connections: 64,
        queue_depth: 64,
        http2_max_concurrent_streams: TEST_MAX_CONCURRENT_STREAMS,
        http2_max_pending_reset_streams: 3,
    });
}

/// Serves `app` on an ephemeral port and returns its address plus a shutdown.
async fn spawn_plaintext(
    app: axum::Router,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = http::serve_router_on(listener, app, async {
            let _ = rx.await;
        })
        .await;
    });
    (addr, tx)
}

// ─────────────────────────────────────────────────────────────────────────────
// 22.5 — operational.request_timeout_secs is enforced
// ─────────────────────────────────────────────────────────────────────────────

/// A handler that never completes must be cut off at the configured deadline.
///
/// The handler parks on a `oneshot` that is never sent rather than sleeping, so
/// the test measures the server's deadline and not a hard-coded delay.
#[tokio::test]
async fn a_handler_that_never_returns_is_cut_off_at_the_configured_timeout() {
    install_limits();

    let (_never_tx, never_rx) = tokio::sync::oneshot::channel::<()>();
    let never_rx = Arc::new(tokio::sync::Mutex::new(Some(never_rx)));
    let app = axum::Router::new().route(
        "/slow",
        axum::routing::get(move || {
            let never_rx = Arc::clone(&never_rx);
            async move {
                let rx = never_rx.lock().await.take();
                if let Some(rx) = rx {
                    let _ = rx.await;
                }
                "unreachable"
            }
        }),
    );

    let (addr, _shutdown) = spawn_plaintext(app).await;

    let started = Instant::now();
    let mut sock = TcpStream::connect(addr).await.expect("connect");
    sock.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let mut response = Vec::new();
    // The whole exchange must finish well inside a generous ceiling; without
    // the fix this read blocks until the ceiling and the test fails on it.
    let read =
        tokio::time::timeout(TEST_REQUEST_TIMEOUT * 5, sock.read_to_end(&mut response)).await;
    let elapsed = started.elapsed();

    assert!(
        read.is_ok(),
        "the server never cut off a handler that cannot complete: \
         operational.request_timeout_secs is not enforced on the plaintext listener"
    );
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 504"),
        "a handler past its deadline must be answered 504 Gateway Timeout; got: {}",
        text.lines().next().unwrap_or("<empty>")
    );
    assert!(
        elapsed >= TEST_REQUEST_TIMEOUT,
        "the response arrived after {elapsed:?}, before the configured \
         {TEST_REQUEST_TIMEOUT:?} deadline — something other than the timeout answered"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 22.12 — security.http2.* reaches the PLAINTEXT listener
// ─────────────────────────────────────────────────────────────────────────────

/// The client half of the HTTP/2 connection preface (RFC 9113 §3.4).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// `SETTINGS_MAX_CONCURRENT_STREAMS` (RFC 9113 §6.5.2).
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;

/// The plaintext listener must advertise the configured stream cap.
///
/// Read directly off the wire: connect with prior-knowledge h2c, send the
/// client preface, and parse the server's first `SETTINGS` frame. Before the
/// fix `serve_router` handed the connection to `axum::serve`, which applies no
/// HTTP/2 configuration at all — the parameter is simply absent and this test
/// fails on the lookup.
#[tokio::test]
async fn the_plaintext_listener_advertises_the_configured_http2_stream_cap() {
    install_limits();

    let app = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
    let (addr, _shutdown) = spawn_plaintext(app).await;

    let mut sock = TcpStream::connect(addr).await.expect("connect");
    sock.write_all(H2_PREFACE).await.expect("write preface");
    // The client's own (empty) SETTINGS frame completes the preface.
    sock.write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0])
        .await
        .expect("write client settings");

    let settings = tokio::time::timeout(Duration::from_secs(5), read_server_settings(&mut sock))
        .await
        .expect("the server must send its SETTINGS frame")
        .expect("read SETTINGS");

    let advertised = settings
        .iter()
        .find(|(id, _)| *id == SETTINGS_MAX_CONCURRENT_STREAMS)
        .map(|(_, value)| *value);

    assert_eq!(
        advertised,
        Some(TEST_MAX_CONCURRENT_STREAMS),
        "the plaintext listener must advertise the configured \
         security.http2.max_concurrent_streams; it advertised {advertised:?}. \
         `None` means no HTTP/2 configuration reached this listener at all — \
         the rapid-reset caps were applied on the TLS accept loop only."
    );
}

/// Reads frames until a `SETTINGS` frame arrives and returns its parameters.
async fn read_server_settings(sock: &mut TcpStream) -> std::io::Result<Vec<(u16, u32)>> {
    loop {
        let mut header = [0_u8; 9];
        sock.read_exact(&mut header).await?;
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let frame_type = header[3];
        let flags = header[4];

        let mut payload = vec![0_u8; length];
        if length > 0 {
            sock.read_exact(&mut payload).await?;
        }

        // 0x4 = SETTINGS; flag 0x1 = ACK, which carries no parameters.
        if frame_type == 0x4 && flags & 0x1 == 0 {
            let mut params = Vec::new();
            for chunk in payload.chunks_exact(6) {
                let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                params.push((id, value));
            }
            return Ok(params);
        }
    }
}
