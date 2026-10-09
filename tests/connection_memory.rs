//! Heap cost of an open connection.
//!
//! The accept loop gave every connection its own copy of the whole router:
//! `Router::layer` re-wraps every route, so a connection cost heap in
//! proportion to the route count (~550 KB with the real router's ~370 routes).
//! A 2026-10-08 soak held ~2,000 client connections and ~2.1 GB of live heap
//! on a 4 GB host, most of it these copies. A connection must cost the same
//! at any route count.
//!
//! This binary installs a counting global allocator, so it holds only this
//! test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use hearth::protocol::http;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Live heap bytes allocated through [`CountingAlloc`].
static LIVE: AtomicIsize = AtomicIsize::new(0);

/// A `System`-backed allocator that tracks live bytes.
struct CountingAlloc;

// SAFETY: every method forwards to `System` with the same `Layout`; the only
// added work is relaxed atomic bookkeeping, which cannot affect the pointers.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size().cast_signed(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size().cast_signed(), Ordering::Relaxed);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size().cast_signed(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = System.realloc(ptr, layout, new_size);
        if !new.is_null() {
            LIVE.fetch_add(
                new_size.cast_signed() - layout.size().cast_signed(),
                Ordering::Relaxed,
            );
        }
        new
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// Routes in the test router, close to the real router's count.
const ROUTES: usize = 400;

/// Connections held open while the heap is measured.
const CONNECTIONS: usize = 50;

/// Most live heap one idle keep-alive connection may hold.
const MAX_BYTES_PER_CONNECTION: isize = 64 * 1024;

fn big_router() -> Router {
    (0..ROUTES).fold(Router::new(), |r, i| {
        r.route(&format!("/r{i}"), get(|| async { "ok" }))
    })
}

/// Opens a keep-alive connection and completes one request on it.
async fn open_and_serve_one(addr: std::net::SocketAddr) -> TcpStream {
    let mut conn = TcpStream::connect(addr).await.expect("connect");
    conn.write_all(b"GET /r0 HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .expect("write");
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await.expect("read");
    assert!(
        buf[..n].starts_with(b"HTTP/1.1 200"),
        "unexpected response: {}",
        String::from_utf8_lossy(&buf[..n])
    );
    conn
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_connection_does_not_copy_the_router() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(http::serve_router_on(
        listener,
        big_router(),
        std::future::pending(),
    ));
    // Warm up: the first connection settles the runtime's one-time allocations.
    drop(open_and_serve_one(addr).await);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let before = LIVE.load(Ordering::Relaxed);
    let mut open = Vec::with_capacity(CONNECTIONS);
    for _ in 0..CONNECTIONS {
        open.push(open_and_serve_one(addr).await);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let per_connection =
        (LIVE.load(Ordering::Relaxed) - before) / isize::try_from(CONNECTIONS).expect("small");
    drop(open);

    assert!(
        per_connection < MAX_BYTES_PER_CONNECTION,
        "each open connection holds {per_connection} live heap bytes \
         (limit {MAX_BYTES_PER_CONNECTION}) with a {ROUTES}-route router"
    );
}
