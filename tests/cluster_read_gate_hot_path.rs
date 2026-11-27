//! The read gate keeps `validate_token` free of heap allocations on a cluster
//! node (cluster-read-fencing 2.4; `CLAUDE.md` hot-path rule 1).
//!
//! `benches/validate_token.rs` gates zero allocations per warm call on
//! single-node storage, whose `serves_reads` is a constant `Ok`. This test
//! runs the same warm calls on a real cluster node: a one-voter cluster, so
//! its lag monitor records contact on every poll and writes the gate word
//! while the calls read it. Only the measuring thread's allocations count.

#![allow(clippy::unwrap_used)]

mod cluster_fixture;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::cluster::{serve, ClusterEngine, ClusterStorageAdapter, HearthNode};
use hearth::config::ClusterConfig;
use hearth::core::{Clock, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    SessionContext,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

use cluster_fixture::{generate_cluster_certs, pick_free_loopback_ports};

// ── Allocation counting, scoped to the measuring thread ──────────────────────

struct CountingAllocator;

thread_local! {
    /// Only the thread that sets this is counted, so the Raft and lag-monitor
    /// threads never contribute. `const`-initialised with no destructor, so
    /// reading it from inside the allocator cannot itself allocate.
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

fn note_allocation() {
    // `try_with`: the allocator also runs during thread-local teardown.
    if COUNTING.try_with(Cell::get).unwrap_or(false) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_allocation();
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Warm calls measured after the warm-up.
const MEASURED_CALLS: usize = 2_000;

/// A one-voter cluster node and the storage handle its application uses.
async fn one_node_cluster(dir: &std::path::Path) -> (Arc<ClusterEngine>, Arc<dyn StorageEngine>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca_path, mut leafs) = generate_cluster_certs(dir, 1);
    let (cert_path, key_path) = leafs.remove(0);
    let port = pick_free_loopback_ports(1)[0];
    let data_dir = dir.join("node-1-data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage_cfg = StorageConfig::dev(data_dir);
    let inner = Arc::new(EmbeddedStorageEngine::open(storage_cfg.clone()).unwrap());
    let cfg = ClusterConfig {
        node_id: 1,
        peer_address: format!("127.0.0.1:{port}"),
        peers: vec![],
        tls_cert_path: cert_path,
        tls_key_path: key_path,
        tls_ca_cert_path: ca_path,
        read_lag_threshold_ms: None,
        write_timeout_ms: None,
        experimental_opt_in: true,
    };
    let cluster = Arc::new(
        ClusterEngine::build_clustered(inner, &cfg, &storage_cfg)
            .await
            .unwrap(),
    );
    let serve_engine = Arc::clone(&cluster);
    let serve_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = serve(&serve_cfg, serve_engine).await;
    });
    let members = BTreeMap::from([(
        1,
        HearthNode {
            addr: cfg.peer_address.clone(),
        },
    )]);
    cluster.initialize_cluster(members).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while cluster.not_ready_reason().is_some() {
        assert!(
            Instant::now() < deadline,
            "the node was not ready in 20 s: {:?}",
            cluster.not_ready_reason()
        );
        // AUDIT: justified-sleep: poll interval for the node's election and read gate, bounded by the 20 s deadline
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let storage: Arc<dyn StorageEngine> =
        Arc::new(ClusterStorageAdapter::new(Arc::clone(&cluster)));
    (cluster, storage)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_warm_validate_token_on_a_cluster_node_allocates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (_cluster, storage) = one_node_cluster(dir.path()).await;

    let allocations = tokio::task::spawn_blocking(move || {
        let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        )) as Arc<dyn AuditEngine>;
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            clock,
            IdentityConfig::default(),
            audit,
        )
        .unwrap();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: format!("gate-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .unwrap()
            .id()
            .clone();
        let user = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "gate@example.com".to_string(),
                    display_name: "Gate User".to_string(),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .unwrap();
        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .unwrap();
        let pair = engine
            .issue_tokens(&realm, user.id(), session.id())
            .unwrap();
        let token = pair.access_token();

        // Warm every cache and this thread's epoch participant.
        for _ in 0..500 {
            black_box(engine.validate_token(&realm, token).unwrap());
        }

        ALLOCATIONS.store(0, Ordering::Relaxed);
        COUNTING.with(|c| c.set(true));
        for _ in 0..MEASURED_CALLS {
            black_box(engine.validate_token(&realm, token).unwrap());
        }
        COUNTING.with(|c| c.set(false));
        ALLOCATIONS.load(Ordering::Relaxed)
    })
    .await
    .unwrap();

    assert_eq!(
        allocations, 0,
        "{allocations} allocations across {MEASURED_CALLS} warm validate_token calls on a \
         cluster node; the read gate must keep the hot path allocation-free"
    );
}
