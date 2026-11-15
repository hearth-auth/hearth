//! A backup holds a fixed amount of heap, whatever the number of users (#866).
//!
//! `POST /admin/backup` collected every user of a realm into one `Vec`,
//! serialised `users.ndjson` into one buffer and encrypted that buffer whole.
//! At 10,000,000 users in one realm the heap grew from about 650 MiB to
//! 9,632 MiB during the backup. These tests export two realms of different
//! sizes and measure the peak heap that the export holds on the calling thread.
//! The peak must not grow with the number of users.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use hearth::backup::{BackupArchive, BackupExporter, BackupManifest, ExportOptions};
use hearth::core::RealmId;
use hearth::identity::{CleartextPassword, CreateUserRequest};

// ── Peak live heap, scoped to the measuring thread ───────────────────────────

struct PeakAllocator;

thread_local! {
    /// Only the thread that sets this is measured. `const`-initialised with no
    /// destructor, so reading these from inside the allocator cannot allocate.
    static MEASURING: Cell<bool> = const { Cell::new(false) };
    /// Bytes this thread allocated and has not freed since measuring started.
    static LIVE: Cell<i64> = const { Cell::new(0) };
    /// The highest `LIVE` reached since measuring started.
    static PEAK: Cell<i64> = const { Cell::new(0) };
}

fn note(delta: i64) {
    // `try_with`: the allocator also runs during thread-local teardown.
    if MEASURING.try_with(Cell::get).unwrap_or(false) {
        let _ = LIVE.try_with(|live| {
            let now = live.get() + delta;
            live.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }
}

#[allow(clippy::cast_possible_wrap)]
fn bytes(n: usize) -> i64 {
    n as i64
}

unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(bytes(layout.size()));
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note(-bytes(layout.size()));
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(bytes(layout.size()));
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(bytes(new_size) - bytes(layout.size()));
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: PeakAllocator = PeakAllocator;

/// Runs `f` and returns its result with the peak heap it held on this thread
/// above what was live when it started.
fn peak_heap_during<T>(f: impl FnOnce() -> T) -> (T, i64) {
    LIVE.with(|live| live.set(0));
    PEAK.with(|peak| peak.set(0));
    MEASURING.with(|m| m.set(true));
    let out = f();
    MEASURING.with(|m| m.set(false));
    (out, PEAK.with(Cell::get))
}

// ── Fixture ──────────────────────────────────────────────────────────────────

/// Users in the small realm.
const SMALL: usize = 500;
/// Users in the large realm: eight times the small one.
const LARGE: usize = 4_000;
/// How much more heap the large export may hold than the small one. An export
/// that keeps the realm in memory holds about 2 KiB more for each user, so
/// about 7 MiB more here. A streaming export holds the same buffers for both.
const GROWTH_BUDGET_BYTES: i64 = 256 * 1024;
/// The heap that one export may hold at its peak: buffers of a fixed size
/// (one encryption chunk, the spool and archive write buffers, one decoded
/// storage block per SST) and one record at a time.
const EXPORT_BUDGET_BYTES: i64 = 2 * 1024 * 1024;

/// Creates a realm with `users` users, each with a password.
fn realm_with_users(h: &common::TestHarness, users: usize) -> RealmId {
    let realm = h.create_realm();
    let password = CleartextPassword::from_string("Sup3rS3cret!".to_string());
    for i in 0..users {
        let user = h
            .identity()
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: format!("user-{i}@memory-bound.example"),
                    display_name: format!("Memory Bound User {i}"),
                    first_name: "Memory".into(),
                    last_name: "Bound".into(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");
        h.identity()
            .set_password(&realm, user.id(), &password)
            .expect("set password");
    }
    realm
}

/// Exports `realm` into a new archive and returns the peak heap of the export
/// and the number of users in the archive.
fn export_peak(h: &common::TestHarness, realm: &RealmId) -> (i64, u64) {
    let exporter = BackupExporter::new(
        h.identity_arc(),
        h.audit_arc(),
        h.rbac_arc(),
        h.webhooks_arc(),
    )
    .snapshot()
    .expect("snapshot");
    let dek = BackupExporter::generate_dek().expect("generate DEK");
    let archive = tempfile::NamedTempFile::new().expect("tempfile");
    let mut writer = BackupArchive::create(archive.path()).expect("create archive");

    let (manifest, peak) = peak_heap_during(|| {
        let realm_manifest = exporter
            .export_realm(realm, &mut writer, &ExportOptions::default(), &dek)
            .expect("export realm");
        writer
            .finish(BackupManifest::new(vec![realm_manifest.clone()]))
            .expect("finish archive");
        realm_manifest
    });

    let reader = BackupArchive::open(archive.path()).expect("open archive");
    reader.verify_checksums().expect("the archive verifies");
    (peak, manifest.record_counts.users)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_heap_of_a_backup_does_not_grow_with_the_number_of_users() {
    let harness = common::TestHarness::in_process().await.expect("harness");
    let small = realm_with_users(&harness, SMALL);
    let large = realm_with_users(&harness, LARGE);

    let (small_peak, small_users) = export_peak(&harness, &small);
    let (large_peak, large_users) = export_peak(&harness, &large);

    assert_eq!(small_users, SMALL as u64, "every user of the small realm");
    assert_eq!(large_users, LARGE as u64, "every user of the large realm");
    assert!(
        large_peak - small_peak <= GROWTH_BUDGET_BYTES,
        "the export of {LARGE} users held {large_peak} bytes of heap at its peak and the \
         export of {SMALL} users {small_peak} bytes: the heap grows with the users \
         (budget for the difference {GROWTH_BUDGET_BYTES})"
    );
    assert!(
        large_peak <= EXPORT_BUDGET_BYTES,
        "the export of {LARGE} users held {large_peak} bytes of heap at its peak \
         (budget {EXPORT_BUDGET_BYTES})"
    );
}
