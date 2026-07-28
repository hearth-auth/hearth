//! Black-box security-property tests at the storage boundary (HEA-1834).
//!
//! These tests exercise two security claims that previously had **no**
//! black-box coverage through the public [`StorageEngine`] surface — they were
//! only enforced by in-module unit tests (`src/storage/engine.rs`) or the
//! debug-build realm tripwire (`engine.rs:664`) and the WAL/SST module tests.
//!
//! ## Coverage matrix (Phase 2 matrix, HEA-1818 ranked gaps 2 & 3)
//!
//! | Security claim | Test |
//! |---|---|
//! | Realm isolation — realm B cannot read realm A's keys via `StorageEngine` | `realm_b_cannot_read_realm_a_data` |
//! | Realm isolation — a scan in realm B never returns realm A's entries | `scan_does_not_leak_across_realms` |
//! | Encryption-at-rest — persisted bytes are ciphertext, not plaintext | `values_are_not_stored_as_plaintext_on_disk` |
//! | Encryption-at-rest — ciphertext survives a crash and reopens readable | `encrypted_data_survives_crash_recovery` |
//!
//! TDD note: each assertion is written so that inverting the guard it protects
//! fails the test. For the isolation tests, returning realm A's value for a
//! realm B lookup (or including it in a realm B scan) fails. For the at-rest
//! tests, writing plaintext to disk fails `values_are_not_stored_as_plaintext`,
//! and dropping the WAL-recovery path fails `encrypted_data_survives_crash`.

use std::sync::Arc;

use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Opens a fresh embedded engine backed by a temp dir. Returns the guard so the
/// directory outlives the engine (and can be inspected on disk).
fn open_engine(dir: &std::path::Path) -> Arc<dyn StorageEngine> {
    Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.to_path_buf())).expect("open engine"),
    ) as Arc<dyn StorageEngine>
}

/// Recursively collects every regular file's bytes under `dir`.
fn read_all_files(dir: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = std::fs::read_dir(&path).expect("read_dir");
        for entry in entries {
            let entry = entry.expect("dir entry");
            let ft = entry.file_type().expect("file type");
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file() {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    out.extend_from_slice(&bytes);
                }
            }
        }
    }
    out
}

/// Returns true if `needle` appears anywhere in `haystack`.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ===== Gap 3: realm isolation at the storage boundary =====

/// Realm B must not be able to read a key written under realm A, even when the
/// two realms use the *same* key bytes. Enforced today only by the debug-build
/// tripwire at `engine.rs:664`; this proves the invariant in release builds too.
#[test]
fn realm_b_cannot_read_realm_a_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = open_engine(dir.path());

    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    let secret = b"realm-a-only-secret-value";
    engine.put(&realm_a, b"shared-key", secret).expect("put a");

    // Realm A reads its own value.
    assert_eq!(
        engine.get(&realm_a, b"shared-key").expect("get a"),
        Some(secret.to_vec()),
        "realm A must read its own key"
    );

    // Realm B, using the identical key, must see nothing — no cross-realm read.
    assert_eq!(
        engine.get(&realm_b, b"shared-key").expect("get b"),
        None,
        "realm B must NOT read realm A's key (cross-realm isolation breach)"
    );
}

/// A range scan issued in realm B must never surface realm A's entries, even
/// when both realms populate overlapping key ranges.
#[test]
fn scan_does_not_leak_across_realms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = open_engine(dir.path());

    let realm_a = RealmId::generate();
    let realm_b = RealmId::generate();

    for i in 0..5u8 {
        let key = [b"user:", &[b'0' + i][..]].concat();
        engine.put(&realm_a, &key, b"a-value").expect("put realm a");
    }
    // Realm B has a single, distinct entry in the same key range.
    engine
        .put(&realm_b, b"user:9", b"b-value")
        .expect("put realm b");

    let b_entries = engine
        .scan(&realm_b, b"user:", b"user:~")
        .expect("scan realm b");

    assert_eq!(
        b_entries.len(),
        1,
        "realm B scan must return only realm B's entries, got {b_entries:?}"
    );
    assert_eq!(b_entries[0].key, b"user:9");
    assert_eq!(b_entries[0].value, b"b-value");
    assert!(
        b_entries.iter().all(|e| e.value != b"a-value"),
        "realm B scan leaked realm A values"
    );
}

// ===== Gap 2: encryption-at-rest (crash recovery + on-disk ciphertext) =====

/// Values written through the public engine must be stored as ciphertext on
/// disk — the plaintext must not appear verbatim in any WAL/SST file. Enforces
/// the encryption-at-rest claim through the public boundary rather than the
/// WAL/SST module internals.
#[test]
fn values_are_not_stored_as_plaintext_on_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Distinctive, high-entropy needle unlikely to collide with framing bytes.
    let plaintext = b"PLAINTEXT-NEEDLE-8f3c1a9e-do-not-persist-in-the-clear";

    {
        let engine = open_engine(dir.path());
        let realm = RealmId::generate();
        engine.put(&realm, b"at-rest-key", plaintext).expect("put");
        // Drop the engine so all buffers are flushed to the WAL on disk.
    }

    let on_disk = read_all_files(dir.path());
    assert!(
        !on_disk.is_empty(),
        "expected WAL/SST files to exist on disk after a write"
    );
    assert!(
        !contains_subslice(&on_disk, plaintext),
        "encryption-at-rest breach: plaintext value found verbatim in on-disk files"
    );
}

/// Encrypted data written before a crash must survive WAL recovery and read
/// back correctly after the engine is reopened against the same data dir.
#[test]
fn encrypted_data_survives_crash_recovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();
    let value = b"durable-encrypted-value-survives-restart";

    // First lifetime: write, then drop (simulates process exit / crash).
    {
        let engine = open_engine(dir.path());
        engine.put(&realm, b"durable-key", value).expect("put");
        engine
            .put(&realm, b"second-key", b"second-value")
            .expect("put 2");
        engine.delete(&realm, b"second-key").expect("delete");
    }

    // Second lifetime: reopen. WAL replay must decrypt and restore state.
    {
        let engine = open_engine(dir.path());
        assert_eq!(
            engine
                .get(&realm, b"durable-key")
                .expect("get after recovery"),
            Some(value.to_vec()),
            "encrypted value must survive crash recovery and decrypt correctly"
        );
        assert_eq!(
            engine
                .get(&realm, b"second-key")
                .expect("get deleted after recovery"),
            None,
            "deletion must also survive recovery (tombstone replayed)"
        );
    }
}
