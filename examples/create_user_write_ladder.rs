//! HEA-1896 · C0 follow-up — `create_user` write-path ms/user ladder.
//!
//! Isolates the one thing the batching change touches: the number of
//! `Memtable::put` copy-on-write cycles per user create. `Memtable::put`
//! deep-clones the entire backing `BTreeMap` on **every** call, so the two
//! user-key writes `create_user` used to issue reallocated the whole (growing)
//! memtable twice per user. Collapsing them into one `put_batch` clones it
//! once. The audit append was already a single `put_batch` and is held
//! identical across both arms, so the only variable under test is the
//! user-key write method.
//!
//! This drives [`EmbeddedStorageEngine`] directly, in-process, with the
//! production default flush threshold (64 MiB) so the memtable accumulates to
//! the same size class as the server-side C0 seed — that growth is exactly
//! what makes an O(N)-per-put path show a rising ms/user. HTTP is out of the
//! loop for the same reason C5/C2 drive the engine directly (HEA-1873): the
//! generator/server co-residency ceiling would void the attribution.
//!
//! Run:  `cargo run --release --example create_user_write_ladder`
//!
//! Reports ms/user at N = 200 / 1 000 / 4 000 / 12 000 for both the legacy
//! two-put arm and the batched arm, plus the slope (ms/user at max N ÷ ms/user
//! at min N). Success = the batched arm's slope is measurably flatter.

// Measurement binary: casts are for reporting math; the print helpers are
// intentionally verbose for auditability.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::time::Instant;

use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Corpus ladder — matches the C0 seed ladder in
/// `docs/perf/HEA-1867-record-size-analysis.md`.
const LADDER: &[usize] = &[200, 1_000, 4_000, 12_000];

/// Representative serialized `User` record size (matches the C2/complexity
/// harness, HEA-1867 finding 3).
const USER_RECORD_BYTES: usize = 300;

/// Representative audit primary-event value size.
const AUDIT_EVENT_BYTES: usize = 400;

/// Builds a value blob of `n` bytes with a per-user discriminator so entries
/// are distinct (no accidental dedupe in the map).
fn blob(n: usize, seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; n];
    let s = seed.to_le_bytes();
    for (i, b) in v.iter_mut().enumerate() {
        *b = s[i % s.len()];
    }
    v
}

/// The audit-append write, identical in both arms: one `put_batch` of the
/// primary event + two indexes + the signed head (mirrors
/// `src/audit/engine.rs:440`).
fn audit_append(storage: &EmbeddedStorageEngine, realm: &RealmId, u: u64) {
    let primary_key = format!("aud:evt:{u:016x}").into_bytes();
    let entries = vec![
        (primary_key.clone(), blob(AUDIT_EVENT_BYTES, u)),
        (
            format!("aud:actor:{u:016x}").into_bytes(),
            primary_key.clone(),
        ),
        (format!("aud:action:{u:016x}").into_bytes(), primary_key),
        (b"aud:head".to_vec(), blob(120, u)),
    ];
    storage.put_batch(realm, &entries).expect("audit put_batch");
}

/// Seeds `n` users with the **legacy** pattern: two individual `put`s for the
/// user keys, then the audit batch.
fn seed_legacy(n: usize) -> f64 {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage =
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open");
    let realm = RealmId::generate();
    let start = Instant::now();
    for u in 0..n as u64 {
        let email_key = format!("usr:email:user-{u}@example.com").into_bytes();
        let id_key = format!("usr:id:{u:032x}").into_bytes();
        storage
            .put(&realm, &email_key, &blob(36, u))
            .expect("put email");
        storage
            .put(&realm, &id_key, &blob(USER_RECORD_BYTES, u))
            .expect("put id");
        audit_append(&storage, &realm, u);
    }
    start.elapsed().as_secs_f64() * 1000.0 / n as f64
}

/// Seeds `n` users with the **batched** pattern: one `put_batch` for the two
/// user keys, then the audit batch (mirrors the HEA-1896 change).
fn seed_batched(n: usize) -> f64 {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage =
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open");
    let realm = RealmId::generate();
    let start = Instant::now();
    for u in 0..n as u64 {
        let email_key = format!("usr:email:user-{u}@example.com").into_bytes();
        let id_key = format!("usr:id:{u:032x}").into_bytes();
        storage
            .put_batch(
                &realm,
                &[
                    (email_key, blob(36, u)),
                    (id_key, blob(USER_RECORD_BYTES, u)),
                ],
            )
            .expect("user put_batch");
        audit_append(&storage, &realm, u);
    }
    start.elapsed().as_secs_f64() * 1000.0 / n as f64
}

fn main() {
    println!("HEA-1896 create_user write-path ms/user ladder");
    println!("(EmbeddedStorageEngine, in-process, prod default 64 MiB flush)\n");
    println!(
        "{:>8} | {:>14} | {:>14}",
        "N", "legacy ms/user", "batched ms/user"
    );
    println!("{}", "-".repeat(44));

    let mut legacy = Vec::new();
    let mut batched = Vec::new();
    for &n in LADDER {
        let l = seed_legacy(n);
        let b = seed_batched(n);
        legacy.push(l);
        batched.push(b);
        println!("{n:>8} | {l:>14.3} | {b:>14.3}");
    }

    let legacy_slope = legacy[legacy.len() - 1] / legacy[0];
    let batched_slope = batched[batched.len() - 1] / batched[0];
    println!("\nslope (max N / min N):");
    println!("  legacy : {legacy_slope:.2}x");
    println!("  batched: {batched_slope:.2}x");
    println!(
        "\n===JSON===\n{{\"ladder\":{LADDER:?},\"legacy_ms_per_user\":{legacy:?},\
         \"batched_ms_per_user\":{batched:?},\"legacy_slope\":{legacy_slope:.4},\
         \"batched_slope\":{batched_slope:.4}}}"
    );
}
