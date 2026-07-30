//! HEA-1946 · K7 disk-footprint — how compressible are Hearth's stored bytes?
//!
//! ## Why this exists
//!
//! `docs/perf/HEA-1904-C0-RERUN-POST-LAYERBA.md` measured **2,840 B on disk per
//! user**; the VISION K7 budget is **2,147 B/user** (200 GB @ 100M users). The
//! gap is 1.4×. Two candidate remediations are on the table:
//!
//! * **Option A** — ZSTD block compression inside SST v3 (compress-then-encrypt,
//!   per ~4 KiB block).
//! * **Option B** — a compact bit-packed audit-event encoding only.
//!
//! Choosing between them needs a real compressibility number for the *actual*
//! stored payload bytes, not a guess.
//!
//! ## Method (every number below is produced this way)
//!
//! 1. **Seed through the real API.** An [`EmbeddedIdentityEngine`] is built over
//!    a real [`EmbeddedStorageEngine`] in a temp dir with [`StorageConfig::dev`]
//!    — the same storage profile the `--dev` server used for the HEA-1904 C0
//!    run. Each user is created with `IdentityEngine::create_user` (which itself
//!    emits one `UserCreated` audit event through the real audit engine), then a
//!    second `UserCreated` audit event is appended exactly as
//!    `admin_create_user` in `src/protocol/http/admin.rs` does
//!    (`metadata = {"via":"admin_api"}`). That pair is the complete storage
//!    footprint of one `POST /admin/users`, which is what the C0 seed drove.
//!    **Nothing is synthesized** — all encodings are the production postcard /
//!    binary encodings.
//! 2. **Validation gate.** Actual bytes on disk in the data dir ÷ N is compared
//!    against the 2,840 B/user baseline. If it is outside ±25 %, the corpus is
//!    not representative and every ratio below is untrustworthy — the harness
//!    says so loudly.
//! 3. **Read back plaintext.** Every stored `(key, value)` is read via the
//!    public `StorageEngine::scan`, which yields *plaintext* (pre-encryption)
//!    bytes.
//! 4. **Reframe into SST blocks.** Entries are concatenated in key order using
//!    the byte-exact framing of `SstWriter::serialize_entry`
//!    (`src/storage/sst.rs`): `tag u8 | realm uuid 16B | key_len u32 LE | key |
//!    val_len u32 LE | value`, sealed into a block once the block reaches
//!    `V3_BLOCK_TARGET_BYTES = 4096` without ever splitting an entry.
//! 5. **Compress.** Each block is compressed *independently* with `zstd` at
//!    levels 1 / 3 / 6 — independence matters because SST v3 seals and AEADs
//!    each block on its own, so no cross-block dictionary is available.
//! 6. **Attribute.** The same measurement is repeated per record class, bucketed
//!    by key prefix (`usr:id:`, `usr:email:`, `audit:*`, other), so Option B's
//!    ceiling can be read directly off the audit class's byte share.
//!
//! Run:  `cargo run --release --example sst_compression_probe [N]`  (N default 4000)

// Measurement binary: casts are reporting math on small magnitudes, and the
// print helpers are intentionally verbose for auditability.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    // `main` is a linear measurement script: seed, gate, read back, compress,
    // report. Splitting it into helpers would hide the execution order that
    // makes the methodology auditable.
    clippy::too_many_lines
)]

use std::sync::Arc;
use std::time::Instant;

use hearth::audit::{AuditAction, AuditEngine, CreateAuditEvent, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Plaintext block target, byte-for-byte the `V3_BLOCK_TARGET_BYTES` constant in
/// `src/storage/sst.rs`. A block is sealed on the first entry that takes it to
/// or past this size; entries are never split.
const V3_BLOCK_TARGET_BYTES: usize = 4096;

/// Measured bytes-on-disk per user from `HEA-1904-C0-RERUN-POST-LAYERBA.md`
/// (OLS slope over N = 200 / 1k / 4k / 12k).
const BASELINE_DISK_BYTES_PER_USER: f64 = 2840.0;

/// VISION K7 budget: 100M users in under 200 GB.
const K7_BUDGET_BYTES_PER_USER: f64 = 2147.0;

/// Tolerance band for the validation gate, as a fraction of the baseline.
const GATE_TOLERANCE: f64 = 0.25;

/// zstd levels probed. Level 1/3/6 bracket the "fast enough for a flush" range.
const LEVELS: &[i32] = &[1, 3, 6];

/// Default corpus size when no CLI argument is given.
const DEFAULT_USERS: usize = 4000;

/// Record classes, bucketed by storage key prefix.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    /// `usr:id:<uuid>` — the primary `User` record.
    UserPrimary,
    /// `usr:email:<email>` — the email→id secondary index.
    EmailIndex,
    /// `audit:evt:` / `audit:actor:` / `audit:action:` / the signed chain head.
    Audit,
    /// Realm records, signing keys, and anything else the seed happens to write.
    Other,
}

impl Class {
    /// Human label used in the report tables.
    fn label(self) -> &'static str {
        match self {
            Class::UserPrimary => "user primary (usr:id:)",
            Class::EmailIndex => "email index (usr:email:)",
            Class::Audit => "audit (audit:*)",
            Class::Other => "other (realm/keys/misc)",
        }
    }

    /// Classifies a raw storage key by its ASCII prefix.
    fn of(key: &[u8]) -> Class {
        if key.starts_with(b"usr:id:") {
            Class::UserPrimary
        } else if key.starts_with(b"usr:email:") {
            Class::EmailIndex
        } else if key.starts_with(b"audit:") {
            Class::Audit
        } else {
            Class::Other
        }
    }
}

/// All four classes in report order.
const ALL_CLASSES: &[Class] = &[
    Class::UserPrimary,
    Class::EmailIndex,
    Class::Audit,
    Class::Other,
];

/// Appends one entry to `buf` using the byte-exact framing of
/// `SstWriter::serialize_entry` in `src/storage/sst.rs`.
///
/// Layout: `tag u8 (0x00 = data) | realm uuid 16B | key_len u32 LE | key |
/// val_len u32 LE | value`. Only live (non-tombstone) entries are produced by
/// `scan`, so the tag is always `0x00`.
fn serialize_entry(buf: &mut Vec<u8>, realm: &RealmId, key: &[u8], value: &[u8]) {
    buf.push(0x00);
    buf.extend_from_slice(realm.as_uuid().as_bytes());
    buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
    buf.extend_from_slice(key);
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
}

/// Packs `(key, value)` pairs — already in key order — into ~4 KiB plaintext
/// blocks using the SST v3 sealing rule.
fn pack_blocks(realm: &RealmId, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    for (k, v) in entries {
        serialize_entry(&mut cur, realm, k, v);
        if cur.len() >= V3_BLOCK_TARGET_BYTES {
            blocks.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }
    blocks
}

/// Result of compressing a block set at one zstd level.
struct LevelResult {
    /// Sum of uncompressed block bytes.
    raw: usize,
    /// Sum of compressed block bytes.
    compressed: usize,
    /// Wall time spent compressing, in seconds.
    secs: f64,
}

impl LevelResult {
    /// compressed ÷ uncompressed (lower is better).
    fn ratio(&self) -> f64 {
        self.compressed as f64 / self.raw.max(1) as f64
    }

    /// Compression throughput over the uncompressed input, in MB/s (10^6).
    fn mb_per_sec(&self) -> f64 {
        (self.raw as f64 / 1e6) / self.secs.max(f64::EPSILON)
    }
}

/// Compresses every block independently at `level` and totals the results.
///
/// `reps` timed passes are run and the **fastest** is kept. A discarded warm-up
/// pass precedes them so the reported throughput is not polluted by first-touch
/// page faults on the freshly-built block buffers — without it, the first level
/// probed measured ~3× slower than the rest purely from cold-cache effects.
fn compress_blocks(blocks: &[Vec<u8>], level: i32, reps: u32) -> LevelResult {
    let raw: usize = blocks.iter().map(Vec::len).sum();
    let mut compressed = 0usize;

    // Warm-up: touch every block, discard timing.
    for b in blocks {
        let out = zstd::bulk::compress(b, level).expect("zstd compress");
        compressed = compressed.saturating_add(out.len());
    }
    compressed = 0;

    let mut best = f64::INFINITY;
    for _ in 0..reps.max(1) {
        let mut total = 0usize;
        let start = Instant::now();
        for b in blocks {
            let out = zstd::bulk::compress(b, level).expect("zstd compress");
            total += out.len();
        }
        let secs = start.elapsed().as_secs_f64();
        if secs < best {
            best = secs;
        }
        compressed = total;
    }

    LevelResult {
        raw,
        compressed,
        secs: best,
    }
}

/// Recursively sums the byte length of every regular file under `dir`,
/// partitioned into (WAL bytes, SST bytes, other bytes).
fn disk_usage(dir: &std::path::Path) -> (u64, u64, u64) {
    let (mut wal, mut sst, mut other) = (0u64, 0u64, 0u64);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&p) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(md) = entry.metadata() else { continue };
            if md.is_dir() {
                stack.push(path);
            } else if md.is_file() {
                let name = path.to_string_lossy().to_lowercase();
                let len = md.len();
                if name.contains("wal") {
                    wal += len;
                } else if std::path::Path::new(&name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("sst"))
                {
                    sst += len;
                } else {
                    other += len;
                }
            }
        }
    }
    (wal, sst, other)
}

fn main() {
    let n_users: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_USERS);

    println!("HEA-1946 · SST payload compressibility probe");
    println!("corpus: {n_users} users, real create_user + 2 audit events each\n");

    // ---------------------------------------------------------------- seed
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
        IdentityConfig::default(),
        Arc::clone(&audit),
    )
    .expect("identity engine");

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "compression-probe".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let seed_start = Instant::now();
    for i in 0..n_users {
        // Email shape matches loadtest/src/params.rs::user_email, which is what
        // produced the 2,840 B/user baseline.
        let email = format!("loaduser-1-r0-u{i}@loadtest.test");
        let user = identity
            .create_user(
                &realm_id,
                &CreateUserRequest {
                    email,
                    display_name: "Load Test User".to_string(),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create_user");
        // Mirrors src/protocol/http/admin.rs::admin_create_user exactly.
        audit
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: user.id().as_uuid().to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: user.id().as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            })
            .expect("audit append");
    }
    let seed_secs = seed_start.elapsed().as_secs_f64();

    // ------------------------------------------------------ validation gate
    let (wal_b, sst_b, other_b) = disk_usage(dir.path());
    let disk_total = wal_b + sst_b + other_b;
    let disk_per_user = disk_total as f64 / n_users as f64;
    let deviation = (disk_per_user - BASELINE_DISK_BYTES_PER_USER) / BASELINE_DISK_BYTES_PER_USER;
    let gate_pass = deviation.abs() <= GATE_TOLERANCE;

    println!("=== 1. VALIDATION GATE ===");
    println!(
        "seed time              : {seed_secs:.2} s ({:.3} ms/user)",
        seed_secs * 1000.0 / n_users as f64
    );
    println!("bytes on disk (total)  : {disk_total}");
    println!(
        "  WAL                  : {wal_b} ({:.1}%)",
        100.0 * wal_b as f64 / disk_total.max(1) as f64
    );
    println!(
        "  SST                  : {sst_b} ({:.1}%)",
        100.0 * sst_b as f64 / disk_total.max(1) as f64
    );
    println!(
        "  other                : {other_b} ({:.1}%)",
        100.0 * other_b as f64 / disk_total.max(1) as f64
    );
    println!("bytes on disk PER USER : {disk_per_user:.0} B");
    println!("baseline (HEA-1904)    : {BASELINE_DISK_BYTES_PER_USER:.0} B");
    println!("deviation              : {:+.1}%", deviation * 100.0);
    if gate_pass {
        println!(
            "GATE: PASS — corpus is within +/-{:.0}% of the measured baseline.",
            GATE_TOLERANCE * 100.0
        );
    } else {
        println!(
            "GATE: *** FAIL *** — corpus is NOT representative ({:+.1}%, band is +/-{:.0}%).",
            deviation * 100.0,
            GATE_TOLERANCE * 100.0
        );
        println!(
            "      >>> Every compression ratio below is UNTRUSTWORTHY as a K7 projection. <<<"
        );
    }
    println!(
        "sst bytes per user     : {:.0} B  (steady-state asymptote once the WAL rotates)",
        sst_b as f64 / n_users as f64
    );

    // ------------------------------------------------- read back plaintext
    let end = vec![0xffu8; 32];
    let mut entries = storage.scan(&realm_id, &[], &end).expect("scan");
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = entries.into_iter().map(|e| (e.key, e.value)).collect();

    let logical_bytes: usize = pairs.iter().map(|(k, v)| k.len() + v.len()).sum();
    println!("\n=== 2. LIVE PLAINTEXT CORPUS (via StorageEngine::scan) ===");
    println!(
        "live keys              : {} ({:.2} per user)",
        pairs.len(),
        pairs.len() as f64 / n_users as f64
    );
    println!(
        "logical key+value bytes: {logical_bytes} ({:.0} B/user)",
        logical_bytes as f64 / n_users as f64
    );
    println!(
        "NOTE: scan returns only the LATEST value per key. Overwritten keys (the audit\n\
         chain head, written once per event) are collapsed to one. Disk holds every\n\
         version until compaction, so live-plaintext B/user < on-disk B/user by design."
    );

    // ------------------------------------------------------ whole-corpus zstd
    let blocks = pack_blocks(&realm_id, &pairs);
    let framed: usize = blocks.iter().map(Vec::len).sum();
    println!("\n=== 3. WHOLE-CORPUS BLOCK COMPRESSION (independent 4 KiB blocks) ===");
    println!(
        "blocks                 : {} (target {V3_BLOCK_TARGET_BYTES} B, SST v3 framing)",
        blocks.len()
    );
    println!("framed plaintext bytes : {framed}");
    println!();
    println!(
        "{:>5} | {:>7} | {:>13} | {:>13} | {:>12} | {:>6}",
        "lvl", "ratio", "B/user (SST)", "B/user (all)", "GiB @ 100M", "K7"
    );
    println!("{}", "-".repeat(76));

    let mut whole: Vec<(i32, LevelResult)> = Vec::new();
    for &lvl in LEVELS {
        let r = compress_blocks(&blocks, lvl, 3);
        // Honest projection: compression lands only on SST bytes; the WAL is
        // written uncompressed and is not touched by Option A.
        let proj_sst_only =
            (sst_b as f64 * r.ratio() + wal_b as f64 + other_b as f64) / n_users as f64;
        // Steady-state projection: at 100M users the WAL is bounded by
        // wal_max_size and rotates away, so per-user disk is SST-dominated.
        let proj_steady = (sst_b as f64 * r.ratio()) / n_users as f64;
        let gib = proj_steady * 100e6 / (1024.0 * 1024.0 * 1024.0);
        let verdict = if proj_steady < K7_BUDGET_BYTES_PER_USER {
            "PASS"
        } else {
            "MISS"
        };
        println!(
            "{lvl:>5} | {:>7.4} | {proj_steady:>13.0} | {proj_sst_only:>13.0} | {gib:>12.1} | {verdict:>6}",
            r.ratio()
        );
        whole.push((lvl, r));
    }
    println!(
        "  B/user (SST)  = SST-only steady state: sst_bytes x ratio / N  <- the K7 verdict column\n\
         \x20 B/user (all)  = today's mixed corpus: (sst x ratio + wal + other) / N\n\
         \x20 K7 budget     = {K7_BUDGET_BYTES_PER_USER:.0} B/user (200 GB @ 100M users)"
    );

    // --------------------------------------------------------- throughput
    println!("\n=== 4. COMPRESSION THROUGHPUT (write path) ===");
    println!("{:>5} | {:>12} | {:>10}", "lvl", "MB/s", "s / GiB");
    println!("{}", "-".repeat(33));
    for (lvl, r) in &whole {
        let mbps = r.mb_per_sec();
        println!(
            "{lvl:>5} | {mbps:>12.1} | {:>10.2}",
            1073.74 / mbps.max(f64::EPSILON)
        );
    }
    println!("(single-threaded, one 4 KiB block at a time — matches how SST v3 seals blocks)");

    // ------------------------------------------------------ per-class break
    println!("\n=== 5. PER-RECORD-CLASS BREAKDOWN ===");
    println!(
        "{:>26} | {:>7} | {:>12} | {:>7} | {:>8} | {:>8} | {:>8}",
        "class", "keys", "framed B", "share", "zstd-1", "zstd-3", "zstd-6"
    );
    println!("{}", "-".repeat(96));
    for &class in ALL_CLASSES {
        let subset: Vec<(Vec<u8>, Vec<u8>)> = pairs
            .iter()
            .filter(|(k, _)| Class::of(k) == class)
            .cloned()
            .collect();
        if subset.is_empty() {
            continue;
        }
        let sub_blocks = pack_blocks(&realm_id, &subset);
        let sub_framed: usize = sub_blocks.iter().map(Vec::len).sum();
        let share = 100.0 * sub_framed as f64 / framed.max(1) as f64;
        // Ratios only here — 1 rep is enough, no timing is reported.
        let r1 = compress_blocks(&sub_blocks, 1, 1).ratio();
        let r3 = compress_blocks(&sub_blocks, 3, 1).ratio();
        let r6 = compress_blocks(&sub_blocks, 6, 1).ratio();
        println!(
            "{:>26} | {:>7} | {sub_framed:>12} | {share:>6.1}% | {r1:>8.4} | {r3:>8.4} | {r6:>8.4}",
            class.label(),
            subset.len()
        );
    }
    println!(
        "NOTE: each class is packed into its OWN 4 KiB blocks here, so its ratio is the\n\
         standalone compressibility of that class. In a real SST the classes interleave\n\
         by key order, so per-class blocks do not exist — this table answers 'could\n\
         Option B alone be enough?', not 'what would a real SST block look like?'."
    );

    // ------------------------------------------------------- Option B bound
    let audit_subset: Vec<(Vec<u8>, Vec<u8>)> = pairs
        .iter()
        .filter(|(k, _)| Class::of(k) == Class::Audit)
        .cloned()
        .collect();
    let audit_blocks = pack_blocks(&realm_id, &audit_subset);
    let audit_framed: usize = audit_blocks.iter().map(Vec::len).sum();
    let audit_share = audit_framed as f64 / framed.max(1) as f64;
    println!("\n=== 6. OPTION B CEILING ===");
    println!(
        "audit share of framed plaintext : {:.1}%",
        audit_share * 100.0
    );
    println!(
        "Even if a bit-packed audit encoding shrank ALL audit bytes to ZERO, total\n\
         payload would fall to {:.1}% of today's. Required to clear K7 from the\n\
         measured baseline: {:.1}% (= {K7_BUDGET_BYTES_PER_USER:.0}/{BASELINE_DISK_BYTES_PER_USER:.0}).",
        (1.0 - audit_share) * 100.0,
        100.0 * K7_BUDGET_BYTES_PER_USER / BASELINE_DISK_BYTES_PER_USER
    );

    // ------------------------------------------------------------ machine
    let json_levels: Vec<String> = whole
        .iter()
        .map(|(l, r)| {
            format!(
                "{{\"level\":{l},\"ratio\":{:.6},\"mb_per_sec\":{:.2}}}",
                r.ratio(),
                r.mb_per_sec()
            )
        })
        .collect();
    println!(
        "\n===JSON===\n{{\"n_users\":{n_users},\"gate_pass\":{gate_pass},\
         \"disk_bytes_per_user\":{disk_per_user:.1},\"wal_bytes\":{wal_b},\"sst_bytes\":{sst_b},\
         \"other_bytes\":{other_b},\"live_keys\":{},\"framed_plaintext_bytes\":{framed},\
         \"audit_share\":{audit_share:.6},\"levels\":[{}]}}",
        pairs.len(),
        json_levels.join(",")
    );
}
