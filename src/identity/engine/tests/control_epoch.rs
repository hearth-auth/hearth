//! The persisted control epoch only ever moves forward.
//!
//! Every local control write (JTI revocation, DPoP block, realm status change,
//! session revocation) bumps the control epoch so other nodes reload their
//! control caches. The bump used to be a read-then-write on the epoch row, so
//! two concurrent bumps could interleave like this:
//!
//! ```text
//! C reads 5 · D writes 6 · E writes 7 · C writes 6 · F reads 6, writes 7
//! ```
//!
//! The persisted epoch went 7 → 6 → 7. A follower that had already reloaded at
//! 7 treats F's 7 as nothing new, so F's control — a suspension, a DPoP block,
//! a session revocation — never binds there. The bump must be one atomic
//! increment: N bumps move the epoch by exactly N.

use super::*;

use std::sync::{Arc, Barrier};

const THREADS: usize = 16;
const BUMPS_PER_THREAD: usize = 40;

fn persisted_epoch(engine: &EmbeddedIdentityEngine) -> u64 {
    let raw = engine
        .storage
        .get(&keys::system_realm_id(), &keys::encode_control_epoch())
        .expect("read the control epoch");
    raw.map_or(0, |bytes| {
        u64::from_le_bytes(
            <[u8; 8]>::try_from(bytes.as_slice()).expect("the control epoch is 8 bytes"),
        )
    })
}

#[test]
fn concurrent_control_epoch_bumps_are_never_lost() {
    let (_dir, engine, _clock) = setup_engine();
    let engine = Arc::new(engine);
    let before = persisted_epoch(&engine);

    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..BUMPS_PER_THREAD {
                    engine.bump_control_epoch();
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("bumping thread");
    }

    let expected = before + (THREADS * BUMPS_PER_THREAD) as u64;
    let after = persisted_epoch(&engine);
    assert_eq!(
        after,
        expected,
        "{THREADS} x {BUMPS_PER_THREAD} concurrent bumps moved the persisted control epoch \
         from {before} to {after}; {} increments were lost, so the epoch can move backwards \
         and a follower that already reloaded at the higher value ignores a later control",
        expected.saturating_sub(after)
    );
}
