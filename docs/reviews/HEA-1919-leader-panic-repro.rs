// CTO review repro for HEA-1919 / follow-up on HEA-1920 F1.
//
// Paste into `simulation/src/tests/wal_group_commit.rs` and run:
//   cargo nextest run -p hearth-simulation repro_leader_panic
//
// Observed on acdf0b87: FAILS with "only 1 did" — the leader unwinds, but the
// two follower slots it had already drained out of `pending` into the local
// `batch` are never marked done, so they block on their condvars forever.
// The LeaderGuard only drains `gs.pending`, which no longer contains them.

/// A panic inside `pre_rotate` must not strand the in-flight batch.
#[test]
fn repro_leader_panic_strands_in_flight_batch() {
    const N: usize = 3;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("panic.wal");

    let mut wal = open_wal(
        &wal_path,
        WalConfig {
            // max_size=1 => every commit_batch triggers pre_rotate.
            max_size: 1,
            sync_mode: SyncMode::EveryWrite,
        },
    );
    wal.commit_barrier = Some(Arc::new(std::sync::Barrier::new(N)));
    let wal = Arc::new(wal);

    let (tx, rx) = std::sync::mpsc::channel::<usize>();
    for t in 0..N {
        let wal = Arc::clone(&wal);
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = wal.append_with_pre_rotate(
                    &make_entry(format!("p-{t}").as_bytes(), b"v"),
                    || panic!("simulated memtable-flush panic inside pre_rotate"),
                );
            }));
            let _ = tx.send(t);
        });
    }
    drop(tx);

    let mut finished = 0;
    while finished < N {
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(_) => finished += 1,
            Err(_) => break,
        }
    }
    assert_eq!(
        finished, N,
        "all {N} writers must return after a leader panic; only {finished} did — \
         in-flight batch members are stranded on their condvars"
    );
}
