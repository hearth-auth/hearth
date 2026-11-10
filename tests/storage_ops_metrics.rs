//! #648: the storage metrics an operator alerts on — WAL fsync latency,
//! compaction runs, and the free space of the data directory.
//!
//! The metrics registry is a process-global singleton, so each check compares
//! the values before and after one storage operation.

use hearth::core::RealmId;
use hearth::metrics::metrics;
use hearth::storage::wal::SyncMode;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// The value of the first sample line that starts with `line_prefix`
/// followed by a space. `None` when the series is absent.
fn sample(render: &str, line_prefix: &str) -> Option<f64> {
    render.lines().find_map(|line| {
        line.strip_prefix(line_prefix)
            .and_then(|rest| rest.strip_prefix(' '))
            .and_then(|v| v.trim().parse::<f64>().ok())
    })
}

fn value(line_prefix: &str) -> f64 {
    sample(&metrics().render(), line_prefix).unwrap_or(0.0)
}

/// An engine that fsyncs every write, flushes the memtable after a few
/// writes, and compacts only when the test asks.
fn engine(dir: &std::path::Path, sync_mode: SyncMode) -> EmbeddedStorageEngine {
    let mut config = StorageConfig::dev(dir.to_path_buf());
    config.wal_config.sync_mode = sync_mode;
    config.set_memtable_flush_bytes(64);
    config.compaction = CompactionConfig {
        enabled: false,
        interval_secs: 0,
        min_sst_count: 2,
        max_sst_count: 0,
        merge_min: 4,
    };
    EmbeddedStorageEngine::open(config).expect("open")
}

#[test]
fn each_wal_fsync_is_timed() {
    const COUNT: &str = "hearth_storage_wal_fsync_duration_seconds_count";
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = engine(dir.path(), SyncMode::EveryWrite);
    let realm = RealmId::generate();

    let before = value(COUNT);
    engine.put(&realm, b"k", b"v").expect("put");
    let after = value(COUNT);
    assert!(
        after >= before + 1.0,
        "a durable write must record one WAL fsync ({before} -> {after})"
    );
}

#[test]
fn a_compaction_is_counted_timed_and_stamped() {
    const OK: &str = "hearth_storage_compactions_total{kind=\"full\",outcome=\"ok\"}";
    const DURATION: &str = "hearth_storage_compaction_duration_seconds_count{kind=\"full\"}";
    const LAST: &str = "hearth_storage_compaction_last_success_timestamp_seconds";

    let rendered = metrics().render();
    for series in [
        OK,
        "hearth_storage_compactions_total{kind=\"full\",outcome=\"error\"}",
        "hearth_storage_compactions_total{kind=\"partial\",outcome=\"ok\"}",
        "hearth_storage_compactions_total{kind=\"partial\",outcome=\"error\"}",
    ] {
        assert!(
            sample(&rendered, series).is_some(),
            "{series} must be on the first scrape, at 0, so an alert on it can fire"
        );
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = engine(dir.path(), SyncMode::None);
    let realm = RealmId::generate();
    for i in 0u32..50 {
        engine
            .put(&realm, format!("k-{i:04}").as_bytes(), b"value")
            .expect("put");
    }

    let ok_before = value(OK);
    let duration_before = value(DURATION);
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs_f64();
    let merged = engine.compact_ssts(2).expect("compact");
    assert!(merged >= 2, "the test needs a real merge, merged {merged}");

    let ok_after = value(OK);
    assert!(
        ok_after >= ok_before + 1.0,
        "a merge must count as one ok compaction ({ok_before} -> {ok_after})"
    );
    let duration_after = value(DURATION);
    assert!(
        duration_after >= duration_before + 1.0,
        "a merge must record its duration ({duration_before} -> {duration_after})"
    );
    let last = value(LAST);
    assert!(
        last >= started.floor(),
        "the last-success time {last} must not be before the merge started at {started}"
    );

    // A pass with nothing to merge is not a compaction.
    let ok_idle = value(OK);
    assert_eq!(engine.compact_ssts(1_000).expect("idle pass"), 0);
    assert!(
        (value(OK) - ok_idle).abs() < f64::EPSILON,
        "a pass that merged nothing must not count as a compaction"
    );
}

#[test]
fn the_data_dir_free_space_is_read_at_each_scrape() {
    const AVAILABLE: &str = "hearth_storage_data_dir_available_bytes";
    const TOTAL: &str = "hearth_storage_data_dir_total_bytes";

    let before = metrics().render();
    assert!(
        sample(&before, AVAILABLE).is_none(),
        "no data-dir gauges before a data dir is installed"
    );

    let parent = tempfile::tempdir().expect("tempdir");
    let data_dir = parent.path().join("data");
    std::fs::create_dir(&data_dir).expect("create data dir");
    metrics()
        .export_data_dir_space(data_dir.clone())
        .expect("first install");

    let rendered = metrics().render();
    let available = sample(&rendered, AVAILABLE).expect("available bytes exported");
    let total = sample(&rendered, TOTAL).expect("total bytes exported");
    assert!(total > 0.0, "the file system has a size, got {total}");
    assert!(
        available <= total,
        "available {available} cannot exceed total {total}"
    );

    assert!(
        metrics().export_data_dir_space(data_dir.clone()).is_err(),
        "a second install must fail, not export the gauges twice"
    );

    // A failed read exports nothing: a 0 would read as a full disk.
    std::fs::remove_dir(&data_dir).expect("remove data dir");
    let rendered = metrics().render();
    assert!(
        sample(&rendered, AVAILABLE).is_none() && sample(&rendered, TOTAL).is_none(),
        "no data-dir gauges when the data dir cannot be read"
    );
}

/// #648: `hearth_backup_last_success_timestamp_seconds{source}` reads the
/// backup markers in the data directory at each scrape. A source with no
/// backup reads 0, so a backup-age alert also fires when no backup ever ran.
#[test]
fn the_backup_time_gauge_reads_the_markers_at_each_scrape() {
    use hearth::backup::marker::{record_success, BackupSource};
    const ONLINE: &str = "hearth_backup_last_success_timestamp_seconds{source=\"online\"}";
    const OFFLINE: &str = "hearth_backup_last_success_timestamp_seconds{source=\"offline\"}";

    assert!(
        sample(&metrics().render(), ONLINE).is_none(),
        "no backup gauge before a data dir is installed"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    metrics()
        .export_backup_status(dir.path().to_path_buf())
        .expect("first install");

    let rendered = metrics().render();
    assert_eq!(sample(&rendered, ONLINE), Some(0.0), "no online backup yet");
    assert_eq!(
        sample(&rendered, OFFLINE),
        Some(0.0),
        "no offline backup yet"
    );

    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000);
    record_success(dir.path(), BackupSource::Offline, at).expect("record");
    let rendered = metrics().render();
    assert_eq!(sample(&rendered, OFFLINE), Some(1_800_000_000.0));
    assert_eq!(sample(&rendered, ONLINE), Some(0.0));

    assert!(
        metrics()
            .export_backup_status(dir.path().to_path_buf())
            .is_err(),
        "a second install must fail, not export the gauge twice"
    );
}
