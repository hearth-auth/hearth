//! Black-box tests for hot-tier / storage `get` observability (HEA-1869).
//!
//! Verifies that the storage engine exports, as real Prometheus metrics, the
//! tier outcome of every `get` (hot / memtable / SST hit or miss), the
//! fall-through latency and SST-probe fan-out, hot-tier eviction/promotion
//! counts, and the live SST file count. The tier-miss load profiles (HEA-1800)
//! consume these to report an *observed* hit ratio instead of an arithmetic
//! estimate.
//!
//! All assertions are delta-based (`after >= before + 1`): the metrics registry
//! is a process-global singleton, so exact-equality on absolute values would be
//! brittle. Every check brackets exactly one storage operation, so a `+1`
//! increment must be observable regardless of what else shares the process.

use hearth::metrics::metrics;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

use hearth::core::RealmId;

/// Parses the numeric value of the first Prometheus sample line whose text
/// begins with `line_prefix`. Returns `0.0` if the series is absent (a counter
/// that has never been incremented and was never pre-created).
fn sample_value(render: &str, line_prefix: &str) -> f64 {
    for line in render.lines() {
        if let Some(rest) = line.strip_prefix(line_prefix) {
            // The remainder is either " <value>" (bare metric) or, for a metric
            // whose prefix already includes the label set, the same. Trim and
            // parse the trailing whitespace-delimited float.
            if let Some(v) = rest.split_whitespace().next() {
                if let Ok(f) = v.parse::<f64>() {
                    return f;
                }
            }
        }
    }
    0.0
}

/// Storage engine tuned so records leave the memtable (tiny flush threshold)
/// and the hot tier is easily overflowed, exercising every tier outcome.
fn engine_forcing_all_tiers() -> (tempfile::TempDir, EmbeddedStorageEngine) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig::dev(dir.path().to_path_buf());
    // Flush after only a few writes so keys land in SST files.
    config.set_memtable_flush_bytes(128);
    let engine = EmbeddedStorageEngine::open(config).expect("open");
    (dir, engine)
}

#[test]
fn get_tier_outcomes_and_fanout_are_observable() {
    let (_dir, engine) = engine_forcing_all_tiers();
    let realm = RealmId::generate();

    // ── hot_hit ─────────────────────────────────────────────────────────────
    // First get promotes into the hot tier; the second is a hot-tier hit.
    engine.put(&realm, b"hot-key", b"hot-val").expect("put");
    let _ = engine.get(&realm, b"hot-key").expect("get"); // promote
    let before = metrics().render();
    let hot_before = sample_value(&before, "hearth_storage_get_total{outcome=\"hot_hit\"}");
    let val = engine.get(&realm, b"hot-key").expect("get");
    assert_eq!(val, Some(b"hot-val".to_vec()));
    let after = metrics().render();
    let hot_after = sample_value(&after, "hearth_storage_get_total{outcome=\"hot_hit\"}");
    assert!(
        hot_after >= hot_before + 1.0,
        "hot_hit counter must increment on a hot-tier hit ({hot_before} -> {hot_after})"
    );

    // ── miss ────────────────────────────────────────────────────────────────
    let before = metrics().render();
    let miss_before = sample_value(&before, "hearth_storage_get_total{outcome=\"miss\"}");
    assert_eq!(engine.get(&realm, b"absent-key").expect("get"), None);
    let after = metrics().render();
    let miss_after = sample_value(&after, "hearth_storage_get_total{outcome=\"miss\"}");
    assert!(
        miss_after >= miss_before + 1.0,
        "miss counter must increment on an absent key ({miss_before} -> {miss_after})"
    );

    // ── sst_hit + probe fan-out ─────────────────────────────────────────────
    // Write many keys with a tiny flush threshold so they live in SST files,
    // then read one back with the hot tier cold for that key.
    for i in 0u32..40 {
        let k = format!("cold-{i:04}");
        engine
            .put(&realm, k.as_bytes(), b"cold-value")
            .expect("put");
    }
    let before = metrics().render();
    let sst_before = sample_value(&before, "hearth_storage_get_total{outcome=\"sst_hit\"}");
    let probe_count_before = sample_value(&before, "hearth_storage_get_ssts_probed_count");
    // A key written early is now flushed to an SST and not in the hot tier.
    let cold = engine.get(&realm, b"cold-0000").expect("get");
    assert_eq!(cold, Some(b"cold-value".to_vec()));
    let after = metrics().render();
    let sst_after = sample_value(&after, "hearth_storage_get_total{outcome=\"sst_hit\"}");
    let probe_count_after = sample_value(&after, "hearth_storage_get_ssts_probed_count");
    assert!(
        sst_after >= sst_before + 1.0,
        "sst_hit counter must increment on a cold/SST read ({sst_before} -> {sst_after})"
    );
    assert!(
        probe_count_after >= probe_count_before + 1.0,
        "ssts_probed histogram must observe the cold read ({probe_count_before} -> {probe_count_after})"
    );

    // ── fall-through latency histogram is populated for the slow tiers ──────
    let render = metrics().render();
    let sst_latency_count = sample_value(
        &render,
        "hearth_storage_get_duration_seconds_count{outcome=\"sst_hit\"}",
    );
    assert!(
        sst_latency_count >= 1.0,
        "sst_hit latency histogram must have at least one observation, render:\n{render}"
    );
    // The hot-tier-hit path is deliberately NOT timed (zero-syscall contract),
    // so no hot_hit latency series may exist.
    assert!(
        !render.contains("hearth_storage_get_duration_seconds_count{outcome=\"hot_hit\"}"),
        "hot-tier hits must not be timed (would break the zero-syscall hot-path rule)"
    );

    // ── promotions counter ──────────────────────────────────────────────────
    // A fall-through read that finds data admits a promotion into the hot tier.
    engine.put(&realm, b"promote-key", b"v").expect("put");
    let before = metrics().render();
    let promo_before = sample_value(&before, "hearth_storage_hot_tier_promotions_total");
    let _ = engine.get(&realm, b"promote-key").expect("get"); // hit -> promote
    let after = metrics().render();
    let promo_after = sample_value(&after, "hearth_storage_hot_tier_promotions_total");
    assert!(
        promo_after >= promo_before + 1.0,
        "promotions counter must increment on a fall-through hit ({promo_before} -> {promo_after})"
    );

    // ── live SST file gauge ─────────────────────────────────────────────────
    // The tiny flush threshold means the writes above already flushed SSTs.
    let render = metrics().render();
    let sst_files = sample_value(&render, "hearth_storage_sst_files");
    assert!(
        sst_files >= 1.0,
        "live SST file gauge must be positive after flushes, got {sst_files}, render:\n{render}"
    );
}

/// Storage engine with a one-entry hot tier, so the second distinct promotion
/// evicts the first. `per_realm_metrics` follows `TieredConfig::default()`
/// unless the caller turns it off.
fn engine_forcing_evictions(per_realm_metrics: bool) -> (tempfile::TempDir, EmbeddedStorageEngine) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig::dev(dir.path().to_path_buf());
    config.set_memtable_flush_bytes(128);
    config.set_hot_tier_capacity(1);
    config.set_hot_tier_per_realm_metrics(per_realm_metrics);
    let engine = EmbeddedStorageEngine::open(config).expect("open");
    (dir, engine)
}

/// Prometheus series names for one realm's hot-tier counters.
fn by_realm_series(realm: &RealmId) -> (String, String) {
    let uuid = realm.as_uuid();
    (
        format!("hearth_storage_hot_tier_promotions_by_realm_total{{realm=\"{uuid}\"}}"),
        format!("hearth_storage_hot_tier_evictions_by_realm_total{{realm=\"{uuid}\"}}"),
    )
}

/// Drives `count` distinct cold reads, each of which promotes into the hot
/// tier and — past the first — evicts the entry before it.
fn drive_promotions_and_evictions(engine: &EmbeddedStorageEngine, realm: &RealmId, count: u32) {
    for i in 0..count {
        let key = format!("k{i}");
        engine.put(realm, key.as_bytes(), b"v").expect("put");
        let _ = engine.get(realm, key.as_bytes()).expect("get");
    }
}

/// Audit 2026-08-28 §4.9#6: the hot tier is one cache shared by every tenant,
/// so the unlabelled eviction and promotion totals cannot name the realm whose
/// working set the tier is holding, nor the realm evicting the others.
#[test]
fn hot_tier_promotions_and_evictions_are_labelled_by_realm() {
    let (_dir, engine) = engine_forcing_evictions(true);
    let realm = RealmId::generate();
    let (promo_series, evict_series) = by_realm_series(&realm);

    drive_promotions_and_evictions(&engine, &realm, 8);

    let render = metrics().render();
    let promotions = sample_value(&render, &promo_series);
    let evictions = sample_value(&render, &evict_series);

    assert!(
        promotions >= 1.0,
        "promotions must be counted under the promoting realm's label \
         ({promo_series} = {promotions}), render:\n{render}"
    );
    assert!(
        evictions >= 1.0,
        "evictions must be counted under the evicted key's realm label \
         ({evict_series} = {evictions}), render:\n{render}"
    );
}

/// The `realm` label costs one series per realm on each counter, so
/// `storage.hot_tier_per_realm_metrics: false` must remove it while leaving
/// the unlabelled totals intact (audit 2026-08-28 §4.9#6).
#[test]
fn hot_tier_per_realm_metrics_can_be_switched_off() {
    let (_dir, engine) = engine_forcing_evictions(false);
    let realm = RealmId::generate();
    let (promo_series, evict_series) = by_realm_series(&realm);

    let before = metrics().render();
    let promo_total_before = sample_value(&before, "hearth_storage_hot_tier_promotions_total");
    let evict_total_before = sample_value(&before, "hearth_storage_hot_tier_evictions_total");

    drive_promotions_and_evictions(&engine, &realm, 8);

    let render = metrics().render();
    assert!(
        !render.contains(&promo_series),
        "no per-realm promotion series may exist when the knob is off, render:\n{render}"
    );
    assert!(
        !render.contains(&evict_series),
        "no per-realm eviction series may exist when the knob is off, render:\n{render}"
    );

    let promo_total_after = sample_value(&render, "hearth_storage_hot_tier_promotions_total");
    let evict_total_after = sample_value(&render, "hearth_storage_hot_tier_evictions_total");
    assert!(
        promo_total_after >= promo_total_before + 1.0,
        "the unlabelled promotion total must still count \
         ({promo_total_before} -> {promo_total_after})"
    );
    assert!(
        evict_total_after >= evict_total_before + 1.0,
        "the unlabelled eviction total must still count \
         ({evict_total_before} -> {evict_total_after})"
    );
}
