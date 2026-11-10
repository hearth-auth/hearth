//! #648: every Prometheus metric that the docs and the shipped alert rules
//! and dashboards name must exist.
//!
//! All metrics are defined in `src/metrics.rs`, so the defined names are the
//! `"hearth_…"` string literals in that file, outside its test module.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Endings that mark a name as a metric, not a config key or a cookie name.
const METRIC_ENDINGS: &[&str] = &[
    "_total",
    "_seconds",
    "_bytes",
    "_entries",
    "_files",
    "_in_flight",
    "_permits",
    "_owed",
    "_disabled",
    "_fenced",
    "_sessions",
    "_probed",
    "_hits",
    "_misses",
];

/// A histogram's sample suffixes, which name the same metric.
const HISTOGRAM_SUFFIXES: &[&str] = &["_bucket", "_sum", "_count"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The metric names defined in `src/metrics.rs`.
fn defined() -> BTreeSet<String> {
    let src = std::fs::read_to_string(root().join("src/metrics.rs")).expect("read metrics.rs");
    let body = src.split("#[cfg(test)]").next().unwrap_or_default();
    let mut names = BTreeSet::new();
    for piece in body.split('"').skip(1).step_by(2) {
        if piece.starts_with("hearth_")
            && piece
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            names.insert(piece.to_owned());
        }
    }
    names
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e, "md" | "mdx" | "yml" | "yaml" | "json"))
        {
            out.push(path);
        }
    }
}

/// The words in `text` that look like metric names, with their line numbers.
/// A word is a run of `[a-z0-9_]`; it looks like a metric when it starts with
/// `hearth_`, or `storage_` in a paragraph that says "metric" or
/// "Prometheus", and ends in a metric ending.
fn named_metrics(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    // For each line, whether its paragraph (lines between blank lines)
    // says "metric" or "Prometheus".
    let mut metric_paragraph = vec![false; lines.len()];
    let mut start = 0;
    for end in 0..=lines.len() {
        if end == lines.len() || lines[end].trim().is_empty() {
            let says = lines[start..end].iter().any(|l| {
                let lower = l.to_ascii_lowercase();
                lower.contains("metric") || lower.contains("prometheus")
            });
            metric_paragraph[start..end].fill(says);
            start = end + 1;
        }
    }
    let mut found = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        let metric_line = metric_paragraph[n];
        for word in
            line.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
        {
            let mut name = word;
            for suffix in HISTOGRAM_SUFFIXES {
                if let Some(stem) = name.strip_suffix(suffix) {
                    if METRIC_ENDINGS.iter().any(|e| stem.ends_with(e)) {
                        name = stem;
                    }
                }
            }
            let candidate =
                name.starts_with("hearth_") || (metric_line && name.starts_with("storage_"));
            if candidate && METRIC_ENDINGS.iter().any(|e| name.ends_with(e)) {
                found.push((n + 1, name.to_owned()));
            }
        }
    }
    found
}

#[test]
fn every_metric_the_docs_and_deploy_files_name_exists() {
    let defined = defined();
    assert!(
        defined.len() > 40,
        "the scan of src/metrics.rs found only {} names; the scan is broken",
        defined.len()
    );

    let mut paths = Vec::new();
    files(&root().join("docs"), &mut paths);
    files(&root().join("deploy"), &mut paths);
    paths.push(root().join("README.md"));
    paths.sort();

    let mut missing = Vec::new();
    let mut checked = 0usize;
    for path in &paths {
        let text = std::fs::read_to_string(path).expect("read doc");
        for (line, name) in named_metrics(&text) {
            checked += 1;
            if !defined.contains(&name) {
                let rel = path.strip_prefix(root()).unwrap_or(path).display();
                missing.push(format!("{rel}:{line}: {name}"));
            }
        }
    }
    assert!(
        checked > 40,
        "the scan of the docs found only {checked} metric names; the scan is broken"
    );
    assert!(
        missing.is_empty(),
        "these files name metrics that Hearth does not export:\n{}",
        missing.join("\n")
    );
}

#[test]
fn the_name_scan_sees_metrics_and_skips_other_names() {
    let text = "Alert on `hearth_storage_writes_shed_total` and \
                rate(hearth_kdf_compute_seconds_bucket[5m]).\n\
                The cookie `hearth_ui_session` and the key `memtable_flush_bytes`.\n\
                \n\
                Hearth exposes `storage_hot_tier_hits` and\n\
                `storage_hot_tier_misses` Prometheus counters.\n\
                \n\
                The `storage_max_bytes` key.";
    let names: Vec<(usize, String)> = named_metrics(text);
    let expected = [
        (1, "hearth_storage_writes_shed_total"),
        (1, "hearth_kdf_compute_seconds"),
        (4, "storage_hot_tier_hits"),
        (5, "storage_hot_tier_misses"),
    ];
    assert_eq!(
        names,
        expected.map(|(n, s)| (n, s.to_owned())),
        "the scan must find each metric name, with its line, and skip other names"
    );
}
