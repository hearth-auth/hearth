//! Tests for the perf-harness quiescence gate (`examples/support/hostenv.rs`).
//!
//! # Why these exist
//!
//! HEA-1974 AC1 makes quiescence a deliverable: "a run on a contended box is not
//! a result." The gate that enforces this only ever *fails* on the developer
//! hosts we have, and a gate that has only ever been observed to fail is
//! indistinguishable from a gate that is hardcoded to fail. These tests pin both
//! directions — that a genuinely quiesced, server-class host is admitted, and
//! that each individual objection is raised by the specific condition that
//! should raise it and not by the others.
//!
//! The module under test is pulled in by path because it is example-support
//! code, not library code: it must not ship in the `hearth` binary.

#[path = "../examples/support/hostenv.rs"]
mod hostenv;

use hostenv::{HostProfile, LoadSnapshot, ProcSample, ProcessCensus};

/// A host that passes every gate: server chassis, pinned clocks, isolated cores.
fn server_class_host() -> HostProfile {
    HostProfile {
        cpu_model: "AMD EPYC 9454P 48-Core Processor".into(),
        cpus: 16,
        governor: Some("performance".into()),
        boost: Some(false),
        isolated_cpus: "8-15".into(),
        has_battery: false,
        temp_c: Some(41.0),
    }
}

/// A load average comfortably under the bar (5% of 16 CPUs = 0.80).
fn quiet_load() -> LoadSnapshot {
    LoadSnapshot {
        load1: 0.11,
        load5: 0.09,
        load15: 0.08,
        running: 1,
    }
}

/// A census with no process over the 5%-of-a-core bar.
fn quiet_census() -> ProcessCensus {
    ProcessCensus {
        procs: vec![ProcSample {
            pid: 42,
            comm: "sshd".into(),
            cpu_pct: 1.2,
            rss_kib: 4096,
        }],
        total_busy_pct: 2.0,
    }
}

#[test]
fn quiesced_server_class_host_is_publishable() {
    let v = hostenv::evaluate(&server_class_host(), &quiet_load(), &quiet_census());

    assert!(
        v.publishable,
        "a quiesced server-class host must be admitted; objections were host_class={:?} \
         contention={:?}",
        v.host_class, v.contention
    );
    assert!(v.host_class.is_empty(), "unexpected: {:?}", v.host_class);
    assert!(v.contention.is_empty(), "unexpected: {:?}", v.contention);
}

#[test]
fn load_average_over_the_bar_is_a_contention_objection_only() {
    // 16 CPUs × 5% = 0.80. 0.81 is the smallest meaningful step over it.
    let load = LoadSnapshot {
        load1: 0.81,
        ..quiet_load()
    };
    let v = hostenv::evaluate(&server_class_host(), &load, &quiet_census());

    assert!(!v.publishable, "load over the bar must block publication");
    assert!(
        v.only_contention(),
        "load is transient, so it must NOT be classed as a host-class objection: {:?}",
        v.host_class
    );
    assert_eq!(v.contention.len(), 1, "got: {:?}", v.contention);
    assert!(
        v.contention[0].contains("0.81") && v.contention[0].contains("0.80"),
        "the objection must state the measured value and the bar: {}",
        v.contention[0]
    );
}

#[test]
fn load_average_exactly_at_the_bar_is_admitted() {
    // Pins the comparison as `<=`, not `<`. Chosen deliberately: the bar is a
    // stated threshold, and a run sitting exactly on it satisfies "below a
    // stated threshold" by the same reading used to publish it.
    let load = LoadSnapshot {
        load1: 0.80,
        ..quiet_load()
    };
    let v = hostenv::evaluate(&server_class_host(), &load, &quiet_census());

    assert!(v.publishable, "objections: {:?}", v.contention);
}

#[test]
fn a_single_busy_neighbour_is_caught_even_when_load_average_is_low() {
    // The regression this guards: aggregate load can look fine while one busy
    // neighbour lands on the generator's core. HEA-1967's collapse was an
    // aggregate-load story, but the per-process bar is what catches the
    // one-noisy-process variant of it.
    let census = ProcessCensus {
        procs: vec![ProcSample {
            pid: 3_587_043,
            comm: "brave".into(),
            cpu_pct: 81.5,
            rss_kib: 353_280,
        }],
        total_busy_pct: 84.0,
    };
    let v = hostenv::evaluate(&server_class_host(), &quiet_load(), &census);

    assert!(!v.publishable);
    assert!(v.only_contention(), "host_class: {:?}", v.host_class);
    assert_eq!(v.contention.len(), 1, "got: {:?}", v.contention);
    assert!(
        v.contention[0].contains("brave") && v.contention[0].contains("81.5"),
        "the objection must name the process and its cost: {}",
        v.contention[0]
    );
}

#[test]
fn a_process_exactly_at_the_bar_is_admitted() {
    let census = ProcessCensus {
        procs: vec![ProcSample {
            pid: 7,
            comm: "cron".into(),
            cpu_pct: 5.0,
            rss_kib: 2048,
        }],
        total_busy_pct: 6.0,
    };
    let v = hostenv::evaluate(&server_class_host(), &quiet_load(), &census);

    assert!(v.publishable, "objections: {:?}", v.contention);
}

#[test]
fn battery_presence_is_a_host_class_objection_that_quiescing_cannot_clear() {
    let host = HostProfile {
        has_battery: true,
        cpu_model: "AMD Ryzen 7 7840HS w/ Radeon 780M Graphics".into(),
        ..server_class_host()
    };
    // Perfectly quiet host — the *only* thing wrong is the chassis.
    let v = hostenv::evaluate(&host, &quiet_load(), &quiet_census());

    assert!(
        !v.publishable,
        "a laptop must not yield publishable figures"
    );
    assert!(
        v.contention.is_empty(),
        "the host is quiet; nothing should be blamed on contention: {:?}",
        v.contention
    );
    assert_eq!(v.host_class.len(), 1, "got: {:?}", v.host_class);
    assert!(
        v.host_class[0].contains("mobile chassis"),
        "got: {}",
        v.host_class[0]
    );
    assert!(
        !v.only_contention(),
        "quiescing this host would not fix it, so it must not read as contention-only"
    );
}

#[test]
fn non_performance_governor_is_a_host_class_objection() {
    for (governor, expect) in [
        (Some("powersave"), true),
        (Some("schedutil"), true),
        (Some("ondemand"), true),
        (Some("performance"), false),
        (None, true),
    ] {
        let host = HostProfile {
            governor: governor.map(Into::into),
            ..server_class_host()
        };
        let reasons = host.non_server_class_reasons();
        let flagged = reasons.iter().any(|r| r.contains("governor"));
        assert_eq!(
            flagged,
            expect,
            "governor {governor:?} should {} raise an objection; got {reasons:?}",
            if expect { "" } else { "NOT" }
        );
    }
}

#[test]
fn missing_cpu_isolation_is_a_host_class_objection() {
    for (isolated, expect_objection) in [("", true), ("   ", true), ("8-15", false)] {
        let host = HostProfile {
            isolated_cpus: isolated.into(),
            ..server_class_host()
        };
        let flagged = host
            .non_server_class_reasons()
            .iter()
            .any(|r| r.contains("isolated CPUs"));
        assert_eq!(
            flagged, expect_objection,
            "isolated_cpus {isolated:?} misclassified"
        );
    }
}

#[test]
fn objections_accumulate_rather_than_short_circuiting() {
    // The developer host this issue was filed from trips three host-class and
    // several contention objections at once. The report has to list all of
    // them, because fixing only the first would leave the run just as
    // unpublishable — that is the escalation argument in HEA-1974 AC6.
    let host = HostProfile {
        cpu_model: "AMD Ryzen 7 7840HS w/ Radeon 780M Graphics".into(),
        cpus: 16,
        governor: Some("powersave".into()),
        boost: Some(true),
        isolated_cpus: String::new(),
        has_battery: true,
        temp_c: Some(69.8),
    };
    let load = LoadSnapshot {
        load1: 17.24,
        load5: 13.26,
        load15: 10.25,
        running: 4,
    };
    let census = ProcessCensus {
        procs: vec![
            ProcSample {
                pid: 1,
                comm: "brave".into(),
                cpu_pct: 81.5,
                rss_kib: 353_280,
            },
            ProcSample {
                pid: 2,
                comm: "mysqld".into(),
                cpu_pct: 31.6,
                rss_kib: 2_521_088,
            },
        ],
        total_busy_pct: 247.0,
    };
    let v = hostenv::evaluate(&host, &load, &census);

    assert!(!v.publishable);
    assert_eq!(v.host_class.len(), 3, "got: {:?}", v.host_class);
    // One load objection + one per over-bar process.
    assert_eq!(v.contention.len(), 3, "got: {:?}", v.contention);
}

#[test]
fn an_unparseable_load_average_fails_closed() {
    // `/proc/loadavg` parsing yields NaN when the file is missing or malformed.
    // NaN is incomparable, so a naive `load1 > bar` test would silently *admit*
    // the run. An unknown load must block publication, not sail through it.
    let load = LoadSnapshot {
        load1: f64::NAN,
        ..quiet_load()
    };
    let v = hostenv::evaluate(&server_class_host(), &load, &quiet_census());

    assert!(
        !v.publishable,
        "an unknown load average must fail closed, not be admitted"
    );
    assert_eq!(v.contention.len(), 1, "got: {:?}", v.contention);
}

#[test]
fn load_per_cpu_is_scale_free() {
    let load = LoadSnapshot {
        load1: 8.0,
        ..quiet_load()
    };
    assert!((load.per_cpu(16) - 0.5).abs() < f64::EPSILON);
    assert!((load.per_cpu(8) - 1.0).abs() < f64::EPSILON);
    assert!(
        load.per_cpu(0).is_nan(),
        "zero CPUs must not divide by zero"
    );
}

#[test]
fn verdict_json_carries_the_publishable_stamp_and_both_objection_classes() {
    // The artifact is the durable record; a consumer six weeks later must be
    // able to tell a clean run from a dirty one without reading the console log.
    // This is the exact failure mode that produced the unreproducible HEA-1967
    // figures.
    let host = HostProfile {
        has_battery: true,
        ..server_class_host()
    };
    let load = LoadSnapshot {
        load1: 9.0,
        ..quiet_load()
    };
    let v = hostenv::evaluate(&host, &load, &quiet_census());
    let j = v.to_json();

    assert_eq!(j["publishable"], serde_json::json!(false));
    assert_eq!(j["host_class_objections"].as_array().map(Vec::len), Some(1));
    assert_eq!(j["contention_objections"].as_array().map(Vec::len), Some(1));
    assert_eq!(j["thresholds"]["max_prerun_load_per_cpu"], 0.05);
}

#[test]
fn live_capture_reports_a_coherent_host() {
    // Not an assertion about *this* host's quiescence — it will differ per
    // machine and per moment. This pins that the /proc and /sys parsers return
    // something internally consistent rather than silently yielding zeros,
    // which would make the gate vacuously passable.
    let host = HostProfile::capture();
    assert!(host.cpus > 0, "must see at least one CPU");
    assert!(
        !host.cpu_model.is_empty(),
        "cpu model must be populated (or explicitly 'unknown')"
    );

    let load = LoadSnapshot::capture();
    assert!(
        load.load1 >= 0.0 && load.load1.is_finite(),
        "load1 must parse to a finite non-negative number, got {}",
        load.load1
    );
    assert!(load.per_cpu(host.cpus).is_finite());

    let census = ProcessCensus::capture(std::process::id());
    assert!(
        census.total_busy_pct >= 0.0 && census.total_busy_pct.is_finite(),
        "busy pct must be finite, got {}",
        census.total_busy_pct
    );
    // This test process itself is excluded, but a live Linux box always has
    // *some* other process; the census may legitimately be empty on a very
    // quiet box, so only ordering is asserted.
    for w in census.procs.windows(2) {
        assert!(
            w[0].cpu_pct >= w[1].cpu_pct,
            "census must be sorted by CPU descending"
        );
    }
}
