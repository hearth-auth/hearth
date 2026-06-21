//! Criterion benchmarks for agent credential operations (HEA-1405 M1).
//!
//! # CI Threshold Gate
//!
//! | Gate | Limit |
//! |------|-------|
//! | `verify_agent_api_key` (correct key, 1 active credential) | p99 ≤ 1 ms |
//!
//! The verify path is called on every agent-authenticated request.

use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, SystemClock};
use hearth::identity::{
    AgentOwner, CreateAgentApiKeyRequest, CreateAgentRequest, CreateRealmRequest,
    CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Threshold ─────────────────────────────────────────────────────────────────

const VERIFY_P99_LIMIT: Duration = Duration::from_millis(1);
const GATE_SAMPLES: usize = 200;
const GATE_WARMUP: usize = 20;

// ── Setup helper ──────────────────────────────────────────────────────────────

struct Fixture {
    engine: EmbeddedIdentityEngine,
    realm_id: hearth::core::RealmId,
    agent_id: hearth::core::AgentId,
    key_hex: String,
    wrong_key: String,
    _dir: tempfile::TempDir,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
        IdentityConfig::default(),
        Arc::clone(&audit),
    )
    .expect("engine");

    let realm_id = engine
        .create_realm(&CreateRealmRequest {
            name: "bench-realm".to_string(),
            config: None,
        })
        .expect("realm")
        .id()
        .clone();

    let user_id = engine
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "bench@example.com".to_string(),
                display_name: "Bench User".to_string(),
                ..Default::default()
            },
        )
        .expect("user")
        .id()
        .clone();

    let agent = engine
        .create_agent(
            &realm_id,
            &CreateAgentRequest {
                display_name: "Bench Agent".to_string(),
                description: None,
                owner: AgentOwner::User(user_id),
                capabilities: vec![],
                max_delegation_depth: 1,
            },
            None,
        )
        .expect("agent");

    let resp = engine
        .create_agent_api_key(
            &realm_id,
            agent.id(),
            &CreateAgentApiKeyRequest {
                label: "bench-key".to_string(),
            },
            None,
        )
        .expect("api key");
    let key_hex = resp.plaintext_key.expose_once().to_string();

    Fixture {
        engine,
        realm_id,
        agent_id: agent.id().clone(),
        key_hex,
        wrong_key: "0".repeat(64),
        _dir: dir,
    }
}

// ── Gate ──────────────────────────────────────────────────────────────────────

fn gate_verify_api_key() {
    let f = setup();

    for _ in 0..GATE_WARMUP {
        let _ = f
            .engine
            .verify_agent_api_key(&f.realm_id, &f.agent_id, &f.key_hex);
    }

    let mut samples: Vec<Duration> = Vec::with_capacity(GATE_SAMPLES);
    for _ in 0..GATE_SAMPLES {
        let start = Instant::now();
        let _ = black_box(f.engine.verify_agent_api_key(
            black_box(&f.realm_id),
            black_box(&f.agent_id),
            black_box(&f.key_hex),
        ));
        samples.push(start.elapsed());
    }

    samples.sort_unstable();
    let p99 = samples[GATE_SAMPLES * 99 / 100];
    assert!(
        p99 <= VERIFY_P99_LIMIT,
        "verify_agent_api_key p99 {p99:?} exceeds {VERIFY_P99_LIMIT:?}"
    );
}

// ── Criterion benchmarks ──────────────────────────────────────────────────────

fn bench_verify(c: &mut Criterion) {
    let f = setup();

    c.bench_function("verify_agent_api_key/correct", |b| {
        b.iter(|| {
            let _ = f.engine.verify_agent_api_key(
                black_box(&f.realm_id),
                black_box(&f.agent_id),
                black_box(&f.key_hex),
            );
        });
    });

    c.bench_function("verify_agent_api_key/wrong", |b| {
        b.iter(|| {
            let _ = f.engine.verify_agent_api_key(
                black_box(&f.realm_id),
                black_box(&f.agent_id),
                black_box(&f.wrong_key),
            );
        });
    });
}

criterion_group!(benches, bench_verify);
criterion_main!(benches, gate_verify_api_key);
