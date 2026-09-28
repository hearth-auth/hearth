//! Tasks 23.1 / 23.16 — the empirical half of the follower-bypass enumeration.
//!
//! `reports/follower-bypass-enumeration-2026-09-21.md` reasoned about follower
//! cache coherence with **two identity engines over one storage engine**. That
//! shape proves the engine-side logic but proves nothing about replication: a
//! single storage handle makes every write instantly visible to both engines,
//! so a test over it cannot distinguish "the control epoch propagated" from
//! "there was nothing to propagate".
//!
//! This file stands up **three real nodes** — three `EmbeddedStorageEngine`s
//! under three `ClusterEngine`s, talking openraft over real mTLS gRPC sockets
//! on loopback, each with its own `EmbeddedRbacEngine` and
//! `EmbeddedIdentityEngine` over a `ClusterStorageAdapter`. Mutations run on
//! the elected leader; every assertion is made on **both** followers, so a
//! mechanism that happens to work for the second node but not the third has
//! nowhere to hide.
//!
//! The cert/port/bootstrap fixture mirrors `tests/cluster_grpc_loopback.rs`.
//!
//! Findings are written up in `reports/cluster-ga-readiness-2026-09-21.md`.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::cluster::{serve, ClusterEngine, ClusterStorageAdapter, HearthNode};
use hearth::config::{ClusterConfig, PeerConfig};
use hearth::core::{Clock, FakeClock, RealmId, SessionId, Timestamp, UserId};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, RealmStatus,
    SessionContext, UpdateRealmRequest,
};
use hearth::rbac::{
    AssignRoleRequest, CreateRoleRequest, EmbeddedRbacEngine, Permission, RbacEngine, RoleId,
    Scope, Subject,
};
use hearth::storage::{
    EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageEngine, StorageError,
};
use tempfile::TempDir;

// ── Throwaway mTLS bundle (same convention as tests/cluster_grpc_loopback.rs) ─

fn generate_cluster_certs(dir: &Path, n_nodes: usize) -> (PathBuf, Vec<(PathBuf, PathBuf)>) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();

    let mut leafs = Vec::with_capacity(n_nodes);
    for i in 1..=n_nodes {
        let leaf_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        let cert_path = dir.join(format!("node-{i}.crt.pem"));
        let key_path = dir.join(format!("node-{i}.key.pem"));
        std::fs::write(&cert_path, leaf_cert.pem()).unwrap();
        std::fs::write(&key_path, leaf_key.serialize_pem()).unwrap();
        leafs.push((cert_path, key_path));
    }
    (ca_path, leafs)
}

fn pick_free_loopback_ports(n: usize) -> Vec<u16> {
    use std::net::TcpListener;
    let mut ports = Vec::with_capacity(n);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        ports.push(l.local_addr().unwrap().port());
        listeners.push(l);
    }
    drop(listeners);
    ports
}

// ── One node: raft engine + the app stack that runs on top of it ─────────────

/// The application stack a single `hearth serve` process owns: the Raft
/// engine, the adapter that makes it look like a `StorageEngine`, and the
/// RBAC + identity engines built over that adapter.
struct Node {
    cluster: Arc<ClusterEngine>,
    rbac: Arc<EmbeddedRbacEngine>,
    identity: Arc<EmbeddedIdentityEngine>,
}

impl Node {
    fn id(&self) -> u64 {
        self.cluster.raft_metrics().map(|m| m.id).unwrap_or(0)
    }
}

struct ThreeNodeCluster {
    nodes: Vec<Node>,
    handles: Vec<tokio::task::JoinHandle<()>>,
    leader_id: u64,
    _tempdir: TempDir,
}

/// Builds the RBAC + identity stack over one node's Raft engine, exactly as
/// `main.rs` does (including the `ReplicatedWriteObserver` wiring).
type AppStack = (Arc<EmbeddedRbacEngine>, Arc<EmbeddedIdentityEngine>);

/// Wraps one node's storage handle (the node's Raft id, its adapter) before
/// the application stack is built over it — the seam a test uses to inject a
/// storage fault on one node.
type StorageWrap = dyn Fn(u64, Arc<dyn StorageEngine>) -> Arc<dyn StorageEngine> + Send + Sync;

fn app_stack_over_wrapped(
    cluster: &Arc<ClusterEngine>,
    clock: &Arc<FakeClock>,
    wrap: &StorageWrap,
) -> AppStack {
    let storage: Arc<dyn StorageEngine> = Arc::new(ClusterStorageAdapter::new(Arc::clone(cluster)));
    let storage = wrap(cluster.node_id().unwrap_or(0), storage);
    app_stack_over_storage(cluster, &storage, clock)
}

/// Same, over an already-built storage handle, so a caller that had to consult
/// the handle first (`await_cold_start_window`) does not build a second one.
fn app_stack_over_storage(
    cluster: &Arc<ClusterEngine>,
    storage: &Arc<dyn StorageEngine>,
    clock: &Arc<FakeClock>,
) -> AppStack {
    let storage = Arc::clone(storage);
    let clock_dyn = Arc::clone(clock) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock_dyn),
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock_dyn),
    )) as Arc<dyn AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&storage),
            clock_dyn,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac) as Arc<dyn RbacEngine>,
            audit,
        )
        .unwrap(),
    );
    cluster.set_replicated_write_observer(
        Arc::clone(&identity) as Arc<dyn hearth::cluster::ReplicatedWriteObserver>
    );
    (rbac, identity)
}

impl ThreeNodeCluster {
    async fn build(clock: &Arc<FakeClock>) -> Self {
        Self::build_with(clock, &|_, storage| storage).await
    }

    /// As [`Self::build`], with each node's storage handle passed through
    /// `wrap` before its application stack is built.
    async fn build_with(clock: &Arc<FakeClock>, wrap: &StorageWrap) -> Self {
        Self::build_inner(clock, wrap, None).await
    }

    /// As [`Self::build`], with every node's data directory a copy of `seed`
    /// made before the node first starts (a data directory populated offline,
    /// such as by `hearth backup restore`).
    async fn build_seeded(clock: &Arc<FakeClock>, seed: &Path) -> Self {
        Self::build_inner(clock, &|_, storage| storage, Some(seed)).await
    }

    async fn build_inner(clock: &Arc<FakeClock>, wrap: &StorageWrap, seed: Option<&Path>) -> Self {
        let tempdir = tempfile::tempdir().unwrap();
        let (ca_path, leaf_certs) = generate_cluster_certs(tempdir.path(), 3);
        let ports = pick_free_loopback_ports(3);

        let mut engines = Vec::with_capacity(3);
        let mut handles = Vec::with_capacity(3);
        let mut configs = Vec::with_capacity(3);

        for i in 0..3 {
            let node_id = (i + 1) as u64;
            let data_dir = tempdir.path().join(format!("node-{node_id}-data"));
            std::fs::create_dir_all(&data_dir).unwrap();
            if let Some(seed) = seed {
                copy_dir(seed, &data_dir);
            }
            let storage_cfg = StorageConfig::dev(data_dir);
            let storage = Arc::new(EmbeddedStorageEngine::open(storage_cfg.clone()).unwrap());
            let (cert_path, key_path) = leaf_certs[i].clone();
            let cluster_cfg = ClusterConfig {
                node_id,
                peer_address: format!("127.0.0.1:{}", ports[i]),
                peers: vec![],
                tls_cert_path: cert_path,
                tls_key_path: key_path,
                tls_ca_cert_path: ca_path.clone(),
                // Generous: the lag monitor must not gate reads during the
                // brief windows between a leader write and follower apply.
                read_lag_threshold_ms: Some(30_000),
                write_timeout_ms: None,
            };
            let engine = Arc::new(
                ClusterEngine::build_clustered(storage, &cluster_cfg, &storage_cfg)
                    .await
                    .unwrap(),
            );
            let serve_engine = Arc::clone(&engine);
            let serve_cfg = cluster_cfg.clone();
            handles.push(tokio::spawn(async move {
                let _ = serve(&serve_cfg, serve_engine).await;
            }));
            engines.push(engine);
            configs.push(cluster_cfg);
        }

        // AUDIT: justified-sleep: gRPC listeners need OS scheduling time to bind before the bootstrap RPC attempts connections
        tokio::time::sleep(Duration::from_millis(400)).await;

        let mut members = BTreeMap::new();
        for cfg in &configs {
            members.insert(
                cfg.node_id,
                HearthNode {
                    addr: cfg.peer_address.clone(),
                },
            );
        }
        engines[0].initialize_cluster(members).await.unwrap();

        let leader_id = wait_for_leader(&engines, Duration::from_secs(20)).await;

        // Build the leader's app stack FIRST. `EmbeddedIdentityEngine`'s
        // constructor persists the global signing key on first start, and on a
        // follower that write is `NotLeader`. See the report finding O-1 —
        // this ordering is a property of the test fixture, not of `serve`.
        let leader_idx = engines
            .iter()
            .position(|e| e.raft_metrics().map(|m| m.id) == Some(leader_id))
            .unwrap();
        let (leader_rbac, leader_identity) =
            app_stack_over_wrapped(&engines[leader_idx], clock, wrap);

        // Let the signing-key write reach every node before the followers'
        // constructors read it.
        wait_converged(&engines, Duration::from_secs(20)).await;

        let mut nodes = Vec::with_capacity(3);
        for (idx, engine) in engines.iter().enumerate() {
            if idx == leader_idx {
                nodes.push(Node {
                    cluster: Arc::clone(engine),
                    rbac: Arc::clone(&leader_rbac),
                    identity: Arc::clone(&leader_identity),
                });
            } else {
                let (rbac, identity) = app_stack_over_wrapped(engine, clock, wrap);
                nodes.push(Node {
                    cluster: Arc::clone(engine),
                    rbac,
                    identity,
                });
            }
        }

        Self {
            nodes,
            handles,
            leader_id,
            _tempdir: tempdir,
        }
    }

    fn leader(&self) -> &Node {
        self.nodes
            .iter()
            .find(|n| n.id() == self.leader_id)
            .unwrap()
    }

    fn followers(&self) -> Vec<&Node> {
        self.nodes
            .iter()
            .filter(|n| n.id() != self.leader_id)
            .collect()
    }

    /// Blocks until every node has applied everything the leader has.
    async fn converge(&self) {
        let engines: Vec<Arc<ClusterEngine>> =
            self.nodes.iter().map(|n| Arc::clone(&n.cluster)).collect();
        wait_converged(&engines, Duration::from_secs(20)).await;
    }

    fn shutdown(self) {
        for h in self.handles {
            h.abort();
        }
    }
}

async fn wait_for_leader(engines: &[Arc<ClusterEngine>], timeout: Duration) -> u64 {
    let start = Instant::now();
    loop {
        for engine in engines {
            let Some(metrics) = engine.raft_metrics() else {
                continue;
            };
            let Some(leader) = metrics.current_leader else {
                continue;
            };
            let self_view = engines
                .iter()
                .find_map(|e| e.raft_metrics().filter(|m| m.id == leader));
            if let Some(m) = self_view {
                if m.current_leader == Some(leader) {
                    return leader;
                }
            }
        }
        assert!(
            start.elapsed() <= timeout,
            "no leader elected in {timeout:?}"
        );
        // AUDIT: justified-sleep: poll interval inside leader-election loop; openraft exposes no ready-signal channel
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn applied(engine: &ClusterEngine) -> u64 {
    engine
        .raft_metrics()
        .and_then(|m| m.last_applied.map(|l| l.index))
        .unwrap_or(0)
}

fn last_log(engine: &ClusterEngine) -> u64 {
    engine
        .raft_metrics()
        .and_then(|m| m.last_log_index)
        .unwrap_or(0)
}

/// Waits until every node has **applied** every entry any node has **logged**.
///
/// The target is `last_log_index`, not `last_applied`: a client write returns
/// on majority commit while the state machine applies asynchronously, so a
/// target taken from `last_applied` can be one or more entries behind the
/// write that was just acknowledged — and every node then satisfies it
/// immediately while the follower's storage is still stale. That mistake makes
/// a coherence assertion measure nothing, so the convergence bar is the log.
async fn wait_converged(engines: &[Arc<ClusterEngine>], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let target = engines.iter().map(|e| last_log(e)).max().unwrap_or(0);
        if target > 0 && engines.iter().all(|e| applied(e) >= target) {
            return;
        }
        assert!(
            Instant::now() <= deadline,
            "replication did not converge within {timeout:?}"
        );
        // AUDIT: justified-sleep: poll interval inside replication-convergence loop; log commit is async with no notification hook
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── Fixture helpers ──────────────────────────────────────────────────────────

fn perm(s: &str) -> Permission {
    Permission::new(s).unwrap()
}

fn make_role(node: &Node, realm: &RealmId, name: &str, permission: &str) -> RoleId {
    node.rbac
        .create_role(
            realm,
            &CreateRoleRequest {
                name: name.to_string(),
                description: None,
                permissions: vec![perm(permission)],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .unwrap()
        .id
}

// ── Test 1: the three control-epoch caches, checked on BOTH followers ────────

/// A control asserted on the leader must bind on every other node — the third
/// as well as the second.
///
/// Realm suspend is the probe for `realm_status_cache` and session revocation
/// the probe for `session_cache`; both are reloaded by the same
/// `sync_control_epoch` call at the top of `validate_token`, which is also
/// what reloads the revoked-JTI and DPoP blocklists. If the epoch row failed
/// to reach node 3 — or reached it but was not observed — both probes fail
/// there while passing on node 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_control_asserted_on_the_leader_binds_on_both_followers() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let cluster = ThreeNodeCluster::build(&clock).await;

    let seeded = seed_realm_user_and_token(&cluster, &clock, "three-node-controls").await;

    // Baseline: every follower accepts the token. This also warms each
    // follower's realm-status, session and claims caches, which is what makes
    // the assertions below meaningful.
    for node in cluster.followers() {
        node.identity
            .validate_token(&seeded.realm_id, &seeded.access_token)
            .unwrap_or_else(|e| panic!("node {} rejected a valid token: {e:?}", node.id()));
    }

    assert_session_revocation_binds(&cluster, &clock, &seeded).await;
    assert_realm_suspension_binds(&cluster, &clock, &seeded).await;

    cluster.shutdown();
}

/// Revoking a sessionless token on the LEADER completes promptly, succeeds,
/// and binds on both followers.
///
/// The Raft observer runs on the leader's own state machine too. It used to
/// project a replicated `oauth:revjti:` row by calling the local revocation
/// path, which bumps the control epoch — a storage write, so a Raft proposal
/// made from inside the state machine's own apply, which then waited for that
/// apply. On a real three-node cluster a normal put took 10.3 ms and a
/// revoked-JTI put took 10.0 s (`write_timeout`) and then failed, after the
/// revocation row had already committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn revoking_a_sessionless_token_on_the_leader_is_prompt_and_binds_on_both_followers() {
    use hearth::identity::{
        ClientCredentialsRequest, ClientTrustLevel, GeneratedClientSecret, RegisterClientRequest,
        TokenRevocationRequest,
    };

    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let cluster = ThreeNodeCluster::build(&clock).await;
    let leader = cluster.leader();

    let realm_id = leader
        .identity
        .create_realm(&CreateRealmRequest {
            name: "three-node-revjti".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap()
        .id()
        .clone();
    let secret = GeneratedClientSecret::generate();
    let client_id = leader
        .identity
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "M2M".to_string(),
                generated_client_secret: Some(secret.clone()),
                grant_types: vec!["client_credentials".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .unwrap()
        .client_id()
        .clone();
    let token = leader
        .identity
        .client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client_id.clone(),
                client_secret: Some(secret.expose().to_string()),
                scope: None,
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .unwrap()
        .access_token()
        .to_string();
    cluster.converge().await;
    for node in cluster.followers() {
        node.identity
            .validate_token(&realm_id, &token)
            .unwrap_or_else(|e| panic!("node {} rejected a valid token: {e:?}", node.id()));
    }

    let started = Instant::now();
    let outcome = leader.identity.revoke_token(
        &realm_id,
        &TokenRevocationRequest {
            token: token.clone(),
            token_type_hint: Some("access_token".to_string()),
            revoking_client_id: Some(client_id),
        },
    );
    let elapsed = started.elapsed();
    assert!(
        outcome.is_ok(),
        "revoking on the leader failed after {elapsed:?}: {outcome:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "revoking a sessionless token on the leader took {elapsed:?}; the replicated-write \
         observer must not write to storage from inside the state machine's apply"
    );

    cluster.converge().await;
    for node in cluster.followers() {
        assert!(
            eventual_rejection(node, &realm_id, &token).await.is_some(),
            "node {} still accepts a token the leader revoked",
            node.id()
        );
    }

    cluster.shutdown();
}

/// Real time a follower's background reloader gets to apply a control after
/// replication has converged. The replicated epoch row signals the reloader
/// from the state machine; the reload itself runs on the reloader thread,
/// never on a validating one, so the bind is eventual.
const RELOAD_DEADLINE: Duration = Duration::from_secs(10);

/// Validates `token` on `node` until it is rejected or [`RELOAD_DEADLINE`]
/// passes; returns the rejection.
async fn eventual_rejection(
    node: &Node,
    realm_id: &RealmId,
    token: &str,
) -> Option<hearth::identity::IdentityError> {
    eventual_rejection_where(node, realm_id, token, |_| true).await
}

/// As [`eventual_rejection`], but keeps polling until the rejection is one
/// `wanted` accepts — a follower can reject for an earlier reason (a missing
/// session) before the reload that makes it reject for the asserted one.
/// Returns the last rejection seen if none matched in time.
async fn eventual_rejection_where(
    node: &Node,
    realm_id: &RealmId,
    token: &str,
    wanted: impl Fn(&hearth::identity::IdentityError) -> bool,
) -> Option<hearth::identity::IdentityError> {
    let deadline = Instant::now() + RELOAD_DEADLINE;
    let mut last = None;
    while Instant::now() < deadline {
        if let Err(e) = node.identity.validate_token(realm_id, token) {
            if wanted(&e) {
                return Some(e);
            }
            last = Some(e);
        }
        // AUDIT: justified-sleep: poll interval of a deadline-bounded condition loop; the follower's background control reload exposes no completion signal to integration tests
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    last
}

/// A realm with one user, one live session and the access token bound to it.
struct SeededRealm {
    realm_id: RealmId,
    user_id: UserId,
    session_id: SessionId,
    access_token: String,
}

/// Creates that realm on the leader and waits for all three nodes to apply
/// every one of those writes.
async fn seed_realm_user_and_token(
    cluster: &ThreeNodeCluster,
    clock: &Arc<FakeClock>,
    realm_name: &str,
) -> SeededRealm {
    let leader = cluster.leader();
    let realm = leader
        .identity
        .create_realm(&CreateRealmRequest {
            name: realm_name.to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();
    let realm_id = realm.id().clone();
    let user = leader
        .identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("coherence@{realm_name}.test"),
                display_name: "Coherence".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                ..Default::default()
            },
        )
        .unwrap();
    let session = leader
        .identity
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .unwrap();
    let pair = leader
        .identity
        .issue_tokens(&realm_id, user.id(), session.id())
        .unwrap();
    let access_token = pair.access_token().to_string();
    clock.advance(1_000_000);
    cluster.converge().await;
    SeededRealm {
        realm_id,
        user_id: user.id().clone(),
        session_id: session.id().clone(),
        access_token,
    }
}

/// B-4 — revoking the session on the leader must stop **both** followers
/// validating a token bound to it.
async fn assert_session_revocation_binds(
    cluster: &ThreeNodeCluster,
    clock: &Arc<FakeClock>,
    seeded: &SeededRealm,
) {
    cluster
        .leader()
        .identity
        .revoke_session(&seeded.realm_id, &seeded.session_id)
        .unwrap();
    cluster.converge().await;
    // Each follower reconciles the control epoch at most once per
    // `EPOCH_SYNC_INTERVAL_MICROS`, because the validation path may perform no
    // storage read. Replication having converged is therefore not on its own
    // enough for a follower to have observed the revocation; the window has to
    // close too. What is asserted is that it binds within one, not instantly.
    clock.advance(1_000_000);

    for node in cluster.followers() {
        let err = eventual_rejection(node, &seeded.realm_id, &seeded.access_token)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "node {} still accepts a token whose session the leader revoked",
                    node.id()
                )
            });
        // The follower validated this exact token a moment ago, which warmed
        // its `session_cache` with a live entry. `lookup_session` returns a
        // cached live session without consulting storage, so the only way the
        // follower can now reject is if `sync_control_epoch` dropped that
        // cache and the storage read found the session gone — which surfaces
        // as `InvalidToken` from `get_session_arc(...).ok_or(...)`.
        assert!(
            matches!(err, hearth::identity::IdentityError::InvalidToken),
            "node {} rejected for the wrong reason: {err:?}",
            node.id()
        );
    }
}

/// B-1 — suspending the realm on the leader must stop **both** followers
/// validating that realm's tokens, via the realm-status cache specifically.
async fn assert_realm_suspension_binds(
    cluster: &ThreeNodeCluster,
    clock: &Arc<FakeClock>,
    seeded: &SeededRealm,
) {
    let leader = cluster.leader();
    // A fresh session and token, so the rejection below cannot be a re-run of
    // the session check.
    let fresh_session = leader
        .identity
        .create_session(
            &seeded.realm_id,
            &seeded.user_id,
            &SessionContext::default(),
        )
        .unwrap();
    let fresh_token = leader
        .identity
        .issue_tokens(&seeded.realm_id, &seeded.user_id, fresh_session.id())
        .unwrap()
        .access_token()
        .to_string();
    clock.advance(1_000_000);
    cluster.converge().await;
    for node in cluster.followers() {
        node.identity
            .validate_token(&seeded.realm_id, &fresh_token)
            .unwrap();
    }

    leader
        .identity
        .update_realm(
            &seeded.realm_id,
            &UpdateRealmRequest {
                name: None,
                status: Some(RealmStatus::Suspended),
                config: None,
            },
        )
        .unwrap();
    cluster.converge().await;
    // The advance above is spent: the validations that followed it claimed each
    // follower's epoch-reconciliation window. Close that window again, or the
    // followers are still entitled to answer from the caches they warmed before
    // the leader suspended the realm.
    clock.advance(1_000_000);

    for node in cluster.followers() {
        let err = eventual_rejection_where(node, &seeded.realm_id, &fresh_token, |e| {
            matches!(e, hearth::identity::IdentityError::RealmSuspended)
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "node {} still validates tokens for a realm the leader suspended",
                node.id()
            )
        });
        // Exactly `RealmSuspended`, not merely "some error". Suspension also
        // revokes the realm's sessions, so a follower that never reloaded
        // `realm_status_cache` still rejects the token — with `InvalidToken`,
        // from the missing session. Accepting that would make this assertion
        // a re-run of the session check and prove nothing about the
        // realm-status cache. The status check runs first in `validate_token`,
        // so `RealmSuspended` is reachable only if the cache did reload.
        assert!(
            matches!(err, hearth::identity::IdentityError::RealmSuspended),
            "node {} did not reload realm_status_cache — rejected with {err:?}, \
             expected RealmSuspended",
            node.id()
        );
    }
}

// ── Test 2: a cold cluster starts every node with no manual bootstrap ────────

/// The three-node start-up sequence, with the guide's bootstrap step removed
/// on purpose — because before task 26.46 that step could never be reached.
///
/// `serve` builds `EmbeddedIdentityEngine` over the `ClusterStorageAdapter`,
/// and that constructor **writes** on a cold data directory: the KEK-enrolment
/// marker, the global signing key, and the system-realm row. In cluster mode
/// each is a Raft proposal, and before bootstrap there is no leader, so the
/// first one returned `NotLeader` and start-up was fatal on all three nodes —
/// before `POST /admin/cluster/bootstrap`, which is served by a router that
/// does not exist until the identity engine has been built, could be called:
///
/// ```text
/// ERROR hearth: error: storage error: storage I/O error:
///               raft: not the leader; redirect to unknown
/// ```
///
/// The fix has two halves and this test fails if either is removed:
///
/// * `ClusterEngine::build_clustered` self-initialises a pristine node from
///   the membership its own `cluster.peers` names, so a leader is elected
///   without any HTTP call.
/// * `EmbeddedIdentityEngine::await_cold_start_window` holds a node at the
///   point `serve` reaches that constructor until either this node is the
///   leader (its writes will land) or the system-realm row has replicated
///   here (the leader did the write set and there is nothing left to do).
///
/// Three cold nodes, real `cluster.peers`, real mTLS gRPC, **no call to
/// `initialize_cluster` anywhere**. The three start-up sequences run
/// concurrently, as three processes would, so nothing depends on the eventual
/// leader happening to be constructed first.
/// Builds `n` cold cluster-mode nodes, each naming the same membership in its
/// own `cluster.peers`, and starts each one's Raft peer server. Nothing
/// bootstraps them.
async fn cold_cluster_nodes(
    tempdir: &TempDir,
    n: usize,
) -> (Vec<Arc<ClusterEngine>>, Vec<tokio::task::JoinHandle<()>>) {
    let (ca_path, leaf_certs) = generate_cluster_certs(tempdir.path(), n);
    let ports = pick_free_loopback_ports(n);
    let addrs: Vec<String> = ports.iter().map(|p| format!("127.0.0.1:{p}")).collect();

    let mut engines: Vec<Arc<ClusterEngine>> = Vec::with_capacity(n);
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let node_id = (i + 1) as u64;
        let data_dir = tempdir.path().join(format!("node-{node_id}-data"));
        std::fs::create_dir_all(&data_dir).unwrap();
        let storage_cfg = StorageConfig::dev(data_dir);
        let inner = Arc::new(EmbeddedStorageEngine::open(storage_cfg.clone()).unwrap());
        // Every node names the same membership — itself plus the others —
        // exactly as the guide's per-node YAML does.
        let peers: Vec<PeerConfig> = (0..n)
            .filter(|j| *j != i)
            .map(|j| PeerConfig {
                id: (j + 1) as u64,
                address: addrs[j].clone(),
            })
            .collect();
        let cluster_cfg = ClusterConfig {
            node_id,
            peer_address: addrs[i].clone(),
            peers,
            tls_cert_path: leaf_certs[i].0.clone(),
            tls_key_path: leaf_certs[i].1.clone(),
            tls_ca_cert_path: ca_path.clone(),
            read_lag_threshold_ms: Some(30_000),
            write_timeout_ms: None,
        };
        let engine = Arc::new(
            ClusterEngine::build_clustered(inner, &cluster_cfg, &storage_cfg)
                .await
                .unwrap(),
        );
        let serve_engine = Arc::clone(&engine);
        let serve_cfg = cluster_cfg.clone();
        handles.push(tokio::spawn(async move {
            let _ = serve(&serve_cfg, serve_engine).await;
        }));
        engines.push(engine);
    }
    (engines, handles)
}

/// The start-up sequence `serve` performs on one node: wait until the cluster
/// can accept this node's start-up writes, then build the app stack over the
/// cluster adapter. Returns the global signing key's ID.
async fn serve_start_sequence(
    node_id: usize,
    engine: &Arc<ClusterEngine>,
    clock: &Arc<FakeClock>,
) -> Result<String, String> {
    let storage: Arc<dyn StorageEngine> = Arc::new(ClusterStorageAdapter::new(Arc::clone(engine)));
    EmbeddedIdentityEngine::await_cold_start_window(&storage, Duration::from_secs(25))
        .await
        .map_err(|e| format!("node {node_id}: cold-start window never opened: {e}"))?;
    let clock_dyn = Arc::clone(clock) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock_dyn),
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock_dyn),
    )) as Arc<dyn AuditEngine>;
    let identity = EmbeddedIdentityEngine::with_rbac(
        storage,
        clock_dyn,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        rbac as Arc<dyn RbacEngine>,
        audit,
    )
    .map_err(|e| format!("node {node_id}: identity engine construction failed: {e}"))?;
    Ok(identity.signing_key().key_id().to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_cold_three_node_cluster_starts_every_node_without_a_manual_bootstrap() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tempdir = tempfile::tempdir().unwrap();
    let (engines, handles) = cold_cluster_nodes(&tempdir, 3).await;

    // Deliberately absent: the guide's step 3. Nothing calls
    // `initialize_cluster` or `POST /admin/cluster/bootstrap`.

    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let mut starts = Vec::with_capacity(3);
    for (i, engine) in engines.iter().enumerate() {
        let engine = Arc::clone(engine);
        let clock = Arc::clone(&clock);
        starts.push(tokio::spawn(async move {
            serve_start_sequence(i + 1, &engine, &clock).await
        }));
    }

    let mut key_ids = Vec::with_capacity(3);
    for start in starts {
        match start.await.expect("start-up task panicked") {
            Ok(kid) => key_ids.push(kid),
            Err(e) => {
                for h in handles {
                    h.abort();
                }
                panic!(
                    "a cold cluster node could not complete `serve`'s start-up sequence \
                     without a manual bootstrap: {e}"
                );
            }
        }
    }

    // One global signing key, not three: every node either wrote it as leader
    // or read the leader's replicated copy. A "make that write local-only"
    // fix would produce three different key IDs and silently fork JWKS.
    assert_eq!(
        key_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        1,
        "the three nodes disagree on the global signing key: {key_ids:?}"
    );

    for h in handles {
        h.abort();
    }
}

// ── Test 3: the cache the analytical pass missed ─────────────────────────────

/// An RBAC grant revoked on the leader must stop resolving on every follower.
///
/// `ShardedResolutionCache::generations` is bumped only by
/// `EmbeddedRbacEngine::invalidate_realm`, which only the node that served the
/// mutation runs. On a follower the revocation arrives as a replicated `rba:`
/// storage write that touches no generation, so a warm entry keeps serving the
/// pre-revocation permission set — and `/ui/admin`'s authorization gate
/// (`src/protocol/web/admin/mod.rs`) resolves through exactly this cache on a
/// plain GET, which a follower is free to serve.
///
/// The control epoch does not cover this: `sync_control_epoch` reloads the
/// identity engine's caches and never touches RBAC, and no RBAC mutation bumps
/// the epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_rbac_grant_revoked_on_the_leader_stops_resolving_on_both_followers() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let cluster = ThreeNodeCluster::build(&clock).await;

    let leader = cluster.leader();
    let realm = leader
        .identity
        .create_realm(&CreateRealmRequest {
            name: "three-node-rbac".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();
    let realm_id = realm.id().clone();
    let user_id = UserId::generate();

    let role = make_role(leader, &realm_id, "auditor", "docs.view");
    let assignment = leader
        .rbac
        .assign_role(
            &realm_id,
            &AssignRoleRequest {
                subject: Subject::User(user_id.clone()),
                role_id: role.clone(),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .unwrap();
    cluster.converge().await;

    // Warm every follower's resolution cache with the pre-revocation answer.
    for node in cluster.followers() {
        let resolved = node
            .rbac
            .resolve_permissions(&user_id, &realm_id, None, None)
            .unwrap();
        assert!(
            resolved.permissions.contains(&perm("docs.view")),
            "node {} did not see the grant before revocation",
            node.id()
        );
    }

    // Revoke on the leader.
    leader
        .rbac
        .unassign_role(&realm_id, &assignment.id)
        .unwrap();
    cluster.converge().await;

    for node in cluster.followers() {
        let resolved = node
            .rbac
            .resolve_permissions(&user_id, &realm_id, None, None)
            .unwrap();
        assert!(
            !resolved.permissions.contains(&perm("docs.view")),
            "node {} still resolves a permission the leader revoked — the RBAC \
             resolution cache is never invalidated by replication",
            node.id()
        );
    }

    cluster.shutdown();
}

// ── Test 4: a follower can persist and clear its own trackers (task 26.49) ──

/// The rate-limit trackers are per-node by design — each node counts what it
/// saw — but their durable rehydration rows were written with
/// `self.storage.put(...)` / `self.storage.delete(...)` and discarded with
/// `let _ =`. In cluster mode both are Raft proposals, so on a follower both
/// fail with `NotLeader` and the discard hides it: the follower can persist
/// nothing, and — the dangerous half — a lockout row that reached it by
/// replication can never be deleted there, so the next restart of that node
/// rehydrates a lockout for a user who has already proved their password.
///
/// `put_node_local` / `delete_node_local` write straight to the node's own
/// engine, which is what per-node state needed all along. The row no longer
/// replicates at all, so the stale-lockout case cannot arise either.
///
/// Both directions are asserted, and each has its own mutation: reverting the
/// persist to `storage.put` fails the first assertion, reverting the clear to
/// `storage.delete` fails the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_follower_persists_and_clears_its_own_rate_limit_tracker_rows() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let cluster = ThreeNodeCluster::build(&clock).await;

    let leader = cluster.leader();
    let realm = leader
        .identity
        .create_realm(&CreateRealmRequest {
            name: "lockout-clear".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();
    let realm_id = realm.id().clone();
    let user = leader
        .identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "lockout@clear.test".to_string(),
                display_name: "Lockout".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                ..Default::default()
            },
        )
        .unwrap();
    let good = CleartextPassword::new(b"correct-horse-battery-staple".to_vec());
    leader
        .identity
        .set_password(&realm_id, user.id(), &good)
        .unwrap();
    cluster.converge().await;

    // `keys::encode_attempt_tracker` is `pub(crate)`; this mirrors its
    // documented `rl:user:{user_uuid}` format. Drift makes the first assertion
    // fail loudly rather than quietly asserting about a key nobody writes.
    let tracker_key = format!("rl:user:{}", user.id().as_uuid()).into_bytes();

    let follower = cluster.followers()[0];
    let follower_id = follower.id();

    // Two failed verifications served by the follower must persist there.
    let bad = CleartextPassword::new(b"wrong-horse-battery-staple".to_vec());
    for _ in 0..2 {
        let _ = follower
            .identity
            .verify_password(&realm_id, user.id(), &bad);
    }
    let persisted = follower.cluster.get(&realm_id, &tracker_key).await.unwrap();
    assert!(
        persisted.is_some(),
        "node {follower_id} counted two failed verifications but persisted nothing: the \
         rehydration row is proposed through Raft and a follower is answered NotLeader, \
         so the durable half of the rate limiter does not exist off the leader (26.49)"
    );

    // A successful verification on the same follower must clear it there.
    assert!(
        follower
            .identity
            .verify_password(&realm_id, user.id(), &good)
            .unwrap(),
        "the correct password did not verify on the follower"
    );
    assert_eq!(
        follower.cluster.get(&realm_id, &tracker_key).await.unwrap(),
        None,
        "the durable lockout row on node {follower_id} survived a successful verification \
         — a restart of that node would rehydrate a lockout for a user who has already \
         authenticated (26.49)"
    );

    cluster.shutdown();
}

// ── Owed control-epoch bumps across a real leader change ─────────────────────

/// A node's cluster storage handle whose `increment_u64` — the control-epoch
/// bump — can be made to fail, standing in for a bump lost between the
/// control row's Raft proposal and its own. Every other call passes through.
struct IncrementFault {
    inner: Arc<dyn StorageEngine>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}

impl StorageEngine for IncrementFault {
    fn accepts_writes(&self) -> bool {
        self.inner.accepts_writes()
    }
    fn put_node_local(&self, r: &RealmId, k: &[u8], v: &[u8]) -> Result<(), StorageError> {
        self.inner.put_node_local(r, k, v)
    }
    fn delete_node_local(&self, r: &RealmId, k: &[u8]) -> Result<(), StorageError> {
        self.inner.delete_node_local(r, k)
    }
    fn get(&self, r: &RealmId, k: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(r, k)
    }
    fn put(&self, r: &RealmId, k: &[u8], v: &[u8]) -> Result<(), StorageError> {
        self.inner.put(r, k, v)
    }
    fn delete(&self, r: &RealmId, k: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(r, k)
    }
    fn scan(&self, r: &RealmId, a: &[u8], b: &[u8]) -> Result<Vec<ScanEntry>, StorageError> {
        self.inner.scan(r, a, b)
    }
    fn put_batch(&self, r: &RealmId, e: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StorageError> {
        self.inner.put_batch(r, e)
    }
    fn write_batch(
        &self,
        r: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        self.inner.write_batch(r, puts, deletes)
    }
    fn backup_barrier(&self) -> Option<Arc<std::sync::RwLock<()>>> {
        self.inner.backup_barrier()
    }
    fn put_if_absent(&self, r: &RealmId, k: &[u8], v: &[u8]) -> Result<bool, StorageError> {
        self.inner.put_if_absent(r, k, v)
    }
    fn increment_u64(&self, r: &RealmId, k: &[u8]) -> Result<u64, StorageError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected: the control-epoch bump was lost",
            )));
        }
        self.inner.increment_u64(r, k)
    }
    fn list_realms(&self) -> Result<Vec<RealmId>, StorageError> {
        self.inner.list_realms()
    }
    fn begin_snapshot_restore(&self, id: &str) -> Result<(), StorageError> {
        self.inner.begin_snapshot_restore(id)
    }
    fn complete_snapshot_restore(&self) -> Result<(), StorageError> {
        self.inner.complete_snapshot_restore()
    }
    fn flush_memtable(&self) -> Result<(), StorageError> {
        self.inner.flush_memtable()
    }
}

fn owed_gauge() -> f64 {
    hearth::metrics::metrics().control_epoch_bumps_owed.get()
}

/// A control whose epoch bump failed on the leader must still bind on every
/// other node after leadership moves.
///
/// Cluster storage does not forward a follower's write to the leader, so once
/// the leader stepped down the bump it owed could never succeed: it retried
/// every 5 s for as long as it lived, and nothing else bumped the epoch, so
/// the other two nodes enforced the stale control (here: kept validating a
/// suspended realm's token) until an unrelated control was asserted somewhere.
///
/// Now the node that wins the election bumps the epoch once, which orders
/// after every row the old leader committed, so every node reloads; and the
/// old leader, refused as `NotLeader`, drops what it owed.
///
/// Real sockets, a real step-down (`transfer_leadership`), no shortcut: the
/// injected fault is only the loss of the one bump.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_control_whose_bump_failed_binds_everywhere_after_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let faults: Arc<std::sync::Mutex<BTreeMap<u64, Arc<std::sync::atomic::AtomicBool>>>> =
        Arc::default();
    let registry = Arc::clone(&faults);
    let wrap = move |id: u64, storage: Arc<dyn StorageEngine>| -> Arc<dyn StorageEngine> {
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        registry.lock().unwrap().insert(id, Arc::clone(&fail));
        Arc::new(IncrementFault {
            inner: storage,
            fail,
        })
    };
    let cluster = ThreeNodeCluster::build_with(&clock, &wrap).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "owed-bump-leader-change").await;
    for node in &cluster.nodes {
        node.identity
            .validate_token(&seeded.realm_id, &seeded.access_token)
            .unwrap_or_else(|e| panic!("node {} rejected a valid token: {e:?}", node.id()));
    }

    // The leader suspends the realm; the row commits, its epoch bump is lost.
    let old_leader_id = cluster.leader_id;
    let fail = Arc::clone(&faults.lock().unwrap()[&old_leader_id]);
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    cluster
        .leader()
        .identity
        .update_realm(
            &seeded.realm_id,
            &UpdateRealmRequest {
                name: None,
                status: Some(RealmStatus::Suspended),
                config: None,
            },
        )
        .unwrap();
    cluster.converge().await;
    assert!(owed_gauge() >= 1.0, "precondition: the lost bump is owed");
    clock.advance(1_000_000);
    for node in cluster.followers() {
        node.identity
            .validate_token(&seeded.realm_id, &seeded.access_token)
            .unwrap_or_else(|e| {
                panic!(
                    "precondition: with the bump lost node {} should not know yet: {e:?}",
                    node.id()
                )
            });
    }

    // Leadership moves. The fault clears, so the old leader's retries reach
    // real cluster storage — which, on a follower, refuses them as NotLeader.
    let new_leader_id = cluster
        .leader()
        .cluster
        .transfer_leadership()
        .await
        .expect("step down");
    assert_ne!(new_leader_id, old_leader_id);
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    cluster.converge().await;
    clock.advance(1_000_000);

    for node in cluster.nodes.iter().filter(|n| n.id() != old_leader_id) {
        let err = eventual_rejection_where(node, &seeded.realm_id, &seeded.access_token, |e| {
            matches!(e, hearth::identity::IdentityError::RealmSuspended)
        })
        .await;
        assert!(
            matches!(err, Some(hearth::identity::IdentityError::RealmSuspended)),
            "node {} (new leader: {}) never enforced a suspension whose bump the old \
             leader lost: {err:?}",
            node.id(),
            node.id() == new_leader_id
        );
    }

    // The old leader dropped the bumps it can no longer make.
    let deadline = Instant::now() + RELOAD_DEADLINE;
    while owed_gauge() > 0.0 && Instant::now() < deadline {
        // AUDIT: justified-sleep: poll interval of a deadline-bounded condition loop on the owed-bumps gauge, which has no change notification
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        owed_gauge() < 0.5,
        "the old leader still owes bumps it can never make: {}",
        owed_gauge()
    );

    cluster.shutdown();
}

// ── Rebuilding a cluster from an offline-restored data directory ─────────────

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

/// Seeds `{root}/restored` the way the upgrading guide does: a store holding
/// a realm, a user and an operator, exported with `hearth backup create`
/// (unfiltered, so the system realm is in it) and restored with `hearth backup
/// restore` into a new empty directory — one shared `HEARTH_MASTER_KEY`, no
/// KEK file. Returns the restored directory, the realm and the user.
fn seed_by_offline_restore(clock: &Arc<FakeClock>, root: &Path) -> (PathBuf, RealmId, UserId) {
    // One HEARTH_MASTER_KEY for the source store, the CLI children and the
    // nodes, as the guide requires. nextest runs each test in its own process.
    const MASTER_KEY: &str = "0b5e55ed0b5e55ed0b5e55ed0b5e55ed0b5e55ed0b5e55ed0b5e55ed0b5e55ed";
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("HEARTH_MASTER_KEY", MASTER_KEY);
    }
    let source = root.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let (realm_id, user_id) = {
        let storage: Arc<dyn StorageEngine> =
            Arc::new(EmbeddedStorageEngine::open(StorageConfig::dev(source.clone())).unwrap());
        let clock_dyn = Arc::clone(clock) as Arc<dyn Clock>;
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock_dyn),
        )) as Arc<dyn AuditEngine>;
        let identity = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            clock_dyn,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            audit,
        )
        .unwrap();
        let realm = identity
            .create_realm(&CreateRealmRequest {
                name: "rebuilt".to_string(),
                config: Some(RealmConfig::default()),
            })
            .unwrap();
        let user = identity
            .create_user(
                realm.id(),
                &CreateUserRequest {
                    email: "survivor@rebuilt.test".to_string(),
                    display_name: "Survivor".to_string(),
                    first_name: String::new(),
                    last_name: String::new(),
                    ..Default::default()
                },
            )
            .unwrap();
        identity
            .create_admin_user(&CreateUserRequest {
                email: "operator@rebuilt.test".to_string(),
                display_name: "Operator".to_string(),
                ..Default::default()
            })
            .unwrap();
        (realm.id().clone(), user.id().clone())
    };
    // The source's storage lock is per-process; the CLI reads a copy.
    let source_copy = root.join("source-copy");
    copy_dir(&source, &source_copy);

    let hearth = |args: &[&std::ffi::OsStr]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hearth"))
            .args(args)
            .env_remove("HEARTH_KEK")
            .env("HEARTH_MASTER_KEY", MASTER_KEY)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "hearth {args:?} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let os = std::ffi::OsStr::new;
    let archive = root.join("pre-upgrade.hearth-backup");
    hearth(&[
        os("backup"),
        os("create"),
        os("--data-dir"),
        source_copy.as_os_str(),
        os("--output"),
        archive.as_os_str(),
    ]);
    let seed = root.join("restored");
    std::fs::create_dir(&seed).unwrap(); // new and empty, as the guide's `mkdir`
    hearth(&[
        os("backup"),
        os("restore"),
        os("--input"),
        archive.as_os_str(),
        os("--data-dir"),
        seed.as_os_str(),
        os("--allow-unsigned"),
    ]);
    assert!(
        !seed.join("raft.db").exists(),
        "a restore into an empty directory must leave no raft.db for the copies to carry"
    );

    (seed, realm_id, user_id)
}

/// The upgrading guide rebuilds a cluster whose Raft logs were purged by
/// restoring the backup OFFLINE into one empty data directory and copying
/// that directory to every node before the new cluster first starts.
///
/// Restoring into each node separately would not do: each restore builds its
/// own engines on a cold store, and each writes its own random keys and
/// timestamps, so the nodes would start with different state machines. A
/// copy is byte-identical, and the fresh Raft log then applies the same
/// entries on top of the same bytes everywhere. A restore through the new
/// leader over HTTP is not a substitute either: realms come from
/// `hearth.yaml`, so start-up has already created every declared realm under
/// a new id (see `a_rebuild_restores_offline_before_the_first_start` in
/// `src/main.rs`).
///
/// Here the seed goes through the real binary, as the guide does: a store
/// holding a realm, a user and an operator is exported with `hearth backup
/// create` (unfiltered, so it carries the system realm) and restored with
/// `hearth backup restore` into an EMPTY directory — one shared
/// `HEARTH_MASTER_KEY`, no KEK file. That directory (which must hold no
/// `raft.db`) is copied to three new directories and the cluster started.
/// Every node must start (a copied store has no persisted Raft state, which
/// must not be mistaken for a purged log), see the realm under the same id and
/// the operator in the system realm, keep both through realm reconciliation
/// from `hearth.yaml` (what `serve` runs at start-up), and validate a token
/// the leader signs with that realm's key; a write after start-up must
/// replicate.
///
/// Not covered: the nodes are in-process `ClusterEngine`s, not `hearth serve`
/// processes, and the source store is this build's, not a v1.6.11 one.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_cluster_seeded_from_one_offline_restored_directory_serves_it_on_every_node() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let seed_root = tempfile::tempdir().unwrap();
    let (seed, realm_id, user_id) = seed_by_offline_restore(&clock, seed_root.path());

    let cluster = ThreeNodeCluster::build_seeded(&clock, &seed).await;

    // Start-up reconciliation from `hearth.yaml`, which declares the same
    // realm name: it must find the restored realm, not create a new one.
    let config = hearth::config::Config {
        realms: Some(std::collections::HashMap::from([(
            "rebuilt".to_string(),
            hearth::config::RealmYamlConfig::default(),
        )])),
        ..hearth::config::Config::default()
    };
    let leader = cluster.leader();
    hearth::identity::reconcile::reconcile_realms(
        leader.identity.as_ref(),
        leader.rbac.as_ref(),
        &config,
    )
    .unwrap();
    clock.advance(1_000_000);
    cluster.converge().await;

    let system = RealmId::new(uuid::Uuid::nil());
    for node in &cluster.nodes {
        assert!(
            node.identity
                .get_user_by_email(&system, "operator@rebuilt.test")
                .unwrap()
                .is_some(),
            "node {} lost the restored operator-console account",
            node.id()
        );
    }
    for node in &cluster.nodes {
        let realm = node
            .identity
            .get_realm_by_name("rebuilt")
            .unwrap()
            .unwrap_or_else(|| panic!("node {} does not hold the restored realm", node.id()));
        assert_eq!(realm.id(), &realm_id, "node {}", node.id());
        assert!(
            node.identity
                .get_user(&realm_id, &user_id)
                .unwrap()
                .is_some(),
            "node {} lost the restored user",
            node.id()
        );
    }

    // Sessions are not restored: sign in again on the leader.
    let leader = cluster.leader();
    let session = leader
        .identity
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .unwrap();
    let token = leader
        .identity
        .issue_tokens(&realm_id, &user_id, session.id())
        .unwrap()
        .access_token()
        .to_string();
    clock.advance(1_000_000);
    cluster.converge().await;
    for node in cluster.followers() {
        node.identity
            .validate_token(&realm_id, &token)
            .unwrap_or_else(|e| {
                panic!(
                    "node {} rejected a token the leader signed with the restored realm's \
                     key: {e:?}",
                    node.id()
                )
            });
    }

    cluster.shutdown();
}

// ── Single-use redemption across a leader change (G4) ────────────────────────

/// Pauses a node's first read of a key under an armed prefix, AFTER the read
/// returned, until the test opens the gate.
///
/// It stands in for a request that loaded a single-use artifact (a PAR
/// `request_uri`, an authorization code, a device code) and is still in
/// flight when leadership moves — the window in which a check-then-write
/// redemption let two nodes spend the same artifact.
#[derive(Default)]
struct ReadGate {
    prefix: std::sync::Mutex<Option<Vec<u8>>>,
    /// `(reads parked so far, gate open)`.
    state: std::sync::Mutex<(usize, bool)>,
    cv: std::sync::Condvar,
}

impl ReadGate {
    const PARK_LIMIT: Duration = Duration::from_secs(60);

    fn arm(&self, prefix: &[u8]) {
        *self.prefix.lock().unwrap() = Some(prefix.to_vec());
    }

    fn pass(&self, key: &[u8]) {
        let armed = self
            .prefix
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|p| key.starts_with(p));
        if !armed {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if state.1 {
            return;
        }
        state.0 += 1;
        self.cv.notify_all();
        let (_state, timeout) = self
            .cv
            .wait_timeout_while(state, Self::PARK_LIMIT, |s| !s.1)
            .unwrap();
        assert!(!timeout.timed_out(), "a parked read was never released");
    }

    /// Blocks until `n` reads are parked; `false` on timeout.
    fn wait_parked(&self, n: usize, timeout: Duration) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .cv
            .wait_timeout_while(state, timeout, |s| s.0 < n)
            .unwrap();
        state.0 >= n
    }

    fn open(&self) {
        self.state.lock().unwrap().1 = true;
        self.cv.notify_all();
    }
}

/// A node's storage handle whose reads pass through a [`ReadGate`].
struct GatedReads {
    inner: Arc<dyn StorageEngine>,
    gate: Arc<ReadGate>,
}

impl StorageEngine for GatedReads {
    fn accepts_writes(&self) -> bool {
        self.inner.accepts_writes()
    }
    fn put_node_local(&self, r: &RealmId, k: &[u8], v: &[u8]) -> Result<(), StorageError> {
        self.inner.put_node_local(r, k, v)
    }
    fn delete_node_local(&self, r: &RealmId, k: &[u8]) -> Result<(), StorageError> {
        self.inner.delete_node_local(r, k)
    }
    fn get(&self, r: &RealmId, k: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let value = self.inner.get(r, k)?;
        self.gate.pass(k);
        Ok(value)
    }
    fn put(&self, r: &RealmId, k: &[u8], v: &[u8]) -> Result<(), StorageError> {
        self.inner.put(r, k, v)
    }
    fn delete(&self, r: &RealmId, k: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(r, k)
    }
    fn scan(&self, r: &RealmId, a: &[u8], b: &[u8]) -> Result<Vec<ScanEntry>, StorageError> {
        self.inner.scan(r, a, b)
    }
    fn put_batch(&self, r: &RealmId, e: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StorageError> {
        self.inner.put_batch(r, e)
    }
    fn write_batch(
        &self,
        r: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        self.inner.write_batch(r, puts, deletes)
    }
    fn backup_barrier(&self) -> Option<Arc<std::sync::RwLock<()>>> {
        self.inner.backup_barrier()
    }
    fn put_if_absent(&self, r: &RealmId, k: &[u8], v: &[u8]) -> Result<bool, StorageError> {
        self.inner.put_if_absent(r, k, v)
    }
    fn increment_u64(&self, r: &RealmId, k: &[u8]) -> Result<u64, StorageError> {
        self.inner.increment_u64(r, k)
    }
    fn list_realms(&self) -> Result<Vec<RealmId>, StorageError> {
        self.inner.list_realms()
    }
    fn begin_snapshot_restore(&self, id: &str) -> Result<(), StorageError> {
        self.inner.begin_snapshot_restore(id)
    }
    fn complete_snapshot_restore(&self) -> Result<(), StorageError> {
        self.inner.complete_snapshot_restore()
    }
    fn flush_memtable(&self) -> Result<(), StorageError> {
        self.inner.flush_memtable()
    }
}

type GateRegistry = Arc<std::sync::Mutex<BTreeMap<u64, Arc<ReadGate>>>>;

async fn gated_cluster(clock: &Arc<FakeClock>) -> (ThreeNodeCluster, GateRegistry) {
    let gates: GateRegistry = Arc::default();
    let registry = Arc::clone(&gates);
    let wrap = move |id: u64, storage: Arc<dyn StorageEngine>| -> Arc<dyn StorageEngine> {
        let gate = Arc::new(ReadGate::default());
        registry.lock().unwrap().insert(id, Arc::clone(&gate));
        Arc::new(GatedReads {
            inner: storage,
            gate,
        })
    };
    let cluster = ThreeNodeCluster::build_with(clock, &wrap).await;
    (cluster, gates)
}

type Redeem = Arc<dyn Fn(&EmbeddedIdentityEngine) -> bool + Send + Sync>;

/// Races one single-use artifact across a leader change and returns how many
/// redemptions succeeded.
///
/// Both followers load the artifact (it is live) and park. The leader then
/// redeems it. Leadership moves to one of the followers and the parked
/// redemptions resume: the one on the new leader can now write through Raft,
/// so only a check the Raft log itself evaluates can stop it spending the
/// artifact a second time.
async fn redemptions_across_a_leader_change(
    cluster: &ThreeNodeCluster,
    gates: &GateRegistry,
    key_prefix: &[u8],
    redeem: &Redeem,
) -> usize {
    let old_leader_id = cluster.leader_id;
    let mut parked = Vec::new();
    for node in cluster.followers() {
        let gate = Arc::clone(&gates.lock().unwrap()[&node.id()]);
        gate.arm(key_prefix);
        let identity = Arc::clone(&node.identity);
        let redeem = Arc::clone(redeem);
        let racer = tokio::task::spawn_blocking(move || redeem(&identity));
        let waiter = Arc::clone(&gate);
        let loaded =
            tokio::task::spawn_blocking(move || waiter.wait_parked(1, Duration::from_secs(20)))
                .await
                .unwrap();
        assert!(loaded, "node {} never loaded the artifact", node.id());
        parked.push((gate, racer));
    }

    let leader_won = redeem(&cluster.leader().identity);
    assert!(
        leader_won,
        "precondition: the leader must redeem a live artifact"
    );

    let new_leader_id = cluster
        .leader()
        .cluster
        .transfer_leadership()
        .await
        .expect("step down");
    assert_ne!(new_leader_id, old_leader_id);

    let mut wins = usize::from(leader_won);
    for (gate, racer) in parked {
        gate.open();
        wins += usize::from(racer.await.unwrap());
    }
    wins
}

const SINGLE_USE_REDIRECT: &str = "https://app.example.com/cb";
const SINGLE_USE_VERIFIER: &str = "g4-single-use-verifier-0123456789abcdefghijk";

fn single_use_challenge() -> String {
    use base64::Engine as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, SINGLE_USE_VERIFIER.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

fn register_client(
    node: &Node,
    realm: &RealmId,
    name: &str,
    grant_types: &[&str],
) -> hearth::core::ClientId {
    node.identity
        .register_client(
            realm,
            &hearth::identity::RegisterClientRequest {
                client_name: name.to_string(),
                redirect_uris: vec![SINGLE_USE_REDIRECT.to_string()],
                grant_types: grant_types.iter().map(|g| (*g).to_string()).collect(),
                require_consent: false,
                ..Default::default()
            },
        )
        .unwrap()
        .client_id()
        .clone()
}

/// A PAR `request_uri` (RFC 9126 §2.2: single use) is consumed exactly once
/// across the cluster, even when a redemption loaded it before another node
/// consumed it and resumes after leadership moved to its own node.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_par_request_uri_is_consumed_once_across_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let (cluster, gates) = gated_cluster(&clock).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "par-single-use").await;
    let leader = cluster.leader();
    let client = register_client(
        leader,
        &seeded.realm_id,
        "par-racer",
        &["authorization_code"],
    );
    let pushed = leader
        .identity
        .push_authorization_request(
            &seeded.realm_id,
            &hearth::identity::PushedAuthorizationRequest {
                client_id: client,
                redirect_uri: SINGLE_USE_REDIRECT.to_string(),
                scope: "openid".to_string(),
                state: "st".to_string(),
                resource: None,
                response_type: "code".to_string(),
                code_challenge: Some(single_use_challenge()),
                code_challenge_method: Some(hearth::identity::CodeChallengeMethod::S256),
                nonce: None,
                request: None,
                response_mode: None,
                prompt: None,
            },
        )
        .unwrap();
    cluster.converge().await;

    let realm = seeded.realm_id.clone();
    let request_uri = pushed.request_uri.clone();
    let redeem: Redeem = Arc::new(move |identity: &EmbeddedIdentityEngine| {
        identity.consume_par(&realm, &request_uri).is_ok()
    });
    let wins = redemptions_across_a_leader_change(&cluster, &gates, b"oauth:par:", &redeem).await;
    assert_eq!(wins, 1, "one request_uri was consumed {wins} times");

    cluster.shutdown();
}

/// An authorization code (RFC 6749 §4.1.2: MUST NOT be used more than once)
/// is redeemed exactly once across the cluster under the same interleaving.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_authorization_code_is_redeemed_once_across_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let (cluster, gates) = gated_cluster(&clock).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "code-single-use").await;
    let leader = cluster.leader();
    let client = register_client(
        leader,
        &seeded.realm_id,
        "code-racer",
        &["authorization_code"],
    );
    let code = leader
        .identity
        .authorize(
            &seeded.realm_id,
            &hearth::identity::AuthorizationRequest {
                client_id: client.clone(),
                redirect_uri: SINGLE_USE_REDIRECT.to_string(),
                scope: "openid".to_string(),
                state: "st".to_string(),
                response_type: "code".to_string(),
                user_id: seeded.user_id.clone(),
                code_challenge: Some(single_use_challenge()),
                code_challenge_method: Some(hearth::identity::CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .unwrap()
        .code()
        .to_string();
    cluster.converge().await;

    let realm = seeded.realm_id.clone();
    let redeem: Redeem = Arc::new(move |identity: &EmbeddedIdentityEngine| {
        identity
            .exchange_authorization_code(
                &realm,
                &hearth::identity::TokenExchangeRequest {
                    client_id: client.clone(),
                    code: code.clone(),
                    redirect_uri: SINGLE_USE_REDIRECT.to_string(),
                    code_verifier: Some(SINGLE_USE_VERIFIER.to_string()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                },
            )
            .is_ok()
    });
    let wins = redemptions_across_a_leader_change(&cluster, &gates, b"oauth:code:", &redeem).await;
    assert_eq!(wins, 1, "one authorization code was redeemed {wins} times");

    cluster.shutdown();
}

/// An approved device code (RFC 8628 §3.5) is redeemed exactly once across
/// the cluster under the same interleaving.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_code_is_redeemed_once_across_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let (cluster, gates) = gated_cluster(&clock).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "device-single-use").await;
    let leader = cluster.leader();
    let client = register_client(
        leader,
        &seeded.realm_id,
        "device-racer",
        &["urn:ietf:params:oauth:grant-type:device_code"],
    );
    let issued = leader
        .identity
        .device_authorize(
            &seeded.realm_id,
            &hearth::identity::DeviceAuthorizationRequest {
                client_id: client.clone(),
                scope: Some("openid".to_string()),
            },
        )
        .unwrap();
    leader
        .identity
        .approve_device(&seeded.realm_id, &issued.user_code, &seeded.user_id)
        .unwrap();
    cluster.converge().await;

    let realm = seeded.realm_id.clone();
    let device_code = issued.device_code.clone();
    let redeem: Redeem = Arc::new(move |identity: &EmbeddedIdentityEngine| {
        identity
            .poll_device_token(&realm, &device_code, &client)
            .is_ok()
    });
    let wins =
        redemptions_across_a_leader_change(&cluster, &gates, b"oauth:device:", &redeem).await;
    assert_eq!(wins, 1, "one device code was redeemed {wins} times");

    cluster.shutdown();
}

fn seeded_email(realm_name: &str) -> String {
    format!("coherence@{realm_name}.test")
}

/// A magic link signs its holder in once across the cluster under the same
/// interleaving.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_magic_link_is_redeemed_once_across_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let (cluster, gates) = gated_cluster(&clock).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "magic-single-use").await;
    let link = cluster
        .leader()
        .identity
        .request_magic_link(&seeded.realm_id, &seeded_email("magic-single-use"))
        .unwrap();
    cluster.converge().await;

    let realm = seeded.realm_id.clone();
    let token = link.token().to_string();
    let redeem: Redeem = Arc::new(move |identity: &EmbeddedIdentityEngine| {
        identity.validate_magic_link(&realm, &token).is_ok()
    });
    let wins = redemptions_across_a_leader_change(&cluster, &gates, b"magic:link:", &redeem).await;
    assert_eq!(wins, 1, "one magic link was redeemed {wins} times");

    cluster.shutdown();
}

/// A password-reset link sets a password once across the cluster.
///
/// The follower parks on its read of the reset watermark — the last thing it
/// reads before setting the password — and the clock moves before the leader
/// resets, so a follower that re-read the watermark afterwards would already
/// refuse. Only a stale read that the Raft log does not re-check gets through.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_password_reset_link_is_redeemed_once_across_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let (cluster, gates) = gated_cluster(&clock).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "reset-single-use").await;
    let token = cluster
        .leader()
        .identity
        .request_password_reset(&seeded.realm_id, &seeded_email("reset-single-use"))
        .unwrap()
        .expect("a reset link for a known address");
    clock.advance(1_000_000);
    cluster.converge().await;

    let realm = seeded.realm_id.clone();
    let redeem: Redeem = Arc::new(move |identity: &EmbeddedIdentityEngine| {
        let password =
            hearth::identity::CleartextPassword::from_string("Correct-Horse-Battery-9".to_string());
        identity
            .reset_password_with_token(&realm, &token, &password)
            .is_ok()
    });
    let wins = redemptions_across_a_leader_change(&cluster, &gates, b"rst:wm:", &redeem).await;
    assert_eq!(wins, 1, "one password-reset link was redeemed {wins} times");

    cluster.shutdown();
}

/// An email-verification link is redeemed once across the cluster.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_email_verification_link_is_redeemed_once_across_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let (cluster, gates) = gated_cluster(&clock).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "verify-single-use").await;
    let token = cluster
        .leader()
        .identity
        .issue_email_verification_token(&seeded.realm_id, &seeded.user_id)
        .unwrap();
    cluster.converge().await;

    let realm = seeded.realm_id.clone();
    let redeem: Redeem = Arc::new(move |identity: &EmbeddedIdentityEngine| {
        identity.verify_email_token(&realm, &token).is_ok()
    });
    let wins =
        redemptions_across_a_leader_change(&cluster, &gates, b"email:verify:", &redeem).await;
    assert_eq!(
        wins, 1,
        "one email-verification link was redeemed {wins} times"
    );

    cluster.shutdown();
}

/// Runs the authorization-code flow for `client` on `node` and returns the
/// refresh token it issued.
fn issue_refresh_token(
    node: &Node,
    seeded: &SeededRealm,
    client: &hearth::core::ClientId,
) -> String {
    let code = node
        .identity
        .authorize(
            &seeded.realm_id,
            &hearth::identity::AuthorizationRequest {
                client_id: client.clone(),
                redirect_uri: SINGLE_USE_REDIRECT.to_string(),
                scope: "openid offline_access".to_string(),
                state: "st".to_string(),
                response_type: "code".to_string(),
                user_id: seeded.user_id.clone(),
                code_challenge: Some(single_use_challenge()),
                code_challenge_method: Some(hearth::identity::CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .unwrap()
        .code()
        .to_string();
    node.identity
        .exchange_authorization_code(
            &seeded.realm_id,
            &hearth::identity::TokenExchangeRequest {
                client_id: client.clone(),
                code,
                redirect_uri: SINGLE_USE_REDIRECT.to_string(),
                code_verifier: Some(SINGLE_USE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .unwrap()
        .refresh_token()
        .to_string()
}

/// A refresh token rotates once across the cluster: a presentation that read
/// the grant family before another node rotated it must not mint a second
/// pair after leadership moves to its own node.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_refresh_token_rotates_once_across_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let (cluster, gates) = gated_cluster(&clock).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "refresh-single-use").await;
    let leader = cluster.leader();
    let client = register_client(
        leader,
        &seeded.realm_id,
        "refresh-racer",
        &["authorization_code", "refresh_token"],
    );
    let refresh_token = issue_refresh_token(leader, &seeded, &client);
    assert!(!refresh_token.is_empty(), "precondition: a refresh token");
    clock.advance(1_000_000);
    cluster.converge().await;

    let realm = seeded.realm_id.clone();
    let redeem: Redeem = Arc::new(move |identity: &EmbeddedIdentityEngine| {
        identity
            .refresh_tokens(
                &realm,
                &refresh_token,
                None,
                Some(&hearth::identity::RefreshBindContext {
                    authenticated_client_id: Some(client.clone()),
                    ..Default::default()
                }),
            )
            .is_ok()
    });
    let wins =
        redemptions_across_a_leader_change(&cluster, &gates, b"oauth:family:", &redeem).await;
    assert_eq!(wins, 1, "one refresh token was rotated {wins} times");

    cluster.shutdown();
}

// ── Monotonic state across a leader change (G6) ──────────────────────────────

type Racer<T> = Arc<dyn Fn(&EmbeddedIdentityEngine) -> T + Send + Sync>;

/// Races `racer` on both followers against `on_leader` across a leader change,
/// and returns the new leader's id with each racer's outcome.
///
/// Both followers run `racer` until it has read a key under `key_prefix`, and
/// park there. The leader then runs `on_leader`. Leadership moves to one of
/// the followers and the parked racers resume: the one on the new leader can
/// now write through Raft with whatever it read before `on_leader` ran.
async fn raced_against_the_leader_across_a_leader_change<T: Send + 'static>(
    cluster: &ThreeNodeCluster,
    gates: &GateRegistry,
    key_prefix: &[u8],
    racer: &Racer<T>,
    on_leader: impl FnOnce(&EmbeddedIdentityEngine),
) -> (u64, Vec<T>) {
    let old_leader_id = cluster.leader_id;
    let mut parked = Vec::new();
    for node in cluster.followers() {
        let gate = Arc::clone(&gates.lock().unwrap()[&node.id()]);
        gate.arm(key_prefix);
        let identity = Arc::clone(&node.identity);
        let racer = Arc::clone(racer);
        let task = tokio::task::spawn_blocking(move || racer(&identity));
        let waiter = Arc::clone(&gate);
        let loaded =
            tokio::task::spawn_blocking(move || waiter.wait_parked(1, Duration::from_secs(20)))
                .await
                .unwrap();
        assert!(loaded, "node {} never read the raced key", node.id());
        parked.push((gate, task));
    }

    on_leader(&cluster.leader().identity);

    let new_leader_id = cluster
        .leader()
        .cluster
        .transfer_leadership()
        .await
        .expect("step down");
    assert_ne!(new_leader_id, old_leader_id);

    let mut outcomes = Vec::new();
    for (gate, task) in parked {
        gate.open();
        outcomes.push(task.await.unwrap());
    }
    (new_leader_id, outcomes)
}

fn node_by_id(cluster: &ThreeNodeCluster, id: u64) -> &Node {
    cluster.nodes.iter().find(|n| n.id() == id).unwrap()
}

/// Withdrawing consent revokes the grant family for good: a rotation that read
/// the family before the revocation and resumes after leadership moved to its
/// own node must neither mint a pair nor write the family back live.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_consent_revocation_is_not_undone_by_a_rotation_across_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let (cluster, gates) = gated_cluster(&clock).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "consent-unrevoke").await;
    let leader = cluster.leader();
    let client = register_client(
        leader,
        &seeded.realm_id,
        "consent-racer",
        &["authorization_code", "refresh_token"],
    );
    leader
        .identity
        .grant_consent(
            &seeded.realm_id,
            &seeded.user_id,
            &client,
            &["openid".to_string(), "offline_access".to_string()],
        )
        .unwrap();
    let refresh_token = issue_refresh_token(leader, &seeded, &client);
    clock.advance(1_000_000);
    cluster.converge().await;

    let realm = seeded.realm_id.clone();
    let bound_client = client.clone();
    let rotate: Racer<Option<String>> = Arc::new(move |identity: &EmbeddedIdentityEngine| {
        identity
            .refresh_tokens(
                &realm,
                &refresh_token,
                None,
                Some(&hearth::identity::RefreshBindContext {
                    authenticated_client_id: Some(bound_client.clone()),
                    ..Default::default()
                }),
            )
            .ok()
            .map(|pair| pair.refresh_token().to_string())
    });
    let (new_leader_id, rotated) = raced_against_the_leader_across_a_leader_change(
        &cluster,
        &gates,
        b"oauth:family:",
        &rotate,
        |identity| {
            identity
                .revoke_consent(&seeded.realm_id, &seeded.user_id, &client)
                .unwrap();
        },
    )
    .await;
    cluster.converge().await;

    let new_leader = node_by_id(&cluster, new_leader_id);
    for minted in rotated.iter().flatten() {
        let still_live = new_leader
            .identity
            .refresh_tokens(
                &seeded.realm_id,
                minted,
                None,
                Some(&hearth::identity::RefreshBindContext {
                    authenticated_client_id: Some(client.clone()),
                    ..Default::default()
                }),
            )
            .is_ok();
        assert!(
            !still_live,
            "a rotation that read the family before the consent revocation \
             wrote it back live: its refresh token still rotates"
        );
    }
    let minted = rotated.iter().flatten().count();
    assert_eq!(
        minted, 0,
        "a rotation that read the family before the consent revocation minted \
         {minted} pair(s) after it"
    );

    cluster.shutdown();
}

/// An organization with an owner, and a pending invitation for a new address;
/// returns the org, the invitee's address, the invitation's id and its token.
fn pending_invitation(
    node: &Node,
    seeded: &SeededRealm,
    slug: &str,
) -> (
    hearth::core::OrganizationId,
    String,
    hearth::core::InvitationId,
    String,
) {
    use hearth::identity::{CreateInvitationRequest, CreateOrganizationRequest, OrganizationRole};
    let org = node
        .identity
        .create_organization(
            &seeded.realm_id,
            &CreateOrganizationRequest {
                name: slug.to_string(),
                slug: slug.to_string(),
                description: None,
                config: None,
                ..Default::default()
            },
        )
        .unwrap();
    node.identity
        .add_member(
            &seeded.realm_id,
            org.id(),
            &seeded.user_id,
            OrganizationRole::Owner,
        )
        .unwrap();
    let invitee = format!("invitee@{slug}.test");
    let (invitation, token) = node
        .identity
        .create_invitation(
            &seeded.realm_id,
            &CreateInvitationRequest {
                org_id: org.id().clone(),
                email: invitee.clone(),
                role: OrganizationRole::Member,
                invited_by: seeded.user_id.clone(),
            },
        )
        .unwrap();
    (org.id().clone(), invitee, invitation.id().clone(), token)
}

/// Whether `email` is a member of `org` on `node`.
fn is_member(
    node: &Node,
    realm: &RealmId,
    org: &hearth::core::OrganizationId,
    email: &str,
) -> bool {
    node.identity
        .get_user_by_email(realm, email)
        .unwrap()
        .is_some_and(|u| {
            node.identity
                .get_membership(realm, org, u.id())
                .unwrap()
                .is_some()
        })
}

/// A revoked invitation stays revoked: an acceptance that read it while still
/// pending, and resumes after leadership moved to its own node, must not
/// admit the invitee.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_revoked_invitation_is_not_accepted_across_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let (cluster, gates) = gated_cluster(&clock).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "inv-revoke").await;
    let (org, invitee, invitation_id, token) =
        pending_invitation(cluster.leader(), &seeded, "inv-revoke");
    cluster.converge().await;

    let realm = seeded.realm_id.clone();
    let accept: Racer<bool> = Arc::new(move |identity: &EmbeddedIdentityEngine| {
        identity.accept_invitation(&realm, &token).is_ok()
    });
    let (new_leader_id, accepted) = raced_against_the_leader_across_a_leader_change(
        &cluster,
        &gates,
        b"orgi:id:",
        &accept,
        |identity| {
            identity
                .revoke_invitation(&seeded.realm_id, &invitation_id)
                .unwrap();
        },
    )
    .await;
    cluster.converge().await;

    let admitted = accepted.iter().filter(|a| **a).count();
    assert_eq!(
        admitted, 0,
        "an acceptance that read the invitation before its revocation admitted \
         the invitee {admitted} time(s)"
    );
    assert!(
        !is_member(
            node_by_id(&cluster, new_leader_id),
            &seeded.realm_id,
            &org,
            &invitee
        ),
        "the revoked invitation's invitee is a member"
    );

    cluster.shutdown();
}

/// An invitation admits once: after it was accepted and the member removed,
/// an acceptance that read it while still pending must not re-admit them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_invitation_is_accepted_once_across_a_leader_change() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let (cluster, gates) = gated_cluster(&clock).await;
    let seeded = seed_realm_user_and_token(&cluster, &clock, "inv-once").await;
    let (org, invitee, _, token) = pending_invitation(cluster.leader(), &seeded, "inv-once");
    cluster.converge().await;

    let realm = seeded.realm_id.clone();
    let racer_token = token.clone();
    let accept: Racer<bool> = Arc::new(move |identity: &EmbeddedIdentityEngine| {
        identity.accept_invitation(&realm, &racer_token).is_ok()
    });
    let (new_leader_id, accepted) = raced_against_the_leader_across_a_leader_change(
        &cluster,
        &gates,
        b"orgi:id:",
        &accept,
        |identity| {
            let membership = identity
                .accept_invitation(&seeded.realm_id, &token)
                .expect("precondition: the leader accepts a pending invitation");
            identity
                .remove_member(&seeded.realm_id, &org, membership.user_id())
                .unwrap();
        },
    )
    .await;
    cluster.converge().await;

    let readmitted = accepted.iter().filter(|a| **a).count();
    assert_eq!(
        readmitted, 0,
        "an acceptance that read the invitation before it was spent admitted \
         the invitee again {readmitted} time(s)"
    );
    assert!(
        !is_member(
            node_by_id(&cluster, new_leader_id),
            &seeded.realm_id,
            &org,
            &invitee
        ),
        "a removed member was re-admitted by a spent invitation"
    );

    cluster.shutdown();
}
