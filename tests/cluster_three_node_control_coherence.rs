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
use hearth::config::ClusterConfig;
use hearth::core::{Clock, FakeClock, RealmId, SessionId, Timestamp, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, RealmConfig, RealmStatus, SessionContext, UpdateRealmRequest,
};
use hearth::rbac::{
    AssignRoleRequest, CreateRoleRequest, EmbeddedRbacEngine, Permission, RbacEngine, RoleId,
    Scope, Subject,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
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
fn app_stack_over(
    cluster: &Arc<ClusterEngine>,
    clock: &Arc<FakeClock>,
) -> (Arc<EmbeddedRbacEngine>, Arc<EmbeddedIdentityEngine>) {
    let storage: Arc<dyn StorageEngine> = Arc::new(ClusterStorageAdapter::new(Arc::clone(cluster)));
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
        let (leader_rbac, leader_identity) = app_stack_over(&engines[leader_idx], clock);

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
                let (rbac, identity) = app_stack_over(engine, clock);
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

    assert_session_revocation_binds(&cluster, &seeded).await;
    assert_realm_suspension_binds(&cluster, &clock, &seeded).await;

    cluster.shutdown();
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
async fn assert_session_revocation_binds(cluster: &ThreeNodeCluster, seeded: &SeededRealm) {
    cluster
        .leader()
        .identity
        .revoke_session(&seeded.realm_id, &seeded.session_id)
        .unwrap();
    cluster.converge().await;

    for node in cluster.followers() {
        let err = node
            .identity
            .validate_token(&seeded.realm_id, &seeded.access_token)
            .err()
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

    for node in cluster.followers() {
        let err = node
            .identity
            .validate_token(&seeded.realm_id, &fresh_token)
            .err()
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

// ── Test 2: the documented bootstrap sequence cannot start a node ────────────

/// `docs/guides/clustering.md` § Bootstrap Sequence says: start every node,
/// wait for them to listen, then POST `/admin/cluster/bootstrap` to one of
/// them. No node survives to step 3.
///
/// `serve` builds `EmbeddedIdentityEngine` over the `ClusterStorageAdapter`,
/// and the constructor's first act is `load_or_persist_global_signing_key`,
/// which **writes** on a cold data dir. In cluster mode that write is a Raft
/// proposal, and before bootstrap there is no leader, so it returns
/// `NotLeader` and start-up is fatal. Observed on all three nodes of a real
/// three-node run:
///
/// ```text
/// ERROR hearth: error: storage error: storage I/O error:
///               raft: not the leader; redirect to unknown
/// ```
///
/// This is a characterisation test, not an approval: it pins the defect at
/// the smallest reproducer (one un-bootstrapped node) so that a fix — lazy
/// key creation, auto-initialisation from `cluster.peers`, or deferring the
/// identity engine until a leader exists — flips it red and has to say so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_engine_construction_fails_on_an_unbootstrapped_cluster_node() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tempdir = tempfile::tempdir().unwrap();
    let (ca_path, leaf_certs) = generate_cluster_certs(tempdir.path(), 1);
    let ports = pick_free_loopback_ports(1);
    let data_dir = tempdir.path().join("node-1-data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage_cfg = StorageConfig::dev(data_dir);
    let inner = Arc::new(EmbeddedStorageEngine::open(storage_cfg.clone()).unwrap());
    let cluster_cfg = ClusterConfig {
        node_id: 1,
        peer_address: format!("127.0.0.1:{}", ports[0]),
        peers: vec![],
        tls_cert_path: leaf_certs[0].0.clone(),
        tls_key_path: leaf_certs[0].1.clone(),
        tls_ca_cert_path: ca_path,
        read_lag_threshold_ms: Some(30_000),
    };
    // Built, never bootstrapped — exactly the state every node is in between
    // step 1 and step 3 of the documented sequence.
    let cluster = Arc::new(
        ClusterEngine::build_clustered(inner, &cluster_cfg, &storage_cfg)
            .await
            .unwrap(),
    );

    let storage: Arc<dyn StorageEngine> = Arc::new(ClusterStorageAdapter::new(cluster));
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    ))) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;

    let err = EmbeddedIdentityEngine::with_rbac(
        storage,
        clock,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        rbac as Arc<dyn RbacEngine>,
        audit,
    )
    .expect_err(
        "identity-engine construction unexpectedly SUCCEEDED on an un-bootstrapped \
         cluster node — if the global signing key is no longer written eagerly, the \
         documented bootstrap sequence may now work; re-run the three-node walkthrough \
         in reports/cluster-ga-readiness-2026-09-21.md and update this test",
    );
    let rendered = err.to_string();
    assert!(
        rendered.contains("not the leader"),
        "expected the constructor's storage write to fail with NotLeader, got: {rendered}"
    );
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
