//! Follower write forwarding (clustering guide H-3).
//!
//! A write that reaches a follower used to be refused with `raft: not the
//! leader` (an HTTP 500), so every login and every mutation served by a
//! follower failed. A follower now forwards the Raft command to the leader
//! over the peer mTLS channel, the leader proposes it and answers with the
//! committed log index, and the follower waits until its own state machine has
//! applied that index before it returns — so the caller reads its own write on
//! the node it wrote to.
//!
//! Every test here stands up **three real nodes** on loopback (real openraft,
//! real mTLS gRPC sockets) and sends the writes to a **follower**. The fixture
//! mirrors `tests/cluster_three_node_control_coherence.rs`, trimmed to what
//! these tests need; nextest runs this binary in the `three-node-cluster`
//! group so it never shares the machine with another cluster.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::cluster::{serve, ClusterEngine, ClusterStorageAdapter, HearthNode, PeerFaults};
use hearth::config::ClusterConfig;
use hearth::core::{Clock, FakeClock, RealmId, Timestamp, UserId};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, SessionContext,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tempfile::TempDir;
use uuid::Uuid;

// ── Throwaway mTLS bundle ────────────────────────────────────────────────────

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
    let listeners: Vec<std::net::TcpListener> = (0..n)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect()
}

// ── The cluster ──────────────────────────────────────────────────────────────

/// One `hearth serve` process: its Raft engine, the storage handle the
/// application layer uses, the fault injector on its outbound peer RPCs, and
/// the peer gRPC server task.
struct Node {
    id: u64,
    cluster: Arc<ClusterEngine>,
    storage: Arc<dyn StorageEngine>,
    faults: Arc<PeerFaults>,
    server: tokio::task::JoinHandle<()>,
}

struct ThreeNodes {
    nodes: Vec<Node>,
    leader_id: u64,
    _tempdir: TempDir,
}

impl ThreeNodes {
    async fn start() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tempdir = tempfile::tempdir().unwrap();
        let (ca_path, leaf_certs) = generate_cluster_certs(tempdir.path(), 3);
        let ports = pick_free_loopback_ports(3);

        let mut nodes = Vec::with_capacity(3);
        let mut members = BTreeMap::new();
        for (i, (cert_path, key_path)) in leaf_certs.into_iter().enumerate() {
            let id = (i + 1) as u64;
            let data_dir = tempdir.path().join(format!("node-{id}-data"));
            std::fs::create_dir_all(&data_dir).unwrap();
            let storage_cfg = StorageConfig::dev(data_dir);
            let inner = Arc::new(EmbeddedStorageEngine::open(storage_cfg.clone()).unwrap());
            let cfg = ClusterConfig {
                node_id: id,
                peer_address: format!("127.0.0.1:{}", ports[i]),
                peers: vec![],
                tls_cert_path: cert_path,
                tls_key_path: key_path,
                tls_ca_cert_path: ca_path.clone(),
                // Generous: follower reads must not be fenced by the lag
                // monitor during the brief window between commit and apply.
                read_lag_threshold_ms: Some(30_000),
                write_timeout_ms: None,
            };
            let faults = PeerFaults::new();
            let cluster = Arc::new(
                ClusterEngine::build_clustered_with_peer_faults(
                    inner,
                    &cfg,
                    &storage_cfg,
                    Arc::clone(&faults),
                )
                .await
                .unwrap(),
            );
            let serve_engine = Arc::clone(&cluster);
            let serve_cfg = cfg.clone();
            let server = tokio::spawn(async move {
                let _ = serve(&serve_cfg, serve_engine).await;
            });
            members.insert(
                id,
                HearthNode {
                    addr: cfg.peer_address.clone(),
                },
            );
            let storage: Arc<dyn StorageEngine> =
                Arc::new(ClusterStorageAdapter::new(Arc::clone(&cluster)));
            nodes.push(Node {
                id,
                cluster,
                storage,
                faults,
                server,
            });
        }

        // AUDIT: justified-sleep: gRPC listeners need OS scheduling time to bind before the bootstrap RPC attempts connections
        tokio::time::sleep(Duration::from_millis(400)).await;
        nodes[0].cluster.initialize_cluster(members).await.unwrap();
        let engines: Vec<Arc<ClusterEngine>> =
            nodes.iter().map(|n| Arc::clone(&n.cluster)).collect();
        let leader_id = wait_for_leader(&engines, &[], Duration::from_secs(20)).await;
        wait_converged(&engines, Duration::from_secs(20)).await;
        Self {
            nodes,
            leader_id,
            _tempdir: tempdir,
        }
    }

    fn node(&self, id: u64) -> &Node {
        self.nodes.iter().find(|n| n.id == id).unwrap()
    }

    fn leader(&self) -> &Node {
        self.node(self.leader_id)
    }

    fn followers(&self) -> Vec<&Node> {
        self.nodes
            .iter()
            .filter(|n| n.id != self.leader_id)
            .collect()
    }

    fn engines(&self) -> Vec<Arc<ClusterEngine>> {
        self.nodes.iter().map(|n| Arc::clone(&n.cluster)).collect()
    }

    async fn converge(&self) {
        wait_converged(&self.engines(), Duration::from_secs(20)).await;
    }

    fn shutdown(self) {
        for n in self.nodes {
            n.server.abort();
        }
    }
}

/// The node every live node agrees leads, ignoring nodes in `dead`.
async fn wait_for_leader(engines: &[Arc<ClusterEngine>], dead: &[u64], timeout: Duration) -> u64 {
    let deadline = Instant::now() + timeout;
    loop {
        let live: Vec<_> = engines
            .iter()
            .filter_map(|e| e.raft_metrics())
            .filter(|m| !dead.contains(&m.id))
            .collect();
        if let Some(leader) = live[0].current_leader {
            if !dead.contains(&leader) && live.iter().all(|m| m.current_leader == Some(leader)) {
                return leader;
            }
        }
        assert!(
            Instant::now() <= deadline,
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

/// Waits until every engine has applied every entry any of them has logged.
async fn wait_converged(engines: &[Arc<ClusterEngine>], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let target = engines
            .iter()
            .filter_map(|e| e.raft_metrics().and_then(|m| m.last_log_index))
            .max()
            .unwrap_or(0);
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

fn realm() -> RealmId {
    RealmId::new(Uuid::new_v4())
}

fn counter(bytes: Option<Vec<u8>>) -> u64 {
    let bytes = bytes.expect("the counter row exists");
    u64::from_le_bytes(bytes.as_slice().try_into().expect("8-byte LE counter"))
}

/// Runs a synchronous storage call off the async worker (the adapter blocks).
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

// ── Raw storage writes on a follower ─────────────────────────────────────────

/// Every write primitive the application layer uses succeeds when issued to a
/// follower, is readable on that follower the moment the call returns, and
/// replicates to the other two nodes. Conditional outcomes are the leader's:
/// a `put_if_absent` of a key another follower already claimed answers
/// `false`, and increments from two followers never collide.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn every_write_primitive_sent_to_a_follower_succeeds_and_reads_back_there() {
    let cluster = ThreeNodes::start().await;
    let realm = realm();
    let followers = cluster.followers();
    let (a, b) = (followers[0], followers[1]);

    for (n, follower) in [a, b].into_iter().enumerate() {
        let storage = Arc::clone(&follower.storage);
        let r = realm.clone();
        let key = format!("put:{n}").into_bytes();
        let (put, read) = blocking(move || {
            let put = storage.put(&r, &key, b"v");
            (put, storage.get(&r, &key))
        })
        .await;
        put.unwrap_or_else(|e| panic!("node {} (a follower) refused a put: {e}", follower.id));
        assert_eq!(
            read.unwrap(),
            Some(b"v".to_vec()),
            "node {} acknowledged a put it cannot read back",
            follower.id
        );
    }

    // Conditional write: the first follower's claim wins, the second's loses.
    let (sa, sb) = (Arc::clone(&a.storage), Arc::clone(&b.storage));
    let r = realm.clone();
    let (first, read, second) = blocking(move || {
        let first = sa.put_if_absent(&r, b"claim", b"a");
        let read = sa.get(&r, b"claim");
        let second = sb.put_if_absent(&r, b"claim", b"b");
        (first, read, second)
    })
    .await;
    assert!(first.unwrap(), "the first claim of an absent key must win");
    assert_eq!(read.unwrap(), Some(b"a".to_vec()));
    assert!(
        !second.unwrap(),
        "a claim of a key another follower holds must lose, not overwrite it"
    );

    // Increments from both followers are serialised by the leader.
    let (sa, sb) = (Arc::clone(&a.storage), Arc::clone(&b.storage));
    let r = realm.clone();
    let (one, two, read_b) = blocking(move || {
        let one = sa.increment_u64(&r, b"ctr").unwrap();
        let two = sb.increment_u64(&r, b"ctr").unwrap();
        (one, two, sb.get(&r, b"ctr").unwrap())
    })
    .await;
    assert_eq!((one, two), (1, 2));
    assert_eq!(
        counter(read_b),
        2,
        "the incrementing follower reads its own increment"
    );

    // Batches and deletes.
    let sa = Arc::clone(&a.storage);
    let r = realm.clone();
    let (batch, gone) = blocking(move || {
        sa.put_batch(
            &r,
            &[
                (b"b1".to_vec(), b"1".to_vec()),
                (b"b2".to_vec(), b"2".to_vec()),
            ],
        )
        .unwrap();
        sa.write_batch(&r, &[(b"b3".to_vec(), b"3".to_vec())], &[b"b1".to_vec()])
            .unwrap();
        sa.delete(&r, b"put:0").unwrap();
        (
            [b"b1".as_slice(), b"b2", b"b3"].map(|k| sa.get(&r, k).unwrap()),
            sa.get(&r, b"put:0").unwrap(),
        )
    })
    .await;
    assert_eq!(batch, [None, Some(b"2".to_vec()), Some(b"3".to_vec())]);
    assert_eq!(
        gone, None,
        "a forwarded delete must be visible on the follower at once"
    );

    // Everything replicated to every node.
    cluster.converge().await;
    for node in &cluster.nodes {
        let s = Arc::clone(&node.storage);
        let r = realm.clone();
        let got = blocking(move || {
            (
                s.get(&r, b"put:1").unwrap(),
                s.get(&r, b"claim").unwrap(),
                s.get(&r, b"ctr").unwrap(),
                s.get(&r, b"b3").unwrap(),
                s.get(&r, b"put:0").unwrap(),
            )
        })
        .await;
        assert_eq!(got.0, Some(b"v".to_vec()), "node {}", node.id);
        assert_eq!(got.1, Some(b"a".to_vec()), "node {}", node.id);
        assert_eq!(counter(got.2), 2, "node {}", node.id);
        assert_eq!(got.3, Some(b"3".to_vec()), "node {}", node.id);
        assert_eq!(got.4, None, "node {}", node.id);
    }

    cluster.shutdown();
}

// ── A login and a single-use claim on a follower ─────────────────────────────

fn identity_over(node: &Node, clock: &Arc<FakeClock>) -> Arc<EmbeddedIdentityEngine> {
    let clock_dyn = Arc::clone(clock) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&node.storage),
        Arc::clone(&clock_dyn),
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&node.storage),
        Arc::clone(&clock_dyn),
    )) as Arc<dyn AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&node.storage),
            clock_dyn,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            rbac as Arc<dyn RbacEngine>,
            audit,
        )
        .unwrap(),
    );
    node.cluster.set_replicated_write_observer(
        Arc::clone(&identity) as Arc<dyn hearth::cluster::ReplicatedWriteObserver>
    );
    identity
}

const REDIRECT: &str = "https://app.example.com/cb";

fn pkce_challenge() -> String {
    use base64::Engine as _;
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        b"forwarding-verifier-0123456789abcdefghijklmn",
    );
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// Registers a client and pushes an authorization request on `identity`
/// (both writes), returning the single-use `request_uri`.
fn push_par_on(identity: &EmbeddedIdentityEngine, realm_id: &RealmId, node_id: u64) -> String {
    let client = identity
        .register_client(
            realm_id,
            &hearth::identity::RegisterClientRequest {
                client_name: "forwarded".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .unwrap()
        .client_id()
        .clone();
    let pushed = identity
        .push_authorization_request(
            realm_id,
            &hearth::identity::PushedAuthorizationRequest {
                client_id: client,
                redirect_uri: REDIRECT.to_string(),
                scope: "openid".to_string(),
                state: "st".to_string(),
                resource: None,
                response_type: "code".to_string(),
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(hearth::identity::CodeChallengeMethod::S256),
                nonce: None,
                request: None,
                response_mode: None,
                prompt: None,
            },
        )
        .unwrap_or_else(|e| panic!("node {} refused a PAR push: {e:?}", node_id));
    pushed.request_uri
}

/// A login served by a follower — password check, session write, token
/// issuance — succeeds, and the token validates on that follower at once and
/// on the other follower after replication. A PAR `request_uri` pushed to a
/// follower is consumable there at once and spent exactly once cluster-wide:
/// the claim is a forwarded `PutIfAbsent`, evaluated by the leader's log.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_login_and_a_single_use_claim_served_by_a_follower_succeed() {
    let cluster = ThreeNodes::start().await;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));

    // The leader's stack first: its constructor writes the start-up set.
    let leader = identity_over(cluster.leader(), &clock);
    cluster.converge().await;
    let followers = cluster.followers();
    let (fa, fb) = (followers[0], followers[1]);
    let on_a = identity_over(fa, &clock);
    let on_b = identity_over(fb, &clock);

    let realm = leader
        .create_realm(&CreateRealmRequest {
            name: "forwarding".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();
    let realm_id = realm.id().clone();
    cluster.converge().await;

    // The user is created ON THE FOLLOWER: an admin write, forwarded.
    let user = on_a
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "login@forwarding.test".to_string(),
                display_name: "Login".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("node {} (a follower) refused create_user: {e:?}", fa.id));
    let user_id: UserId = user.id().clone();
    let password = CleartextPassword::new(b"correct-horse-battery-staple".to_vec());
    on_a.set_password(&realm_id, &user_id, &password)
        .unwrap_or_else(|e| panic!("node {} refused set_password: {e:?}", fa.id));

    // The login, entirely on the follower.
    assert!(on_a
        .verify_password(&realm_id, &user_id, &password)
        .unwrap());
    let session = on_a
        .create_session(&realm_id, &user_id, &SessionContext::default())
        .unwrap_or_else(|e| panic!("node {} refused the login's session write: {e:?}", fa.id));
    let pair = on_a
        .issue_tokens(&realm_id, &user_id, session.id())
        .unwrap_or_else(|e| panic!("node {} refused token issuance: {e:?}", fa.id));
    let claims = on_a
        .validate_token(&realm_id, pair.access_token())
        .unwrap_or_else(|e| {
            panic!(
                "node {} issued a token it cannot validate at once: {e:?}",
                fa.id
            )
        });
    assert!(
        claims.sub.ends_with(&user_id.as_uuid().to_string()),
        "the token names {} instead of the user who logged in",
        claims.sub
    );

    cluster.converge().await;
    on_b.validate_token(&realm_id, pair.access_token())
        .unwrap_or_else(|e| panic!("node {} rejected the follower's token: {e:?}", fb.id));
    leader
        .validate_token(&realm_id, pair.access_token())
        .unwrap_or_else(|e| panic!("the leader rejected the follower's token: {e:?}"));

    // A single-use artifact issued to, and claimed on, a follower.
    let request_uri = push_par_on(&on_a, &realm_id, fa.id);
    on_a.consume_par(&realm_id, &request_uri)
        .unwrap_or_else(|e| {
            panic!(
                "node {} could not spend a request_uri it just issued: {e:?}",
                fa.id
            )
        });
    cluster.converge().await;
    assert!(
        on_b.consume_par(&realm_id, &request_uri).is_err(),
        "a spent request_uri was redeemed again on node {}",
        fb.id
    );
    assert!(
        leader.consume_par(&realm_id, &request_uri).is_err(),
        "a spent request_uri was redeemed again on the leader"
    );

    cluster.shutdown();
}

// ── Exactly once ─────────────────────────────────────────────────────────────

/// A forwarded write whose reply is lost after the leader committed it has an
/// unknown outcome from the follower's point of view. It must be reported as
/// such and **not** retried: a retry of a `PutIfAbsent` would answer `false`
/// for the caller's own write, and a retried increment would count twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_forwarded_write_whose_reply_is_lost_is_applied_once_and_never_retried() {
    let cluster = ThreeNodes::start().await;
    let realm = realm();
    let leader_id = cluster.leader_id;
    let follower = cluster.followers()[0];
    follower.faults.lose_forward_replies(leader_id);

    let s = Arc::clone(&follower.storage);
    let r = realm.clone();
    let (inc, claim) = blocking(move || {
        (
            s.increment_u64(&r, b"ctr"),
            s.put_if_absent(&r, b"claim", b"mine"),
        )
    })
    .await;
    let inc = inc.expect_err("the reply was lost: the increment's outcome is unknown");
    let claim = claim.expect_err("the reply was lost: the claim's outcome is unknown");
    for err in [&inc, &claim] {
        let msg = err.to_string();
        assert!(
            msg.contains("outcome is unknown") && !hearth::cluster::is_not_leader(err),
            "a lost reply must read as an unknown outcome, not a refusal: {msg}"
        );
    }
    assert_eq!(
        follower.faults.forwards_sent(leader_id),
        2,
        "each write was forwarded more than once: a retry after an unknown outcome can apply \
         a conditional write twice"
    );

    follower.faults.heal_all();
    cluster.converge().await;
    for node in &cluster.nodes {
        let s = Arc::clone(&node.storage);
        let r = realm.clone();
        let (ctr, claim) =
            blocking(move || (s.get(&r, b"ctr").unwrap(), s.get(&r, b"claim").unwrap())).await;
        assert_eq!(
            counter(ctr),
            1,
            "node {}: the increment applied twice",
            node.id
        );
        assert_eq!(claim, Some(b"mine".to_vec()), "node {}", node.id);
    }

    cluster.shutdown();
}

/// What each worker's `put_if_absent` of a fresh key answered.
type Claims = Vec<(Vec<u8>, Result<bool, String>)>;
/// What each worker's `increment_u64` answered.
type Incs = Vec<Result<u64, String>>;

/// No conditional write the workers issued was applied twice, and none they
/// were told succeeded is missing on the survivors.
async fn assert_applied_at_most_once(
    cluster: &ThreeNodes,
    survivor_ids: &[u64],
    realm: &RealmId,
    claims: &Claims,
    incs: &Incs,
) {
    let lost_claims: Vec<_> = claims.iter().filter(|(_, r)| *r == Ok(false)).collect();
    assert!(
        lost_claims.is_empty(),
        "a claim of a key nobody else writes answered `false` — the write was applied twice: \
         {lost_claims:?}"
    );
    let won: BTreeSet<Vec<u8>> = claims
        .iter()
        .filter(|(_, r)| *r == Ok(true))
        .map(|(k, _)| k.clone())
        .collect();
    let values: Vec<u64> = incs
        .iter()
        .filter_map(|r| r.as_ref().ok().copied())
        .collect();
    let distinct: BTreeSet<u64> = values.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        values.len(),
        "two increments returned the same value"
    );
    let failed_incs = incs.iter().filter(|r| r.is_err()).count() as u64;

    for id in survivor_ids {
        let s = Arc::clone(&cluster.node(*id).storage);
        let r = realm.clone();
        let keys: Vec<Vec<u8>> = won.iter().cloned().collect();
        let (present, ctr) = blocking(move || {
            let present = keys
                .iter()
                .filter(|k| s.get(&r, k).unwrap().is_some())
                .count();
            (present, s.get(&r, b"ctr").unwrap())
        })
        .await;
        assert_eq!(
            present,
            won.len(),
            "node {id} lost a claim it reported as won"
        );
        let ctr = counter(ctr);
        assert!(
            ctr >= values.iter().copied().max().unwrap_or(0),
            "node {id}: the counter ({ctr}) is behind an acknowledged increment"
        );
        assert!(
            ctr <= values.len() as u64 + failed_incs,
            "node {id}: the counter ({ctr}) moved further than the {} acknowledged plus {} \
             failed increments could — an increment applied twice",
            values.len(),
            failed_incs
        );
    }
}

/// Sets the flag when dropped.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// The leader is killed while a follower is forwarding a stream of
/// conditional writes to it. Afterwards: every claim the follower reported as
/// won is durable on the survivors, no claim of a fresh key ever answered
/// `false` (which only a duplicate application can produce), every reported
/// increment is distinct, and the counter never moved further than the
/// increments that could have landed. Writes resume on the new leader.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn killing_the_leader_mid_forwarding_never_applies_a_conditional_write_twice() {
    let cluster = ThreeNodes::start().await;
    let realm = realm();
    let dead = cluster.leader_id;
    let follower = cluster.followers()[0];
    let survivor_ids: Vec<u64> = cluster.followers().iter().map(|n| n.id).collect();

    let claims: Arc<Mutex<Claims>> = Arc::default();
    let incs: Arc<Mutex<Incs>> = Arc::default();
    let stop = Arc::new(AtomicBool::new(false));
    // Stops the workers however this test ends, a failed assertion included,
    // so no worker outlives the runtime.
    let _stop_on_exit = StopOnDrop(Arc::clone(&stop));
    let killed = Arc::new(AtomicBool::new(false));
    let wins_after_kill = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let mut workers = Vec::new();
    for w in 0..4 {
        let (s, r) = (Arc::clone(&follower.storage), realm.clone());
        let (claims, incs, stop) = (Arc::clone(&claims), Arc::clone(&incs), Arc::clone(&stop));
        let (killed, wins_after_kill) = (Arc::clone(&killed), Arc::clone(&wins_after_kill));
        workers.push(tokio::task::spawn_blocking(move || {
            let mut i = 0u64;
            while !stop.load(Ordering::SeqCst) {
                let key = format!("claim:{w}:{i}").into_bytes();
                let won = s.put_if_absent(&r, &key, b"x").map_err(|e| e.to_string());
                if won == Ok(true) && killed.load(Ordering::SeqCst) {
                    wins_after_kill.fetch_add(1, Ordering::SeqCst);
                }
                claims.lock().unwrap().push((key, won));
                let inc = s.increment_u64(&r, b"ctr").map_err(|e| e.to_string());
                incs.lock().unwrap().push(inc);
                i += 1;
            }
        }));
    }

    // Let a steady stream of forwarded writes build up, then kill the leader
    // with writes in flight: stop its Raft core and its peer server, and cut
    // the survivors off from it as a dead host would be.
    let deadline = Instant::now() + Duration::from_secs(20);
    while claims
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, r)| *r == Ok(true))
        .count()
        < 20
    {
        assert!(
            Instant::now() < deadline,
            "forwarded writes never got going"
        );
        // AUDIT: justified-sleep: poll interval of a deadline-bounded condition loop on the workers' progress
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let leader = cluster.leader();
    leader.server.abort();
    leader.cluster.shutdown().await;
    killed.store(true, Ordering::SeqCst);
    for id in &survivor_ids {
        cluster.node(*id).faults.isolate(dead);
    }

    let survivors: Vec<Arc<ClusterEngine>> = survivor_ids
        .iter()
        .map(|id| Arc::clone(&cluster.node(*id).cluster))
        .collect();
    let new_leader = wait_for_leader(&survivors, &[dead], Duration::from_secs(30)).await;
    assert_ne!(new_leader, dead);
    let deadline = Instant::now() + Duration::from_secs(30);
    while wins_after_kill.load(Ordering::SeqCst) < 5 {
        assert!(
            Instant::now() < deadline,
            "forwarded writes never resumed on the new leader (node {new_leader})"
        );
        // AUDIT: justified-sleep: poll interval of a deadline-bounded condition loop on the workers' progress
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stop.store(true, Ordering::SeqCst);
    for w in workers {
        w.await.unwrap();
    }
    wait_converged(&survivors, Duration::from_secs(20)).await;

    let claims = std::mem::take(&mut *claims.lock().unwrap());
    let incs = std::mem::take(&mut *incs.lock().unwrap());
    assert_applied_at_most_once(&cluster, &survivor_ids, &realm, &claims, &incs).await;

    cluster.shutdown();
}
