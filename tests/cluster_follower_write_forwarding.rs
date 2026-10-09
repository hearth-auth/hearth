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
//! lives in `tests/cluster_fixture/`; nextest runs this binary in the `three-node-cluster`
//! group so it never shares the machine with another cluster.

#![allow(clippy::unwrap_used)]

mod cluster_fixture;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cluster_fixture::{
    blocking, counter, realm, wait_converged, wait_for_leader, Node, ThreeNodes,
};
use hearth::audit::{AuditAction, AuditEngine, AuditQuery, CreateAuditEvent, EmbeddedAuditEngine};
use hearth::cluster::ClusterEngine;
use hearth::core::{Clock, FakeClock, RealmId, Timestamp, UserId};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, SessionContext,
};
use hearth::metrics::ForwardedWriteOutcomeLabel;
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};

fn forwarded(outcome: ForwardedWriteOutcomeLabel) -> u64 {
    hearth::metrics::metrics().forwarded_writes(outcome)
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

    let committed_before = forwarded(ForwardedWriteOutcomeLabel::Committed);
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
    // 2 puts + 2 claims + 2 increments + put_batch + write_batch + delete.
    assert_eq!(
        forwarded(ForwardedWriteOutcomeLabel::Committed) - committed_before,
        9,
        "hearth_cluster_forwarded_writes_total{{outcome=\"committed\"}} must count each \
         forwarded write once"
    );

    assert_replicated_everywhere(&cluster, &realm).await;

    cluster.shutdown();
}

/// Every node holds what the first test wrote through the followers.
async fn assert_replicated_everywhere(cluster: &ThreeNodes, realm: &RealmId) {
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
                organization: None,
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

// ── Split-commit writes (the audit engine's group commit) ────────────────────

/// `enqueue_batch` / `await_batch_durable` are forwarded to the embedded
/// engine's WAL group commit only in single-node mode (#441). In cluster mode
/// they must stay a Raft proposal: a follower forwards the batch to the leader
/// once, the batch is readable on the follower as soon as `enqueue_batch`
/// returns (before the durability wait, which has nothing left to do), and it
/// replicates to every node. Had the adapter handed the batch to the
/// follower's own engine, nothing would be forwarded and the other two nodes
/// would never see it (#451).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_enqueued_batch_is_a_raft_proposal_on_the_leader_and_on_a_follower() {
    let cluster = ThreeNodes::start().await;
    let realm = realm();
    let leader_id = cluster.leader_id;
    let follower = cluster.followers()[0];
    let committed_before = forwarded(ForwardedWriteOutcomeLabel::Committed);

    let s = Arc::clone(&follower.storage);
    let r = realm.clone();
    let (read_before_wait, durable) = blocking(move || {
        let handle = s
            .enqueue_batch(
                &r,
                &[
                    (b"f1".to_vec(), b"1".to_vec()),
                    (b"f2".to_vec(), b"2".to_vec()),
                ],
            )
            .expect("a follower's enqueue_batch is forwarded and committed");
        let read = [b"f1".as_slice(), b"f2"].map(|k| s.get(&r, k).unwrap());
        (read, s.await_batch_durable(handle))
    })
    .await;
    durable.expect("a cluster-mode durability handle has nothing left to wait for");
    assert_eq!(
        read_before_wait,
        [Some(b"1".to_vec()), Some(b"2".to_vec())],
        "node {}: a committed batch must be readable on the follower before the durability \
         wait",
        follower.id
    );
    assert_eq!(
        follower.faults.forwards_sent(leader_id),
        1,
        "node {}: a follower's enqueue_batch must be forwarded to the leader exactly once",
        follower.id
    );
    assert_eq!(
        forwarded(ForwardedWriteOutcomeLabel::Committed) - committed_before,
        1,
        "the forwarded batch must commit as one Raft entry"
    );

    let s = Arc::clone(&cluster.leader().storage);
    let r = realm.clone();
    blocking(move || {
        let handle = s
            .enqueue_batch(&r, &[(b"l1".to_vec(), b"3".to_vec())])
            .expect("the leader's enqueue_batch is proposed");
        s.await_batch_durable(handle)
    })
    .await
    .expect("durable");

    cluster.converge().await;
    for node in &cluster.nodes {
        let s = Arc::clone(&node.storage);
        let r = realm.clone();
        let got =
            blocking(move || [b"f1".as_slice(), b"f2", b"l1"].map(|k| s.get(&r, k).unwrap())).await;
        assert_eq!(
            got,
            [
                Some(b"1".to_vec()),
                Some(b"2".to_vec()),
                Some(b"3".to_vec())
            ],
            "node {}: an enqueued batch did not replicate",
            node.id
        );
    }

    cluster.shutdown();
}

/// The audit engine appends through `enqueue_batch` under its realm chain
/// lock and waits for durability after releasing it. In cluster mode an event
/// appended on a follower must be the replicated log's: every node reads it,
/// and every node's chain for the realm verifies (#441, #451).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_audit_event_appended_on_a_follower_replicates_and_verifies_everywhere() {
    let cluster = ThreeNodes::start().await;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    ))) as Arc<dyn Clock>;
    let audit_on = |node: &Node| {
        Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&node.storage),
            Arc::clone(&clock),
        )) as Arc<dyn AuditEngine>
    };
    let realm = realm();
    let follower = cluster.followers()[0];

    let audit = audit_on(follower);
    let request = CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "issue-451".to_string(),
        action: AuditAction::UserCreated,
        resource_type: "user".to_string(),
        resource_id: "u-451".to_string(),
        metadata: None,
    };
    let appended = blocking(move || audit.append(&request))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "node {} (a follower) refused an audit append: {e}",
                follower.id
            )
        });

    cluster.converge().await;
    for node in &cluster.nodes {
        let audit = audit_on(node);
        let r = realm.clone();
        let (events, verified) = blocking(move || {
            let events = audit
                .query(&AuditQuery {
                    realm_id: r.clone(),
                    start_time: None,
                    end_time: None,
                    actor: None,
                    action: None,
                    limit: None,
                    agent_id: None,
                    tool: None,
                })
                .unwrap();
            (events, audit.verify_integrity(&r, None, None).unwrap())
        })
        .await;
        assert_eq!(
            events.iter().map(|e| e.id.clone()).collect::<Vec<_>>(),
            vec![appended.id.clone()],
            "node {}: the follower's audit event did not replicate",
            node.id
        );
        assert!(
            verified,
            "node {}: the realm's audit chain does not verify",
            node.id
        );
    }

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
    let unknown_before = forwarded(ForwardedWriteOutcomeLabel::OutcomeUnknown);

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
    assert_eq!(
        forwarded(ForwardedWriteOutcomeLabel::OutcomeUnknown) - unknown_before,
        2,
        "both lost replies must be counted as outcome_unknown"
    );
    let claim = claim.expect_err("the reply was lost: the claim's outcome is unknown");
    for err in [&inc, &claim] {
        assert_eq!(
            err.retry_class(),
            Some(hearth::storage::RetryClass::OutcomeUnknown),
            "a lost reply must surface as a structured outcome-unknown error: {err}"
        );
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
