//! `/admin/cluster/*` on a real `hearth serve` process in cluster mode.
//!
//! The cluster admin handlers answer `503 not in cluster mode` when the HTTP
//! state holds no cluster engine. `serve` built the engine but never handed it
//! to the HTTP state, so on a running cluster every node answered that 503 to
//! `GET /admin/cluster/status`, `POST /admin/cluster/bootstrap` and
//! `POST /admin/cluster/transfer-leadership`. The handler tests build their
//! state by hand, so only a test through `serve` catches the wiring.
//!
//! Production mode throughout: three `hearth serve` processes with HTTPS, peer
//! mTLS, a key-encryption key and `HEARTH_MASTER_KEY`, started from copies of
//! one store, and an operator token from `hearth admin token` minted into that
//! store before the copy (the documented rebuild).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::key_encryption::StorageKek;
use hearth::identity::{
    CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const MASTER_KEY: &str = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";
const KEK_HEX: &str = "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
const ISSUER: &str = "https://auth.hearth.example";
const OPERATOR: &str = "ops@hearth.example";
const SYSTEM_REALM: &str = "00000000-0000-0000-0000-000000000000";

/// Kills the server when the test ends, whatever the outcome.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port `p` with `p - 1` free too: with TLS on, `serve` also binds an
/// HTTP-to-HTTPS redirect listener on `port - 1`.
fn free_port_pair() -> u16 {
    for _ in 0..100 {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = l.local_addr().expect("addr").port();
        if port > 1024 && TcpListener::bind(("127.0.0.1", port - 1)).is_ok() {
            return port;
        }
    }
    panic!("no free port pair on 127.0.0.1");
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// A CA and one leaf for `localhost` / `127.0.0.1`, used for both HTTPS and
/// peer mTLS. Returns the CA certificate PEM.
fn write_certs(dir: &Path) -> String {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let ca = ca_params.self_signed(&ca_key).expect("ca cert");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
        .expect("leaf params")
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("leaf cert");
    std::fs::write(dir.join("ca.crt"), ca.pem()).expect("write ca");
    std::fs::write(dir.join("node.crt"), leaf.pem()).expect("write leaf");
    std::fs::write(dir.join("node.key"), leaf_key.serialize_pem()).expect("write key");
    ca.pem()
}

/// An empty production store whose system realm holds one operator account
/// with `realm.admin`. Every engine is dropped on return, which releases the
/// data-directory lock.
fn seed_operator(data_dir: &Path) {
    // nextest runs each test in its own process, so this cannot leak.
    std::env::set_var("HEARTH_MASTER_KEY", MASTER_KEY);
    std::env::remove_var("HEARTH_KEK");
    let storage: Arc<dyn StorageEngine> = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::production(
            data_dir.to_path_buf(),
            64 * 1024 * 1024,
            4 * 1024 * 1024,
            10_000,
        ))
        .expect("open the production store"),
    );
    let kek: [u8; 32] = hex::decode(KEK_HEX)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let audit = Arc::new(
        EmbeddedAuditEngine::new(Arc::clone(&storage), Arc::clone(&clock)).with_kek(Some(kek)),
    );
    let identity = EmbeddedIdentityEngine::with_rbac(
        storage,
        clock,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            key_encryption_key: Some(StorageKek::new(kek)),
            ..IdentityConfig::default()
        },
        Arc::clone(&rbac) as Arc<dyn RbacEngine>,
        audit as Arc<dyn AuditEngine>,
    )
    .expect("identity engine");

    let sys = RealmId::new(uuid::Uuid::nil());
    rbac.seed_realm(&sys).expect("seed system realm roles");
    let role = rbac
        .get_role_by_name(&sys, "realm.admin")
        .expect("look up realm.admin")
        .expect("realm.admin seeded");
    let user = hearth::identity::IdentityEngine::create_admin_user(
        &identity,
        &CreateUserRequest {
            email: OPERATOR.into(),
            display_name: "Operator".into(),
            ..Default::default()
        },
    )
    .expect("operator account");
    rbac.assign_role(
        &sys,
        &AssignRoleRequest {
            subject: Subject::User(user.id().clone()),
            role_id: role.id.clone(),
            scope: Scope::Realm,
            assigned_by: None,
        },
    )
    .expect("grant realm.admin");
}

/// One node of the test cluster.
#[derive(Clone)]
struct NodeSpec {
    id: u64,
    port: u16,
    peer_port: u16,
}

/// A production `hearth.yaml` for `node`, whose `cluster.peers` lists every
/// other node of `cluster`.
fn write_config(dir: &Path, node: &NodeSpec, cluster: &[NodeSpec]) -> PathBuf {
    let d = dir.display();
    let id = node.id;
    let peers: String = cluster
        .iter()
        .filter(|n| n.id != id)
        .map(|n| {
            format!(
                "    - id: {}\n      address: \"localhost:{}\"\n",
                n.id, n.peer_port
            )
        })
        .collect();
    let path = dir.join(format!("node{id}.yaml"));
    std::fs::write(
        &path,
        format!(
            "oidc:\n  issuer: \"{ISSUER}\"\n\
             server:\n  bind_address: \"127.0.0.1\"\n  port: {port}\n\
             \x20 tls_cert_path: \"{d}/node.crt\"\n  tls_key_path: \"{d}/node.key\"\n\
             security:\n  key_encryption_key: \"{KEK_HEX}\"\n\
             \x20 allowed_hosts: [\"auth.hearth.example\", \"localhost\"]\n\
             storage:\n  data_dir: \"{d}/data{id}\"\n\
             email:\n  transport: log\n  allow_log_transport_in_production: true\n\
             cluster:\n  node_id: {id}\n  peer_address: \"127.0.0.1:{peer_port}\"\n\
             \x20 peers:\n{peers}\
             \x20 tls_cert_path: \"{d}/node.crt\"\n  tls_key_path: \"{d}/node.key\"\n\
             \x20 tls_ca_cert_path: \"{d}/ca.crt\"\n",
            port = node.port,
            peer_port = node.peer_port,
        ),
    )
    .expect("write config");
    path
}

/// Copies a stopped node's data directory, file by file.
fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir(dst).expect("create the node's data directory");
    for entry in std::fs::read_dir(src).expect("read the seed store") {
        let entry = entry.expect("entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy a store file");
        }
    }
}

fn hearth() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hearth"));
    cmd.env_remove("HEARTH_KEK")
        .env("HEARTH_MASTER_KEY", MASTER_KEY);
    cmd
}

/// `GET` or `POST` an `/admin/cluster/*` route with the system-realm token.
async fn cluster_admin(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    token: &str,
) -> (u16, String) {
    let resp = client
        .request(method, url)
        .bearer_auth(token)
        .header("X-Realm-ID", SYSTEM_REALM)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

/// Mints a 10-minute system-realm token into the stopped store `seed` with
/// `hearth admin token`, reading the issuer and KEK from `config`.
fn mint_token(seed: &Path, config: &Path) -> String {
    let mint = hearth()
        .args([
            "admin",
            "token",
            "--user",
            OPERATOR,
            "--ttl",
            "10m",
            "--data-dir",
        ])
        .arg(seed)
        .arg("--config")
        .arg(config)
        .output()
        .expect("run hearth admin token");
    assert!(
        mint.status.success(),
        "hearth admin token: {}",
        String::from_utf8_lossy(&mint.stderr)
    );
    String::from_utf8(mint.stdout)
        .expect("utf-8")
        .trim()
        .to_string()
}

/// Starts one `hearth serve` per node, each on its own copy of `seed`. Returns
/// the running servers and their log files.
fn start_nodes(
    dir: &Path,
    seed: &Path,
    cluster: &[NodeSpec],
    configs: &[PathBuf],
) -> (Vec<Server>, Vec<PathBuf>) {
    let mut servers = Vec::new();
    let mut logs = Vec::new();
    for (node, config) in cluster.iter().zip(configs) {
        copy_dir(seed, &dir.join(format!("data{}", node.id)));
        let (server, log_path) = spawn_node(dir, node, config);
        servers.push(server);
        logs.push(log_path);
    }
    (servers, logs)
}

/// Starts `hearth serve` for `node` on the data directory it already has.
/// Returns the server and its log file (truncated on each start).
fn spawn_node(dir: &Path, node: &NodeSpec, config: &Path) -> (Server, PathBuf) {
    let log_path = dir.join(format!("node{}.log", node.id));
    let log = std::fs::File::create(&log_path).expect("log file");
    let server = Server(
        hearth()
            .args(["serve", "--config"])
            .arg(config)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn hearth serve"),
    );
    (server, log_path)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cluster_admin_api_reaches_the_raft_engine_of_every_serving_node() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_pem = write_certs(dir.path());
    let cluster: Vec<NodeSpec> = (1..=3)
        .map(|id| NodeSpec {
            id,
            port: free_port_pair(),
            peer_port: free_port(),
        })
        .collect();
    let configs: Vec<PathBuf> = cluster
        .iter()
        .map(|n| write_config(dir.path(), n, &cluster))
        .collect();

    // The documented rebuild: seed one store, mint the token into it while it
    // holds no raft.db, then start every node from a copy of it.
    let seed = dir.path().join("seed");
    seed_operator(&seed);
    let token = mint_token(&seed, &configs[0]);

    let (_servers, logs) = start_nodes(dir.path(), &seed, &cluster, &configs);
    let server_logs = || {
        logs.iter()
            .map(|p| std::fs::read_to_string(p).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n----\n")
    };

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("ca"))
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut leaders = 0;
    for node in &cluster {
        let url = format!("https://localhost:{}/admin/cluster/status", node.port);
        // Ready means serving, and a node serves once the cluster has a leader.
        let (status, body) = loop {
            let ready = client
                .get(format!("https://localhost:{}/readyz", node.port))
                .send()
                .await;
            if ready.is_ok_and(|r| r.status().is_success()) {
                break cluster_admin(&client, reqwest::Method::GET, &url, &token).await;
            }
            assert!(
                Instant::now() < deadline,
                "node {} did not become ready in 40 s:\n{}",
                node.id,
                server_logs()
            );
            // AUDIT: justified-sleep: poll interval for /readyz on a child process, bounded by the 40 s deadline
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        assert_eq!(
            status, 200,
            "node {}: GET /admin/cluster/status: {body}",
            node.id
        );
        let status: serde_json::Value = serde_json::from_str(&body).expect("status JSON");
        let mut peer_ids: Vec<u64> = status["peers"]
            .as_array()
            .expect("peers is a list")
            .iter()
            .map(|p| p["id"].as_u64().expect("peer id"))
            .collect();
        peer_ids.sort_unstable();
        let others: Vec<u64> = cluster
            .iter()
            .map(|n| n.id)
            .filter(|&id| id != node.id)
            .collect();
        assert_eq!(
            peer_ids, others,
            "node {}: the peers are the other nodes: {status}",
            node.id
        );
        assert!(
            status["last_applied_index"].is_u64(),
            "node {}: an applied index: {status}",
            node.id
        );
        if status["role"] == "leader" {
            leaders += 1;
        }
    }
    assert_eq!(leaders, 1, "exactly one node reports itself leader");

    // The cluster formed on its own, so bootstrap is refused as already done:
    // 409 comes from Raft, not the 503 of a node without a Raft engine.
    let (status, body) = cluster_admin(
        &client,
        reqwest::Method::POST,
        &format!(
            "https://localhost:{}/admin/cluster/bootstrap",
            cluster[0].port
        ),
        &token,
    )
    .await;
    assert_eq!(status, 409, "POST /admin/cluster/bootstrap: {body}");
}

/// `/readyz` on a node that cannot commit a write. A node whose store needs
/// no start-up writes (a restart, or a store seeded through `/ui/setup`)
/// serves HTTP before any quorum exists, and `/readyz` answered `200` there:
/// it checked storage and the write fence, never Raft. A node restarted on
/// its own committed vote even resumes as leader, with no quorum.
#[tokio::test(flavor = "multi_thread")]
async fn readyz_is_not_ready_while_the_node_cannot_commit_a_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_pem = write_certs(dir.path());
    let cluster: Vec<NodeSpec> = (1..=3)
        .map(|id| NodeSpec {
            id,
            port: free_port_pair(),
            peer_port: free_port(),
        })
        .collect();
    let configs: Vec<PathBuf> = cluster
        .iter()
        .map(|n| write_config(dir.path(), n, &cluster))
        .collect();
    let seed = dir.path().join("seed");
    seed_operator(&seed);
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("ca"))
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let probe = |node: &NodeSpec| {
        let req = client.get(format!("https://localhost:{}/readyz", node.port));
        async move {
            let resp = req.send().await.ok()?;
            let status = resp.status().as_u16();
            Some((status, resp.text().await.unwrap_or_default()))
        }
    };
    let log_of = |id: u64| {
        std::fs::read_to_string(dir.path().join(format!("node{id}.log"))).unwrap_or_default()
    };
    let await_ready = |node: &NodeSpec| {
        let probe = &probe;
        let log_of = &log_of;
        let id = node.id;
        let node = node.clone();
        async move {
            let deadline = Instant::now() + Duration::from_secs(40);
            loop {
                if let Some((200, body)) = probe(&node).await {
                    assert!(body.contains("\"ready\""), "node {id} ready body: {body}");
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "node {id} was not ready in 40 s:\n{}",
                    log_of(id)
                );
                // AUDIT: justified-sleep: poll interval for /readyz on a child process, bounded by the 40 s deadline
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    };

    // First run: every start-up write is applied, on every node.
    let (servers, _) = start_nodes(dir.path(), &seed, &cluster, &configs);
    for node in &cluster {
        await_ready(node).await;
    }
    drop(servers);

    // Node 1 alone: nothing to write, so HTTP comes up; one of three is no
    // quorum, so no leader.
    let (_first, _) = spawn_node(dir.path(), &cluster[0], &configs[0]);
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        if probe(&cluster[0]).await.is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "node 1 did not serve HTTP in 40 s:\n{}",
            log_of(1)
        );
        // AUDIT: justified-sleep: poll interval for node 1's HTTP listener, bounded by the 40 s deadline
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // A follower keeps a dead leader until its election timeout (at most
    // 3 s) passes; after that, and for longer than another election
    // timeout, node 1 must not be ready. If node 1 led the first run, it
    // resumes as leader with no quorum and is `no_quorum` from the start.
    // AUDIT: justified-sleep: node 1 must stay not ready past a real election timeout (3 s) of separate processes
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let mut answer = probe(&cluster[0]).await.expect("node 1 still serves HTTP");
    let watch_until = Instant::now() + Duration::from_secs(4);
    loop {
        assert_eq!(
            answer.0,
            503,
            "a node with no leader or no quorum must not be ready: {}\n{}",
            answer.1,
            log_of(1)
        );
        assert!(
            answer.1.contains("no_leader") || answer.1.contains("no_quorum"),
            "the body names the reason: {}",
            answer.1
        );
        if Instant::now() >= watch_until {
            break;
        }
        // AUDIT: justified-sleep: probe interval while watching node 1 stay not ready for a span of real time
        tokio::time::sleep(Duration::from_millis(250)).await;
        answer = probe(&cluster[0]).await.expect("node 1 still serves HTTP");
    }

    // The other two come back; a leader is elected, and node 1 is ready.
    let _rest: Vec<_> = cluster[1..]
        .iter()
        .zip(&configs[1..])
        .map(|(node, config)| spawn_node(dir.path(), node, config))
        .collect();
    await_ready(&cluster[0]).await;
}
