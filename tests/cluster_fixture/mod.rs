//! Shared three-node loopback cluster fixture for the cluster test binaries
//! (`cluster_follower_write_forwarding`, `cluster_peer_message_size`).
//!
//! Three real nodes — three `EmbeddedStorageEngine`s under three
//! `ClusterEngine`s, talking openraft over real mTLS gRPC sockets on
//! loopback, each with a `PeerFaults` injector on its outbound peer RPCs.

#![allow(dead_code, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::cluster::{serve, ClusterEngine, ClusterStorageAdapter, HearthNode, PeerFaults};
use hearth::config::ClusterConfig;
use hearth::core::RealmId;
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
pub struct Node {
    pub id: u64,
    pub cluster: Arc<ClusterEngine>,
    pub storage: Arc<dyn StorageEngine>,
    pub faults: Arc<PeerFaults>,
    pub server: tokio::task::JoinHandle<()>,
}

pub struct ThreeNodes {
    pub nodes: Vec<Node>,
    pub leader_id: u64,
    _tempdir: TempDir,
}

impl ThreeNodes {
    pub async fn start() -> Self {
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

    pub fn node(&self, id: u64) -> &Node {
        self.nodes.iter().find(|n| n.id == id).unwrap()
    }

    pub fn leader(&self) -> &Node {
        self.node(self.leader_id)
    }

    pub fn followers(&self) -> Vec<&Node> {
        self.nodes
            .iter()
            .filter(|n| n.id != self.leader_id)
            .collect()
    }

    pub fn engines(&self) -> Vec<Arc<ClusterEngine>> {
        self.nodes.iter().map(|n| Arc::clone(&n.cluster)).collect()
    }

    pub async fn converge(&self) {
        wait_converged(&self.engines(), Duration::from_secs(20)).await;
    }

    pub fn shutdown(self) {
        for n in self.nodes {
            n.server.abort();
        }
    }
}

/// The node every live node agrees leads, ignoring nodes in `dead`.
pub async fn wait_for_leader(
    engines: &[Arc<ClusterEngine>],
    dead: &[u64],
    timeout: Duration,
) -> u64 {
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

pub fn applied(engine: &ClusterEngine) -> u64 {
    engine
        .raft_metrics()
        .and_then(|m| m.last_applied.map(|l| l.index))
        .unwrap_or(0)
}

/// Waits until every engine has applied every entry any of them has logged.
pub async fn wait_converged(engines: &[Arc<ClusterEngine>], timeout: Duration) {
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

pub fn realm() -> RealmId {
    RealmId::new(Uuid::new_v4())
}

pub fn counter(bytes: Option<Vec<u8>>) -> u64 {
    let bytes = bytes.expect("the counter row exists");
    u64::from_le_bytes(bytes.as_slice().try_into().expect("8-byte LE counter"))
}

/// Runs a synchronous storage call off the async worker (the adapter blocks).
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}
