# Clustering Guide

> **⚠ EXPERIMENTAL — Do not use in production.** Multi-node clustering is incomplete in Hearth 1.x. Known defects (described below) make multi-node deployments unsafe for production data. **The supported deployment model for Hearth 1.x is single-node.** Clustering improvements are tracked in Wave 5 of the production-readiness roadmap.

Hearth includes a partial Raft consensus implementation (`src/cluster/` via `openraft`). The clustering code path exists, but several critical components are either unimplemented or incorrect. This guide documents the current state accurately so operators can make informed decisions.

**Single-node mode is the default and only production-supported configuration.** Omit the `cluster:` YAML section entirely. There is zero overhead — no extra port, no Raft log, no election timers.

---

## Known Defects in Experimental Cluster Mode

### C-5 — Followers do not invalidate RBAC or session caches

When a permission is revoked or a session is terminated on the leader, that change propagates to followers via Raft log replication. However, `src/cluster/state_machine.rs` contains no cache-invalidation logic, and `RaftCommand` has no invalidation variant.

**Consequence:** A permission revoked on the leader continues to be honoured on followers indefinitely. A user whose access is revoked can still authenticate successfully against a follower node.

### C-6 — Cluster membership is immutable after bootstrap

`add_learner` and `change_membership` are not implemented. The only path to set cluster membership is `raft.initialize()` from static YAML at first bootstrap.

**Consequence:** Nodes cannot be added or removed from a running cluster. Replacing a failed node requires a full-cluster restart with updated YAML. Online membership changes are not possible in Hearth 1.x.

### H-3 — Writes to a follower return HTTP 500

In cluster mode, mutation requests (user creation, token issuance, session writes) that arrive on a follower return HTTP 500. The caller receives no leader-address hint to retry against.

**Consequence:** A load balancer that distributes write traffic across all nodes will cause approximately `(n-1)/n` of write requests to fail in an n-node cluster. Writes must be routed exclusively to the leader node.

### Exclusive `data_dir` lock

Hearth holds an OS-level advisory flock on the `data_dir/LOCK` file for the lifetime of the process. A second process attempting to open the same `data_dir` will fail immediately with `StorageError::AlreadyLocked`.

This lock is process-scoped and cannot be shared across nodes. Each node in a cluster must use a completely separate `data_dir` on separate storage. You cannot point two nodes at the same directory or network share.

**In Kubernetes:** Use `accessMode: ReadWriteOnce` and a separate PVC per pod. A `ReadWriteMany` mount shared between pods will trigger the lock and prevent startup.

---

## When Clustering Will Be Production-Ready

The Wave 5 roadmap items covering clustering are:
- **HEA-2177 (W5-1)** — RBAC/claims cache invalidation on followers (C-5)
- **HEA-2178 (W5-2)** — Online membership changes via `add_learner` / `change_membership` (C-6)
- **HEA-2173 (W3-3)** — Follower-write 307 redirect to leader instead of HTTP 500 (H-3)

All three are post-GA. Because Hearth 1.x ships **no supported multi-node path**, none of
them gate the 1.0 release.

Until these ship, the production deployment model is single-node with external backups and a planned failover procedure. If your reliability requirements exceed what a single node provides, contact us to understand the timeline.

---

## Experimental Usage (Development and Evaluation Only)

If you are evaluating cluster behaviour for integration work or contributing to the clustering implementation, the following documents the current API. Do not run this in production.

> **Cluster init failure is fatal.** If a `cluster:` section is present in `hearth.yaml` and Raft initialization fails (for example, because peer nodes are unreachable), Hearth exits non-zero. It does **not** fall back to running as a standalone single-node writer. To run single-node, omit the `cluster:` section entirely.

> **Startup will emit an EXPERIMENTAL warning (HEA-2188).** When the `cluster:` section is present, Hearth will log a `WARN`-level message at startup indicating that cluster mode is experimental and not production-supported. This is tracked in HEA-2188 and not yet implemented.

### Prerequisites

Before enabling cluster mode in a test environment:

1. **NTP on every node.** Hearth embeds a `leader_timestamp` (wall-clock microseconds) in every Raft log entry so all nodes apply the same timestamp to concurrent writes. Clocks must be NTP-synchronized.

2. **Mutual TLS certificates.** All inter-node gRPC connections are mTLS — plaintext is unconditionally rejected. You need:
   - A CA certificate shared by all nodes
   - A leaf certificate and private key for each node, signed by that CA

3. **Port reachability.** Each node's `peer_address` port (default `8421`) must be reachable from all other nodes.

4. **Separate `data_dir` per node.** The exclusive directory lock means no two nodes may share a `data_dir`.

---

### Generating Certificates

Any PKI tooling works. A minimal setup with `openssl`:

```bash
# 1 — CA
openssl req -new -x509 -days 3650 -nodes \
  -subj "/CN=hearth-cluster-ca" \
  -keyout ca.key -out ca.crt

# 2 — Leaf cert for node 1 (repeat with node-specific CN/SAN for each node)
openssl req -new -nodes \
  -subj "/CN=hearth-node-1" \
  -keyout node1.key -out node1.csr

openssl x509 -req -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in node1.csr -out node1.crt
```

For a test environment with IP-based SANs:

```bash
openssl x509 -req -days 365 \
  -extfile <(printf "subjectAltName=IP:10.0.0.1") \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in node1.csr -out node1.crt
```

---

### Configuration

Each node gets its own `hearth.yaml`. The `cluster.node_id` and `cluster.peer_address` are unique per node; the CA cert and `peers` list are the same across all nodes.

**Node 1 (`hearth-1.yaml`):**

```yaml
oidc:
  issuer: "https://auth.example.com"

storage:
  data_dir: "/var/lib/hearth/data"

cluster:
  node_id: 1
  peer_address: "10.0.0.1:8421"
  peers:
    - id: 2
      address: "10.0.0.2:8421"
    - id: 3
      address: "10.0.0.3:8421"
  tls_cert_path: "/etc/hearth/certs/node1.crt"
  tls_key_path:  "/etc/hearth/certs/node1.key"
  tls_ca_cert_path: "/etc/hearth/certs/ca.crt"
```

**Node 2 (`hearth-2.yaml`):** Same, but `node_id: 2`, `peer_address: "10.0.0.2:8421"`, `tls_cert_path/key_path` point to node 2's leaf cert.

**Node 3:** Analogous.

> All config fields are documented in the [Configuration reference](../specs/CONFIGURATION.md#cluster).

---

### Bootstrap Sequence

Bootstrapping initializes the cluster's initial membership. Do this **once** — running bootstrap on an already-initialized cluster is a no-op (Raft rejects double-initialization).

> **Membership is fixed at bootstrap.** The peers list set here cannot be changed without a full-cluster restart. There is no online membership change API in Hearth 1.x (see C-6 above).

1. Start all nodes: `hearth serve -c hearth-N.yaml`
2. Wait until all nodes are listening (check logs for `"Raft peer gRPC server starting (mTLS)"`).
3. Call the bootstrap endpoint on **one** designated bootstrap node:

> **System-realm token required.** Cluster admin endpoints are gated to the system realm
> (the nil UUID). Your admin token must carry `X-Realm-ID: 00000000-0000-0000-0000-000000000000`.

```bash
curl -s -X POST http://10.0.0.1:8420/admin/cluster/bootstrap \
  -H "Authorization: Bearer <system-admin-token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"
```

**Expected response (`200 OK`):**

```json
{
  "node_id": 1,
  "term": 1,
  "leader_id": 1
}
```

**Error responses:**
- `409 Conflict` — cluster already initialized (safe to ignore on retry)
- `503 Service Unavailable` — server is running in single-node mode (no `cluster:` config)

---

### Write Routing

**All writes must go to the leader.** Due to H-3, writes to a follower return HTTP 500. Your load balancer must route write traffic exclusively to the leader node. There is no automatic redirect.

Reads from followers may be stale due to C-5 (no cache invalidation). For consistent reads, route all traffic to the leader.

---

### Quorum and Failure Tolerance

| Cluster size | Fault tolerance |
|:---:|:---:|
| 1 | 0 (single-node mode, no Raft) |
| 3 | 1 node failure |
| 5 | 2 node failures |

A majority (quorum) of nodes must be reachable for writes to succeed.

**If a node fails permanently:** Replace it by restarting all remaining nodes with updated YAML (removing the failed node from the `peers` list). Online membership changes are not supported in Hearth 1.x.

---

### Cluster Status

```bash
curl -s http://10.0.0.1:8420/admin/cluster/status \
  -H "Authorization: Bearer <system-admin-token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"
```

`role` is one of `"leader"`, `"follower"`, `"candidate"`, `"learner"`, or `"unknown"`. `is_healthy` reflects whether the peer appears in the leader's replication map.

---

### Graceful Shutdown

Before shutting down the leader node, initiate a Raft leadership transfer to avoid an election timeout:

```bash
# Transfer leadership before stopping the process
curl -s -X POST http://10.0.0.1:8420/admin/cluster/transfer-leadership \
  -H "Authorization: Bearer <system-admin-token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"

# Then stop the process
systemctl stop hearth
```

---

### Backups

Take backups from a **follower** to avoid adding I/O load to the leader.

See the [Backup and Restore Guide](./backup.md) for the full procedure.

> **Note on followers and stale RBAC state (C-5):** Because followers do not invalidate caches on permission changes, a backup taken from a follower may reflect the storage state correctly but should not be used to audit access-control decisions — the follower may have served stale permissions since the last leader write.
