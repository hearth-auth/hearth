# Clustering Guide

Hearth supports multi-node Raft consensus for high availability and horizontal read scaling. In cluster mode, writes go through Raft log replication before being acknowledged; reads are served locally by followers as long as replication lag is within the configured threshold.

> **Early access — not production-validated.** The Raft clustering implementation is complete and wired (`src/cluster/` + `openraft`), but no 3-node deployment has been chaos-tested under production load. For v1.0 deployments, single-node mode is recommended unless you are comfortable operating software at this validation level. HA clustering is the primary Phase 2 focus. Feedback from early cluster operators is welcome.

**Single-node mode is the default.** Omit the `cluster:` YAML section entirely if you do not need HA. There is zero overhead — no extra port, no Raft log, no election timers.

---

## Prerequisites

Before enabling cluster mode:

1. **NTP on every node.** Hearth embeds a `leader_timestamp` (wall-clock microseconds) in every Raft log entry so all nodes apply the same timestamp to concurrent writes. Clocks must be NTP-synchronized. Skew above 1 second triggers a startup warning; skew above several seconds will produce incorrectly ordered writes.

2. **Mutual TLS certificates.** All inter-node gRPC connections are mTLS — plaintext is unconditionally rejected. You need:
   - A CA certificate shared by all nodes
   - A leaf certificate and private key for each node, signed by that CA

3. **Port reachability.** Each node's `peer_address` port (default `8421`) must be reachable from all other nodes.

---

## Generating Certificates

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

For production, add a SAN matching the node's IP or hostname:

```bash
openssl x509 -req -days 365 \
  -extfile <(printf "subjectAltName=IP:10.0.0.1") \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in node1.csr -out node1.crt
```

---

## Configuration

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

## Bootstrap Sequence

Bootstrapping initializes the cluster's initial membership. Do this **once** — running bootstrap on an already-initialized cluster is a no-op (Raft rejects double-initialization).

1. Start all nodes: `hearth serve -c hearth-N.yaml`
2. Wait until all nodes are listening (check logs for `"Raft peer gRPC server starting (mTLS)"`).
3. Call the bootstrap endpoint on **one** designated bootstrap node:

> **System-realm token required.** Cluster admin endpoints are gated to the system realm
> (the nil UUID). Your admin token must carry `X-Realm-ID: 00000000-0000-0000-0000-000000000000`.
> Tokens issued against a tenant realm return `403 Forbidden` even if the user is an admin.
> Obtain a system-realm admin token with `POST /admin/bootstrap` (dev) or via your bootstrap
> token in `hearth.yaml`.

```bash
curl -s -X POST http://10.0.0.1:8420/admin/cluster/bootstrap \
  -H "Authorization: Bearer <admin-token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"
```

This sends the initial membership list (derived from the node's `peers` + its own `node_id`) to `openraft`'s `initialize()`. The cluster holds an election and begins accepting writes within one election timeout (~1.5–3 seconds).

**Expected response (`200 OK`):**

```json
{
  "node_id": 1,
  "term": 1,
  "leader_id": 1
}
```

`leader_id` is the node that won the election. If the election has not completed within 3 seconds, the response still returns `200` with the best available values.

**Error responses:**
- `409 Conflict` — cluster already initialized (safe to ignore on retry)
- `503 Service Unavailable` — server is running in single-node mode (no `cluster:` config)

4. Verify with the cluster status endpoint:

```bash
curl -s http://10.0.0.1:8420/admin/cluster/status \
  -H "Authorization: Bearer <admin-token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"
```

**Expected response (`200 OK`):**

```json
{
  "role": "leader",
  "term": 1,
  "last_applied_index": 0,
  "peers": [
    { "id": 2, "addr": "10.0.0.2:8421", "is_healthy": true },
    { "id": 3, "addr": "10.0.0.3:8421", "is_healthy": true }
  ]
}
```

`role` is one of `"leader"`, `"follower"`, `"candidate"`, `"learner"`, or `"unknown"`. `is_healthy` reflects whether the peer appears in the leader's replication map; on a follower node all peers report `is_healthy: false` (followers have no replication state).

**Error responses:**
- `503 Service Unavailable` — server is running in single-node mode or Raft is not yet initialized

---

## Write and Read Routing

### Writes

Every mutation (user create, token issuance, session write, etc.) is proposed as a Raft log entry. Only the **leader** can propose entries.

If a write arrives on a follower, Hearth returns an error with the leader's address. Your load balancer should route writes to the leader, or your client should retry against the returned address.

### Reads

Followers serve reads locally from their storage engine. A background task checks replication lag every 50 ms. If the follower's committed index lags the leader by more than `read_lag_threshold_ms` (default 500 ms), reads are refused and the caller is redirected to the leader.

This means follower reads have **eventual consistency** within the configured threshold — appropriate for most identity lookups, where a 500 ms staleness window is acceptable.

---

## Quorum and Failure Tolerance

| Cluster size | Fault tolerance | Notes |
|:---:|:---:|---|
| 1 | 0 | Single-node mode (no Raft) |
| 3 | 1 | Minimum recommended HA configuration |
| 5 | 2 | Tolerates 2 simultaneous node failures |

A majority (quorum) of nodes must be reachable for writes to succeed. A 3-node cluster tolerates one node failure; a 5-node cluster tolerates two.

---

## Raft Timing Parameters

These are compiled-in and not configurable today:

| Parameter | Value |
|---|---|
| Heartbeat interval | 500 ms |
| Election timeout | 1500–3000 ms (randomized) |
| Lag monitor interval | 50 ms |

A leader is elected within 1.5–3 seconds of the previous leader becoming unreachable.

---

## Graceful Shutdown

Before shutting down a node, initiate a **Raft leadership transfer** to avoid a brief unavailability window while the remaining nodes hold a new election. This is especially important when rolling a node that is currently the leader.

```bash
# Transfer leadership before stopping the process
curl -s -X POST http://10.0.0.1:8420/admin/cluster/transfer-leadership \
  -H "Authorization: Bearer <admin-token>" \
  -H "X-Realm-ID: 00000000-0000-0000-0000-000000000000"

# Then stop the process
systemctl stop hearth
```

The request body is optional. To request a specific target node, pass:

```json
{ "target_node_id": 2 }
```

`target_node_id` is accepted for forward-compatibility. In the current release, openraft 0.9 does not support targeted transfer, so the election winner is not guaranteed to be the requested node. Check `exact_target` in the response to verify.

**Expected response (`200 OK`):**

```json
{
  "new_leader_id": 2,
  "exact_target": true
}
```

**Error responses:**
- `409 Conflict` — this node is not the leader; transfer must be initiated from the leader
- `503 Service Unavailable` — server is running in single-node mode

The server drains in-flight requests (up to `operational.shutdown_timeout_secs`, default 10 s) after receiving `SIGTERM`. The leadership transfer should complete well within this window on a healthy cluster.

---

## Backups

Take backups from a **follower** to avoid adding I/O load to the leader (which is processing all writes).

```bash
# Create a backup archive from a follower node
hearth backup create \
  --data-dir /var/lib/hearth/data \
  --output /backups/hearth-$(date +%F).hearth-backup
```

The Raft log (`raft.db`) is ephemeral metadata — only the storage WAL and SSTs need to be backed up. Restoring to a new node from a backup and then rejoining the cluster is the recommended recovery path for a completely failed node.

See the [Backup and Restore Guide](./backup.md) for the full `hearth backup` CLI reference, archive format, and restore procedure.

---

## Monitoring

Key health signals to watch:

| Signal | What to watch for |
|---|---|
| Leader changes | Frequent re-elections indicate network instability or overloaded nodes |
| Replication lag | Persistent lag approaching `read_lag_threshold_ms` means a follower is struggling |
| `ClusterError::NotLeader` rate | Spikes indicate the load balancer is not routing writes to the leader |
| `ClusterError::ReplicationLagExceeded` rate | Follower is consistently behind; investigate node resources |

These appear as structured log fields (`node_id`, `peer_address`, `read_lag_threshold_ms`) emitted at startup and in error events. Route them to your log aggregator and alert on `ClusterError::NotLeader` surges during non-maintenance windows.
