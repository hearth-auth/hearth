# Clustering Guide

> **⚠ EXPERIMENTAL — and, as of 2026-09-21, a multi-node cluster does not start.** See [G-1](#g-1--a-cold-cluster-cannot-be-bootstrapped) below: every node exits fatally during start-up, before the bootstrap endpoint can be called. The rest of this guide documents the intended API and the known defects of a *running* cluster; none of it is reachable today. **The supported deployment model for Hearth 1.x is single-node.** Clustering improvements are tracked in Wave 5 of the production-readiness roadmap.

Hearth includes a partial Raft consensus implementation (`src/cluster/` via `openraft`). The clustering code path exists, but several critical components are either unimplemented or incorrect. This guide documents the current state accurately so operators can make informed decisions.

**Single-node mode is the default and only production-supported configuration.** Omit the `cluster:` YAML section entirely. There is zero overhead — no extra port, no Raft log, no election timers.

---

## Known Defects in Experimental Cluster Mode

### G-1 — A cold cluster could not be bootstrapped (FIXED)

`serve` builds the identity engine over the cluster storage adapter, and that
constructor **writes** on a cold `data_dir` — the KEK-enrolment marker, the
global signing key and the system-realm row. In cluster mode each is a Raft
proposal, and a cluster that has not been bootstrapped has no leader, so the
first one returned `NotLeader` and start-up was fatal on every node:

```text
ERROR hearth: error: storage error: storage I/O error:
              raft: not the leader; redirect to unknown
```

The consequence was that the Bootstrap Sequence could not be performed at all:
step 1 (start all nodes) never completed, so step 3 (POST
`/admin/cluster/bootstrap`) was unreachable — including on the designated
bootstrap node. Verified on three nodes on 2026-09-21; the transcript is in
`reports/cluster-ga-readiness-2026-09-21.md`.

**Fixed in two halves** (task 26.46), both covered by
`tests/cluster_three_node_control_coherence.rs::a_cold_three_node_cluster_starts_every_node_without_a_manual_bootstrap`:

* **Self-initialisation.** The node with the **lowest node ID** in the
  membership its own `cluster.peers` names initialises Raft at start-up, so a
  leader is elected without an HTTP call. The other nodes stay pristine and
  adopt the membership from the first `AppendEntries` they receive. Nothing new
  is trusted — the membership, peer addresses and mTLS material all come from
  that node's own `hearth.yaml`.
* **A start-up write window.** Before building the identity engine, a node
  waits until either it is the leader (its writes will land) or the
  system-realm row has replicated to it (the leader finished the write set, so
  there is nothing left to write). If neither happens within 120 s, start-up
  fails with a message naming the likely causes.

**Operational consequences.**

* A cold cluster forms on its own. `POST /admin/cluster/bootstrap` still works
  and now answers `409` on an already-initialised cluster; it remains the
  escape hatch when the lowest-ID node is the one that is down.
* Provision the lowest-ID node first, or at least start it alongside the
  others. If it never starts, the remaining nodes wait out the 120 s window and
  exit — bootstrap one of them explicitly instead.
* A `cluster:` section with an empty `peers` list does **not** self-initialise;
  there is nothing to replicate to. Use the endpoint.

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

> **Startup emits an EXPERIMENTAL warning.** When the `cluster:` section is present, Hearth logs a `WARN`-level message at startup indicating that cluster mode is experimental and not production-supported (HEA-2154).

### Prerequisites

Before enabling cluster mode in a test environment:

1. **NTP on every node.** Hearth embeds a `leader_timestamp` (wall-clock microseconds) in every Raft log entry so all nodes apply the same timestamp to concurrent writes. Clocks must be NTP-synchronized.

2. **Mutual TLS certificates.** All inter-node gRPC connections are mTLS — plaintext is unconditionally rejected. You need:
   - A CA certificate shared by all nodes
   - A leaf certificate and private key for each node, signed by that CA

3. **Port reachability.** Each node's `peer_address` port (default `8421`) must be reachable from all other nodes.

4. **Separate `data_dir` per node.** The exclusive directory lock means no two nodes may share a `data_dir`.

5. **The same `HEARTH_MASTER_KEY` and key-encryption key on every node.** Both wrap data that *replicates*: a row encrypted by one node must be decryptable by the others. Generate each value **once** for the whole cluster and distribute it — do not run `openssl rand -hex 32` per node. Every node also needs the full set of settings that are [mandatory in production](../specs/CONFIGURATION.md#mandatory-in-production):

   | Setting | Where | Must match across nodes? |
   |---|---|---|
   | `HEARTH_MASTER_KEY` (env) | environment | **Yes** |
   | `security.key_encryption_key` (or `HEARTH_KEK`) | YAML or environment | **Yes** |
   | `server.tls_cert_path` + `server.tls_key_path`, **or** `server.trust_forwarded_proto: true` with a non-empty `server.trusted_proxies` | YAML | No — per node |

   `hearth config validate` reports this on the success path for any
   configuration with a non-empty `cluster.peers` — both when
   `HEARTH_MASTER_KEY` is unset and, because nothing local can compare one
   node's value against its peers', when it is set (task 26.51). It is a
   warning, not an error: the key is a property of the machine, not of the file
   being validated, so validating a cluster config on a laptop stays legal.
   Note that the single-node host-key check is satisfied by an existing
   `{data_dir}/hearth.host_key` — which is exactly the per-node, auto-generated
   key that is *wrong* in a cluster — so the cluster note is emitted
   independently of it.

---

### Generating Certificates

Any PKI tooling works. A minimal setup with `openssl`:

```bash
# 1 — CA
openssl req -new -x509 -days 3650 -nodes \
  -subj "/CN=hearth-cluster-ca" \
  -keyout ca.key -out ca.crt

# 2 — Leaf key + CSR for node 1 (repeat with a node-specific CN for each node)
openssl req -new -nodes \
  -subj "/CN=hearth-node-1" \
  -keyout node1.key -out node1.csr

# 3 — Sign it. The SAN is REQUIRED: rustls verifies the peer against
#     subjectAltName and ignores the Common Name, so a leaf signed without
#     -extfile fails the handshake with no usable diagnostic.
#     Use the address the peers will actually dial.
openssl x509 -req -days 3650 \
  -extfile <(printf "subjectAltName=IP:10.0.0.1") \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -in node1.csr -out node1.crt
```

Use `subjectAltName=DNS:node1.example.com` instead when `peers[].address` names
a hostname rather than an IP. Verify before deploying:

```bash
openssl x509 -in node1.crt -noout -text | grep -A1 "Subject Alternative Name"
```

An empty result means the certificate will not work.

---

### Configuration

Each node gets its own `hearth.yaml`. The `cluster.node_id` and `cluster.peer_address` are unique per node; the CA cert and `peers` list are the same across all nodes.

**Node 1 (`hearth-1.yaml`):**

```yaml
oidc:
  issuer: "https://auth.example.com"

server:
  # Distinct per node only when several nodes share a host (evaluation).
  # On separate hosts every node can keep the default 8420.
  port: 8420
  tls_cert_path: "/etc/hearth/certs/https-node1.crt"
  tls_key_path:  "/etc/hearth/certs/https-node1.key"

security:
  # REQUIRED in production, and IDENTICAL on every node — see Prerequisites §5.
  # Prefer the HEARTH_KEK environment variable to putting it in YAML.
  key_encryption_key: "<64 lowercase hex chars, generated once for the cluster>"

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

> Note the two certificate pairs. `server.tls_cert_path` is the node's **HTTPS**
> identity for client traffic; `cluster.tls_cert_path` is its **peer mTLS**
> identity for Raft. They are unrelated and are not interchangeable.

> Every node must also have `HEARTH_MASTER_KEY` exported in its environment,
> with the same value on all three. It is not a YAML key and `hearth config
> validate` does not check for it.

> All config fields are documented in the [Configuration reference](../specs/CONFIGURATION.md#cluster).

---

### Bootstrap Sequence

> **Usually unnecessary.** As of task 26.46 the lowest-ID node in the
> configured membership initialises the cluster itself at start-up — see
> [G-1](#g-1--a-cold-cluster-could-not-be-bootstrapped-fixed). Follow this
> sequence when that node is unavailable, or when you want to form the cluster
> from a different node's membership. On an already-initialised cluster the
> endpoint answers `409`.

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
